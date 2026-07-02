/*
 * cmd/antsd/run.c — `antsd run`: the node's event loop.
 *
 * Stands the QUIC transport and the Kademlia DHT up from the config and
 * drives the single-threaded tick loop until SIGINT/SIGTERM. The
 * transport event callback here is the daemon's central demux: every
 * event is forwarded to the DHT first (it consumes the ones belonging
 * to its in-flight RPCs, per the delegation contract in ants_dht.h),
 * then handled locally; gossip and chain handlers plug in the same way
 * in later PRs. The DHT is seeded from the config's bootstrap list.
 * Logging and signal handling live in the daemon by design — the
 * protocol libraries never log, never install handlers, never malloc.
 */
#define _POSIX_C_SOURCE 200809L

#include "run.h"

#include "config.h"
#include "util.h"

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_transport.h"

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Bounded sleep between ticks. The transport exposes no socket fd in
 * v1.0, so the loop cannot block on socket-readable; it sleeps at most
 * this long before the next tick. Inbound packets are therefore picked
 * up within this latency bound, at the cost of idle wakeups (~20/s).
 * When the transport grows an fd accessor this becomes a real poll()
 * wait, per the idiomatic loop in ants_transport.h. */
#define ANTSD_TICK_SLEEP_CAP_MS 50u

/* Transport limits the daemon runs with. Not yet operator-tunable: they
 * move into the config file when a deployment needs different values.
 * idle_timeout is ants_transport.h's recommended default;
 * max_connections is sized for DHT degree (20-50, RFC-0002) plus gossip
 * fanout (6-12, RFC-0004) plus margin. */
#define ANTSD_IDLE_TIMEOUT_MS      30000u
#define ANTSD_MAX_CONNECTIONS      64u
#define ANTSD_MAX_STREAMS_PER_CONN 64u

/* DHT maintenance cadence — the recommended caller-side defaults from
 * ants_dht.h (bucket refresh, lookup deadline, announce republish). */
#define ANTSD_DHT_REFRESH_MS            60000u
#define ANTSD_DHT_LOOKUP_DEADLINE_MS    5000u
#define ANTSD_DHT_ANNOUNCE_REPUBLISH_MS 1800000u

/* config.h spells the seed-list bound out (it sits below the DHT by
 * design); every config seed must be bootstrappable, so the two bounds
 * must not drift apart. Same compile-time-assertion idiom as
 * foundation/crypto. */
typedef char antsd_seed_capacity_check[(ANTSD_MAX_SEEDS == ANTS_DHT_MAX_BOOTSTRAP_PEERS) ? 1 : -1];

static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* The daemon's composed state, threaded through both event callbacks
 * as their ctx. `dht` stays NULL until ants_dht_init succeeds, so the
 * transport router is safe during the window between the two inits. */
typedef struct {
    ants_dht_t *dht;
    uint64_t conns_ready;
    uint64_t conns_closed;
    uint64_t dht_peers;
} antsd_node_t;

/* The daemon's event demux. Every event is forwarded to the DHT first
 * (it consumes the ones belonging to its in-flight RPCs and ignores the
 * rest — cheap no-op, per ants_dht.h's delegation contract); connection
 * lifecycle is then logged. Remaining stream events have no local
 * consumer yet — gossip plugs in here next. */
static ants_error_t event_router(const ants_transport_event_t *ev, void *ctx)
{
    antsd_node_t *node = (antsd_node_t *)ctx;
    if (node->dht != NULL) {
        (void)ants_dht_handle_transport_event(node->dht, ev);
    }
    char hex[ANTS_PEER_ID_SIZE * 2 + 1];
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        node->conns_ready++;
        antsd_hex_format(ev->peer_id.bytes, sizeof ev->peer_id.bytes, hex, sizeof hex);
        printf("antsd: conn ready peer=%s\n", hex);
        break;
    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        node->conns_closed++;
        antsd_hex_format(ev->peer_id.bytes, sizeof ev->peer_id.bytes, hex, sizeof hex);
        printf("antsd: conn closed peer=%s\n", hex);
        break;
    default:
        break;
    }
    return ANTS_OK;
}

/* DHT event demux: routing-table membership is logged (it is the
 * node's emerging view of the network); lookup/announce completions
 * get consumers when the upper layers arrive. */
static ants_error_t dht_event_router(const ants_dht_event_t *ev, void *ctx)
{
    antsd_node_t *node = (antsd_node_t *)ctx;
    char hex[ANTS_PEER_ID_SIZE * 2 + 1];
    switch (ev->kind) {
    case ANTS_DHT_EV_PEER_DISCOVERED:
        node->dht_peers++;
        antsd_hex_format(ev->peer.peer_id.bytes, sizeof ev->peer.peer_id.bytes, hex, sizeof hex);
        printf("antsd: dht peer discovered peer=%s addr=%s\n", hex, ev->peer.multiaddr);
        break;
    case ANTS_DHT_EV_PEER_EVICTED:
        if (node->dht_peers > 0) {
            node->dht_peers--;
        }
        antsd_hex_format(ev->peer.peer_id.bytes, sizeof ev->peer.peer_id.bytes, hex, sizeof hex);
        printf("antsd: dht peer evicted peer=%s\n", hex);
        break;
    case ANTS_DHT_EV_BOOTSTRAP_COMPLETE:
        /* The seed answered our self-FIND_NODE — the join round-trip
         * worked, not just the handshake. */
        antsd_hex_format(ev->peer.peer_id.bytes, sizeof ev->peer.peer_id.bytes, hex, sizeof hex);
        printf("antsd: dht bootstrap complete peer=%s\n", hex);
        break;
    default:
        break;
    }
    return ANTS_OK;
}

/* The minimal in-memory-key sign callback from ants_transport.h:
 * sign_ctx is the config's Ed25519 private seed. The transport itself
 * never sees the key. */
static ants_error_t sign_with_identity(const uint8_t *transcript,
                                       size_t transcript_len,
                                       uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                                       void *sign_ctx)
{
    return ants_ed25519_sign((const uint8_t *)sign_ctx, transcript, transcript_len, out_sig);
}

static void sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    /* An early EINTR return on SIGINT/SIGTERM is exactly what we want:
     * the loop re-checks g_stop immediately. */
    nanosleep(&ts, NULL);
}

int antsd_cmd_run(const char *path)
{
    /* Line-buffer stdout even when it is a pipe: a supervisor (or the
     * integration test) must see the "listening" line as soon as the
     * socket is bound, not when the stdio buffer happens to fill. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    if (antsd_read_file(path, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "antsd: could not read %s (missing or too large)\n", path);
        return 1;
    }
    antsd_config_t cfg;
    ants_error_t rc = antsd_config_decode(buf, len, &cfg);
    /* The raw encoding holds the identity seed; drop it now that the
     * struct owns the only copy we need. */
    memset(buf, 0, sizeof buf);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: malformed config: %s\n", ants_strerror(rc));
        return 1;
    }

    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    rc = ants_ed25519_pubkey_from_priv(cfg.identity_priv, pub);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: key derivation failed: %s\n", ants_strerror(rc));
        return 1;
    }
    char hex[ANTS_ED25519_PUBKEY_SIZE * 2 + 1];
    antsd_hex_format(pub, sizeof pub, hex, sizeof hex);
    printf("antsd: peer id %s\n", hex);

    /* Stop on SIGINT/SIGTERM; the handlers only set a flag the loop
     * polls. No SA_RESTART: a signal during the bounded sleep wakes it
     * early, so shutdown is immediate. SIGPIPE is ignored — a dying
     * supervisor pipe must not kill the node. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        fprintf(stderr, "antsd: sigaction failed\n");
        return 1;
    }
    struct sigaction ign;
    memset(&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    if (sigaction(SIGPIPE, &ign, NULL) != 0) {
        fprintf(stderr, "antsd: sigaction failed\n");
        return 1;
    }

    antsd_node_t node;
    memset(&node, 0, sizeof node);
    ants_transport_config_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, pub, sizeof pub);
    tcfg.sign_fn = sign_with_identity;
    tcfg.sign_ctx = cfg.identity_priv;
    tcfg.listen_multiaddr = cfg.listen_multiaddr[0] != '\0' ? cfg.listen_multiaddr : NULL;
    tcfg.idle_timeout_ms = ANTSD_IDLE_TIMEOUT_MS;
    tcfg.max_connections = ANTSD_MAX_CONNECTIONS;
    tcfg.max_streams_per_conn = ANTSD_MAX_STREAMS_PER_CONN;
    tcfg.event_fn = event_router;
    tcfg.event_ctx = &node;

    /* 16 KB of opaque picoquic state — static keeps it off the stack. */
    static ants_transport_t transport;
    memset(&transport, 0, sizeof transport);
    rc = ants_transport_init(&transport, &tcfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: transport init failed: %s\n", ants_strerror(rc));
        return 1;
    }

    if (tcfg.listen_multiaddr != NULL) {
        /* Report the actually-bound address: the config may say port 0
         * (kernel-assigned), and dialers need the real one. */
        char addr[ANTS_MULTIADDR_MAX_LEN];
        rc = ants_transport_local_addr(&transport, addr, sizeof addr);
        if (rc != ANTS_OK) {
            fprintf(stderr, "antsd: local addr unavailable: %s\n", ants_strerror(rc));
            ants_transport_destroy(&transport, 0);
            return 1;
        }
        printf("antsd: listening %s\n", addr);
    } else {
        printf("antsd: dial-only (no listener)\n");
    }

    /* 32 KB of routing-table + lookup state — static, off the stack. */
    static ants_dht_t dht;
    memset(&dht, 0, sizeof dht);
    ants_dht_config_t dhtcfg;
    memset(&dhtcfg, 0, sizeof dhtcfg);
    dhtcfg.transport = &transport;
    memcpy(dhtcfg.local_peer_id.bytes, pub, sizeof pub);
    dhtcfg.event_fn = dht_event_router;
    dhtcfg.event_ctx = &node;
    dhtcfg.refresh_interval_ms = ANTSD_DHT_REFRESH_MS;
    dhtcfg.lookup_deadline_ms = ANTSD_DHT_LOOKUP_DEADLINE_MS;
    dhtcfg.announce_republish_ms = ANTSD_DHT_ANNOUNCE_REPUBLISH_MS;
    rc = ants_dht_init(&dht, &dhtcfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: dht init failed: %s\n", ants_strerror(rc));
        ants_transport_destroy(&transport, 0);
        return 1;
    }
    node.dht = &dht;

    /* Seed the routing table. A failed seed is logged and skipped —
     * the node can still be ignited by the remaining seeds or by
     * inbound connections. */
    for (size_t i = 0; i < cfg.seed_count; i++) {
        ants_peer_id_t seed_id;
        memcpy(seed_id.bytes, cfg.seeds[i].peer_id, sizeof seed_id.bytes);
        rc = ants_dht_bootstrap(&dht, cfg.seeds[i].addr, &seed_id);
        if (rc != ANTS_OK) {
            fprintf(stderr,
                    "antsd: bootstrap via %s failed: %s\n",
                    cfg.seeds[i].addr,
                    ants_strerror(rc));
        } else {
            printf("antsd: bootstrapping via %s\n", cfg.seeds[i].addr);
        }
    }

    while (!g_stop) {
        uint32_t t_wait = ants_transport_tick(&transport);
        uint32_t d_wait = ants_dht_tick(&dht);
        if (g_stop) {
            break;
        }
        uint32_t wait_ms = t_wait < d_wait ? t_wait : d_wait;
        uint32_t nap = wait_ms < ANTSD_TICK_SLEEP_CAP_MS ? wait_ms : ANTSD_TICK_SLEEP_CAP_MS;
        if (nap > 0) {
            sleep_ms(nap);
        }
    }

    printf("antsd: shutting down (conns ready %" PRIu64 ", closed %" PRIu64 ", dht peers %" PRIu64
           ")\n",
           node.conns_ready,
           node.conns_closed,
           node.dht_peers);
    /* Teardown order matters: the transport goes first, so its
     * CONN_CLOSED callbacks still reach the DHT (via the router above)
     * and let it release any bootstrap-owned connection state; only
     * then is the DHT itself destroyed. See the teardown note in
     * network/dht/tests/test_dht.c. */
    ants_transport_destroy(&transport, 0);
    ants_dht_destroy(&dht);
    memset(cfg.identity_priv, 0, sizeof cfg.identity_priv);
    return 0;
}
