/*
 * cmd/antsd/run.c — `antsd run`: the node's event loop.
 *
 * Stands the QUIC transport, the Kademlia DHT and the gossip engine up
 * from the config and drives the single-threaded tick loop until
 * SIGINT/SIGTERM. The transport event callback here is the daemon's
 * central demux: every event is forwarded to the DHT and to the gossip
 * transport binding (each consumes the ones belonging to its own
 * streams/conns, per the delegation contracts in ants_dht.h /
 * ants_gossip.h), then handled locally; the chain loop plugs in the
 * same way in a later PR. The DHT is seeded from the config's
 * bootstrap list; the gossip view is fed from DHT discovery and
 * refreshed on the anti-eclipse epoch cadence (probe + rotated
 * bucket-diverse sample, the composed recipe from ants_dht.h /
 * RFC-0005). Logging and signal handling live in the daemon by design
 * — the protocol libraries never log, never install handlers, never
 * malloc.
 */
#define _POSIX_C_SOURCE 200809L

#include "run.h"

#include "config.h"
#include "util.h"

#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_gossip.h"
#include "ants_transport.h"

#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
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

/* Gossip view size: how many peers the daemon keeps in the engine's
 * forwarding view. Comfortably above the default fanout (6) so the
 * rotating selection has room, well under the engine ceiling (64) so
 * epoch rotation actually rotates once the routing table outgrows the
 * view (the S3 property — see ants_dht_sample_peers_rotated). The real
 * number is a testnet calibration. */
#define ANTSD_GOSSIP_VIEW_SIZE 16u

/* Anti-eclipse view-refresh epoch: each epoch runs one unpredictable
 * random-target probe (S2, enriches the table), redraws the view as a
 * rotated bucket-diverse sample (S1+S3), and originates one lazy-pull
 * anti-entropy round (IHAVE). Aligned with the DHT bucket-refresh
 * cadence. */
#define ANTSD_VIEW_REFRESH_MS 60000u

static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* The daemon's composed state, threaded through the event callbacks as
 * their ctx. The component pointers stay NULL until their inits
 * succeed, so the routers are safe during the start-up window. `view`
 * is the daemon's copy of what it last put into the gossip engine's
 * peer view — the engine has no enumerate API, and the epoch refresh
 * needs the previous draw to diff against. */
typedef struct {
    ants_dht_t *dht;
    ants_gossip_t *gossip;
    ants_gossip_transport_t *gossip_binding;
    uint64_t conns_ready;
    uint64_t conns_closed;
    uint64_t dht_peers;
    ants_peer_id_t view[ANTSD_GOSSIP_VIEW_SIZE];
    size_t view_count;
} antsd_node_t;

static bool view_contains(const ants_peer_id_t *view, size_t n, const uint8_t *peer_id)
{
    for (size_t i = 0; i < n; i++) {
        if (memcmp(view[i].bytes, peer_id, ANTS_PEER_ID_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/* Add a peer to the gossip view (engine + the daemon's tracking copy),
 * logging genuinely new entries. Idempotent. */
static void gossip_view_add(antsd_node_t *node, const uint8_t *peer_id)
{
    if (node->gossip == NULL || view_contains(node->view, node->view_count, peer_id)) {
        return;
    }
    if (node->view_count >= ANTSD_GOSSIP_VIEW_SIZE) {
        return; /* full — the next epoch redraw decides who stays */
    }
    if (ants_gossip_add_peer(node->gossip, peer_id) != ANTS_OK) {
        return;
    }
    memcpy(node->view[node->view_count].bytes, peer_id, ANTS_PEER_ID_SIZE);
    node->view_count++;
    char hex[ANTS_PEER_ID_SIZE * 2 + 1];
    antsd_hex_format(peer_id, ANTS_PEER_ID_SIZE, hex, sizeof hex);
    printf("antsd: gossip view add peer=%s\n", hex);
}

/* Remove a peer from the gossip view (engine + tracking copy). */
static void gossip_view_drop(antsd_node_t *node, const uint8_t *peer_id)
{
    if (node->gossip == NULL) {
        return;
    }
    for (size_t i = 0; i < node->view_count; i++) {
        if (memcmp(node->view[i].bytes, peer_id, ANTS_PEER_ID_SIZE) != 0) {
            continue;
        }
        (void)ants_gossip_remove_peer(node->gossip, peer_id);
        node->view[i] = node->view[node->view_count - 1];
        node->view_count--;
        char hex[ANTS_PEER_ID_SIZE * 2 + 1];
        antsd_hex_format(peer_id, ANTS_PEER_ID_SIZE, hex, sizeof hex);
        printf("antsd: gossip view drop peer=%s\n", hex);
        return;
    }
}

/* The daemon's event demux. Every event is forwarded to the DHT and to
 * the gossip transport binding first (each consumes the ones belonging
 * to its own streams/conns and ignores the rest — cheap no-ops, per
 * the delegation contracts); connection lifecycle is then logged. */
static ants_error_t event_router(const ants_transport_event_t *ev, void *ctx)
{
    antsd_node_t *node = (antsd_node_t *)ctx;
    if (node->dht != NULL) {
        (void)ants_dht_handle_transport_event(node->dht, ev);
    }
    if (node->gossip_binding != NULL) {
        (void)ants_gossip_transport_handle_event(node->gossip_binding, ev);
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
 * node's emerging view of the network) and mirrored into the gossip
 * view between epoch redraws; lookup/announce completions get
 * consumers when the upper layers arrive. */
static ants_error_t dht_event_router(const ants_dht_event_t *ev, void *ctx)
{
    antsd_node_t *node = (antsd_node_t *)ctx;
    char hex[ANTS_PEER_ID_SIZE * 2 + 1];
    switch (ev->kind) {
    case ANTS_DHT_EV_PEER_DISCOVERED:
        node->dht_peers++;
        antsd_hex_format(ev->peer.peer_id.bytes, sizeof ev->peer.peer_id.bytes, hex, sizeof hex);
        printf("antsd: dht peer discovered peer=%s addr=%s\n", hex, ev->peer.multiaddr);
        gossip_view_add(node, ev->peer.peer_id.bytes);
        break;
    case ANTS_DHT_EV_PEER_EVICTED:
        if (node->dht_peers > 0) {
            node->dht_peers--;
        }
        antsd_hex_format(ev->peer.peer_id.bytes, sizeof ev->peer.peer_id.bytes, hex, sizeof hex);
        printf("antsd: dht peer evicted peer=%s\n", hex);
        gossip_view_drop(node, ev->peer.peer_id.bytes);
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

/* One anti-eclipse epoch (the composed per-epoch refresh documented in
 * ants_dht.h / RFC-0005 §Anti-eclipse peer sampling):
 *   S2  — one unpredictable random-target probe enriches the table
 *         (verified-only fold, enrich-never-displace);
 *   S1+S3 — the view is redrawn as a rotated bucket-diverse sample, so
 *         a static eclipse cannot lock in;
 *   and one lazy-pull anti-entropy round (IHAVE) rides the cadence.
 * The previous epoch's probe handle is cancelled first (idempotent on
 * completed probes) — at most one probe in flight, per ants_dht.h. */
static void gossip_view_refresh(antsd_node_t *node,
                                ants_dht_t *dht,
                                ants_dht_lookup_t *probe,
                                bool *probe_active,
                                uint64_t *epoch)
{
    if (*probe_active) {
        (void)ants_dht_lookup_cancel(probe);
        *probe_active = false;
    }
    uint64_t random_key = 0;
    if (antsd_read_random((uint8_t *)&random_key, sizeof random_key) == 0) {
        if (ants_dht_probe(dht, random_key, probe) == ANTS_OK) {
            *probe_active = true;
        }
    }

    ants_dht_peer_t sample[ANTSD_GOSSIP_VIEW_SIZE];
    size_t n = ants_dht_sample_peers_rotated(dht, *epoch, sample, ANTSD_GOSSIP_VIEW_SIZE);
    (*epoch)++;
    if (n > 0) {
        /* Drop view entries that fell out of the draw, then adopt it. */
        ants_peer_id_t previous[ANTSD_GOSSIP_VIEW_SIZE];
        size_t previous_count = node->view_count;
        memcpy(previous, node->view, sizeof previous);
        for (size_t i = 0; i < previous_count; i++) {
            bool kept = false;
            for (size_t j = 0; j < n; j++) {
                if (memcmp(previous[i].bytes, sample[j].peer_id.bytes, ANTS_PEER_ID_SIZE) == 0) {
                    kept = true;
                    break;
                }
            }
            if (!kept) {
                gossip_view_drop(node, previous[i].bytes);
            }
        }
        for (size_t j = 0; j < n; j++) {
            gossip_view_add(node, sample[j].peer_id.bytes);
        }
    }

    size_t sent = 0;
    if (node->gossip != NULL) {
        (void)ants_gossip_announce(node->gossip, &sent);
    }
    if (sent > 0) {
        printf("antsd: gossip announce sent=%zu\n", sent);
    }
    /* One health line per epoch: a table that stops growing across
     * epochs on a live network means probe enrichment has stalled
     * (e.g. the DHT's pending-dial slots are exhausted — a known v1
     * capacity limit) and is worth an operator's attention. */
    printf("antsd: epoch %" PRIu64 " table=%zu view=%zu\n",
           *epoch,
           ants_dht_routing_table_size(dht),
           node->view_count);
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

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
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

    /* The gossip stack: the L1 G-Set the engine disseminates into, the
     * transport binding, then the engine itself — binding before engine
     * per the wiring order in ants_gossip.h (the binding captures the
     * engine pointer early; the engine gets the binding as send_ctx).
     * Engine defaults (fanout 6, 4 KiB frame cap) apply. */
    ants_crdt_t *gset = NULL;
    rc = ants_crdt_init(&gset);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: g-set init failed: %s\n", ants_strerror(rc));
        ants_transport_destroy(&transport, 0);
        ants_dht_destroy(&dht);
        return 1;
    }
    /* 8 KB engine + 16 KB binding — static, off the stack. */
    static ants_gossip_t gossip;
    static ants_gossip_transport_t gossip_binding;
    memset(&gossip, 0, sizeof gossip);
    memset(&gossip_binding, 0, sizeof gossip_binding);
    rc = ants_gossip_transport_init(&gossip_binding, &gossip, &transport);
    if (rc == ANTS_OK) {
        rc =
            ants_gossip_init(&gossip, gset, pub, NULL, ants_gossip_transport_send, &gossip_binding);
    }
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: gossip init failed: %s\n", ants_strerror(rc));
        ants_transport_destroy(&transport, 0);
        ants_gossip_transport_destroy(&gossip_binding);
        ants_dht_destroy(&dht);
        ants_crdt_destroy(gset);
        return 1;
    }
    node.gossip = &gossip;
    node.gossip_binding = &gossip_binding;

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

    /* Anti-eclipse epoch state. The first refresh runs one interval in:
     * at startup the view is fed by bootstrap discovery, and a probe
     * before any peer is in the table would be a no-op. */
    static ants_dht_lookup_t probe;
    memset(&probe, 0, sizeof probe);
    bool probe_active = false;
    uint64_t epoch = 0;
    uint64_t last_refresh_ms = monotonic_ms();

    while (!g_stop) {
        uint32_t t_wait = ants_transport_tick(&transport);
        uint32_t d_wait = ants_dht_tick(&dht);
        if (g_stop) {
            break;
        }
        if (monotonic_ms() - last_refresh_ms >= ANTSD_VIEW_REFRESH_MS) {
            last_refresh_ms = monotonic_ms();
            gossip_view_refresh(&node, &dht, &probe, &probe_active, &epoch);
        }
        uint32_t wait_ms = t_wait < d_wait ? t_wait : d_wait;
        uint32_t nap = wait_ms < ANTSD_TICK_SLEEP_CAP_MS ? wait_ms : ANTSD_TICK_SLEEP_CAP_MS;
        if (nap > 0) {
            sleep_ms(nap);
        }
    }

    printf("antsd: shutting down (conns ready %" PRIu64 ", closed %" PRIu64 ", dht peers %" PRIu64
           ", view %zu)\n",
           node.conns_ready,
           node.conns_closed,
           node.dht_peers,
           node.view_count);
    /* Teardown order matters: the transport goes first, so its
     * CONN_CLOSED callbacks still reach the DHT and the gossip binding
     * (via the router above) and let them release the connection state
     * they own (bootstrap conns, retained outbound stream handles);
     * only then are the components themselves destroyed. See the
     * teardown notes in network/dht/tests/test_dht.c and
     * ants_gossip.h. */
    ants_transport_destroy(&transport, 0);
    ants_gossip_transport_destroy(&gossip_binding);
    ants_dht_destroy(&dht);
    ants_crdt_destroy(gset);
    memset(cfg.identity_priv, 0, sizeof cfg.identity_priv);
    return 0;
}
