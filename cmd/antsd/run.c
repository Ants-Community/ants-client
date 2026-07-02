/*
 * cmd/antsd/run.c — `antsd run`: the node's event loop.
 *
 * Stands the QUIC transport up from the config and drives the
 * single-threaded tick loop until SIGINT/SIGTERM. The event callback
 * here is the daemon's central demux: subsequent PRs route DHT, gossip
 * and chain traffic out of it to the component handlers; today it logs
 * connection lifecycle and counts events. Logging and signal handling
 * live in the daemon by design — the protocol libraries never log,
 * never install handlers, never malloc.
 */
#define _POSIX_C_SOURCE 200809L

#include "run.h"

#include "config.h"
#include "util.h"

#include "ants_common.h"
#include "ants_crypto.h"
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

static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

typedef struct {
    uint64_t conns_ready;
    uint64_t conns_closed;
} antsd_stats_t;

/* The daemon's event demux. Connection lifecycle is logged; stream
 * events have no consumer yet — the DHT and gossip handlers plug in
 * here in later PRs. */
static ants_error_t event_router(const ants_transport_event_t *ev, void *ctx)
{
    antsd_stats_t *stats = (antsd_stats_t *)ctx;
    char hex[ANTS_PEER_ID_SIZE * 2 + 1];
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        stats->conns_ready++;
        antsd_hex_format(ev->peer_id.bytes, sizeof ev->peer_id.bytes, hex, sizeof hex);
        printf("antsd: conn ready peer=%s\n", hex);
        break;
    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        stats->conns_closed++;
        antsd_hex_format(ev->peer_id.bytes, sizeof ev->peer_id.bytes, hex, sizeof hex);
        printf("antsd: conn closed peer=%s\n", hex);
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

    antsd_stats_t stats = {0, 0};
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
    tcfg.event_ctx = &stats;

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

    while (!g_stop) {
        uint32_t wait_ms = ants_transport_tick(&transport);
        if (g_stop) {
            break;
        }
        uint32_t nap = wait_ms < ANTSD_TICK_SLEEP_CAP_MS ? wait_ms : ANTSD_TICK_SLEEP_CAP_MS;
        if (nap > 0) {
            sleep_ms(nap);
        }
    }

    printf("antsd: shutting down (conns ready %" PRIu64 ", closed %" PRIu64 ")\n",
           stats.conns_ready,
           stats.conns_closed);
    ants_transport_destroy(&transport, 0);
    memset(cfg.identity_priv, 0, sizeof cfg.identity_priv);
    return 0;
}
