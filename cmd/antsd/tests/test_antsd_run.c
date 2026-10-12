/*
 * test_antsd_run.c — integration test for `antsd run`.
 *
 * Spawns the real antsd binary (its path arrives as argv[1], wired by
 * CTest as $<TARGET_FILE:antsd>) with a config whose identity is a
 * fixed test seed, reads the daemon's "listening" line off a pipe,
 * dials the advertised multiaddr over loopback QUIC with
 * expected_peer_id pinned to the config-derived pubkey, and requires:
 *
 *   - the dialer observes CONN_READY: the daemon's tick loop is alive
 *     and its sign_fn signs with the config identity — a wrong key
 *     would fail the RFC 7250 pin with PEER_MISMATCH, not READY;
 *   - the daemon's event router logs its own CONN_READY carrying the
 *     dialer's pubkey (mutual TLS gives the listener the client key);
 *   - after the dialer disconnects, the daemon logs CONN_CLOSED with
 *     the SAME peer id (the transport mirrors the pubkey into close
 *     events too — ready/closed pairs stay correlatable per peer);
 *   - SIGTERM produces a clean exit (status 0). Under the Debug
 *     ASan/UBSan CI jobs that also proves the shutdown path tears the
 *     transport down without leaking.
 *
 * A second spawn exercises the DHT wiring end-to-end: the test runs an
 * in-process seed node (transport + DHT, the same composition the
 * daemon uses), puts it in the config's bootstrap list, and requires
 * the daemon to dial it (pinned to the seed's peer id), complete the
 * bootstrap self-FIND_NODE against the seed's server dispatcher —
 * asserted via the daemon's "dht bootstrap complete" line, which fires
 * only when the seed's response arrives — and log the seed's discovery
 * into its routing table.
 *
 * Inference serving (RFC-0008 §11.14): the test runs the real `antsd ask`
 * against the spawned daemon and requires an answer that checks out —
 * signed by the daemon's identity, under the pinned v1 model hash, round 0
 * with the chain off — a decline for a tier the node does not serve, and
 * no answer from a node whose peer-id does not match the pin. The answer is
 * paid for with a receipt (§11.15) the daemon countersigns and files; a
 * restart reloads the bag from disk — skipping a record whose signature was
 * corrupted and cutting a torn final record, so a receipt filed after the
 * restart is readable — and `antsd receipts` reads the same bag.
 *
 * Plus the cheap failure path: `antsd run <missing-file>` exits 1.
 *
 * Every wait is bounded by a wall-clock deadline and every child is
 * reaped (SIGKILL on overrun), so a regression fails the test rather
 * than hanging CI.
 */

/* POSIX feature test — required on glibc to expose nanosleep(),
 * clock_gettime(), mkstemp() and friends. Mirrors the same block in
 * network/transport/tests/test_transport.c. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include "ants_attest.h"
#include "ants_chain_runtime.h"
#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_gossip.h"
#include "ants_tee.h"
#include "ants_transport.h"

#include "tdx_kat_vectors.h"

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

/* Wall-clock deadlines, generous for CI scheduling variance; the green
 * path exits each wait as soon as its predicate holds. */
#define READY_DEADLINE_MS     15000
#define HANDSHAKE_DEADLINE_MS 15000
#define EXIT_DEADLINE_MS      10000

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* 1 ms pacing for tick spin-loops — same rationale as tick_pace() in
 * test_transport.c: picoquic's timers run off the wall clock. */
static void tick_pace(void)
{
    struct timespec ts = {0, 1000000L};
    nanosleep(&ts, NULL);
}

static void hex_format(const uint8_t *bytes, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

static ants_error_t real_sign(const uint8_t *transcript,
                              size_t transcript_len,
                              uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                              void *sign_ctx)
{
    return ants_ed25519_sign((const uint8_t *)sign_ctx, transcript, transcript_len, out_sig);
}

typedef struct {
    int conn_ready;
    int conn_closed;
} recorder_t;

static ants_error_t recording_event(const ants_transport_event_t *ev, void *ctx)
{
    recorder_t *r = (recorder_t *)ctx;
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        r->conn_ready++;
        break;
    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        r->conn_closed++;
        break;
    default:
        break;
    }
    return ANTS_OK;
}

/* Spawn `antsd run <cfg_path>` with its stdout piped back to us.
 * Returns the read end of the pipe (and the pid via *out_pid), or -1. */
static int spawn_run(const char *antsd_path, const char *cfg_path, pid_t *out_pid)
{
    int p[2];
    if (pipe(p) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(p[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(p[0]);
        close(p[1]);
        execl(antsd_path, "antsd", "run", cfg_path, (char *)NULL);
        _exit(127); /* exec failed */
    }
    close(p[1]);
    *out_pid = pid;
    return p[0];
}

/* Everything the daemon prints, accumulated NUL-terminated so the test
 * can strstr() it. 64 KB is orders of magnitude above the handful of
 * lines `antsd run` emits. */
typedef struct {
    char data[65536];
    size_t len;
} capture_t;

/* Pull whatever is available on fd into c, waiting at most wait_ms.
 * Returns >0 on bytes read, 0 on timeout, -1 on EOF/error/overflow. */
static int capture_pump(int fd, capture_t *c, int wait_ms)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, wait_ms);
    if (pr <= 0) {
        return 0; /* timeout, or EINTR treated as one */
    }
    if (c->len >= sizeof c->data - 1) {
        return -1;
    }
    ssize_t r = read(fd, c->data + c->len, sizeof c->data - 1 - c->len);
    if (r <= 0) {
        return -1; /* EOF or error */
    }
    c->len += (size_t)r;
    c->data[c->len] = '\0';
    return (int)r;
}

/* Wait until the captured output contains `needle`, EOF, or the
 * absolute deadline. While waiting, optionally tick a transport (and a
 * DHT riding on it) so our side of the QUIC/RPC exchange can progress
 * while we watch the daemon's log. */
/* Extra work to run on every iteration of wait_for_output (the in-process
 * seed's chain runtime, which needs its clock driven); NULL when unused. */
static void (*g_extra_tick)(void) = NULL;

static const char *wait_for_output(int fd,
                                   capture_t *c,
                                   const char *needle,
                                   uint64_t deadline,
                                   ants_transport_t *tick,
                                   ants_dht_t *dht_tick)
{
    for (;;) {
        const char *hit = strstr(c->data, needle);
        if (hit != NULL) {
            return hit;
        }
        if (now_ms() >= deadline) {
            return NULL;
        }
        if (tick != NULL) {
            ants_transport_tick(tick);
        }
        if (dht_tick != NULL) {
            ants_dht_tick(dht_tick);
        }
        if (g_extra_tick != NULL) {
            g_extra_tick();
        }
        if (capture_pump(fd, c, tick != NULL ? 1 : 50) < 0) {
            return strstr(c->data, needle); /* EOF: last look */
        }
    }
}

/* Extract the multiaddr from a complete "antsd: listening <addr>\n"
 * line. Returns 0 on success. */
static int extract_listen_addr(const capture_t *c, char *out, size_t cap)
{
    static const char tag[] = "antsd: listening ";
    const char *p = strstr(c->data, tag);
    if (p == NULL) {
        return -1;
    }
    p += sizeof tag - 1;
    const char *nl = strchr(p, '\n');
    if (nl == NULL) {
        return -1; /* line not complete yet — pump more */
    }
    size_t n = (size_t)(nl - p);
    if (n == 0 || n >= cap) {
        return -1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

/* Reap `pid` within deadline_ms; SIGKILL + reap on overrun. Returns the
 * wait status, or -1 if the child had to be killed. */
static int reap_with_deadline(pid_t pid, int deadline_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)deadline_ms;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            return status;
        }
        if (r < 0) {
            return -1;
        }
        if (now_ms() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;
        }
        struct timespec ts = {0, 10000000L}; /* 10 ms */
        nanosleep(&ts, NULL);
    }
}

static void test_run_missing_config(const char *antsd_path)
{
    pid_t pid = -1;
    int fd = spawn_run(antsd_path, "/nonexistent/antsd-test-config", &pid);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    close(fd);
}

static void test_run_serves_and_shuts_down(const char *antsd_path)
{
    /* Fixed identity seed → deterministic daemon peer id the dialer can
     * pin. Port 0: the kernel assigns; the daemon must advertise it. */
    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.identity_priv, 0x33, sizeof cfg.identity_priv);
    static const char listen[] = "/ip4/127.0.0.1/udp/0/quic-v1";
    memcpy(cfg.listen_multiaddr, listen, sizeof listen);

    uint8_t daemon_pub[ANTS_ED25519_PUBKEY_SIZE];
    CHECK(ants_ed25519_pubkey_from_priv(cfg.identity_priv, daemon_pub) == ANTS_OK);

    uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len = 0;
    CHECK(antsd_config_encode(&cfg, enc, sizeof enc, &enc_len) == ANTS_OK);

    char cfg_path[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(cfg_path, sizeof cfg_path, "%s/antsd_run_XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    int cfd = mkstemp(cfg_path);
    CHECK(cfd >= 0);
    if (cfd < 0) {
        return;
    }
    CHECK(write(cfd, enc, enc_len) == (ssize_t)enc_len);
    CHECK(close(cfd) == 0);

    pid_t pid = -1;
    int out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd < 0) {
        unlink(cfg_path);
        return;
    }

    static capture_t cap; /* 64 KB — off the stack */
    memset(&cap, 0, sizeof cap);

    /* 1. The daemon must advertise its bound address. */
    char addr[ANTS_MULTIADDR_MAX_LEN];
    int have_addr = -1;
    uint64_t deadline = now_ms() + READY_DEADLINE_MS;
    for (;;) {
        have_addr = extract_listen_addr(&cap, addr, sizeof addr);
        if (have_addr == 0 || now_ms() >= deadline) {
            break;
        }
        if (capture_pump(out_fd, &cap, 50) < 0) {
            have_addr = extract_listen_addr(&cap, addr, sizeof addr);
            break;
        }
    }
    CHECK(have_addr == 0);
    if (have_addr != 0) {
        fprintf(stderr, "daemon output so far: <<<%s>>>\n", cap.data);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        close(out_fd);
        unlink(cfg_path);
        return;
    }
    CHECK(strncmp(addr, "/ip4/127.0.0.1/udp/", 19) == 0);
    CHECK(strstr(addr, "/quic-v1") != NULL);
    CHECK(atoi(addr + 19) > 0);

    /* 2. Dial it, pinning the peer id to the config identity. */
    uint8_t dialer_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t dialer_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(dialer_priv, 0x44, sizeof dialer_priv);
    CHECK(ants_ed25519_pubkey_from_priv(dialer_priv, dialer_pub) == ANTS_OK);

    recorder_t rec;
    memset(&rec, 0, sizeof rec);
    static ants_transport_t dialer; /* 16 KB — off the stack */
    memset(&dialer, 0, sizeof dialer);
    ants_transport_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    memcpy(dcfg.pub, dialer_pub, sizeof dialer_pub);
    dcfg.sign_fn = real_sign;
    dcfg.sign_ctx = dialer_priv;
    dcfg.event_fn = recording_event;
    dcfg.event_ctx = &rec;
    CHECK(ants_transport_init(&dialer, &dcfg) == ANTS_OK);

    ants_peer_id_t expect;
    memcpy(expect.bytes, daemon_pub, sizeof expect.bytes);
    ants_transport_conn_t conn = {{0}};
    CHECK(ants_transport_dial(&dialer, addr, &expect, &conn) == ANTS_OK);

    deadline = now_ms() + HANDSHAKE_DEADLINE_MS;
    while (rec.conn_ready == 0 && now_ms() < deadline) {
        ants_transport_tick(&dialer);
        tick_pace();
    }
    CHECK(rec.conn_ready == 1);
    CHECK(rec.conn_closed == 0);

    /* 3. The daemon's event router logged the inbound connection with
     * the dialer's pubkey as the peer id. Keep ticking the dialer while
     * we watch: the daemon may still need our final handshake ACKs. */
    char dialer_hex[ANTS_ED25519_PUBKEY_SIZE * 2 + 1];
    hex_format(dialer_pub, sizeof dialer_pub, dialer_hex);
    char needle[sizeof dialer_hex + 32];
    snprintf(needle, sizeof needle, "antsd: conn ready peer=%s", dialer_hex);
    const char *hit =
        wait_for_output(out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &dialer, NULL);
    CHECK(hit != NULL);

    /* 4. Disconnect: the daemon must log the close with the SAME peer
     * id, not a zeroed one — ready/closed pairs stay correlatable. */
    CHECK(ants_transport_peer_disconnect(&conn, 0) == ANTS_OK);
    snprintf(needle, sizeof needle, "antsd: conn closed peer=%s", dialer_hex);
    hit = wait_for_output(out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &dialer, NULL);
    CHECK(hit != NULL);

    /* 5. SIGTERM → clean exit 0 with the shutdown line. */
    CHECK(kill(pid, SIGTERM) == 0);
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    while (capture_pump(out_fd, &cap, 100) > 0) {
    }
    CHECK(strstr(cap.data, "antsd: shutting down") != NULL);

    if (failures > 0) {
        fprintf(stderr, "daemon output: <<<%s>>>\n", cap.data);
    }

    CHECK(ants_transport_destroy(&dialer, 0) == ANTS_OK);
    close(out_fd);
    unlink(cfg_path);
}

/* Transport event forwarder for the in-process seed node: every event
 * goes to the seed's DHT first (its server dispatcher answers the
 * daemon's bootstrap FIND_NODE), CONN_READY is counted. Mirrors the
 * endpoint idiom in network/dht/tests/test_dht.c — and the daemon's own
 * router in run.c. */
typedef struct {
    ants_dht_t *dht;
    ants_attest_t *attest;
    int conn_ready;
    int conn_closed;
    int verdicts;
    ants_attest_result_t last_verdict;
} seed_endpoint_t;

static ants_error_t seed_endpoint_event(const ants_transport_event_t *ev, void *ctx)
{
    seed_endpoint_t *e = (seed_endpoint_t *)ctx;
    if (e->dht != NULL) {
        (void)ants_dht_handle_transport_event(e->dht, ev);
    }
    if (e->attest != NULL) {
        ants_attest_handle_transport_event(e->attest, ev, (int64_t)time(NULL));
    }
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        e->conn_ready++;
    } else if (ev->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        e->conn_closed++;
    }
    return ANTS_OK;
}

static void seed_verdict(const ants_attest_result_t *r, void *ctx)
{
    seed_endpoint_t *e = (seed_endpoint_t *)ctx;
    e->verdicts++;
    e->last_verdict = *r;
}

static ants_error_t noop_dht_event(const ants_dht_event_t *ev, void *ctx)
{
    (void)ev;
    (void)ctx;
    return ANTS_OK;
}

/* `seed_local` NULL: the honest v1 run — bootstrap, gossip view, and the
 * attestation gate admitting each side UNATTESTED. Non-NULL: the seed
 * presents that evidence; the daemon must judge it REJECTED and drop the
 * connection (RFC-0005 verify-and-tag: false evidence → disconnect). */
static void test_run_bootstraps_to_seed(const char *antsd_path,
                                        const ants_attest_presentation_t *seed_local)
{
    /* In-process seed node: listening transport + DHT — the same
     * composition the daemon runs, driven from this process. */
    uint8_t seed_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t seed_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(seed_priv, 0x55, sizeof seed_priv);
    CHECK(ants_ed25519_pubkey_from_priv(seed_priv, seed_pub) == ANTS_OK);

    seed_endpoint_t ep;
    memset(&ep, 0, sizeof ep);
    static ants_transport_t seed_transport; /* 16 KB — off the stack */
    memset(&seed_transport, 0, sizeof seed_transport);
    ants_transport_config_t scfg;
    memset(&scfg, 0, sizeof scfg);
    memcpy(scfg.pub, seed_pub, sizeof seed_pub);
    scfg.sign_fn = real_sign;
    scfg.sign_ctx = seed_priv;
    scfg.event_fn = seed_endpoint_event;
    scfg.event_ctx = &ep;
    scfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK(ants_transport_init(&seed_transport, &scfg) == ANTS_OK);
    char seed_addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK(ants_transport_local_addr(&seed_transport, seed_addr, sizeof seed_addr) == ANTS_OK);

    static ants_dht_t seed_dht; /* 32 KB — off the stack */
    memset(&seed_dht, 0, sizeof seed_dht);
    ants_dht_config_t sdcfg;
    memset(&sdcfg, 0, sizeof sdcfg);
    sdcfg.transport = &seed_transport;
    memcpy(sdcfg.local_peer_id.bytes, seed_pub, sizeof seed_pub);
    sdcfg.event_fn = noop_dht_event;
    sdcfg.event_ctx = &ep;
    /* Timers 0: no automatic refresh — the test drives everything. */
    CHECK(ants_dht_init(&seed_dht, &sdcfg) == ANTS_OK);
    ep.dht = &seed_dht;

    /* The seed also runs the attestation gate, sharing the connection
     * (and its bidi streams) with the DHT — both directions of the
     * §11.12 exchange then ride alongside the bootstrap RPCs. */
    static ants_attest_t seed_attest; /* 32 KB — off the stack */
    ants_attest_config_t sacfg;
    memset(&sacfg, 0, sizeof sacfg);
    sacfg.local = seed_local;
    sacfg.freshness_window_seconds = ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS;
    sacfg.request_on_ready = true;
    sacfg.verdict_fn = seed_verdict;
    sacfg.verdict_ctx = &ep;
    CHECK(ants_attest_init(&seed_attest, &sacfg) == ANTS_OK);
    ep.attest = &seed_attest;

    /* Daemon config: fixed identity, a listener, and the seed in the
     * bootstrap list. */
    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.identity_priv, 0x33, sizeof cfg.identity_priv);
    static const char listen[] = "/ip4/127.0.0.1/udp/0/quic-v1";
    memcpy(cfg.listen_multiaddr, listen, sizeof listen);
    CHECK(strlen(seed_addr) < sizeof cfg.seeds[0].addr);
    memcpy(cfg.seeds[0].addr, seed_addr, strlen(seed_addr));
    memcpy(cfg.seeds[0].peer_id, seed_pub, sizeof cfg.seeds[0].peer_id);
    cfg.seed_count = 1;

    uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len = 0;
    CHECK(antsd_config_encode(&cfg, enc, sizeof enc, &enc_len) == ANTS_OK);

    char cfg_path[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(cfg_path, sizeof cfg_path, "%s/antsd_seed_XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    int cfd = mkstemp(cfg_path);
    CHECK(cfd >= 0);
    if (cfd < 0) {
        return;
    }
    CHECK(write(cfd, enc, enc_len) == (ssize_t)enc_len);
    CHECK(close(cfd) == 0);

    pid_t pid = -1;
    int out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd < 0) {
        unlink(cfg_path);
        return;
    }

    static capture_t cap;
    memset(&cap, 0, sizeof cap);

    /* The daemon must dial the seed (pinned to its peer id), run the
     * bootstrap self-FIND_NODE against the seed's server dispatcher,
     * and log the completed join round-trip. Waiting on the
     * BOOTSTRAP_COMPLETE line (not the earlier promotion-time
     * "discovered" line) is what forces the full RPC exchange: it only
     * fires after the seed's dispatcher answered our FIND_NODE. We tick
     * the seed's transport + DHT the whole time — it is the other half
     * of the exchange. */
    char seed_hex[ANTS_ED25519_PUBKEY_SIZE * 2 + 1];
    hex_format(seed_pub, sizeof seed_pub, seed_hex);
    char needle[sizeof seed_hex + 48];
    const char *hit = NULL;
    if (seed_local != NULL) {
        /* The daemon verifies the seed's presentation against the seed's
         * AUTHENTICATED peer-id: the genuine quote is not bound to it, so
         * the verdict is REJECTED and the daemon disconnects. The seed
         * observes the close. */
        snprintf(needle, sizeof needle, "antsd: attest peer=%s verdict=rejected", seed_hex);
        hit = wait_for_output(
            out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &seed_transport, &seed_dht);
        CHECK(hit != NULL);
        for (int i = 0; i < 3000 && ep.conn_closed == 0; i++) {
            tick_pace();
            ants_transport_tick(&seed_transport);
        }
        CHECK(ep.conn_closed >= 1);
    } else {
        snprintf(needle, sizeof needle, "antsd: dht bootstrap complete peer=%s", seed_hex);
        hit = wait_for_output(
            out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &seed_transport, &seed_dht);
        CHECK(hit != NULL);
        /* The promotion-time discovery line must have preceded it. */
        snprintf(needle, sizeof needle, "antsd: dht peer discovered peer=%s", seed_hex);
        CHECK(strstr(cap.data, needle) != NULL);
        CHECK(strstr(cap.data, "antsd: bootstrapping via ") != NULL);
        /* Discovery also feeds the gossip view: the seed must have been
         * added as a gossip neighbour. */
        snprintf(needle, sizeof needle, "antsd: gossip view add peer=%s", seed_hex);
        CHECK(strstr(cap.data, needle) != NULL);
        /* Mutual handshake: the seed side saw the daemon connect. */
        CHECK(ep.conn_ready >= 1);

        /* Attestation gate, both directions, on the same connection as the
         * DHT exchange: neither node can present evidence in v1, so each
         * admits the other UNATTESTED (RFC-0005 verify-and-tag). */
        snprintf(needle, sizeof needle, "antsd: attest peer=%s verdict=unattested", seed_hex);
        hit = wait_for_output(
            out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &seed_transport, &seed_dht);
        CHECK(hit != NULL);
        for (int i = 0; i < 2000 && ep.verdicts == 0; i++) {
            tick_pace();
            ants_transport_tick(&seed_transport);
        }
        CHECK(ep.verdicts == 1);
        CHECK(ep.last_verdict.verdict == ANTS_ATTEST_VERDICT_UNATTESTED);
        uint8_t daemon_pub[ANTS_ED25519_PUBKEY_SIZE];
        CHECK(ants_ed25519_pubkey_from_priv(cfg.identity_priv, daemon_pub) == ANTS_OK);
        CHECK(memcmp(ep.last_verdict.peer_id.bytes, daemon_pub, sizeof daemon_pub) == 0);
    }

    /* SIGTERM → clean exit 0 (the daemon tears down transport before
     * DHT; ASan in the child verifies the bootstrap conn is freed). */
    CHECK(kill(pid, SIGTERM) == 0);
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    while (capture_pump(out_fd, &cap, 100) > 0) {
    }
    CHECK(strstr(cap.data, "antsd: shutting down") != NULL);

    if (failures > 0) {
        fprintf(stderr, "daemon output: <<<%s>>>\n", cap.data);
    }

    CHECK(ants_transport_destroy(&seed_transport, 0) == ANTS_OK);
    ants_attest_destroy(&seed_attest);
    CHECK(ants_dht_destroy(&seed_dht) == ANTS_OK);
    close(out_fd);
    unlink(cfg_path);
}

/* ------------------------------------------------------------------------ */
/* L2 chain: two trustees, one of them the spawned daemon                    */
/* ------------------------------------------------------------------------ */

/* The in-process seed for the chain scenario: transport + DHT (so the
 * daemon's bootstrap and gossip-view discovery work as in production) +
 * gossip (binding + engine over its own G-Set) + a trustee chain runtime. */
typedef struct {
    ants_dht_t *dht;
    ants_gossip_transport_t *binding;
    ants_gossip_t *gossip;
    ants_chain_rt_t *rt;     /* NULL until the genesis time arrives */
    ants_chain_rt_t *rt_mem; /* storage, initialised lazily by cs_tick */
    ants_chain_rt_config_t rcfg;
    uint64_t genesis_time;
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t trustees[2][32];
    int finals;
    ants_chain_head_t head;
} chain_seed_t;

static chain_seed_t g_cs;

static ants_error_t cs_event(const ants_transport_event_t *ev, void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    (void)ants_dht_handle_transport_event(c->dht, ev);
    (void)ants_gossip_transport_handle_event(c->binding, ev);
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        (void)ants_gossip_add_peer(c->gossip, ev->peer_id.bytes);
    }
    return ANTS_OK;
}

static ants_error_t cs_sign(const uint8_t hash[32], uint8_t sig[64], void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    return ants_ed25519_sign(c->priv, hash, 32, sig);
}

/* The seed's Layer-1 view: its G-Set is empty, like the daemon's. */
static ants_error_t cs_view(uint64_t cutoff,
                            const uint8_t (**ids)[32],
                            size_t *n_ids,
                            const ants_chain_event_t **events,
                            size_t *n_events,
                            void *ctx)
{
    (void)cutoff;
    (void)ctx;
    *ids = NULL;
    *n_ids = 0;
    *events = NULL;
    *n_events = 0;
    return ANTS_OK;
}

static void cs_out_proposal(const uint8_t *block, size_t len, void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    static uint8_t frame[ANTS_GOSSIP_CHAIN_MAX_BLOCK_FRAME];
    size_t flen = 0;
    if (ants_gossip_block_encode(block, len, frame, sizeof frame, &flen) == ANTS_OK) {
        (void)ants_gossip_broadcast_chain(c->gossip, frame, flen, NULL);
    }
}

static void cs_out_attestation(const ants_chain_attestation_t *att, void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    ants_gossip_attest_t a;
    a.height = att->height;
    memcpy(a.block_hash, att->block_hash, 32);
    memcpy(a.signer, att->signer, 32);
    memcpy(a.sig, att->sig, 64);
    uint8_t frame[256];
    size_t flen = 0;
    if (ants_gossip_attest_encode(&a, frame, sizeof frame, &flen) == ANTS_OK) {
        (void)ants_gossip_broadcast_chain(c->gossip, frame, flen, NULL);
    }
}

static void cs_final(const ants_chain_head_t *head, void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    c->finals++;
    c->head = *head;
}

static ants_error_t
cs_on_chain(const uint8_t *from, uint64_t type, const uint8_t *frame, size_t len, void *ctx)
{
    chain_seed_t *c = (chain_seed_t *)ctx;
    (void)from;
    uint64_t now = (uint64_t)time(NULL);
    if (c->rt == NULL) {
        return ANTS_ERROR_UNSUPPORTED_TYPE; /* before genesis */
    }
    if (type == ANTS_GOSSIP_MSG_BLOCK) {
        const uint8_t *b;
        size_t bl;
        ants_error_t rc = ants_gossip_block_decode(frame, len, &b, &bl);
        return rc != ANTS_OK ? rc : ants_chain_rt_on_proposal(c->rt, b, bl, now);
    }
    ants_gossip_attest_t a;
    if (ants_gossip_attest_decode(frame, len, &a) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    ants_chain_attestation_t att;
    att.height = a.height;
    memcpy(att.block_hash, a.block_hash, 32);
    memcpy(att.signer, a.signer, 32);
    memcpy(att.sig, a.sig, 64);
    return ants_chain_rt_on_attestation(c->rt, &att, now);
}

static void cs_send(const uint8_t peer[32], const uint8_t *frame, size_t len, void *ctx)
{
    ants_gossip_transport_send(peer, frame, len, ctx);
}

static void cs_tick(void)
{
    uint64_t now = (uint64_t)time(NULL);
    if (g_cs.rt == NULL && now >= g_cs.genesis_time) {
        CHECK(ants_chain_rt_init(g_cs.rt_mem, &g_cs.rcfg, now) == ANTS_OK);
        g_cs.rt = g_cs.rt_mem;
    }
    if (g_cs.rt != NULL) {
        ants_chain_rt_tick(g_cs.rt, now);
    }
}

static void test_run_chain_two_trustees(const char *antsd_path)
{
    /* The daemon and an in-process seed are the two genesis trustees.
     * With k = 2, finality needs BOTH signatures, so a final block can only
     * come out of a real exchange over the wire: the proposer's BLOCK frame
     * reaching the other node, which recomputes it from its own view and
     * gossips its ATTEST back. Both must then report the same head. */
    memset(&g_cs, 0, sizeof g_cs);
    memset(g_cs.priv, 0x56, sizeof g_cs.priv);
    uint8_t seed_pub[32];
    CHECK(ants_ed25519_pubkey_from_priv(g_cs.priv, seed_pub) == ANTS_OK);

    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.identity_priv, 0x34, sizeof cfg.identity_priv);
    uint8_t daemon_pub[32];
    CHECK(ants_ed25519_pubkey_from_priv(cfg.identity_priv, daemon_pub) == ANTS_OK);
    bool seed_first = memcmp(seed_pub, daemon_pub, 32) < 0;
    memcpy(g_cs.trustees[0], seed_first ? seed_pub : daemon_pub, 32);
    memcpy(g_cs.trustees[1], seed_first ? daemon_pub : seed_pub, 32);
    /* Genesis 2 s ahead: both nodes start before it — the daemon must wait
     * for it (pending) rather than run with the chain off. */
    uint64_t genesis_time = (uint64_t)time(NULL) + 2;
    g_cs.genesis_time = genesis_time;

    static ants_transport_t st;
    memset(&st, 0, sizeof st);
    ants_transport_config_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, seed_pub, 32);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = g_cs.priv;
    tcfg.event_fn = cs_event;
    tcfg.event_ctx = &g_cs;
    tcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK(ants_transport_init(&st, &tcfg) == ANTS_OK);
    char seed_addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK(ants_transport_local_addr(&st, seed_addr, sizeof seed_addr) == ANTS_OK);

    static ants_dht_t sd;
    memset(&sd, 0, sizeof sd);
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &st;
    memcpy(dcfg.local_peer_id.bytes, seed_pub, 32);
    dcfg.event_fn = noop_dht_event;
    CHECK(ants_dht_init(&sd, &dcfg) == ANTS_OK);
    g_cs.dht = &sd;

    ants_crdt_t *gset = NULL;
    CHECK(ants_crdt_init(&gset) == ANTS_OK);
    static ants_gossip_t sg;
    static ants_gossip_transport_t sb;
    memset(&sg, 0, sizeof sg);
    memset(&sb, 0, sizeof sb);
    CHECK(ants_gossip_transport_init(&sb, &sg, &st) == ANTS_OK);
    CHECK(ants_gossip_init(&sg, gset, seed_pub, NULL, cs_send, &sb) == ANTS_OK);
    CHECK(ants_gossip_set_chain_handler(&sg, cs_on_chain, &g_cs) == ANTS_OK);
    g_cs.gossip = &sg;
    g_cs.binding = &sb;

    static ants_chain_rt_t srt;
    ants_chain_rt_config_t rcfg;
    memset(&rcfg, 0, sizeof rcfg);
    g_cs.rt_mem = &srt;
    rcfg.trustees = (const uint8_t(*)[32])g_cs.trustees;
    rcfg.n_trustees = 2;
    rcfg.genesis_time = genesis_time;
    memset(rcfg.genesis_hash, 0x47, 32);
    rcfg.k_phase = ANTS_CHAIN_RT_PHASE1_K;
    memcpy(rcfg.self, seed_pub, 32);
    rcfg.sign_fn = cs_sign;
    rcfg.sign_ctx = &g_cs;
    rcfg.view_fn = cs_view;
    rcfg.proposal_fn = cs_out_proposal;
    rcfg.attestation_fn = cs_out_attestation;
    rcfg.final_fn = cs_final;
    rcfg.out_ctx = &g_cs;
    g_cs.rcfg = rcfg; /* initialised by cs_tick at the genesis time */

    /* Daemon config: listener, the seed to bootstrap from, the genesis. */
    static const char listen[] = "/ip4/127.0.0.1/udp/0/quic-v1";
    memcpy(cfg.listen_multiaddr, listen, sizeof listen);
    memcpy(cfg.seeds[0].addr, seed_addr, strlen(seed_addr));
    memcpy(cfg.seeds[0].peer_id, seed_pub, 32);
    cfg.seed_count = 1;
    cfg.genesis.present = true;
    cfg.genesis.time = genesis_time;
    memset(cfg.genesis.hash, 0x47, 32);
    memcpy(cfg.genesis.trustees, g_cs.trustees, sizeof g_cs.trustees);
    cfg.genesis.trustee_count = 2;
    static uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len = 0;
    CHECK(antsd_config_encode(&cfg, enc, sizeof enc, &enc_len) == ANTS_OK);
    char cfg_path[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(cfg_path, sizeof cfg_path, "%s/antsd_chain_XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    int cfd = mkstemp(cfg_path);
    CHECK(cfd >= 0);
    if (cfd < 0) {
        return;
    }
    CHECK(write(cfd, enc, enc_len) == (ssize_t)enc_len);
    CHECK(close(cfd) == 0);

    pid_t pid = -1;
    int out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd < 0) {
        unlink(cfg_path);
        return;
    }
    static capture_t cap;
    memset(&cap, 0, sizeof cap);

    /* First final block: the drand floor (30 s) dominates. */
    g_extra_tick = cs_tick;
    const char *hit = wait_for_output(out_fd,
                                      &cap,
                                      "antsd: chain final height=",
                                      now_ms() + 30000 + ANTS_CHAIN_RT_DRAND_FLOOR_S * 1000,
                                      &st,
                                      &sd);
    CHECK(hit != NULL);
    CHECK(strstr(cap.data, "antsd: chain waiting for genesis time") != NULL);
    CHECK(strstr(cap.data, "antsd: chain on (trustee, 2 trustees) at genesis time") != NULL);
    unsigned long long d_height = 0;
    char d_hash[65] = {0};
    if (hit != NULL) {
        CHECK(sscanf(hit, "antsd: chain final height=%llu hash=%64s", &d_height, d_hash) == 2);
    }
    /* The seed reaches the same head (it may finalise a beat later). */
    uint64_t until = now_ms() + 10000;
    while (now_ms() < until && (g_cs.rt == NULL || g_cs.head.height < d_height)) {
        tick_pace();
        ants_transport_tick(&st);
        ants_dht_tick(&sd);
        cs_tick();
    }
    g_extra_tick = NULL;
    CHECK(d_height >= 1);
    CHECK(g_cs.head.height == d_height);
    char s_hash[65];
    hex_format(g_cs.head.hash, 32, s_hash);
    s_hash[64] = '\0';
    CHECK(strcmp(s_hash, d_hash) == 0);
    CHECK(g_cs.head.degraded_seed);

    CHECK(kill(pid, SIGTERM) == 0);
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    while (capture_pump(out_fd, &cap, 100) > 0) {
    }
    if (failures > 0) {
        fprintf(stderr, "daemon output: <<<%s>>>\n", cap.data);
    }
    CHECK(ants_transport_destroy(&st, 0) == ANTS_OK);
    ants_gossip_transport_destroy(&sb);
    CHECK(ants_dht_destroy(&sd) == ANTS_OK);
    ants_crdt_destroy(gset);
    close(out_fd);
    unlink(cfg_path);
}

/* A valid equivocation fault proof against `priv`'s identity at `epoch`
 * (two different statements over the same domain/epoch/slot). */
static size_t make_fault_proof(const uint8_t priv[32], uint64_t epoch, uint8_t proof[512])
{
    uint8_t pub[32], body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    static const uint8_t pa[2] = {0x0A, 0x0B};
    static const uint8_t pb[2] = {0x0C, 0x0D};
    CHECK(ants_ed25519_pubkey_from_priv(priv, pub) == ANTS_OK);
    CHECK(ants_crdt_statement_encode(9, epoch, 3, pa, sizeof pa, body_a, sizeof body_a, &la) ==
          ANTS_OK);
    CHECK(ants_crdt_statement_encode(9, epoch, 3, pb, sizeof pb, body_b, sizeof body_b, &lb) ==
          ANTS_OK);
    CHECK(ants_ed25519_sign(priv, body_a, la, sig_a) == ANTS_OK);
    CHECK(ants_ed25519_sign(priv, body_b, lb, sig_b) == ANTS_OK);
    CHECK(ants_crdt_equivocation_encode(
              pub, epoch, body_a, la, sig_a, body_b, lb, sig_b, proof, 512, &plen) == ANTS_OK);
    return plen;
}

static void test_run_chain_prunes(const char *antsd_path)
{
    /* The daemon is the sole trustee of a chain whose genesis was 40 days
     * ago, so its first block lands in epoch 40. Through gossip it receives
     * two fault proofs, at epochs 5 and 35. The block's view window is
     * epochs [11, 40], so the epoch-35 proof is in the block and the
     * epoch-5 one is not. Once the block is final, the daemon prunes
     * everything below epoch 40 - 30 = 10: exactly the epoch-5 proof. */
    memset(&g_cs, 0, sizeof g_cs);
    memset(g_cs.priv, 0x57, sizeof g_cs.priv);
    g_cs.genesis_time = UINT64_MAX; /* the seed runs no chain here */
    uint8_t seed_pub[32];
    CHECK(ants_ed25519_pubkey_from_priv(g_cs.priv, seed_pub) == ANTS_OK);

    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.identity_priv, 0x35, sizeof cfg.identity_priv);
    uint8_t daemon_pub[32];
    CHECK(ants_ed25519_pubkey_from_priv(cfg.identity_priv, daemon_pub) == ANTS_OK);

    static ants_transport_t st;
    memset(&st, 0, sizeof st);
    ants_transport_config_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, seed_pub, 32);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = g_cs.priv;
    tcfg.event_fn = cs_event;
    tcfg.event_ctx = &g_cs;
    tcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK(ants_transport_init(&st, &tcfg) == ANTS_OK);
    char seed_addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK(ants_transport_local_addr(&st, seed_addr, sizeof seed_addr) == ANTS_OK);
    static ants_dht_t sd;
    memset(&sd, 0, sizeof sd);
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &st;
    memcpy(dcfg.local_peer_id.bytes, seed_pub, 32);
    dcfg.event_fn = noop_dht_event;
    CHECK(ants_dht_init(&sd, &dcfg) == ANTS_OK);
    g_cs.dht = &sd;
    ants_crdt_t *gset = NULL;
    CHECK(ants_crdt_init(&gset) == ANTS_OK);
    static ants_gossip_t sg;
    static ants_gossip_transport_t sb;
    memset(&sg, 0, sizeof sg);
    memset(&sb, 0, sizeof sb);
    CHECK(ants_gossip_transport_init(&sb, &sg, &st) == ANTS_OK);
    CHECK(ants_gossip_init(&sg, gset, seed_pub, NULL, cs_send, &sb) == ANTS_OK);
    g_cs.gossip = &sg;
    g_cs.binding = &sb;

    static const char listen[] = "/ip4/127.0.0.1/udp/0/quic-v1";
    memcpy(cfg.listen_multiaddr, listen, sizeof listen);
    memcpy(cfg.seeds[0].addr, seed_addr, strlen(seed_addr));
    memcpy(cfg.seeds[0].peer_id, seed_pub, 32);
    cfg.seed_count = 1;
    cfg.genesis.present = true;
    cfg.genesis.time = (uint64_t)time(NULL) - 40u * 86400u;
    memset(cfg.genesis.hash, 0x48, 32);
    memcpy(cfg.genesis.trustees[0], daemon_pub, 32);
    cfg.genesis.trustee_count = 1;
    static uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len = 0;
    CHECK(antsd_config_encode(&cfg, enc, sizeof enc, &enc_len) == ANTS_OK);
    char cfg_path[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(cfg_path, sizeof cfg_path, "%s/antsd_prune_XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    int cfd = mkstemp(cfg_path);
    CHECK(cfd >= 0);
    if (cfd < 0) {
        return;
    }
    CHECK(write(cfd, enc, enc_len) == (ssize_t)enc_len);
    CHECK(close(cfd) == 0);

    pid_t pid = -1;
    int out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd < 0) {
        unlink(cfg_path);
        return;
    }
    static capture_t cap;
    memset(&cap, 0, sizeof cap);

    /* Once the daemon is in the seed's gossip view, push the two proofs. */
    uint64_t until = now_ms() + HANDSHAKE_DEADLINE_MS;
    while (now_ms() < until && ants_gossip_peer_count(&sg) == 0) {
        tick_pace();
        ants_transport_tick(&st);
        ants_dht_tick(&sd);
        (void)capture_pump(out_fd, &cap, 0);
    }
    CHECK(ants_gossip_peer_count(&sg) == 1);
    uint8_t subject[32];
    memset(subject, 0x66, sizeof subject);
    uint8_t proof[512];
    size_t fwd = 0;
    size_t plen = make_fault_proof(subject, 5, proof);
    CHECK(ants_gossip_submit(&sg, proof, plen, &fwd) == ANTS_OK);
    CHECK(fwd == 1);
    plen = make_fault_proof(subject, 35, proof);
    CHECK(ants_gossip_submit(&sg, proof, plen, &fwd) == ANTS_OK);
    CHECK(fwd == 1);

    const char *hit = wait_for_output(out_fd,
                                      &cap,
                                      "antsd: l1 pruned 1 proofs below epoch 10",
                                      now_ms() + 30000 + ANTS_CHAIN_RT_DRAND_FLOOR_S * 1000,
                                      &st,
                                      &sd);
    CHECK(hit != NULL);
    CHECK(strstr(cap.data, "antsd: chain on (trustee, 1 trustees)") != NULL);
    CHECK(strstr(cap.data, " epoch=40 degraded") != NULL);

    CHECK(kill(pid, SIGTERM) == 0);
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    while (capture_pump(out_fd, &cap, 100) > 0) {
    }
    if (failures > 0) {
        fprintf(stderr, "daemon output: <<<%s>>>\n", cap.data);
    }
    CHECK(ants_transport_destroy(&st, 0) == ANTS_OK);
    ants_gossip_transport_destroy(&sb);
    CHECK(ants_dht_destroy(&sd) == ANTS_OK);
    ants_crdt_destroy(gset);
    close(out_fd);
    unlink(cfg_path);
}

/* ------------------------------------------------------------------------ */
/* Inference serving: the real `antsd ask` against the spawned daemon       */
/* ------------------------------------------------------------------------ */

/* The pinned v1 reference-model hash (test_orchestration.c pins the same
 * bytes from the compiled artifact). */
#define REF_MODEL_V1_HEX "c64a0f641f2040b5073dcdb611bc1db47101a221aa7dc21c3409a6d6fde3eba3"

/* Run `antsd ask <addr> <peer> <prompt> <tier>` to completion; its stdout
 * lands in `c`. Returns the wait status (-1 if it had to be killed). */
static int run_ask(const char *antsd_path,
                   const char *addr,
                   const char *peer_hex,
                   const char *tier,
                   capture_t *c)
{
    int p[2];
    if (pipe(p) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(p[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(p[0]);
        close(p[1]);
        execl(antsd_path, "antsd", "ask", addr, peer_hex, "hello, colony", tier, (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    memset(c, 0, sizeof *c);
    uint64_t deadline = now_ms() + 40000u; /* > the ask's own 30-s budget */
    while (now_ms() < deadline && capture_pump(p[0], c, 50) >= 0) {
    }
    close(p[0]);
    return reap_with_deadline(pid, EXIT_DEADLINE_MS);
}

static void test_run_serves_inference(const char *antsd_path)
{
    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.identity_priv, 0x35, sizeof cfg.identity_priv);
    static const char listen[] = "/ip4/127.0.0.1/udp/0/quic-v1";
    memcpy(cfg.listen_multiaddr, listen, sizeof listen);
    uint8_t daemon_pub[ANTS_ED25519_PUBKEY_SIZE];
    CHECK(ants_ed25519_pubkey_from_priv(cfg.identity_priv, daemon_pub) == ANTS_OK);
    char daemon_hex[ANTS_ED25519_PUBKEY_SIZE * 2 + 1];
    hex_format(daemon_pub, sizeof daemon_pub, daemon_hex);

    uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len = 0;
    CHECK(antsd_config_encode(&cfg, enc, sizeof enc, &enc_len) == ANTS_OK);
    char cfg_path[512];
    const char *tmp = getenv("TMPDIR");
    snprintf(cfg_path, sizeof cfg_path, "%s/antsd_infer_XXXXXX", tmp && tmp[0] ? tmp : "/tmp");
    int cfd = mkstemp(cfg_path);
    CHECK(cfd >= 0);
    if (cfd < 0) {
        return;
    }
    CHECK(write(cfd, enc, enc_len) == (ssize_t)enc_len);
    CHECK(close(cfd) == 0);

    pid_t pid = -1;
    int out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd < 0) {
        unlink(cfg_path);
        return;
    }
    static capture_t cap;
    memset(&cap, 0, sizeof cap);
    char addr[ANTS_MULTIADDR_MAX_LEN];
    int have_addr = -1;
    uint64_t deadline = now_ms() + READY_DEADLINE_MS;
    while (have_addr != 0 && now_ms() < deadline) {
        have_addr = extract_listen_addr(&cap, addr, sizeof addr);
        if (have_addr != 0 && capture_pump(out_fd, &cap, 50) < 0) {
            have_addr = extract_listen_addr(&cap, addr, sizeof addr);
            break;
        }
    }
    CHECK(have_addr == 0);
    CHECK(wait_for_output(out_fd,
                          &cap,
                          "antsd: serving inference (reference model v1)",
                          now_ms() + READY_DEADLINE_MS,
                          NULL,
                          NULL) != NULL);
    if (have_addr != 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        close(out_fd);
        unlink(cfg_path);
        return;
    }

    static capture_t ask;
    char want[160];

    /* 1. An answer that checks out: signed by the daemon's identity (the
     *    ask pins it and the engine verifies under it), the pinned model,
     *    round 0 with the chain off, the reference 16 positions. */
    int st = run_ask(antsd_path, addr, daemon_hex, "2", &ask);
    CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(strstr(ask.data, "antsd: ask verdict=answered") != NULL);
    snprintf(
        want, sizeof want, "antsd: ask round=0 tier=2 positions=16 model=%s", REF_MODEL_V1_HEX);
    CHECK(strstr(ask.data, want) != NULL);
    /* paid for: 16 positions at the 1000-uNCS reference rate */
    CHECK(strstr(ask.data, "antsd: ask receipt=acked ncs=16000") != NULL);
    CHECK(wait_for_output(out_fd,
                          &cap,
                          "antsd: receipt filed client=",
                          now_ms() + HANDSHAKE_DEADLINE_MS,
                          NULL,
                          NULL) != NULL);
    CHECK(wait_for_output(out_fd,
                          &cap,
                          "antsd: infer served peer=",
                          now_ms() + HANDSHAKE_DEADLINE_MS,
                          NULL,
                          NULL) != NULL);
    if (failures > 0) {
        fprintf(stderr, "ask output: <<<%s>>>\n", ask.data);
    }

    /* 2. A tier the node does not serve: declined, exit 1. */
    st = run_ask(antsd_path, addr, daemon_hex, "9", &ask);
    CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 1);
    CHECK(strstr(ask.data, "antsd: ask verdict=declined") != NULL);
    CHECK(wait_for_output(out_fd,
                          &cap,
                          "antsd: infer declined peer=",
                          now_ms() + HANDSHAKE_DEADLINE_MS,
                          NULL,
                          NULL) != NULL);

    /* 3. The wrong peer pinned: the handshake fails, nothing is asked. */
    {
        char wrong[sizeof daemon_hex];
        memcpy(wrong, daemon_hex, sizeof wrong);
        wrong[0] = wrong[0] == '0' ? '1' : '0';
        st = run_ask(antsd_path, addr, wrong, "2", &ask);
        CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 1);
        CHECK(strstr(ask.data, "antsd: ask verdict=no-answer") != NULL);
    }

    CHECK(kill(pid, SIGTERM) == 0);
    int status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
    CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    while (capture_pump(out_fd, &cap, 100) > 0) {
    }
    CHECK(strstr(cap.data, "infer 1/1 served/declined, receipts 1,") != NULL);
    CHECK(strstr(cap.data, "antsd: receipts 0 loaded (0 skipped, 0 torn bytes cut) A=0 T=0 uNCS") !=
          NULL);
    CHECK(strstr(cap.data, "antsd: reputation A=16000 T=16000 uNCS over 1 receipts") != NULL ||
          strstr(cap.data, "antsd: reputation A=8000 ") != NULL); /* an hour bin may tick */
    if (failures > 0) {
        fprintf(stderr, "daemon output: <<<%s>>>\n", cap.data);
    }
    close(out_fd);

    /* The bag on disk: one 229-byte record (2 + 99-byte body + 2 x 64).
     * Append a copy with a flipped server-signature byte (must be skipped)
     * and three bytes of a torn record (must end the load quietly). */
    char bag_path[600];
    snprintf(bag_path, sizeof bag_path, "%s.receipts", cfg_path);
    {
        uint8_t rec[512];
        FILE *f = fopen(bag_path, "rb");
        size_t n = 0;
        CHECK(f != NULL);
        if (f != NULL) {
            n = fread(rec, 1, sizeof rec, f);
            fclose(f);
        }
        CHECK(n == 229);
        if (n == 229) {
            static const uint8_t torn[3] = {0x00, 0x63, 0xa5};
            rec[2 + 99 + 10] ^= 0x01;
            f = fopen(bag_path, "ab");
            CHECK(f != NULL);
            if (f != NULL) {
                CHECK(fwrite(rec, 1, n, f) == n);
                CHECK(fwrite(torn, 1, sizeof torn, f) == sizeof torn);
                fclose(f);
            }
        }
    }

    /* Restart: the good receipt is reloaded, the corrupted one skipped. */
    out_fd = spawn_run(antsd_path, cfg_path, &pid);
    CHECK(out_fd >= 0);
    if (out_fd >= 0) {
        memset(&cap, 0, sizeof cap);
        CHECK(wait_for_output(out_fd,
                              &cap,
                              "antsd: receipts 1 loaded (1 skipped, 3 torn bytes cut) A=",
                              now_ms() + READY_DEADLINE_MS,
                              NULL,
                              NULL) != NULL);
        CHECK(strstr(cap.data, "torn bytes cut) A=0 ") == NULL);
        /* A receipt filed after the cut lands on a record boundary — before
         * the fix it sat behind the torn bytes and was lost on reload. */
        {
            char addr2[ANTS_MULTIADDR_MAX_LEN];
            uint64_t dl = now_ms() + READY_DEADLINE_MS;
            while (extract_listen_addr(&cap, addr2, sizeof addr2) != 0 && now_ms() < dl) {
                (void)capture_pump(out_fd, &cap, 50);
            }
            CHECK(extract_listen_addr(&cap, addr2, sizeof addr2) == 0);
            st = run_ask(antsd_path, addr2, daemon_hex, "2", &ask);
            CHECK(st >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
            CHECK(strstr(ask.data, "antsd: ask receipt=acked ncs=16000") != NULL);
            CHECK(wait_for_output(out_fd,
                                  &cap,
                                  "antsd: receipt filed client=",
                                  now_ms() + HANDSHAKE_DEADLINE_MS,
                                  NULL,
                                  NULL) != NULL);
        }
        CHECK(kill(pid, SIGTERM) == 0);
        status = reap_with_deadline(pid, EXIT_DEADLINE_MS);
        CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (failures > 0) {
            while (capture_pump(out_fd, &cap, 100) > 0) {
            }
            fprintf(stderr, "restarted daemon output: <<<%s>>>\n", cap.data);
        }
        close(out_fd);
    }

    /* `antsd receipts` reads the same bag. */
    {
        int p[2];
        CHECK(pipe(p) == 0);
        pid_t rp = fork();
        if (rp == 0) {
            dup2(p[1], STDOUT_FILENO);
            close(p[0]);
            close(p[1]);
            execl(antsd_path, "antsd", "receipts", cfg_path, (char *)NULL);
            _exit(127);
        }
        close(p[1]);
        static capture_t rc_out;
        memset(&rc_out, 0, sizeof rc_out);
        uint64_t dl = now_ms() + EXIT_DEADLINE_MS;
        while (now_ms() < dl && capture_pump(p[0], &rc_out, 50) >= 0) {
        }
        close(p[0]);
        status = reap_with_deadline(rp, EXIT_DEADLINE_MS);
        CHECK(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        /* the torn tail was cut by the restart: none left to cut now */
        CHECK(strstr(rc_out.data, "receipts: 2 (1 skipped, 0 torn bytes cut)") != NULL);
    }
    unlink(bag_path);
    unlink(cfg_path);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-antsd>\n", argv[0]);
        return 2;
    }
    test_run_missing_config(argv[1]);
    test_run_serves_and_shuts_down(argv[1]);
    test_run_serves_inference(argv[1]);
    test_run_bootstraps_to_seed(argv[1], NULL);

    /* A GENUINE Intel TDX quote (real chain, real signatures) presented by
     * a peer it was never bound to — a relayed attestation. */
    ants_attest_presentation_t foreign;
    memset(&foreign, 0, sizeof foreign);
    foreign.present = true;
    foreign.vendor = ANTS_TEE_VENDOR_INTEL_TDX;
    foreign.issued_at_unix = (int64_t)1735689600; /* inside the chain's validity */
    foreign.blob = TDX_KAT_QUOTE;
    foreign.blob_len = sizeof TDX_KAT_QUOTE;
    test_run_bootstraps_to_seed(argv[1], &foreign);
    test_run_chain_two_trustees(argv[1]);
    test_run_chain_prunes(argv[1]);

    if (failures == 0) {
        printf("all checks passed\n");
        return 0;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
}
