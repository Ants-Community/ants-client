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

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_transport.h"

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
 * absolute deadline. While waiting, optionally tick a transport so the
 * QUIC handshake can progress while we watch the daemon's log. */
static const char *
wait_for_output(int fd, capture_t *c, const char *needle, uint64_t deadline, ants_transport_t *tick)
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
        wait_for_output(out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &dialer);
    CHECK(hit != NULL);

    /* 4. Disconnect: the daemon must log the close with the SAME peer
     * id, not a zeroed one — ready/closed pairs stay correlatable. */
    CHECK(ants_transport_peer_disconnect(&conn, 0) == ANTS_OK);
    snprintf(needle, sizeof needle, "antsd: conn closed peer=%s", dialer_hex);
    hit = wait_for_output(out_fd, &cap, needle, now_ms() + HANDSHAKE_DEADLINE_MS, &dialer);
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

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-antsd>\n", argv[0]);
        return 2;
    }
    test_run_missing_config(argv[1]);
    test_run_serves_and_shuts_down(argv[1]);

    if (failures == 0) {
        printf("all checks passed\n");
        return 0;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
}
