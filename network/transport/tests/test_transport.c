/*
 * test_transport.c — Tests for the P2P transport API.
 *
 * v1.0 scaffold: every function returns NOT_IMPLEMENTED or the
 * documented safe default. These tests pin the API contract so a
 * future implementation can't silently change shape:
 *
 *   - Public symbols link.
 *   - Stub return values match what ants_transport.h documents
 *     (NOT_IMPLEMENTED for most; UINT32_MAX for tick(); UINT64_MAX
 *     for stream_send_window(); 0 for byte counters; out_count=0 for
 *     peer_list).
 *   - Opaque ctx sizes match the documented constants.
 *   - Event-kind enum values are pinned (they appear in caller code
 *     so changing them is an API break).
 *   - Static asserts: ANTS_PEER_ID_SIZE = 32 (matches Ed25519 pubkey).
 *
 * Same pattern as foundation/tee/tests/test_tee.c.
 */

#include "ants_common.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                 \
    do {                                                                                           \
        ants_error_t _a = (actual);                                                                \
        ants_error_t _e = (expected);                                                              \
        if (_a != _e) {                                                                            \
            failures++;                                                                            \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

static void test_pinned_constants(void)
{
    /* Peer ID size MUST equal Ed25519 pubkey size — this is the
     * cross-layer assumption (RFC-0010 line 57: peer_id = Ed25519
     * pubkey). Any future change is a protocol break. */
    CHECK(ANTS_PEER_ID_SIZE == 32);
    CHECK(ANTS_PEER_ID_SIZE == ANTS_ED25519_PUBKEY_SIZE);

    /* Multiaddr max length pinned at 256 (textual form). */
    CHECK(ANTS_MULTIADDR_MAX_LEN == 256);

    /* Opaque ctx sizes — v1.0 starting estimates. If a future PR
     * tightens these based on measurements, the test must be updated
     * together. The point is to make accidental size changes visible. */
    CHECK(ANTS_TRANSPORT_CTX_SIZE == 16384);
    CHECK(ANTS_TRANSPORT_CONN_CTX_SIZE == 8192);
    CHECK(ANTS_TRANSPORT_STREAM_CTX_SIZE == 1024);

    /* Event-kind values: stable for the wire / for caller switch
     * statements. Adding new kinds is OK; renumbering existing ones
     * is not. */
    CHECK(ANTS_TRANSPORT_EV_CONN_READY == 1);
    CHECK(ANTS_TRANSPORT_EV_CONN_CLOSED == 2);
    CHECK(ANTS_TRANSPORT_EV_STREAM_OPENED == 3);
    CHECK(ANTS_TRANSPORT_EV_STREAM_READABLE == 4);
    CHECK(ANTS_TRANSPORT_EV_STREAM_FIN == 5);
    CHECK(ANTS_TRANSPORT_EV_STREAM_RESET == 6);
    CHECK(ANTS_TRANSPORT_EV_STREAM_WRITABLE == 7);
}

static void test_opaque_ctx_layout(void)
{
    /* The opaque-context types must be uint64_t-aligned (the union's
     * _align member forces this). Verify by checking that a stack-
     * allocated instance's address is 8-byte aligned. */
    ants_transport_t t;
    ants_transport_conn_t c;
    ants_transport_stream_t s;
    CHECK(((uintptr_t)&t & 7u) == 0);
    CHECK(((uintptr_t)&c & 7u) == 0);
    CHECK(((uintptr_t)&s & 7u) == 0);

    /* Sizes match the constants exactly. */
    CHECK(sizeof t == ANTS_TRANSPORT_CTX_SIZE);
    CHECK(sizeof c == ANTS_TRANSPORT_CONN_CTX_SIZE);
    CHECK(sizeof s == ANTS_TRANSPORT_STREAM_CTX_SIZE);
}

/* Minimal sign callback that does nothing — we never reach the TLS
 * handshake in phase 1 lifecycle tests. Real callers (and phase 2
 * tests) wire ants_ed25519_sign here. */
static ants_error_t test_noop_sign(const uint8_t *transcript,
                                   size_t transcript_len,
                                   uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                                   void *sign_ctx)
{
    (void)transcript;
    (void)transcript_len;
    (void)sign_ctx;
    memset(out_sig, 0, ANTS_ED25519_SIG_SIZE);
    return ANTS_OK;
}

static ants_error_t test_noop_event(const ants_transport_event_t *event, void *user_ctx)
{
    (void)event;
    (void)user_ctx;
    return ANTS_OK;
}

static void test_init_rejects_invalid_args(void)
{
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);

    /* NULL transport or config */
    CHECK_EQ(ants_transport_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_init(&t, NULL), ANTS_ERROR_INVALID_ARG);

    /* Missing sign_fn or event_fn */
    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_ERROR_INVALID_ARG);
    cfg.event_fn = NULL;
    cfg.sign_fn = test_noop_sign;
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_ERROR_INVALID_ARG);
}

static void test_init_destroy_roundtrip(void)
{
    /* Phase 1: prove the picoquic context is created and freed cleanly.
     * No networking yet — we just exercise the lifecycle. ASan/UBSan
     * runs catch any leak or use-after-free. */
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sign_fn = test_noop_sign;
    cfg.event_fn = test_noop_event;
    cfg.max_connections = 32;
    cfg.max_streams_per_conn = 64;
    cfg.idle_timeout_ms = 30000;

    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_OK);
    /* Phase 2 tick(): on an idle transport without a listening socket
     * it returns the picoquic wake-delay, typically very large
     * (UINT32_MAX equivalent). The exact value depends on picoquic
     * internals; we just check it doesn't return 0 (which would mean
     * "spin"). */
    uint32_t wake = ants_transport_tick(&t);
    CHECK(wake > 0);
    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);

    /* Re-init the same buffer (verify destroy zeroed cleanly). */
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);

    /* destroy on a zeroed transport is a no-op (state.quic == NULL). */
    memset(&t, 0, sizeof t);
    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);

    /* NULL transport rejected. */
    CHECK_EQ(ants_transport_destroy(NULL, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_listener_bind(void)
{
    /* Phase 2: bind a UDP socket on /ip4/127.0.0.1/udp/0/quic-v1 (port
     * 0 = kernel-assigned). After init the local_addr API must report
     * the actually-bound multiaddr with a non-zero port. tick() runs
     * the I/O loop; on an empty network it returns a finite wake
     * delay (probably UINT32_MAX-equivalent) but does not crash. */
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sign_fn = test_noop_sign;
    cfg.event_fn = test_noop_event;
    cfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    cfg.max_connections = 32;
    cfg.max_streams_per_conn = 64;
    cfg.idle_timeout_ms = 30000;

    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_OK);

    /* Local address: non-empty, starts with the right prefix, ends
     * with /quic-v1, contains a non-zero port. */
    char addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&t, addr, sizeof addr), ANTS_OK);
    CHECK(strncmp(addr, "/ip4/127.0.0.1/udp/", 19) == 0);
    CHECK(strstr(addr, "/quic-v1") != NULL);
    /* Port is between '/' and '/quic-v1'; verify it's non-zero. */
    const char *port_start = addr + 19;
    int port = atoi(port_start);
    CHECK(port > 0);
    CHECK(port < 65536);

    /* Run a few ticks to make sure the event loop is harmless on an
     * idle socket. ASan/UBSan would flag any leak or UB. */
    for (int i = 0; i < 5; i++) {
        uint32_t w = ants_transport_tick(&t);
        CHECK(w > 0); /* idle → non-zero wake delay */
    }

    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);
}

static void test_local_addr_without_listener(void)
{
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sign_fn = test_noop_sign;
    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_OK);

    char addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    /* No listener configured → NOT_IMPLEMENTED. */
    CHECK_EQ(ants_transport_local_addr(&t, addr, sizeof addr), ANTS_ERROR_NOT_IMPLEMENTED);

    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);
}

static void test_listener_bad_multiaddr(void)
{
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sign_fn = test_noop_sign;
    cfg.event_fn = test_noop_event;
    cfg.listen_multiaddr = "/not/a/real/multiaddr";
    /* Bad multiaddr → init fails with INVALID_ARG, no leaks. */
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_ERROR_INVALID_ARG);
}

static void test_dial_rejects_invalid_args(void)
{
    ants_transport_t t = {{0}};
    ants_transport_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sign_fn = test_noop_sign;
    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_transport_init(&t, &cfg), ANTS_OK);

    ants_transport_conn_t c = {{0}};

    /* NULL guards */
    CHECK_EQ(ants_transport_dial(NULL, "/ip4/127.0.0.1/udp/4242/quic-v1", NULL, &c),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_dial(&t, NULL, NULL, &c), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_dial(&t, "/ip4/127.0.0.1/udp/4242/quic-v1", NULL, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* Bad multiaddr */
    CHECK_EQ(ants_transport_dial(&t, "not-a-multiaddr", NULL, &c), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_dial(&t, "/ip4/127.0.0.1/tcp/4242", NULL, &c), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_transport_destroy(&t, 0), ANTS_OK);
}

static void test_dial_to_listener_no_handshake(void)
{
    /* Phase 3a: dial() creates a picoquic client connection and queues
     * the INITIAL packet. Without TLS material wired up (phase 3b), the
     * actual handshake won't complete, but the dial path is exercised:
     *   1. parse_multiaddr ok
     *   2. ephemeral UDP socket bound on the dialer
     *   3. picoquic_create_client_cnx returns non-NULL
     *   4. tick() flushes the INITIAL packet onto the wire
     *
     * ASan/UBSan would catch any leak or UB along the way. */

    /* Listener: bind a random local port. */
    ants_transport_t listener = {{0}};
    ants_transport_config_t listener_cfg;
    memset(&listener_cfg, 0, sizeof listener_cfg);
    listener_cfg.sign_fn = test_noop_sign;
    listener_cfg.event_fn = test_noop_event;
    listener_cfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&listener, &listener_cfg), ANTS_OK);

    char listener_addr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&listener, listener_addr, sizeof listener_addr), ANTS_OK);

    /* Dialer: no listener (client-only). */
    ants_transport_t dialer = {{0}};
    ants_transport_config_t dialer_cfg;
    memset(&dialer_cfg, 0, sizeof dialer_cfg);
    dialer_cfg.sign_fn = test_noop_sign;
    dialer_cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_transport_init(&dialer, &dialer_cfg), ANTS_OK);

    /* Dial the listener. NULL expected_peer_id (no MITM check). */
    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&dialer, listener_addr, NULL, &conn), ANTS_OK);

    /* Run a few ticks on both. The dialer should at least try to send
     * the INITIAL packet; the listener may receive bytes (which
     * picoquic_incoming_packet will eventually fail on without TLS
     * material — that's expected for phase 3a). No crash, no leak. */
    for (int i = 0; i < 10; i++) {
        ants_transport_tick(&dialer);
        ants_transport_tick(&listener);
    }

    CHECK_EQ(ants_transport_destroy(&dialer, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&listener, 0), ANTS_OK);
}

static void test_stream_rejects_invalid_args(void)
{
    /* Phase 3c contract: NULL guards, fin-only stream_send with a non-
     * zero len rejects, and operations on a stream whose parent_conn
     * is dead (e.g. the zero-init handle a test stack-allocates) return
     * ANTS_ERROR_PEER_UNREACHABLE rather than NOT_IMPLEMENTED. */
    ants_transport_conn_t c = {{0}}; /* zero-init: cnx==NULL */
    ants_transport_stream_t s = {{0}};
    uint8_t buf[16] = {0};
    size_t got;

    /* NULL arg rejections come first — they're independent of conn state. */
    CHECK_EQ(ants_transport_open_bidi_stream(NULL, &s), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_open_bidi_stream(&c, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_open_uni_stream(NULL, &s), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_open_uni_stream(&c, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_stream_send(NULL, buf, sizeof buf, false), ANTS_ERROR_INVALID_ARG);
    /* Non-zero len with NULL data is a contract violation. */
    CHECK_EQ(ants_transport_stream_send(&s, NULL, sizeof buf, false), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_stream_recv(NULL, buf, sizeof buf, &got), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_stream_recv(&s, buf, sizeof buf, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_stream_close(NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_transport_stream_reset(NULL, 42), ANTS_ERROR_INVALID_ARG);

    /* With a dead/zero conn, opens fail with PEER_UNREACHABLE. */
    CHECK_EQ(ants_transport_open_bidi_stream(&c, &s), ANTS_ERROR_PEER_UNREACHABLE);
    CHECK_EQ(ants_transport_open_uni_stream(&c, &s), ANTS_ERROR_PEER_UNREACHABLE);
    /* Send/close/reset on a stream whose parent_conn pointer is NULL
     * (default zero-init) also surface PEER_UNREACHABLE. */
    CHECK_EQ(ants_transport_stream_send(&s, buf, sizeof buf, false), ANTS_ERROR_PEER_UNREACHABLE);
    CHECK_EQ(ants_transport_stream_close(&s), ANTS_ERROR_PEER_UNREACHABLE);
    CHECK_EQ(ants_transport_stream_reset(&s, 42), ANTS_ERROR_PEER_UNREACHABLE);
    /* Recv is a pure observer of the local recv buffer — on a zeroed
     * stream it reports 0 bytes with no error. */
    got = 99;
    CHECK_EQ(ants_transport_stream_recv(&s, buf, sizeof buf, &got), ANTS_OK);
    CHECK(got == 0);
}

/* Tiny event recorder: counts kinds seen by the user's event_fn. */
typedef struct {
    int conn_ready;
    int conn_closed;
    int stream_readable;
    int stream_fin;
    int stream_reset;
    int other;
} test_event_recorder_t;

static ants_error_t test_recording_event(const ants_transport_event_t *event, void *user_ctx)
{
    test_event_recorder_t *r = (test_event_recorder_t *)user_ctx;
    switch (event->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        r->conn_ready++;
        break;
    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        r->conn_closed++;
        break;
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        r->stream_readable++;
        break;
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        r->stream_fin++;
        break;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        r->stream_reset++;
        break;
    default:
        r->other++;
        break;
    }
    return ANTS_OK;
}

static void test_stream_lifecycle(void)
{
    /* Phase 3c: open + send + recv + close + reset on a live dial.
     * Without TLS (phase 3b deferred), the handshake never completes so
     * no payload reaches the listener — but the local API path is fully
     * exercised: stream-id allocation, picoquic_set_app_stream_ctx
     * binding, send queue, FIN propagation, RESET. ASan/UBSan catch
     * any leak or UB along the way. */
    test_event_recorder_t rec;
    memset(&rec, 0, sizeof rec);

    ants_transport_t listener = {{0}};
    ants_transport_config_t lcfg;
    memset(&lcfg, 0, sizeof lcfg);
    lcfg.sign_fn = test_noop_sign;
    lcfg.event_fn = test_recording_event;
    lcfg.event_ctx = &rec;
    lcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&listener, &lcfg), ANTS_OK);

    char laddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&listener, laddr, sizeof laddr), ANTS_OK);

    ants_transport_t dialer = {{0}};
    ants_transport_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.sign_fn = test_noop_sign;
    dcfg.event_fn = test_recording_event;
    dcfg.event_ctx = &rec;
    CHECK_EQ(ants_transport_init(&dialer, &dcfg), ANTS_OK);

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&dialer, laddr, NULL, &conn), ANTS_OK);

    /* Open both stream types. picoquic_get_next_local_stream_id +
     * picoquic_set_app_stream_ctx must materialise both without error. */
    ants_transport_stream_t s_bidi = {{0}};
    ants_transport_stream_t s_uni = {{0}};
    CHECK_EQ(ants_transport_open_bidi_stream(&conn, &s_bidi), ANTS_OK);
    CHECK_EQ(ants_transport_open_uni_stream(&conn, &s_uni), ANTS_OK);

    /* Send: bytes queue into picoquic's send buffer. Won't actually flow
     * until handshake completes (which won't happen without TLS), but
     * the API path is exercised. */
    const uint8_t payload[] = "hello";
    CHECK_EQ(ants_transport_stream_send(&s_bidi, payload, sizeof payload, false /* fin */),
             ANTS_OK);
    CHECK_EQ(ants_transport_stream_send(&s_uni, payload, sizeof payload, true /* fin */), ANTS_OK);
    /* After fin=true, further sends on s_uni reject with INVALID_ARG. */
    CHECK_EQ(ants_transport_stream_send(&s_uni, payload, sizeof payload, false),
             ANTS_ERROR_INVALID_ARG);

    /* Recv before any inbound bytes: 0 length, no error. */
    uint8_t buf[16];
    size_t got = 99;
    CHECK_EQ(ants_transport_stream_recv(&s_bidi, buf, sizeof buf, &got), ANTS_OK);
    CHECK(got == 0);

    /* stream_close on bidi sends FIN; idempotent second call also OK. */
    CHECK_EQ(ants_transport_stream_close(&s_bidi), ANTS_OK);
    CHECK_EQ(ants_transport_stream_close(&s_bidi), ANTS_OK);

    /* Open one more stream and reset it; reset path is independent of
     * close path. */
    ants_transport_stream_t s_reset = {{0}};
    CHECK_EQ(ants_transport_open_bidi_stream(&conn, &s_reset), ANTS_OK);
    CHECK_EQ(ants_transport_stream_reset(&s_reset, 42), ANTS_OK);

    /* Drive the I/O loop. picoquic may fire CONN_CLOSED if it detects
     * the listener has no TLS material; we don't tightly require it
     * (timing is picoquic-internal) so just verify no crash. */
    for (int i = 0; i < 20; i++) {
        ants_transport_tick(&dialer);
        ants_transport_tick(&listener);
    }

    /* peer_disconnect: graceful close queues CONNECTION_CLOSE.
     * Idempotent if the conn already closed itself. */
    CHECK_EQ(ants_transport_peer_disconnect(&conn, 0), ANTS_OK);

    /* Flush the close. */
    for (int i = 0; i < 5; i++) {
        ants_transport_tick(&dialer);
        ants_transport_tick(&listener);
    }

    /* peer_disconnect is idempotent after the conn is dead. */
    CHECK_EQ(ants_transport_peer_disconnect(&conn, 0), ANTS_OK);

    CHECK_EQ(ants_transport_destroy(&dialer, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&listener, 0), ANTS_OK);

    /* The recorder is allowed to have observed CONN_CLOSED but is not
     * required to — picoquic's exact behaviour without TLS depends on
     * internal state machine handling. We do NOT assert specific counts
     * here; the phase-3d loopback PR will exercise real event flow. */
    (void)rec;
}

static void test_introspection_safe_defaults(void)
{
    /* The four introspection helpers return safe defaults rather than
     * NOT_IMPLEMENTED (they're observers, not actions). */
    ants_transport_stream_t s = {{0}};
    CHECK(ants_transport_stream_send_window(&s) == UINT64_MAX);
    CHECK(ants_transport_stream_bytes_sent(&s) == 0);
    CHECK(ants_transport_stream_bytes_received(&s) == 0);

    /* peer_list writes 0 to *out_count even when returning
     * NOT_IMPLEMENTED — callers reading the count without checking the
     * return value see "no peers", which is safe. */
    ants_transport_t t = {{0}};
    ants_peer_id_t peers[4];
    size_t count = 99;
    CHECK_EQ(ants_transport_peer_list(&t, peers, 4, &count), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(count == 0);
}

static void test_conn_introspection_stubs(void)
{
    /* conn_peer_id and conn_peer_addr still require TLS handshake to
     * have bound a peer identity — phase 3b. peer_disconnect IS wired
     * (phase 3c) and is idempotent on a zero-init conn. */
    ants_transport_conn_t c = {{0}};
    ants_peer_id_t pid;
    char addr[ANTS_MULTIADDR_MAX_LEN];
    CHECK_EQ(ants_transport_conn_peer_id(&c, &pid), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_conn_peer_addr(&c, addr, sizeof addr), ANTS_ERROR_NOT_IMPLEMENTED);
    /* peer_disconnect on a never-dialed conn is a no-op success. */
    CHECK_EQ(ants_transport_peer_disconnect(&c, 0), ANTS_OK);
    /* NULL guard. */
    CHECK_EQ(ants_transport_peer_disconnect(NULL, 0), ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_init_destroy_roundtrip();
    test_listener_bind();
    test_local_addr_without_listener();
    test_listener_bad_multiaddr();
    test_dial_rejects_invalid_args();
    test_dial_to_listener_no_handshake();
    test_stream_rejects_invalid_args();
    test_stream_lifecycle();
    test_introspection_safe_defaults();
    test_conn_introspection_stubs();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
