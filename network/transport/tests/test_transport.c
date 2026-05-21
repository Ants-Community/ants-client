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
    /* tick is still NOT_IMPLEMENTED in phase 1; verify it still
     * returns the documented safe default UINT32_MAX. */
    CHECK(ants_transport_tick(&t) == UINT32_MAX);
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

static void test_dial_stub(void)
{
    ants_transport_t t = {{0}};
    ants_transport_conn_t c = {{0}};
    ants_peer_id_t expected = {{0}};
    CHECK_EQ(ants_transport_dial(&t, "/ip4/127.0.0.1/udp/4242/quic-v1", &expected, &c),
             ANTS_ERROR_NOT_IMPLEMENTED);
    /* NULL expected_peer_id is also accepted (and returns NOT_IMPLEMENTED). */
    CHECK_EQ(ants_transport_dial(&t, "/ip4/127.0.0.1/udp/4242/quic-v1", NULL, &c),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_stream_stubs(void)
{
    ants_transport_conn_t c = {{0}};
    ants_transport_stream_t s = {{0}};
    uint8_t buf[16] = {0};
    size_t got;
    CHECK_EQ(ants_transport_open_bidi_stream(&c, &s), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_open_uni_stream(&c, &s), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_stream_send(&s, buf, sizeof buf, false), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_stream_recv(&s, buf, sizeof buf, &got), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_stream_close(&s), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_stream_reset(&s, 42), ANTS_ERROR_NOT_IMPLEMENTED);
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
    ants_transport_conn_t c = {{0}};
    ants_peer_id_t pid;
    char addr[ANTS_MULTIADDR_MAX_LEN];
    CHECK_EQ(ants_transport_conn_peer_id(&c, &pid), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_conn_peer_addr(&c, addr, sizeof addr), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_transport_peer_disconnect(&c, 0), ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_init_destroy_roundtrip();
    test_dial_stub();
    test_stream_stubs();
    test_introspection_safe_defaults();
    test_conn_introspection_stubs();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
