/*
 * test_dht.c — Tests for the DHT API surface.
 *
 * v1.0 scaffold: pins the API contract via stub return values and
 * compile-time constants so subsequent implementation PRs can't
 * silently change shape. Same pattern as foundation/tee/test_tee
 * and network/transport/test_transport's early phases:
 *
 *   - Public symbols link.
 *   - Stub return values match what ants_dht.h documents
 *     (NOT_IMPLEMENTED for actions; safe defaults for observers).
 *   - Opaque ctx sizes / alignment match the documented constants.
 *   - Event-kind enum values are pinned (they appear in caller code,
 *     so changing them is an API break).
 *   - Kademlia parameters (K, alpha, bucket count) pinned.
 */

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_dht.h"
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
    /* Kademlia parameters: changes are protocol-incompatible breaks. */
    CHECK(ANTS_DHT_K == 20);
    CHECK(ANTS_DHT_ALPHA == 3);
    CHECK(ANTS_DHT_BUCKET_COUNT == 256);

    /* Opaque ctx sizes — v1.0 starting estimates. If a future PR
     * tightens these the test must be updated together. */
    CHECK(ANTS_DHT_CTX_SIZE == 32768);
    CHECK(ANTS_DHT_LOOKUP_CTX_SIZE == 8192);

    /* Event-kind enum: stable for caller switch statements. Adding new
     * kinds is OK; renumbering existing ones is not. */
    CHECK(ANTS_DHT_EV_PEER_DISCOVERED == 1);
    CHECK(ANTS_DHT_EV_PEER_EVICTED == 2);
    CHECK(ANTS_DHT_EV_LOOKUP_COMPLETE == 3);
    CHECK(ANTS_DHT_EV_LOOKUP_TIMEOUT == 4);
    CHECK(ANTS_DHT_EV_ANNOUNCE_CONFIRMED == 5);
    CHECK(ANTS_DHT_EV_TABLE_REFRESHED == 6);
}

static void test_opaque_ctx_layout(void)
{
    /* Both opaque types are uint64_t-aligned via the union's _align
     * member. Verify by checking that a stack-allocated instance's
     * address is 8-byte aligned and the sizeof matches the constant. */
    ants_dht_t d;
    ants_dht_lookup_t l;
    CHECK(((uintptr_t)&d & 7u) == 0);
    CHECK(((uintptr_t)&l & 7u) == 0);
    CHECK(sizeof d == ANTS_DHT_CTX_SIZE);
    CHECK(sizeof l == ANTS_DHT_LOOKUP_CTX_SIZE);
}

static ants_error_t test_noop_event(const ants_dht_event_t *event, void *user_ctx)
{
    (void)event;
    (void)user_ctx;
    return ANTS_OK;
}

static void test_init_rejects_invalid_args(void)
{
    ants_dht_t d = {{0}};
    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);

    /* NULL dht or config. */
    CHECK_EQ(ants_dht_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_init(&d, NULL), ANTS_ERROR_INVALID_ARG);

    /* Missing required fields. */
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_ERROR_INVALID_ARG); /* no transport */

    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_ERROR_INVALID_ARG); /* still no transport */

    /* A non-NULL but stack-allocated transport pointer satisfies the
     * arg-validation check (init only checks for NULL — it doesn't
     * inspect the transport's state, which is correct since the DHT
     * v1.0 just stashes the pointer). */
    ants_transport_t t = {{0}};
    cfg.transport = &t;
    cfg.event_fn = NULL;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_ERROR_INVALID_ARG); /* no event_fn */

    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_destroy_rejects_null(void)
{
    CHECK_EQ(ants_dht_destroy(NULL), ANTS_ERROR_INVALID_ARG);

    /* destroy on a zeroed dht is a no-op (safe re-init pattern). */
    ants_dht_t d = {{0}};
    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_tick_returns_idle_sentinel(void)
{
    /* Phase 1: no state to drive. tick() returns UINT32_MAX so the
     * caller's poll loop blocks until socket-readable rather than
     * busy-spinning on this DHT. */
    ants_dht_t d = {{0}};
    CHECK(ants_dht_tick(&d) == UINT32_MAX);
}

static void test_action_stubs_return_not_implemented(void)
{
    ants_dht_t d = {{0}};
    ants_dht_lookup_t l = {{0}};
    ants_peer_id_t pid;
    memset(&pid, 0, sizeof pid);

    /* Action APIs: all NOT_IMPLEMENTED in phase 1. NULL-arg checks
     * run first and return INVALID_ARG, so we pass valid pointers. */
    CHECK_EQ(ants_dht_bootstrap(&d, "/ip4/127.0.0.1/udp/4242/quic-v1", &pid),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_dht_announce(&d, 0x12345678ABCDEF00ULL), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_dht_unannounce(&d, 0x12345678ABCDEF00ULL), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_dht_lookup(&d, 0x12345678ABCDEF00ULL, &l), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_dht_lookup_cancel(&l), ANTS_ERROR_NOT_IMPLEMENTED);

    /* NULL-arg guards. */
    CHECK_EQ(ants_dht_bootstrap(NULL, "/ip4/127.0.0.1/udp/4242/quic-v1", &pid),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_bootstrap(&d, NULL, &pid), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_bootstrap(&d, "/ip4/127.0.0.1/udp/4242/quic-v1", NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_announce(NULL, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_unannounce(NULL, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_lookup(NULL, 0, &l), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_lookup(&d, 0, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_lookup_cancel(NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_introspection_safe_defaults(void)
{
    /* Observers return safe defaults rather than NOT_IMPLEMENTED so
     * callers that don't check error codes still see "empty table"
     * (matching ants_transport_peer_list's convention). */
    ants_dht_t d = {{0}};
    CHECK(ants_dht_routing_table_size(&d) == 0);

    ants_dht_peer_t peers[4];
    size_t count = 99;
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, peers, 4, &count), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(count == 0);

    /* NULL-arg guards. */
    CHECK_EQ(ants_dht_routing_table_enumerate(NULL, peers, 4, &count), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, peers, 4, NULL), ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_destroy_rejects_null();
    test_tick_returns_idle_sentinel();
    test_action_stubs_return_not_implemented();
    test_introspection_safe_defaults();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
