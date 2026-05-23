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
#include "dht_internal.h"
#include "dht_rpc.h"
#include "dht_wire.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    CHECK(ANTS_DHT_LOOKUP_CTX_SIZE == 16384);

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
    /* After phase 6, all the action APIs are implemented. The only
     * stubs left would be future-phase additions (none currently).
     * This test now only exercises the NULL-arg guard surface, which
     * is part of the stable contract regardless of implementation
     * status. */
    ants_dht_t d = {{0}};
    ants_dht_lookup_t l = {{0}};
    ants_peer_id_t pid;
    memset(&pid, 0, sizeof pid);

    /* bootstrap on a zero-init dht: transport is NULL → INVALID_ARG
     * (treated like a missing required field). */
    CHECK_EQ(ants_dht_bootstrap(&d, "/ip4/127.0.0.1/udp/4242/quic-v1", &pid),
             ANTS_ERROR_INVALID_ARG);

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

static void test_introspection_empty_table(void)
{
    /* Empty table — phase 2 implements both size() and enumerate()
     * against the actual k-bucket data structure. With no insertions,
     * size returns 0 and enumerate succeeds with *out_count = 0. */
    ants_dht_t d = {{0}};
    CHECK(ants_dht_routing_table_size(&d) == 0);

    ants_dht_peer_t peers[4];
    size_t count = 99;
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, peers, 4, &count), ANTS_OK);
    CHECK(count == 0);

    /* NULL-arg guards. */
    CHECK_EQ(ants_dht_routing_table_enumerate(NULL, peers, 4, &count), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, peers, 4, NULL), ANTS_ERROR_INVALID_ARG);
    /* cap > 0 with NULL out_peers is rejected (we'd otherwise write
     * to a NULL pointer in the enumerate copy loop). */
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, NULL, 4, &count), ANTS_ERROR_INVALID_ARG);

    /* size() returns 0 on NULL too (observer-safe). */
    CHECK(ants_dht_routing_table_size(NULL) == 0);
}

/* ------------------------------------------------------------------------ */
/* K-bucket internal-API tests                                              */
/*                                                                          */
/* Phase 2 exposes a small private test hook surface (ants_dht__test_*) so  */
/* we can exercise XOR-distance bucket placement and insertion/eviction    */
/* without first wiring bootstrap/dial. Declared extern here, defined in   */
/* dht.c. Production callers never touch these.                             */
/* ------------------------------------------------------------------------ */

extern ants_error_t
ants_dht__test_insert_peer(ants_dht_t *dht, const ants_dht_peer_t *peer, uint64_t now_us);
extern ants_error_t ants_dht__test_insert_peer_with_conn(ants_dht_t *dht,
                                                         const ants_dht_peer_t *peer,
                                                         ants_transport_conn_t *conn,
                                                         uint64_t now_us);
extern ants_error_t ants_dht__test_remove_peer(ants_dht_t *dht, const ants_peer_id_t *peer_id);
extern uint32_t ants_dht__test_bucket_index(const ants_dht_t *dht, const ants_peer_id_t *peer_id);

/* Phase 6.1.a maintenance-tick test hooks. State snapshot exposes the
 * entry's last_seen_us + dead_strikes so tests can verify refresh-tick
 * effects without inspecting the internal struct directly. */
typedef struct {
    bool exists;
    uint64_t last_seen_us;
    uint8_t dead_strikes;
    bool ping_in_flight;
} ants_dht__test_entry_state_t;
extern void ants_dht__test_get_entry_state(const ants_dht_t *dht,
                                           const ants_peer_id_t *peer_id,
                                           ants_dht__test_entry_state_t *out);
extern uint64_t ants_dht__test_now_us(void);

/* Helper: zero-init a dht with a deterministic local pubkey. */
static ants_error_t test_init_with_local(ants_dht_t *d,
                                         const uint8_t local_pub[ANTS_ED25519_PUBKEY_SIZE])
{
    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    static ants_transport_t dummy_transport = {{0}};
    cfg.transport = &dummy_transport;
    cfg.event_fn = test_noop_event;
    memcpy(cfg.local_peer_id.bytes, local_pub, ANTS_ED25519_PUBKEY_SIZE);
    return ants_dht_init(d, &cfg);
}

/* Helper: build a peer at a known XOR distance from local. For test
 * determinism: take local, flip a single bit at `flip_bit` (0 = LSB,
 * 255 = MSB), use the result as the peer's pubkey. The peer is then
 * guaranteed to land in bucket `flip_bit`. */
static void test_make_peer(const uint8_t local[ANTS_ED25519_PUBKEY_SIZE],
                           uint32_t flip_bit,
                           ants_dht_peer_t *out_peer)
{
    memset(out_peer, 0, sizeof *out_peer);
    memcpy(out_peer->peer_id.bytes, local, ANTS_ED25519_PUBKEY_SIZE);
    /* flip_bit indexes bits from LSB (0) within the entire 256-bit ID.
     * Big-endian layout: byte index for bit i is (31 - i/8); bit
     * position within that byte is i % 8. */
    uint32_t byte_idx = (uint32_t)ANTS_PEER_ID_SIZE - 1 - flip_bit / 8;
    uint32_t bit_in_byte = flip_bit % 8;
    out_peer->peer_id.bytes[byte_idx] ^= (uint8_t)(1u << bit_in_byte);
    /* Stash a recognisable multiaddr so we can match peers after
     * enumerate. The flip_bit value is the discriminator. */
    snprintf(out_peer->multiaddr,
             sizeof out_peer->multiaddr,
             "/ip4/127.0.0.1/udp/%u/quic-v1",
             (unsigned)(flip_bit + 1));
}

static void test_bucket_index_math(void)
{
    /* Local id = all zeros. Peers at single-bit-flip positions land
     * in their flip_bit's bucket. */
    uint8_t local[ANTS_ED25519_PUBKEY_SIZE] = {0};
    ants_dht_t d = {{0}};
    CHECK_EQ(test_init_with_local(&d, local), ANTS_OK);

    /* LSB flip → bucket 0. */
    ants_dht_peer_t p;
    test_make_peer(local, 0, &p);
    CHECK(ants_dht__test_bucket_index(&d, &p.peer_id) == 0);

    /* MSB flip → bucket 255. */
    test_make_peer(local, 255, &p);
    CHECK(ants_dht__test_bucket_index(&d, &p.peer_id) == 255);

    /* Middle: bit 127 → bucket 127. */
    test_make_peer(local, 127, &p);
    CHECK(ants_dht__test_bucket_index(&d, &p.peer_id) == 127);

    /* Self-insertion sentinel: XOR is zero → UINT32_MAX. */
    ants_peer_id_t self;
    memcpy(self.bytes, local, ANTS_ED25519_PUBKEY_SIZE);
    CHECK(ants_dht__test_bucket_index(&d, &self) == UINT32_MAX);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_kbucket_insert_and_enumerate(void)
{
    uint8_t local[ANTS_ED25519_PUBKEY_SIZE] = {0};
    ants_dht_t d = {{0}};
    CHECK_EQ(test_init_with_local(&d, local), ANTS_OK);

    /* Insert 10 peers at distinct bit-flip positions → 10 different
     * buckets, 10 total entries. */
    for (uint32_t i = 0; i < 10; i++) {
        ants_dht_peer_t p;
        test_make_peer(local, i * 16, &p); /* bits 0, 16, 32, ..., 144 */
        CHECK_EQ(ants_dht__test_insert_peer(&d, &p, 1000 + i), ANTS_OK);
    }
    CHECK(ants_dht_routing_table_size(&d) == 10);

    /* Inserting the same peer again is idempotent (refresh, not duplicate). */
    ants_dht_peer_t dup;
    test_make_peer(local, 0, &dup);
    CHECK_EQ(ants_dht__test_insert_peer(&d, &dup, 2000), ANTS_OK);
    CHECK(ants_dht_routing_table_size(&d) == 10);

    /* Enumerate them all. */
    ants_dht_peer_t out[20];
    size_t count = 0;
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, out, 20, &count), ANTS_OK);
    CHECK(count == 10);

    /* Too-small buffer: BUFFER_TOO_SMALL with *out_count = total available. */
    count = 0;
    CHECK_EQ(ants_dht_routing_table_enumerate(&d, out, 5, &count), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(count == 10);

    /* Self-insertion rejected. */
    ants_dht_peer_t self;
    memset(&self, 0, sizeof self);
    memcpy(self.peer_id.bytes, local, ANTS_PEER_ID_SIZE);
    CHECK_EQ(ants_dht__test_insert_peer(&d, &self, 0), ANTS_ERROR_INVALID_ARG);
    CHECK(ants_dht_routing_table_size(&d) == 10);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_kbucket_full_rejects(void)
{
    /* Insert K+1 peers that all land in the same bucket. The K+1-th
     * insertion is rejected with BUFFER_TOO_SMALL (phase 2 has no
     * LRU eviction — that's phase 6). */
    uint8_t local[ANTS_ED25519_PUBKEY_SIZE] = {0};
    ants_dht_t d = {{0}};
    CHECK_EQ(test_init_with_local(&d, local), ANTS_OK);

    /* Construct K+1 peers all in bucket 0 (low-bit-flip + high-bit-XOR
     * variations that keep the top set bit at position 0). For bucket
     * 0 we need XOR with MSB at position 0, i.e. XOR == 1. So only one
     * peer can land in bucket 0 — we need a different strategy.
     *
     * Instead use bucket 255: peers whose pubkey differs from local
     * only in the MSB plus low-order bits. We flip bit 255 plus K
     * different combinations of lower bits — all land in bucket 255
     * because the MSB-XOR dominates. */
    for (size_t i = 0; i < ANTS_DHT_K; i++) {
        ants_dht_peer_t p;
        memset(&p, 0, sizeof p);
        /* High-bit-flip (bit 255) plus a unique low-bit pattern. */
        p.peer_id.bytes[0] ^= 0x80;
        /* Encode i into the bottom byte to make each ID unique. */
        p.peer_id.bytes[ANTS_PEER_ID_SIZE - 1] = (uint8_t)i;
        CHECK_EQ(ants_dht__test_insert_peer(&d, &p, 1000 + i), ANTS_OK);
    }
    CHECK(ants_dht_routing_table_size(&d) == ANTS_DHT_K);

    /* Add one more — bucket is full. */
    ants_dht_peer_t overflow;
    memset(&overflow, 0, sizeof overflow);
    overflow.peer_id.bytes[0] ^= 0x80;
    overflow.peer_id.bytes[ANTS_PEER_ID_SIZE - 1] = 0xFF;
    CHECK_EQ(ants_dht__test_insert_peer(&d, &overflow, 9999), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(ants_dht_routing_table_size(&d) == ANTS_DHT_K);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_kbucket_remove(void)
{
    uint8_t local[ANTS_ED25519_PUBKEY_SIZE] = {0};
    ants_dht_t d = {{0}};
    CHECK_EQ(test_init_with_local(&d, local), ANTS_OK);

    /* Insert 3 peers. */
    ants_dht_peer_t p0, p1, p2;
    test_make_peer(local, 10, &p0);
    test_make_peer(local, 20, &p1);
    test_make_peer(local, 30, &p2);
    CHECK_EQ(ants_dht__test_insert_peer(&d, &p0, 1), ANTS_OK);
    CHECK_EQ(ants_dht__test_insert_peer(&d, &p1, 2), ANTS_OK);
    CHECK_EQ(ants_dht__test_insert_peer(&d, &p2, 3), ANTS_OK);
    CHECK(ants_dht_routing_table_size(&d) == 3);

    /* Remove the middle one. */
    CHECK_EQ(ants_dht__test_remove_peer(&d, &p1.peer_id), ANTS_OK);
    CHECK(ants_dht_routing_table_size(&d) == 2);

    /* Removing a not-present peer returns NOT_IMPLEMENTED (our
     * placeholder for "not found"). */
    CHECK_EQ(ants_dht__test_remove_peer(&d, &p1.peer_id), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(ants_dht_routing_table_size(&d) == 2);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_destroy_frees_heap_entries(void)
{
    /* Insert peers, destroy, re-init, destroy again. ASan would catch
     * any leak across this sequence. */
    uint8_t local[ANTS_ED25519_PUBKEY_SIZE] = {0};
    ants_dht_t d = {{0}};

    for (int iter = 0; iter < 3; iter++) {
        CHECK_EQ(test_init_with_local(&d, local), ANTS_OK);
        for (uint32_t i = 0; i < 50; i++) {
            ants_dht_peer_t p;
            test_make_peer(local, i * 5, &p); /* bits 0, 5, 10, ..., 245 */
            CHECK_EQ(ants_dht__test_insert_peer(&d, &p, i + 1), ANTS_OK);
        }
        CHECK(ants_dht_routing_table_size(&d) == 50);
        CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
        CHECK(ants_dht_routing_table_size(&d) == 0);
    }
}

/* ------------------------------------------------------------------------ */
/* Wire codec round-trip tests                                              */
/*                                                                          */
/* Round-trip every message type: encode → decode → assert fields match.   */
/* The wire codec is in src/dht_wire.{h,c} (private to the dht module).    */
/* foundation/cbor enforces canonical encoding on the encode side and       */
/* rejects non-canonical input on the decode side, so a successful round-   */
/* trip implies the bytes-on-the-wire are deterministic.                    */
/* ------------------------------------------------------------------------ */

/* Encode buffer big enough for the largest message (FIND_NODE_RESP with
 * 20 peers × ~80 bytes each + envelope = ~1700 bytes). */
#define WIRE_BUF_CAP 4096

static void fill_test_peer(ants_dht_peer_t *peer, uint32_t i)
{
    memset(peer, 0, sizeof *peer);
    /* Deterministic peer-id: byte 0 = i, rest = 0xAB. */
    peer->peer_id.bytes[0] = (uint8_t)(i & 0xFF);
    for (size_t j = 1; j < ANTS_PEER_ID_SIZE; j++) {
        peer->peer_id.bytes[j] = 0xAB;
    }
    snprintf(peer->multiaddr,
             sizeof peer->multiaddr,
             "/ip4/127.0.0.1/udp/%u/quic-v1",
             (unsigned)(4242 + i));
}

static void test_wire_peek_type(void)
{
    /* Encode a PING, decode just the type via the peek helper. */
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;
    ants_dht_ping_req_t ping = {.txid = 7};
    CHECK_EQ(ants_dht_wire_encode_ping_req(buf, sizeof buf, &len, &ping), ANTS_OK);
    ants_dht_msg_type_t type;
    CHECK_EQ(ants_dht_wire_peek_type(buf, len, &type), ANTS_OK);
    CHECK(type == ANTS_DHT_MSG_PING);

    /* Same for a FIND_NODE_RESP. */
    ants_dht_find_node_resp_t fnr;
    memset(&fnr, 0, sizeof fnr);
    fnr.txid = 42;
    fnr.peer_count = 2;
    fill_test_peer(&fnr.peers[0], 0);
    fill_test_peer(&fnr.peers[1], 1);
    CHECK_EQ(ants_dht_wire_encode_find_node_resp(buf, sizeof buf, &len, &fnr), ANTS_OK);
    CHECK_EQ(ants_dht_wire_peek_type(buf, len, &type), ANTS_OK);
    CHECK(type == ANTS_DHT_MSG_FIND_NODE_RESP);
}

static void test_wire_ping_roundtrip(void)
{
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;

    ants_dht_ping_req_t req = {.txid = 0x12345678};
    CHECK_EQ(ants_dht_wire_encode_ping_req(buf, sizeof buf, &len, &req), ANTS_OK);
    /* PING has the smallest possible envelope: map(2) with two uint kv
     * pairs. Sanity-check it's small. */
    CHECK(len < 20);

    ants_dht_ping_req_t dec_req;
    memset(&dec_req, 0, sizeof dec_req);
    CHECK_EQ(ants_dht_wire_decode_ping_req(buf, len, &dec_req), ANTS_OK);
    CHECK(dec_req.txid == req.txid);

    /* PING_RESP — same shape, different type tag. */
    ants_dht_ping_resp_t resp = {.txid = 99};
    CHECK_EQ(ants_dht_wire_encode_ping_resp(buf, sizeof buf, &len, &resp), ANTS_OK);

    ants_dht_ping_resp_t dec_resp;
    memset(&dec_resp, 0, sizeof dec_resp);
    CHECK_EQ(ants_dht_wire_decode_ping_resp(buf, len, &dec_resp), ANTS_OK);
    CHECK(dec_resp.txid == resp.txid);

    /* Cross-type decode: PING_RESP encoded, decoded as PING — should fail. */
    CHECK_EQ(ants_dht_wire_decode_ping_req(buf, len, &dec_req), ANTS_ERROR_NON_CANONICAL);
}

static void test_wire_find_node_roundtrip(void)
{
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;

    /* Request: txid + target. */
    ants_dht_find_node_req_t req;
    memset(&req, 0, sizeof req);
    req.txid = 0xDEADBEEF;
    for (size_t i = 0; i < ANTS_PEER_ID_SIZE; i++) {
        req.target.bytes[i] = (uint8_t)(i * 7 + 1);
    }
    CHECK_EQ(ants_dht_wire_encode_find_node_req(buf, sizeof buf, &len, &req), ANTS_OK);

    ants_dht_find_node_req_t dec_req;
    memset(&dec_req, 0, sizeof dec_req);
    CHECK_EQ(ants_dht_wire_decode_find_node_req(buf, len, &dec_req), ANTS_OK);
    CHECK(dec_req.txid == req.txid);
    CHECK(memcmp(dec_req.target.bytes, req.target.bytes, ANTS_PEER_ID_SIZE) == 0);

    /* Response: 0, 1, K peers — boundary cases. */
    for (size_t n = 0; n <= ANTS_DHT_K; n++) {
        ants_dht_find_node_resp_t resp;
        memset(&resp, 0, sizeof resp);
        resp.txid = (uint32_t)(n + 100);
        resp.peer_count = n;
        for (size_t i = 0; i < n; i++) {
            fill_test_peer(&resp.peers[i], (uint32_t)i);
        }
        CHECK_EQ(ants_dht_wire_encode_find_node_resp(buf, sizeof buf, &len, &resp), ANTS_OK);

        ants_dht_find_node_resp_t dec_resp;
        memset(&dec_resp, 0, sizeof dec_resp);
        CHECK_EQ(ants_dht_wire_decode_find_node_resp(buf, len, &dec_resp), ANTS_OK);
        CHECK(dec_resp.txid == resp.txid);
        CHECK(dec_resp.peer_count == n);
        for (size_t i = 0; i < n; i++) {
            CHECK(memcmp(dec_resp.peers[i].peer_id.bytes,
                         resp.peers[i].peer_id.bytes,
                         ANTS_PEER_ID_SIZE) == 0);
            CHECK(strcmp(dec_resp.peers[i].multiaddr, resp.peers[i].multiaddr) == 0);
        }
    }

    /* Over-cap peer_count rejected at encode. */
    ants_dht_find_node_resp_t over;
    memset(&over, 0, sizeof over);
    over.peer_count = ANTS_DHT_MAX_PEERS_PER_MSG + 1;
    CHECK_EQ(ants_dht_wire_encode_find_node_resp(buf, sizeof buf, &len, &over),
             ANTS_ERROR_INVALID_ARG);
}

static void test_wire_get_peers_roundtrip(void)
{
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;

    /* Request. */
    ants_dht_get_peers_req_t req = {.txid = 0xCAFEBABE, .key = 0x0123456789ABCDEFULL};
    CHECK_EQ(ants_dht_wire_encode_get_peers_req(buf, sizeof buf, &len, &req), ANTS_OK);

    ants_dht_get_peers_req_t dec_req;
    memset(&dec_req, 0, sizeof dec_req);
    CHECK_EQ(ants_dht_wire_decode_get_peers_req(buf, len, &dec_req), ANTS_OK);
    CHECK(dec_req.txid == req.txid);
    CHECK(dec_req.key == req.key);

    /* Response with peers + token. */
    ants_dht_get_peers_resp_t resp;
    memset(&resp, 0, sizeof resp);
    resp.txid = 0xFEEDFACE;
    resp.peer_count = 3;
    fill_test_peer(&resp.peers[0], 10);
    fill_test_peer(&resp.peers[1], 20);
    fill_test_peer(&resp.peers[2], 30);
    for (size_t i = 0; i < ANTS_DHT_TOKEN_SIZE; i++) {
        resp.token[i] = (uint8_t)(0x55 ^ i);
    }
    CHECK_EQ(ants_dht_wire_encode_get_peers_resp(buf, sizeof buf, &len, &resp), ANTS_OK);

    ants_dht_get_peers_resp_t dec_resp;
    memset(&dec_resp, 0, sizeof dec_resp);
    CHECK_EQ(ants_dht_wire_decode_get_peers_resp(buf, len, &dec_resp), ANTS_OK);
    CHECK(dec_resp.txid == resp.txid);
    CHECK(dec_resp.peer_count == 3);
    CHECK(memcmp(dec_resp.token, resp.token, ANTS_DHT_TOKEN_SIZE) == 0);
    for (size_t i = 0; i < 3; i++) {
        CHECK(strcmp(dec_resp.peers[i].multiaddr, resp.peers[i].multiaddr) == 0);
    }
}

static void test_wire_announce_peer_roundtrip(void)
{
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;

    /* Request: key + token. */
    ants_dht_announce_peer_req_t req;
    memset(&req, 0, sizeof req);
    req.txid = 1;
    req.key = 0xAA55AA55AA55AA55ULL;
    for (size_t i = 0; i < ANTS_DHT_TOKEN_SIZE; i++) {
        req.token[i] = (uint8_t)i;
    }
    CHECK_EQ(ants_dht_wire_encode_announce_peer_req(buf, sizeof buf, &len, &req), ANTS_OK);

    ants_dht_announce_peer_req_t dec_req;
    memset(&dec_req, 0, sizeof dec_req);
    CHECK_EQ(ants_dht_wire_decode_announce_peer_req(buf, len, &dec_req), ANTS_OK);
    CHECK(dec_req.txid == req.txid);
    CHECK(dec_req.key == req.key);
    CHECK(memcmp(dec_req.token, req.token, ANTS_DHT_TOKEN_SIZE) == 0);

    /* Response: ack only. */
    ants_dht_announce_peer_resp_t resp = {.txid = 2};
    CHECK_EQ(ants_dht_wire_encode_announce_peer_resp(buf, sizeof buf, &len, &resp), ANTS_OK);

    ants_dht_announce_peer_resp_t dec_resp;
    memset(&dec_resp, 0, sizeof dec_resp);
    CHECK_EQ(ants_dht_wire_decode_announce_peer_resp(buf, len, &dec_resp), ANTS_OK);
    CHECK(dec_resp.txid == resp.txid);
}

static void test_wire_rejects_truncation(void)
{
    /* Encode a valid FIND_NODE_REQ. Truncating the buffer by 1 byte
     * must reject. */
    uint8_t buf[WIRE_BUF_CAP];
    size_t len = 0;
    ants_dht_find_node_req_t req;
    memset(&req, 0, sizeof req);
    req.txid = 42;
    CHECK_EQ(ants_dht_wire_encode_find_node_req(buf, sizeof buf, &len, &req), ANTS_OK);
    CHECK(len > 1);

    ants_dht_find_node_req_t dec;
    /* Trailing-byte truncation: decoder either fails decode or
     * finalise-fails because fewer bytes remain. */
    CHECK(ants_dht_wire_decode_find_node_req(buf, len - 1, &dec) != ANTS_OK);
}

static void test_wire_rejects_buffer_too_small(void)
{
    /* Encode into a 4-byte buffer: PING needs more — BUFFER_TOO_SMALL. */
    uint8_t tiny[4];
    size_t len = 99;
    ants_dht_ping_req_t req = {.txid = 1};
    CHECK_EQ(ants_dht_wire_encode_ping_req(tiny, sizeof tiny, &len, &req),
             ANTS_ERROR_BUFFER_TOO_SMALL);
}

/* ------------------------------------------------------------------------ */
/* Phase 4: RPC dispatch round-trip                                         */
/*                                                                          */
/* Two real transports (A=dialer, B=listener) exchange CBOR-encoded RPC    */
/* requests/responses over QUIC bidi streams. A drives outbound RPCs       */
/* through the DHT dispatcher; B acts as a manual server (decode-and-      */
/* respond) since the server-side dispatch logic lands in phase 5+.        */
/*                                                                          */
/* Test hooks declared in dht.c expose the dht_rpc_send_* primitives:      */
/* ------------------------------------------------------------------------ */

extern ants_error_t ants_dht__test_send_ping(ants_dht_t *dht,
                                             ants_transport_conn_t *conn,
                                             ants_dht_rpc_completion_fn completion,
                                             void *ctx);
extern ants_error_t ants_dht__test_send_find_node(ants_dht_t *dht,
                                                  ants_transport_conn_t *conn,
                                                  const ants_peer_id_t *target,
                                                  ants_dht_rpc_completion_fn completion,
                                                  void *ctx);
extern ants_error_t ants_dht__test_send_get_peers(ants_dht_t *dht,
                                                  ants_transport_conn_t *conn,
                                                  ants_dht_shard_key_t key,
                                                  ants_dht_rpc_completion_fn completion,
                                                  void *ctx);
extern ants_error_t ants_dht__test_send_announce_peer(ants_dht_t *dht,
                                                      ants_transport_conn_t *conn,
                                                      ants_dht_shard_key_t key,
                                                      const uint8_t token[ANTS_DHT_TOKEN_SIZE],
                                                      ants_dht_rpc_completion_fn completion,
                                                      void *ctx);

/* Real-key sign callback: signs the TLS handshake transcript with the
 * Ed25519 private key passed via sign_ctx. Same shape as the one in
 * test_transport.c. */
static ants_error_t test_real_sign(const uint8_t *transcript,
                                   size_t transcript_len,
                                   uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                                   void *sign_ctx)
{
    const uint8_t *priv = (const uint8_t *)sign_ctx;
    return ants_ed25519_sign(priv, transcript, transcript_len, out_sig);
}

/* Server-side state: B accumulates inbound request bytes per stream and
 * synthesises a response on STREAM_FIN. respond_with selects the RPC
 * type B should answer with — caller sets it before each round. */
#define TEST_RPC_BUF_SIZE 2048

typedef struct {
    ants_transport_stream_t *inbound_stream;
    uint8_t recv_buf[TEST_RPC_BUF_SIZE];
    size_t recv_len;
    ants_dht_msg_type_t respond_with;
    int stream_opened;
    int stream_readable;
    int stream_fin;
    int response_sent;
    ants_error_t last_err;
} test_rpc_server_t;

static void test_rpc_server_reset(test_rpc_server_t *s)
{
    s->inbound_stream = NULL;
    s->recv_len = 0;
    s->stream_opened = 0;
    s->stream_readable = 0;
    s->stream_fin = 0;
    s->response_sent = 0;
    s->last_err = ANTS_OK;
}

/* Build a response based on the inbound request and respond_with. Returns
 * the encoded length via *out_len; 0 on failure. */
static ants_error_t
test_rpc_build_response(test_rpc_server_t *s, uint8_t *out, size_t cap, size_t *out_len)
{
    ants_error_t err = ANTS_ERROR_NOT_IMPLEMENTED;
    switch (s->respond_with) {
    case ANTS_DHT_MSG_PING_RESP: {
        ants_dht_ping_req_t req;
        memset(&req, 0, sizeof req);
        err = ants_dht_wire_decode_ping_req(s->recv_buf, s->recv_len, &req);
        if (err != ANTS_OK) {
            return err;
        }
        ants_dht_ping_resp_t resp;
        resp.txid = req.txid;
        return ants_dht_wire_encode_ping_resp(out, cap, out_len, &resp);
    }
    case ANTS_DHT_MSG_FIND_NODE_RESP: {
        ants_dht_find_node_req_t req;
        memset(&req, 0, sizeof req);
        err = ants_dht_wire_decode_find_node_req(s->recv_buf, s->recv_len, &req);
        if (err != ANTS_OK) {
            return err;
        }
        ants_dht_find_node_resp_t resp;
        memset(&resp, 0, sizeof resp);
        resp.txid = req.txid;
        /* Synthesise a single fake-peer response so the encode path
         * exercises the peer-array case. */
        resp.peer_count = 1;
        memset(resp.peers[0].peer_id.bytes, 0xCC, ANTS_PEER_ID_SIZE);
        snprintf(resp.peers[0].multiaddr,
                 sizeof resp.peers[0].multiaddr,
                 "/ip4/127.0.0.1/udp/9999/quic-v1");
        return ants_dht_wire_encode_find_node_resp(out, cap, out_len, &resp);
    }
    case ANTS_DHT_MSG_GET_PEERS_RESP: {
        ants_dht_get_peers_req_t req;
        memset(&req, 0, sizeof req);
        err = ants_dht_wire_decode_get_peers_req(s->recv_buf, s->recv_len, &req);
        if (err != ANTS_OK) {
            return err;
        }
        ants_dht_get_peers_resp_t resp;
        memset(&resp, 0, sizeof resp);
        resp.txid = req.txid;
        resp.peer_count = 1;
        /* Use a distinct sentinel byte (0xEE) so the lookup-round-trip
         * test can tell apart a real GET_PEERS_RESP peer from the
         * find_node sentinel (0xCC). */
        memset(resp.peers[0].peer_id.bytes, 0xEE, ANTS_PEER_ID_SIZE);
        snprintf(resp.peers[0].multiaddr,
                 sizeof resp.peers[0].multiaddr,
                 "/ip4/127.0.0.1/udp/12345/quic-v1");
        memset(resp.token, 0xAB, ANTS_DHT_TOKEN_SIZE);
        return ants_dht_wire_encode_get_peers_resp(out, cap, out_len, &resp);
    }
    default:
        return ANTS_ERROR_NOT_IMPLEMENTED;
    }
}

static ants_error_t test_rpc_server_event(const ants_transport_event_t *ev, void *ctx)
{
    test_rpc_server_t *s = (test_rpc_server_t *)ctx;
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_OPENED:
        s->stream_opened++;
        s->inbound_stream = ev->stream;
        s->recv_len = 0;
        break;
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        s->stream_readable++;
        if (ev->payload != NULL && ev->payload_len > 0 &&
            ev->payload_len <= sizeof s->recv_buf - s->recv_len) {
            memcpy(s->recv_buf + s->recv_len, ev->payload, ev->payload_len);
            s->recv_len += ev->payload_len;
        }
        break;
    case ANTS_TRANSPORT_EV_STREAM_FIN: {
        s->stream_fin++;
        uint8_t resp[TEST_RPC_BUF_SIZE];
        size_t resp_len = 0;
        ants_error_t err = test_rpc_build_response(s, resp, sizeof resp, &resp_len);
        if (err != ANTS_OK) {
            s->last_err = err;
            break;
        }
        if (s->inbound_stream == NULL) {
            s->last_err = ANTS_ERROR_INVALID_ARG;
            break;
        }
        err = ants_transport_stream_send(s->inbound_stream, resp, resp_len, true /* fin */);
        if (err == ANTS_OK) {
            s->response_sent++;
        } else {
            s->last_err = err;
        }
        break;
    }
    default:
        break;
    }
    return ANTS_OK;
}

/* Client-side: forward EVERY transport event to the DHT. The dispatcher
 * silently ignores non-RPC events. CONN_READY captures the peer_id of
 * the remote so the lookup test can seed it into A's routing table
 * with the live conn pointer. */
typedef struct {
    ants_dht_t *dht;
    int conn_ready;
    ants_peer_id_t peer_id;
} test_rpc_client_t;

static ants_error_t test_rpc_client_event(const ants_transport_event_t *ev, void *ctx)
{
    test_rpc_client_t *c = (test_rpc_client_t *)ctx;
    if (c->dht != NULL) {
        ants_dht_handle_transport_event(c->dht, ev);
    }
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        c->conn_ready++;
        c->peer_id = ev->peer_id;
    }
    return ANTS_OK;
}

/* Completion recorder: captures status + a copy of the decoded response
 * struct (the response pointer is only valid for the duration of the
 * callback, so we snapshot what we need). */
typedef struct {
    int fired;
    ants_error_t last_status;
    ants_dht_msg_type_t last_resp_type;
    ants_dht_ping_resp_t last_ping;
    ants_dht_find_node_resp_t last_find_node;
} test_rpc_completion_t;

static void test_rpc_complete_ping(ants_error_t status, const void *resp, void *ctx)
{
    test_rpc_completion_t *c = (test_rpc_completion_t *)ctx;
    c->fired++;
    c->last_status = status;
    if (status == ANTS_OK && resp != NULL) {
        c->last_resp_type = ANTS_DHT_MSG_PING_RESP;
        c->last_ping = *(const ants_dht_ping_resp_t *)resp;
    }
}

static void test_rpc_complete_find_node(ants_error_t status, const void *resp, void *ctx)
{
    test_rpc_completion_t *c = (test_rpc_completion_t *)ctx;
    c->fired++;
    c->last_status = status;
    if (status == ANTS_OK && resp != NULL) {
        c->last_resp_type = ANTS_DHT_MSG_FIND_NODE_RESP;
        c->last_find_node = *(const ants_dht_find_node_resp_t *)resp;
    }
}

static void test_rpc_send_rejects_invalid_args(void)
{
    ants_dht_t d = {{0}};
    ants_transport_conn_t conn = {{0}};
    ants_peer_id_t pid;
    memset(&pid, 0, sizeof pid);
    uint8_t token[ANTS_DHT_TOKEN_SIZE] = {0};

    /* NULL guards on every send_*. completion required (non-NULL). */
    CHECK_EQ(ants_dht__test_send_ping(NULL, &conn, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_ping(&d, NULL, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_ping(&d, &conn, NULL, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_dht__test_send_find_node(NULL, &conn, &pid, test_rpc_complete_find_node, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_find_node(&d, NULL, &pid, test_rpc_complete_find_node, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_find_node(&d, &conn, NULL, test_rpc_complete_find_node, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_find_node(&d, &conn, &pid, NULL, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_dht__test_send_get_peers(NULL, &conn, 0, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_get_peers(&d, NULL, 0, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_get_peers(&d, &conn, 0, NULL, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_dht__test_send_announce_peer(NULL, &conn, 0, token, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_announce_peer(&d, NULL, 0, token, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_announce_peer(&d, &conn, 0, NULL, test_rpc_complete_ping, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht__test_send_announce_peer(&d, &conn, 0, token, NULL, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* handle_transport_event NULL guards. */
    ants_transport_event_t ev;
    memset(&ev, 0, sizeof ev);
    CHECK_EQ(ants_dht_handle_transport_event(NULL, &ev), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_handle_transport_event(&d, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_rpc_handle_event_ignores_non_dht(void)
{
    /* Initialise a real (but no-transport) DHT and feed it events that
     * don't belong to any pending RPC. handle_transport_event must
     * return ANTS_OK without touching the registry. */
    ants_transport_t dummy_transport = {{0}};
    ants_dht_t d = {{0}};
    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.transport = &dummy_transport;
    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_OK);

    /* CONN_CLOSED with a conn pointer we never owned — should be a
     * no-op (no slots match). */
    ants_transport_conn_t fake_conn = {{0}};
    ants_transport_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = ANTS_TRANSPORT_EV_CONN_CLOSED;
    ev.conn = &fake_conn;
    CHECK_EQ(ants_dht_handle_transport_event(&d, &ev), ANTS_OK);

    /* STREAM_READABLE with a stream pointer we never owned. */
    ants_transport_stream_t fake_stream = {{0}};
    memset(&ev, 0, sizeof ev);
    ev.kind = ANTS_TRANSPORT_EV_STREAM_READABLE;
    ev.conn = &fake_conn;
    ev.stream = &fake_stream;
    const uint8_t data[] = {0xa2, 0x00, 0x05, 0x01, 0x01};
    ev.payload = data;
    ev.payload_len = sizeof data;
    CHECK_EQ(ants_dht_handle_transport_event(&d, &ev), ANTS_OK);

    /* Stream-scoped event with NULL stream pointer is a no-op too. */
    memset(&ev, 0, sizeof ev);
    ev.kind = ANTS_TRANSPORT_EV_STREAM_FIN;
    ev.conn = &fake_conn;
    ev.stream = NULL;
    CHECK_EQ(ants_dht_handle_transport_event(&d, &ev), ANTS_OK);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_rpc_round_trip(void)
{
    /* PING + FIND_NODE round trip over a real QUIC bidi stream. A is
     * the dialer running the DHT dispatcher; B is the listener acting
     * as a manual server (decodes the request, encodes a response,
     * sends it back on the same stream). */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x33, sizeof a_priv);
    memset(b_priv, 0x77, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_rpc_server_t server;
    memset(&server, 0, sizeof server);
    test_rpc_client_t client;
    memset(&client, 0, sizeof client);

    /* B = listener. */
    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_rpc_server_event;
    bcfg.event_ctx = &server;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    /* A = dialer. */
    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_rpc_client_event;
    acfg.event_ctx = &client;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    /* A's DHT, configured against A's transport. */
    ants_dht_t da = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_noop_event;
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    client.dht = &da;

    /* Dial. */
    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (client.conn_ready >= 1) {
            break;
        }
    }
    CHECK(client.conn_ready == 1);

    /* --- Round 1: PING --- */
    server.respond_with = ANTS_DHT_MSG_PING_RESP;
    test_rpc_completion_t comp_ping;
    memset(&comp_ping, 0, sizeof comp_ping);
    CHECK_EQ(ants_dht__test_send_ping(&da, &conn, test_rpc_complete_ping, &comp_ping), ANTS_OK);

    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (comp_ping.fired >= 1) {
            break;
        }
    }

    CHECK(server.stream_opened >= 1);
    CHECK(server.stream_fin >= 1);
    CHECK(server.response_sent == 1);
    CHECK(server.last_err == ANTS_OK);
    CHECK(comp_ping.fired == 1);
    CHECK_EQ(comp_ping.last_status, ANTS_OK);
    CHECK(comp_ping.last_resp_type == ANTS_DHT_MSG_PING_RESP);
    /* PING_RESP carries no body — only the txid. We don't pin a
     * specific txid value (the registry's monotonic counter would
     * leak as a test dependency); just verify it's non-zero. */
    CHECK(comp_ping.last_ping.txid != 0);

    /* --- Round 2: FIND_NODE --- */
    test_rpc_server_reset(&server);
    server.respond_with = ANTS_DHT_MSG_FIND_NODE_RESP;
    test_rpc_completion_t comp_fn;
    memset(&comp_fn, 0, sizeof comp_fn);
    ants_peer_id_t target;
    memset(target.bytes, 0x42, sizeof target.bytes);
    CHECK_EQ(
        ants_dht__test_send_find_node(&da, &conn, &target, test_rpc_complete_find_node, &comp_fn),
        ANTS_OK);

    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (comp_fn.fired >= 1) {
            break;
        }
    }

    CHECK(server.stream_opened == 1);
    CHECK(server.stream_fin == 1);
    CHECK(server.response_sent == 1);
    CHECK(server.last_err == ANTS_OK);
    CHECK(comp_fn.fired == 1);
    CHECK_EQ(comp_fn.last_status, ANTS_OK);
    CHECK(comp_fn.last_resp_type == ANTS_DHT_MSG_FIND_NODE_RESP);
    CHECK(comp_fn.last_find_node.peer_count == 1);
    if (comp_fn.last_find_node.peer_count == 1) {
        uint8_t expected_pid[ANTS_PEER_ID_SIZE];
        memset(expected_pid, 0xCC, sizeof expected_pid);
        CHECK(memcmp(comp_fn.last_find_node.peers[0].peer_id.bytes,
                     expected_pid,
                     ANTS_PEER_ID_SIZE) == 0);
        CHECK(strcmp(comp_fn.last_find_node.peers[0].multiaddr,
                     "/ip4/127.0.0.1/udp/9999/quic-v1") == 0);
    }

    /* Teardown: destroy DHT first (pending slots are all free at this
     * point — every RPC completed). Then destroy transports. ASan
     * catches any unfreed stream / recv_buf. */
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Phase 5: iterative-lookup state machine                                  */
/* ------------------------------------------------------------------------ */

typedef struct {
    int lookup_complete;
    int lookup_timeout;
    size_t last_peer_count;
    ants_dht_peer_t last_peers[ANTS_DHT_K];
    ants_dht_shard_key_t last_shard_key;
} test_lookup_recorder_t;

static ants_error_t test_lookup_event_fn(const ants_dht_event_t *ev, void *ctx)
{
    test_lookup_recorder_t *r = (test_lookup_recorder_t *)ctx;
    switch (ev->kind) {
    case ANTS_DHT_EV_LOOKUP_COMPLETE:
        r->lookup_complete++;
        r->last_peer_count = ev->peer_count;
        r->last_shard_key = ev->shard_key;
        if (ev->peers != NULL && ev->peer_count > 0) {
            size_t n = ev->peer_count < ANTS_DHT_K ? ev->peer_count : ANTS_DHT_K;
            memcpy(r->last_peers, ev->peers, n * sizeof *ev->peers);
        }
        break;
    case ANTS_DHT_EV_LOOKUP_TIMEOUT:
        r->lookup_timeout++;
        break;
    default:
        break;
    }
    return ANTS_OK;
}

static void test_lookup_no_candidates(void)
{
    /* A lookup with an empty routing table should converge on the very
     * first tick: no candidates, no in-flight RPCs, immediate
     * LOOKUP_COMPLETE with peer_count = 0. Exercises the convergence-
     * on-empty edge case without any transport. */
    ants_transport_t dummy_transport = {{0}};
    ants_dht_t d = {{0}};
    test_lookup_recorder_t rec;
    memset(&rec, 0, sizeof rec);

    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.transport = &dummy_transport;
    cfg.event_fn = test_lookup_event_fn;
    cfg.event_ctx = &rec;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_OK);

    ants_dht_lookup_t lookup = {{0}};
    CHECK_EQ(ants_dht_lookup(&d, 0xDEADBEEFCAFEBABEULL, &lookup), ANTS_OK);

    /* Tick triggers the first lookup_advance which observes the empty
     * state and fires LOOKUP_COMPLETE synchronously. */
    (void)ants_dht_tick(&d);

    CHECK(rec.lookup_complete == 1);
    CHECK(rec.last_peer_count == 0);
    CHECK(rec.last_shard_key == 0xDEADBEEFCAFEBABEULL);

    /* A second tick must not re-fire (the lookup is completed and
     * unregistered). */
    (void)ants_dht_tick(&d);
    CHECK(rec.lookup_complete == 1);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

static void test_lookup_round_trip(void)
{
    /* End-to-end iterative lookup with a single seed peer. A's routing
     * table is seeded with B (post-handshake conn pointer). A.lookup
     * issues GET_PEERS to B; B's manual server side answers with a
     * fake peer; A's lookup folds the response in, finds no new
     * UNQUERIED candidates, converges, fires LOOKUP_COMPLETE with the
     * B-supplied peer as the result. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x55, sizeof a_priv);
    memset(b_priv, 0xBB, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_rpc_server_t server;
    memset(&server, 0, sizeof server);
    test_rpc_client_t client;
    memset(&client, 0, sizeof client);
    test_lookup_recorder_t rec;
    memset(&rec, 0, sizeof rec);

    /* B = listener. */
    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_rpc_server_event;
    bcfg.event_ctx = &server;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    /* A = dialer with DHT delegation. */
    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_rpc_client_event;
    acfg.event_ctx = &client;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_lookup_event_fn;
    dcfg.event_ctx = &rec;
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    client.dht = &da;

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (client.conn_ready >= 1) {
            break;
        }
    }
    CHECK(client.conn_ready == 1);

    /* Seed A's routing table with B (peer_id captured from CONN_READY,
     * conn = the live connection). */
    ants_dht_peer_t b_peer;
    memset(&b_peer, 0, sizeof b_peer);
    b_peer.peer_id = client.peer_id;
    snprintf(b_peer.multiaddr, sizeof b_peer.multiaddr, "%s", baddr);
    CHECK_EQ(ants_dht__test_insert_peer_with_conn(&da, &b_peer, &conn, 100), ANTS_OK);
    CHECK(ants_dht_routing_table_size(&da) == 1);

    /* Tell the server how to respond. */
    server.respond_with = ANTS_DHT_MSG_GET_PEERS_RESP;

    /* Issue the lookup and drive both sides until LOOKUP_COMPLETE. */
    ants_dht_lookup_t lookup = {{0}};
    ants_dht_shard_key_t target = 0x123456789ABCDEF0ULL;
    CHECK_EQ(ants_dht_lookup(&da, target, &lookup), ANTS_OK);

    for (int i = 0; i < 300; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        if (rec.lookup_complete >= 1) {
            break;
        }
    }

    CHECK(server.stream_opened >= 1);
    CHECK(server.stream_fin >= 1);
    CHECK(server.response_sent == 1);
    CHECK(server.last_err == ANTS_OK);

    CHECK(rec.lookup_complete == 1);
    CHECK(rec.last_shard_key == target);
    /* B answered with one peer (peer_id = 0xEE bytes, multiaddr =
     * .../udp/12345/...). The lookup folded it into the candidate set;
     * it stays UNQUERIED (we have no conn to it) and doesn't appear
     * in the ANSWERED result. So the result set contains exactly B
     * itself, which IS ANSWERED. */
    CHECK(rec.last_peer_count == 1);
    if (rec.last_peer_count >= 1) {
        CHECK(memcmp(rec.last_peers[0].peer_id.bytes, client.peer_id.bytes, ANTS_PEER_ID_SIZE) ==
              0);
    }

    /* Teardown. */
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
}

static void test_lookup_cancel(void)
{
    /* Cancelling a lookup before it converges suppresses the
     * LOOKUP_COMPLETE event. The slot is unregistered so a later tick
     * doesn't drive it. (We don't bother issuing real RPCs here — the
     * cancellation path is exercised even when the lookup is "stuck"
     * in its seeded-empty state.) */
    ants_transport_t dummy_transport = {{0}};
    ants_dht_t d = {{0}};
    test_lookup_recorder_t rec;
    memset(&rec, 0, sizeof rec);

    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.transport = &dummy_transport;
    cfg.event_fn = test_lookup_event_fn;
    cfg.event_ctx = &rec;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_OK);

    ants_dht_lookup_t lookup = {{0}};
    CHECK_EQ(ants_dht_lookup(&d, 0x4242424242424242ULL, &lookup), ANTS_OK);

    /* Cancel before any tick. No event must ever fire. */
    CHECK_EQ(ants_dht_lookup_cancel(&lookup), ANTS_OK);

    /* Second cancel is idempotent. */
    CHECK_EQ(ants_dht_lookup_cancel(&lookup), ANTS_OK);

    /* Several ticks: no LOOKUP_COMPLETE / LOOKUP_TIMEOUT can fire. */
    for (int i = 0; i < 5; i++) {
        (void)ants_dht_tick(&d);
    }
    CHECK(rec.lookup_complete == 0);
    CHECK(rec.lookup_timeout == 0);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Phase 6: server-side dispatch + bootstrap                                */
/* ------------------------------------------------------------------------ */

static void test_announce_unannounce_local(void)
{
    /* Local announce/unannounce should not require transport. They
     * update the in-state announce sets (both the local-host list and
     * the server-side announce set) so subsequent GET_PEERS_REQ from
     * a peer who routes us hits a real entry. */
    ants_transport_t dummy_transport = {{0}};
    ants_dht_t d = {{0}};
    ants_dht_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.transport = &dummy_transport;
    cfg.event_fn = test_noop_event;
    CHECK_EQ(ants_dht_init(&d, &cfg), ANTS_OK);

    CHECK_EQ(ants_dht_announce(&d, 0xAAAAAAAAAAAAAAAAULL), ANTS_OK);
    /* Idempotent. */
    CHECK_EQ(ants_dht_announce(&d, 0xAAAAAAAAAAAAAAAAULL), ANTS_OK);
    /* Independent keys add separate slots. */
    CHECK_EQ(ants_dht_announce(&d, 0xBBBBBBBBBBBBBBBBULL), ANTS_OK);

    /* Unannounce drops the entry; second call is a no-op. */
    CHECK_EQ(ants_dht_unannounce(&d, 0xAAAAAAAAAAAAAAAAULL), ANTS_OK);
    CHECK_EQ(ants_dht_unannounce(&d, 0xAAAAAAAAAAAAAAAAULL), ANTS_OK);

    /* NULL guards. */
    CHECK_EQ(ants_dht_announce(NULL, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_unannounce(NULL, 0), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_dht_destroy(&d), ANTS_OK);
}

/* Both A and B run a full DHT. Each transport event_fn forwards to its
 * own DHT via ants_dht_handle_transport_event, so the server-side
 * dispatcher is exercised end-to-end. stream_opened counts peer-initiated
 * bidi streams (used by phase 6.1.a refresh tests to verify a PING was
 * or wasn't dispatched). */
typedef struct {
    ants_dht_t *dht;
    int conn_ready;
    int stream_opened;
    ants_peer_id_t peer_id;
} test_dht_endpoint_t;

static ants_error_t test_dht_endpoint_event(const ants_transport_event_t *ev, void *ctx)
{
    test_dht_endpoint_t *e = (test_dht_endpoint_t *)ctx;
    if (e->dht != NULL) {
        ants_dht_handle_transport_event(e->dht, ev);
    }
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        e->conn_ready++;
        e->peer_id = ev->peer_id;
    } else if (ev->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        e->stream_opened++;
    }
    return ANTS_OK;
}

/* DHT-event recorder. Counts the kinds the refresh-tick tests care
 * about (PEER_EVICTED, TABLE_REFRESHED) so they can observe the
 * maintenance loop's effects via the registered event_fn rather than
 * direct struct inspection. */
typedef struct {
    int peer_evicted;
    int table_refreshed;
    ants_dht_peer_t last_evicted;
} test_dht_event_recorder_t;

static ants_error_t test_dht_event_recorder(const ants_dht_event_t *ev, void *ctx)
{
    test_dht_event_recorder_t *r = (test_dht_event_recorder_t *)ctx;
    if (ev->kind == ANTS_DHT_EV_PEER_EVICTED) {
        r->peer_evicted++;
        r->last_evicted = ev->peer;
    } else if (ev->kind == ANTS_DHT_EV_TABLE_REFRESHED) {
        r->table_refreshed++;
    }
    return ANTS_OK;
}

/* Transport event_fn that resets every peer-initiated stream the moment
 * it opens. Used by the refresh-eviction test as B's "always-fail" peer:
 * A's PINGs hit a STREAM_RESET, which the dht_rpc dispatcher surfaces as
 * an RPC failure, bumping A's dead_strikes for the entry. */
typedef struct {
    int streams_reset;
} test_reset_server_t;

static ants_error_t test_reset_server_event(const ants_transport_event_t *ev, void *ctx)
{
    test_reset_server_t *s = (test_reset_server_t *)ctx;
    if (ev->kind == ANTS_TRANSPORT_EV_STREAM_OPENED && ev->stream != NULL) {
        (void)ants_transport_stream_reset(ev->stream, 99 /* "refresh-test reset" */);
        s->streams_reset++;
    }
    return ANTS_OK;
}

static void test_server_responds_to_ping(void)
{
    /* A sends PING to B; B's DHT server dispatcher decodes the request
     * and answers PING_RESP automatically — no manual server-side stub
     * on B. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x66, sizeof a_priv);
    memset(b_priv, 0xCC, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.event_fn = test_noop_event;

    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1 && b_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready == 1);
    CHECK(b_ep.conn_ready == 1);

    test_rpc_completion_t comp;
    memset(&comp, 0, sizeof comp);
    CHECK_EQ(ants_dht__test_send_ping(&da, &conn, test_rpc_complete_ping, &comp), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (comp.fired >= 1) {
            break;
        }
    }
    CHECK(comp.fired == 1);
    CHECK_EQ(comp.last_status, ANTS_OK);
    CHECK(comp.last_resp_type == ANTS_DHT_MSG_PING_RESP);
    CHECK(comp.last_ping.txid != 0);

    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
}

static void test_server_get_peers_with_announce(void)
{
    /* B announces shard X locally → its server-side announce set lists
     * itself. A then sends GET_PEERS X to B; B answers with the
     * announce list. End-to-end GET_PEERS_RESP encode + decode against
     * the real server. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x71, sizeof a_priv);
    memset(b_priv, 0xD2, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.event_fn = test_noop_event;

    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    ants_dht_shard_key_t shard_x = 0xFEEDFACECAFEBABEULL;
    CHECK_EQ(ants_dht_announce(&db, shard_x), ANTS_OK);

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1 && b_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready == 1);
    CHECK(b_ep.conn_ready == 1);

    test_rpc_completion_t comp;
    memset(&comp, 0, sizeof comp);
    CHECK_EQ(ants_dht__test_send_get_peers(&da, &conn, shard_x, test_rpc_complete_ping, &comp),
             ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (comp.fired >= 1) {
            break;
        }
    }
    CHECK(comp.fired == 1);
    CHECK_EQ(comp.last_status, ANTS_OK);

    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
}

static void test_bootstrap_completes(void)
{
    /* A bootstraps B. After CONN_READY observed (via event delegation),
     * B should appear in A's routing table with the live conn pointer.
     * Phase 6 also issues a self-FIND_NODE on completion; with B having
     * no peers the RPC still succeeds with peer_count=0. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x88, sizeof a_priv);
    memset(b_priv, 0x44, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.event_fn = test_noop_event;

    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    ants_peer_id_t b_pid;
    memcpy(b_pid.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_bootstrap(&da, baddr, &b_pid), ANTS_OK);

    /* NULL-arg guards on the now-implemented function. */
    CHECK_EQ(ants_dht_bootstrap(NULL, baddr, &b_pid), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_bootstrap(&da, NULL, &b_pid), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_dht_bootstrap(&da, baddr, NULL), ANTS_ERROR_INVALID_ARG);

    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1 && b_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready == 1);
    CHECK(b_ep.conn_ready == 1);

    /* Drive a few more ticks for the self-FIND_NODE round-trip. */
    for (int i = 0; i < 50; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }

    /* A's routing table should now contain B. */
    CHECK(ants_dht_routing_table_size(&da) == 1);
    ants_dht_peer_t peers[4];
    size_t count = 0;
    CHECK_EQ(ants_dht_routing_table_enumerate(&da, peers, 4, &count), ANTS_OK);
    CHECK(count == 1);
    if (count == 1) {
        CHECK(memcmp(peers[0].peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE) == 0);
    }

    /* B should still have an empty routing table. */
    CHECK(ants_dht_routing_table_size(&db) == 0);

    /* Teardown order matters here: when the DHT holds a bootstrap-
     * allocated heap conn, the transport must be destroyed FIRST so
     * its CONN_CLOSED callback delegates to dht_handle_transport_event,
     * which then frees the heap conn via handle_bootstrap_conn_closed.
     * Destroying the DHT first would free the conn before picoquic
     * finishes using it (heap-use-after-free during transport_destroy).
     * For tests that don't use bootstrap (or have already-closed
     * conns), either order works. */
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Phase 6.1.a: refresh PING + dead_strikes eviction                        */
/*                                                                          */
/* Three tests cover the refresh-tick state machine end-to-end on real      */
/* QUIC transports:                                                          */
/*                                                                          */
/*   1. test_refresh_pings_stale_peer       — stale entry → PING → refresh  */
/*   2. test_refresh_evicts_after_threshold — failed PINGs → eviction event */
/*   3. test_refresh_no_ping_when_fresh     — fresh entry → no PING         */
/* ------------------------------------------------------------------------ */

static void test_refresh_pings_stale_peer(void)
{
    /* A configured with a short refresh_interval_ms; B is a real DHT
     * that auto-responds to PINGs. A dials B to get a live conn, then
     * uses the test hook to back-date the entry's last_seen_us. After
     * ticking, A should observe a successful PING_RESP — visible as
     * the entry's dead_strikes staying at 0 AND last_seen_us moving
     * forward past the back-dated value. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x33, sizeof a_priv);
    memset(b_priv, 0x99, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);
    test_dht_event_recorder_t a_rec;
    memset(&a_rec, 0, sizeof a_rec);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);

    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_dht_event_recorder;
    dcfg.event_ctx = &a_rec;
    dcfg.refresh_interval_ms = 100;
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_noop_event;
    dcfg.event_ctx = NULL;
    dcfg.refresh_interval_ms = 0; /* B doesn't need its own refresh. */
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    /* Stack-allocated conn — A owns the buffer, will outlive the test. */
    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1 && b_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready >= 1);
    CHECK(b_ep.conn_ready >= 1);

    /* Insert B into A's routing table with the live conn and a stale
     * last_seen_us. now_us=1 places the entry safely in the past so
     * the very next refresh sweep will PING it. */
    ants_dht_peer_t b_peer;
    memset(&b_peer, 0, sizeof b_peer);
    memcpy(b_peer.peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE);
    CHECK_EQ(ants_dht__test_insert_peer_with_conn(&da, &b_peer, &conn, 1 /* very stale */),
             ANTS_OK);

    /* Snapshot — entry should exist with stale last_seen and no strikes. */
    ants_peer_id_t b_pid;
    memcpy(b_pid.bytes, b_pub, ANTS_PEER_ID_SIZE);
    ants_dht__test_entry_state_t st0;
    ants_dht__test_get_entry_state(&da, &b_pid, &st0);
    CHECK(st0.exists);
    CHECK(st0.last_seen_us == 1);
    CHECK(st0.dead_strikes == 0);

    /* Drive ticks. The refresh sweep should issue a PING; B's DHT
     * responds; A's completion bumps last_seen_us and keeps strikes at 0. */
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        ants_dht__test_entry_state_t st;
        ants_dht__test_get_entry_state(&da, &b_pid, &st);
        if (st.exists && st.last_seen_us > 1 && !st.ping_in_flight) {
            break;
        }
    }
    ants_dht__test_entry_state_t st_final;
    ants_dht__test_get_entry_state(&da, &b_pid, &st_final);
    CHECK(st_final.exists);
    CHECK(st_final.last_seen_us > 1);
    CHECK(st_final.dead_strikes == 0);
    CHECK(a_rec.peer_evicted == 0);
    CHECK(a_rec.table_refreshed >= 1);

    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
}

static void test_refresh_evicts_after_threshold(void)
{
    /* B's transport is not wired to a DHT — its event_fn resets every
     * inbound stream. A's PINGs hit STREAM_RESET; each failure bumps
     * dead_strikes; on the third strike A's event_fn observes a
     * PEER_EVICTED event and the entry is gone from the routing table. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x55, sizeof a_priv);
    memset(b_priv, 0xAA, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_reset_server_t b_srv;
    memset(&b_srv, 0, sizeof b_srv);
    test_dht_event_recorder_t a_rec;
    memset(&a_rec, 0, sizeof a_rec);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_reset_server_event;
    bcfg.event_ctx = &b_srv;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_dht_event_recorder;
    dcfg.event_ctx = &a_rec;
    dcfg.refresh_interval_ms = 50;
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready >= 1);

    ants_dht_peer_t b_peer;
    memset(&b_peer, 0, sizeof b_peer);
    memcpy(b_peer.peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE);
    CHECK_EQ(ants_dht__test_insert_peer_with_conn(&da, &b_peer, &conn, 1 /* stale */), ANTS_OK);
    CHECK(ants_dht_routing_table_size(&da) == 1);

    ants_peer_id_t b_pid;
    memcpy(b_pid.bytes, b_pub, ANTS_PEER_ID_SIZE);

    /* Drive ticks until eviction fires. Sweep cadence is 12.5 ms (50/4),
     * each PING fails on round-trip within a few ms, so 3 strikes take
     * ~50-80 ms; 500 ticks gives comfortable margin even on a slow CI. */
    for (int i = 0; i < 500; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        if (a_rec.peer_evicted >= 1) {
            break;
        }
    }
    CHECK(a_rec.peer_evicted == 1);
    CHECK(memcmp(a_rec.last_evicted.peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE) == 0);
    CHECK(ants_dht_routing_table_size(&da) == 0);
    /* The reset-server should have observed at least three streams (one
     * per strike); the exact count can be higher under refresh-cadence
     * timing variance, so we only assert the lower bound. */
    CHECK(b_srv.streams_reset >= ANTS_DHT_DEAD_STRIKE_THRESHOLD);

    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
}

static void test_refresh_no_ping_when_fresh(void)
{
    /* A configured with a long refresh_interval_ms; B is a full DHT.
     * A inserts B with a fresh last_seen_us. Ticking for a short window
     * should NOT trigger any PING — B's stream_opened count stays at 0,
     * A's entry stays untouched. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x77, sizeof a_priv);
    memset(b_priv, 0xBB, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_noop_event;
    dcfg.refresh_interval_ms = 60000; /* 60 s — well beyond test window. */
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.refresh_interval_ms = 0;
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 200; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 1 && b_ep.conn_ready >= 1) {
            break;
        }
    }
    CHECK(a_ep.conn_ready >= 1);
    CHECK(b_ep.conn_ready >= 1);

    ants_dht_peer_t b_peer;
    memset(&b_peer, 0, sizeof b_peer);
    memcpy(b_peer.peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE);
    uint64_t fresh_now = ants_dht__test_now_us();
    CHECK_EQ(ants_dht__test_insert_peer_with_conn(&da, &b_peer, &conn, fresh_now), ANTS_OK);

    int b_streams_before = b_ep.stream_opened;
    for (int i = 0; i < 100; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
    }
    /* No refresh PING should have hit B. */
    CHECK(b_ep.stream_opened == b_streams_before);

    ants_peer_id_t b_pid;
    memcpy(b_pid.bytes, b_pub, ANTS_PEER_ID_SIZE);
    ants_dht__test_entry_state_t st;
    ants_dht__test_get_entry_state(&da, &b_pid, &st);
    CHECK(st.exists);
    CHECK(st.dead_strikes == 0);
    CHECK(!st.ping_in_flight);
    /* last_seen_us hasn't moved because no PING_RESP fired. */
    CHECK(st.last_seen_us == fresh_now);

    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Phase 7: end-to-end two-node DHT integration                             */
/*                                                                          */
/* "ANTS DHT live" milestone: A and B both run full DHTs over real QUIC     */
/* transports. They bootstrap each other (mutual dials), each announces a   */
/* shard, then each looks up the other's announced shard. Both observe a    */
/* LOOKUP_COMPLETE event containing the other peer.                         */
/* ------------------------------------------------------------------------ */

static void test_two_node_end_to_end(void)
{
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x11, sizeof a_priv);
    memset(b_priv, 0xEE, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    test_dht_endpoint_t a_ep;
    memset(&a_ep, 0, sizeof a_ep);
    test_dht_endpoint_t b_ep;
    memset(&b_ep, 0, sizeof b_ep);
    test_lookup_recorder_t a_rec;
    memset(&a_rec, 0, sizeof a_rec);
    test_lookup_recorder_t b_rec;
    memset(&b_rec, 0, sizeof b_rec);

    /* Both endpoints are listener+dialer so each can bootstrap the
     * other. Two independent QUIC connections result (one in each
     * direction) — bootstrap dials are tracked separately in each
     * DHT's bootstrap_entries; inbound conns on the other side are
     * handled by the server-side dispatcher. */
    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    acfg.sign_fn = test_real_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = test_dht_endpoint_event;
    acfg.event_ctx = &a_ep;
    acfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);
    char aaddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&ta, aaddr, sizeof aaddr), ANTS_OK);

    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    bcfg.sign_fn = test_real_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = test_dht_endpoint_event;
    bcfg.event_ctx = &b_ep;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    ants_dht_t da = {{0}};
    ants_dht_t db = {{0}};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);

    dcfg.transport = &ta;
    memcpy(dcfg.local_peer_id.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_lookup_event_fn;
    dcfg.event_ctx = &a_rec;
    CHECK_EQ(ants_dht_init(&da, &dcfg), ANTS_OK);
    a_ep.dht = &da;

    dcfg.transport = &tb;
    memcpy(dcfg.local_peer_id.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    dcfg.event_fn = test_lookup_event_fn;
    dcfg.event_ctx = &b_rec;
    CHECK_EQ(ants_dht_init(&db, &dcfg), ANTS_OK);
    b_ep.dht = &db;

    /* Mutual bootstrap. Each endpoint dials the other's listener. */
    ants_peer_id_t b_pid;
    memcpy(b_pid.bytes, b_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_bootstrap(&da, baddr, &b_pid), ANTS_OK);
    ants_peer_id_t a_pid;
    memcpy(a_pid.bytes, a_pub, ANTS_ED25519_PUBKEY_SIZE);
    CHECK_EQ(ants_dht_bootstrap(&db, aaddr, &a_pid), ANTS_OK);

    /* Drive until both directions complete the handshake (each side
     * sees one outbound CONN_READY and one inbound CONN_READY). */
    for (int i = 0; i < 300; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (a_ep.conn_ready >= 2 && b_ep.conn_ready >= 2) {
            break;
        }
    }
    CHECK(a_ep.conn_ready >= 2);
    CHECK(b_ep.conn_ready >= 2);

    /* Drive the self-FIND_NODE round-trips spawned by each bootstrap.
     * Both sides have empty initial routing tables (we haven't done
     * any inserts yet), so FIND_NODE returns peer_count=0 from each
     * server. */
    for (int i = 0; i < 100; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        (void)ants_dht_tick(&db);
    }

    /* Each routing table should now contain exactly the other peer. */
    CHECK(ants_dht_routing_table_size(&da) == 1);
    CHECK(ants_dht_routing_table_size(&db) == 1);

    /* Each peer announces a distinct shard. */
    ants_dht_shard_key_t shard_x = 0x1111111111111111ULL;
    ants_dht_shard_key_t shard_y = 0x2222222222222222ULL;
    CHECK_EQ(ants_dht_announce(&da, shard_x), ANTS_OK);
    CHECK_EQ(ants_dht_announce(&db, shard_y), ANTS_OK);

    /* A looks up shard_y (announced by B). A's only known peer with a
     * conn is B; A queries B → B's server returns its announce set
     * for shard_y = [B] → A folds, B already in candidates (was
     * seeded), A converges → LOOKUP_COMPLETE fires with B as the
     * answered peer. */
    ants_dht_lookup_t la = {{0}};
    CHECK_EQ(ants_dht_lookup(&da, shard_y, &la), ANTS_OK);
    for (int i = 0; i < 300; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        (void)ants_dht_tick(&db);
        if (a_rec.lookup_complete >= 1) {
            break;
        }
    }
    CHECK(a_rec.lookup_complete == 1);
    CHECK(a_rec.last_shard_key == shard_y);
    CHECK(a_rec.last_peer_count == 1);
    if (a_rec.last_peer_count == 1) {
        CHECK(memcmp(a_rec.last_peers[0].peer_id.bytes, b_pub, ANTS_PEER_ID_SIZE) == 0);
    }

    /* Symmetric: B looks up shard_x (announced by A). */
    ants_dht_lookup_t lb = {{0}};
    CHECK_EQ(ants_dht_lookup(&db, shard_x, &lb), ANTS_OK);
    for (int i = 0; i < 300; i++) {
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        (void)ants_dht_tick(&da);
        (void)ants_dht_tick(&db);
        if (b_rec.lookup_complete >= 1) {
            break;
        }
    }
    CHECK(b_rec.lookup_complete == 1);
    CHECK(b_rec.last_shard_key == shard_x);
    CHECK(b_rec.last_peer_count == 1);
    if (b_rec.last_peer_count == 1) {
        CHECK(memcmp(b_rec.last_peers[0].peer_id.bytes, a_pub, ANTS_PEER_ID_SIZE) == 0);
    }

    /* Teardown: bootstrap conns are open, so the transport must die
     * first so its CONN_CLOSED callbacks reach our DHT and mark
     * bootstrap entries dead before destroy frees their heap. */
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&da), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&db), ANTS_OK);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_destroy_rejects_null();
    test_tick_returns_idle_sentinel();
    test_action_stubs_return_not_implemented();
    test_introspection_empty_table();
    test_bucket_index_math();
    test_kbucket_insert_and_enumerate();
    test_kbucket_full_rejects();
    test_kbucket_remove();
    test_destroy_frees_heap_entries();

    test_wire_peek_type();
    test_wire_ping_roundtrip();
    test_wire_find_node_roundtrip();
    test_wire_get_peers_roundtrip();
    test_wire_announce_peer_roundtrip();
    test_wire_rejects_truncation();
    test_wire_rejects_buffer_too_small();

    test_rpc_send_rejects_invalid_args();
    test_rpc_handle_event_ignores_non_dht();
    test_rpc_round_trip();

    test_lookup_no_candidates();
    test_lookup_round_trip();
    test_lookup_cancel();

    test_announce_unannounce_local();
    test_server_responds_to_ping();
    test_server_get_peers_with_announce();
    test_bootstrap_completes();

    test_refresh_pings_stale_peer();
    test_refresh_evicts_after_threshold();
    test_refresh_no_ping_when_fresh();

    test_two_node_end_to_end();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
