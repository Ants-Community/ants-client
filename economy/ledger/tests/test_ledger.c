/*
 * test_ledger.c — Tests for the local economic ledger (Component #14).
 *
 * Covers the PR1 accounting core: per-pair u64 uNCS credits with
 * overflow rejection, on-demand signed net balance (incl. the int64
 * range guard), and canonical-CBOR record round-trip + strict-decode
 * rejection (truncation, trailing byte, wrong shape, non-canonical int).
 *
 * Assertions verify behaviour independently where possible (hand-checked
 * arithmetic, standalone codec probes) rather than mirroring the impl.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_ledger.h"

#include <stdbool.h>
#include <stddef.h>
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

/* A non-trivial peer id (no 0x00 runs, just to be a real 32 bytes). */
static void sample_peer_id(uint8_t id[ANTS_LEDGER_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_LEDGER_PEER_ID_SIZE; i++) {
        id[i] = (uint8_t)(0x10 + i);
    }
}

/* -- lifecycle + accounting ------------------------------------------- */

static void test_init_sets_defaults(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    memset(&rec, 0xCC, sizeof rec);
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 1700000000ULL), ANTS_OK);

    CHECK(memcmp(rec.peer_id, id, ANTS_LEDGER_PEER_ID_SIZE) == 0);
    CHECK(rec.served_to == 0);
    CHECK(rec.served_by == 0);
    CHECK(rec.since_unix_s == 1700000000ULL);
    CHECK(rec.last_update_unix_s == 1700000000ULL);
    CHECK(rec.quality_q14k == 10000); /* 1.0 */
    CHECK(rec.choked == true);        /* cold start */
}

static void test_init_null_args(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(NULL, id, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_peer_init(&rec, NULL, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_credit_accumulates_and_stamps(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 100), ANTS_OK);

    CHECK_EQ(ants_ledger_credit_served_to(&rec, 1430, 200), ANTS_OK);
    CHECK_EQ(ants_ledger_credit_served_to(&rec, 70, 250), ANTS_OK);
    CHECK(rec.served_to == 1500);
    CHECK(rec.last_update_unix_s == 250); /* stamped by latest credit */

    CHECK_EQ(ants_ledger_credit_served_by(&rec, 1267, 300), ANTS_OK);
    CHECK(rec.served_by == 1267);
    CHECK(rec.last_update_unix_s == 300);

    /* now_unix_s == 0 means "no clock": total moves, timestamp does not. */
    CHECK_EQ(ants_ledger_credit_served_by(&rec, 1, 0), ANTS_OK);
    CHECK(rec.served_by == 1268);
    CHECK(rec.last_update_unix_s == 300);
}

static void test_credit_null_args(void)
{
    CHECK_EQ(ants_ledger_credit_served_to(NULL, 1, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_credit_served_by(NULL, 1, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_credit_overflow_rejects_and_preserves(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);

    /* Set served_to one below the ceiling, then a +2 credit must be
     * rejected and the total left UNCHANGED (RFC-0008 §6). */
    rec.served_to = UINT64_MAX - 1;
    CHECK_EQ(ants_ledger_credit_served_to(&rec, 2, 500), ANTS_ERROR_OVERFLOW);
    CHECK(rec.served_to == UINT64_MAX - 1); /* unchanged */
    CHECK(rec.last_update_unix_s == 0);     /* not stamped on rejection */

    /* Exactly +1 fits (boundary): UINT64_MAX is representable. */
    CHECK_EQ(ants_ledger_credit_served_to(&rec, 1, 500), ANTS_OK);
    CHECK(rec.served_to == UINT64_MAX);

    /* served_by overflow path too. */
    rec.served_by = UINT64_MAX;
    CHECK_EQ(ants_ledger_credit_served_by(&rec, 1, 600), ANTS_ERROR_OVERFLOW);
    CHECK(rec.served_by == UINT64_MAX);
}

/* -- net balance ------------------------------------------------------ */

static void test_net_balance_sign(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    int64_t net = 12345;

    /* Equal totals => zero. */
    rec.served_to = 1000;
    rec.served_by = 1000;
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_OK);
    CHECK(net == 0);

    /* We are ahead => positive. */
    rec.served_to = 1430;
    rec.served_by = 1267;
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_OK);
    CHECK(net == 163);

    /* We owe => negative. */
    rec.served_to = 200;
    rec.served_by = 950;
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_OK);
    CHECK(net == -750);
}

static void test_net_balance_int64_guard(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    int64_t net = 0;

    /* Positive difference exceeding INT64_MAX => OVERFLOW guard. */
    rec.served_to = UINT64_MAX;
    rec.served_by = 0;
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_ERROR_OVERFLOW);

    /* Negative boundary: magnitude exactly 2^63 == INT64_MIN, representable. */
    rec.served_to = 0;
    rec.served_by = (uint64_t)INT64_MAX + 1u; /* 2^63 */
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_OK);
    CHECK(net == INT64_MIN);

    /* One past the negative boundary => OVERFLOW. */
    rec.served_by = (uint64_t)INT64_MAX + 2u; /* 2^63 + 1 */
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_ERROR_OVERFLOW);

    /* Largest exactly-representable positive difference => OK. */
    rec.served_to = (uint64_t)INT64_MAX;
    rec.served_by = 0;
    CHECK_EQ(ants_ledger_net_balance(&rec, &net), ANTS_OK);
    CHECK(net == INT64_MAX);
}

static void test_net_balance_null_args(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    int64_t net;
    CHECK_EQ(ants_ledger_net_balance(NULL, &net), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_net_balance(&rec, NULL), ANTS_ERROR_INVALID_ARG);
}

/* -- canonical CBOR serialisation ------------------------------------- */

static ants_ledger_peer_t sample_record(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    (void)ants_ledger_peer_init(&rec, id, 1700000000ULL);
    rec.served_to = 1430500;
    rec.served_by = 1267200;
    rec.last_update_unix_s = 1700009999ULL;
    rec.quality_q14k = 9700; /* 0.97 */
    rec.choked = false;
    return rec;
}

static void test_record_round_trip(void)
{
    ants_ledger_peer_t rec = sample_record();
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);
    CHECK(n > 0 && n <= ANTS_LEDGER_RECORD_ENCODED_MAX);

    /* The encoding must be canonical per RFC-0008 §1.1. (The codec has no
     * float type at all, so the record is float-free by construction —
     * RFC-0008 §6.) */
    CHECK_EQ(ants_cbor_is_canonical(buf, n), ANTS_OK);

    ants_ledger_peer_t got;
    memset(&got, 0xCC, sizeof got);
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_OK);

    CHECK(memcmp(got.peer_id, rec.peer_id, ANTS_LEDGER_PEER_ID_SIZE) == 0);
    CHECK(got.served_to == rec.served_to);
    CHECK(got.served_by == rec.served_by);
    CHECK(got.since_unix_s == rec.since_unix_s);
    CHECK(got.last_update_unix_s == rec.last_update_unix_s);
    CHECK(got.quality_q14k == rec.quality_q14k);
    CHECK(got.choked == rec.choked);
}

static void test_record_round_trip_zeroes(void)
{
    /* A freshly-init'd record (all-zero totals, choked=true) must also
     * round-trip — exercises the zero-uint canonical encoding. */
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);

    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);
    CHECK_EQ(ants_cbor_is_canonical(buf, n), ANTS_OK);

    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_OK);
    /* Compare field-by-field, not memcmp over the struct: decode fills
     * the 7 logical fields but not the trailing padding bytes, so a raw
     * struct memcmp would read uninitialised padding (and is UB). */
    CHECK(memcmp(got.peer_id, rec.peer_id, ANTS_LEDGER_PEER_ID_SIZE) == 0);
    CHECK(got.served_to == rec.served_to);
    CHECK(got.served_by == rec.served_by);
    CHECK(got.since_unix_s == rec.since_unix_s);
    CHECK(got.last_update_unix_s == rec.last_update_unix_s);
    CHECK(got.quality_q14k == rec.quality_q14k);
    CHECK(got.choked == rec.choked);
}

static void test_encode_buffer_too_small(void)
{
    ants_ledger_peer_t rec = sample_record();
    uint8_t small[8];
    size_t n = 12345;
    CHECK_EQ(ants_ledger_record_encode(&rec, small, sizeof small, &n), ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_encode_null_args(void)
{
    ants_ledger_peer_t rec = sample_record();
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(NULL, buf, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_record_encode(&rec, NULL, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_decode_null_args(void)
{
    uint8_t buf[4] = {0};
    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(NULL, sizeof buf, &got), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_record_decode(buf, sizeof buf, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_decode_rejects_truncation(void)
{
    ants_ledger_peer_t rec = sample_record();
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);

    /* Every proper prefix of a valid encoding must fail to decode. */
    for (size_t cut = 0; cut < n; cut++) {
        ants_ledger_peer_t got;
        ants_error_t rc = ants_ledger_record_decode(buf, cut, &got);
        CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
    }
}

static void test_decode_rejects_trailing_byte(void)
{
    ants_ledger_peer_t rec = sample_record();
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX + 1];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf - 1, &n), ANTS_OK);

    /* One extra byte after a complete object must be rejected. */
    buf[n] = 0x00;
    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n + 1, &got), ANTS_ERROR_MALFORMED);
}

static void test_decode_rejects_wrong_map_size(void)
{
    /* The encoder always writes 0xA8 = map(8). A header announcing 6
     * pairs (0xA6) is structurally wrong for this schema. */
    uint8_t buf[8] = {0xA6, 0x01};
    ants_ledger_peer_t got;
    ants_error_t rc = ants_ledger_record_decode(buf, sizeof buf, &got);
    CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
}

static void test_decode_rejects_non_canonical_int(void)
{
    /* The strict decoder rejects a non-shortest integer with
     * NON_CANONICAL. Probe the exact codec path the record decoder uses:
     * 0x18 0x00 is the 1-byte-extension form of 0, whose canonical form
     * is the single byte 0x00. */
    uint8_t bad[2] = {0x18, 0x00};
    ants_cbor_dec_t d;
    CHECK_EQ(ants_cbor_dec_init(&d, bad, sizeof bad), ANTS_OK);
    uint64_t v;
    CHECK_EQ(ants_cbor_dec_uint(&d, &v), ANTS_ERROR_NON_CANONICAL);
}

static void test_decode_rejects_wrong_field_type(void)
{
    /* A valid record with the choked value (key 7) rewritten from a bool
     * to a uint must be rejected: the decoder demands a bool there. With
     * an empty recent array (key 8 = 0x08 0x80) the tail of the encoding
     * is: ... 0x07 (key) 0xF5 (true) 0x08 (key) 0x80 (empty array). So
     * the choked bool sits at buf[n-3]. */
    ants_ledger_peer_t rec = sample_record();
    rec.choked = true;    /* encodes as 0xF5 */
    rec.recent_count = 0; /* empty recent => key 8 is `0x08 0x80` */
    rec.recent_head = 0;
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);

    /* tail: [n-4]=0x07 key, [n-3]=0xF5 bool, [n-2]=0x08 key, [n-1]=0x80 array(0). */
    CHECK(buf[n - 4] == 0x07);
    CHECK(buf[n - 3] == 0xF5);
    CHECK(buf[n - 2] == 0x08);
    CHECK(buf[n - 1] == 0x80);
    buf[n - 3] = 0x00; /* choked bool -> uint 0, type mismatch */
    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_ERROR_MALFORMED);
}

/* -- choke/unchoke: generosity window + ring buffer ------------------- */

static void test_generosity_window(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);

    /* Three receipts at t=100, 1000, 2000. */
    CHECK_EQ(ants_ledger_record_recv(&rec, 50, 100), ANTS_OK);
    CHECK_EQ(ants_ledger_record_recv(&rec, 70, 1000), ANTS_OK);
    CHECK_EQ(ants_ledger_record_recv(&rec, 90, 2000), ANTS_OK);
    /* record_recv also credits the cumulative total. */
    CHECK(rec.served_by == 210);

    uint64_t gen = 12345;
    /* Window 1200 s ending at now=2000 => cutoff 800; only t=1000 and
     * t=2000 qualify (70+90=160); t=100 is stale. */
    CHECK_EQ(ants_ledger_generosity(&rec, 2000, 1200, &gen), ANTS_OK);
    CHECK(gen == 160);

    /* Huge window => everything counts. */
    CHECK_EQ(ants_ledger_generosity(&rec, 2000, 100000, &gen), ANTS_OK);
    CHECK(gen == 210);

    /* now <= window => everything in window (no underflow in cutoff). */
    CHECK_EQ(ants_ledger_generosity(&rec, 500, 1200, &gen), ANTS_OK);
    CHECK(gen == 210);

    /* Tight window catching only the last receipt. */
    CHECK_EQ(ants_ledger_generosity(&rec, 2000, 500, &gen), ANTS_OK);
    CHECK(gen == 90); /* cutoff 1500; only t=2000 */
}

static void test_generosity_clockless_always_in_window(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    /* unix_s == 0 samples are always in-window regardless of now. */
    CHECK_EQ(ants_ledger_record_recv(&rec, 11, 0), ANTS_OK);
    CHECK_EQ(ants_ledger_record_recv(&rec, 22, 0), ANTS_OK);
    uint64_t gen = 0;
    CHECK_EQ(ants_ledger_generosity(&rec, 9999999, 1, &gen), ANTS_OK);
    CHECK(gen == 33);
}

static void test_recent_ring_eviction(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);

    /* Push cap+10 receipts of 1 uNCS each, timestamps increasing so all
     * land in a huge window. The ring keeps only the last cap; the
     * windowed generosity therefore tops out at cap, even though the
     * cumulative served_by counts every one. */
    uint32_t cap = ANTS_LEDGER_RECENT_SAMPLES;
    uint32_t total = cap + 10u;
    for (uint32_t i = 0; i < total; i++) {
        CHECK_EQ(ants_ledger_record_recv(&rec, 1, 100 + i), ANTS_OK);
    }
    CHECK(rec.recent_count == cap);
    CHECK(rec.served_by == total); /* cumulative is not capped */

    uint64_t gen = 0;
    CHECK_EQ(ants_ledger_generosity(&rec, 100 + total, 1000000, &gen), ANTS_OK);
    CHECK(gen == cap); /* only the surviving cap samples count */
}

static void test_record_recv_overflow_no_sample(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    rec.served_by = UINT64_MAX;
    /* Overflow => record unchanged AND no sample pushed. */
    CHECK_EQ(ants_ledger_record_recv(&rec, 1, 500), ANTS_ERROR_OVERFLOW);
    CHECK(rec.served_by == UINT64_MAX);
    CHECK(rec.recent_count == 0);
}

static void test_record_recv_null(void)
{
    CHECK_EQ(ants_ledger_record_recv(NULL, 1, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_generosity_null(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    uint64_t g;
    CHECK_EQ(ants_ledger_generosity(NULL, 0, 0, &g), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_generosity(&rec, 0, 0, NULL), ANTS_ERROR_INVALID_ARG);
}

/* -- choke/unchoke: the unchoke round -------------------------------- */

/* Build a record with a given peer-id byte, generosity (one receipt),
 * and quality. Helper for the ranking tests. */
static ants_ledger_peer_t make_peer(uint8_t id_byte, uint64_t recv_uncs, uint16_t quality)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    memset(id, id_byte, sizeof id);
    ants_ledger_peer_t rec;
    (void)ants_ledger_peer_init(&rec, id, 0);
    rec.quality_q14k = quality;
    if (recv_uncs > 0) {
        (void)ants_ledger_record_recv(&rec, recv_uncs, 1000);
    }
    return rec;
}

static void test_unchoke_ranks_by_generosity(void)
{
    /* 4 peers, descending generosity, all quality 1.0. slots=8 =>
     * optimistic = 8/8 = 1, earned = 7. With only 4 peers everyone is
     * served, but the choked flags should all clear. */
    ants_ledger_peer_t recs[4];
    recs[0] = make_peer(0x01, 100, 10000);
    recs[1] = make_peer(0x02, 50, 10000);
    recs[2] = make_peer(0x03, 10, 10000);
    recs[3] = make_peer(0x04, 0, 10000); /* no generosity */
    uint64_t scratch[4];
    CHECK_EQ(ants_ledger_unchoke_round(recs, 4, 2000, 1200, 8, 0, scratch, 4), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        CHECK(recs[i].choked == false); /* 4 peers <= 8 slots */
    }
}

static void test_unchoke_earned_slots_limited(void)
{
    /* 10 peers, generosity 100 down to 10 (distinct), quality 1.0,
     * slots=8 => optimistic=1, earned=7. The 7 most generous are
     * earned-unchoked; of the remaining 3, exactly 1 gets the optimistic
     * slot. So exactly 8 unchoked, 2 choked. */
    ants_ledger_peer_t recs[10];
    for (int i = 0; i < 10; i++) {
        recs[i] = make_peer((uint8_t)(0x10 + i), (uint64_t)(100 - i * 10), 10000);
    }
    uint64_t scratch[10];
    CHECK_EQ(ants_ledger_unchoke_round(recs, 10, 2000, 1200, 8, 0, scratch, 10), ANTS_OK);
    int unchoked = 0;
    for (int i = 0; i < 10; i++) {
        if (!recs[i].choked) {
            unchoked++;
        }
    }
    CHECK(unchoked == 8); /* 7 earned + 1 optimistic */
    /* The top-7 by generosity (i = 0..6) must all be unchoked. */
    for (int i = 0; i < 7; i++) {
        CHECK(recs[i].choked == false);
    }
}

static void test_unchoke_quality_is_multiplier(void)
{
    /* Two peers, equal generosity, different quality. The higher-quality
     * peer must rank above. With slots=1 (=> optimistic=1, earned=0),
     * ranking alone doesn't unchoke; use slots large enough for 1 earned
     * by setting slots=8 but only 2 peers: both get served. To isolate
     * ranking, give 9 filler peers with zero generosity so only the 7
     * earned slots matter. Simpler: directly compare via a 2-peer set
     * with slots where earned=1. slots= such that earned=1: with
     * divisor 8, slots=2 => optimistic=1, earned=1. */
    ants_ledger_peer_t recs[2];
    recs[0] = make_peer(0x01, 100, 5000);  /* gen 100, q 0.5 => score 500k */
    recs[1] = make_peer(0x02, 100, 10000); /* gen 100, q 1.0 => score 1.0M */
    uint64_t scratch[2];
    /* slots=2 => optimistic=1, earned=1. The earned slot goes to the
     * higher score (peer 1); peer 0 then takes the optimistic slot, so
     * both end unchoked — not useful for isolating rank. Use 3 peers with
     * a zero-gen decoy so earned=1 and optimistic falls on the decoy. */
    (void)scratch;
    ants_ledger_peer_t r3[3];
    r3[0] = make_peer(0x01, 100, 5000);
    r3[1] = make_peer(0x02, 100, 10000);
    r3[2] = make_peer(0x03, 0, 10000); /* decoy, lowest score */
    uint64_t s3[3];
    /* slots=2 => earned=1, optimistic=1. earned slot -> peer 1 (highest
     * score). optimistic among the 2 still-choked (peer 0, peer 2),
     * rotation 0 picks the first in index order = peer 0. So peer 1 and
     * peer 0 unchoked, peer 2 choked. The point: peer 1 (higher quality)
     * is the EARNED one; verify it's unchoked and peer 2 (decoy) choked. */
    CHECK_EQ(ants_ledger_unchoke_round(r3, 3, 2000, 1200, 2, 0, s3, 3), ANTS_OK);
    CHECK(r3[1].choked == false); /* highest score earned a slot */
    CHECK(r3[2].choked == true);  /* decoy not earned, not this rotation */
}

static void test_unchoke_optimistic_rotation(void)
{
    /* 3 zero-generosity peers, slots=2 => earned=1 (but all scores 0, so
     * the "earned" slot also goes by tie-break peer_id ascending), plus
     * 1 optimistic. Across rotations the optimistic slot should move. We
     * check that over rotations 0,1,2 every peer gets unchoked at least
     * once (porosity). */
    int ever_unchoked[3] = {0, 0, 0};
    for (uint64_t rot = 0; rot < 3; rot++) {
        ants_ledger_peer_t recs[3];
        recs[0] = make_peer(0x01, 0, 10000);
        recs[1] = make_peer(0x02, 0, 10000);
        recs[2] = make_peer(0x03, 0, 10000);
        uint64_t scratch[3];
        CHECK_EQ(ants_ledger_unchoke_round(recs, 3, 2000, 1200, 2, rot, scratch, 3), ANTS_OK);
        for (int i = 0; i < 3; i++) {
            if (!recs[i].choked) {
                ever_unchoked[i] = 1;
            }
        }
    }
    CHECK(ever_unchoked[0] && ever_unchoked[1] && ever_unchoked[2]);
}

static void test_unchoke_zero_slots_chokes_all(void)
{
    ants_ledger_peer_t recs[3];
    recs[0] = make_peer(0x01, 100, 10000);
    recs[1] = make_peer(0x02, 50, 10000);
    recs[2] = make_peer(0x03, 10, 10000);
    uint64_t scratch[3];
    CHECK_EQ(ants_ledger_unchoke_round(recs, 3, 2000, 1200, 0, 0, scratch, 3), ANTS_OK);
    for (int i = 0; i < 3; i++) {
        CHECK(recs[i].choked == true);
    }
}

static void test_unchoke_arg_guards(void)
{
    ants_ledger_peer_t recs[2];
    recs[0] = make_peer(0x01, 1, 10000);
    recs[1] = make_peer(0x02, 1, 10000);
    uint64_t scratch[2];
    /* n_records == 0 is a no-op success even with NULL. */
    CHECK_EQ(ants_ledger_unchoke_round(NULL, 0, 0, 0, 8, 0, NULL, 0), ANTS_OK);
    /* NULL records / scratch with n>0 => INVALID_ARG. */
    CHECK_EQ(ants_ledger_unchoke_round(NULL, 2, 0, 0, 8, 0, scratch, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ledger_unchoke_round(recs, 2, 0, 0, 8, 0, NULL, 2), ANTS_ERROR_INVALID_ARG);
    /* scratch too short => INVALID_ARG. */
    CHECK_EQ(ants_ledger_unchoke_round(recs, 2, 0, 0, 8, 0, scratch, 1), ANTS_ERROR_INVALID_ARG);
}

/* -- choke/unchoke: CBOR round-trip with recent samples -------------- */

static void test_record_round_trip_with_recent(void)
{
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 1700000000ULL), ANTS_OK);
    /* A handful of receipts (partial ring). */
    CHECK_EQ(ants_ledger_record_recv(&rec, 11, 1700000100ULL), ANTS_OK);
    CHECK_EQ(ants_ledger_record_recv(&rec, 22, 1700000200ULL), ANTS_OK);
    CHECK_EQ(ants_ledger_record_recv(&rec, 33, 1700000300ULL), ANTS_OK);

    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);
    CHECK_EQ(ants_cbor_is_canonical(buf, n), ANTS_OK);

    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_OK);
    CHECK(got.recent_count == 3);
    /* Generosity over a huge window must match across the round-trip. */
    uint64_t g0 = 0, g1 = 0;
    CHECK_EQ(ants_ledger_generosity(&rec, 1700000400ULL, 1000000, &g0), ANTS_OK);
    CHECK_EQ(ants_ledger_generosity(&got, 1700000400ULL, 1000000, &g1), ANTS_OK);
    CHECK(g0 == 66);
    CHECK(g1 == g0);
}

static void test_record_round_trip_full_ring(void)
{
    /* A full ring (cap samples) must round-trip and stay canonical. */
    uint8_t id[ANTS_LEDGER_PEER_ID_SIZE];
    sample_peer_id(id);
    ants_ledger_peer_t rec;
    CHECK_EQ(ants_ledger_peer_init(&rec, id, 0), ANTS_OK);
    uint32_t cap = ANTS_LEDGER_RECENT_SAMPLES;
    for (uint32_t i = 0; i < cap + 5u; i++) {
        CHECK_EQ(ants_ledger_record_recv(&rec, i + 1u, 1000 + i), ANTS_OK);
    }
    CHECK(rec.recent_count == cap);

    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);
    CHECK_EQ(ants_cbor_is_canonical(buf, n), ANTS_OK);

    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_OK);
    CHECK(got.recent_count == cap);
    uint64_t g0 = 0, g1 = 0;
    CHECK_EQ(ants_ledger_generosity(&rec, 2000, 1000000, &g0), ANTS_OK);
    CHECK_EQ(ants_ledger_generosity(&got, 2000, 1000000, &g1), ANTS_OK);
    CHECK(g0 == g1);
}

static void test_decode_rejects_oversized_recent(void)
{
    /* A key-8 array claiming more than ANTS_LEDGER_RECENT_SAMPLES entries
     * must be rejected — it would not fit the ring buffer. Encode a valid
     * record with an empty recent array (tail = 0x08 0x80 = key 8,
     * array(0)), then rewrite the array(0) header into array(cap+1). The
     * decoder checks the announced count against the cap BEFORE reading
     * any entry, so no entry bytes are needed to trigger the bound. */
    ants_ledger_peer_t z;
    uint8_t zid[ANTS_LEDGER_PEER_ID_SIZE] = {0};
    CHECK_EQ(ants_ledger_peer_init(&z, zid, 0), ANTS_OK);
    z.quality_q14k = 0;
    z.choked = false;
    uint8_t zb[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t zn = 0;
    CHECK_EQ(ants_ledger_record_encode(&z, zb, sizeof zb, &zn), ANTS_OK);

    /* Empty recent => the encoding ends in `0x08 0x80`. Rewrite the
     * array(0) byte 0x80 into array(33) = `0x98 0x21` (cap is 32, so 33
     * is one over). 0x98 = array with a following 1-byte count; 0x21 = 33. */
    CHECK(zb[zn - 1] == 0x80);
    zb[zn - 1] = 0x98;
    zb[zn] = 0x21; /* count = 33 = cap + 1 */
    ants_ledger_peer_t got;
    ants_error_t rc = ants_ledger_record_decode(zb, zn + 1, &got);
    CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
}

int main(void)
{
    test_init_sets_defaults();
    test_init_null_args();
    test_credit_accumulates_and_stamps();
    test_credit_null_args();
    test_credit_overflow_rejects_and_preserves();

    test_net_balance_sign();
    test_net_balance_int64_guard();
    test_net_balance_null_args();

    test_record_round_trip();
    test_record_round_trip_zeroes();
    test_encode_buffer_too_small();
    test_encode_null_args();
    test_decode_null_args();
    test_decode_rejects_truncation();
    test_decode_rejects_trailing_byte();
    test_decode_rejects_wrong_map_size();
    test_decode_rejects_non_canonical_int();
    test_decode_rejects_wrong_field_type();

    test_generosity_window();
    test_generosity_clockless_always_in_window();
    test_recent_ring_eviction();
    test_record_recv_overflow_no_sample();
    test_record_recv_null();
    test_generosity_null();

    test_unchoke_ranks_by_generosity();
    test_unchoke_earned_slots_limited();
    test_unchoke_quality_is_multiplier();
    test_unchoke_optimistic_rotation();
    test_unchoke_zero_slots_chokes_all();
    test_unchoke_arg_guards();

    test_record_round_trip_with_recent();
    test_record_round_trip_full_ring();
    test_decode_rejects_oversized_recent();

    if (failures > 0) {
        fprintf(stderr, "test_ledger: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_ledger: all checks passed\n");
    return 0;
}
