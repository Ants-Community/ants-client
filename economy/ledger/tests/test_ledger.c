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
    /* The encoder always writes 0xA7 = map(7). A header announcing 6
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
     * to a uint must be rejected: the decoder demands a bool there. We
     * build a valid record, then find the final two bytes (0x07 key +
     * 0xF4/0xF5 bool) and corrupt the bool to a uint 0x00. */
    ants_ledger_peer_t rec = sample_record();
    rec.choked = true; /* encodes as 0xF5 */
    uint8_t buf[ANTS_LEDGER_RECORD_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_ledger_record_encode(&rec, buf, sizeof buf, &n), ANTS_OK);

    /* The last pair is key 7 (0x07) then the bool (0xF5 true / 0xF4
     * false). Rewrite the trailing bool byte to 0x00 (uint 0). */
    CHECK(buf[n - 2] == 0x07);
    CHECK(buf[n - 1] == 0xF5);
    buf[n - 1] = 0x00; /* now a uint where a bool is required */
    ants_ledger_peer_t got;
    CHECK_EQ(ants_ledger_record_decode(buf, n, &got), ANTS_ERROR_MALFORMED);
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

    if (failures > 0) {
        fprintf(stderr, "test_ledger: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_ledger: all checks passed\n");
    return 0;
}
