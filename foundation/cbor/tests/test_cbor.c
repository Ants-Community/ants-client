/*
 * test_cbor.c — tests for the CBOR codec.
 *
 * Covers: major types 0 (uint), 1 (negint), 2 (bytes), 3 (text) for
 * both encode and decode, with round-trip and canonical-rejection
 * vectors. The remaining stubs (array, map, tag, bool, null,
 * is_canonical) are tested only at the "returns ANTS_ERROR_NOT_IMPLEMENTED"
 * level until they land.
 *
 * Test framework: stdio + a small CHECK macro. Deliberately no
 * framework dependency.
 */

#include "ants_cbor.h"
#include "ants_common.h"

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

/* Compare actual bytes against expected, dumping both as hex on
 * mismatch. */
static void check_bytes(const char *what,
                        const uint8_t *actual,
                        size_t actual_len,
                        const uint8_t *expected,
                        size_t expected_len)
{
    if (actual_len != expected_len ||
        (expected_len > 0 && memcmp(actual, expected, expected_len) != 0)) {
        failures++;
        fprintf(stderr, "FAIL %s\n", what);
        fprintf(stderr, "  expected (%zu bytes):", expected_len);
        for (size_t i = 0; i < expected_len; i++) {
            fprintf(stderr, " %02x", expected[i]);
        }
        fprintf(stderr, "\n  actual   (%zu bytes):", actual_len);
        for (size_t i = 0; i < actual_len; i++) {
            fprintf(stderr, " %02x", actual[i]);
        }
        fprintf(stderr, "\n");
    }
}

/* ------------------------------------------------------------------------ */
/* Sanity: strerror, init contract                                          */
/* ------------------------------------------------------------------------ */

static void test_strerror_covers_every_code(void)
{
    for (int i = 0; i < (int)ANTS_ERROR__MAX; i++) {
        const char *s = ants_strerror((ants_error_t)i);
        CHECK(s != NULL);
        CHECK(strlen(s) > 0);
    }
    const char *unk = ants_strerror((ants_error_t)9999);
    CHECK(unk != NULL);
    CHECK(strcmp(unk, "unknown") == 0);
}

static void test_enc_init_rejects_invalid_args(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(NULL, buf, sizeof buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_enc_init(&enc, NULL, sizeof buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_dec_init_rejects_invalid_args(void)
{
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(NULL, (const uint8_t *)"x", 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_dec_init(&dec, NULL, 1), ANTS_ERROR_INVALID_ARG);
    /* len=0 with buf=NULL is valid (empty input). */
    CHECK_EQ(ants_cbor_dec_init(&dec, NULL, 0), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Encode: uint (major type 0) — shortest-form                              */
/* ------------------------------------------------------------------------ */

/* Per RFC 8949 §3:
 *   0     -> 0x00            (1 byte)
 *   23    -> 0x17            (1 byte)
 *   24    -> 0x18 18         (2 bytes)
 *   255   -> 0x18 ff         (2 bytes)
 *   256   -> 0x19 01 00      (3 bytes)
 *   65535 -> 0x19 ff ff      (3 bytes)
 *   65536 -> 0x1a 00 01 00 00 (5 bytes)
 *   2^32  -> 0x1b 00 00 00 01 00 00 00 00 (9 bytes)
 *   2^64-1-> 0x1b ff ff ff ff ff ff ff ff (9 bytes)
 */
static void test_encode_uint_shortest_form(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;

    struct {
        uint64_t v;
        const uint8_t *expected;
        size_t expected_len;
    } cases[] = {
        {0, (const uint8_t *)"\x00", 1},
        {1, (const uint8_t *)"\x01", 1},
        {23, (const uint8_t *)"\x17", 1},
        {24, (const uint8_t *)"\x18\x18", 2},
        {25, (const uint8_t *)"\x18\x19", 2},
        {0xff, (const uint8_t *)"\x18\xff", 2},
        {0x100, (const uint8_t *)"\x19\x01\x00", 3},
        {0xffff, (const uint8_t *)"\x19\xff\xff", 3},
        {0x10000, (const uint8_t *)"\x1a\x00\x01\x00\x00", 5},
        {0xffffffff, (const uint8_t *)"\x1a\xff\xff\xff\xff", 5},
        {0x100000000ULL, (const uint8_t *)"\x1b\x00\x00\x00\x01\x00\x00\x00\x00", 9},
        {UINT64_MAX, (const uint8_t *)"\x1b\xff\xff\xff\xff\xff\xff\xff\xff", 9},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, cases[i].v), ANTS_OK);
        check_bytes("uint encode", buf, enc.pos, cases[i].expected, cases[i].expected_len);
    }
}

static void test_encode_uint_buffer_too_small(void)
{
    uint8_t small[1];
    ants_cbor_enc_t enc;
    /* 24 requires 2 bytes; 1-byte buffer must reject. */
    CHECK_EQ(ants_cbor_enc_init(&enc, small, sizeof small), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 24), ANTS_ERROR_BUFFER_TOO_SMALL);
    /* Value 23 fits in 1 byte though. */
    CHECK_EQ(ants_cbor_enc_init(&enc, small, sizeof small), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 23), ANTS_OK);
    CHECK(enc.pos == 1);
}

/* ------------------------------------------------------------------------ */
/* Encode: int (major type 0 or 1 depending on sign)                        */
/* ------------------------------------------------------------------------ */

/* Per RFC 8949: positive ints use major 0, negatives use major 1 with
 * encoded value -1 - n.
 *   -1     -> 0x20            (1 byte)
 *   -24    -> 0x37            (1 byte)
 *   -25    -> 0x38 18         (2 bytes)
 *   -100   -> 0x38 63         (2 bytes)
 *   -1000  -> 0x39 03 e7      (3 bytes)
 *   INT64_MIN (-2^63) -> 0x3b 7f ff ff ff ff ff ff ff
 */
static void test_encode_int_round_trip(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;

    struct {
        int64_t v;
        const uint8_t *expected;
        size_t expected_len;
    } cases[] = {
        {0, (const uint8_t *)"\x00", 1},
        {23, (const uint8_t *)"\x17", 1},
        {-1, (const uint8_t *)"\x20", 1},
        {-24, (const uint8_t *)"\x37", 1},
        {-25, (const uint8_t *)"\x38\x18", 2},
        {-100, (const uint8_t *)"\x38\x63", 2},
        {-1000, (const uint8_t *)"\x39\x03\xe7", 3},
        {INT64_MIN, (const uint8_t *)"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff", 9},
        {INT64_MAX, (const uint8_t *)"\x1b\x7f\xff\xff\xff\xff\xff\xff\xff", 9},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_int(&enc, cases[i].v), ANTS_OK);
        check_bytes("int encode", buf, enc.pos, cases[i].expected, cases[i].expected_len);
    }
}

/* ------------------------------------------------------------------------ */
/* Encode: bytes / text (major types 2 and 3)                               */
/* ------------------------------------------------------------------------ */

static void test_encode_bytes_round_trip(void)
{
    uint8_t buf[32];
    ants_cbor_enc_t enc;

    /* Empty byte string. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, NULL, 0), ANTS_OK);
    check_bytes("bytes empty", buf, enc.pos, (const uint8_t *)"\x40", 1);

    /* 4-byte content. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, (const uint8_t *)"\x01\x02\x03\x04", 4), ANTS_OK);
    check_bytes("bytes 4", buf, enc.pos, (const uint8_t *)"\x44\x01\x02\x03\x04", 5);

    /* 24-byte content (header transitions to 2-byte form). */
    uint8_t in24[24];
    for (size_t i = 0; i < sizeof in24; i++) {
        in24[i] = (uint8_t)i;
    }
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, in24, sizeof in24), ANTS_OK);
    CHECK(enc.pos == sizeof in24 + 2);
    CHECK(buf[0] == 0x58);
    CHECK(buf[1] == 0x18);
}

static void test_encode_text_round_trip(void)
{
    uint8_t buf[32];
    ants_cbor_enc_t enc;

    /* Empty text. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, NULL, 0), ANTS_OK);
    check_bytes("text empty", buf, enc.pos, (const uint8_t *)"\x60", 1);

    /* "ANTS" (4 bytes). */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "ANTS", 4), ANTS_OK);
    check_bytes("text ANTS", buf, enc.pos, (const uint8_t *)"\x64\x41\x4e\x54\x53", 5);
}

/* ------------------------------------------------------------------------ */
/* Decode: round-trip + canonical-rejection                                 */
/* ------------------------------------------------------------------------ */

static void test_decode_uint_canonical_form(void)
{
    /* Valid shortest-form. */
    const uint8_t v0[] = {0x00};
    const uint8_t v23[] = {0x17};
    const uint8_t v24[] = {0x18, 0x18};
    const uint8_t vmax8[] = {0x18, 0xff};
    const uint8_t v256[] = {0x19, 0x01, 0x00};
    const uint8_t v65536[] = {0x1a, 0x00, 0x01, 0x00, 0x00};
    const uint8_t v2_32[] = {0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    const uint8_t vu64max[] = {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    struct {
        const uint8_t *input;
        size_t input_len;
        uint64_t expected;
    } cases[] = {
        {v0, sizeof v0, 0},
        {v23, sizeof v23, 23},
        {v24, sizeof v24, 24},
        {vmax8, sizeof vmax8, 255},
        {v256, sizeof v256, 256},
        {v65536, sizeof v65536, 65536},
        {v2_32, sizeof v2_32, 0x100000000ULL},
        {vu64max, sizeof vu64max, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ants_cbor_dec_t dec;
        uint64_t got = 0;
        CHECK_EQ(ants_cbor_dec_init(&dec, cases[i].input, cases[i].input_len), ANTS_OK);
        CHECK_EQ(ants_cbor_dec_uint(&dec, &got), ANTS_OK);
        CHECK(got == cases[i].expected);
        CHECK(ants_cbor_dec_eof(&dec));
    }
}

static void test_decode_uint_rejects_non_shortest(void)
{
    /* 0x18 0x00: header says "1-byte follows" but the value is 0, which
     * fits in the initial byte alone. §4.2.1 requires shortest-form. */
    const uint8_t bad_24_for_0[] = {0x18, 0x00};
    /* 0x19 0x00 0x17: 2-byte follows, value 23 — fits in 1 byte. */
    const uint8_t bad_25_for_23[] = {0x19, 0x00, 0x17};
    /* 0x1a 0x00 0x00 0x00 0xff: 4-byte follows, value 255 — fits in 2-byte form. */
    const uint8_t bad_26_for_255[] = {0x1a, 0x00, 0x00, 0x00, 0xff};
    /* 0x1b 0x00 0x00 0x00 0x00 0xff 0xff 0xff 0xff: 8-byte follows, value 2^32-1 — fits in 4-byte
     * form. */
    const uint8_t bad_27_for_u32[] = {0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};

    const struct {
        const uint8_t *input;
        size_t input_len;
    } cases[] = {
        {bad_24_for_0, sizeof bad_24_for_0},
        {bad_25_for_23, sizeof bad_25_for_23},
        {bad_26_for_255, sizeof bad_26_for_255},
        {bad_27_for_u32, sizeof bad_27_for_u32},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ants_cbor_dec_t dec;
        uint64_t got = 0;
        CHECK_EQ(ants_cbor_dec_init(&dec, cases[i].input, cases[i].input_len), ANTS_OK);
        CHECK_EQ(ants_cbor_dec_uint(&dec, &got), ANTS_ERROR_NON_CANONICAL);
    }
}

static void test_decode_rejects_indefinite_and_reserved(void)
{
    /* Major type 0, additional info 31 (indefinite-length) — invalid here
     * and rejected as non-canonical under §4.2.1. */
    const uint8_t indef_uint[] = {0x1f};
    /* Additional info 28 (reserved). */
    const uint8_t reserved_28[] = {0x1c};
    /* Additional info 29 (reserved). */
    const uint8_t reserved_29[] = {0x1d};
    /* Additional info 30 (reserved). */
    const uint8_t reserved_30[] = {0x1e};

    const struct {
        const uint8_t *input;
        size_t input_len;
    } cases[] = {
        {indef_uint, sizeof indef_uint},
        {reserved_28, sizeof reserved_28},
        {reserved_29, sizeof reserved_29},
        {reserved_30, sizeof reserved_30},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ants_cbor_dec_t dec;
        uint64_t got = 0;
        CHECK_EQ(ants_cbor_dec_init(&dec, cases[i].input, cases[i].input_len), ANTS_OK);
        CHECK_EQ(ants_cbor_dec_uint(&dec, &got), ANTS_ERROR_NON_CANONICAL);
    }
}

static void test_decode_int_round_trip(void)
{
    struct {
        const uint8_t *input;
        size_t input_len;
        int64_t expected;
    } cases[] = {
        {(const uint8_t *)"\x00", 1, 0},
        {(const uint8_t *)"\x17", 1, 23},
        {(const uint8_t *)"\x20", 1, -1},
        {(const uint8_t *)"\x37", 1, -24},
        {(const uint8_t *)"\x38\x18", 2, -25},
        {(const uint8_t *)"\x38\x63", 2, -100},
        {(const uint8_t *)"\x39\x03\xe7", 3, -1000},
        {(const uint8_t *)"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff", 9, INT64_MIN},
        {(const uint8_t *)"\x1b\x7f\xff\xff\xff\xff\xff\xff\xff", 9, INT64_MAX},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ants_cbor_dec_t dec;
        int64_t got = 0;
        CHECK_EQ(ants_cbor_dec_init(&dec, cases[i].input, cases[i].input_len), ANTS_OK);
        CHECK_EQ(ants_cbor_dec_int(&dec, &got), ANTS_OK);
        CHECK(got == cases[i].expected);
    }
}

static void test_decode_int_overflow(void)
{
    /* uint that exceeds INT64_MAX must overflow when decoded as int. */
    const uint8_t too_big_pos[] = {0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    /* Negative that exceeds INT64_MIN. */
    const uint8_t too_big_neg[] = {0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ants_cbor_dec_t dec;
    int64_t got = 0;
    CHECK_EQ(ants_cbor_dec_init(&dec, too_big_pos, sizeof too_big_pos), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_int(&dec, &got), ANTS_ERROR_OVERFLOW);
    CHECK_EQ(ants_cbor_dec_init(&dec, too_big_neg, sizeof too_big_neg), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_int(&dec, &got), ANTS_ERROR_OVERFLOW);
}

static void test_decode_bytes_round_trip(void)
{
    /* Empty byte string: 0x40 */
    const uint8_t empty[] = {0x40};
    /* 4-byte content. */
    const uint8_t bytes4[] = {0x44, 0x01, 0x02, 0x03, 0x04};
    /* 24-byte content (2-byte header). */
    const uint8_t bytes24[] = {
        0x58, 0x18, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };

    ants_cbor_dec_t dec;
    const uint8_t *out = NULL;
    size_t out_len = 0;

    CHECK_EQ(ants_cbor_dec_init(&dec, empty, sizeof empty), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bytes(&dec, &out, &out_len), ANTS_OK);
    CHECK(out_len == 0);

    CHECK_EQ(ants_cbor_dec_init(&dec, bytes4, sizeof bytes4), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bytes(&dec, &out, &out_len), ANTS_OK);
    CHECK(out_len == 4);
    CHECK(out == bytes4 + 1);
    CHECK(memcmp(out, "\x01\x02\x03\x04", 4) == 0);

    CHECK_EQ(ants_cbor_dec_init(&dec, bytes24, sizeof bytes24), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bytes(&dec, &out, &out_len), ANTS_OK);
    CHECK(out_len == 24);
    CHECK(out == bytes24 + 2);

    /* Truncated input must be rejected as malformed. */
    const uint8_t truncated[] = {0x44, 0x01, 0x02};
    CHECK_EQ(ants_cbor_dec_init(&dec, truncated, sizeof truncated), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bytes(&dec, &out, &out_len), ANTS_ERROR_MALFORMED);
}

static void test_decode_text_round_trip(void)
{
    const uint8_t empty[] = {0x60};
    const uint8_t ants[] = {0x64, 0x41, 0x4e, 0x54, 0x53};

    ants_cbor_dec_t dec;
    const char *out = NULL;
    size_t out_len = 0;

    CHECK_EQ(ants_cbor_dec_init(&dec, empty, sizeof empty), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_text(&dec, &out, &out_len), ANTS_OK);
    CHECK(out_len == 0);

    CHECK_EQ(ants_cbor_dec_init(&dec, ants, sizeof ants), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_text(&dec, &out, &out_len), ANTS_OK);
    CHECK(out_len == 4);
    CHECK(memcmp(out, "ANTS", 4) == 0);
}

/* ------------------------------------------------------------------------ */
/* Peek + type dispatch                                                     */
/* ------------------------------------------------------------------------ */

static void test_peek_type(void)
{
    struct {
        uint8_t initial;
        ants_cbor_type_t expected;
        bool valid;
    } cases[] = {
        {0x00, ANTS_CBOR_TYPE_UINT, true},   /* major 0 */
        {0x20, ANTS_CBOR_TYPE_NEGINT, true}, /* major 1 */
        {0x40, ANTS_CBOR_TYPE_BYTES, true},  /* major 2 */
        {0x60, ANTS_CBOR_TYPE_TEXT, true},   /* major 3 */
        {0x80, ANTS_CBOR_TYPE_ARRAY, true},  /* major 4 */
        {0xa0, ANTS_CBOR_TYPE_MAP, true},    /* major 5 */
        {0xc0, ANTS_CBOR_TYPE_TAG, true},    /* major 6 */
        {0xf4, ANTS_CBOR_TYPE_BOOL, true},   /* major 7, info 20 (false) */
        {0xf5, ANTS_CBOR_TYPE_BOOL, true},   /* major 7, info 21 (true) */
        {0xf6, ANTS_CBOR_TYPE_NULL, true},   /* major 7, info 22 (null) */
        {0xf7, ANTS_CBOR_TYPE_UINT, false},  /* major 7, info 23 (undef): unsupported */
        {0xfa, ANTS_CBOR_TYPE_UINT, false},  /* major 7, info 26 (float32): unsupported */
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ants_cbor_dec_t dec;
        ants_cbor_type_t got;
        CHECK_EQ(ants_cbor_dec_init(&dec, &cases[i].initial, 1), ANTS_OK);
        ants_error_t err = ants_cbor_dec_peek_type(&dec, &got);
        if (cases[i].valid) {
            CHECK_EQ(err, ANTS_OK);
            CHECK(got == cases[i].expected);
        } else {
            CHECK_EQ(err, ANTS_ERROR_UNSUPPORTED_TYPE);
        }
    }

    /* peek on empty buffer must report malformed. */
    ants_cbor_dec_t dec;
    ants_cbor_type_t t;
    CHECK_EQ(ants_cbor_dec_init(&dec, NULL, 0), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_peek_type(&dec, &t), ANTS_ERROR_MALFORMED);
}

/* ------------------------------------------------------------------------ */
/* Encode: array (major type 4)                                             */
/* ------------------------------------------------------------------------ */

static void test_encode_array_empty(void)
{
    uint8_t buf[8];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 0), ANTS_OK);
    check_bytes("empty array", buf, enc.pos, (const uint8_t *)"\x80", 1);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_array_flat(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 3), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 3), ANTS_OK);
    /* After the third item, container closes automatically. */
    check_bytes("array[1,2,3]", buf, enc.pos, (const uint8_t *)"\x83\x01\x02\x03", 4);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_array_nested(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    /* [[1, 2], [3]] */
    CHECK_EQ(ants_cbor_enc_array(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 3), ANTS_OK);
    check_bytes("nested array", buf, enc.pos, (const uint8_t *)"\x82\x82\x01\x02\x81\x03", 6);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_array_underfill(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    /* Declare 3 items, add only 2, then finalise. */
    CHECK_EQ(ants_cbor_enc_array(&enc, 3), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_ERROR_MALFORMED);
}

/* ------------------------------------------------------------------------ */
/* Encode: map (major type 5) with canonical-key-order enforcement          */
/* ------------------------------------------------------------------------ */

static void test_encode_map_empty(void)
{
    uint8_t buf[8];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 0), ANTS_OK);
    check_bytes("empty map", buf, enc.pos, (const uint8_t *)"\xa0", 1);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_map_canonical_order(void)
{
    uint8_t buf[32];
    ants_cbor_enc_t enc;
    /* {1: "one", 2: "two"} — keys 1 and 2 encode to 0x01 and 0x02; correct order. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "one", 3), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "two", 3), ANTS_OK);
    /* Expected: 0xa2 0x01 0x63 'o' 'n' 'e' 0x02 0x63 't' 'w' 'o' */
    check_bytes("map {1:one, 2:two}",
                buf,
                enc.pos,
                (const uint8_t *)"\xa2\x01\x63\x6f\x6e\x65\x02\x63\x74\x77\x6f",
                11);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_map_rejects_unsorted_keys(void)
{
    uint8_t buf[32];
    ants_cbor_enc_t enc;
    /* {2: "two", 1: ...} — keys out of order; encoder must reject the
     * second key. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "two", 3), ANTS_OK);
    /* Second key 1 < 2: should be rejected. */
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_ERROR_NON_CANONICAL);
}

static void test_encode_map_rejects_duplicate_keys(void)
{
    uint8_t buf[32];
    ants_cbor_enc_t enc;
    /* {1: ..., 1: ...} — duplicate key. Strict canonical requires strict
     * monotone order, so duplicates are NON_CANONICAL too. */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "one", 3), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_ERROR_NON_CANONICAL);
}

static void test_encode_map_in_array(void)
{
    /* Mixed nesting: [{1: 10}, {2: 20}] */
    uint8_t buf[32];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 10), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 20), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
    /* 0x82 0xa1 0x01 0x0a 0xa1 0x02 0x14 */
    check_bytes(
        "nested map-in-array", buf, enc.pos, (const uint8_t *)"\x82\xa1\x01\x0a\xa1\x02\x14", 7);
}

/* ------------------------------------------------------------------------ */
/* Decode: array + map                                                      */
/* ------------------------------------------------------------------------ */

static void test_decode_array_round_trip(void)
{
    /* [1, 2, 3] */
    const uint8_t input[] = {0x83, 0x01, 0x02, 0x03};
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    size_t n = 0;
    CHECK_EQ(ants_cbor_dec_array(&dec, &n), ANTS_OK);
    CHECK(n == 3);
    uint64_t v = 0;
    CHECK_EQ(ants_cbor_dec_uint(&dec, &v), ANTS_OK);
    CHECK(v == 1);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &v), ANTS_OK);
    CHECK(v == 2);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &v), ANTS_OK);
    CHECK(v == 3);
    CHECK(ants_cbor_dec_eof(&dec));
    CHECK(dec.depth == -1); /* container auto-closed */
}

static void test_decode_array_empty(void)
{
    const uint8_t input[] = {0x80};
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    size_t n = 999;
    CHECK_EQ(ants_cbor_dec_array(&dec, &n), ANTS_OK);
    CHECK(n == 0);
    CHECK(ants_cbor_dec_eof(&dec));
    CHECK(dec.depth == -1);
}

static void test_decode_map_round_trip(void)
{
    /* {1: "one", 2: "two"} canonical encoding. */
    const uint8_t input[] = {
        0xa2,
        0x01,
        0x63,
        0x6f,
        0x6e,
        0x65,
        0x02,
        0x63,
        0x74,
        0x77,
        0x6f,
    };
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    size_t n = 0;
    CHECK_EQ(ants_cbor_dec_map(&dec, &n), ANTS_OK);
    CHECK(n == 2);
    uint64_t k;
    const char *v;
    size_t vlen;
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_OK);
    CHECK(k == 1);
    CHECK_EQ(ants_cbor_dec_text(&dec, &v, &vlen), ANTS_OK);
    CHECK(vlen == 3 && memcmp(v, "one", 3) == 0);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_OK);
    CHECK(k == 2);
    CHECK_EQ(ants_cbor_dec_text(&dec, &v, &vlen), ANTS_OK);
    CHECK(vlen == 3 && memcmp(v, "two", 3) == 0);
    CHECK(ants_cbor_dec_eof(&dec));
    CHECK(dec.depth == -1);
}

static void test_decode_map_rejects_unsorted_keys(void)
{
    /* {2: "two", 1: ...} — well-formed CBOR but keys out of order. */
    const uint8_t input[] = {
        0xa2,
        0x02,
        0x63,
        0x74,
        0x77,
        0x6f,
        0x01,
        0x63,
        0x6f,
        0x6e,
        0x65,
    };
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    size_t n = 0;
    CHECK_EQ(ants_cbor_dec_map(&dec, &n), ANTS_OK);
    CHECK(n == 2);
    uint64_t k;
    const char *v;
    size_t vlen;
    /* First pair: key 2, value "two". OK. */
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_OK);
    CHECK(k == 2);
    CHECK_EQ(ants_cbor_dec_text(&dec, &v, &vlen), ANTS_OK);
    /* Second key is 1, less than 2: must be rejected as non-canonical. */
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_ERROR_NON_CANONICAL);
}

static void test_decode_map_rejects_duplicate_keys(void)
{
    /* {1: "one", 1: "two"} — duplicate keys; strict canonical order
     * requires strict monotone, so equal keys are rejected. */
    const uint8_t input[] = {
        0xa2,
        0x01,
        0x63,
        0x6f,
        0x6e,
        0x65,
        0x01,
        0x63,
        0x74,
        0x77,
        0x6f,
    };
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    size_t n = 0;
    CHECK_EQ(ants_cbor_dec_map(&dec, &n), ANTS_OK);
    CHECK(n == 2);
    uint64_t k;
    const char *v;
    size_t vlen;
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_text(&dec, &v, &vlen), ANTS_OK);
    /* Duplicate key 1: rejected. */
    CHECK_EQ(ants_cbor_dec_uint(&dec, &k), ANTS_ERROR_NON_CANONICAL);
}

/* ------------------------------------------------------------------------ */
/* Encode / Decode: bool (major type 7, simple values 20/21)                 */
/* ------------------------------------------------------------------------ */

static void test_encode_bool(void)
{
    uint8_t buf[4];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bool(&enc, false), ANTS_OK);
    check_bytes("encode false", buf, enc.pos, (const uint8_t *)"\xf4", 1);

    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bool(&enc, true), ANTS_OK);
    check_bytes("encode true", buf, enc.pos, (const uint8_t *)"\xf5", 1);
}

static void test_decode_bool(void)
{
    const uint8_t inp_false[] = {0xf4};
    const uint8_t inp_true[] = {0xf5};
    ants_cbor_dec_t dec;
    bool v;

    CHECK_EQ(ants_cbor_dec_init(&dec, inp_false, sizeof inp_false), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bool(&dec, &v), ANTS_OK);
    CHECK(v == false);

    CHECK_EQ(ants_cbor_dec_init(&dec, inp_true, sizeof inp_true), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bool(&dec, &v), ANTS_OK);
    CHECK(v == true);
}

static void test_decode_bool_rejects_non_bool(void)
{
    const uint8_t null_byte[] = {0xf6};
    ants_cbor_dec_t dec;
    bool v;
    CHECK_EQ(ants_cbor_dec_init(&dec, null_byte, sizeof null_byte), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_bool(&dec, &v), ANTS_ERROR_UNSUPPORTED_TYPE);
}

/* ------------------------------------------------------------------------ */
/* Encode / Decode: null (major type 7, simple value 22)                     */
/* ------------------------------------------------------------------------ */

static void test_encode_null(void)
{
    uint8_t buf[4];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_null(&enc), ANTS_OK);
    check_bytes("encode null", buf, enc.pos, (const uint8_t *)"\xf6", 1);
}

static void test_decode_null(void)
{
    const uint8_t input[] = {0xf6};
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_null(&dec), ANTS_OK);
}

static void test_decode_null_rejects_non_null(void)
{
    const uint8_t bool_byte[] = {0xf4};
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(&dec, bool_byte, sizeof bool_byte), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_null(&dec), ANTS_ERROR_UNSUPPORTED_TYPE);
}

/* ------------------------------------------------------------------------ */
/* Encode / Decode: tag (major type 6, RFC-0008 §1.1 reserved set 0/32/42)   */
/* ------------------------------------------------------------------------ */

static void test_encode_tag_reserved(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;

    /* tag 0 + uint 5: 0xc0 0x05 (2 bytes) */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 0), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 5), ANTS_OK);
    check_bytes("tag 0 + uint 5", buf, enc.pos, (const uint8_t *)"\xc0\x05", 2);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);

    /* tag 32 + uint 5: 0xd8 0x20 0x05 (3 bytes; tag 32 needs 2-byte form) */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 32), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 5), ANTS_OK);
    check_bytes("tag 32 + uint 5", buf, enc.pos, (const uint8_t *)"\xd8\x20\x05", 3);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);

    /* tag 42 + text "hi": 0xd8 0x2a 0x62 0x68 0x69 (5 bytes) */
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 42), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_text(&enc, "hi", 2), ANTS_OK);
    check_bytes("tag 42 + text hi", buf, enc.pos, (const uint8_t *)"\xd8\x2a\x62\x68\x69", 5);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

static void test_encode_tag_rejects_non_reserved(void)
{
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    /* tag 1 not in reserved set */
    CHECK_EQ(ants_cbor_enc_tag(&enc, 1), ANTS_ERROR_UNSUPPORTED_TYPE);
    /* tag 100 not in reserved set */
    CHECK_EQ(ants_cbor_enc_tag(&enc, 100), ANTS_ERROR_UNSUPPORTED_TYPE);
    /* tag 31 (close to but not 32) not in reserved set */
    CHECK_EQ(ants_cbor_enc_tag(&enc, 31), ANTS_ERROR_UNSUPPORTED_TYPE);
}

static void test_decode_tag_reserved(void)
{
    const uint8_t inp0[] = {0xc0, 0x05};
    const uint8_t inp32[] = {0xd8, 0x20, 0x05};
    const uint8_t inp42[] = {0xd8, 0x2a, 0x62, 0x68, 0x69};

    ants_cbor_dec_t dec;
    uint64_t tag;
    uint64_t u;
    const char *txt;
    size_t txtlen;

    CHECK_EQ(ants_cbor_dec_init(&dec, inp0, sizeof inp0), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_tag(&dec, &tag), ANTS_OK);
    CHECK(tag == 0);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &u), ANTS_OK);
    CHECK(u == 5);
    CHECK(dec.depth == -1); /* tag closed after item */

    CHECK_EQ(ants_cbor_dec_init(&dec, inp32, sizeof inp32), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_tag(&dec, &tag), ANTS_OK);
    CHECK(tag == 32);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &u), ANTS_OK);
    CHECK(u == 5);

    CHECK_EQ(ants_cbor_dec_init(&dec, inp42, sizeof inp42), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_tag(&dec, &tag), ANTS_OK);
    CHECK(tag == 42);
    CHECK_EQ(ants_cbor_dec_text(&dec, &txt, &txtlen), ANTS_OK);
    CHECK(txtlen == 2 && memcmp(txt, "hi", 2) == 0);
}

static void test_decode_tag_rejects_non_reserved(void)
{
    /* tag 1 + uint 5: 0xc1 0x05 */
    const uint8_t inp[] = {0xc1, 0x05};
    ants_cbor_dec_t dec;
    uint64_t tag;
    CHECK_EQ(ants_cbor_dec_init(&dec, inp, sizeof inp), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_tag(&dec, &tag), ANTS_ERROR_UNSUPPORTED_TYPE);
}

static void test_encode_tag_in_array(void)
{
    /* [tag 0 + uint 1, tag 32 + uint 2] */
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 0), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 32), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    /* Expected: 0x82 0xc0 0x01 0xd8 0x20 0x02 */
    check_bytes("array of tagged", buf, enc.pos, (const uint8_t *)"\x82\xc0\x01\xd8\x20\x02", 6);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Mixed: map with simple values                                             */
/* ------------------------------------------------------------------------ */

static void test_encode_map_with_simple_values(void)
{
    /* {1: true, 2: null} */
    uint8_t buf[16];
    ants_cbor_enc_t enc;
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bool(&enc, true), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_null(&enc), ANTS_OK);
    /* Expected: 0xa2 0x01 0xf5 0x02 0xf6 */
    check_bytes("map with simple values", buf, enc.pos, (const uint8_t *)"\xa2\x01\xf5\x02\xf6", 5);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Stubs still in place: is_canonical (the top-level validator)              */
/* ------------------------------------------------------------------------ */

static void test_remaining_stubs(void)
{
    const uint8_t input[] = {0x00};
    CHECK_EQ(ants_cbor_is_canonical(input, sizeof input), ANTS_ERROR_NOT_IMPLEMENTED);
}

/* ------------------------------------------------------------------------ */

int main(void)
{
    test_strerror_covers_every_code();
    test_enc_init_rejects_invalid_args();
    test_dec_init_rejects_invalid_args();

    test_encode_uint_shortest_form();
    test_encode_uint_buffer_too_small();
    test_encode_int_round_trip();
    test_encode_bytes_round_trip();
    test_encode_text_round_trip();

    test_decode_uint_canonical_form();
    test_decode_uint_rejects_non_shortest();
    test_decode_rejects_indefinite_and_reserved();
    test_decode_int_round_trip();
    test_decode_int_overflow();
    test_decode_bytes_round_trip();
    test_decode_text_round_trip();

    test_peek_type();

    test_encode_array_empty();
    test_encode_array_flat();
    test_encode_array_nested();
    test_encode_array_underfill();
    test_encode_map_empty();
    test_encode_map_canonical_order();
    test_encode_map_rejects_unsorted_keys();
    test_encode_map_rejects_duplicate_keys();
    test_encode_map_in_array();

    test_decode_array_round_trip();
    test_decode_array_empty();
    test_decode_map_round_trip();
    test_decode_map_rejects_unsorted_keys();
    test_decode_map_rejects_duplicate_keys();

    test_encode_bool();
    test_decode_bool();
    test_decode_bool_rejects_non_bool();
    test_encode_null();
    test_decode_null();
    test_decode_null_rejects_non_null();

    test_encode_tag_reserved();
    test_encode_tag_rejects_non_reserved();
    test_decode_tag_reserved();
    test_decode_tag_rejects_non_reserved();
    test_encode_tag_in_array();
    test_encode_map_with_simple_values();

    test_remaining_stubs();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
