/*
 * test_cbor.c — placeholder tests for the CBOR codec.
 *
 * At this stage the implementation is stubbed (returns
 * ANTS_ERROR_NOT_IMPLEMENTED for every encode/decode operation), so
 * the only behavioural tests we can write validate:
 *
 *   - that ants_cbor_enc_init and ants_cbor_dec_init succeed on
 *     well-formed inputs;
 *   - that they reject obviously-invalid inputs (NULL pointers, zero
 *     capacity);
 *   - that stub functions return ANTS_ERROR_NOT_IMPLEMENTED rather
 *     than crashing or returning a misleading success;
 *   - that ants_strerror returns a non-NULL string for every defined
 *     error code.
 *
 * As implementation lands per major type, these placeholder tests are
 * replaced with vector-driven tests that validate against the
 * ants-test-vectors pack.
 *
 * Test framework: stdio + assert. Deliberately no framework dependency
 * at this stage — too small to justify.
 */

#include "ants_cbor.h"
#include "ants_common.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                              \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            failures++;                                                                          \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                      \
        }                                                                                        \
    } while (0)

#define CHECK_EQ(actual, expected)                                                               \
    do {                                                                                         \
        ants_error_t _a = (actual);                                                              \
        ants_error_t _e = (expected);                                                            \
        if (_a != _e) {                                                                          \
            failures++;                                                                          \
            fprintf(stderr, "FAIL %s:%d  expected %s (%d), got %s (%d)\n", __FILE__, __LINE__,   \
                    ants_strerror(_e), (int)_e, ants_strerror(_a), (int)_a);                     \
        }                                                                                        \
    } while (0)

static void test_strerror_covers_every_code(void)
{
    for (int i = 0; i < (int)ANTS_ERROR__MAX; i++) {
        const char *s = ants_strerror((ants_error_t)i);
        CHECK(s != NULL);
        CHECK(strlen(s) > 0);
    }
    /* Out-of-range value should still return a valid pointer (not crash). */
    const char *unk = ants_strerror((ants_error_t)9999);
    CHECK(unk != NULL);
    CHECK(strcmp(unk, "unknown") == 0);
}

static void test_enc_init_rejects_invalid_args(void)
{
    uint8_t          buf[16];
    ants_cbor_enc_t  enc;

    CHECK_EQ(ants_cbor_enc_init(NULL, buf, sizeof buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_enc_init(&enc, NULL, sizeof buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_enc_init_succeeds(void)
{
    uint8_t          buf[16];
    ants_cbor_enc_t  enc;

    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK(enc.buf == buf);
    CHECK(enc.cap == sizeof buf);
    CHECK(enc.pos == 0);
    CHECK(enc.depth == -1);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_ERROR_MALFORMED); /* empty */
}

static void test_enc_stubs_return_not_implemented(void)
{
    uint8_t          buf[16];
    ants_cbor_enc_t  enc;

    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);

    CHECK_EQ(ants_cbor_enc_uint(&enc, 42), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_int(&enc, -1), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, NULL, 0), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_text(&enc, NULL, 0), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_array(&enc, 0), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_map(&enc, 0), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_bool(&enc, true), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_null(&enc), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_enc_tag(&enc, 0), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_dec_init_rejects_invalid_args(void)
{
    ants_cbor_dec_t dec;
    CHECK_EQ(ants_cbor_dec_init(NULL, (const uint8_t *)"x", 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_cbor_dec_init(&dec, NULL, 1), ANTS_ERROR_INVALID_ARG);
    /* len=0 with buf=NULL is valid (empty input). */
    CHECK_EQ(ants_cbor_dec_init(&dec, NULL, 0), ANTS_OK);
}

static void test_dec_stubs_return_not_implemented(void)
{
    const uint8_t   input[] = {0x00};
    ants_cbor_dec_t dec;

    CHECK_EQ(ants_cbor_dec_init(&dec, input, sizeof input), ANTS_OK);

    ants_cbor_type_t  t;
    uint64_t          u;
    int64_t           i;
    const uint8_t    *bp;
    const char       *sp;
    size_t            sz;
    uint64_t          tag;
    bool              b;

    CHECK_EQ(ants_cbor_dec_peek_type(&dec, &t), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_uint(&dec, &u), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_int(&dec, &i), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_bytes(&dec, &bp, &sz), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_text(&dec, &sp, &sz), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_array(&dec, &sz), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_map(&dec, &sz), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_tag(&dec, &tag), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_bool(&dec, &b), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_dec_null(&dec), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_cbor_is_canonical(input, sizeof input), ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_strerror_covers_every_code();
    test_enc_init_rejects_invalid_args();
    test_enc_init_succeeds();
    test_enc_stubs_return_not_implemented();
    test_dec_init_rejects_invalid_args();
    test_dec_stubs_return_not_implemented();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
