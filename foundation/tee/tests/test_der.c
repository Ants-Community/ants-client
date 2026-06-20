/*
 * test_der.c — unit tests for the strict DER reader (foundation/tee/src/der.c).
 *
 * The reader walks attacker-controlled DER (a quote may embed a hostile
 * certificate chain), so most of these cases are malformed inputs that MUST be
 * rejected: indefinite and non-minimal lengths, leading-zero length octets,
 * truncation, high-tag-number identifiers, and buffer overruns.
 */

#include "der.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))

/* A well-formed SEQUENCE { INTEGER 0x2A } parses, descends, and reaches EOF. */
static void test_sequence_of_integer(void)
{
    const uint8_t in[] = {0x30, 0x03, 0x02, 0x01, 0x2A};
    ants_der r;
    ants_der_init(&r, in, sizeof in);

    ants_der inner;
    CHECK_EQ(ants_der_enter(&r, ANTS_DER_TAG_SEQUENCE, &inner), ANTS_OK);
    CHECK(ants_der_eof(&r)); /* the SEQUENCE was the whole buffer */

    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&inner, ANTS_DER_TAG_INTEGER, &tlv), ANTS_OK);
    CHECK_EQ(tlv.len, (size_t)1);
    CHECK_EQ(tlv.val[0], 0x2A);
    CHECK(ants_der_eof(&inner));
}

/* A zero-length value (DER NULL) is valid and yields an empty slice. */
static void test_empty_value(void)
{
    const uint8_t in[] = {0x05, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, ANTS_DER_TAG_NULL, &tlv), ANTS_OK);
    CHECK_EQ(tlv.len, (size_t)0);
    CHECK(ants_der_eof(&r));
}

/* Long-form length of exactly 128 (the smallest value that needs long form). */
static void test_long_form_min(void)
{
    uint8_t in[3 + 128];
    memset(in, 0, sizeof in);
    in[0] = ANTS_DER_TAG_OCTET_STRING;
    in[1] = 0x81; /* one length octet follows */
    in[2] = 0x80; /* 128 */
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, ANTS_DER_TAG_OCTET_STRING, &tlv), ANTS_OK);
    CHECK_EQ(tlv.len, (size_t)128);
    CHECK(tlv.val == in + 3);
    CHECK(ants_der_eof(&r));
}

/* Indefinite-length form (0x80) is BER, not DER — rejected. */
static void test_reject_indefinite(void)
{
    const uint8_t in[] = {0x30, 0x80, 0x00, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* A length of 5 expressed in long form must be rejected (should be short). */
static void test_reject_nonminimal_long_form(void)
{
    const uint8_t in[] = {0x02, 0x81, 0x05, 0, 0, 0, 0, 0};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* A leading zero in the long-form length octets is non-minimal — rejected. */
static void test_reject_leading_zero_length(void)
{
    uint8_t in[4 + 128];
    memset(in, 0, sizeof in);
    in[0] = ANTS_DER_TAG_OCTET_STRING;
    in[1] = 0x82; /* two length octets */
    in[2] = 0x00; /* leading zero */
    in[3] = 0x80; /* 128 */
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* A value that claims more bytes than the buffer holds — rejected. */
static void test_reject_truncated_value(void)
{
    const uint8_t in[] = {0x04, 0x05, 0x01, 0x02}; /* claims 5, has 2 */
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* Long form claiming two length octets but only one present — rejected. */
static void test_reject_truncated_length(void)
{
    const uint8_t in[] = {0x02, 0x82, 0x01};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* High-tag-number form (identifier low 5 bits == 0x1F) — rejected. */
static void test_reject_high_tag_number(void)
{
    const uint8_t in[] = {0x1F, 0x01, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
}

/* expect_tag mismatch — rejected without consuming. */
static void test_reject_tag_mismatch(void)
{
    const uint8_t in[] = {0x02, 0x01, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, ANTS_DER_TAG_SEQUENCE, &tlv), ANTS_ERROR_MALFORMED);
}

/* Buffers too short to hold tag + length — rejected. */
static void test_reject_short_buffers(void)
{
    const uint8_t one[] = {0x30};
    ants_der r;
    ants_der_init(&r, one, sizeof one);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);

    ants_der_init(&r, one, 0); /* empty */
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
    CHECK(ants_der_eof(&r)); /* empty buffer is trivially consumed */
}

/* enter() requires a constructed tag; a primitive tag is a usage error. */
static void test_enter_requires_constructed(void)
{
    const uint8_t in[] = {0x02, 0x01, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der inner;
    CHECK_EQ(ants_der_enter(&r, ANTS_DER_TAG_INTEGER, &inner), ANTS_ERROR_INVALID_ARG);
}

/* Two-deep nesting: SEQUENCE { SEQUENCE { INTEGER } }. */
static void test_nested(void)
{
    const uint8_t in[] = {0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07};
    ants_der r, a, b;
    ants_der_init(&r, in, sizeof in);
    CHECK_EQ(ants_der_enter(&r, ANTS_DER_TAG_SEQUENCE, &a), ANTS_OK);
    CHECK_EQ(ants_der_enter(&a, ANTS_DER_TAG_SEQUENCE, &b), ANTS_OK);
    CHECK(ants_der_eof(&a));
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&b, ANTS_DER_TAG_INTEGER, &tlv), ANTS_OK);
    CHECK_EQ(tlv.val[0], 0x07);
    CHECK(ants_der_eof(&b));
}

/* skip() advances past one element; peek_tag() does not advance. */
static void test_skip_and_peek(void)
{
    const uint8_t in[] = {0x02, 0x01, 0x0A, 0x04, 0x02, 0xBB, 0xCC};
    ants_der r;
    ants_der_init(&r, in, sizeof in);

    uint8_t tag = 0;
    CHECK_EQ(ants_der_peek_tag(&r, &tag), ANTS_OK);
    CHECK_EQ(tag, (uint8_t)ANTS_DER_TAG_INTEGER);
    CHECK(!ants_der_eof(&r)); /* peek did not consume */

    CHECK_EQ(ants_der_skip(&r), ANTS_OK); /* skip the INTEGER */
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(&r, ANTS_DER_TAG_OCTET_STRING, &tlv), ANTS_OK);
    CHECK_EQ(tlv.len, (size_t)2);
    CHECK_EQ(tlv.val[1], 0xCC);
    CHECK(ants_der_eof(&r));

    /* Reading past the end is malformed; peeking past the end too. */
    CHECK_EQ(ants_der_read(&r, 0, &tlv), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_der_peek_tag(&r, &tag), ANTS_ERROR_MALFORMED);
}

/* NULL arguments are a caller error, distinct from malformed input. */
static void test_null_args(void)
{
    const uint8_t in[] = {0x02, 0x01, 0x00};
    ants_der r;
    ants_der_init(&r, in, sizeof in);
    ants_der_tlv tlv;
    CHECK_EQ(ants_der_read(NULL, 0, &tlv), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_der_read(&r, 0, NULL), ANTS_ERROR_INVALID_ARG);
    uint8_t tag;
    CHECK_EQ(ants_der_peek_tag(NULL, &tag), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_der_peek_tag(&r, NULL), ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_sequence_of_integer();
    test_empty_value();
    test_long_form_min();
    test_reject_indefinite();
    test_reject_nonminimal_long_form();
    test_reject_leading_zero_length();
    test_reject_truncated_value();
    test_reject_truncated_length();
    test_reject_high_tag_number();
    test_reject_tag_mismatch();
    test_reject_short_buffers();
    test_enter_requires_constructed();
    test_nested();
    test_skip_and_peek();
    test_null_args();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
