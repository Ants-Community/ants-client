/*
 * test_payment.c — Tests for the RFC-0006 payment_terms object
 * (Component #14 PR3).
 *
 * Covers: object init/validation, per-kind scheme validity, scheme-kind
 * intersection, and the canonical-CBOR codec — per-kind round-trips,
 * canonicity, and strict-decode rejection of truncation / trailing bytes
 * / wrong shape / too-many-schemes / a scheme whose key set does not
 * match its kind / an over-long text field.
 *
 * Assertions verify behaviour independently where practical (hand-built
 * malformed CBOR, hand-checked field semantics) rather than mirroring the
 * implementation.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_payment.h"

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

/* ---- scheme builders ------------------------------------------------ */

static ants_payment_scheme_t scheme_none(void)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_NONE;
    return s;
}

static ants_payment_scheme_t scheme_ncs(const char *rate_table)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_NCS;
    snprintf(s.ref_a, sizeof s.ref_a, "%s", rate_table);
    return s;
}

static ants_payment_scheme_t scheme_stripe(uint64_t rate, const char *cur, const char *endpoint)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_FIAT_STRIPE;
    s.amount = rate;
    snprintf(s.currency, sizeof s.currency, "%s", cur);
    snprintf(s.ref_a, sizeof s.ref_a, "%s", endpoint);
    return s;
}

static ants_payment_scheme_t scheme_lightning(uint64_t sats, const char *invoice)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_FIAT_LIGHTNING;
    s.amount = sats;
    snprintf(s.ref_a, sizeof s.ref_a, "%s", invoice);
    return s;
}

static ants_payment_scheme_t scheme_subscription(const char *provider, const char *plan)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_SUBSCRIPTION;
    snprintf(s.ref_a, sizeof s.ref_a, "%s", provider);
    snprintf(s.ref_b, sizeof s.ref_b, "%s", plan);
    return s;
}

static ants_payment_scheme_t scheme_custom(const char *uri)
{
    ants_payment_scheme_t s;
    memset(&s, 0, sizeof s);
    s.kind = ANTS_PAYMENT_SCHEME_CUSTOM;
    snprintf(s.ref_a, sizeof s.ref_a, "%s", uri);
    return s;
}

/* ---- init + validation ---------------------------------------------- */

static void test_init_defaults(void)
{
    ants_payment_terms_t t;
    memset(&t, 0xCC, sizeof t);
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    CHECK(t.n_schemes == 0);
    CHECK(t.validity_unix_s == 0);
    CHECK(t.scope == ANTS_PAYMENT_SCOPE_PER_QUERY);
    CHECK(t.notes[0] == '\0');
    CHECK_EQ(ants_payment_terms_init(NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_scheme_valid_per_kind(void)
{
    ants_payment_scheme_t s;

    /* Each well-formed kind is valid. */
    s = scheme_none();
    CHECK(ants_payment_scheme_valid(&s));
    s = scheme_ncs("default");
    CHECK(ants_payment_scheme_valid(&s));
    s = scheme_stripe(300, "USD", "https://pay.example/abc");
    CHECK(ants_payment_scheme_valid(&s));
    s = scheme_lightning(50, "lnbc...");
    CHECK(ants_payment_scheme_valid(&s));
    s = scheme_subscription("acme", "pro-monthly");
    CHECK(ants_payment_scheme_valid(&s));
    s = scheme_custom("https://schema.example/scheme.json");
    CHECK(ants_payment_scheme_valid(&s));

    CHECK(!ants_payment_scheme_valid(NULL));
}

static void test_scheme_invalid_cases(void)
{
    ants_payment_scheme_t s;

    /* Out-of-range kind. */
    s = scheme_none();
    s.kind = (ants_payment_scheme_kind_t)99;
    CHECK(!ants_payment_scheme_valid(&s));

    /* NONE must carry no fields. */
    s = scheme_none();
    s.amount = 1;
    CHECK(!ants_payment_scheme_valid(&s));
    s = scheme_none();
    s.ref_a[0] = 'x';
    s.ref_a[1] = '\0';
    CHECK(!ants_payment_scheme_valid(&s));

    /* NCS carries ref_a but not amount/currency/ref_b. */
    s = scheme_ncs("t");
    s.amount = 5;
    CHECK(!ants_payment_scheme_valid(&s));
    s = scheme_ncs("t");
    s.currency[0] = 'U';
    s.currency[1] = '\0';
    CHECK(!ants_payment_scheme_valid(&s));

    /* Stripe requires a currency. */
    s = scheme_stripe(300, "", "https://pay");
    CHECK(!ants_payment_scheme_valid(&s));

    /* Lightning must not carry a currency (forbidden field). */
    s = scheme_lightning(50, "lnbc");
    s.currency[0] = 'B';
    s.currency[1] = '\0';
    CHECK(!ants_payment_scheme_valid(&s));

    /* Subscription must not carry an amount. */
    s = scheme_subscription("acme", "plan");
    s.amount = 9;
    CHECK(!ants_payment_scheme_valid(&s));

    /* Unterminated text field (fill ref_a with non-NUL to the brim). */
    s = scheme_custom("x");
    memset(s.ref_a, 'A', sizeof s.ref_a);
    CHECK(!ants_payment_scheme_valid(&s));
}

static void test_add_scheme(void)
{
    ants_payment_terms_t t;
    ants_payment_scheme_t s = scheme_ncs("default");
    ants_payment_scheme_t bad = scheme_none();
    uint32_t i;

    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &s), ANTS_OK);
    CHECK(t.n_schemes == 1);
    CHECK(t.schemes[0].kind == ANTS_PAYMENT_SCHEME_NCS);

    /* NULL + invalid scheme rejected. */
    CHECK_EQ(ants_payment_terms_add_scheme(NULL, &s), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, NULL), ANTS_ERROR_INVALID_ARG);
    bad.amount = 1; /* NONE with an amount → invalid */
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &bad), ANTS_ERROR_INVALID_ARG);
    CHECK(t.n_schemes == 1); /* unchanged */

    /* Fill to capacity, then overflow. */
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    for (i = 0; i < ANTS_PAYMENT_MAX_SCHEMES; i++) {
        CHECK_EQ(ants_payment_terms_add_scheme(&t, &s), ANTS_OK);
    }
    CHECK(t.n_schemes == ANTS_PAYMENT_MAX_SCHEMES);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &s), ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_intersects(void)
{
    ants_payment_terms_t a, b;
    ants_payment_scheme_t ncs = scheme_ncs("default");
    ants_payment_scheme_t stripe = scheme_stripe(300, "USD", "https://pay");
    ants_payment_scheme_t none = scheme_none();
    bool match = true;

    /* a offers {ncs}, b accepts {stripe} → no match. */
    CHECK_EQ(ants_payment_terms_init(&a), ANTS_OK);
    CHECK_EQ(ants_payment_terms_init(&b), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&a, &ncs), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&b, &stripe), ANTS_OK);
    CHECK_EQ(ants_payment_terms_intersects(&a, &b, &match), ANTS_OK);
    CHECK(match == false);

    /* b also accepts ncs → match. */
    CHECK_EQ(ants_payment_terms_add_scheme(&b, &ncs), ANTS_OK);
    CHECK_EQ(ants_payment_terms_intersects(&a, &b, &match), ANTS_OK);
    CHECK(match == true);

    /* Empty vs anything → no match. */
    CHECK_EQ(ants_payment_terms_init(&a), ANTS_OK);
    CHECK_EQ(ants_payment_terms_intersects(&a, &b, &match), ANTS_OK);
    CHECK(match == false);

    /* both have none → match. */
    CHECK_EQ(ants_payment_terms_add_scheme(&a, &none), ANTS_OK);
    CHECK_EQ(ants_payment_terms_init(&b), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&b, &none), ANTS_OK);
    CHECK_EQ(ants_payment_terms_intersects(&a, &b, &match), ANTS_OK);
    CHECK(match == true);

    CHECK_EQ(ants_payment_terms_intersects(NULL, &b, &match), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_intersects(&a, NULL, &match), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_intersects(&a, &b, NULL), ANTS_ERROR_INVALID_ARG);
}

/* ---- round-trip ----------------------------------------------------- */

/* Encode `in`, assert canonical, decode, and compare every field. */
static void round_trip(const ants_payment_terms_t *in)
{
    uint8_t buf[ANTS_PAYMENT_ENCODED_MAX];
    size_t n = 0;
    ants_payment_terms_t out;
    uint32_t i;

    CHECK_EQ(ants_payment_terms_encode(in, buf, sizeof buf, &n), ANTS_OK);
    CHECK(n > 0 && n <= ANTS_PAYMENT_ENCODED_MAX);
    CHECK_EQ(ants_cbor_is_canonical(buf, n), ANTS_OK);

    memset(&out, 0xCC, sizeof out);
    CHECK_EQ(ants_payment_terms_decode(buf, n, &out), ANTS_OK);

    CHECK(out.n_schemes == in->n_schemes);
    CHECK(out.validity_unix_s == in->validity_unix_s);
    CHECK(out.scope == in->scope);
    CHECK(strcmp(out.notes, in->notes) == 0);
    for (i = 0; i < in->n_schemes; i++) {
        CHECK(out.schemes[i].kind == in->schemes[i].kind);
        CHECK(out.schemes[i].amount == in->schemes[i].amount);
        CHECK(strcmp(out.schemes[i].currency, in->schemes[i].currency) == 0);
        CHECK(strcmp(out.schemes[i].ref_a, in->schemes[i].ref_a) == 0);
        CHECK(strcmp(out.schemes[i].ref_b, in->schemes[i].ref_b) == 0);
    }
}

static void test_round_trip_each_kind(void)
{
    ants_payment_terms_t t;
    ants_payment_scheme_t kinds[6];
    int i;
    kinds[0] = scheme_none();
    kinds[1] = scheme_ncs("net-default");
    kinds[2] = scheme_stripe(3, "USD", "https://pay.example/x");
    kinds[3] = scheme_lightning(50, "lnbc1qxyz");
    kinds[4] = scheme_subscription("acme", "pro");
    kinds[5] = scheme_custom("https://schema.example/s.json");

    for (i = 0; i < 6; i++) {
        CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
        CHECK_EQ(ants_payment_terms_add_scheme(&t, &kinds[i]), ANTS_OK);
        t.validity_unix_s = 1700000000ULL + (uint64_t)i;
        t.scope = ANTS_PAYMENT_SCOPE_SESSION;
        snprintf(t.notes, sizeof t.notes, "kind %d notes", i);
        round_trip(&t);
    }
}

static void test_round_trip_multi_scheme(void)
{
    ants_payment_terms_t t;
    ants_payment_scheme_t a = scheme_ncs("default");
    ants_payment_scheme_t b = scheme_stripe(300, "EUR", "https://pay");
    ants_payment_scheme_t c = scheme_lightning(21, "lnbc");
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &a), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &b), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &c), ANTS_OK);
    t.validity_unix_s = 1800000000ULL;
    t.scope = ANTS_PAYMENT_SCOPE_SUBSCRIPTION;
    snprintf(t.notes, sizeof t.notes, "%s", "mixed terms; see https://example/terms");
    round_trip(&t);
}

static void test_round_trip_empty_and_no_notes(void)
{
    ants_payment_terms_t t;
    /* No schemes, empty notes, validity 0 — the minimal object. */
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    round_trip(&t);
}

/* ---- encode contract ------------------------------------------------ */

static void test_encode_invalid_and_null(void)
{
    ants_payment_terms_t t;
    uint8_t buf[ANTS_PAYMENT_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);

    CHECK_EQ(ants_payment_terms_encode(NULL, buf, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_encode(&t, NULL, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_encode(&t, buf, sizeof buf, NULL), ANTS_ERROR_INVALID_ARG);

    /* An object holding an invalid scheme cannot be encoded. */
    t.n_schemes = 1;
    memset(&t.schemes[0], 0, sizeof t.schemes[0]);
    t.schemes[0].kind = ANTS_PAYMENT_SCHEME_NONE;
    t.schemes[0].amount = 7; /* NONE with amount → invalid */
    CHECK_EQ(ants_payment_terms_encode(&t, buf, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
}

static void test_encode_buffer_too_small(void)
{
    ants_payment_terms_t t;
    ants_payment_scheme_t s = scheme_custom("https://schema.example/s.json");
    uint8_t small[8];
    size_t n = 12345;
    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &s), ANTS_OK);
    CHECK_EQ(ants_payment_terms_encode(&t, small, sizeof small, &n), ANTS_ERROR_BUFFER_TOO_SMALL);
}

/* ---- strict decode rejections --------------------------------------- */

static void test_decode_null(void)
{
    uint8_t buf[4] = {0};
    ants_payment_terms_t t;
    CHECK_EQ(ants_payment_terms_decode(NULL, sizeof buf, &t), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_payment_terms_decode(buf, sizeof buf, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_decode_truncation_and_trailing(void)
{
    ants_payment_terms_t t;
    ants_payment_scheme_t s = scheme_stripe(300, "USD", "https://pay.example/abc");
    uint8_t buf[ANTS_PAYMENT_ENCODED_MAX + 1];
    size_t n = 0;
    size_t cut;
    ants_payment_terms_t out;

    CHECK_EQ(ants_payment_terms_init(&t), ANTS_OK);
    CHECK_EQ(ants_payment_terms_add_scheme(&t, &s), ANTS_OK);
    snprintf(t.notes, sizeof t.notes, "%s", "x");
    CHECK_EQ(ants_payment_terms_encode(&t, buf, sizeof buf - 1, &n), ANTS_OK);

    /* Every proper prefix fails. */
    for (cut = 0; cut < n; cut++) {
        ants_error_t rc = ants_payment_terms_decode(buf, cut, &out);
        CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
    }
    /* One trailing byte after a complete object fails. */
    buf[n] = 0x00;
    CHECK_EQ(ants_payment_terms_decode(buf, n + 1, &out), ANTS_ERROR_MALFORMED);
}

static void test_decode_wrong_outer_map_size(void)
{
    /* Encoder writes map(4) = 0xA4. A map(3) header is the wrong shape. */
    uint8_t buf[8] = {0xA3, 0x01};
    ants_payment_terms_t out;
    ants_error_t rc = ants_payment_terms_decode(buf, sizeof buf, &out);
    CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
}

static void test_decode_too_many_schemes(void)
{
    /* map(4), key 1, array(9) — 9 > ANTS_PAYMENT_MAX_SCHEMES (8). The
     * decoder checks the count before reading entries, so the 3-byte
     * prefix suffices to trigger the bound. */
    uint8_t buf[3] = {0xA4, 0x01, 0x89}; /* 0x89 = array(9) */
    ants_payment_terms_t out;
    ants_error_t rc = ants_payment_terms_decode(buf, sizeof buf, &out);
    CHECK(rc == ANTS_ERROR_MALFORMED || rc == ANTS_ERROR_NON_CANONICAL);
}

static void test_decode_scheme_key_mismatch_kind(void)
{
    /* A NONE scheme (kind 0) must be a 1-pair map. Here it carries an
     * extra amount key (map(2): kind=0, amount=5), which does not belong
     * to NONE → MALFORMED.
     * Outer: map(4) key1 array(1) <scheme> key2 0 key3 0 key4 text(0). */
    uint8_t buf[] = {
        0xA4, /* map(4)            */
        0x01,
        0x81, /* key 1, array(1)   */
        0xA2,
        0x01,
        0x00, /*   scheme map(2): key1 kind=0 */
        0x02,
        0x05, /*   key2 amount=5 (illegal for NONE) */
        0x02,
        0x00, /* key 2, validity 0 */
        0x03,
        0x00, /* key 3, scope 0    */
        0x04,
        0x60 /* key 4, notes ""   */
    };
    ants_payment_terms_t out;
    CHECK_EQ(ants_payment_terms_decode(buf, sizeof buf, &out), ANTS_ERROR_MALFORMED);
}

static void test_decode_overlong_text(void)
{
    /* notes text(256) — equals ANTS_PAYMENT_NOTES_MAX, so it cannot hold
     * a NUL and is rejected. Build map(4) key1 array(0) key2 0 key3 0
     * key4 text(256) + 256 payload bytes. */
    uint8_t buf[8 + 3 + 256];
    size_t i;
    ants_payment_terms_t out;
    static const uint8_t prefix[] = {
        0xA4, /* map(4)            */
        0x01,
        0x80, /* key 1, array(0)   */
        0x02,
        0x00, /* key 2, validity 0 */
        0x03,
        0x00, /* key 3, scope 0    */
        0x04  /* key 4 (notes) ... */
    };
    memcpy(buf, prefix, sizeof prefix);
    /* text(256) = 0x79 0x01 0x00 */
    buf[8] = 0x79;
    buf[9] = 0x01;
    buf[10] = 0x00;
    for (i = 0; i < 256; i++) {
        buf[11 + i] = (uint8_t)'a';
    }
    CHECK_EQ(ants_payment_terms_decode(buf, sizeof buf, &out), ANTS_ERROR_MALFORMED);
}

static void test_decode_non_canonical_int(void)
{
    /* The strict CBOR decoder rejects a non-shortest integer; probe the
     * exact codec path the terms decoder uses for keys/uints. */
    uint8_t bad[2] = {0x18, 0x00}; /* 1-byte-extension form of 0 */
    ants_cbor_dec_t d;
    uint64_t v;
    CHECK_EQ(ants_cbor_dec_init(&d, bad, sizeof bad), ANTS_OK);
    CHECK_EQ(ants_cbor_dec_uint(&d, &v), ANTS_ERROR_NON_CANONICAL);
}

int main(void)
{
    test_init_defaults();
    test_scheme_valid_per_kind();
    test_scheme_invalid_cases();
    test_add_scheme();
    test_intersects();

    test_round_trip_each_kind();
    test_round_trip_multi_scheme();
    test_round_trip_empty_and_no_notes();

    test_encode_invalid_and_null();
    test_encode_buffer_too_small();

    test_decode_null();
    test_decode_truncation_and_trailing();
    test_decode_wrong_outer_map_size();
    test_decode_too_many_schemes();
    test_decode_scheme_key_mismatch_kind();
    test_decode_overlong_text();
    test_decode_non_canonical_int();

    if (failures > 0) {
        fprintf(stderr, "test_payment: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_payment: all checks passed\n");
    return 0;
}
