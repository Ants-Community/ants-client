/*
 * payment.c — Payment-terms advertisement object (Component #14,
 * RFC-0006 Payment Terms & Economic Pluralism).
 *
 * PR3 of Component #14: the payment_terms object + canonical-CBOR
 * (de)serialisation + structural validation. The requester's
 * candidate-ranking / scheme-matching policy, cross-economy cache
 * settlement, and the fiat-NCS gateway are out of scope (RFC-0006 v0.1
 * leaves them open).
 *
 * No floats (RFC-0008 §1.3 / §6), no malloc, no threads, no hidden global
 * state. The CBOR codec helpers mirror the ledger / inference-orchestration
 * precedent: a strict decoder that folds the codec's error vocabulary onto
 * {NON_CANONICAL, MALFORMED}.
 *
 * Spec: RFC-0006 v0.1 §"The payment_terms field"; RFC-0008 v0.5 §1.1.
 */

#include "ants_payment.h"

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Per-kind field set                                                       */
/*                                                                          */
/* Each scheme map always carries key 1 (kind); the remaining keys present  */
/* depend on the kind. The mask drives BOTH encode and decode so they stay  */
/* in lockstep — the decoder rejects any scheme whose key set does not      */
/* match its kind. Keys, ascending: 2 amount, 3 currency, 4 ref_a, 5 ref_b. */
/* ------------------------------------------------------------------------ */

#define F_AMOUNT   0x1u
#define F_CURRENCY 0x2u
#define F_REF_A    0x4u
#define F_REF_B    0x8u

enum {
    PAY_KEY_KIND = 1,
    PAY_KEY_AMOUNT = 2,
    PAY_KEY_CURRENCY = 3,
    PAY_KEY_REF_A = 4,
    PAY_KEY_REF_B = 5
};

/* Outer payment_terms map keys (ascending). */
enum { PAY_KEY_SCHEMES = 1, PAY_KEY_VALIDITY = 2, PAY_KEY_SCOPE = 3, PAY_KEY_NOTES = 4 };
#define PAY_TERMS_PAIRS 4

static bool kind_valid(ants_payment_scheme_kind_t kind)
{
    return (unsigned)kind <= (unsigned)ANTS_PAYMENT_SCHEME_CUSTOM;
}

/* Which optional fields (amount/currency/ref_a/ref_b) a kind carries.
 * Returns 0 for NONE and for any out-of-range kind (callers check
 * kind_valid separately). */
static unsigned scheme_field_mask(ants_payment_scheme_kind_t kind)
{
    switch (kind) {
    case ANTS_PAYMENT_SCHEME_NONE:
        return 0;
    case ANTS_PAYMENT_SCHEME_NCS:
        return F_REF_A; /* rate_table reference */
    case ANTS_PAYMENT_SCHEME_FIAT_STRIPE:
        return F_AMOUNT | F_CURRENCY | F_REF_A; /* rate, currency, endpoint */
    case ANTS_PAYMENT_SCHEME_FIAT_LIGHTNING:
        return F_AMOUNT | F_REF_A; /* sats/unit, invoice address */
    case ANTS_PAYMENT_SCHEME_SUBSCRIPTION:
        return F_REF_A | F_REF_B; /* provider, plan id */
    case ANTS_PAYMENT_SCHEME_CUSTOM:
        return F_REF_A; /* schema URI */
    default:
        return 0;
    }
}

/* CBOR map-pair count for a scheme: kind + one per present field. */
static size_t scheme_pairs(unsigned mask)
{
    size_t n = 1; /* kind */
    if (mask & F_AMOUNT) {
        n++;
    }
    if (mask & F_CURRENCY) {
        n++;
    }
    if (mask & F_REF_A) {
        n++;
    }
    if (mask & F_REF_B) {
        n++;
    }
    return n;
}

/* A char buffer is a usable C string iff it contains a NUL within cap. */
static bool field_terminated(const char *s, size_t cap)
{
    return memchr(s, 0, cap) != NULL;
}

/* ------------------------------------------------------------------------ */
/* Validation                                                               */
/* ------------------------------------------------------------------------ */

bool ants_payment_scheme_valid(const ants_payment_scheme_t *scheme)
{
    unsigned mask;

    if (scheme == NULL) {
        return false;
    }
    if (!kind_valid(scheme->kind)) {
        return false;
    }
    /* Every text field must be NUL-terminated within its buffer. */
    if (!field_terminated(scheme->currency, ANTS_PAYMENT_CURRENCY_MAX) ||
        !field_terminated(scheme->ref_a, ANTS_PAYMENT_REF_MAX) ||
        !field_terminated(scheme->ref_b, ANTS_PAYMENT_REF_MAX)) {
        return false;
    }

    mask = scheme_field_mask(scheme->kind);

    /* Fields not part of this kind must be empty/zero — this fixes the
     * scheme's canonical shape (the encoder emits only the kind's fields,
     * so junk in a forbidden field would be silently dropped on a
     * round-trip; rejecting it up front prevents that surprise). */
    if (!(mask & F_AMOUNT) && scheme->amount != 0) {
        return false;
    }
    if (!(mask & F_CURRENCY) && scheme->currency[0] != '\0') {
        return false;
    }
    if (!(mask & F_REF_A) && scheme->ref_a[0] != '\0') {
        return false;
    }
    if (!(mask & F_REF_B) && scheme->ref_b[0] != '\0') {
        return false;
    }

    /* A fiat-Stripe quote without a currency is meaningless (RFC-0006
     * §"Standard schemes": fiat_stripe { currency, rate_per_unit, key }). */
    if (scheme->kind == ANTS_PAYMENT_SCHEME_FIAT_STRIPE && scheme->currency[0] == '\0') {
        return false;
    }

    return true;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_payment_terms_init(ants_payment_terms_t *terms)
{
    if (terms == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(terms, 0, sizeof *terms);
    terms->n_schemes = 0;
    terms->validity_unix_s = 0;
    terms->scope = ANTS_PAYMENT_SCOPE_PER_QUERY;
    terms->notes[0] = '\0';
    return ANTS_OK;
}

ants_error_t ants_payment_terms_add_scheme(ants_payment_terms_t *terms,
                                           const ants_payment_scheme_t *scheme)
{
    if (terms == NULL || scheme == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!ants_payment_scheme_valid(scheme)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (terms->n_schemes >= ANTS_PAYMENT_MAX_SCHEMES) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    terms->schemes[terms->n_schemes] = *scheme;
    terms->n_schemes++;
    return ANTS_OK;
}

ants_error_t ants_payment_terms_intersects(const ants_payment_terms_t *a,
                                           const ants_payment_terms_t *b,
                                           bool *out_match)
{
    uint32_t i, j;

    if (a == NULL || b == NULL || out_match == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_match = false;
    for (i = 0; i < a->n_schemes; i++) {
        for (j = 0; j < b->n_schemes; j++) {
            if (a->schemes[i].kind == b->schemes[j].kind) {
                *out_match = true;
                return ANTS_OK;
            }
        }
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Encode helpers (mirror ledger / orchestration precedent)                 */
/* ------------------------------------------------------------------------ */

static ants_error_t enc_kv_uint(ants_cbor_enc_t *enc, uint64_t key, uint64_t val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_uint(enc, val);
}

static ants_error_t enc_kv_text(ants_cbor_enc_t *enc, uint64_t key, const char *s)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_text(enc, s, strlen(s));
}

static ants_error_t enc_scheme(ants_cbor_enc_t *enc, const ants_payment_scheme_t *s)
{
    unsigned mask = scheme_field_mask(s->kind);
    ants_error_t rc;

    rc = ants_cbor_enc_map(enc, scheme_pairs(mask));
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(enc, PAY_KEY_KIND, (uint64_t)s->kind);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (mask & F_AMOUNT) {
        rc = enc_kv_uint(enc, PAY_KEY_AMOUNT, s->amount);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_CURRENCY) {
        rc = enc_kv_text(enc, PAY_KEY_CURRENCY, s->currency);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_REF_A) {
        rc = enc_kv_text(enc, PAY_KEY_REF_A, s->ref_a);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_REF_B) {
        rc = enc_kv_text(enc, PAY_KEY_REF_B, s->ref_b);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    return ANTS_OK;
}

ants_error_t ants_payment_terms_encode(const ants_payment_terms_t *terms,
                                       uint8_t *buf,
                                       size_t cap,
                                       size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;
    uint32_t i;

    if (terms == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* The object must be valid before it can be canonically encoded. */
    if (terms->n_schemes > ANTS_PAYMENT_MAX_SCHEMES) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((unsigned)terms->scope > (unsigned)ANTS_PAYMENT_SCOPE_SUBSCRIPTION) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!field_terminated(terms->notes, ANTS_PAYMENT_NOTES_MAX)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (i = 0; i < terms->n_schemes; i++) {
        if (!ants_payment_scheme_valid(&terms->schemes[i])) {
            return ANTS_ERROR_INVALID_ARG;
        }
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, PAY_TERMS_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* key 1: schemes array */
    rc = ants_cbor_enc_uint(&enc, PAY_KEY_SCHEMES);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_array(&enc, terms->n_schemes);
    if (rc != ANTS_OK) {
        return rc;
    }
    for (i = 0; i < terms->n_schemes; i++) {
        rc = enc_scheme(&enc, &terms->schemes[i]);
        if (rc != ANTS_OK) {
            return rc;
        }
    }

    /* key 2: validity, key 3: scope, key 4: notes */
    rc = enc_kv_uint(&enc, PAY_KEY_VALIDITY, terms->validity_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, PAY_KEY_SCOPE, (uint64_t)terms->scope);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_text(&enc, PAY_KEY_NOTES, terms->notes);
    if (rc != ANTS_OK) {
        return rc;
    }

    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Decode helpers (mirror ledger / orchestration precedent)                 */
/* ------------------------------------------------------------------------ */

static ants_error_t norm_decode_err(ants_error_t rc)
{
    if (rc == ANTS_OK || rc == ANTS_ERROR_NON_CANONICAL) {
        return rc;
    }
    return ANTS_ERROR_MALFORMED;
}

static ants_error_t expect_key(ants_cbor_dec_t *dec, uint64_t want)
{
    uint64_t key;
    ants_error_t rc = norm_decode_err(ants_cbor_dec_uint(dec, &key));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (key != want) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

static ants_error_t decode_uint_field(ants_cbor_dec_t *dec, uint64_t key, uint64_t *out)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_uint(dec, out));
}

/* Decode a text field (already past its key) into a bounded buffer. An
 * input that does not leave room for the NUL is malformed. */
static ants_error_t decode_text_into(ants_cbor_dec_t *dec, char *dst, size_t cap)
{
    const char *p;
    size_t len;
    ants_error_t rc = norm_decode_err(ants_cbor_dec_text(dec, &p, &len));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (len >= cap) {
        return ANTS_ERROR_MALFORMED;
    }
    if (len > 0) {
        memcpy(dst, p, len);
    }
    dst[len] = '\0';
    return ANTS_OK;
}

static ants_error_t decode_text_field(ants_cbor_dec_t *dec, uint64_t key, char *dst, size_t cap)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return decode_text_into(dec, dst, cap);
}

static ants_error_t decode_scheme(ants_cbor_dec_t *dec, ants_payment_scheme_t *s)
{
    size_t n_pairs = 0;
    uint64_t kind_u = 0;
    unsigned mask;
    ants_error_t rc;

    memset(s, 0, sizeof *s);

    rc = norm_decode_err(ants_cbor_dec_map(dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    /* key 1: kind (always first, ascending). */
    rc = decode_uint_field(dec, PAY_KEY_KIND, &kind_u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (kind_u > (uint64_t)ANTS_PAYMENT_SCHEME_CUSTOM) {
        return ANTS_ERROR_MALFORMED;
    }
    s->kind = (ants_payment_scheme_kind_t)kind_u;
    mask = scheme_field_mask(s->kind);

    /* The map must hold exactly kind + the kind's fields — no missing, no
     * extra (a key belonging to another kind would also trip this). */
    if (n_pairs != scheme_pairs(mask)) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Read present fields in ascending key order; expect_key enforces the
     * order and exact key, so a scheme carrying a wrong-kind key fails. */
    if (mask & F_AMOUNT) {
        rc = decode_uint_field(dec, PAY_KEY_AMOUNT, &s->amount);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_CURRENCY) {
        rc = decode_text_field(dec, PAY_KEY_CURRENCY, s->currency, ANTS_PAYMENT_CURRENCY_MAX);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_REF_A) {
        rc = decode_text_field(dec, PAY_KEY_REF_A, s->ref_a, ANTS_PAYMENT_REF_MAX);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    if (mask & F_REF_B) {
        rc = decode_text_field(dec, PAY_KEY_REF_B, s->ref_b, ANTS_PAYMENT_REF_MAX);
        if (rc != ANTS_OK) {
            return rc;
        }
    }

    /* Final invariant: the decoded scheme must be structurally valid
     * (e.g. a Stripe scheme decoded with an empty currency is rejected). */
    if (!ants_payment_scheme_valid(s)) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

ants_error_t ants_payment_terms_decode(const uint8_t *buf, size_t len, ants_payment_terms_t *terms)
{
    ants_cbor_dec_t dec;
    size_t n_pairs = 0;
    size_t n_schemes = 0;
    size_t i;
    uint64_t validity = 0;
    uint64_t scope_u = 0;
    ants_error_t rc;

    if (buf == NULL || terms == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(terms, 0, sizeof *terms);

    rc = norm_decode_err(ants_cbor_dec_init(&dec, buf, len));
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != PAY_TERMS_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }

    /* key 1: schemes array */
    rc = expect_key(&dec, PAY_KEY_SCHEMES);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_array(&dec, &n_schemes));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_schemes > ANTS_PAYMENT_MAX_SCHEMES) {
        return ANTS_ERROR_MALFORMED;
    }
    for (i = 0; i < n_schemes; i++) {
        rc = decode_scheme(&dec, &terms->schemes[i]);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    terms->n_schemes = (uint32_t)n_schemes;

    /* key 2: validity */
    rc = decode_uint_field(&dec, PAY_KEY_VALIDITY, &validity);
    if (rc != ANTS_OK) {
        return rc;
    }
    terms->validity_unix_s = validity;

    /* key 3: scope (range-checked before narrowing to the enum) */
    rc = decode_uint_field(&dec, PAY_KEY_SCOPE, &scope_u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (scope_u > (uint64_t)ANTS_PAYMENT_SCOPE_SUBSCRIPTION) {
        return ANTS_ERROR_MALFORMED;
    }
    terms->scope = (ants_payment_scope_t)scope_u;

    /* key 4: notes */
    rc = decode_text_field(&dec, PAY_KEY_NOTES, terms->notes, ANTS_PAYMENT_NOTES_MAX);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* Reject trailing bytes / unclosed containers (strict contract). */
    return norm_decode_err(ants_cbor_dec_finalise(&dec));
}
