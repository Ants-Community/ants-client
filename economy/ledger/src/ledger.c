/*
 * ledger.c — Local community-layer economic ledger (Component #14).
 *
 * PR1: the accounting core. Per-pair u64 micro-NCS running totals with
 * overflow-checked credits, an on-demand signed net balance, and
 * canonical-CBOR (de)serialisation of one peer record.
 *
 * No floats anywhere (RFC-0008 §6). No malloc, no threads, no hidden
 * global state — every entry point operates on a caller-allocated
 * record. The CBOR codec helpers mirror the precedent established by
 * inference/orchestration (commit_encode/decode): a strict decoder that
 * folds the codec's error vocabulary onto {NON_CANONICAL, MALFORMED}.
 *
 * Spec: RFC-0001 v0.3 §"The local ledger"; RFC-0008 v0.5 §6 + §1.1.
 */

#include "ants_ledger.h"

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Canonical CBOR record schema (DRAFT, defined by this PR)                  */
/*                                                                          */
/* A definite-length CBOR map of 7 pairs with ascending integer keys 1..7   */
/* in struct-field order, float-free. Keys 1..7 each encode to a single     */
/* byte (0x01..0x07) and so are already in canonical bytewise-ascending     */
/* order. Documented here for byte-for-byte agreement with any independent  */
/* implementation, pending an RFC-0008 §"Ledger record" section.            */
/*                                                                          */
/*   1 peer_id[32]   2 served_to(u64)   3 served_by(u64)                     */
/*   4 since_unix_s(u64)   5 last_update_unix_s(u64)                         */
/*   6 quality_q14k(u16)   7 choked(bool)                                    */
/* ------------------------------------------------------------------------ */

#define LEDGER_CBOR_PAIRS 7

enum {
    LEDGER_KEY_PEER_ID = 1,
    LEDGER_KEY_SERVED_TO = 2,
    LEDGER_KEY_SERVED_BY = 3,
    LEDGER_KEY_SINCE = 4,
    LEDGER_KEY_LAST_UPDATE = 5,
    LEDGER_KEY_QUALITY = 6,
    LEDGER_KEY_CHOKED = 7
};

/* Quality fixed-point scale: 10000 == 1.0 (verified-correct rate). */
#define LEDGER_QUALITY_ONE 10000u

/* ------------------------------------------------------------------------ */
/* Record lifecycle + accounting                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_ledger_peer_init(ants_ledger_peer_t *rec,
                                   const uint8_t peer_id[ANTS_LEDGER_PEER_ID_SIZE],
                                   uint64_t now_unix_s)
{
    if (rec == NULL || peer_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(rec, 0, sizeof *rec);
    memcpy(rec->peer_id, peer_id, ANTS_LEDGER_PEER_ID_SIZE);
    rec->served_to = 0;
    rec->served_by = 0;
    rec->since_unix_s = now_unix_s;
    rec->last_update_unix_s = now_unix_s;
    rec->quality_q14k = (uint16_t)LEDGER_QUALITY_ONE; /* 1.0 at the start */
    rec->choked = true;                               /* RFC-0001 cold start */
    return ANTS_OK;
}

/* Shared overflow-checked add of `amount` into `*total`, stamping
 * last_update on success. The record is left UNCHANGED on overflow
 * (RFC-0008 §6: the transaction is rejected). */
static ants_error_t
credit(ants_ledger_peer_t *rec, uint64_t *total, uint64_t amount, uint64_t now_unix_s)
{
    if (rec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (amount > UINT64_MAX - *total) {
        return ANTS_ERROR_OVERFLOW; /* reject; *total unchanged */
    }
    *total += amount;
    if (now_unix_s != 0) {
        rec->last_update_unix_s = now_unix_s;
    }
    return ANTS_OK;
}

ants_error_t
ants_ledger_credit_served_to(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s)
{
    if (rec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return credit(rec, &rec->served_to, amount_uncs, now_unix_s);
}

ants_error_t
ants_ledger_credit_served_by(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s)
{
    if (rec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return credit(rec, &rec->served_by, amount_uncs, now_unix_s);
}

ants_error_t ants_ledger_net_balance(const ants_ledger_peer_t *rec, int64_t *out_net)
{
    if (rec == NULL || out_net == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (rec->served_to >= rec->served_by) {
        /* Non-negative result: magnitude must fit INT64_MAX. */
        uint64_t d = rec->served_to - rec->served_by;
        if (d > (uint64_t)INT64_MAX) {
            return ANTS_ERROR_OVERFLOW;
        }
        *out_net = (int64_t)d;
    } else {
        /* Negative result of magnitude d. INT64_MIN has magnitude
         * 2^63 == (uint64_t)INT64_MAX + 1, which IS representable; one
         * more than that is not. Handle the boundary without the UB of
         * casting 2^63 through a signed int64. */
        uint64_t d = rec->served_by - rec->served_to;
        if (d > (uint64_t)INT64_MAX + 1u) {
            return ANTS_ERROR_OVERFLOW;
        }
        if (d == (uint64_t)INT64_MAX + 1u) {
            *out_net = INT64_MIN;
        } else {
            *out_net = -(int64_t)d;
        }
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Encode helpers (mirror inference/orchestration precedent)                */
/* ------------------------------------------------------------------------ */

static ants_error_t enc_kv_bytes(ants_cbor_enc_t *enc, uint64_t key, const uint8_t *b, size_t len)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bytes(enc, b, len);
}

static ants_error_t enc_kv_uint(ants_cbor_enc_t *enc, uint64_t key, uint64_t val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_uint(enc, val);
}

static ants_error_t enc_kv_bool(ants_cbor_enc_t *enc, uint64_t key, bool val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bool(enc, val);
}

ants_error_t
ants_ledger_record_encode(const ants_ledger_peer_t *rec, uint8_t *buf, size_t cap, size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (rec == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, LEDGER_CBOR_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, LEDGER_KEY_PEER_ID, rec->peer_id, sizeof rec->peer_id);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, LEDGER_KEY_SERVED_TO, rec->served_to);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, LEDGER_KEY_SERVED_BY, rec->served_by);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, LEDGER_KEY_SINCE, rec->since_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, LEDGER_KEY_LAST_UPDATE, rec->last_update_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, LEDGER_KEY_QUALITY, rec->quality_q14k);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bool(&enc, LEDGER_KEY_CHOKED, rec->choked);
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
/* Decode helpers (mirror inference/orchestration precedent)                */
/* ------------------------------------------------------------------------ */

/* Collapse the decoder's full error vocabulary onto the record_decode
 * contract: a §4.2.1 canonical violation keeps its NON_CANONICAL
 * identity; everything else (wrong major type, truncation, etc.) is
 * structural framing damage and folds into MALFORMED. INVALID_ARG
 * cannot occur here — the decoder only raises it for NULL arguments,
 * which this path never passes. */
static ants_error_t norm_decode_err(ants_error_t rc)
{
    if (rc == ANTS_OK || rc == ANTS_ERROR_NON_CANONICAL) {
        return rc;
    }
    return ANTS_ERROR_MALFORMED;
}

/* Read the next map key and require it to equal `want`. The keys are
 * fixed and ascending, so a mismatch is a structural error; a canonical-
 * order violation surfaces as NON_CANONICAL straight from the decoder. */
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

static ants_error_t
decode_bytes_field(ants_cbor_dec_t *dec, uint64_t key, uint8_t *dst, size_t want)
{
    const uint8_t *p;
    size_t len;
    ants_error_t rc;

    rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_bytes(dec, &p, &len));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (len != want) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(dst, p, want);
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

static ants_error_t decode_bool_field(ants_cbor_dec_t *dec, uint64_t key, bool *out)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_bool(dec, out));
}

ants_error_t ants_ledger_record_decode(const uint8_t *buf, size_t len, ants_ledger_peer_t *rec)
{
    ants_cbor_dec_t dec;
    size_t n_pairs = 0;
    uint64_t u;
    ants_error_t rc;

    if (buf == NULL || rec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = norm_decode_err(ants_cbor_dec_init(&dec, buf, len));
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != LEDGER_CBOR_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }

    rc = decode_bytes_field(&dec, LEDGER_KEY_PEER_ID, rec->peer_id, sizeof rec->peer_id);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, LEDGER_KEY_SERVED_TO, &rec->served_to);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, LEDGER_KEY_SERVED_BY, &rec->served_by);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, LEDGER_KEY_SINCE, &rec->since_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, LEDGER_KEY_LAST_UPDATE, &rec->last_update_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    /* quality is u16-bounded; the decoder yields u64, range-check before
     * narrowing (an out-of-range value is malformed for this schema). */
    rc = decode_uint_field(&dec, LEDGER_KEY_QUALITY, &u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (u > UINT16_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    rec->quality_q14k = (uint16_t)u;

    rc = decode_bool_field(&dec, LEDGER_KEY_CHOKED, &rec->choked);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* Reject trailing bytes / unclosed container (closes the strict
     * contract — a permissive tail would be hash-malleable). */
    return norm_decode_err(ants_cbor_dec_finalise(&dec));
}
