/*
 * ledger.c — Local community-layer economic ledger (Component #14).
 *
 * PR1: the accounting core — per-pair u64 micro-NCS running totals with
 * overflow-checked credits, an on-demand signed net balance, and
 * canonical-CBOR (de)serialisation of one peer record.
 * PR2: the choke / unchoke loop — a windowed generosity score over a
 * recent-receipts ring buffer, and ants_ledger_unchoke_round (rank by
 * generosity*quality, earned slots + a reserved optimistic-unchoke
 * slot). The record + CBOR grow by the recent[] array (key 8).
 *
 * No floats anywhere (RFC-0008 §6). No malloc, no threads, no hidden
 * global state — every entry point operates on caller-allocated records
 * (the loop takes a caller score-scratch buffer, no internal alloc). The
 * CBOR codec helpers mirror the precedent established by
 * inference/orchestration (commit_encode/decode): a strict decoder that
 * folds the codec's error vocabulary onto {NON_CANONICAL, MALFORMED}.
 *
 * Spec: RFC-0001 v0.3 §"The local ledger" + §"The choke / unchoke
 * algorithm"; RFC-0008 v0.5 §6 + §1.1 + §7 (choke constants).
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
/* A definite-length CBOR map of 8 pairs with ascending integer keys 1..8   */
/* in struct-field order, float-free. Keys 1..8 each encode to a single     */
/* byte (0x01..0x08) and so are already in canonical bytewise-ascending     */
/* order. Documented here for byte-for-byte agreement with any independent  */
/* implementation, pending an RFC-0008 §"Ledger record" section.            */
/*                                                                          */
/*   1 peer_id[32]   2 served_to(u64)   3 served_by(u64)                     */
/*   4 since_unix_s(u64)   5 last_update_unix_s(u64)                         */
/*   6 quality_q14k(u16)   7 choked(bool)                                    */
/*   8 recent(array of [unix_s(u64), amount_uncs(u64)], oldest-first)        */
/* ------------------------------------------------------------------------ */

#define LEDGER_CBOR_PAIRS 8

enum {
    LEDGER_KEY_PEER_ID = 1,
    LEDGER_KEY_SERVED_TO = 2,
    LEDGER_KEY_SERVED_BY = 3,
    LEDGER_KEY_SINCE = 4,
    LEDGER_KEY_LAST_UPDATE = 5,
    LEDGER_KEY_QUALITY = 6,
    LEDGER_KEY_CHOKED = 7,
    LEDGER_KEY_RECENT = 8
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
/* Choke / unchoke loop                                                     */
/* ------------------------------------------------------------------------ */

/* Saturating u64 add / multiply: used for the generosity sum and the
 * generosity*quality ranking score. Saturation is a guard against
 * pathological inputs (real 20-minute sums sit far below UINT64_MAX); it
 * preserves ordering everywhere the product fits, which is the only
 * property the ranking needs. */
static uint64_t sat_add_u64(uint64_t a, uint64_t b)
{
    if (a > UINT64_MAX - b) {
        return UINT64_MAX;
    }
    return a + b;
}

static uint64_t sat_mul_u64(uint64_t a, uint64_t b)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return UINT64_MAX;
    }
    return a * b;
}

/* Push a receipt sample into the ring buffer (head = next write). */
static void recent_push(ants_ledger_peer_t *rec, uint64_t now_unix_s, uint64_t amount_uncs)
{
    uint32_t cap = ANTS_LEDGER_RECENT_SAMPLES;
    rec->recent[rec->recent_head].unix_s = now_unix_s;
    rec->recent[rec->recent_head].amount_uncs = amount_uncs;
    rec->recent_head = (rec->recent_head + 1u) % cap;
    if (rec->recent_count < cap) {
        rec->recent_count++;
    }
}

ants_error_t
ants_ledger_record_recv(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s)
{
    ants_error_t rc;
    if (rec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Credit the cumulative total first; on overflow the record is left
     * unchanged and we push no sample (RFC-0008 §6). */
    rc = credit(rec, &rec->served_by, amount_uncs, now_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    recent_push(rec, now_unix_s, amount_uncs);
    return ANTS_OK;
}

ants_error_t ants_ledger_generosity(const ants_ledger_peer_t *rec,
                                    uint64_t now_unix_s,
                                    uint64_t window_s,
                                    uint64_t *out_uncs)
{
    uint64_t sum = 0;
    uint32_t k;

    if (rec == NULL || out_uncs == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    for (k = 0; k < rec->recent_count; k++) {
        const ants_ledger_recv_sample_t *s = &rec->recent[k];
        /* In window iff sample.unix_s + window_s >= now_unix_s, computed
         * without overflow. unix_s == 0 (clockless) is always in window.
         * now <= window means everything is in window. */
        bool in_window;
        if (s->unix_s == 0 || now_unix_s <= window_s) {
            in_window = true;
        } else {
            /* now - window is the cutoff; sample is in if unix_s >= cutoff. */
            in_window = (s->unix_s >= now_unix_s - window_s);
        }
        if (in_window) {
            sum = sat_add_u64(sum, s->amount_uncs);
        }
    }
    *out_uncs = sum;
    return ANTS_OK;
}

/* Rank score for one record: generosity over the window, weighted by the
 * quality multiplier. quality_q14k in [0,10000]; the product is the sort
 * key (no divide — ordering is preserved, and dividing would only lose
 * precision). */
static uint64_t unchoke_score(const ants_ledger_peer_t *rec, uint64_t now_unix_s, uint64_t window_s)
{
    uint64_t gen = 0;
    (void)ants_ledger_generosity(rec, now_unix_s, window_s, &gen);
    return sat_mul_u64(gen, (uint64_t)rec->quality_q14k);
}

/* Strict ranking comparison: is record `i` ranked ABOVE record `j`?
 * Higher score wins; ties break by peer_id bytewise-ascending (a total,
 * deterministic, unbiased order). */
static bool
ranks_above(const ants_ledger_peer_t *records, const uint64_t *scores, size_t i, size_t j)
{
    if (scores[i] != scores[j]) {
        return scores[i] > scores[j];
    }
    return memcmp(records[i].peer_id, records[j].peer_id, ANTS_LEDGER_PEER_ID_SIZE) < 0;
}

ants_error_t ants_ledger_unchoke_round(ants_ledger_peer_t *records,
                                       size_t n_records,
                                       uint64_t now_unix_s,
                                       uint64_t window_s,
                                       uint32_t slots,
                                       uint64_t rotation,
                                       uint64_t *score_scratch,
                                       size_t scratch_len)
{
    size_t i, j;
    uint32_t optimistic, earned;
    size_t still_choked;
    uint64_t opt_taken;

    if (n_records == 0) {
        return ANTS_OK;
    }
    if (records == NULL || score_scratch == NULL || scratch_len < n_records) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Slot split: reserve 1/DIVISOR (>=1) for optimistic unchoke, the
     * rest are earned. slots == 0 chokes everyone. */
    if (slots == 0) {
        for (i = 0; i < n_records; i++) {
            records[i].choked = true;
        }
        return ANTS_OK;
    }
    optimistic = slots / ANTS_LEDGER_OPTIMISTIC_UNCHOKE_DIVISOR;
    if (optimistic == 0) {
        optimistic = 1;
    }
    earned = (optimistic >= slots) ? 0 : (slots - optimistic);

    /* Score every record once into the caller scratch. */
    for (i = 0; i < n_records; i++) {
        score_scratch[i] = unchoke_score(&records[i], now_unix_s, window_s);
    }

    /* Earned slots: a record is earned-unchoked iff strictly fewer than
     * `earned` other records rank above it (rank-counting, no sort, no
     * extra scratch). Everything starts choked. */
    for (i = 0; i < n_records; i++) {
        uint32_t above = 0;
        bool earned_unchoked;
        records[i].choked = true;
        if (earned == 0) {
            continue;
        }
        for (j = 0; j < n_records; j++) {
            if (j != i && ranks_above(records, score_scratch, j, i)) {
                above++;
                if (above >= earned) {
                    break;
                }
            }
        }
        earned_unchoked = (above < earned);
        if (earned_unchoked) {
            records[i].choked = false;
        }
    }

    /* Optimistic slots: among the still-choked records, pick `optimistic`
     * of them round-robin starting at rotation % still_choked. This is
     * the deterministic, RNG-free stand-in for the reference impl's
     * random optimistic pick. */
    still_choked = 0;
    for (i = 0; i < n_records; i++) {
        if (records[i].choked) {
            still_choked++;
        }
    }
    if (still_choked == 0 || optimistic == 0) {
        return ANTS_OK;
    }

    {
        size_t start = (size_t)(rotation % (uint64_t)still_choked);
        size_t seen = 0;
        opt_taken = 0;
        /* Walk the still-choked records in index order; unchoke those at
         * logical positions [start, start+optimistic) modulo the count. */
        for (i = 0; i < n_records && opt_taken < optimistic; i++) {
            if (!records[i].choked) {
                continue;
            }
            /* `seen` is this choked record's logical position. It is in
             * the optimistic window if (seen - start) mod still_choked
             * < optimistic. */
            {
                size_t rel = (seen + still_choked - start) % still_choked;
                if (rel < optimistic) {
                    records[i].choked = false;
                    opt_taken++;
                }
            }
            seen++;
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

    /* key 8: recent receipts, normalised oldest-first (the ring head is
     * not serialised, so the bytes are canonical regardless of where the
     * head sits internally). */
    rc = ants_cbor_enc_uint(&enc, LEDGER_KEY_RECENT);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_array(&enc, rec->recent_count);
    if (rc != ANTS_OK) {
        return rc;
    }
    {
        uint32_t ring_cap = ANTS_LEDGER_RECENT_SAMPLES;
        uint32_t oldest = (rec->recent_head + ring_cap - rec->recent_count) % ring_cap;
        uint32_t k;
        for (k = 0; k < rec->recent_count; k++) {
            uint32_t idx = (oldest + k) % ring_cap;
            rc = ants_cbor_enc_array(&enc, 2);
            if (rc != ANTS_OK) {
                return rc;
            }
            rc = ants_cbor_enc_uint(&enc, rec->recent[idx].unix_s);
            if (rc != ANTS_OK) {
                return rc;
            }
            rc = ants_cbor_enc_uint(&enc, rec->recent[idx].amount_uncs);
            if (rc != ANTS_OK) {
                return rc;
            }
        }
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

    /* key 8: recent receipts array, oldest-first. Rebuilds the ring with
     * recent_count samples at indices [0, recent_count). */
    rc = expect_key(&dec, LEDGER_KEY_RECENT);
    if (rc != ANTS_OK) {
        return rc;
    }
    {
        size_t n_recent = 0;
        size_t k;
        rc = norm_decode_err(ants_cbor_dec_array(&dec, &n_recent));
        if (rc != ANTS_OK) {
            return rc;
        }
        if (n_recent > ANTS_LEDGER_RECENT_SAMPLES) {
            return ANTS_ERROR_MALFORMED; /* would not fit the ring buffer */
        }
        for (k = 0; k < n_recent; k++) {
            size_t two = 0;
            uint64_t ts = 0;
            uint64_t amt = 0;
            rc = norm_decode_err(ants_cbor_dec_array(&dec, &two));
            if (rc != ANTS_OK) {
                return rc;
            }
            if (two != 2) {
                return ANTS_ERROR_MALFORMED;
            }
            rc = norm_decode_err(ants_cbor_dec_uint(&dec, &ts));
            if (rc != ANTS_OK) {
                return rc;
            }
            rc = norm_decode_err(ants_cbor_dec_uint(&dec, &amt));
            if (rc != ANTS_OK) {
                return rc;
            }
            rec->recent[k].unix_s = ts;
            rec->recent[k].amount_uncs = amt;
        }
        rec->recent_count = (uint32_t)n_recent;
        rec->recent_head = (n_recent == ANTS_LEDGER_RECENT_SAMPLES) ? 0u : (uint32_t)n_recent;
    }

    /* Reject trailing bytes / unclosed container (closes the strict
     * contract — a permissive tail would be hash-malleable). */
    return norm_decode_err(ants_cbor_dec_finalise(&dec));
}
