/*
 * reputation.c — The (A, T, κ) reputation spine (Component #9,
 * RFC-0004 §"Tenure: the (A, T, κ) spine" + §"Computing A" + reference
 * sketch §1392).
 *
 * PR1: the spine — the countersigned NCS receipt (canonical-CBOR body +
 * dual Ed25519 verification), the deterministic fixed-point decay
 * primitive (the spec-mandated alternative to non-deterministic float
 * exp(), RFC-0004 §"A reference sketch"), and the A / T computation from
 * a receipt bag.
 *
 * No floats anywhere — decay is pinned q32 fixed-point integer
 * arithmetic. No malloc, no threads, no hidden global state; the only
 * scratch is a stack bool array sized to ANTS_REP_MAX_RECEIPTS caching
 * per-receipt validity so signatures are verified exactly once.
 *
 * Spec: RFC-0004 v0.6; RFC-0008 v0.5 §1.1 (canonical CBOR) + §6 (NCS).
 */

#include "ants_reputation.h"

#include "ants_cbor.h"
#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Canonical CBOR receipt-body schema (DRAFT, defined by this PR)            */
/*                                                                          */
/* The signed body is a definite-length map of 5 integer-keyed pairs in     */
/* ascending key order (keys 1..5 each a single byte, so already canonical) */
/*   1 server(bytes32) 2 client(bytes32) 3 ncs_value(u64)                    */
/*   4 timestamp(u64)  5 nonce(bytes16)                                       */
/* Float-free. Both signatures are computed over exactly these bytes.        */
/* ------------------------------------------------------------------------ */

#define REP_BODY_PAIRS 5

enum {
    REP_KEY_SERVER = 1,
    REP_KEY_CLIENT = 2,
    REP_KEY_NCS = 3,
    REP_KEY_TIMESTAMP = 4,
    REP_KEY_NONCE = 5
};

/* ------------------------------------------------------------------------ */
/* Saturating helpers                                                       */
/* ------------------------------------------------------------------------ */

static uint64_t sat_add_u64(uint64_t a, uint64_t b)
{
    if (a > UINT64_MAX - b) {
        return UINT64_MAX;
    }
    return a + b;
}

/* ------------------------------------------------------------------------ */
/* Fixed-point decay primitive (deterministic, no float)                    */
/* ------------------------------------------------------------------------ */

uint64_t ants_reputation_fp_mul(uint64_t a_q32, uint64_t b_q32)
{
    /* 1.0 · x = x — also keeps the product strictly below 2^64 (the only
     * way to reach 2^32 · 2^32 is both == 1.0, handled here). */
    if (a_q32 >= ANTS_REP_FP_ONE) {
        return b_q32;
    }
    if (b_q32 >= ANTS_REP_FP_ONE) {
        return a_q32;
    }
    /* both < 2^32 → product < 2^64, exact. */
    return (a_q32 * b_q32) >> ANTS_REP_FP_BITS;
}

uint64_t ants_reputation_decay_factor(uint64_t ratio_q32, uint64_t age_bins)
{
    uint64_t acc = ANTS_REP_FP_ONE;
    uint64_t k;

    /* No decay (ratio >= 1.0) or zero age → factor is exactly 1.0. */
    if (ratio_q32 >= ANTS_REP_FP_ONE || age_bins == 0) {
        return ANTS_REP_FP_ONE;
    }

    /* The pinned canonical recipe is REPEATED MULTIPLICATION: factor =
     * fp_mul(fp_mul(... fp_mul(1.0, r) ...), r), k times. q32 multiply
     * truncates and is therefore NOT associative, so the recipe must be
     * a single fixed sequence — square-and-multiply would give a
     * different (also-valid-looking) bit result and break cross-peer
     * agreement. Repeated multiplication is the natural "apply the
     * per-bin decay once per elapsed bin" definition and the one every
     * peer runs. The zero short-circuit bounds the loop: once the factor
     * underflows to 0 (after at most ~2200 bins for the slowest realistic
     * ratio) it stays 0, so age cannot drive unbounded work. */
    for (k = 0; k < age_bins; k++) {
        acc = ants_reputation_fp_mul(acc, ratio_q32);
        if (acc == 0) {
            break;
        }
    }
    return acc;
}

/* Apply a q32 decay factor to a μ-NCS value: (value · factor) >> 32,
 * saturating at UINT64_MAX. value is an arbitrary u64; factor <= 2^32.
 * Portable 64×32→shift via hi/lo split (no 128-bit type, strict C99). */
static uint64_t apply_decay(uint64_t value, uint64_t factor_q32)
{
    uint64_t hi, lo, lo_term, hi_term, r;

    if (factor_q32 >= ANTS_REP_FP_ONE) {
        return value; /* factor == 1.0 */
    }
    hi = value >> 32;
    lo = value & 0xFFFFFFFFu;
    /* lo < 2^32 and factor < 2^32 → product < 2^64, exact. */
    lo_term = (lo * factor_q32) >> ANTS_REP_FP_BITS;
    /* hi · factor can exceed 2^64 for very large value — saturate. */
    if (hi != 0 && factor_q32 > UINT64_MAX / hi) {
        return UINT64_MAX;
    }
    hi_term = hi * factor_q32;
    r = hi_term + lo_term;
    if (r < hi_term) {
        return UINT64_MAX; /* addition overflow */
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Saturating T_eff fork-choice transform (RFC-0004 §"T → T_eff")           */
/* ------------------------------------------------------------------------ */

/* floor(a · 2^32 / d) for a < d, in q32, exact and overflow-safe with no
 * 128-bit type: 32-iteration binary long division. The invariant rem < d
 * is preserved every step, and the "double rem mod d" is written so no
 * intermediate exceeds 2^64 even for d near UINT64_MAX:
 *   if 2·rem >= d (tested as rem >= d − rem):  rem ← 2·rem − d, bit = 1
 *   else:                                       rem ← 2·rem,     bit = 0
 * 2·rem − d is computed as rem − (d − rem) (both operands < 2^64, result
 * >= 0 and < d); the else branch has 2·rem < d < 2^64. */
static uint64_t muldiv_q32(uint64_t a, uint64_t d)
{
    uint64_t q = 0;
    uint64_t rem = a; /* invariant: rem < d */
    int i;
    for (i = 0; i < 32; i++) {
        if (rem >= d - rem) {
            rem = rem - (d - rem); /* 2*rem - d, in [0, d) */
            q = (q << 1) | 1u;
        } else {
            rem = rem + rem; /* 2*rem < d */
            q = q << 1;
        }
    }
    return q;
}

/* exp(−f) for f ∈ [0, 1) in q32, via a pinned Horner-form Taylor series
 * of ANTS_REP_TAYLOR_TERMS terms:
 *   exp(−f) = 1 − f/1·(1 − f/2·(1 − f/3·( … (1 − f/N) … )))
 * Each step s ← 1 − (f·s)/k uses the exact q32 fp_mul then an integer
 * divide by k. For f < 1 the result stays in (1/e, 1], so the subtraction
 * never underflows. The term count is part of the canonical recipe. */
static uint64_t taylor_expneg_q32(uint64_t f_q32)
{
    uint64_t s = ANTS_REP_FP_ONE;
    uint64_t k;
    for (k = ANTS_REP_TAYLOR_TERMS; k >= 1; k--) {
        uint64_t term = ants_reputation_fp_mul(f_q32, s) / k;
        s = ANTS_REP_FP_ONE - term;
    }
    return s;
}

/* exp(−t/t_cap) in q32 by range reduction t/t_cap = n + f:
 *   exp(−(n+f)) = exp(−1)^n · exp(−f).
 * exp(−1)^n reuses the pinned repeated-multiplication decay_factor (it
 * short-circuits to 0 after ~61 iterations regardless of how large n is,
 * so a huge t cannot drive unbounded work); exp(−f) is the Taylor series
 * above. Requires t_cap > 0 (caller-checked). */
static uint64_t expneg_ratio_q32(uint64_t t, uint64_t t_cap)
{
    uint64_t n = t / t_cap;
    uint64_t rem = t % t_cap; /* rem < t_cap → safe muldiv input */
    uint64_t f_q32 = muldiv_q32(rem, t_cap);
    uint64_t int_part = ants_reputation_decay_factor(ANTS_REP_EXP_NEG1_Q32, n);
    uint64_t frac_part = taylor_expneg_q32(f_q32);
    return ants_reputation_fp_mul(int_part, frac_part);
}

ants_error_t ants_reputation_t_eff(uint64_t t, uint64_t t_cap, uint64_t *out)
{
    uint64_t expx, one_minus;

    if (out == NULL || t_cap == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    expx = expneg_ratio_q32(t, t_cap);  /* exp(−t/t_cap) in q32 ∈ [0,1] */
    one_minus = ANTS_REP_FP_ONE - expx; /* 1 − exp(−t/t_cap)  in q32     */
    /* t_cap · (1 − exp), saturating; reuses the q32-scale multiply. The
     * result is <= t_cap because one_minus <= 1.0. */
    *out = apply_decay(t_cap, one_minus);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Receipt body encode + verify                                             */
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

ants_error_t ants_reputation_receipt_body_encode(const ants_reputation_receipt_t *r,
                                                 uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (r == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, REP_BODY_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, REP_KEY_SERVER, r->server, sizeof r->server);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, REP_KEY_CLIENT, r->client, sizeof r->client);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, REP_KEY_NCS, r->ncs_value);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, REP_KEY_TIMESTAMP, r->timestamp_unix_s);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, REP_KEY_NONCE, r->nonce, sizeof r->nonce);
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

ants_error_t ants_reputation_receipt_verify(const ants_reputation_receipt_t *r, bool *out_ok)
{
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len = 0;
    ants_error_t rc;

    if (r == NULL || out_ok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_ok = false;

    rc = ants_reputation_receipt_body_encode(r, body, sizeof body, &body_len);
    if (rc != ANTS_OK) {
        /* A body that cannot even be encoded is not a valid receipt, but
         * the function contract is "verify" → report a false verdict
         * rather than a hard error (unless the args were NULL, handled). */
        return rc;
    }

    /* Server signature over the body. */
    rc = ants_ed25519_verify(r->server, body, body_len, r->server_sig);
    if (rc == ANTS_ERROR_INVALID_ARG) {
        return rc;
    }
    if (rc != ANTS_OK) {
        return ANTS_OK; /* invalid server signature → false verdict */
    }
    /* Client countersignature over the same body. */
    rc = ants_ed25519_verify(r->client, body, body_len, r->client_sig);
    if (rc == ANTS_ERROR_INVALID_ARG) {
        return rc;
    }
    if (rc != ANTS_OK) {
        return ANTS_OK; /* invalid client countersignature → false verdict */
    }

    *out_ok = true;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* The (A, T) computation                                                    */
/* ------------------------------------------------------------------------ */

ants_error_t ants_reputation_params_default(ants_reputation_params_t *params)
{
    if (params == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    params->decay_ratio_a_q32 = ANTS_REP_DECAY_RATIO_A_Q32;
    params->decay_ratio_t_q32 = ANTS_REP_DECAY_RATIO_T_Q32;
    params->kappa_uncs_per_bin = ANTS_REP_KAPPA_UNCS_PER_BIN;
    params->bin_width_s = ANTS_REP_BIN_WIDTH_S;
    return ANTS_OK;
}

ants_error_t ants_reputation_compute(const uint8_t server_id[ANTS_REP_PEER_ID_SIZE],
                                     const ants_reputation_receipt_t *receipts,
                                     size_t n_receipts,
                                     uint64_t now_unix_s,
                                     const ants_reputation_params_t *params,
                                     uint64_t *out_a,
                                     uint64_t *out_t)
{
    /* Per-receipt validity cache: verified AND server==server_id AND
     * timestamp <= now. The only scratch; bounds signature verification
     * to one pass. 1 byte/receipt on the stack. */
    bool valid[ANTS_REP_MAX_RECEIPTS];
    uint64_t a_total = 0;
    uint64_t t_total = 0;
    uint64_t now_bin;
    size_t i, j;

    if (server_id == NULL || out_a == NULL || out_t == NULL || params == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_receipts > 0 && receipts == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_receipts > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (params->bin_width_s == 0 || params->decay_ratio_a_q32 == 0 ||
        params->decay_ratio_t_q32 == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    now_bin = now_unix_s / params->bin_width_s;

    /* Pass 1: validity + A (per-receipt fast decay, uncapped). */
    for (i = 0; i < n_receipts; i++) {
        const ants_reputation_receipt_t *r = &receipts[i];
        bool ok = false;
        ants_error_t rc;
        uint64_t age_bins, factor;

        valid[i] = false;

        rc = ants_reputation_receipt_verify(r, &ok);
        if (rc != ANTS_OK) {
            return rc; /* only INVALID_ARG reaches here */
        }
        if (!ok) {
            continue;
        }
        if (memcmp(r->server, server_id, ANTS_REP_PEER_ID_SIZE) != 0) {
            continue; /* receipt credits a different server */
        }
        if (r->timestamp_unix_s > now_unix_s) {
            continue; /* future-dated → not yet contributing */
        }
        valid[i] = true;

        age_bins = (now_unix_s - r->timestamp_unix_s) / params->bin_width_s;
        factor = ants_reputation_decay_factor(params->decay_ratio_a_q32, age_bins);
        a_total = sat_add_u64(a_total, apply_decay(r->ncs_value, factor));
    }

    /* Pass 2: T — per-bin κ-clip then slow decay. Each bin is processed
     * once, by its first-occurring valid receipt; the inner loop sums the
     * bin. O(n²) over valid receipts, no allocation. */
    for (i = 0; i < n_receipts; i++) {
        uint64_t bin_i, bin_total, clipped, bin_age, factor_t;
        bool first_in_bin = true;

        if (!valid[i]) {
            continue;
        }
        bin_i = receipts[i].timestamp_unix_s / params->bin_width_s;

        /* Is an earlier valid receipt in the same bin? Then i is not the
         * representative and this bin was already counted. */
        for (j = 0; j < i; j++) {
            if (valid[j] && (receipts[j].timestamp_unix_s / params->bin_width_s) == bin_i) {
                first_in_bin = false;
                break;
            }
        }
        if (!first_in_bin) {
            continue;
        }

        /* Sum every valid receipt in this bin (including i). */
        bin_total = 0;
        for (j = i; j < n_receipts; j++) {
            if (valid[j] && (receipts[j].timestamp_unix_s / params->bin_width_s) == bin_i) {
                bin_total = sat_add_u64(bin_total, receipts[j].ncs_value);
            }
        }

        /* κ-clip, then decay by the bin's age. */
        clipped = (bin_total < params->kappa_uncs_per_bin) ? bin_total : params->kappa_uncs_per_bin;
        bin_age = now_bin - bin_i; /* bin_i <= now_bin since timestamp <= now */
        factor_t = ants_reputation_decay_factor(params->decay_ratio_t_q32, bin_age);
        t_total = sat_add_u64(t_total, apply_decay(clipped, factor_t));
    }

    *out_a = a_total;
    *out_t = t_total;
    return ANTS_OK;
}
