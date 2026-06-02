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

/* A peer-receipt's contribution to A: ncs_value decayed by the fast δ_A
 * factor over its whole-bin age. The single definition of "decayed_value"
 * shared by ants_reputation_compute's A pass and the selective-disclosure
 * A >= b recompute, so the two agree bit-for-bit (a verifier credits exactly
 * what compute would). Requires params->bin_width_s > 0 (callers check). */
static uint64_t receipt_a_contribution(const ants_reputation_receipt_t *r,
                                       uint64_t now_unix_s,
                                       const ants_reputation_params_t *params)
{
    uint64_t age_bins = (now_unix_s - r->timestamp_unix_s) / params->bin_width_s;
    uint64_t factor = ants_reputation_decay_factor(params->decay_ratio_a_q32, age_bins);
    return apply_decay(r->ncs_value, factor);
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

        a_total = sat_add_u64(a_total, receipt_a_contribution(r, now_unix_s, params));
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

/* ------------------------------------------------------------------------ */
/* L1 slash interaction (RFC-0004 §"How tenure interacts with Layer 1")     */
/* ------------------------------------------------------------------------ */

ants_error_t ants_reputation_compute_checked(const uint8_t server_id[ANTS_REP_PEER_ID_SIZE],
                                             const ants_reputation_receipt_t *receipts,
                                             size_t n_receipts,
                                             uint64_t now_unix_s,
                                             const ants_reputation_params_t *params,
                                             ants_reputation_is_slashed_fn is_slashed,
                                             void *slash_ctx,
                                             uint64_t *out_a,
                                             uint64_t *out_t)
{
    /* NULL-check only what the slash gate itself touches or writes, before
     * the gate; the remaining preconditions (params, n_receipts, degenerate
     * values) are the delegated ants_reputation_compute's single source of
     * truth on the non-slashed path. */
    if (server_id == NULL || out_a == NULL || out_t == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* The negative half of the spine (RFC-0004 §597 / reference sketch
     * §1404): a slashed identity is globally dead — zero A AND zero T,
     * without reading the receipt bag. */
    if (is_slashed != NULL && is_slashed(server_id, slash_ctx)) {
        *out_a = 0;
        *out_t = 0;
        return ANTS_OK;
    }

    /* Not slashed (or no slash source bound) → exactly the unchecked
     * computation, including all of its argument validation. */
    return ants_reputation_compute(
        server_id, receipts, n_receipts, now_unix_s, params, out_a, out_t);
}

/* ------------------------------------------------------------------------ */
/* Selective disclosure: the receipt-bag Merkle tree (RFC-0004              */
/* §"Selective disclosure of receipts")                                     */
/*                                                                          */
/* The SAME domain-separated, promote-lone-trailing BLAKE3 Merkle scheme as */
/* reputation/chain's confirmed_proofs root and inference/orchestration's   */
/* commit Merkle (leaf 0x00 / node 0x01 / empty 0x02), so the codebase has  */
/* one canonical tree. Receipt-specific: the leaf commits the whole receipt */
/* (canonical body ‖ both signatures), the canonical leaf order is          */
/* (timestamp ASC, then leaf-hash ASC), and bag_root binds the tree root to */
/* the peer-id via BLAKE3.derive_key. No malloc, no float; an O(log n)      */
/* bounded peak stack, like chain.                                          */
/* ------------------------------------------------------------------------ */

#define REP_MERKLE_LEAF_PREFIX  0x00u
#define REP_MERKLE_NODE_PREFIX  0x01u
#define REP_MERKLE_EMPTY_PREFIX 0x02u

/* leaf(R) = BLAKE3(0x00 ‖ body(R) ‖ server_sig ‖ client_sig). Streams the
 * receipt into the hasher (no concatenation buffer beyond the <=128-byte
 * canonical body). Binds the whole receipt — body and both signatures — so
 * one leaf hash anchors both the inclusion proof and the countersignature
 * integrity check. */
static ants_error_t receipt_leaf_hash(const ants_reputation_receipt_t *r,
                                      uint8_t out[ANTS_REP_HASH_SIZE])
{
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len = 0;
    const uint8_t prefix = REP_MERKLE_LEAF_PREFIX;
    ants_blake3_ctx_t h;
    ants_error_t rc;

    rc = ants_reputation_receipt_body_encode(r, body, sizeof body, &body_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, &prefix, 1);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, body, body_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, r->server_sig, ANTS_REP_SIG_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, r->client_sig, ANTS_REP_SIG_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out);
}

/* node(L,R) = BLAKE3(0x01 ‖ L ‖ R). `out` may alias `left`/`right`: both
 * inputs are consumed into the hasher before final writes out. */
static ants_error_t rep_node_hash(const uint8_t left[ANTS_REP_HASH_SIZE],
                                  const uint8_t right[ANTS_REP_HASH_SIZE],
                                  uint8_t out[ANTS_REP_HASH_SIZE])
{
    const uint8_t prefix = REP_MERKLE_NODE_PREFIX;
    ants_blake3_ctx_t h;
    ants_error_t rc;

    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, &prefix, 1);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, left, ANTS_REP_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, right, ANTS_REP_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out);
}

/* empty-bag root = BLAKE3(0x02). */
static ants_error_t rep_empty_root(uint8_t out[ANTS_REP_HASH_SIZE])
{
    const uint8_t prefix = REP_MERKLE_EMPTY_PREFIX;
    return ants_blake3_hash(&prefix, 1, out);
}

/* Merkle root over receipts[lo, hi) (requires hi > lo) under the
 * promote-lone-trailing level scheme, computed with an O(log n) bounded
 * peak stack and no allocation (the same online MMR build as
 * reputation/chain). Leaves are hashed on push via receipt_leaf_hash. */
static ants_error_t rep_subtree_root_range(const ants_reputation_receipt_t *receipts,
                                           size_t lo,
                                           size_t hi,
                                           uint8_t out[ANTS_REP_HASH_SIZE])
{
    uint8_t stack[ANTS_REP_BAG_MERKLE_MAX_DEPTH + 2][ANTS_REP_HASH_SIZE];
    int height[ANTS_REP_BAG_MERKLE_MAX_DEPTH + 2];
    int top = 0;
    ants_error_t rc;
    size_t i;
    int k;

    for (i = lo; i < hi; i++) {
        rc = receipt_leaf_hash(&receipts[i], stack[top]);
        if (rc != ANTS_OK) {
            return rc;
        }
        height[top] = 0;
        top++;
        while (top >= 2 && height[top - 1] == height[top - 2]) {
            rc = rep_node_hash(stack[top - 2], stack[top - 1], stack[top - 2]);
            if (rc != ANTS_OK) {
                return rc;
            }
            height[top - 2]++;
            top--;
        }
    }

    /* Bag the leftover peaks right-to-left (lone-trailing-node promotion),
     * accumulating into the rightmost peak — identical to chain. */
    for (k = top - 2; k >= 0; k--) {
        rc = rep_node_hash(stack[k], stack[top - 1], stack[top - 1]);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    memcpy(out, stack[top - 1], ANTS_REP_HASH_SIZE);
    return ANTS_OK;
}

/* Number of sibling hashes on the path from leaf `index` to the root in a
 * promote-lone-node tree of `n_leaves` (identical to chain/inference). */
static size_t rep_merkle_path_len(size_t index, size_t n_leaves)
{
    size_t len = 0;
    size_t idx = index;
    size_t count = n_leaves;

    while (count > 1) {
        if ((idx & 1u) == 1u) {
            len++; /* right child: always has a left sibling */
        } else if (idx + 1 < count) {
            len++; /* left child with a right sibling present */
        }
        idx /= 2;
        count = (count + 1) / 2;
    }
    return len;
}

/* True (via *out_ok) iff the n >= 1 receipts are in canonical bag order:
 * strictly ascending by (timestamp_unix_s, then leaf-hash). Strictness also
 * rejects an exact-duplicate receipt (equal on both keys). Each leaf hash is
 * computed once, carried as `prev` across the walk. A hashing failure is
 * returned as an error (not a verdict). */
static ants_error_t
receipts_canonical_ordered(const ants_reputation_receipt_t *receipts, size_t n, bool *out_ok)
{
    uint8_t prev_leaf[ANTS_REP_HASH_SIZE];
    uint8_t cur_leaf[ANTS_REP_HASH_SIZE];
    ants_error_t rc;
    size_t i;

    *out_ok = false;
    rc = receipt_leaf_hash(&receipts[0], prev_leaf);
    if (rc != ANTS_OK) {
        return rc;
    }
    for (i = 1; i < n; i++) {
        rc = receipt_leaf_hash(&receipts[i], cur_leaf);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (receipts[i].timestamp_unix_s < receipts[i - 1].timestamp_unix_s) {
            return ANTS_OK; /* timestamps descend → not canonical */
        }
        if (receipts[i].timestamp_unix_s == receipts[i - 1].timestamp_unix_s &&
            memcmp(cur_leaf, prev_leaf, ANTS_REP_HASH_SIZE) <= 0) {
            return ANTS_OK; /* tie on timestamp, leaf not strictly greater */
        }
        memcpy(prev_leaf, cur_leaf, ANTS_REP_HASH_SIZE);
    }
    *out_ok = true;
    return ANTS_OK;
}

/* bag_root = BLAKE3.derive_key(context, peer_id ‖ merkle_root). */
static ants_error_t derive_bag_root(const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                    const uint8_t merkle_root[ANTS_REP_HASH_SIZE],
                                    uint8_t out_root[ANTS_REP_HASH_SIZE])
{
    ants_blake3_ctx_t h;
    ants_error_t rc;

    rc = ants_blake3_init_derive(&h, ANTS_REP_BAG_ROOT_CONTEXT);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, peer_id, ANTS_REP_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, merkle_root, ANTS_REP_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out_root);
}

ants_error_t ants_reputation_bag_root(const ants_reputation_receipt_t *receipts,
                                      size_t n,
                                      const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                      uint8_t out_root[ANTS_REP_HASH_SIZE])
{
    uint8_t merkle_root[ANTS_REP_HASH_SIZE];
    ants_error_t rc;

    if (out_root == NULL || peer_id == NULL || (receipts == NULL && n != 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }

    if (n == 0) {
        rc = rep_empty_root(merkle_root);
        if (rc != ANTS_OK) {
            return rc;
        }
    } else {
        bool ordered = false;
        rc = receipts_canonical_ordered(receipts, n, &ordered);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (!ordered) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        rc = rep_subtree_root_range(receipts, 0, n, merkle_root);
        if (rc != ANTS_OK) {
            return rc;
        }
    }

    return derive_bag_root(peer_id, merkle_root, out_root);
}

ants_error_t ants_reputation_bag_prove(const ants_reputation_receipt_t *receipts,
                                       size_t n,
                                       size_t index,
                                       uint8_t *out_path,
                                       size_t path_cap,
                                       size_t *out_path_len)
{
    size_t need_bytes;
    size_t written = 0;
    size_t idx;
    size_t count;
    int level = 0;
    bool ordered = false;
    ants_error_t rc;

    if (receipts == NULL || n == 0 || index >= n || out_path == NULL || out_path_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    rc = receipts_canonical_ordered(receipts, n, &ordered);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (!ordered) {
        return ANTS_ERROR_NON_CANONICAL;
    }

    need_bytes = rep_merkle_path_len(index, n) * ANTS_REP_HASH_SIZE;
    if (need_bytes > path_cap) {
        *out_path_len = need_bytes;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    idx = index;
    count = n;
    while (count > 1) {
        bool has_sib = false;
        size_t sib = 0;

        if ((idx & 1u) == 1u) {
            has_sib = true;
            sib = idx - 1;
        } else if (idx + 1 < count) {
            has_sib = true;
            sib = idx + 1;
        }
        if (has_sib) {
            uint64_t lo64 = (uint64_t)sib << level;
            uint64_t hi64 = ((uint64_t)sib + 1) << level;
            if (hi64 > (uint64_t)n) {
                hi64 = (uint64_t)n;
            }
            rc = rep_subtree_root_range(
                receipts, (size_t)lo64, (size_t)hi64, out_path + written * ANTS_REP_HASH_SIZE);
            if (rc != ANTS_OK) {
                return rc;
            }
            written++;
        }
        idx /= 2;
        count = (count + 1) / 2;
        level++;
    }

    *out_path_len = written * ANTS_REP_HASH_SIZE;
    return ANTS_OK;
}

ants_error_t ants_reputation_bag_verify_inclusion(const ants_reputation_receipt_t *receipt,
                                                  size_t index,
                                                  size_t n,
                                                  const uint8_t *path,
                                                  size_t path_len,
                                                  const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                                  const uint8_t bag_root[ANTS_REP_HASH_SIZE],
                                                  bool *out_ok)
{
    uint8_t cur[ANTS_REP_HASH_SIZE];
    uint8_t derived[ANTS_REP_HASH_SIZE];
    size_t consumed = 0;
    size_t idx;
    size_t count;
    ants_error_t rc;

    if (receipt == NULL || n == 0 || index >= n || path == NULL || peer_id == NULL ||
        bag_root == NULL || out_ok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (path_len != rep_merkle_path_len(index, n) * ANTS_REP_HASH_SIZE) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_ok = false;

    rc = receipt_leaf_hash(receipt, cur);
    if (rc != ANTS_OK) {
        return rc;
    }

    idx = index;
    count = n;
    while (count > 1) {
        bool has_sib = false;
        bool sib_on_left = false;

        if ((idx & 1u) == 1u) {
            has_sib = true;
            sib_on_left = true;
        } else if (idx + 1 < count) {
            has_sib = true;
            sib_on_left = false;
        }
        if (has_sib) {
            const uint8_t *sib = path + consumed * ANTS_REP_HASH_SIZE;
            if (sib_on_left) {
                rc = rep_node_hash(sib, cur, cur);
            } else {
                rc = rep_node_hash(cur, sib, cur);
            }
            if (rc != ANTS_OK) {
                return rc;
            }
            consumed++;
        }
        idx /= 2;
        count = (count + 1) / 2;
    }

    /* cur is the recomputed Merkle root; bind it to peer_id and compare to
     * the committed bag_root. (consumed == path_len/HASH is guaranteed by
     * the entry check, kept as a belt-and-suspenders conjunct.) */
    rc = derive_bag_root(peer_id, cur, derived);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_ok = (consumed * ANTS_REP_HASH_SIZE == path_len) &&
              (memcmp(derived, bag_root, ANTS_REP_HASH_SIZE) == 0);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Selective disclosure: proving A >= b over a revealed subset (RFC-0004    */
/* §"Selective disclosure of receipts", steps 1-3)                          */
/* ------------------------------------------------------------------------ */

ants_error_t ants_reputation_bag_select_for_bound(const ants_reputation_receipt_t *receipts,
                                                  size_t n,
                                                  const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                                  uint64_t now_unix_s,
                                                  const ants_reputation_params_t *params,
                                                  uint64_t b,
                                                  size_t *out_indices,
                                                  size_t indices_cap,
                                                  size_t *out_count,
                                                  bool *out_reached)
{
    uint64_t acc = 0;
    size_t count = 0;
    size_t i;
    bool ordered = false;
    ants_error_t rc;

    if (receipts == NULL || peer_id == NULL || params == NULL || out_indices == NULL ||
        out_count == NULL || out_reached == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n == 0 || n > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (params->bin_width_s == 0 || params->decay_ratio_a_q32 == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = receipts_canonical_ordered(receipts, n, &ordered);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (!ordered) {
        return ANTS_ERROR_NON_CANONICAL;
    }

    *out_count = 0;
    *out_reached = (b == 0);
    if (b == 0) {
        return ANTS_OK; /* trivially reached with the empty subset */
    }

    /* Most-recent-first: canonical order is timestamp ASC, so walk from the
     * tail (recent receipts have decayed least → fewest revealed to reach b,
     * RFC-0004 §"Selective disclosure" step 1). Only A-eligible receipts
     * count: both sigs valid, this peer, not future-dated. */
    for (i = n; i-- > 0;) {
        const ants_reputation_receipt_t *r = &receipts[i];
        bool ok = false;

        rc = ants_reputation_receipt_verify(r, &ok);
        if (rc != ANTS_OK) {
            return rc; /* only INVALID_ARG */
        }
        if (!ok) {
            continue;
        }
        if (memcmp(r->server, peer_id, ANTS_REP_PEER_ID_SIZE) != 0) {
            continue;
        }
        if (r->timestamp_unix_s > now_unix_s) {
            continue;
        }
        if (count == indices_cap) {
            *out_count = count;
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        out_indices[count++] = i;
        acc = sat_add_u64(acc, receipt_a_contribution(r, now_unix_s, params));
        if (acc >= b) {
            *out_count = count;
            *out_reached = true;
            return ANTS_OK;
        }
    }

    /* Exhausted all eligible receipts without reaching b: the peer's
     * revealable A is below b. */
    *out_count = count;
    *out_reached = false;
    return ANTS_OK;
}

ants_error_t ants_reputation_bag_verify_bound(const ants_reputation_bag_opening_t *openings,
                                              size_t k,
                                              size_t n,
                                              const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                              const uint8_t bag_root[ANTS_REP_HASH_SIZE],
                                              uint64_t now_unix_s,
                                              const ants_reputation_params_t *params,
                                              uint64_t b,
                                              bool *out_ok)
{
    uint64_t acc = 0;
    size_t i, j;
    ants_error_t rc;

    if (peer_id == NULL || bag_root == NULL || params == NULL || out_ok == NULL ||
        (openings == NULL && k != 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (k > ANTS_REP_MAX_RECEIPTS || n > ANTS_REP_MAX_RECEIPTS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (params->bin_width_s == 0 || params->decay_ratio_a_q32 == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_ok = false;

    /* The openings are UNTRUSTED input: any malformed or failing opening is a
     * false verdict (reject), never a hard error. */
    for (i = 0; i < k; i++) {
        const ants_reputation_bag_opening_t *op = &openings[i];
        bool sig_ok = false;
        bool inc_ok = false;

        if (op->index >= n) {
            return ANTS_OK; /* index outside the bag → reject */
        }
        /* Distinct canonical index → no double-counting a receipt. */
        for (j = 0; j < i; j++) {
            if (openings[j].index == op->index) {
                return ANTS_OK;
            }
        }

        /* Countersignature integrity (both signatures over the body). */
        rc = ants_reputation_receipt_verify(&op->receipt, &sig_ok);
        if (rc != ANTS_OK) {
            return rc; /* only INVALID_ARG; op->receipt is non-NULL */
        }
        if (!sig_ok) {
            return ANTS_OK;
        }
        /* Must credit this peer, and not be future-dated. */
        if (memcmp(op->receipt.server, peer_id, ANTS_REP_PEER_ID_SIZE) != 0) {
            return ANTS_OK;
        }
        if (op->receipt.timestamp_unix_s > now_unix_s) {
            return ANTS_OK;
        }
        /* Merkle inclusion against the committed bag_root (pre-check the path
         * shape so a malformed proof is a reject, not an INVALID_ARG). */
        if (op->path == NULL ||
            op->path_len != rep_merkle_path_len(op->index, n) * ANTS_REP_HASH_SIZE) {
            return ANTS_OK;
        }
        rc = ants_reputation_bag_verify_inclusion(
            &op->receipt, op->index, n, op->path, op->path_len, peer_id, bag_root, &inc_ok);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (!inc_ok) {
            return ANTS_OK; /* not in the committed bag → reject */
        }

        acc = sat_add_u64(acc, receipt_a_contribution(&op->receipt, now_unix_s, params));
    }

    /* Lower bound: the revealed subset's summed A must clear b. */
    *out_ok = (acc >= b);
    return ANTS_OK;
}
