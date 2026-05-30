/*
 * test_reputation.c — Tests for the (A, T, κ) reputation spine
 * (Component #9 PR1).
 *
 * Covers the deterministic fixed-point decay primitive (fp_mul +
 * decay_factor: identities, monotone fall, cross-recipe determinism, the
 * no-decay and zero-age edges), the countersigned-receipt body codec +
 * dual-signature verification (real Ed25519), and ants_reputation_compute
 * (A uncapped fast decay; T binned + κ-clipped + slow decay; invalid /
 * wrong-server / future-dated receipts skipped; κ actually caps a bin).
 *
 * Receipts are signed with real Ed25519 keys, so verification is
 * exercised end-to-end rather than mocked.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_reputation.h"

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

/* ---- key helpers ---------------------------------------------------- */

/* Deterministic test keypair from a single seed byte. */
static void make_key(uint8_t seed, uint8_t priv[32], uint8_t pub[32])
{
    memset(priv, seed, 32);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
}

/* Build a fully-signed receipt: server (with priv `s_priv`) did
 * `ncs` work for client `c_pub` at `ts`; both sign the canonical body. */
static ants_reputation_receipt_t make_receipt(const uint8_t s_priv[32],
                                              const uint8_t s_pub[32],
                                              const uint8_t c_priv[32],
                                              const uint8_t c_pub[32],
                                              uint64_t ncs,
                                              uint64_t ts,
                                              uint8_t nonce_seed)
{
    ants_reputation_receipt_t r;
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len = 0;
    memset(&r, 0, sizeof r);
    memcpy(r.server, s_pub, 32);
    memcpy(r.client, c_pub, 32);
    r.ncs_value = ncs;
    r.timestamp_unix_s = ts;
    memset(r.nonce, nonce_seed, sizeof r.nonce);
    CHECK_EQ(ants_reputation_receipt_body_encode(&r, body, sizeof body, &body_len), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(s_priv, body, body_len, r.server_sig), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(c_priv, body, body_len, r.client_sig), ANTS_OK);
    return r;
}

/* ---- fixed-point decay --------------------------------------------- */

static void test_fp_mul_identities(void)
{
    /* 1.0 · x = x and x · 1.0 = x; including the both-1.0 overflow edge. */
    CHECK(ants_reputation_fp_mul(ANTS_REP_FP_ONE, 12345) == 12345);
    CHECK(ants_reputation_fp_mul(12345, ANTS_REP_FP_ONE) == 12345);
    CHECK(ants_reputation_fp_mul(ANTS_REP_FP_ONE, ANTS_REP_FP_ONE) == ANTS_REP_FP_ONE);
    /* 0.5 · 0.5 = 0.25 in q32. */
    uint64_t half = ANTS_REP_FP_ONE >> 1;
    CHECK(ants_reputation_fp_mul(half, half) == (ANTS_REP_FP_ONE >> 2));
}

static void test_decay_factor_basics(void)
{
    uint64_t half = ANTS_REP_FP_ONE >> 1;

    /* age 0 → 1.0 regardless of ratio. */
    CHECK(ants_reputation_decay_factor(half, 0) == ANTS_REP_FP_ONE);
    /* ratio 0.5 → 0.5^k. */
    CHECK(ants_reputation_decay_factor(half, 1) == half);
    CHECK(ants_reputation_decay_factor(half, 2) == (ANTS_REP_FP_ONE >> 2));
    CHECK(ants_reputation_decay_factor(half, 3) == (ANTS_REP_FP_ONE >> 3));
    CHECK(ants_reputation_decay_factor(half, 32) == 1); /* 0.5^32 = 1 ulp in q32 */
    CHECK(ants_reputation_decay_factor(half, 33) == 0); /* underflows to 0 */
    /* no decay: ratio >= 1.0 → 1.0 for any age. */
    CHECK(ants_reputation_decay_factor(ANTS_REP_FP_ONE, 1000) == ANTS_REP_FP_ONE);
    /* monotone non-increasing in age. */
    uint64_t prev = ANTS_REP_FP_ONE;
    for (uint64_t k = 1; k <= 40; k++) {
        uint64_t f = ants_reputation_decay_factor(ANTS_REP_DECAY_RATIO_T_Q32, k);
        CHECK(f <= prev);
        prev = f;
    }
}

static void test_decay_factor_is_repeated_mul(void)
{
    /* Pins the canonical recipe: decay_factor is REPEATED multiplication,
     * decay(k) == fp_mul(decay(k-1), r), NOT square-and-multiply. The two
     * differ bit-for-bit because q32 fp_mul truncates (is not
     * associative); this guards against a future "optimisation" to binary
     * exponentiation silently changing every peer's computed tenure. The
     * reference here recomputes the k-fold product independently per k
     * (the impl carries one running accumulator), so a mismatch in the
     * accumulation method would still surface. Ratio ≈ 0.99 so the factor
     * stays non-zero across the whole range. */
    uint64_t ratio = ANTS_REP_DECAY_RATIO_T_Q32;
    for (uint64_t k = 0; k <= 50; k++) {
        uint64_t ref = ANTS_REP_FP_ONE;
        uint64_t m;
        for (m = 0; m < k; m++) {
            ref = ants_reputation_fp_mul(ref, ratio);
        }
        CHECK(ants_reputation_decay_factor(ratio, k) == ref);
    }
}

/* ---- receipt codec + verify ---------------------------------------- */

static void test_receipt_body_canonical_and_verify(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32];
    make_key(0x11, sp, su);
    make_key(0x22, cp, cu);
    ants_reputation_receipt_t r = make_receipt(sp, su, cp, cu, 500000, 1700000000ULL, 0xAB);

    /* The body must be canonical CBOR. */
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t n = 0;
    CHECK_EQ(ants_reputation_receipt_body_encode(&r, body, sizeof body, &n), ANTS_OK);
    CHECK(n > 0 && n <= ANTS_REP_RECEIPT_BODY_ENCODED_MAX);
    CHECK_EQ(ants_cbor_is_canonical(body, n), ANTS_OK);

    bool ok = false;
    CHECK_EQ(ants_reputation_receipt_verify(&r, &ok), ANTS_OK);
    CHECK(ok == true);

    /* Tamper the value → server sig no longer covers it → false verdict. */
    ants_reputation_receipt_t bad = r;
    bad.ncs_value += 1;
    CHECK_EQ(ants_reputation_receipt_verify(&bad, &ok), ANTS_OK);
    CHECK(ok == false);

    /* Tamper one byte of the client countersignature → false verdict. */
    bad = r;
    bad.client_sig[0] ^= 0x01;
    CHECK_EQ(ants_reputation_receipt_verify(&bad, &ok), ANTS_OK);
    CHECK(ok == false);

    /* A receipt the client never countersigned (re-sign body with the
     * wrong key) → false verdict. */
    uint8_t wp[32], wu[32];
    make_key(0x99, wp, wu);
    bad = r;
    uint8_t b2[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t b2n = 0;
    CHECK_EQ(ants_reputation_receipt_body_encode(&bad, b2, sizeof b2, &b2n), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(wp, b2, b2n, bad.client_sig), ANTS_OK);
    CHECK_EQ(ants_reputation_receipt_verify(&bad, &ok), ANTS_OK);
    CHECK(ok == false);

    /* NULL guards. */
    CHECK_EQ(ants_reputation_receipt_verify(NULL, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_receipt_verify(&r, NULL), ANTS_ERROR_INVALID_ARG);
}

/* ---- compute A / T -------------------------------------------------- */

static void test_compute_basic_and_skips(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], op[32], ou[32];
    make_key(0x11, sp, su); /* server  */
    make_key(0x22, cp, cu); /* client  */
    make_key(0x33, op, ou); /* other server */

    ants_reputation_params_t params;
    CHECK_EQ(ants_reputation_params_default(&params), ANTS_OK);
    /* Pin a simple recipe for hand-checking: bin = 100 s, A ratio 0.5,
     * κ huge (so no clipping here), T ratio 1.0 (no decay) for an exact T. */
    params.bin_width_s = 100;
    params.decay_ratio_a_q32 = ANTS_REP_FP_ONE >> 1; /* 0.5 */
    params.decay_ratio_t_q32 = ANTS_REP_FP_ONE;      /* 1.0, no decay */
    params.kappa_uncs_per_bin = UINT64_MAX;          /* effectively uncapped */

    uint64_t now = 1000;
    ants_reputation_receipt_t bag[5];
    /* 0: valid, this server, now (age 0)         → A += 1000, T bin 10 += 1000 */
    bag[0] = make_receipt(sp, su, cp, cu, 1000, 1000, 1);
    /* 1: valid, this server, 200 s ago = 2 bins  → A += 1000*0.25=250, T bin 8 += 500 */
    bag[1] = make_receipt(sp, su, cp, cu, 1000, 800, 2);
    /* 2: other server → skipped entirely. */
    bag[2] = make_receipt(op, ou, cp, cu, 9999, 1000, 3);
    /* 3: future-dated → skipped. */
    bag[3] = make_receipt(sp, su, cp, cu, 7777, 2000, 4);
    /* 4: tampered (invalid sig) → skipped. */
    bag[4] = make_receipt(sp, su, cp, cu, 5000, 900, 5);
    bag[4].ncs_value += 1; /* breaks both signatures */

    uint64_t A = 0, T = 0;
    CHECK_EQ(ants_reputation_compute(su, bag, 5, now, &params, &A, &T), ANTS_OK);

    /* A = 1000*decay(0) + 1000*decay(2 bins, r=0.5). decay(2)=0.25 in q32;
     * 1000*0.25 = 250. So A = 1250. (bin = 100s, ages: 0 and 2.) */
    CHECK(A == 1250);
    /* T: no decay (ratio 1.0), κ uncapped, two distinct bins (10 and 8),
     * each summing one receipt → T = 1000 + 1000 = 2000. */
    CHECK(T == 2000);
}

static void test_compute_kappa_clips_a_bin(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32];
    make_key(0x44, sp, su);
    make_key(0x55, cp, cu);

    ants_reputation_params_t params;
    CHECK_EQ(ants_reputation_params_default(&params), ANTS_OK);
    params.bin_width_s = 100;
    params.decay_ratio_t_q32 = ANTS_REP_FP_ONE; /* no decay → isolate κ */
    params.kappa_uncs_per_bin = 1500;           /* cap per bin */

    /* now must be at/after every receipt timestamp, else a receipt is
     * future-dated and skipped. now = 1099 → now_bin = 10, all three
     * receipts (ts 1000/1050/1099 → bin 10) are present and same-bin. */
    uint64_t now = 1099;
    /* Three receipts in the SAME bin (all ts in [1000,1099] → bin 10),
     * totalling 3000, must be κ-clipped to 1500 for T. */
    ants_reputation_receipt_t bag[3];
    bag[0] = make_receipt(sp, su, cp, cu, 1000, 1000, 1);
    bag[1] = make_receipt(sp, su, cp, cu, 1000, 1050, 2);
    bag[2] = make_receipt(sp, su, cp, cu, 1000, 1099, 3);

    uint64_t A = 0, T = 0;
    CHECK_EQ(ants_reputation_compute(su, bag, 3, now, &params, &A, &T), ANTS_OK);
    /* A is uncapped: 3 * 1000 * decay(age 0) = 3000. */
    CHECK(A == 3000);
    /* T is κ-clipped to 1500 for the single bin. */
    CHECK(T == 1500);
}

static void test_compute_empty_and_args(void)
{
    uint8_t su[32], priv[32];
    make_key(0x66, priv, su);
    ants_reputation_params_t params;
    CHECK_EQ(ants_reputation_params_default(&params), ANTS_OK);

    uint64_t A = 123, T = 456;
    /* Empty bag → A = T = 0. */
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 1000, &params, &A, &T), ANTS_OK);
    CHECK(A == 0 && T == 0);

    /* NULL guards. */
    CHECK_EQ(ants_reputation_compute(NULL, NULL, 0, 0, &params, &A, &T), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 0, NULL, &A, &T), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 0, &params, NULL, &T), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 0, &params, &A, NULL), ANTS_ERROR_INVALID_ARG);

    /* Degenerate params. */
    ants_reputation_params_t bad = params;
    bad.bin_width_s = 0;
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 0, &bad, &A, &T), ANTS_ERROR_INVALID_ARG);
    bad = params;
    bad.decay_ratio_a_q32 = 0;
    CHECK_EQ(ants_reputation_compute(su, NULL, 0, 0, &bad, &A, &T), ANTS_ERROR_INVALID_ARG);

    /* Over-cap receipt count → INVALID_ARG (n too large; receipts NULL is
     * fine because the size check fires first). */
    CHECK_EQ(
        ants_reputation_compute(su, NULL, (size_t)ANTS_REP_MAX_RECEIPTS + 1, 0, &params, &A, &T),
        ANTS_ERROR_INVALID_ARG);
}

static void test_params_default(void)
{
    ants_reputation_params_t p;
    memset(&p, 0xCC, sizeof p);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    CHECK(p.bin_width_s == ANTS_REP_BIN_WIDTH_S);
    CHECK(p.decay_ratio_a_q32 == ANTS_REP_DECAY_RATIO_A_Q32);
    CHECK(p.decay_ratio_t_q32 == ANTS_REP_DECAY_RATIO_T_Q32);
    CHECK(p.kappa_uncs_per_bin == ANTS_REP_KAPPA_UNCS_PER_BIN);
    CHECK_EQ(ants_reputation_params_default(NULL), ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_fp_mul_identities();
    test_decay_factor_basics();
    test_decay_factor_is_repeated_mul();
    test_receipt_body_canonical_and_verify();
    test_compute_basic_and_skips();
    test_compute_kappa_clips_a_bin();
    test_compute_empty_and_args();
    test_params_default();

    if (failures > 0) {
        fprintf(stderr, "test_reputation: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_reputation: all checks passed\n");
    return 0;
}
