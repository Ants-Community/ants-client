/*
 * test_reputation.c — Tests for the (A, T, κ) reputation spine
 * (Component #9 PR1).
 *
 * Covers the deterministic fixed-point decay primitive (fp_mul +
 * decay_factor: identities, monotone fall, cross-recipe determinism, the
 * no-decay and zero-age edges), the countersigned-receipt body codec +
 * dual-signature verification (real Ed25519), ants_reputation_compute
 * (A uncapped fast decay; T binned + κ-clipped + slow decay; invalid /
 * wrong-server / future-dated receipts skipped; κ actually caps a bin),
 * the saturating T_eff fork-choice transform, and the L1 slash gate
 * (ants_reputation_compute_checked) bound to the REAL Component #7 G-Set:
 * an equivocation proof against the server zeroes both A and T.
 *
 * Receipts are signed with real Ed25519 keys, so verification is
 * exercised end-to-end rather than mocked.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crdt.h"
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

/* ---- saturating T_eff fork-choice transform ------------------------- */

static void test_t_eff_pinned_values(void)
{
    /* Regression pin of the fixed-point recipe's exact outputs at cap =
     * 2e9. These are the canonical bytes: if a future change to the exp
     * recipe (term count, range-reduction split, the muldiv) shifts any of
     * them, fork choice would silently diverge across peers — so they are
     * nailed down. Each is within 1 unit of the true (libm double)
     * cap·(1 − exp(−t/cap)); the true values, for the record:
     *   t=2e6  → 1999000.50    t=2e7 → 19900330.83
     *   t=2e8  → 190325163.64  t=cap → 1264241117.66                     */
    uint64_t cap = ANTS_REP_T_FORK_CHOICE_CAP; /* 2e9 */
    uint64_t v;

    CHECK_EQ(ants_reputation_t_eff(0, cap, &v), ANTS_OK);
    CHECK(v == 0);
    CHECK_EQ(ants_reputation_t_eff(2000000, cap, &v), ANTS_OK);
    CHECK(v == 1999000);
    CHECK_EQ(ants_reputation_t_eff(20000000, cap, &v), ANTS_OK);
    CHECK(v == 19900331);
    CHECK_EQ(ants_reputation_t_eff(200000000, cap, &v), ANTS_OK);
    CHECK(v == 190325163);
    CHECK_EQ(ants_reputation_t_eff(cap, cap, &v), ANTS_OK);
    CHECK(v == 1264241117);

    /* Independent algebraic anchor at t == cap: the range reduction gives
     * n = 1, f = 0 exactly, so the Taylor path contributes exactly 1.0 and
     * T_eff(cap) = cap · (1 − exp(−1)) with exp(−1) the PINNED q32
     * constant — reproduced here WITHOUT the impl's muldiv / Taylor loop
     * (cap·(2^32 − E1) ≈ 5.4e18 fits in u64, so the >>32 is exact). If
     * this and the pin above ever disagree, the exp(−1) constant or the
     * f==0 path regressed. */
    {
        uint64_t one_minus_e1 = ANTS_REP_FP_ONE - ANTS_REP_EXP_NEG1_Q32;
        uint64_t at_cap = (cap * one_minus_e1) >> ANTS_REP_FP_BITS;
        CHECK(at_cap == 1264241117);
        CHECK_EQ(ants_reputation_t_eff(cap, cap, &v), ANTS_OK);
        CHECK(v == at_cap);
    }
}

static void test_t_eff_properties(void)
{
    uint64_t cap = ANTS_REP_T_FORK_CHOICE_CAP;
    uint64_t v, prev;
    uint64_t i;

    /* Linear regime: for t ≪ cap, T_eff(t) ≈ t (within ~0.1% at t=cap/1000). */
    CHECK_EQ(ants_reputation_t_eff(cap / 1000, cap, &v), ANTS_OK);
    {
        uint64_t t = cap / 1000;
        uint64_t diff = (v > t) ? (v - t) : (t - v);
        CHECK(diff * 1000 <= t); /* |T_eff − t| ≤ 0.1% of t */
    }

    /* Never exceeds the cap, and saturates toward it. */
    CHECK_EQ(ants_reputation_t_eff(50 * cap, cap, &v), ANTS_OK);
    CHECK(v <= cap);
    CHECK(v >= cap - cap / 1000); /* within 0.1% of cap by 50× */
    CHECK_EQ(ants_reputation_t_eff(UINT64_MAX, cap, &v), ANTS_OK);
    CHECK(v <= cap); /* pathological huge t still bounded, no runaway */

    /* Monotone non-decreasing across a sweep (the recipe was checked to
     * have zero inversions; assert it holds). */
    prev = 0;
    for (i = 0; i <= 200; i++) {
        uint64_t t = i * (cap / 20); /* 0 … 10·cap */
        CHECK_EQ(ants_reputation_t_eff(t, cap, &v), ANTS_OK);
        CHECK(v >= prev);
        prev = v;
    }

    /* Determinism: same input → same output (no hidden state). */
    {
        uint64_t a = 0, b = 0;
        CHECK_EQ(ants_reputation_t_eff(123456789, cap, &a), ANTS_OK);
        CHECK_EQ(ants_reputation_t_eff(123456789, cap, &b), ANTS_OK);
        CHECK(a == b);
    }

    /* A small cap (edge of the range reduction) still obeys the bound. */
    CHECK_EQ(ants_reputation_t_eff(5, 1, &v), ANTS_OK);
    CHECK(v <= 1);
}

static void test_t_eff_args(void)
{
    uint64_t v;
    CHECK_EQ(ants_reputation_t_eff(100, 0, &v), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_t_eff(100, 2000000000, NULL), ANTS_ERROR_INVALID_ARG);
}

/* ---- L1 slash gate (compute_checked) ------------------------------- */

/* Bind the REAL Component #7 G-Set check to the spine's slash predicate.
 * ctx is the ants_crdt_t* G-Set handle. This is the canonical production
 * binding, exercised here end-to-end rather than mocked. */
static bool slash_via_crdt(const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE], void *ctx)
{
    return ants_crdt_is_slashed((const ants_crdt_t *)ctx, peer_id);
}

/* Forge a real equivocation fault proof against `s_pub`: two statements
 * signed by s_priv over the same (domain=1, epoch=5, slot=0) with different
 * payloads. Returns the encoded proof length. */
static size_t
build_equiv_against(const uint8_t s_priv[32], const uint8_t s_pub[32], uint8_t proof[512])
{
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    const uint8_t pa[2] = {1, 2};
    const uint8_t pb[2] = {3, 4};
    CHECK_EQ(ants_crdt_statement_encode(1, 5, 0, pa, sizeof pa, body_a, sizeof body_a, &la),
             ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(s_priv, body_a, la, sig_a), ANTS_OK);
    CHECK_EQ(ants_crdt_statement_encode(1, 5, 0, pb, sizeof pb, body_b, sizeof body_b, &lb),
             ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(s_priv, body_b, lb, sig_b), ANTS_OK);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 s_pub, 5, body_a, la, sig_a, body_b, lb, sig_b, proof, 512, &plen),
             ANTS_OK);
    return plen;
}

static void test_compute_checked_not_slashed(void)
{
    uint8_t s_priv[32], s_pub[32], c_priv[32], c_pub[32];
    ants_reputation_params_t p;
    ants_reputation_receipt_t r;
    ants_crdt_t *set = NULL;
    uint64_t a_chk = 0, t_chk = 0, a_un = 0, t_un = 0;

    make_key(0xA1, s_priv, s_pub);
    make_key(0xA2, c_priv, c_pub);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    r = make_receipt(s_priv, s_pub, c_priv, c_pub, 1000000, 1000000, 0x10);

    CHECK_EQ(ants_crdt_init(&set), ANTS_OK); /* empty G-Set: S is not slashed */

    CHECK_EQ(ants_reputation_compute(s_pub, &r, 1, 1000000, &p, &a_un, &t_un), ANTS_OK);
    CHECK_EQ(ants_reputation_compute_checked(
                 s_pub, &r, 1, 1000000, &p, slash_via_crdt, set, &a_chk, &t_chk),
             ANTS_OK);
    /* Not slashed → byte-identical to the unchecked computation, and nonzero. */
    CHECK(a_un > 0 && t_un > 0);
    CHECK(a_chk == a_un);
    CHECK(t_chk == t_un);

    ants_crdt_destroy(set);
}

static void test_compute_checked_slashed_zeroes_both(void)
{
    uint8_t s_priv[32], s_pub[32], c_priv[32], c_pub[32], o_priv[32], o_pub[32];
    ants_reputation_params_t p;
    ants_reputation_receipt_t r, ro;
    ants_crdt_t *set = NULL;
    uint8_t proof[512];
    size_t plen;
    bool ins = false;
    uint64_t a0 = 0, t0 = 0, a_chk = 1, t_chk = 1, a_o = 0, t_o = 0, a_d = 1, t_d = 1;

    make_key(0xB1, s_priv, s_pub);
    make_key(0xB2, c_priv, c_pub);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    r = make_receipt(s_priv, s_pub, c_priv, c_pub, 1000000, 1000000, 0x20);

    /* Sanity: with no slash this exact bag yields nonzero A and T, so the
     * zeroing below is a real effect, not an artefact of an empty bag. */
    CHECK_EQ(ants_reputation_compute(s_pub, &r, 1, 1000000, &p, &a0, &t0), ANTS_OK);
    CHECK(a0 > 0 && t0 > 0);

    /* Insert a real equivocation proof against S into the live G-Set. */
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    plen = build_equiv_against(s_priv, s_pub, proof);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    CHECK(ins == true);
    CHECK(ants_crdt_is_slashed(set, s_pub) == true);

    /* The checked compute now zeroes BOTH A and T despite the live bag. */
    CHECK_EQ(ants_reputation_compute_checked(
                 s_pub, &r, 1, 1000000, &p, slash_via_crdt, set, &a_chk, &t_chk),
             ANTS_OK);
    CHECK(a_chk == 0);
    CHECK(t_chk == 0);

    /* A different (non-slashed) server in the same set is unaffected. */
    make_key(0xB3, o_priv, o_pub);
    ro = make_receipt(o_priv, o_pub, c_priv, c_pub, 1000000, 1000000, 0x21);
    CHECK_EQ(ants_reputation_compute_checked(
                 o_pub, &ro, 1, 1000000, &p, slash_via_crdt, set, &a_o, &t_o),
             ANTS_OK);
    CHECK(a_o > 0 && t_o > 0);

    /* The slash gate short-circuits BEFORE the bag: a slashed peer returns
     * 0/0 even with NULL params (params is never read on the slashed path). */
    CHECK_EQ(ants_reputation_compute_checked(
                 s_pub, &r, 1, 1000000, NULL, slash_via_crdt, set, &a_d, &t_d),
             ANTS_OK);
    CHECK(a_d == 0 && t_d == 0);

    ants_crdt_destroy(set);
}

static void test_compute_checked_null_predicate_equals_unchecked(void)
{
    uint8_t s_priv[32], s_pub[32], c_priv[32], c_pub[32];
    ants_reputation_params_t p;
    ants_reputation_receipt_t r;
    uint64_t a_un = 0, t_un = 0, a_chk = 0, t_chk = 0;

    make_key(0xC1, s_priv, s_pub);
    make_key(0xC2, c_priv, c_pub);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    r = make_receipt(s_priv, s_pub, c_priv, c_pub, 1000000, 1000000, 0x30);

    CHECK_EQ(ants_reputation_compute(s_pub, &r, 1, 1000000, &p, &a_un, &t_un), ANTS_OK);
    /* NULL predicate → no gate → identical to unchecked; slash_ctx ignored. */
    CHECK_EQ(ants_reputation_compute_checked(s_pub, &r, 1, 1000000, &p, NULL, NULL, &a_chk, &t_chk),
             ANTS_OK);
    CHECK(a_chk == a_un && t_chk == t_un);
    CHECK(a_chk > 0 && t_chk > 0);
}

static void test_compute_checked_args(void)
{
    uint8_t s_priv[32], s_pub[32];
    ants_reputation_params_t p;
    uint64_t a = 0, t = 0;

    make_key(0xD1, s_priv, s_pub);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);

    /* NULL server_id / out_a / out_t → INVALID_ARG before the gate. */
    CHECK_EQ(ants_reputation_compute_checked(NULL, NULL, 0, 0, &p, NULL, NULL, &a, &t),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_compute_checked(s_pub, NULL, 0, 0, &p, NULL, NULL, NULL, &t),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_compute_checked(s_pub, NULL, 0, 0, &p, NULL, NULL, &a, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* Non-slashed path delegates full validation: NULL params → INVALID_ARG. */
    CHECK_EQ(ants_reputation_compute_checked(s_pub, NULL, 0, 0, NULL, NULL, NULL, &a, &t),
             ANTS_ERROR_INVALID_ARG);

    /* Empty bag, not slashed → 0/0 with ANTS_OK (no receipts to credit). */
    a = 1;
    t = 1;
    CHECK_EQ(ants_reputation_compute_checked(s_pub, NULL, 0, 1000, &p, NULL, NULL, &a, &t),
             ANTS_OK);
    CHECK(a == 0 && t == 0);
}

/* ---- selective disclosure: receipt-bag Merkle ---------------------- */

/* Independent BLAKE3 leaf/node/derive recomputed BY HAND to cross-check the
 * impl. The reference is a DIFFERENT construction (explicit pairing below,
 * not the impl's MMR/range walk) and hardcodes the derive_key context, so a
 * regression in the promote-lone replay, the leaf preimage, or the context
 * string surfaces as a mismatch. */
static void ref_receipt_leaf(const ants_reputation_receipt_t *r, uint8_t out[32])
{
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len = 0;
    const uint8_t prefix = 0x00u;
    ants_blake3_ctx_t h;
    CHECK_EQ(ants_reputation_receipt_body_encode(r, body, sizeof body, &body_len), ANTS_OK);
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, body, body_len), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, r->server_sig, 64), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, r->client_sig, 64), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

static void ref_node(const uint8_t l[32], const uint8_t r[32], uint8_t out[32])
{
    const uint8_t prefix = 0x01u;
    ants_blake3_ctx_t h;
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, l, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, r, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

/* bag_root reference: derive_key("ants-v1-receipt-bag-root", peer ‖ root)
 * with the context literal hardcoded (independent of the impl's macro). */
static void ref_bag_root(const uint8_t peer[32], const uint8_t merkle_root[32], uint8_t out[32])
{
    ants_blake3_ctx_t h;
    CHECK_EQ(ants_blake3_init_derive(&h, "ants-v1-receipt-bag-root"), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, peer, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, merkle_root, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

static void test_bag_root_reference(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32];
    ants_reputation_receipt_t r[5];
    uint8_t leaf[5][32];
    uint8_t got[32], want[32], mroot[32], n01[32], n23[32], c[32];
    size_t i;

    make_key(0x70, sp, su);
    make_key(0x71, cp, cu);
    memset(peer, 0x7E, sizeof peer); /* arbitrary commit identity */

    /* Distinct, canonically-ordered receipts: strictly increasing timestamps
     * so the timestamp key alone fixes the order (the leaf-hash tiebreak is
     * covered by test_bag_canonical_order). */
    for (i = 0; i < 5; i++) {
        r[i] = make_receipt(sp, su, cp, cu, 1000 + i, 2000 + i, (uint8_t)(0x80 + i));
        ref_receipt_leaf(&r[i], leaf[i]);
    }

    /* n == 0 → merkle_root = BLAKE3(0x02), bag_root = derive_key(peer ‖ root). */
    {
        const uint8_t empty_prefix = 0x02u;
        CHECK_EQ(ants_blake3_hash(&empty_prefix, 1, mroot), ANTS_OK);
        ref_bag_root(peer, mroot, want);
        CHECK_EQ(ants_reputation_bag_root(NULL, 0, peer, got), ANTS_OK);
        CHECK(memcmp(got, want, 32) == 0);
    }
    /* n == 1 → merkle_root = leaf0. */
    ref_bag_root(peer, leaf[0], want);
    CHECK_EQ(ants_reputation_bag_root(r, 1, peer, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 2 → node(leaf0, leaf1). */
    ref_node(leaf[0], leaf[1], mroot);
    ref_bag_root(peer, mroot, want);
    CHECK_EQ(ants_reputation_bag_root(r, 2, peer, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 3 → node(node(leaf0,leaf1), leaf2) — lone trailing leaf promoted. */
    ref_node(leaf[0], leaf[1], n01);
    ref_node(n01, leaf[2], mroot);
    ref_bag_root(peer, mroot, want);
    CHECK_EQ(ants_reputation_bag_root(r, 3, peer, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 4 → node(node(leaf0,leaf1), node(leaf2,leaf3)). */
    ref_node(leaf[0], leaf[1], n01);
    ref_node(leaf[2], leaf[3], n23);
    ref_node(n01, n23, mroot);
    ref_bag_root(peer, mroot, want);
    CHECK_EQ(ants_reputation_bag_root(r, 4, peer, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 5 → node(node(node(0,1),node(2,3)), leaf4) — promote at two levels. */
    ref_node(leaf[0], leaf[1], n01);
    ref_node(leaf[2], leaf[3], n23);
    ref_node(n01, n23, c);
    ref_node(c, leaf[4], mroot);
    ref_bag_root(peer, mroot, want);
    CHECK_EQ(ants_reputation_bag_root(r, 5, peer, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* bag_root binds the peer-id: a different commit identity → different root. */
    {
        uint8_t peer2[32], got2[32];
        memset(peer2, 0x3C, sizeof peer2);
        CHECK_EQ(ants_reputation_bag_root(r, 5, peer2, got2), ANTS_OK);
        CHECK(memcmp(got, got2, 32) != 0);
    }
}

static void test_bag_prove_verify(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32];
    ants_reputation_receipt_t r[8];
    size_t i, n, idx;

    make_key(0x72, sp, su);
    make_key(0x73, cp, cu);
    memset(peer, 0x5A, sizeof peer);
    for (i = 0; i < 8; i++) {
        r[i] = make_receipt(sp, su, cp, cu, 1000 + i, 3000 + i, (uint8_t)(0x90 + i));
    }

    for (n = 1; n <= 8; n++) {
        uint8_t root[32];
        CHECK_EQ(ants_reputation_bag_root(r, n, peer, root), ANTS_OK);

        for (idx = 0; idx < n; idx++) {
            uint8_t path[ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
            size_t path_len = 0;
            bool ok = false;

            CHECK_EQ(ants_reputation_bag_prove(r, n, idx, path, sizeof path, &path_len), ANTS_OK);
            CHECK_EQ(ants_reputation_bag_verify_inclusion(
                         &r[idx], idx, n, path, path_len, peer, root, &ok),
                     ANTS_OK);
            CHECK(ok == true);

            /* Tamper the revealed receipt → leaf changes → false. */
            {
                ants_reputation_receipt_t bad = r[idx];
                bad.ncs_value ^= 0x01u;
                CHECK_EQ(ants_reputation_bag_verify_inclusion(
                             &bad, idx, n, path, path_len, peer, root, &ok),
                         ANTS_OK);
                CHECK(ok == false);
            }
            /* Wrong committing peer → bag_root binding fails → false. */
            {
                uint8_t bad_peer[32];
                memset(bad_peer, 0xEE, sizeof bad_peer);
                CHECK_EQ(ants_reputation_bag_verify_inclusion(
                             &r[idx], idx, n, path, path_len, bad_peer, root, &ok),
                         ANTS_OK);
                CHECK(ok == false);
            }
            /* Wrong committed root → false. */
            {
                uint8_t bad_root[32];
                memcpy(bad_root, root, 32);
                bad_root[0] ^= 0x01u;
                CHECK_EQ(ants_reputation_bag_verify_inclusion(
                             &r[idx], idx, n, path, path_len, peer, bad_root, &ok),
                         ANTS_OK);
                CHECK(ok == false);
            }
            /* Flip a byte of the inclusion path (when there is one) → false. */
            if (path_len > 0) {
                uint8_t bad_path[ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
                memcpy(bad_path, path, path_len);
                bad_path[0] ^= 0x01u;
                CHECK_EQ(ants_reputation_bag_verify_inclusion(
                             &r[idx], idx, n, bad_path, path_len, peer, root, &ok),
                         ANTS_OK);
                CHECK(ok == false);
            }
            /* Right receipt, WRONG position (a sibling's path) → false. */
            if (n >= 2) {
                size_t other = (idx == 0) ? 1 : idx - 1;
                uint8_t opath[ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
                size_t olen = 0;
                CHECK_EQ(ants_reputation_bag_prove(r, n, other, opath, sizeof opath, &olen),
                         ANTS_OK);
                CHECK_EQ(ants_reputation_bag_verify_inclusion(
                             &r[idx], other, n, opath, olen, peer, root, &ok),
                         ANTS_OK);
                CHECK(ok == false);
            }
        }
    }
}

static void test_bag_canonical_order(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32], root[32];
    uint8_t la[32], lb[32];
    uint8_t path[ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
    size_t plen = 0;
    ants_reputation_receipt_t a, b, ord[2], rev[2], desc[2], dup[2];

    make_key(0x74, sp, su);
    make_key(0x75, cp, cu);
    memset(peer, 0x44, sizeof peer);

    /* Two distinct receipts with the SAME timestamp: canonical order is by
     * leaf-hash ASC. Order them so ord[0]'s leaf < ord[1]'s leaf. */
    a = make_receipt(sp, su, cp, cu, 10, 5000, 0x01);
    b = make_receipt(sp, su, cp, cu, 20, 5000, 0x02);
    ref_receipt_leaf(&a, la);
    ref_receipt_leaf(&b, lb);
    if (memcmp(la, lb, 32) < 0) {
        ord[0] = a;
        ord[1] = b;
    } else {
        ord[0] = b;
        ord[1] = a;
    }
    rev[0] = ord[1];
    rev[1] = ord[0];

    /* Canonical (timestamp tie broken by ascending leaf-hash) → accepted. */
    CHECK_EQ(ants_reputation_bag_root(ord, 2, peer, root), ANTS_OK);
    /* Reversed (leaf-hash descending at equal timestamp) → NON_CANONICAL. */
    CHECK_EQ(ants_reputation_bag_root(rev, 2, peer, root), ANTS_ERROR_NON_CANONICAL);
    /* prove rejects the same out-of-order input. */
    CHECK_EQ(ants_reputation_bag_prove(rev, 2, 0, path, sizeof path, &plen),
             ANTS_ERROR_NON_CANONICAL);

    /* Timestamps descending → NON_CANONICAL. */
    desc[0] = make_receipt(sp, su, cp, cu, 10, 6000, 0x03);
    desc[1] = make_receipt(sp, su, cp, cu, 10, 5999, 0x04);
    CHECK_EQ(ants_reputation_bag_root(desc, 2, peer, root), ANTS_ERROR_NON_CANONICAL);

    /* Exact duplicate (identical bytes → tie on both keys) → NON_CANONICAL. */
    dup[0] = make_receipt(sp, su, cp, cu, 10, 5000, 0x05);
    dup[1] = dup[0];
    CHECK_EQ(ants_reputation_bag_root(dup, 2, peer, root), ANTS_ERROR_NON_CANONICAL);
}

static void test_bag_args(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32], root[32];
    uint8_t path[ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
    size_t plen = 0;
    bool ok = false;
    ants_reputation_receipt_t r[4];
    size_t i;

    make_key(0x76, sp, su);
    make_key(0x77, cp, cu);
    memset(peer, 0x11, sizeof peer);
    for (i = 0; i < 4; i++) {
        r[i] = make_receipt(sp, su, cp, cu, 1 + i, 7000 + i, (uint8_t)(0xA0 + i));
    }

    /* bag_root: NULL guards, over-cap, and the empty-bag exception. */
    CHECK_EQ(ants_reputation_bag_root(r, 4, peer, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_root(r, 4, NULL, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_root(NULL, 4, peer, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_root(r, (size_t)ANTS_REP_MAX_RECEIPTS + 1, peer, root),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_root(NULL, 0, peer, root), ANTS_OK); /* empty bag OK */

    /* bag_prove: index >= n, n == 0, NULL, and BUFFER_TOO_SMALL reporting. */
    CHECK_EQ(ants_reputation_bag_prove(r, 4, 4, path, sizeof path, &plen), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_prove(r, 0, 0, path, sizeof path, &plen), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_prove(NULL, 4, 0, path, sizeof path, &plen),
             ANTS_ERROR_INVALID_ARG);
    /* path_cap 0 with a 4-leaf tree (needs 2 sibling hashes) → BUFFER_TOO_SMALL
     * with *out_path_len set to the requirement. */
    CHECK_EQ(ants_reputation_bag_prove(r, 4, 0, path, 0, &plen), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(plen == 2 * 32);

    /* bag_verify_inclusion: real path, then break each arg. */
    CHECK_EQ(ants_reputation_bag_prove(r, 4, 0, path, sizeof path, &plen), ANTS_OK);
    CHECK_EQ(ants_reputation_bag_root(r, 4, peer, root), ANTS_OK);
    CHECK_EQ(ants_reputation_bag_verify_inclusion(NULL, 0, 4, path, plen, peer, root, &ok),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_verify_inclusion(&r[0], 4, 4, path, plen, peer, root, &ok),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_verify_inclusion(&r[0], 0, 0, path, plen, peer, root, &ok),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_verify_inclusion(&r[0], 0, 4, NULL, plen, peer, root, &ok),
             ANTS_ERROR_INVALID_ARG);
    /* A path_len inconsistent with (index, n) is a hard INVALID_ARG, not a
     * false verdict. */
    CHECK_EQ(ants_reputation_bag_verify_inclusion(&r[0], 0, 4, path, plen - 1, peer, root, &ok),
             ANTS_ERROR_INVALID_ARG);
}

/* ---- selective disclosure: A >= b recompute ------------------------ */

/* Build openings for the given canonical indices: each gets its bag_prove
 * inclusion path (into caller-owned `paths`) bound to the receipt + index. */
static void bag_build_openings(const ants_reputation_receipt_t *bag,
                               size_t n,
                               const size_t *idx,
                               size_t k,
                               ants_reputation_bag_opening_t *out,
                               uint8_t paths[][ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32],
                               size_t *plens)
{
    size_t j;
    for (j = 0; j < k; j++) {
        plens[j] = 0;
        CHECK_EQ(ants_reputation_bag_prove(
                     bag, n, idx[j], paths[j], ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32, &plens[j]),
                 ANTS_OK);
        out[j].receipt = bag[idx[j]];
        out[j].index = idx[j];
        out[j].path = paths[j];
        out[j].path_len = plens[j];
    }
}

static void test_bag_bound_select_and_verify(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32], root[32];
    ants_reputation_params_t p;
    ants_reputation_receipt_t bag[5];
    ants_reputation_bag_opening_t op[5];
    uint8_t paths[5][ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
    size_t plens[5];
    size_t idx[5];
    size_t count = 0;
    bool reached = false, ok = false;
    uint64_t A_full = 0, T = 0;
    uint64_t now = 1000;
    size_t i;

    make_key(0x78, sp, su);
    make_key(0x79, cp, cu);
    memcpy(peer, su, 32); /* the committing peer == the server being scored */

    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    p.bin_width_s = 100;
    p.decay_ratio_a_q32 = ANTS_REP_FP_ONE >> 1; /* 0.5 */

    /* Canonical order (ts ASC); the most recent (ts == now) is age 0, so its
     * A contribution is exactly its ncs_value (decay factor 1.0). */
    bag[0] = make_receipt(sp, su, cp, cu, 1000, 600, 1);
    bag[1] = make_receipt(sp, su, cp, cu, 1000, 700, 2);
    bag[2] = make_receipt(sp, su, cp, cu, 1000, 800, 3);
    bag[3] = make_receipt(sp, su, cp, cu, 1000, 900, 4);
    bag[4] = make_receipt(sp, su, cp, cu, 1000, 1000, 5);

    CHECK_EQ(ants_reputation_bag_root(bag, 5, peer, root), ANTS_OK);
    CHECK_EQ(ants_reputation_compute(su, bag, 5, now, &p, &A_full, &T), ANTS_OK);
    CHECK(A_full > 0);

    /* Exact lower-bound boundary: reveal only the age-0 receipt (index 4),
     * contribution == 1000. Accept at b=1000, reject at b=1001. */
    idx[0] = 4;
    bag_build_openings(bag, 5, idx, 1, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 1, 5, peer, root, now, &p, 1000, &ok), ANTS_OK);
    CHECK(ok == true);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 1, 5, peer, root, now, &p, 1001, &ok), ANTS_OK);
    CHECK(ok == false);

    /* select_for_bound reaches a small bound with just the most-recent. */
    CHECK_EQ(
        ants_reputation_bag_select_for_bound(bag, 5, su, now, &p, 1000, idx, 5, &count, &reached),
        ANTS_OK);
    CHECK(reached == true);
    CHECK(count == 1 && idx[0] == 4); /* most-recent-first */
    bag_build_openings(bag, 5, idx, count, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, count, 5, peer, root, now, &p, 1000, &ok),
             ANTS_OK);
    CHECK(ok == true);

    /* b == full A: selection reaches it (revealing all eligible); verify ok. */
    CHECK_EQ(
        ants_reputation_bag_select_for_bound(bag, 5, su, now, &p, A_full, idx, 5, &count, &reached),
        ANTS_OK);
    CHECK(reached == true);
    bag_build_openings(bag, 5, idx, count, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, count, 5, peer, root, now, &p, A_full, &ok),
             ANTS_OK);
    CHECK(ok == true);

    /* b == full A + 1: unreachable, and revealing every receipt sums to A_full
     * (< b), so the verifier rejects (the lower bound cannot exceed true A). */
    CHECK_EQ(ants_reputation_bag_select_for_bound(
                 bag, 5, su, now, &p, A_full + 1, idx, 5, &count, &reached),
             ANTS_OK);
    CHECK(reached == false);
    for (i = 0; i < 5; i++) {
        idx[i] = i;
    }
    bag_build_openings(bag, 5, idx, 5, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 5, 5, peer, root, now, &p, A_full, &ok), ANTS_OK);
    CHECK(ok == true);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 5, 5, peer, root, now, &p, A_full + 1, &ok),
             ANTS_OK);
    CHECK(ok == false);
}

static void test_bag_bound_negatives(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], wp[32], wu[32], peer[32], root[32];
    ants_reputation_params_t p;
    ants_reputation_receipt_t bag[4];
    ants_reputation_bag_opening_t op[4];
    uint8_t paths[4][ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
    size_t plens[4];
    size_t idx[4] = {0, 1, 2, 3};
    bool ok = true;
    uint64_t now = 1000;

    make_key(0x7A, sp, su);
    make_key(0x7B, cp, cu);
    make_key(0x7C, wp, wu); /* a different server */
    (void)wp;
    memcpy(peer, su, 32);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    p.bin_width_s = 100;
    p.decay_ratio_a_q32 = ANTS_REP_FP_ONE >> 1;

    bag[0] = make_receipt(sp, su, cp, cu, 1000, 700, 1);
    bag[1] = make_receipt(sp, su, cp, cu, 1000, 800, 2);
    bag[2] = make_receipt(sp, su, cp, cu, 1000, 900, 3);
    bag[3] = make_receipt(sp, su, cp, cu, 1000, 1000, 4);
    CHECK_EQ(ants_reputation_bag_root(bag, 4, peer, root), ANTS_OK);

    /* A valid full reveal clears a low bound. */
    bag_build_openings(bag, 4, idx, 4, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 4, 4, peer, root, now, &p, 1000, &ok), ANTS_OK);
    CHECK(ok == true);

    /* Tamper one revealed receipt → its countersignature breaks → reject. */
    {
        ants_reputation_bag_opening_t bad[4];
        memcpy(bad, op, sizeof bad);
        bad[1].receipt.ncs_value += 1;
        CHECK_EQ(ants_reputation_bag_verify_bound(bad, 4, 4, peer, root, now, &p, 1, &ok), ANTS_OK);
        CHECK(ok == false);
    }
    /* Duplicate index → reject (no double-counting). */
    {
        ants_reputation_bag_opening_t dup[2];
        dup[0] = op[3];
        dup[1] = op[3];
        CHECK_EQ(ants_reputation_bag_verify_bound(dup, 2, 4, peer, root, now, &p, 1, &ok), ANTS_OK);
        CHECK(ok == false);
    }
    /* Wrong peer_id (receipts credit su, not wu) → reject. */
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 4, 4, wu, root, now, &p, 1, &ok), ANTS_OK);
    CHECK(ok == false);
    /* now earlier than a revealed receipt's timestamp → that opening is
     * future-dated → reject (op[3] has ts 1000 > now 999). */
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 4, 4, peer, root, 999, &p, 1, &ok), ANTS_OK);
    CHECK(ok == false);
    /* Right index/path but the WRONG receipt at it → Merkle inclusion fails. */
    {
        ants_reputation_bag_opening_t swp[4];
        ants_reputation_receipt_t tmp;
        memcpy(swp, op, sizeof swp);
        tmp = swp[0].receipt;
        swp[0].receipt = swp[1].receipt; /* index 0 now carries receipt 1 */
        swp[1].receipt = tmp;
        CHECK_EQ(ants_reputation_bag_verify_bound(swp, 4, 4, peer, root, now, &p, 1, &ok), ANTS_OK);
        CHECK(ok == false);
    }
}

static void test_bag_bound_args(void)
{
    uint8_t sp[32], su[32], cp[32], cu[32], peer[32], root[32];
    ants_reputation_params_t p, badp;
    ants_reputation_receipt_t bag[3];
    ants_reputation_bag_opening_t op[3];
    uint8_t paths[3][ANTS_REP_BAG_MERKLE_MAX_DEPTH * 32];
    size_t plens[3];
    size_t idx[3] = {0, 1, 2};
    size_t count = 9;
    bool reached = false, ok = true;
    uint64_t now = 1000;

    make_key(0x7D, sp, su);
    make_key(0x7E, cp, cu);
    memcpy(peer, su, 32);
    CHECK_EQ(ants_reputation_params_default(&p), ANTS_OK);
    p.bin_width_s = 100;
    bag[0] = make_receipt(sp, su, cp, cu, 1000, 800, 1);
    bag[1] = make_receipt(sp, su, cp, cu, 1000, 900, 2);
    bag[2] = make_receipt(sp, su, cp, cu, 1000, 1000, 3);
    CHECK_EQ(ants_reputation_bag_root(bag, 3, peer, root), ANTS_OK);

    /* select: b == 0 → reached immediately, empty subset. */
    CHECK_EQ(ants_reputation_bag_select_for_bound(bag, 3, su, now, &p, 0, idx, 3, &count, &reached),
             ANTS_OK);
    CHECK(reached == true && count == 0);

    /* select: NULL + degenerate-param + n guards. */
    CHECK_EQ(
        ants_reputation_bag_select_for_bound(NULL, 3, su, now, &p, 1, idx, 3, &count, &reached),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_select_for_bound(bag, 0, su, now, &p, 1, idx, 3, &count, &reached),
             ANTS_ERROR_INVALID_ARG);
    badp = p;
    badp.bin_width_s = 0;
    CHECK_EQ(
        ants_reputation_bag_select_for_bound(bag, 3, su, now, &badp, 1, idx, 3, &count, &reached),
        ANTS_ERROR_INVALID_ARG);

    /* select: needing more than indices_cap to reach b → BUFFER_TOO_SMALL.
     * Full A needs all 3 receipts; a cap of 1 cannot hold them. */
    {
        uint64_t A = 0, T = 0;
        size_t small[1];
        CHECK_EQ(ants_reputation_compute(su, bag, 3, now, &p, &A, &T), ANTS_OK);
        CHECK_EQ(ants_reputation_bag_select_for_bound(
                     bag, 3, su, now, &p, A, small, 1, &count, &reached),
                 ANTS_ERROR_BUFFER_TOO_SMALL);
    }

    /* verify_bound: k == 0 → ok iff b == 0. */
    CHECK_EQ(ants_reputation_bag_verify_bound(NULL, 0, 3, peer, root, now, &p, 0, &ok), ANTS_OK);
    CHECK(ok == true);
    CHECK_EQ(ants_reputation_bag_verify_bound(NULL, 0, 3, peer, root, now, &p, 1, &ok), ANTS_OK);
    CHECK(ok == false);

    /* verify_bound: NULL + degenerate-param guards. */
    bag_build_openings(bag, 3, idx, 3, op, paths, plens);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 3, 3, NULL, root, now, &p, 1, &ok),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 3, 3, peer, NULL, now, &p, 1, &ok),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 3, 3, peer, root, now, NULL, 1, &ok),
             ANTS_ERROR_INVALID_ARG);
    badp = p;
    badp.decay_ratio_a_q32 = 0;
    CHECK_EQ(ants_reputation_bag_verify_bound(op, 3, 3, peer, root, now, &badp, 1, &ok),
             ANTS_ERROR_INVALID_ARG);
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

    test_t_eff_pinned_values();
    test_t_eff_properties();
    test_t_eff_args();

    test_compute_checked_not_slashed();
    test_compute_checked_slashed_zeroes_both();
    test_compute_checked_null_predicate_equals_unchecked();
    test_compute_checked_args();

    test_bag_root_reference();
    test_bag_prove_verify();
    test_bag_canonical_order();
    test_bag_args();
    test_bag_bound_select_and_verify();
    test_bag_bound_negatives();
    test_bag_bound_args();

    if (failures > 0) {
        fprintf(stderr, "test_reputation: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_reputation: all checks passed\n");
    return 0;
}
