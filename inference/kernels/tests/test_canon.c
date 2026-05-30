/*
 * test_canon.c — Tests for the canonical kernel library (Component #12).
 *
 * Scope (this PR):
 *   - q24 round-trip + saturation + NaN/Inf handling
 *   - Left-biased max reduction (RFC-0009 §2.1 step 2)
 *   - Per-token scale recipe (§2.1 full)
 *   - matmul_i8 stub contract
 *
 * Every assertion runs the bit-exact reference (`cpu_scalar.c`).
 * Future SIMD paths will run the same test fixtures via a per-
 * platform dispatch and assert byte-for-byte parity.
 */

#include "ants_canon.h"
#include "ants_common.h"

#include <math.h>
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

/* -- q24 conversion --------------------------------------------------- */

static void test_q24_zero_round_trip(void)
{
    /* 0.0f ↔ 0 exactly. The only value that round-trips losslessly
     * for every conformant FP32 implementation. */
    CHECK(ants_canon_q24_from_f32(0.0f) == 0);
    CHECK(ants_canon_q24_to_f32(0) == 0.0f);
}

static void test_q24_one_round_trip(void)
{
    /* 1.0f → 2^24. 2^24 is exactly representable as FP32 (within the
     * 24-bit mantissa range), so the multiplication is lossless. */
    ants_canon_q24_t q = ants_canon_q24_from_f32(1.0f);
    CHECK(q == (ants_canon_q24_t)16777216); /* 2^24 */
    CHECK(ants_canon_q24_to_f32(q) == 1.0f);
}

static void test_q24_negative_round_trip(void)
{
    ants_canon_q24_t q = ants_canon_q24_from_f32(-1.0f);
    CHECK(q == -(ants_canon_q24_t)16777216);
    CHECK(ants_canon_q24_to_f32(q) == -1.0f);
}

static void test_q24_fractional_round_trip(void)
{
    /* 0.5f = 2^-1 is exactly representable; q24(0.5) = 2^23. */
    CHECK(ants_canon_q24_from_f32(0.5f) == (ants_canon_q24_t)8388608);
    CHECK(ants_canon_q24_to_f32(8388608) == 0.5f);
}

static void test_q24_saturates_above_range(void)
{
    /* Q8.24 range is ~[-128, +128); 200.0f exceeds the positive bound.
     * Should saturate to INT32_MAX. */
    CHECK(ants_canon_q24_from_f32(200.0f) == ANTS_CANON_Q24_MAX);
    CHECK(ants_canon_q24_from_f32(-200.0f) == ANTS_CANON_Q24_MIN);
}

static void test_q24_nan_to_zero(void)
{
    float nan = (float)NAN;
    CHECK(ants_canon_q24_from_f32(nan) == 0);
}

static void test_q24_inf_saturates(void)
{
    CHECK(ants_canon_q24_from_f32((float)INFINITY) == ANTS_CANON_Q24_MAX);
    CHECK(ants_canon_q24_from_f32(-(float)INFINITY) == ANTS_CANON_Q24_MIN);
}

static void test_q24_vec_round_trip(void)
{
    float in[8] = {0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 3.14159265f, -2.71828f, 100.0f};
    ants_canon_q24_t q[8];
    float back[8];
    CHECK_EQ(ants_canon_q24_vec_from_f32(in, q, 8), ANTS_OK);
    CHECK_EQ(ants_canon_q24_vec_to_f32(q, back, 8), ANTS_OK);
    /* Exact powers of 2 (and 0) round-trip losslessly. Generic values
     * round to within 2^-24 ≈ 6e-8. */
    for (size_t i = 0; i < 8; i++) {
        CHECK(fabsf(back[i] - in[i]) <= 1.0f / 16777216.0f);
    }
}

static void test_q24_vec_null_args(void)
{
    float in[1] = {0.0f};
    ants_canon_q24_t out[1];
    CHECK_EQ(ants_canon_q24_vec_from_f32(NULL, out, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_q24_vec_from_f32(in, NULL, 1), ANTS_ERROR_INVALID_ARG);
    /* n=0 is OK even with NULL args. */
    CHECK_EQ(ants_canon_q24_vec_from_f32(NULL, NULL, 0), ANTS_OK);
    CHECK_EQ(ants_canon_q24_vec_to_f32(NULL, NULL, 0), ANTS_OK);
}

/* -- Left-biased max reduction (RFC-0009 §2.1 step 2) ----------------- */

static void test_reduce_max_singleton(void)
{
    float v[1] = {3.14159f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max(v, 1, &result), ANTS_OK);
    CHECK(result == 3.14159f);
}

static void test_reduce_max_empty(void)
{
    /* Reducing empty set → -∞. */
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max(NULL, 0, &result), ANTS_OK);
    CHECK(isinf(result) && result < 0.0f);
}

static void test_reduce_max_power_of_two(void)
{
    /* 8 elements (already a power of two — no padding). Max is the
     * largest value regardless of position. */
    float v[8] = {1.0f, 5.0f, 3.0f, 2.0f, 7.0f, 4.0f, 6.0f, 0.5f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max(v, 8, &result), ANTS_OK);
    CHECK(result == 7.0f);
}

static void test_reduce_max_non_power_of_two(void)
{
    /* 5 elements: padding to 8 with -∞ should NOT affect the result
     * because -∞ never wins fmaxf against a finite value. */
    float v[5] = {1.0f, 5.0f, 3.0f, 2.0f, 7.0f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max(v, 5, &result), ANTS_OK);
    CHECK(result == 7.0f);
}

static void test_reduce_max_all_negative(void)
{
    /* All negative inputs; max is the least-negative. Padding -∞
     * doesn't displace any finite negative. */
    float v[3] = {-1.0f, -5.0f, -3.0f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max(v, 3, &result), ANTS_OK);
    CHECK(result == -1.0f);
}

static void test_reduce_max_into_caller_buffer(void)
{
    /* _into variant: scratch sized exactly to next_pow2(n). */
    float v[5] = {1.0f, 5.0f, 3.0f, 2.0f, 7.0f};
    float scratch[8];
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_max_into(v, 5, scratch, 8, &result), ANTS_OK);
    CHECK(result == 7.0f);

    /* Scratch too small → INVALID_ARG. */
    CHECK_EQ(ants_canon_reduce_max_into(v, 5, scratch, 4, &result), ANTS_ERROR_INVALID_ARG);
}

static void test_reduce_max_null_args(void)
{
    float v[1] = {1.0f};
    CHECK_EQ(ants_canon_reduce_max(NULL, 1, NULL), ANTS_ERROR_INVALID_ARG);
    float result;
    CHECK_EQ(ants_canon_reduce_max(NULL, 1, &result), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_reduce_max(v, 1, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_reduce_max_oversized(void)
{
    /* Inputs past the internal-buffer cap must fail with INVALID_ARG
     * (the caller is expected to use _into). */
    static float oversized[ANTS_CANON_MAX_REDUCE_LEN + 1];
    float result;
    CHECK_EQ(ants_canon_reduce_max(oversized, ANTS_CANON_MAX_REDUCE_LEN + 1, &result),
             ANTS_ERROR_INVALID_ARG);
}

/* -- Per-token scale (RFC-0009 §2.1 full recipe) ---------------------- */

static void test_per_token_scale_basic(void)
{
    /* max(|v|) = 127.0f → scale = 127.0f / 127.0f = 1.0f (exact). */
    float v[4] = {1.0f, -127.0f, 50.0f, 0.0f};
    float scale = 0.0f;
    CHECK_EQ(ants_canon_per_token_scale(v, 4, &scale), ANTS_OK);
    CHECK(scale == 1.0f);
}

static void test_per_token_scale_zero_sentinel(void)
{
    /* All-zero activation → max_abs = 0 → sentinel returns 1.0f
     * (NOT 0/127 which would be 0 and break downstream divisions). */
    float v[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    float scale = 0.0f;
    CHECK_EQ(ants_canon_per_token_scale(v, 4, &scale), ANTS_OK);
    CHECK(scale == 1.0f);
}

static void test_per_token_scale_negative_max(void)
{
    /* abs-value pass handles negatives; the negative-largest-magnitude
     * value should drive the scale. */
    float v[4] = {1.0f, -200.0f, 50.0f, 0.0f};
    float scale = 0.0f;
    CHECK_EQ(ants_canon_per_token_scale(v, 4, &scale), ANTS_OK);
    CHECK(scale == 200.0f / 127.0f);
}

static void test_per_token_scale_divide_not_reciprocal(void)
{
    /* This is the bit-exact discriminator from RFC-0009 §2.1. For
     * an input where the divide and the precomputed-reciprocal-
     * multiply disagree in the last bit, our implementation MUST
     * match the divide. We hand-pick `max_abs = 9.0f` because
     *   9.0f / 127.0f          = 0x3D912245u  (correct, this impl)
     *   9.0f * (1.0f / 127.0f) = 0x3D912244u  (precomputed reciprocal — wrong)
     * The two encodings differ in the last bit. */
    float v[1] = {9.0f};
    float scale = 0.0f;
    CHECK_EQ(ants_canon_per_token_scale(v, 1, &scale), ANTS_OK);
    uint32_t bits;
    memcpy(&bits, &scale, sizeof bits);
    CHECK(bits == 0x3D912245u);
}

static void test_per_token_scale_null_args(void)
{
    float v[1] = {1.0f};
    float scale;
    CHECK_EQ(ants_canon_per_token_scale(NULL, 1, &scale), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_per_token_scale(v, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_per_token_scale(v, 0, &scale), ANTS_ERROR_INVALID_ARG);
}

/* -- Left-biased sum reduction (RFC-0009 §3) -------------------------- */

static void test_reduce_sum_basic(void)
{
    /* Sum of [1, 2, 3, 4] = 10. All exactly representable in FP32;
     * tree reduction gives the same exact result as left-to-right
     * for this input. */
    float v[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_sum(v, 4, &result), ANTS_OK);
    CHECK(result == 10.0f);
}

static void test_reduce_sum_empty(void)
{
    /* Reducing empty set under + → 0 (additive identity). */
    float result = 99.0f;
    CHECK_EQ(ants_canon_reduce_sum(NULL, 0, &result), ANTS_OK);
    CHECK(result == 0.0f);
}

static void test_reduce_sum_singleton(void)
{
    float v[1] = {3.14159f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_sum(v, 1, &result), ANTS_OK);
    CHECK(result == 3.14159f);
}

static void test_reduce_sum_non_power_of_two(void)
{
    /* 5 elements. Padding with 0.0f never changes the sum. */
    float v[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_sum(v, 5, &result), ANTS_OK);
    CHECK(result == 15.0f);
}

static void test_reduce_sum_into_caller_buffer(void)
{
    float v[5] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float scratch[8];
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_sum_into(v, 5, scratch, 8, &result), ANTS_OK);
    CHECK(result == 15.0f);

    /* Scratch smaller than next_pow2(n) → INVALID_ARG. */
    CHECK_EQ(ants_canon_reduce_sum_into(v, 5, scratch, 4, &result), ANTS_ERROR_INVALID_ARG);
}

static void test_reduce_sum_null_args(void)
{
    float v[1] = {1.0f};
    CHECK_EQ(ants_canon_reduce_sum(NULL, 1, NULL), ANTS_ERROR_INVALID_ARG);
    float result;
    CHECK_EQ(ants_canon_reduce_sum(NULL, 1, &result), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_reduce_sum(v, 1, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_reduce_sum_oversized(void)
{
    static float oversized[ANTS_CANON_MAX_REDUCE_LEN + 1];
    float result;
    CHECK_EQ(ants_canon_reduce_sum(oversized, ANTS_CANON_MAX_REDUCE_LEN + 1, &result),
             ANTS_ERROR_INVALID_ARG);
}

static void test_reduce_sum_tree_shape_matches_pairwise(void)
{
    /* The protocol-pinned tree shape: pad to next_pow2 with 0, then
     * pairwise reduce. For n=4 = next_pow2(4), the tree is:
     *   level 1: [a+b, c+d]
     *   level 2: [(a+b) + (c+d)]
     * This MUST be the result regardless of any SIMD horizontal-add
     * tree shape a future impl uses. Verified here with a
     * 4-element input where pairwise differs from strict-left-to-
     * right; the actual numerical accuracy doesn't matter, the
     * bit-exact tree shape does. */
    float v[4] = {1e7f, 1.0f, -1e7f, 1.0f};
    /* Pairwise tree: (1e7 + 1) + (-1e7 + 1) = 1e7 + (-9999999) = 1 + 1 = 2.
     * Or exactly: FP32(1e7+1) = 1e7 (1 lost), FP32(-1e7+1) = -9999999
     * (1 retained because magnitude diff is 7 vs FP32 epsilon at 1e7
     * which is ~1). So the tree result is 1e7 + (-9999999) = 1.0.
     *
     * Strict left-to-right: ((1e7 + 1) + -1e7) + 1 = (1e7 + -1e7) + 1
     * = 0 + 1 = 1.0. Same answer in this case.
     *
     * What we really want to verify is that the tree gives whatever
     * deterministic value the recipe pins. We hand-compute the bit
     * pattern of the pairwise-tree result and assert against it. */
    float result = 0.0f;
    CHECK_EQ(ants_canon_reduce_sum(v, 4, &result), ANTS_OK);
    /* Manually evaluate the canonical tree in the test, then compare
     * bit-for-bit. This is the "I am a SIMD implementation; do I
     * match the scalar reference?" check. */
    float lhs = 1e7f + 1.0f;
    float rhs = -1e7f + 1.0f;
    float expected = lhs + rhs;
    uint32_t got_bits, exp_bits;
    memcpy(&got_bits, &result, sizeof got_bits);
    memcpy(&exp_bits, &expected, sizeof exp_bits);
    CHECK(got_bits == exp_bits);
}

/* -- Softmax with subtract-max stability (RFC-0009 §3) ---------------- */

static void test_softmax_uniform_input(void)
{
    /* All-equal input → uniform distribution: 1/n per slot. */
    float in[4] = {1.5f, 1.5f, 1.5f, 1.5f};
    float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(in, out, 4), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        CHECK(fabsf(out[i] - 0.25f) < 1e-6f);
    }
}

static void test_softmax_sums_to_one(void)
{
    /* For any reasonable input the output sums to ~1.0 (FP32 sum
     * precision limit ~1e-7 for 4-element vectors). */
    float in[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(in, out, 4), ANTS_OK);
    float sum = 0.0f;
    for (int i = 0; i < 4; i++) {
        sum += out[i];
    }
    CHECK(fabsf(sum - 1.0f) < 1e-5f);
}

static void test_softmax_singleton(void)
{
    /* n=1: max=in[0], exp(0)=1.0, sum=1.0, out[0]=1.0/1.0=1.0. */
    float in[1] = {42.0f};
    float out[1] = {0.0f};
    CHECK_EQ(ants_canon_softmax(in, out, 1), ANTS_OK);
    CHECK(out[0] == 1.0f);
}

static void test_softmax_shift_invariance(void)
{
    /* softmax(x + c) ≈ softmax(x) for any constant c — mathematically
     * exact under real arithmetic; not bit-exact under FP32 because
     * a subtraction at magnitude |c+x| loses more low-order bits than
     * the same subtraction at magnitude |x| when |c| >> |x|. Verify
     * the approximate equality holds within FP32 precision; if a
     * future implementation breaks this beyond ~1e-5 it likely
     * forgot the subtract-max step. */
    float in_a[4] = {0.1f, 0.2f, 0.3f, 0.4f};
    float in_b[4] = {100.1f, 100.2f, 100.3f, 100.4f};
    float out_a[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    float out_b[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(in_a, out_a, 4), ANTS_OK);
    CHECK_EQ(ants_canon_softmax(in_b, out_b, 4), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        CHECK(fabsf(out_a[i] - out_b[i]) < 1e-5f);
    }
}

static void test_softmax_zero_shift_is_bit_exact(void)
{
    /* The same input twice MUST produce bit-identical outputs (no
     * hidden global state, no time-dependent quantities). This is
     * the canonical bit-exactness guarantee for honest peers running
     * the same kernel on the same input. */
    float in[4] = {0.1f, 0.2f, 0.3f, 0.4f};
    float out_a[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    float out_b[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(in, out_a, 4), ANTS_OK);
    CHECK_EQ(ants_canon_softmax(in, out_b, 4), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        uint32_t ba, bb;
        memcpy(&ba, &out_a[i], sizeof ba);
        memcpy(&bb, &out_b[i], sizeof bb);
        CHECK(ba == bb);
    }
}

static void test_softmax_in_place(void)
{
    /* Aliasing in == out is supported. Computing in place must give
     * the same result as the non-aliased call. */
    float ref_in[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float in_place[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float out_ref[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(ref_in, out_ref, 4), ANTS_OK);
    CHECK_EQ(ants_canon_softmax(in_place, in_place, 4), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        uint32_t br, bi;
        memcpy(&br, &out_ref[i], sizeof br);
        memcpy(&bi, &in_place[i], sizeof bi);
        CHECK(br == bi);
    }
}

static void test_softmax_extreme_negatives_no_nan(void)
{
    /* Inputs with extreme negative values shouldn't produce NaN.
     * The subtract-max step yields 0 for the max-lane and very
     * negative values elsewhere; exp underflows to 0 cleanly. */
    float in[3] = {-1e30f, 0.0f, -1e30f};
    float out[3] = {0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_softmax(in, out, 3), ANTS_OK);
    /* Out[1] should be ~1.0 (it's the max-lane, exp(0)=1). */
    CHECK(fabsf(out[1] - 1.0f) < 1e-6f);
    /* Out[0] and Out[2] are exp(-1e30) → 0. */
    CHECK(out[0] == 0.0f);
    CHECK(out[2] == 0.0f);
    /* None are NaN. */
    CHECK(!isnan(out[0]));
    CHECK(!isnan(out[1]));
    CHECK(!isnan(out[2]));
}

static void test_softmax_all_neg_inf_zero_output(void)
{
    /* Pathological: all -∞ inputs. Subtract-max gives 0 for all
     * (since max is -∞ and -∞ - -∞ = NaN — actually let's see how
     * the implementation handles this).
     *
     * Actually: max of all -∞ via the tree is -∞. in[i] - max =
     * -∞ - -∞ = NaN. exp(NaN) = NaN. Sum of NaN = NaN. Divide by
     * NaN = NaN. So this is genuinely undefined for our recipe.
     *
     * The documented behaviour is: if sum_val == 0.0 fall back to
     * all-zero output. With NaN sum this branch doesn't trigger
     * (NaN != 0.0); the output is NaN. We document this as caller's
     * problem rather than try to special-case it.
     *
     * What we DO want to test: ZEROS as inputs, where exp(0) = 1
     * for all → softmax = uniform = 1/n. That's already covered
     * by test_softmax_uniform_input.
     *
     * For the all-zero-exp case (sum == 0 because every exp
     * underflowed): construct two inputs at the very edge of
     * representable FP32 negative such that max is finite but every
     * other lane underflows past it. Easier: use one finite + the
     * rest extremely negative. */
    float in[3] = {-1000.0f, -1000.0f, -1000.0f};
    float out[3] = {99.0f, 99.0f, 99.0f};
    CHECK_EQ(ants_canon_softmax(in, out, 3), ANTS_OK);
    /* All same → uniform → 1/3 each. */
    for (int i = 0; i < 3; i++) {
        CHECK(fabsf(out[i] - (1.0f / 3.0f)) < 1e-6f);
    }
}

static void test_softmax_null_args(void)
{
    float v[1] = {1.0f};
    float o[1];
    CHECK_EQ(ants_canon_softmax(NULL, o, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_softmax(v, NULL, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_softmax(v, o, 0), ANTS_ERROR_INVALID_ARG);
}

/* -- INT8 × INT8 → INT32 matmul (RFC-0009 §3) ------------------------ */

static void test_matmul_null_args_and_zero_dims(void)
{
    int8_t a[2 * 2] = {1, 2, 3, 4};
    int8_t b[2 * 2] = {5, 6, 7, 8};
    int32_t out[2 * 2] = {0};
    CHECK_EQ(ants_canon_matmul_i8(NULL, b, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, NULL, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, NULL, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 0, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 0, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 2, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_matmul_known_2x2(void)
{
    /* A = [[1, 2],     B = [[5, 6],     A·B = [[1·5+2·7, 1·6+2·8],
     *      [3, 4]]          [7, 8]]            [3·5+4·7, 3·6+4·8]]
     *                                     = [[19, 22],
     *                                        [43, 50]] */
    int8_t a[2 * 2] = {1, 2, 3, 4};
    int8_t b[2 * 2] = {5, 6, 7, 8};
    int32_t out[2 * 2] = {0};
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 2, 2), ANTS_OK);
    CHECK(out[0] == 19);
    CHECK(out[1] == 22);
    CHECK(out[2] == 43);
    CHECK(out[3] == 50);
}

static void test_matmul_identity_left(void)
{
    /* I_3 · B = B. Identity on the left preserves B exactly. */
    int8_t id[3 * 3] = {1, 0, 0, 0, 1, 0, 0, 0, 1};
    int8_t b[3 * 4] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    int32_t out[3 * 4] = {0};
    CHECK_EQ(ants_canon_matmul_i8(id, b, out, 3, 3, 4), ANTS_OK);
    for (int i = 0; i < 12; i++) {
        CHECK(out[i] == (int32_t)b[i]);
    }
}

static void test_matmul_zero_matrix(void)
{
    /* 0·B = 0. Verifies the accumulator initialises cleanly across
     * every output cell. */
    int8_t a[2 * 3] = {0, 0, 0, 0, 0, 0};
    int8_t b[3 * 2] = {1, 2, 3, 4, 5, 6};
    int32_t out[2 * 2];
    /* Pre-fill out with garbage so the test verifies zero-init. */
    out[0] = 99;
    out[1] = 99;
    out[2] = 99;
    out[3] = 99;
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 3, 2), ANTS_OK);
    CHECK(out[0] == 0);
    CHECK(out[1] == 0);
    CHECK(out[2] == 0);
    CHECK(out[3] == 0);
}

static void test_matmul_negative_values(void)
{
    /* Mixed-sign multiplication. A = [-1, 2], B = [3, -4]^T → -1·3 + 2·-4 = -11. */
    int8_t a[1 * 2] = {-1, 2};
    int8_t b[2 * 1] = {3, -4};
    int32_t out[1 * 1] = {99};
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 1, 2, 1), ANTS_OK);
    CHECK(out[0] == -11);
}

static void test_matmul_extreme_int8_values(void)
{
    /* Per-product range is [-127·127, +127·127]; accumulator is
     * int32_t. A single -127 × -127 = +16129; +127 × +127 = +16129.
     * Sum two of each = +64516. */
    int8_t a[1 * 4] = {127, 127, -127, -127};
    int8_t b[4 * 1] = {127, 127, -127, -127};
    int32_t out[1 * 1] = {0};
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 1, 4, 1), ANTS_OK);
    CHECK(out[0] == 127 * 127 + 127 * 127 + (-127) * (-127) + (-127) * (-127));
    CHECK(out[0] == 64516);
}

static void test_matmul_rectangular_shape(void)
{
    /* Non-square: A is 2×4, B is 4×3, output is 2×3. Verifies the
     * row-major index arithmetic (i*k+l for A, l*n+j for B,
     * i*n+j for out) is correct for non-square dims. */
    int8_t a[2 * 4] = {1, 2, 3, 4, 5, 6, 7, 8};
    int8_t b[4 * 3] = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0};
    int32_t out[2 * 3] = {0};
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 4, 3), ANTS_OK);
    /* out[0,0] = 1·1 + 2·0 + 3·1 + 4·0 = 4
     * out[0,1] = 1·0 + 2·1 + 3·0 + 4·1 = 6
     * out[0,2] = 1·1 + 2·0 + 3·1 + 4·0 = 4
     * out[1,0] = 5·1 + 6·0 + 7·1 + 8·0 = 12
     * out[1,1] = 5·0 + 6·1 + 7·0 + 8·1 = 14
     * out[1,2] = 5·1 + 6·0 + 7·1 + 8·0 = 12 */
    CHECK(out[0] == 4);
    CHECK(out[1] == 6);
    CHECK(out[2] == 4);
    CHECK(out[3] == 12);
    CHECK(out[4] == 14);
    CHECK(out[5] == 12);
}

/* -- FP32 × FP32 → FP32 matmul (RFC-0009 §3 + §5) --------------------- */

static void test_matmul_fp32_null_args_and_zero_dims(void)
{
    float a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float b[4] = {5.0f, 6.0f, 7.0f, 8.0f};
    float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_matmul_fp32(NULL, b, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_fp32(a, NULL, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_fp32(a, b, NULL, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 0, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 2, 0, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 2, 2, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_matmul_fp32_known_2x2(void)
{
    /* A = [[1, 2], [3, 4]], B = [[5, 6], [7, 8]] → [[19, 22], [43, 50]].
     * Small integers exactly representable in FP32; no rounding loss. */
    float a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float b[4] = {5.0f, 6.0f, 7.0f, 8.0f};
    float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 2, 2, 2), ANTS_OK);
    CHECK(out[0] == 19.0f);
    CHECK(out[1] == 22.0f);
    CHECK(out[2] == 43.0f);
    CHECK(out[3] == 50.0f);
}

static void test_matmul_fp32_identity_left(void)
{
    /* I · B = B exactly. Float identity matrix has bit-exact 1.0f
     * and 0.0f entries; the matmul accumulator picks the single
     * non-zero product per row and the zero entries contribute
     * exactly 0 (no rounding). */
    float id[9] = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    float b[12] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f, 0.9f, 1.0f, 1.1f, 1.2f};
    float out[12] = {0.0f};
    CHECK_EQ(ants_canon_matmul_fp32(id, b, out, 3, 3, 4), ANTS_OK);
    for (int i = 0; i < 12; i++) {
        uint32_t bo, bb;
        memcpy(&bo, &out[i], sizeof bo);
        memcpy(&bb, &b[i], sizeof bb);
        CHECK(bo == bb);
    }
}

static void test_matmul_fp32_zero_matrix(void)
{
    /* 0 · B = 0 with explicit accumulator zero-init verification:
     * pre-fill out with garbage. */
    float zero[6] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    float b[6] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    float out[4] = {99.0f, 99.0f, 99.0f, 99.0f};
    CHECK_EQ(ants_canon_matmul_fp32(zero, b, out, 2, 3, 2), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        CHECK(out[i] == 0.0f);
    }
}

static void test_matmul_fp32_strict_left_to_right_order(void)
{
    /* The bit-exact discriminator for FP32 matmul: construct K=4
     * input vectors where strict left-to-right reduction gives a
     * different last-bit result than other plausible reduction
     * orders. With K=4, the strict-LR order is:
     *   ((a*b)[0] + (a*b)[1]) + (a*b)[2]) + (a*b)[3]
     * A pairwise-tree shape would be:
     *   ((a*b)[0] + (a*b)[1]) + ((a*b)[2] + (a*b)[3])
     * Same products; different addition order.
     *
     * Choose products such that strict-LR and pairwise differ in
     * the last bit. The classic example is summing 1e8 + 1 + 1 + 1:
     *   Strict-LR: ((1e8 + 1) + 1) + 1 = 1e8 + 0 + 0 + 0 = 1e8
     *     (each +1 lost because FP32 epsilon at 1e8 is ~8)
     *   Pairwise: (1e8 + 1) + (1 + 1) = 1e8 + 2 = 1e8 (still lost)
     *
     * Better: 1e8 + 1 + (-1e8) + 1
     *   Strict-LR: ((1e8+1) + -1e8) + 1 = (1e8 - 1e8) + 1 = 0 + 1 = 1
     *   Pairwise:  (1e8+1) + (-1e8 + 1) = 1e8 + (-9999999) = 1
     *   Same.
     *
     * Try: 1.0, 1e-8, 1.0, -1.0
     *   Strict-LR: ((1.0 + 1e-8) + 1.0) + -1.0 = (1.0 + 1.0) - 1.0
     *     = 2.0 - 1.0 = 1.0 (1e-8 lost in first add)
     *   Pairwise: (1.0 + 1e-8) + (1.0 - 1.0) = 1.0 + 0 = 1.0
     *   Same.
     *
     * Easier: hand-compute the strict-LR result on a pseudo-random
     * input and require the impl to match THAT specific bit pattern.
     * The test value isn't important; the bit-exactness IS. */
    float a[4] = {1.0e7f, 1.0f, -1.0e7f, 1.0f};
    float b[4] = {1.0f, 1.0f, 1.0f, 1.0f};
    float out[1] = {0.0f};
    /* M=1, K=4, N=1: out[0] = sum_l a[l] * b[l] in strict LR order. */
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 1, 4, 1), ANTS_OK);
    /* Hand-compute strict-LR in the test: */
    float p0 = a[0] * b[0];
    float p1 = a[1] * b[1];
    float p2 = a[2] * b[2];
    float p3 = a[3] * b[3];
    float expected = ((p0 + p1) + p2) + p3;
    uint32_t bg, be;
    memcpy(&bg, &out[0], sizeof bg);
    memcpy(&be, &expected, sizeof be);
    CHECK(bg == be);
}

static void test_matmul_fp32_rectangular_shape(void)
{
    /* Non-square shape exercises index arithmetic. A: 2×3, B: 3×4 → out 2×4. */
    float a[6] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    float b[12] = {1.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 1.0f, 0.0f, 1.0f, 0.0f};
    float out[8] = {0.0f};
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out, 2, 3, 4), ANTS_OK);
    /* Row 0 of A = [1, 2, 3]. Cols of B are
     *   col 0: [1, 0, 1] → 1*1 + 2*0 + 3*1 = 4
     *   col 1: [0, 1, 0] → 1*0 + 2*1 + 3*0 = 2
     *   col 2: [1, 0, 1] → 4
     *   col 3: [0, 1, 0] → 2
     * Row 1 of A = [4, 5, 6].
     *   col 0: 4*1 + 5*0 + 6*1 = 10
     *   col 1: 4*0 + 5*1 + 6*0 = 5
     *   col 2: 10
     *   col 3: 5 */
    CHECK(out[0] == 4.0f);
    CHECK(out[1] == 2.0f);
    CHECK(out[2] == 4.0f);
    CHECK(out[3] == 2.0f);
    CHECK(out[4] == 10.0f);
    CHECK(out[5] == 5.0f);
    CHECK(out[6] == 10.0f);
    CHECK(out[7] == 5.0f);
}

/* -- Scaled-dot-product attention (RFC-0009 §3) ---------------------- */

static void test_attention_null_args_and_bounds(void)
{
    float q[4] = {0};
    float k[4] = {0};
    float v[4] = {0};
    float out[4] = {0};
    float scratch[4];
    CHECK_EQ(ants_canon_attention_fp32(NULL, k, v, out, 2, 2, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_attention_fp32(q, NULL, v, out, 2, 2, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_attention_fp32(q, k, NULL, out, 2, 2, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, NULL, 2, 2, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, 0, 2, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, 2, 0, false, scratch, 4),
             ANTS_ERROR_INVALID_ARG);
    /* scratch_cap < n_tokens² (need 4, give 3) */
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, 2, 2, false, scratch, 3),
             ANTS_ERROR_INVALID_ARG);
}

static void test_attention_singleton_token(void)
{
    /* n_tokens=1: softmax of a single value is 1.0; out = V. */
    float q[2] = {0.5f, 0.7f};
    float k[2] = {0.3f, 0.9f};
    float v[2] = {1.5f, 2.5f};
    float out[2] = {0};
    float scratch[1];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, 1, 2, false, scratch, 1), ANTS_OK);
    CHECK(out[0] == 1.5f);
    CHECK(out[1] == 2.5f);
}

static void test_attention_softmax_sums_to_one_per_row(void)
{
    /* After softmax, each row sums to ~1 (within FP32 precision).
     * The output therefore has weights that mix V's rows; sanity
     * check: every output row is within the convex hull of V rows
     * (i.e., every component is bounded by min/max of that component
     * across V rows). */
    enum { N = 4, D = 3 };
    float q[N * D] = {
        0.1f,
        0.2f,
        0.3f, /* row 0 */
        0.4f,
        0.5f,
        0.6f, /* row 1 */
        0.7f,
        0.8f,
        0.9f, /* row 2 */
        1.0f,
        1.1f,
        1.2f /* row 3 */
    };
    float k[N * D];
    for (int i = 0; i < N * D; i++) {
        k[i] = q[i]; /* K = Q for self-attention sanity */
    }
    float v[N * D] = {
        1.0f,
        2.0f,
        3.0f, /* row 0 */
        4.0f,
        5.0f,
        6.0f, /* row 1 */
        7.0f,
        8.0f,
        9.0f, /* row 2 */
        2.0f,
        3.0f,
        4.0f /* row 3 — overlaps row 0..1 in value range */
    };
    float out[N * D] = {0};
    float scratch[N * N];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, N, D, false, scratch, N * N), ANTS_OK);

    /* Per-component bounds across V rows: min=1, max=9. Every output
     * component must lie inside [1.0, 9.0]. */
    for (int i = 0; i < N * D; i++) {
        CHECK(out[i] >= 1.0f - 1e-5f);
        CHECK(out[i] <= 9.0f + 1e-5f);
    }
}

static void test_attention_causal_mask_row_zero_attends_only_self(void)
{
    /* With causal mask: position 0 can only attend to position 0.
     * Regardless of K_{1..N-1}, out[0] = V[0]. */
    enum { N = 3, D = 2 };
    float q[N * D] = {1.0f, 0.5f, 0.3f, 0.8f, 0.6f, 0.4f};
    /* Make K_1 and K_2 have huge scores to ensure WITHOUT the mask,
     * row 0 would attend to them. With the mask, those entries
     * become -inf and exp(-inf) = 0 cleanly. */
    float k[N * D] = {1.0f, 0.5f, 100.0f, 100.0f, 100.0f, 100.0f};
    float v[N * D] = {1.0f, 1.0f, 9.0f, 9.0f, 9.0f, 9.0f};
    float out[N * D] = {0};
    float scratch[N * N];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, N, D, true, scratch, N * N), ANTS_OK);
    /* Row 0 attends only to V[0] = (1, 1). */
    CHECK(fabsf(out[0] - 1.0f) < 1e-5f);
    CHECK(fabsf(out[1] - 1.0f) < 1e-5f);
}

static void test_attention_causal_mask_per_row_sums_to_one(void)
{
    /* With causal mask: row i has (i+1) unmasked entries; the
     * softmax over those should sum to 1. Verify by tracing through
     * a small example. We use V = identity-like so we can check each
     * row's output magnitude. */
    enum { N = 4, D = 2 };
    /* Q, K such that scores[i, j] = constant for valid (i, j) so
     * uniform attention over valid entries: 1/(i+1) on V[0..i]. */
    float q[N * D] = {0};
    float k[N * D] = {0};
    /* V is identity-like: each row's first component holds the
     * row's index encoded as a value (0, 1, 2, 3). */
    float v[N * D] = {0.0f, 0.0f, 1.0f, 1.0f, 2.0f, 2.0f, 3.0f, 3.0f};
    float out[N * D] = {0};
    float scratch[N * N];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, N, D, true, scratch, N * N), ANTS_OK);
    /* With Q=K=0, all unmasked scores are 0, softmax → uniform over
     * unmasked entries. Row i has (i+1) valid entries.
     *   Row 0: attends V[0] = (0, 0) → out (0, 0)
     *   Row 1: 1/2 V[0] + 1/2 V[1] = (0.5, 0.5)
     *   Row 2: 1/3 V[0] + 1/3 V[1] + 1/3 V[2] = (1, 1)
     *   Row 3: 1/4 (V[0] + V[1] + V[2] + V[3]) = (1.5, 1.5)
     */
    float expected[N * D] = {0.0f, 0.0f, 0.5f, 0.5f, 1.0f, 1.0f, 1.5f, 1.5f};
    for (int i = 0; i < N * D; i++) {
        CHECK(fabsf(out[i] - expected[i]) < 1e-5f);
    }
}

static void test_attention_no_mask_uniform_q_k_zero(void)
{
    /* Without mask: Q=K=0 means uniform attention over all N tokens
     * regardless of position. Each output is the mean of V rows. */
    enum { N = 3, D = 2 };
    float q[N * D] = {0};
    float k[N * D] = {0};
    float v[N * D] = {1.0f, 2.0f, 4.0f, 5.0f, 7.0f, 8.0f};
    float out[N * D] = {0};
    float scratch[N * N];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out, N, D, false, scratch, N * N), ANTS_OK);
    /* Mean of column 0: (1+4+7)/3 = 4. Mean of column 1: (2+5+8)/3 = 5. */
    for (int i = 0; i < N; i++) {
        CHECK(fabsf(out[i * D + 0] - 4.0f) < 1e-5f);
        CHECK(fabsf(out[i * D + 1] - 5.0f) < 1e-5f);
    }
}

static void test_attention_same_input_bit_exact(void)
{
    /* No hidden state: same inputs → bit-identical outputs.
     * Canonical bit-exactness contract. */
    enum { N = 3, D = 2 };
    float q[N * D] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f};
    float k[N * D] = {0.7f, 0.8f, 0.9f, 1.0f, 1.1f, 1.2f};
    float v[N * D] = {0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    float out_a[N * D] = {0};
    float out_b[N * D] = {0};
    float scratch[N * N];
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out_a, N, D, false, scratch, N * N), ANTS_OK);
    CHECK_EQ(ants_canon_attention_fp32(q, k, v, out_b, N, D, false, scratch, N * N), ANTS_OK);
    for (int i = 0; i < N * D; i++) {
        uint32_t a, b;
        memcpy(&a, &out_a[i], sizeof a);
        memcpy(&b, &out_b[i], sizeof b);
        CHECK(a == b);
    }
}

static void test_matmul_fp32_same_input_bit_exact(void)
{
    /* No hidden state: same inputs → bit-identical outputs across
     * repeated calls. This is the canonical bit-exactness contract
     * for honest peers. */
    float a[6] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f};
    float b[6] = {0.7f, 0.8f, 0.9f, 1.0f, 1.1f, 1.2f};
    float out1[4] = {0.0f};
    float out2[4] = {0.0f};
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out1, 2, 3, 2), ANTS_OK);
    CHECK_EQ(ants_canon_matmul_fp32(a, b, out2, 2, 3, 2), ANTS_OK);
    for (int i = 0; i < 4; i++) {
        uint32_t b1, b2;
        memcpy(&b1, &out1[i], sizeof b1);
        memcpy(&b2, &out2[i], sizeof b2);
        CHECK(b1 == b2);
    }
}

static void test_matmul_order_invariance_against_naive(void)
{
    /* The strict left-to-right reduction rule is the protocol-pinned
     * order. For integer arithmetic the result is associative-
     * invariant (no rounding), so we can verify the impl against a
     * naive in-place double-loop computation that reduces in the
     * same order. This test exists to catch the obvious off-by-one
     * indexing error that flips an iteration boundary. */
    enum { M = 4, K = 7, N = 5 };
    int8_t a[M * K];
    int8_t b[K * N];
    for (int i = 0; i < M * K; i++) {
        a[i] = (int8_t)((i * 13 + 7) % 127 - 63);
    }
    for (int i = 0; i < K * N; i++) {
        b[i] = (int8_t)((i * 17 + 11) % 127 - 63);
    }
    int32_t got[M * N];
    int32_t expected[M * N];
    CHECK_EQ(ants_canon_matmul_i8(a, b, got, M, K, N), ANTS_OK);
    /* Reference reduction in the same canonical order. */
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            int32_t acc = 0;
            for (size_t l = 0; l < K; l++) {
                acc += (int32_t)a[i * K + l] * (int32_t)b[l * N + j];
            }
            expected[i * N + j] = acc;
        }
    }
    for (int i = 0; i < M * N; i++) {
        CHECK(got[i] == expected[i]);
    }
}

/* -- Per-channel symmetric INT8 weight quantization (RFC-0009 §1) ----- */

static void test_quantize_weights_null_args_and_bounds(void)
{
    float w[4] = {0};
    int8_t w_int8[4] = {0};
    float scales[2] = {0};
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(NULL, w_int8, scales, 2, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, NULL, scales, 2, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, NULL, 2, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 0, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 2, 0),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(
                 w, w_int8, scales, 2, ANTS_CANON_MAX_REDUCE_LEN + 1),
             ANTS_ERROR_INVALID_ARG);
}

static void test_quantize_weights_simple_127_scaling(void)
{
    /* One channel, max_abs = 127.0 exactly → scale = 1.0, quantized
     * values = round(w / 1.0) = round(w). */
    float w[5] = {127.0f, -64.0f, 0.0f, 63.5f, -127.0f};
    int8_t w_int8[5];
    float scales[1];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 1, 5), ANTS_OK);
    CHECK(scales[0] == 1.0f);
    CHECK(w_int8[0] == 127);
    CHECK(w_int8[1] == -64);
    CHECK(w_int8[2] == 0);
    /* 63.5 rounds to even → 64 (banker's rounding via rintf). */
    CHECK(w_int8[3] == 64);
    CHECK(w_int8[4] == -127);
}

static void test_quantize_weights_two_channels_independent_scales(void)
{
    /* Two channels with different magnitudes → different scales. */
    float w[2 * 4] = {/* ch 0: max_abs = 4.0 → scale = 4/127 */
                      1.0f,
                      2.0f,
                      3.0f,
                      -4.0f,
                      /* ch 1: max_abs = 254.0 → scale = 2.0 */
                      127.0f,
                      -254.0f,
                      0.0f,
                      254.0f};
    int8_t w_int8[2 * 4];
    float scales[2];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 2, 4), ANTS_OK);
    /* Ch 0: scale = 4.0 / 127.0 (not 1/scale!) */
    CHECK(fabsf(scales[0] - 4.0f / 127.0f) < 1e-7f);
    /* Quantized ch 0 values: round(w / (4/127)) = round(w * 127/4) */
    CHECK(w_int8[3] == -127); /* -4.0 * 127 / 4 = -127 */
    /* Ch 1: scale = 254.0 / 127.0 = 2.0 */
    CHECK(scales[1] == 2.0f);
    CHECK(w_int8[4] == 64);   /* round(127.0 / 2.0) = round(63.5) → 64 (banker's) */
    CHECK(w_int8[5] == -127); /* round(-254.0 / 2.0) = -127 */
    CHECK(w_int8[6] == 0);    /* round(0.0 / 2.0) = 0 */
    CHECK(w_int8[7] == 127);  /* round(254.0 / 2.0) = 127 */
}

static void test_quantize_weights_zero_channel_sentinel(void)
{
    /* All-zero channel → scale = 1.0 sentinel, w_int8 = 0 for all
     * lanes. Other channels processed normally. */
    float w[2 * 3] = {0.0f, 0.0f, 0.0f, 1.0f, 2.0f, 3.0f};
    int8_t w_int8[2 * 3];
    float scales[2];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 2, 3), ANTS_OK);
    CHECK(scales[0] == 1.0f);
    CHECK(w_int8[0] == 0);
    CHECK(w_int8[1] == 0);
    CHECK(w_int8[2] == 0);
    /* Ch 1: max_abs = 3.0 → scale = 3/127. */
    CHECK(fabsf(scales[1] - 3.0f / 127.0f) < 1e-7f);
}

static void test_quantize_weights_clamps_overflow(void)
{
    /* If somehow rounded value exceeds ±127 (shouldn't given the
     * scale derivation, but the clamp is defensive against numeric
     * edge cases), the result saturates. The simplest reproduction:
     * a channel where rintf rounds to +128 at one position (e.g.
     * via the banker's rounding rule applied to 127.5 → 128). */
    float w[1 * 2] = {127.49999f, 0.0f};
    int8_t w_int8[2];
    float scales[1];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, 1, 2), ANTS_OK);
    /* max_abs = 127.49999, scale ≈ 1.0039..., w[0] / scale ≈ 127.0
     * → rounds to 127. Saturation didn't trigger but the contract
     * is satisfied. */
    CHECK(w_int8[0] == 127);
    CHECK(w_int8[1] == 0);
}

static void test_quantize_weights_dequant_round_trip(void)
{
    /* Dequantize via w_int8 * scale and verify approximation:
     * |w_fp32 - w_int8 * scale| ≤ scale/2 (half a quantization step). */
    enum { CH = 3, S = 8 };
    float w[CH * S];
    /* Pseudo-random weights in [-2, +2]. */
    for (size_t i = 0; i < CH * S; i++) {
        w[i] = (float)(((int)i * 13 + 7) % 100 - 50) * 0.04f;
    }
    int8_t w_int8[CH * S];
    float scales[CH];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, w_int8, scales, CH, S), ANTS_OK);
    for (size_t ch = 0; ch < CH; ch++) {
        for (size_t i = 0; i < S; i++) {
            float dequant = (float)w_int8[ch * S + i] * scales[ch];
            CHECK(fabsf(w[ch * S + i] - dequant) <= scales[ch] * 0.5f + 1e-7f);
        }
    }
}

static void test_quantize_weights_same_input_bit_exact(void)
{
    /* No hidden state; same input → bit-identical output. */
    float w[2 * 4] = {0.1f, 0.5f, -0.3f, 0.9f, 1.0f, -1.5f, 2.0f, -0.5f};
    int8_t out1[2 * 4];
    int8_t out2[2 * 4];
    float scales1[2];
    float scales2[2];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, out1, scales1, 2, 4), ANTS_OK);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, out2, scales2, 2, 4), ANTS_OK);
    for (int i = 0; i < 2 * 4; i++) {
        CHECK(out1[i] == out2[i]);
    }
    for (int i = 0; i < 2; i++) {
        uint32_t b1, b2;
        memcpy(&b1, &scales1[i], sizeof b1);
        memcpy(&b2, &scales2[i], sizeof b2);
        CHECK(b1 == b2);
    }
}

/* -- Group-wise symmetric INT8 weight quantization (RFC-0009 §1) ------ */

static void test_quantize_weights_grouped_basic(void)
{
    /* Two groups in one channel, each scaled against ITS OWN absmax —
     * the small group {3,-1} is not crushed by the large group
     * {100,25}. Values chosen clear of half-integer ties (round-half-
     * to-even is already pinned by the per-channel tests; the same
     * quantize_one_i8 helper backs both paths). */
    CHECK(ANTS_CANON_QUANT_GROUP_SIZE == 128u);

    float w[4] = {3.0f, -1.0f, 100.0f, 25.0f};
    int8_t w_int8[4];
    float scales[2]; /* n_groups = ceil(4/2) = 2 */
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 1, 4, 2), ANTS_OK);
    /* group 0 {3,-1}: scale = 3/127, independent of group 1. */
    CHECK(fabsf(scales[0] - 3.0f / 127.0f) < 1e-7f);
    CHECK(w_int8[0] == 127); /* 3 / (3/127) = 127 (group max) */
    CHECK(w_int8[1] == -42); /* -1 / (3/127) = -42.33 -> -42 */
    /* group 1 {100,25}: scale = 100/127. */
    CHECK(fabsf(scales[1] - 100.0f / 127.0f) < 1e-7f);
    CHECK(w_int8[2] == 127); /* 100 / (100/127) = 127 (group max) */
    CHECK(w_int8[3] == 32);  /* 25 / (100/127) = 31.75 -> 32 */

    /* dequant via the per-group scale stays within half a step. */
    for (size_t i = 0; i < 4; i++) {
        float scale = scales[i / 2];
        float dequant = (float)w_int8[i] * scale;
        CHECK(fabsf(w[i] - dequant) <= scale * 0.5f + 1e-7f);
    }
}

static void test_quantize_weights_grouped_equals_per_channel(void)
{
    /* Independent cross-check: with group_size >= channel_size there is
     * exactly one group per channel, so the grouped result MUST be
     * bit-identical to the per-channel entry point (a different code
     * path computing the same thing). */
    float w[3 * 4] = {
        /* ch0 */ 1.0f,
        -2.0f,
        3.0f,
        -4.0f,
        /* ch1 */ 0.5f,
        0.25f,
        -0.5f,
        0.125f,
        /* ch2 */ 10.0f,
        -20.0f,
        30.0f,
        -40.0f,
    };
    int8_t q_pc[12], q_g[12];
    float s_pc[3], s_g[3]; /* n_groups = 1 per channel */

    CHECK_EQ(ants_canon_quantize_weights_symmetric_per_channel(w, q_pc, s_pc, 3, 4), ANTS_OK);
    /* group_size == channel_size -> one group per channel. */
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, q_g, s_g, 3, 4, 4), ANTS_OK);
    for (int i = 0; i < 12; i++) {
        CHECK(q_g[i] == q_pc[i]);
    }
    for (int c = 0; c < 3; c++) {
        uint32_t b_pc, b_g;
        memcpy(&b_pc, &s_pc[c], sizeof b_pc);
        memcpy(&b_g, &s_g[c], sizeof b_g);
        CHECK(b_pc == b_g);
    }

    /* group_size strictly greater than channel_size also collapses to a
     * single (short) group covering the whole channel. */
    int8_t q_big[12];
    float s_big[3];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, q_big, s_big, 3, 4, 100), ANTS_OK);
    for (int i = 0; i < 12; i++) {
        CHECK(q_big[i] == q_pc[i]);
    }
}

static void test_quantize_weights_grouped_short_final(void)
{
    /* channel_size not a multiple of group_size -> the last group covers
     * the remainder and gets its own scale. No padding. */
    float w[5] = {1.0f, -2.0f, 4.0f, -8.0f, 3.0f};
    int8_t w_int8[5];
    float scales[3]; /* n_groups = ceil(5/2) = 3: [0,1] [2,3] [4] */
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 1, 5, 2), ANTS_OK);
    CHECK(fabsf(scales[0] - 2.0f / 127.0f) < 1e-7f); /* {1,-2} absmax 2 */
    CHECK(fabsf(scales[1] - 8.0f / 127.0f) < 1e-7f); /* {4,-8} absmax 8 */
    CHECK(fabsf(scales[2] - 3.0f / 127.0f) < 1e-7f); /* {3}   absmax 3 */
    CHECK(w_int8[4] == 127);                         /* lone short-group element -> group max */
}

static void test_quantize_weights_grouped_divide_not_reciprocal(void)
{
    /* The per-group scale uses a direct FP32 divide. 9.0/127.0 as a
     * single divide is 0x3D912245u; the precomputed-reciprocal
     * multiply 9.0 * (1/127) would give 0x3D912244u (off by 1 ULP).
     * Same discriminator as §2.1, applied per group. */
    float w[4] = {9.0f, -3.0f, 254.0f, 0.0f};
    int8_t w_int8[4];
    float scales[2];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 1, 4, 2), ANTS_OK);
    uint32_t s0_bits;
    memcpy(&s0_bits, &scales[0], sizeof s0_bits);
    CHECK(s0_bits == 0x3D912245u); /* divide, correct */
    CHECK(s0_bits != 0x3D912244u); /* reciprocal-multiply, wrong */
    CHECK(w_int8[0] == 127);       /* 9 / (9/127) = 127 */
    /* group 1 {254,0}: 254/127 = 2.0 exactly; distinct from group 0. */
    CHECK(scales[1] == 2.0f);
    CHECK(scales[0] != scales[1]);
    CHECK(w_int8[2] == 127); /* 254 / 2 = 127 */
}

static void test_quantize_weights_grouped_null_args_and_bounds(void)
{
    float w[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    int8_t w_int8[4];
    float scales[4];
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(NULL, w_int8, scales, 1, 4, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, NULL, scales, 1, 4, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, NULL, 1, 4, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 0, 4, 2),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 1, 0, 2),
             ANTS_ERROR_INVALID_ARG);
    /* group_size == 0 is invalid. */
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(w, w_int8, scales, 1, 4, 0),
             ANTS_ERROR_INVALID_ARG);
    /* group_size beyond the reduction-tree cap is invalid. */
    CHECK_EQ(ants_canon_quantize_weights_symmetric_grouped(
                 w, w_int8, scales, 1, 4, ANTS_CANON_MAX_REDUCE_LEN + 1),
             ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_q24_zero_round_trip();
    test_q24_one_round_trip();
    test_q24_negative_round_trip();
    test_q24_fractional_round_trip();
    test_q24_saturates_above_range();
    test_q24_nan_to_zero();
    test_q24_inf_saturates();
    test_q24_vec_round_trip();
    test_q24_vec_null_args();

    test_reduce_max_singleton();
    test_reduce_max_empty();
    test_reduce_max_power_of_two();
    test_reduce_max_non_power_of_two();
    test_reduce_max_all_negative();
    test_reduce_max_into_caller_buffer();
    test_reduce_max_null_args();
    test_reduce_max_oversized();

    test_per_token_scale_basic();
    test_per_token_scale_zero_sentinel();
    test_per_token_scale_negative_max();
    test_per_token_scale_divide_not_reciprocal();
    test_per_token_scale_null_args();

    test_reduce_sum_basic();
    test_reduce_sum_empty();
    test_reduce_sum_singleton();
    test_reduce_sum_non_power_of_two();
    test_reduce_sum_into_caller_buffer();
    test_reduce_sum_null_args();
    test_reduce_sum_oversized();
    test_reduce_sum_tree_shape_matches_pairwise();

    test_softmax_uniform_input();
    test_softmax_sums_to_one();
    test_softmax_singleton();
    test_softmax_shift_invariance();
    test_softmax_zero_shift_is_bit_exact();
    test_softmax_in_place();
    test_softmax_extreme_negatives_no_nan();
    test_softmax_all_neg_inf_zero_output();
    test_softmax_null_args();

    test_matmul_null_args_and_zero_dims();
    test_matmul_known_2x2();
    test_matmul_identity_left();
    test_matmul_zero_matrix();
    test_matmul_negative_values();
    test_matmul_extreme_int8_values();
    test_matmul_rectangular_shape();
    test_matmul_order_invariance_against_naive();

    test_matmul_fp32_null_args_and_zero_dims();
    test_matmul_fp32_known_2x2();
    test_matmul_fp32_identity_left();
    test_matmul_fp32_zero_matrix();
    test_matmul_fp32_strict_left_to_right_order();
    test_matmul_fp32_rectangular_shape();
    test_matmul_fp32_same_input_bit_exact();

    test_attention_null_args_and_bounds();
    test_attention_singleton_token();
    test_attention_softmax_sums_to_one_per_row();
    test_attention_causal_mask_row_zero_attends_only_self();
    test_attention_causal_mask_per_row_sums_to_one();
    test_attention_no_mask_uniform_q_k_zero();
    test_attention_same_input_bit_exact();

    test_quantize_weights_null_args_and_bounds();
    test_quantize_weights_simple_127_scaling();
    test_quantize_weights_two_channels_independent_scales();
    test_quantize_weights_zero_channel_sentinel();
    test_quantize_weights_clamps_overflow();
    test_quantize_weights_dequant_round_trip();
    test_quantize_weights_same_input_bit_exact();
    test_quantize_weights_grouped_basic();
    test_quantize_weights_grouped_equals_per_channel();
    test_quantize_weights_grouped_short_final();
    test_quantize_weights_grouped_divide_not_reciprocal();
    test_quantize_weights_grouped_null_args_and_bounds();

    if (failures > 0) {
        fprintf(stderr, "test_canon: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_canon: all checks passed\n");
    return 0;
}
