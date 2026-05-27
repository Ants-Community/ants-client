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

/* -- matmul stub contract --------------------------------------------- */

static void test_matmul_stub_contract(void)
{
    /* The stub returns NOT_IMPLEMENTED on a valid call; rejects NULL
     * args + zero dims with INVALID_ARG. Pins the contract so the
     * real implementation in a follow-up PR can be diffed against
     * the stub. */
    int8_t a[2 * 2] = {1, 2, 3, 4};
    int8_t b[2 * 2] = {5, 6, 7, 8};
    int32_t out[2 * 2] = {0};
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 2, 2), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_canon_matmul_i8(NULL, b, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, NULL, out, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, NULL, 2, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 0, 2, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 0, 2), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_canon_matmul_i8(a, b, out, 2, 2, 0), ANTS_ERROR_INVALID_ARG);
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

    test_matmul_stub_contract();

    if (failures > 0) {
        fprintf(stderr, "test_canon: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_canon: all checks passed\n");
    return 0;
}
