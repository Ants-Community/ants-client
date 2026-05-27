/*
 * cpu_scalar.c — Bit-exact reference implementation of canonical
 * kernels (Component #12).
 *
 * Per RFC-0009 §"The reference kernel library", this path is the
 * canonical ground truth: pure scalar arithmetic, no SIMD intrinsics,
 * no parallelism, no vendor-specific tricks. Every other platform-
 * specific implementation (AVX2 / AVX-512 / NEON / SVE / future GPU
 * paths) MUST produce byte-identical output against this file for
 * every test vector. SIMD implementations are optimisations on this
 * reference, not redefinitions of it.
 *
 * Scope (this PR — scaffold + first two kernels):
 *   - ants_canon_q24_{from,to}_f32 + _vec_*           §5
 *   - ants_canon_reduce_max{,_into}                    §2.1 step 2
 *   - ants_canon_per_token_scale                       §2.1 full
 *   - ants_canon_matmul_i8                             STUB (§3)
 *
 * Implementation discipline:
 *   - Every reduction is left-biased and binary-tree shaped where the
 *     RFC pins it (max reduction); the inner-product reduction for
 *     matmul is strict left-to-right per §3.
 *   - FP32 operations rely on IEEE-754 default rounding
 *     (round-to-nearest-even). Strict ISO C99: no compiler-specific
 *     intrinsics; the compiler's FP32 codegen on a conformant target
 *     produces bit-identical results regardless of `-O0` vs `-O3`
 *     because there's no associativity reordering to exploit at this
 *     level. CI matrix must verify this empirically.
 *   - No malloc: bounded internal buffers (sized to
 *     ANTS_CANON_MAX_REDUCE_LEN); inputs past the cap fail loud with
 *     INVALID_ARG and the caller is expected to use the _into
 *     variant.
 */

#include "ants_canon.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Internal helpers                                                         */
/* ------------------------------------------------------------------------ */

/* Smallest power of two ≥ n, with 1 as the result for n ∈ {0, 1}.
 * Used to pad the max-reduction tree to a power-of-two length per
 * RFC-0009 §2.1 step 2. */
static size_t next_pow2_size(size_t n)
{
    if (n <= 1) {
        return 1;
    }
    size_t p = 1;
    while (p < n) {
        p <<= 1;
    }
    return p;
}

/* Type-punning helper: read the bit pattern of a uint32 into a float
 * without UB. The `memcpy` route is the canonical strict-aliasing-safe
 * idiom — every conformant C99 compiler optimises it to a register
 * move, so it costs nothing at -O1+. */
static float bits_to_f32(uint32_t bits)
{
    float f;
    memcpy(&f, &bits, sizeof f);
    return f;
}

/* ------------------------------------------------------------------------ */
/* q24 fixed-point conversion (RFC-0009 §5)                                 */
/* ------------------------------------------------------------------------ */

ants_canon_q24_t ants_canon_q24_from_f32(float value)
{
    /* NaN → 0. Documented behaviour: NaN logits would already poison
     * downstream computation; the alternative of propagating NaN
     * through fixed-point breaks the byte-identical-output contract. */
    if (isnan(value)) {
        return 0;
    }
    /* Infinity saturates to ±INT32_MAX. */
    if (isinf(value)) {
        return (value > 0.0f) ? ANTS_CANON_Q24_MAX : ANTS_CANON_Q24_MIN;
    }
    /* Scale by 2^24 then round-to-nearest-even. `rintf` is the
     * IEEE-754-compliant round-to-current-rounding-mode operation;
     * with the default rounding mode (round-to-nearest-even) this is
     * exactly what RFC-0009 §5 pins. */
    float scaled = value * ANTS_CANON_Q24_SCALE_F32;
    float rounded = rintf(scaled);
    /* Saturate to INT32 range. Comparing against the f32-roundtrip
     * representations of the bounds avoids the UB of casting a too-
     * large float directly to int32. INT32_MAX = 2^31 - 1 = 2147483647
     * rounds up to 2147483648.0f as an FP32; we compare against the
     * INT32_MAX_AS_F32 conservatively. */
    if (rounded >= 2147483648.0f) {
        return ANTS_CANON_Q24_MAX;
    }
    if (rounded < -2147483648.0f) {
        return ANTS_CANON_Q24_MIN;
    }
    return (ants_canon_q24_t)rounded;
}

float ants_canon_q24_to_f32(ants_canon_q24_t q)
{
    /* Divide by 2^24. IEEE-754 division by an exact power-of-two is
     * lossless (just adjusts the exponent), so this is the inverse
     * of `from_f32` modulo the original rounding error. */
    return (float)q / ANTS_CANON_Q24_SCALE_F32;
}

ants_error_t ants_canon_q24_vec_from_f32(const float *in, ants_canon_q24_t *out, size_t n)
{
    if (n == 0) {
        return ANTS_OK;
    }
    if (in == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = ants_canon_q24_from_f32(in[i]);
    }
    return ANTS_OK;
}

ants_error_t ants_canon_q24_vec_to_f32(const ants_canon_q24_t *in, float *out, size_t n)
{
    if (n == 0) {
        return ANTS_OK;
    }
    if (in == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = ants_canon_q24_to_f32(in[i]);
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Left-biased max reduction (RFC-0009 §2.1 step 2)                         */
/* ------------------------------------------------------------------------ */

/* Run the left-biased binary-tree max on a power-of-two-padded `m`
 * array in-place. After return, m[0] holds the result; the rest is
 * indeterminate. */
static void reduce_max_tree_in_place(float *m, size_t d_pad)
{
    /* Pairwise pass: m[i] ← fmaxf(m[2i], m[2i+1]). After the first
     * pass, d_pad halves. Repeat until d_pad == 1. */
    while (d_pad > 1) {
        size_t half = d_pad >> 1;
        for (size_t i = 0; i < half; i++) {
            m[i] = fmaxf(m[2 * i], m[2 * i + 1]);
        }
        d_pad = half;
    }
}

ants_error_t ants_canon_reduce_max(const float *values, size_t n, float *out_result)
{
    if (out_result == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n == 0) {
        /* Reducing the empty set under max returns -∞. */
        *out_result = bits_to_f32(ANTS_CANON_NEG_INF_BITS);
        return ANTS_OK;
    }
    if (values == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n > ANTS_CANON_MAX_REDUCE_LEN) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Internal scratch sized for the worst case. ~64 KiB on the stack;
     * tolerable given the cap. Callers with larger n use the _into
     * variant. */
    float scratch[ANTS_CANON_MAX_REDUCE_LEN * 2u];
    size_t d_pad = next_pow2_size(n);
    /* Copy values into scratch, pad with -∞. */
    memcpy(scratch, values, n * sizeof(float));
    float neg_inf = bits_to_f32(ANTS_CANON_NEG_INF_BITS);
    for (size_t i = n; i < d_pad; i++) {
        scratch[i] = neg_inf;
    }
    reduce_max_tree_in_place(scratch, d_pad);
    *out_result = scratch[0];
    return ANTS_OK;
}

ants_error_t ants_canon_reduce_max_into(const float *values,
                                        size_t n,
                                        float *scratch,
                                        size_t scratch_cap,
                                        float *out_result)
{
    if (out_result == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n == 0) {
        *out_result = bits_to_f32(ANTS_CANON_NEG_INF_BITS);
        return ANTS_OK;
    }
    if (values == NULL || scratch == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t d_pad = next_pow2_size(n);
    if (scratch_cap < d_pad) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memcpy(scratch, values, n * sizeof(float));
    float neg_inf = bits_to_f32(ANTS_CANON_NEG_INF_BITS);
    for (size_t i = n; i < d_pad; i++) {
        scratch[i] = neg_inf;
    }
    reduce_max_tree_in_place(scratch, d_pad);
    *out_result = scratch[0];
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Per-token INT8 quantization scale (RFC-0009 §2.1)                        */
/* ------------------------------------------------------------------------ */

ants_error_t ants_canon_per_token_scale(const float *activations, size_t n, float *out_scale)
{
    if (activations == NULL || out_scale == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n > ANTS_CANON_MAX_REDUCE_LEN) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Step 1: abs-value pass into the scratch buffer; we share the
     * scratch with the reduce tree by allocating it once at the top
     * of this function. */
    float scratch[ANTS_CANON_MAX_REDUCE_LEN * 2u];
    for (size_t i = 0; i < n; i++) {
        scratch[i] = fabsf(activations[i]);
    }
    /* Step 2: left-biased tree max reduction. Pad to next_pow2 with
     * -∞ so the tree is a complete binary tree. */
    size_t d_pad = next_pow2_size(n);
    float neg_inf = bits_to_f32(ANTS_CANON_NEG_INF_BITS);
    for (size_t i = n; i < d_pad; i++) {
        scratch[i] = neg_inf;
    }
    reduce_max_tree_in_place(scratch, d_pad);
    float max_abs = scratch[0];

    /* Step 4: zero-token sentinel (single explicit branch — prevents
     * division by zero from producing platform-dependent NaN/Inf
     * propagation). Checked BEFORE step 3 to avoid the divide. */
    if (max_abs == 0.0f) {
        *out_scale = 1.0f;
        return ANTS_OK;
    }

    /* Step 3: single FP32 divide, NOT a precomputed reciprocal.
     * `max_abs / 127.0f` is deterministic across IEEE-754 hardware;
     * `max_abs * (1.0f / 127.0f)` is NOT (the precomputed `1/127`
     * is FP32-rounded once and then multiplied, which differs in
     * the last bit on roughly half of inputs). */
    *out_scale = max_abs / (float)ANTS_CANON_INT8_SCALE_DENOM;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* INT8 × INT8 → INT32 matmul — STUB (RFC-0009 §3)                          */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_canon_matmul_i8(const int8_t *a, const int8_t *b, int32_t *out, size_t m, size_t k, size_t n)
{
    /* NULL / zero-dim validation is meaningful even at stub stage —
     * lets the test scaffold pin the contract. */
    if (a == NULL || b == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (m == 0 || k == 0 || n == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Implementation lands in a follow-up PR. */
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
