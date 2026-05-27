/*
 * ants_canon.h — Canonical inference kernels (Component #12).
 *
 * The reference library of bit-exact inference primitives. Per
 * RFC-0009 §"The reference kernel library" the library follows the
 * ggml precedent (flat C headers + per-platform impl units, no
 * abstraction layers between caller and metal), but adds a discipline
 * layer above ggml that pins reduction order, scale computation, and
 * fixed-point output so two honest implementations on different
 * hardware produce byte-identical outputs for every audited operation.
 *
 * `cpu_scalar.c` is the bit-exact reference: pure scalar, no SIMD, no
 * parallelism, no vendor tricks. Every other platform-specific
 * implementation (AVX2 / AVX-512 / NEON / SVE / future GPU paths)
 * MUST produce byte-identical output against `cpu_scalar.c` for every
 * test vector on every supported architecture. SIMD implementations
 * are optimisations on the scalar reference, not redefinitions of it.
 *
 * Spec references:
 *   - RFC-0009 §1   INT8-GPTQ-128 weight quantization
 *   - RFC-0009 §2   Integer-domain activations on the audited path
 *   - RFC-0009 §2.1 Bit-exact per-token scale (left-biased tree max,
 *                   direct FP32 divide, zero-token sentinel)
 *   - RFC-0009 §3   Fixed accumulation order for INT8 × INT8 → INT32
 *   - RFC-0009 §4   Deterministic flags + single-thread audited path
 *   - RFC-0009 §5   FP32 unembedding + q24 fixed-point representation
 *   - RFC-0009 §5.1 q24 collision + birthday-attack bounds
 *
 * Status (scaffold + first kernels):
 *   - q24 ↔ FP32 conversion: implemented (§5)
 *   - Left-biased max reduction: implemented (§2.1 step 2)
 *   - Per-token scale (full §2.1 recipe): implemented
 *   - INT8 × INT8 → INT32 matmul (§3): stub
 *   - Softmax + attention (§3): stub
 *   - GPTQ / AWQ quantization (§1): stub
 *
 * API model: caller-allocated buffers, no internal allocation, no
 * threads, no hidden global state. Every entry point is pure
 * (modulo `inout` parameter writes). Matches the project's C99 +
 * caller-owns-state discipline established by foundation/, network/,
 * cache/.
 */

#ifndef ANTS_CANON_H
#define ANTS_CANON_H

#include "ants_common.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Protocol-pinned constants (RFC-0009)                                     */
/* ------------------------------------------------------------------------ */

/* INT8 quantization scale denominator per RFC-0009 §1: symmetric INT8
 * range is [-127, +127]; the +1 slot (-128) is excluded to keep the
 * representation symmetric. */
#define ANTS_CANON_INT8_SCALE_DENOM 127

/* q24 fixed-point format per RFC-0009 §5: signed 32-bit integer with
 * 24 fractional bits (Q8.24). 7 decimal digits of fractional
 * precision; integer range ~[-128, +128). Logit values that exceed
 * the representable range saturate to ±(2^31 − 1) — clamping is part
 * of the canonical recipe so two implementations agree on the
 * fixed-point output even for adversarially-large inputs. */
#define ANTS_CANON_Q24_FRACTIONAL_BITS 24
#define ANTS_CANON_Q24_SCALE_F32       16777216.0f /* 2^24 */
#define ANTS_CANON_Q24_MIN             INT32_MIN
#define ANTS_CANON_Q24_MAX             INT32_MAX

typedef int32_t ants_canon_q24_t;

/* The IEEE-754 negative infinity bit pattern used to pad the
 * left-biased max-reduction tree per RFC-0009 §2.1 step 2. Defining
 * it as a named constant makes the recipe self-documenting; tests
 * compare against this value. */
#define ANTS_CANON_NEG_INF_BITS 0xFF800000u

/* ------------------------------------------------------------------------ */
/* q24 fixed-point conversion (RFC-0009 §5)                                 */
/* ------------------------------------------------------------------------ */

/*
 * Convert one FP32 value to q24 fixed-point per RFC-0009 §5.
 *
 * Algorithm: `q = round_to_nearest_even(value * 2^24)`, clamped to
 * [INT32_MIN, INT32_MAX]. The round-to-nearest-even rule is the
 * IEEE-754 default and is preserved across every conformant FP32
 * implementation; the clamp handles inputs outside Q8.24's
 * representable range (~[-128, +128)).
 *
 * NaN inputs convert to 0 (a deterministic but somewhat arbitrary
 * choice — NaN logits would already poison downstream computation,
 * and the alternative of propagating NaN through fixed-point breaks
 * the byte-identical-output contract). Infinity inputs saturate to
 * ±INT32_MAX with sign matching the input.
 *
 * Returns the q24 representation. Pure function; never errors.
 */
ants_canon_q24_t ants_canon_q24_from_f32(float value);

/*
 * Convert one q24 fixed-point value back to FP32. Pure inverse of
 * `ants_canon_q24_from_f32` for values that fit in Q8.24 range.
 * Lossless modulo the original round-to-nearest-even rounding error
 * (∼6×10⁻⁸ at the most precise scale).
 */
float ants_canon_q24_to_f32(ants_canon_q24_t q);

/*
 * Bulk FP32 → q24 conversion over a vector. Equivalent to looping
 * `ants_canon_q24_from_f32` over `in[0..n−1]`; exists as a separate
 * entry point so SIMD platforms can produce byte-identical output via
 * a vectorised implementation while the scalar path provides the
 * reference.
 *
 * `in` and `out` MUST NOT alias.
 *
 * Returns:
 *   ANTS_OK                — n values converted;
 *   ANTS_ERROR_INVALID_ARG — NULL pointer with n > 0.
 */
ants_error_t ants_canon_q24_vec_from_f32(const float *in, ants_canon_q24_t *out, size_t n);

/*
 * Bulk q24 → FP32 conversion. Mirror of `_q24_vec_from_f32`.
 */
ants_error_t ants_canon_q24_vec_to_f32(const ants_canon_q24_t *in, float *out, size_t n);

/* ------------------------------------------------------------------------ */
/* Left-biased max reduction (RFC-0009 §2.1 step 2)                         */
/* ------------------------------------------------------------------------ */

/*
 * Reduce a vector to its maximum via the left-biased binary tree per
 * RFC-0009 §2.1 step 2. The recipe:
 *
 *   1. Pad to d_pad = next_pow2(n) with -∞ (encoded as
 *      ANTS_CANON_NEG_INF_BITS = 0xFF800000).
 *   2. For each level 0..log2(d_pad)−1:
 *          m[i] ← fmaxf(m[2i], m[2i+1])  for i = 0..d_pad/2^{level+1} − 1
 *   3. Return m[0].
 *
 * `fmaxf` is the IEEE-754 maximumNumber operation: NaN-suppressing,
 * preserves -0 < +0 convention. The output is bit-identical across
 * conformant implementations.
 *
 * `n == 0` returns -∞ (consistent with reducing an empty set under
 * max). The function uses a fixed-size internal buffer sized to
 * `ANTS_CANON_MAX_REDUCE_LEN` (16384, sufficient for d_model up to
 * the largest current LLM hidden dimension); larger inputs are
 * rejected via `out_result` being unset and a non-OK return.
 *
 * Returns:
 *   ANTS_OK                       — *out_result set;
 *   ANTS_ERROR_INVALID_ARG        — NULL args, or n > MAX_REDUCE_LEN
 *                                   (no internal allocation: see
 *                                   ants_canon_reduce_max_into for
 *                                   the caller-buffer variant).
 */
#define ANTS_CANON_MAX_REDUCE_LEN 16384u
ants_error_t ants_canon_reduce_max(const float *values, size_t n, float *out_result);

/*
 * Caller-buffer variant of `ants_canon_reduce_max` for inputs that
 * may exceed the internal-buffer cap. `scratch` MUST hold at least
 * `next_pow2(n)` floats and is left in indeterminate state on return.
 *
 * Returns ANTS_OK or ANTS_ERROR_INVALID_ARG (NULL args, or n > 0 with
 * NULL scratch).
 */
ants_error_t ants_canon_reduce_max_into(const float *values,
                                        size_t n,
                                        float *scratch,
                                        size_t scratch_cap,
                                        float *out_result);

/* ------------------------------------------------------------------------ */
/* Per-token INT8 quantization scale (RFC-0009 §2.1 — full recipe)          */
/* ------------------------------------------------------------------------ */

/*
 * Compute the per-token INT8 quantization scale for an FP32
 * activation vector following the full RFC-0009 §2.1 recipe:
 *
 *   1. abs-value pass:      a[i] = fabsf(h[i])
 *   2. max-reduction tree:  max_abs = left_biased_tree_max(a, n)
 *   3. divide by 127.0f:    scale = max_abs / 127.0f
 *   4. zero-token sentinel: if max_abs == 0.0f then scale = 1.0f
 *
 * Step 3 explicitly uses a single FP32 divide, NOT a precomputed
 * reciprocal — the precomputed `1/127.0f` is FP32-rounded once and
 * then multiplied, which gives a different last-bit result than the
 * direct divide on roughly half of all inputs and breaks bit-
 * exactness. The IEEE-754 divide is deterministic across hardware.
 *
 * Returns:
 *   ANTS_OK                — *out_scale set;
 *   ANTS_ERROR_INVALID_ARG — NULL args, n == 0, or n > MAX_REDUCE_LEN.
 */
ants_error_t ants_canon_per_token_scale(const float *activations, size_t n, float *out_scale);

/* ------------------------------------------------------------------------ */
/* INT8 × INT8 → INT32 matmul (RFC-0009 §3)                                 */
/* ------------------------------------------------------------------------ */

/*
 * Canonical INT8 × INT8 → INT32 GEMM per RFC-0009 §3:
 *   - Row-major iteration order for the output matrix.
 *   - Inner-product summation in a strictly left-to-right reduction
 *     over the inner (K) dimension. NO tiling-induced reordering.
 *
 * Shapes (row-major):
 *   a:   [M × K]   INT8
 *   b:   [K × N]   INT8
 *   out: [M × N]   INT32
 *
 * Status: STUB. Lands in a follow-up PR.
 *
 * Returns:
 *   ANTS_OK                    — out populated (when implemented);
 *   ANTS_ERROR_INVALID_ARG     — NULL args, zero-sized dim;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold stage.
 */
ants_error_t
ants_canon_matmul_i8(const int8_t *a, const int8_t *b, int32_t *out, size_t m, size_t k, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CANON_H */
