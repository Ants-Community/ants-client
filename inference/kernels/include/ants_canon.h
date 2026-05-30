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
 * Status:
 *   - q24 ↔ FP32 conversion: implemented (§5)
 *   - Left-biased max + sum reductions: implemented (§2.1 step 2 + §3)
 *   - Per-token scale (full §2.1 recipe): implemented
 *   - INT8 × INT8 → INT32 matmul: implemented (§3)
 *   - FP32 × FP32 → FP32 matmul (strict left-to-right): implemented (§3 + §5)
 *   - Softmax with stable subtract-max + divide: implemented (§3)
 *   - Full scaled-dot-product attention (Q·K^T + softmax + ·V): implemented (§3)
 *   - Per-channel symmetric INT8 weight quantization (§1, AbsMax variant,
 *     one scale per channel): implemented
 *   - Group-wise symmetric INT8 weight quantization (§1, AbsMax per group,
 *     canonical group size 128): implemented
 *   - GPTQ Hessian-optimized scales: future PR (calibration-driven)
 *   - SIMD parity (AVX2/AVX-512/NEON/SVE): future PRs
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

#include <stdbool.h>
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

/* Canonical group size for group-wise weight quantization (RFC-0009 §1:
 * "per-channel symmetric scaling, group size 128"). Each contiguous run
 * of this many weights within an output channel gets its own scale. The
 * grouped entry point takes the size as a parameter so short final groups
 * and finer/coarser grids are testable, but 128 is the value the canonical
 * INT8-GPTQ-128 audited path pins. */
#define ANTS_CANON_QUANT_GROUP_SIZE 128u

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
/* Left-biased sum reduction (RFC-0009 §3, parallel to §2.1 step 2)         */
/* ------------------------------------------------------------------------ */

/*
 * Reduce a vector to its sum via the left-biased binary tree, mirror
 * of `ants_canon_reduce_max` but padding with 0.0f (additive identity)
 * instead of -∞. FP32 summation is NOT associative, so the order
 * matters even for honest implementations — the canonical recipe
 * pins the tree shape so two implementations on different hardware
 * produce byte-identical output for the same input.
 *
 * The recipe:
 *   1. Pad to d_pad = next_pow2(n) with 0.0f.
 *   2. For each level 0..log2(d_pad)−1:
 *          m[i] ← m[2i] + m[2i+1]    for i = 0..d_pad/2^{level+1} − 1
 *   3. Return m[0].
 *
 * `n == 0` returns 0.0f.
 *
 * Used by the softmax recipe (RFC-0009 §3 attention) to sum the
 * exponentiated values before the final divide.
 *
 * Returns:
 *   ANTS_OK                — *out_result set;
 *   ANTS_ERROR_INVALID_ARG — NULL args, or n > MAX_REDUCE_LEN
 *                            (use _into for larger inputs).
 */
ants_error_t ants_canon_reduce_sum(const float *values, size_t n, float *out_result);

/*
 * Caller-buffer variant. `scratch` MUST hold at least `next_pow2(n)`
 * floats; left in indeterminate state on return.
 */
ants_error_t ants_canon_reduce_sum_into(const float *values,
                                        size_t n,
                                        float *scratch,
                                        size_t scratch_cap,
                                        float *out_result);

/* ------------------------------------------------------------------------ */
/* Softmax with numerical stability (RFC-0009 §3 attention)                 */
/* ------------------------------------------------------------------------ */

/*
 * Compute the softmax of an FP32 vector with the fixed numerical-
 * stability subtraction per RFC-0009 §3:
 *
 *   1. m = max(in[0..n−1])           (left-biased tree max per §2.1)
 *   2. e_i = expf(in_i − m)          (per-element FP32)
 *   3. s = sum(e_0..e_{n−1})         (left-biased tree sum)
 *   4. out_i = e_i / s               (single FP32 divide per lane,
 *                                     NOT a precomputed reciprocal —
 *                                     same §2.1 discipline)
 *
 * Pathological s == 0 (all inputs −∞ or extreme negatives whose exp
 * underflows to 0): out is set to all zeros and ANTS_OK is returned.
 * This is the deterministic recipe; callers that want a uniform-
 * distribution fallback can detect zero sum from the output.
 *
 * `in` and `out` MAY alias (in-place softmax is supported). Internal
 * scratch holds the exp results during the sum reduction.
 *
 * Returns:
 *   ANTS_OK                — out populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args, n == 0, or n > MAX_REDUCE_LEN.
 */
ants_error_t ants_canon_softmax(const float *in, float *out, size_t n);

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
 *   - Inner-product summation in a strict left-to-right reduction
 *     over the inner (K) dimension. NO tiling-induced reordering.
 *
 * Shapes (row-major):
 *   a:   [m × k]   INT8
 *   b:   [k × n]   INT8
 *   out: [m × n]   INT32
 *
 * Accumulator is int32_t. Per-product range is [-127·127, +127·127];
 * INT32_MAX / 127² ≈ 133150 → K up to that value is overflow-safe.
 * No realistic transformer K dimension exceeds this; callers passing
 * larger K are responsible for verifying overflow safety.
 *
 * Returns:
 *   ANTS_OK                — out populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args or zero-sized dim.
 */
ants_error_t
ants_canon_matmul_i8(const int8_t *a, const int8_t *b, int32_t *out, size_t m, size_t k, size_t n);

/*
 * Canonical FP32 × FP32 → FP32 GEMM per RFC-0009 §3 + §5:
 *   - Row-major iteration order for the output matrix.
 *   - Inner-product summation in a strict left-to-right reduction
 *     over the inner (K) dimension. NO tiling-induced reordering,
 *     NO horizontal-SIMD reordering that violates left-to-right.
 *
 * Used by §5 unembedding (FP32 hidden-state → vocab logits projection)
 * and as a building block for the FP32 fallback inference path
 * referenced in §"The FP16 fallback".
 *
 * FP32 addition is NOT associative, so the reduction order matters
 * bit-exactly. Two honest implementations that reduce in different
 * orders (e.g. a SIMD horizontal-add tree vs strict left-to-right)
 * will produce different last-bit results — the canonical recipe
 * pins left-to-right so byte-identical output is reproducible.
 *
 * Shapes (row-major):
 *   a:   [m × k]   FP32
 *   b:   [k × n]   FP32
 *   out: [m × n]   FP32
 *
 * No overflow analogue to the INT8 case: FP32 saturates to ±∞ for
 * extreme magnitudes, which propagates through softmax + downstream
 * matmuls deterministically. Callers concerned about overflow should
 * either scale inputs or expect ±∞ in their output.
 *
 * Returns:
 *   ANTS_OK                — out populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args or zero-sized dim.
 */
ants_error_t
ants_canon_matmul_fp32(const float *a, const float *b, float *out, size_t m, size_t k, size_t n);

/* ------------------------------------------------------------------------ */
/* Scaled-dot-product attention (RFC-0009 §3)                               */
/* ------------------------------------------------------------------------ */

/*
 * Canonical FP32 scaled-dot-product attention per RFC-0009 §3:
 *
 *   scores[i, j] = sum_d Q[i, d] * K[j, d]               (strict L-to-R)
 *   scores[i, j] /= sqrtf((float)d_head)                 (single FP32 div)
 *   if causal_mask and j > i: scores[i, j] = -inf        (causal)
 *   probs[i, :] = softmax(scores[i, :])                  (§3 stable recipe)
 *   out[i, d] = sum_j probs[i, j] * V[j, d]              (strict L-to-R)
 *
 * Shapes (row-major, single attention head):
 *   q:   [n_tokens × d_head]    FP32
 *   k:   [n_tokens × d_head]    FP32
 *   v:   [n_tokens × d_head]    FP32
 *   out: [n_tokens × d_head]    FP32
 *
 * The `causal_mask` boolean enables autoregressive masking — set to
 * true for decoder self-attention, false for encoder / cross-
 * attention. Masked entries become 0.0f in the softmax output via the
 * subtract-max trick (max is finite from the non-masked entries; the
 * masked -inf produces exp(-inf) = 0 cleanly).
 *
 * `scratch` MUST hold at least `n_tokens × n_tokens` floats — the
 * intermediate attention-scores buffer. The contract decouples
 * attention's memory budget from the public ctx size (which has to
 * stay small enough to stack-allocate). For n_tokens = 1024 this is
 * 4 MiB; for n_tokens = 8192, 256 MiB. Callers manage the heap.
 *
 * `q`, `k`, `v`, `out` MAY alias each other if the caller knows the
 * read-before-write ordering is safe — but the reference impl does
 * NOT verify this and may behave unpredictably if (out == q) etc.
 * Recommended: distinct buffers.
 *
 * Returns:
 *   ANTS_OK                — out populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args, zero-sized dim, or scratch_cap
 *                            < n_tokens * n_tokens.
 */
ants_error_t ants_canon_attention_fp32(const float *q,
                                       const float *k,
                                       const float *v,
                                       float *out,
                                       size_t n_tokens,
                                       size_t d_head,
                                       bool causal_mask,
                                       float *scratch,
                                       size_t scratch_cap);

/* ------------------------------------------------------------------------ */
/* Per-channel symmetric INT8 weight quantization (RFC-0009 §1)             */
/* ------------------------------------------------------------------------ */

/*
 * Quantize FP32 weights to INT8 with per-channel symmetric scaling.
 *
 * The full canonical recipe per RFC-0009 §1 is "INT8-GPTQ-128":
 *  (a) per-channel symmetric scaling — one or more scales per output channel;
 *  (b) group size 128 — each channel divided into groups of 128 weights,
 *      each group with its own scale;
 *  (c) GPTQ Hessian-based optimisation — scales tuned per row using
 *      a Hessian-based optimisation against calibration data.
 *
 * This entry point implements (a) only — one scale per channel, computed
 * via AbsMax (max(|w|) / 127.0) over the full channel. (b) and (c) are
 * future PRs. The output FORMAT (INT8 weights + FP32 scales) is
 * forward-compatible: a future caller can run AbsMax for fast
 * deployment or full GPTQ-128 for canonical-recipe conformance, and
 * both produce the same downstream tensor layout.
 *
 * Per channel ch:
 *   max_abs = left-biased-tree-max(|w[ch, 0..channel_size-1]|)
 *   if max_abs == 0:
 *     scales[ch] = 1.0f                              (zero-channel sentinel)
 *     w_int8[ch, i] = 0 for all i
 *   else:
 *     scales[ch] = max_abs / 127.0f                  (single FP32 divide
 *                                                     per §2.1 discipline)
 *     w_int8[ch, i] = clamp(rintf(w[ch, i] / scales[ch]), -127, +127)
 *
 * Dequantization: w_fp32 ≈ w_int8 * scales[ch].
 *
 * Shapes (row-major):
 *   w:       [n_channels × channel_size]   FP32
 *   w_int8:  [n_channels × channel_size]   INT8 (output)
 *   scales:  [n_channels]                  FP32 (output)
 *
 * channel_size MUST be ≤ ANTS_CANON_MAX_REDUCE_LEN (the reduce_max
 * scratch limit). Future PRs may relax this once a group-size-128
 * variant lands.
 *
 * Returns:
 *   ANTS_OK                — quantization complete;
 *   ANTS_ERROR_INVALID_ARG — NULL args, zero-sized dim, or
 *                            channel_size > MAX_REDUCE_LEN.
 */
ants_error_t ants_canon_quantize_weights_symmetric_per_channel(const float *w,
                                                               int8_t *w_int8,
                                                               float *scales,
                                                               size_t n_channels,
                                                               size_t channel_size);

/*
 * Quantize FP32 weights to INT8 with group-wise symmetric scaling
 * (RFC-0009 §1: "per-channel symmetric scaling, group size 128"). This
 * is the finer-grained sibling of the per-channel entry point above:
 * each output channel is split into contiguous groups of `group_size`
 * weights along the input dimension, and each group gets its own scale.
 * It is the granularity the canonical INT8-GPTQ-128 audited path uses;
 * per-channel is the special case group_size >= channel_size.
 *
 * Per channel ch, per group g (same recipe as per-channel, applied to
 * the group's slice — §2.1 discipline throughout):
 *   max_abs = left-biased-tree-max(|w[ch, g*G .. g*G + len - 1]|)
 *   if max_abs == 0:
 *     scales[ch, g] = 1.0f                   (zero-group sentinel)
 *     w_int8[...]   = 0 for the group
 *   else:
 *     scales[ch, g] = max_abs / 127.0f       (single FP32 divide, NOT
 *                                             a precomputed reciprocal)
 *     w_int8[ch, i] = clamp(rintf(w[ch, i] / scales[ch, g]), -127, +127)
 *
 * When channel_size is not a multiple of group_size, the final group is
 * SHORT (covers the remainder, `len` < group_size) and scales over just
 * those weights — no padding. The number of groups per channel is
 * n_groups = (channel_size + group_size - 1) / group_size.
 *
 * Because each absmax reduces over one group, channel_size is NOT bound
 * by ANTS_CANON_MAX_REDUCE_LEN here (only group_size is) — unlike the
 * per-channel variant, which reduces the whole channel at once.
 *
 * Shapes (row-major):
 *   w:       [n_channels × channel_size]   FP32
 *   w_int8:  [n_channels × channel_size]   INT8 (output)
 *   scales:  [n_channels × n_groups]       FP32 (output, n_groups above)
 *
 * Dequantization: w_fp32 ≈ w_int8[ch, i] * scales[ch, i / group_size].
 *
 * Returns:
 *   ANTS_OK                — quantization complete;
 *   ANTS_ERROR_INVALID_ARG — NULL args, zero-sized dim, group_size == 0,
 *                            or group_size > ANTS_CANON_MAX_REDUCE_LEN.
 */
ants_error_t ants_canon_quantize_weights_symmetric_grouped(const float *w,
                                                           int8_t *w_int8,
                                                           float *scales,
                                                           size_t n_channels,
                                                           size_t channel_size,
                                                           size_t group_size);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CANON_H */
