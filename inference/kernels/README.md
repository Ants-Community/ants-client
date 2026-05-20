# kernels — Component #12

`ants-canonical-kernels`. Inference layer.
**The largest engineering risk in the entire corpus.**

**Status:** pending claim.
**Effort:** 6–12 EM (CPU baseline). GPU canonical kernels add 6–18 EM each per platform as v0.2+ deliverables.
**Spec:** [RFC-0009 v0.5](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0009-canonical-numerics.md) (all sections, incl. §2.1 bit-exact per-token scale, §5 unembedding + q24, §"The reference kernel library" structural skeleton).
**Dependencies:** `foundation/crypto` (for q24-Merkle root hashing). Vendored: [`ggml`](https://github.com/ggerganov/ggml) under `deps/ggml/`.

## Scope

The library of canonical inference primitives. C99/C11 with
hand-tuned SIMD intrinsics + assembly for AVX2/AVX-512/NEON/SVE; a
**pure scalar `cpu_scalar.c`** path serves as the bit-exact reference
that every SIMD implementation must match byte-for-byte on every
supported architecture for every test vector.

Discipline layer (per RFC-0009 §§ 1–5) above `ggml`:

- **Left-biased binary tree max reduction** (§2.1) over
  power-of-two-padded arrays with -∞ padding.
- **Direct FP32 divide** for scale computation, **not** precomputed
  reciprocal (§2.1).
- **Zero-token sentinel** for all-zero activation vectors.
- **INT8-GPTQ-128 quantization** (§1) with per-channel symmetric
  scaling.
- **q24 representation** for FP32 → fixed-point conversion at the
  unembedding output (§5), feeding into BLAKE3 Merkle root.
- **Pinned reduction order** for INT8 × INT8 → INT32 matmul (§3).

## Critical path

This component is the largest single engineering risk in the corpus.
The mitigation strategy per IMPLEMENTATION.md: ship v0.1 testnet with
**CPU-only canonical**, add GPU canonical kernels per platform
(CUDA / ROCm / Metal Performance Shaders) as v0.2+ deliverables.

## Good-first-contribution flag

**No.** SOTA SIMD intrinsics work + bit-exact discipline + integration
with `ggml`. Claims from contributors with prior ML-kernel or HPC
experience (`llama.cpp` contributors, CUDA / oneAPI / Triton authors,
high-performance crypto-library authors).
