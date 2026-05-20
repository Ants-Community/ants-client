# deps/blake3 — vendored BLAKE3 C reference implementation

Vendored snapshot of [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3).

| Field | Value |
|---|---|
| **Version** | `1.8.5` |
| **Upstream tag** | https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.5 |
| **Vendored on** | 2026-05-20 |
| **License** | Apache-2.0 / Apache-2.0 with LLVM exception / CC0 (triple-licensed by upstream; we use under Apache-2.0 to match the ants-client dual-license) |

## Source files

Files downloaded from `c/` and the repo root at the pinned tag:

- `blake3.h`           — public API
- `blake3.c`           — main implementation
- `blake3_dispatch.c`  — architecture/SIMD dispatch
- `blake3_impl.h`      — internal header
- `blake3_portable.c`  — pure C portable implementation
- `LICENSE_A2`, `LICENSE_A2LLVM`, `LICENSE_CC0` — upstream license texts (all three preserved)

## What is intentionally not vendored (yet)

The portable C path is the minimum needed for a working build on every
target platform. The following SIMD acceleration sources are
**deliberately omitted** from this initial vendoring and will be added
in a follow-up PR once we want CPU-specific performance:

- `blake3_avx2.c`, `blake3_avx2_x86-64_*.S` (AVX2)
- `blake3_sse41.c`, `blake3_sse2.c`, `blake3_sse41_x86-64_*.S`,
  `blake3_sse2_x86-64_*.S`
- `blake3_avx512.c`, `blake3_avx512_x86-64_*.S`
- `blake3_neon.c` (ARM NEON)

The CMake build (in `foundation/crypto/CMakeLists.txt`) defines
`BLAKE3_NO_SSE2`, `BLAKE3_NO_SSE41`, `BLAKE3_NO_AVX2`,
`BLAKE3_NO_AVX512`, and `BLAKE3_USE_NEON=0` to force the dispatch to
the portable path.

## How to update

Re-fetch and replace the C files plus the LICENSE files from a newer
upstream tag, update the table above, run the test suite (`ctest
--test-dir build` against the BLAKE3 vectors in
`ants-test-vectors/vectors/blake3/`), and commit. Pin to a tagged
release; never to `master`.

## Why snapshot, not git submodule

Audit-friendliness. Every byte the protocol's reference client links
against is committed in this repo. A reviewer reading the
`ants-client` codebase sees exactly what `ants_blake3_hash` will
execute, with no transitive fetch step at build time. Submodule
support can be added later if vendoring becomes a maintenance
burden, but for a foundation-layer security primitive, snapshot is
the safer default.
