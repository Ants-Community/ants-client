# deps/blst — vendored supranational/blst (BLS12-381)

Vendored snapshot of the BLS12-381 reference implementation from
[supranational/blst](https://github.com/supranational/blst). blst is
the constant-time, formally-audited C+asm library that ships with
Ethereum 2.0 consensus clients, Filecoin, and most production BLS
deployments.

| Field | Value |
|---|---|
| **Upstream** | https://github.com/supranational/blst |
| **Pinned tag** | `v0.3.15` |
| **Vendored on** | 2026-05-21 |
| **License** | Apache-2.0 (see [`LICENSE`](./LICENSE)) — compatible with the ants-client Apache-2.0 OR MIT dual-license |

## What is vendored

Single-translation-unit build: the only file we compile is
`src/server.c`, which internally `#include`s every other `.c` file
under `src/`. This matches the upstream build pattern and is also the
recommended way for downstream embedders.

### Source files (`src/`)

37 `.c` and `.h` files vendored verbatim from
`https://github.com/supranational/blst/tree/v0.3.15/src/`. The full
list (compiled transitively via `server.c`):

| Category | Files |
|---|---|
| Single-TU entrypoint | `server.c` (the only one CMake compiles) |
| Field arithmetic | `vect.c`, `vect.h`, `bytes.h`, `consts.c`, `consts.h`, `fields.h`, `errors.h` |
| Portable C path (no asm) | `no_asm.h` |
| G1 / G2 / pairing | `e1.c`, `e2.c`, `ec_ops.h`, `ec_mult.h`, `pairing.c`, `fp12_tower.c`, `point.h` |
| Hash-to-curve | `map_to_g1.c`, `map_to_g2.c`, `hash_to_field.c` |
| BLS keygen | `keygen.c` |
| Aggregation | `aggregate.c`, `bulk_addition.c`, `multi_scalar.c` |
| Math helpers | `sqrt.c`, `sqrt-addchain.h`, `recip.c`, `recip-addchain.h`, `pentaroot.c`, `pentaroot-addchain.h`, `exp.c` |
| Misc | `cpuid.c`, `rb_tree.c`, `sha256.h`, `client_min_pk.c`, `client_min_sig.c`, `blst_t.hpp`, `exports.c` |

### Headers

| File | Purpose |
|---|---|
| `include/blst.h` | Public C API |
| `include/blst_aux.h` | Auxiliary helpers |

### What is intentionally NOT vendored

- **Architecture-specific assembly** under `build/{elf,coff,mach-o,cheri}/`
  — every architecture's tuned asm path is excluded. We force the
  portable C path via `-D__BLST_NO_ASM__` so the asm files are
  unreachable at link time regardless of host architecture.
- **`build.sh`, `build.bat`, `bindings/`** — we don't ship build
  scripts or language bindings; the CMakeLists.txt in this directory
  is sufficient.
- **Test vectors and benchmarks** under `bindings/python/`,
  `bindings/rust/` — out of scope for the C wrapper.

## Local patches

All edits are annotated in-source with the marker `ants-client local
patch` for mechanical rediscovery on upstream re-fetches.

1. **`src/vect.h`** — branch-reorder for the `LIMB_T_BITS` macro
   chain. Upstream order is `(x86_64|aarch64) → _WIN64 →
   __BLST_NO_ASM__ → fallback`, which on arm64 selects
   `LIMB_T_BITS=64` even when `__BLST_NO_ASM__` is set; but the
   portable `no_asm.h` only defines `llimb_t` (the double-width
   multiplication type) when `LIMB_T_BITS==32`, so the portable build
   fails to compile on Apple Silicon. The patch hoists
   `__BLST_NO_ASM__` ahead of the 64-bit hardware branches so the
   32-bit-limb path wins whenever we ask for the portable build. The
   asm paths still work for builds that don't define
   `__BLST_NO_ASM__` — we just never make such a build.

## Build configuration

The local `CMakeLists.txt` compiles `src/server.c` with three
defines that fix the build target:

- `__BLST_NO_ASM__` — force the portable C limb path.
- `__BLST_NO_CPUID__` — skip the x86 CPUID detection (which references
  intrinsics that don't compile under arm64 even with the asm path
  disabled).
- `__BLST_PORTABLE__` — additionally disable ADX-specific
  optimisations in `vect.h` and the ARM crypto extension in
  `sha256.h` (belt-and-braces against any conditionally-compiled fast
  path slipping through).

## How to update

1. Download the new release tarball from the upstream tags page (e.g.
   `https://github.com/supranational/blst/releases/tag/vX.Y.Z`).
2. Replace the contents of `src/` and `include/` with the upstream
   release, EXCLUDING `src/asm/*` and `build/*`.
3. Re-apply the single local patch by searching for `ants-client
   local patch` in `src/vect.h` and applying the same branch reorder
   if upstream hasn't merged a similar change.
4. Update this README's pinning table and the file list above.
5. Run `ctest --test-dir build` from the repo root — the BLS tests
   in `foundation/crypto/tests/test_crypto.c` MUST pass byte-for-byte,
   including the G1-generator-at-sk=1 vector which is a curve-
   definition invariant of any conformant BLS implementation.
6. Pin to a tagged release; never to `master`.

## Why snapshot, not git submodule

Same rationale as `deps/blake3/` and `deps/ed25519/`: audit-
friendliness for a foundation-layer security primitive. Every byte the
reference client links against is committed in this repo.
