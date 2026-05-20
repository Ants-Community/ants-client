# deps/ed25519 — vendored libsodium Ed25519 ref10 subset

Vendored snapshot of the Ed25519 reference-10 (`ref10`) implementation
from [jedisct1/libsodium](https://github.com/jedisct1/libsodium).
`ref10` is the formally-studied portable C implementation that
libsodium has tracked since the original NaCl Ed25519 work.

| Field | Value |
|---|---|
| **Upstream** | https://github.com/jedisct1/libsodium |
| **Pinned tag** | `1.0.22-RELEASE` |
| **Vendored on** | 2026-05-20 |
| **License** | ISC (see [`LICENSE`](./LICENSE)) — compatible with the ants-client Apache-2.0 OR MIT dual-license |

## What is vendored

The minimum subset of libsodium needed to compile and run Ed25519
sign / verify / pubkey-derive with deterministic RFC 8032 semantics:

### Source files (`src/`)

| File | Upstream origin |
|---|---|
| `sign_ed25519.c` | `crypto_sign/ed25519/sign_ed25519.c` (top-level dispatch) |
| `ref10_keypair.c` | `crypto_sign/ed25519/ref10/keypair.c` |
| `ref10_sign.c` | `crypto_sign/ed25519/ref10/sign.c` |
| `ref10_open.c` | `crypto_sign/ed25519/ref10/open.c` |
| `ed25519_ref10_core.c` | `crypto_core/ed25519/ref10/ed25519_ref10.c` (fe25519 + ge25519 + sc25519 ops) |
| `hash_sha512.c` | `crypto_hash/sha512/cp/hash_sha512_cp.c` (SHA-512 portable) |
| `verify.c` | `crypto_verify/verify.c` (constant-time `memcmp` family) |
| `utils.c` | `sodium/utils.c` (sodium_memzero, sodium_pad, …) |
| `sodium_stub.c` | *not from upstream* — minimal `sodium_misuse()` / `randombytes_buf()` abort-stubs (see file comment) |

### Headers

| File | Upstream origin |
|---|---|
| `include/crypto_sign.h`, `crypto_sign_ed25519.h`, `crypto_hash.h`, `crypto_hash_sha512.h`, `crypto_verify_{16,32,64}.h`, `crypto_scalarmult_curve25519.h`, `utils.h`, `core.h`, `export.h`, `randombytes.h` | `include/sodium/*.h` |
| `include/sign_ed25519_ref10.h` | `crypto_sign/ed25519/ref10/sign_ed25519_ref10.h` |
| `include/private/ed25519_ref10.h`, `ed25519_ref10_fe_25_5.h`, `ed25519_ref10_fe_51.h`, `common.h`, `quirks.h` | `include/sodium/private/*.h` |
| `include/private/fe_25_5/*.h`, `fe_51/*.h` | `crypto_core/ed25519/ref10/fe_{25_5,51}/*.h` (field-element constants) |

All upstream files are bit-identical to libsodium 1.0.22 except for
one mechanical rename in `src/sign_ed25519.c`: the include `"ref10/sign_ed25519_ref10.h"`
has been adjusted to `"sign_ed25519_ref10.h"` to match the flattened
header layout under `include/`.

## What is intentionally not vendored

- **SIMD acceleration** — disabled via the CMake compile definitions.
  The portable C path is forced on every architecture; AMD64 inline
  asm, SSE2/AVX paths in `verify.c`, and NEON paths are unreachable
  because the `HAVE_*_ASM` / `HAVE_*MMINTRIN_H` macros are not defined.
- **Memory protection plumbing** — libsodium's `sodium_malloc`,
  `sodium_mlock`, `sodium_mprotect_*` are present in `utils.c` for
  compilation but our wrapper does not call them. They are stripped
  from the link footprint via dead-code elimination.
- **Randomness backend** — `randombytes_buf` is stubbed to `abort()`
  in `sodium_stub.c`. The deterministic Ed25519 ref10 sign path does
  not call it. Code paths that do (e.g. libsodium's `sodium_malloc`
  zero-init) are also not used by our wrapper. The stub fails loudly
  if any such path is unexpectedly hit, surfacing the dependency.
- **Other libsodium primitives** — secretbox, hashing-other-than-SHA-512,
  HKDF, etc. None are vendored.

## How to update

Re-fetch the file set from a newer libsodium tag, re-apply the single
`sign_ed25519.c` include-path edit, run the test suite (`ctest --test-dir
build` in the repo root; the RFC 8032 §7.1 vectors in
`foundation/crypto/tests/test_crypto.c` must pass), update the table
above, and commit. Pin to a tagged release; never to `master`.

## Why snapshot, not git submodule

Same rationale as `deps/blake3/`: audit-friendliness for a foundation-
layer security primitive. Every byte the reference client links
against is committed in this repo.

## Honest residuals

- `sodium_stub.c` provides abort-stubs for `sodium_misuse()` and
  `randombytes_buf()`. These are correct fail-closed behaviour for the
  current wrapper API (which doesn't exercise either path), but a
  future PR that adds a randomness-dependent operation (key
  generation, deterministic-random variant) must wire a real entropy
  source rather than rely on the stub.
- The `utils.c` we vendor is the full libsodium file. Most of its
  body (memory-protection plumbing) is dead code in the link. A
  follow-up PR may slim it to a `utils_lite.c` that contains only
  `sodium_memzero` + `sodium_memcmp` + `sodium_increment`, but the
  current full-file approach keeps the upstream bytes intact and
  defers that decision.
