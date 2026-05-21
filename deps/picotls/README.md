# deps/picotls — vendored h2o/picotls (TLS 1.3 backend)

Vendored snapshot of [h2o/picotls](https://github.com/h2o/picotls), the
TLS 1.3 reference implementation in C used by picoquic for the QUIC
handshake. We vendor the **minicrypto** backend exclusively (cifra +
micro-ecc, all pure C99 / public domain / BSD); the OpenSSL, mbedTLS,
AEGIS, and AES-NI fusion backends are NOT vendored.

| Field | Value |
|---|---|
| **Upstream** | https://github.com/h2o/picotls |
| **Pinned commit** | `7c32032f91449d695b24b82955f20d04d47e6cff` (master HEAD, 2026-05-21) |
| **Vendored on** | 2026-05-21 |
| **License** | MIT (picotls) + CC0 (cifra) + 2-clause BSD (micro-ecc) — all compatible with ants-client's Apache-2.0 OR MIT outbound. See [`LICENSE`](./LICENSE). |

## What is vendored

### picotls core (TLS state machine)

| File | Upstream origin |
|---|---|
| `lib/picotls.c` | `lib/picotls.c` |
| `lib/hpke.c` | `lib/hpke.c` |
| `lib/pembase64.c` | `lib/pembase64.c` |

### picotls minicrypto adapter

| File | Upstream origin |
|---|---|
| `lib/cifra.c` | `lib/cifra.c` |
| `lib/cifra/{x25519,chacha20,aes128,aes256,random}.c` + `aes-common.h` | `lib/cifra/*` |
| `lib/chacha20poly1305.h` | `lib/chacha20poly1305.h` |
| `lib/minicrypto-pem.c` | `lib/minicrypto-pem.c` |
| `lib/uecc.c` | `lib/uecc.c` |
| `lib/asn1.c` | `lib/asn1.c` |
| `lib/ffx.c` | `lib/ffx.c` |

### cifra (CC0 — symmetric primitives)

`deps/cifra/src/{aes,blockwise,chacha20,chash,curve25519,drbg,hmac,gcm,gf128,modes,poly1305,sha256,sha512}.c` plus headers. Full snapshot of `deps/cifra/src/` from upstream `h2o/picotls`.

### micro-ecc (2-clause BSD — secp256r1)

`deps/micro-ecc/{uECC.c, uECC.h, uECC_vli.h, types.h, platform-specific.inc, curve-specific.inc, asm_*.inc}` from upstream `h2o/picotls/deps/micro-ecc`.

### Public headers

`include/picotls.h` plus `include/picotls/{asn1,certificate_compression,ffx,minicrypto,pembase64,fusion,mbedtls,openssl,ptlsbcrypt}.h`. We don't compile against fusion/mbedtls/openssl/ptlsbcrypt but the headers exist and are conditionally included by picoquic's source files; rather than patch every #include we vendor the whole header set and disable the backends via `PTLS_WITHOUT_OPENSSL=1` etc. in the CMakeLists.

## What is intentionally NOT vendored

- **Test trees, fuzzers, build scripts, IDE projects**.
- **OpenSSL backend** (`lib/openssl.c`, `lib/mbedtls.c`, `lib/mbedtls_sign.c`, `lib/fusion.c`, `lib/libaegis.c`, `lib/ptlsbcrypt.c`).
- **Brotli certificate compression** (would require linking `libbrotlidec` / `libbrotlienc`).
- **DTrace probes** (`picotls-probes.d`, `picotls-probes.h` generation).

## Local patches

None yet. If the upstream re-fetch surfaces incompatibilities, they will be annotated with `ants-client local patch` markers.

## How to update

1. Clone `h2o/picotls` at the new commit/tag.
2. Re-copy the files enumerated above into the matching paths under this directory.
3. Re-copy `deps/cifra/src/`, `deps/micro-ecc/` (excluding test dirs).
4. Run `ctest --test-dir build` from the repo root — the existing crypto and CBOR tests must still pass (picotls itself has no in-tree tests in our build).
5. Update the pinned-commit line in this README's table.
6. Pin to a release tag if available; otherwise document the master commit SHA.

## Why snapshot, not git submodule

Same rationale as `deps/blake3` / `deps/ed25519` / `deps/blst`: audit-friendliness for a security-critical primitive. Every byte the reference client links against is committed in this repo.
