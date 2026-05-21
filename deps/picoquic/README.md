# deps/picoquic — vendored private-octopus/picoquic (IETF QUIC reference)

Vendored snapshot of [private-octopus/picoquic](https://github.com/private-octopus/picoquic), the IETF QUIC reference implementation in pure C. Used as the transport backbone for the ANTS network layer.

| Field | Value |
|---|---|
| **Upstream** | https://github.com/private-octopus/picoquic |
| **Pinned commit** | `d9c705a451837a5f05e116726ccc34e93b530cb3` (master HEAD, 2026-05-21) |
| **Vendored on** | 2026-05-21 |
| **License** | BSD-3-Clause (see [`LICENSE`](./LICENSE)) — compatible with the ants-client Apache-2.0 OR MIT dual-license |
| **TLS backend** | [`deps/picotls`](../picotls) minicrypto (no OpenSSL, no AES-NI, no mbedTLS) |

## What is vendored

The `picoquic/` source directory (the core library, 47 `.c` files + 33 `.h` files, ~64k LOC), excluding three backend-specific TLS adapter files:

- ~~`picoquic_ptls_openssl.c`~~ — OpenSSL backend (not vendored)
- ~~`picoquic_ptls_fusion.c`~~ — AES-NI fusion AES-GCM (not vendored)
- ~~`picoquic_mbedtls.c`~~ — mbedTLS backend (not vendored)
- ~~`mbedtls_sign.inc`~~ — mbedTLS signature helper (not vendored)

The remaining `picoquic_ptls_minicrypto.c` is the only TLS adapter compiled. It registers cifra/micro-ecc-based cipher suites with picotls.

## What is intentionally NOT vendored

- **Test trees**: `picoquictest/`, `picoquic_t/`, `UnitTest1/`, `PerfAndStressTest/` — picoquic's own test suite.
- **Tools & examples**: `picoquicfirst/`, `sample/`, `quicwind/`, `picohttp/`, `baton_app/`, `pqbench_app/`, `p_sim/`, `thread_tester/`, `picoquic_mbedtls/`.
- **Build scaffolding**: `Dockerfile`, `appveyor.yml`, `picoquic.sln`, `CMakeSettings.json`, `cmake/`, `ci/`, `scripts/`, the top-level upstream `CMakeLists.txt`.
- **Logging extras**: `loglib/`, `picolog/`, `performance_log.c` (the .c is in the lib build; the standalone tool isn't).
- **Documentation, certs**: `doc/`, `certs/`, `*.md` (except this README), `*.htm`, `*.txt` from upstream.

## Build configuration

The local `CMakeLists.txt` builds the static library `picoquic_core` with three compile definitions:

- `PICOQUIC_WITHOUT_OPENSSL=1` — picoquic's own no-OpenSSL guard.
- `PTLS_WITHOUT_OPENSSL=1` — picotls's no-OpenSSL guard (picoquic transitively includes `picotls/openssl.h` from `tls_api.c` and we need to gate that out).

`picoquic_core` links publicly against `picotls_minicrypto` (which itself links `picotls_core`).

## Local patches

None yet. The build works clean against upstream master at the pinned SHA with just the per-target compile defines + warning suppressions. If the upstream re-fetch surfaces incompatibilities, they will be annotated with `ants-client local patch` markers.

## How to update

1. Clone `private-octopus/picoquic` at the new commit/tag.
2. Re-copy the `picoquic/` source directory into `deps/picoquic/picoquic/`.
3. Delete the four excluded files: `picoquic_ptls_openssl.c`, `picoquic_ptls_fusion.c`, `picoquic_mbedtls.c`, `mbedtls_sign.inc`.
4. Update the file list in `deps/picoquic/CMakeLists.txt` if upstream added/removed source files.
5. Run `ctest --test-dir build` — at minimum, all existing tests must still pass. (When the transport wire-up lands, picoquic-specific tests will be added.)
6. Update the pinned-commit line in this README's table.
7. Pin to a release tag if available; otherwise document the master commit SHA.

## Why snapshot, not git submodule

Same rationale as `deps/blake3` / `deps/ed25519` / `deps/blst` / `deps/picotls`: audit-friendliness for a security-critical, network-facing primitive. Every byte the reference client links against is committed in this repo. Submodules would invite "I'll check the deep tag history later" complacency on a transport that touches every peer-handshake.
