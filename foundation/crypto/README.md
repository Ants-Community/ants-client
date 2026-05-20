# crypto — Component #1

Crypto primitives library. Foundation layer.

**Status:** in progress (BDFL interim primary; claim still open).
BLAKE3 (hash + `derive_key` + incremental streaming API) implemented
via vendored `deps/blake3` (pinned to upstream `1.8.5`). Ed25519,
BLS12-381, ECVRF-ELL2 still stubbed; per-primitive PRs land them
next.

**Effort:** 2 EM (per IMPLEMENTATION.md).
**Spec:** [RFC-0008 §§ 2–4](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md).

## Public API

Declared in [`include/ants_crypto.h`](./include/ants_crypto.h):

| Primitive | API | Implementation source |
|---|---|---|
| BLAKE3 hash + derive_key + streaming | `ants_blake3_*` | [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) C ref impl (vendored) |
| Ed25519 sign/verify + pubkey derive | `ants_ed25519_*` | `ed25519-donna` or a formally-verified C impl (vendored) |
| BLS12-381 sign/verify + aggregate | `ants_bls_*` | [`supranational/blst`](https://github.com/supranational/blst) (C + asm, vendored) |
| ECVRF-EDWARDS25519-SHA512-ELL2 | `ants_vrf_*` | RFC 9381 reference + Elligator 2 port (forked, vendored) |

## Per-primitive PR sequence (interim-primary plan)

1. Vendor BLAKE3 under `deps/blake3/` and implement `ants_blake3_*`. Test vectors against [RFC-9706](https://www.rfc-editor.org/rfc/rfc9706) and the BLAKE3 spec test pack.
2. Vendor `ed25519-donna` under `deps/ed25519/` and implement `ants_ed25519_*`. Test vectors against [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
3. Vendor `blst` under `deps/blst/` and implement `ants_bls_*`. Test vectors from the [IETF BLS signature draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).
4. Port the RFC 9381 ECVRF C reference + Elligator 2, implement `ants_vrf_*`. Test vectors from [RFC 9381 §A.4](https://www.rfc-editor.org/rfc/rfc9381#name-elligator-2-test-vectors).

Each vendored library carries its upstream license (CC0 for BLAKE3, MIT for ed25519-donna, Apache-2.0 for blst, CC0 for RFC 9381 reference). Notices preserved in `deps/<name>/LICENSE`.

## Good-first-contribution flag

**No.** This component is the project's cryptographic root-of-trust. The bytes the primitives produce gate every protocol-level signature, every fault proof, every committee-membership VRF. Claims encouraged from contributors with prior crypto-library experience.
