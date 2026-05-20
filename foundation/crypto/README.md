# crypto — Component #1

Crypto primitives library. Foundation layer.

**Status:** pending claim.
**Effort:** 2 EM.
**Spec:** [RFC-0008 §§ 2–4](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md) (hash functions, signatures, PRF/VRF).
**Dependencies:** none internal. Vendored: BLAKE3 C ref, `blst`, `ed25519-donna`, ECVRF-ELL2 port.

## Scope

Wraps mature C libraries to provide a uniform, testable surface for
the protocol's crypto primitives:

- **BLAKE3** hashing — 32-byte output, default mode + `derive_key`
  mode with the reserved context strings of RFC-0008 §4.1.
- **Ed25519** sign/verify — per RFC 8032, used for peer identity
  signatures and trustee-rotation acks.
- **BLS12-381** sign/verify/aggregate — `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`
  ciphersuite per IETF draft-irtf-cfrg-bls-signature, used for L2
  PoUH committee aggregate signatures (`K > BLS_TRANSITION_K`).
- **ECVRF-EDWARDS25519-SHA512-ELL2** prove/verify — RFC 9381 with
  Elligator 2 hash-to-curve (constant-time, per RFC-0008 v0.3+).
  Used for L2 PoUH committee selection.

## Intended public API

```c
// blake3.h
typedef struct ants_blake3_ctx ants_blake3_ctx_t;
void ants_blake3_init(ants_blake3_ctx_t *ctx);
void ants_blake3_init_keyed(ants_blake3_ctx_t *ctx, const uint8_t key[32]);
void ants_blake3_init_derive(ants_blake3_ctx_t *ctx, const char *context);
void ants_blake3_update(ants_blake3_ctx_t *ctx, const uint8_t *data, size_t len);
void ants_blake3_final(ants_blake3_ctx_t *ctx, uint8_t out[32]);
void ants_blake3_derive_key(const char *context, const uint8_t *km, size_t km_len, uint8_t out[32]);

// ed25519.h
ants_error_t ants_ed25519_sign(const uint8_t sk[32], const uint8_t *msg, size_t len, uint8_t sig[64]);
ants_error_t ants_ed25519_verify(const uint8_t pk[32], const uint8_t *msg, size_t len, const uint8_t sig[64]);

// bls12_381.h
ants_error_t ants_bls_sign(const uint8_t sk[32], const uint8_t *msg, size_t len, uint8_t sig[96]);
ants_error_t ants_bls_verify(const uint8_t pk[48], const uint8_t *msg, size_t len, const uint8_t sig[96]);
ants_error_t ants_bls_aggregate(const uint8_t **sigs, size_t n, uint8_t out_sig[96]);
ants_error_t ants_bls_verify_aggregate(const uint8_t **pks, size_t n,
                                       const uint8_t *msg, size_t len, const uint8_t sig[96]);

// ecvrf.h  (ELL2 ciphersuite)
ants_error_t ants_vrf_prove(const uint8_t sk[32], const uint8_t *alpha, size_t len,
                            uint8_t proof[80]);
ants_error_t ants_vrf_verify(const uint8_t pk[32], const uint8_t *alpha, size_t len,
                             const uint8_t proof[80], uint8_t out_beta[64]);
```

Signatures are non-binding sketches; the claiming contributor's
proposal can refine names and ordering.

## Test vectors

Every primitive ships fixed-input/fixed-output test vectors in the
sibling repo
[`Ants-Community/ants-test-vectors`](https://github.com/Ants-Community/ants-test-vectors),
keyed by primitive + context string per RFC-0008 §4.1. The
component's CI must validate against every relevant vector before
merge.

## Good-first-contribution flag

This is **not** a good first contribution: it touches the project's
cryptographic root-of-trust. Claims are encouraged from contributors
with prior crypto-library experience (any of Bitcoin Core, Dalek
crates, Tendermint Core, Solana Labs sig-libs would qualify).
