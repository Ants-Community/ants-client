/*
 * ants_crypto.h — Crypto primitives library.
 *
 * Wraps mature C implementations of the protocol's crypto primitives:
 * BLAKE3 (hashing + keyed PRF), Ed25519 (peer identity signatures),
 * BLS12-381 (L2 PoUH committee aggregate signatures), and ECVRF with
 * the Elligator 2 hash-to-curve (committee selection).
 *
 * Spec reference: RFC-0008 §§ 2–4 (hash functions, signatures, PRF/VRF).
 *
 * Implementation strategy:
 *   - BLAKE3: vendored from BLAKE3-team/BLAKE3 official C reference impl.
 *   - Ed25519: vendored from ed25519-donna (or a formally-verified C impl).
 *   - BLS12-381: vendored from supranational/blst (C + asm).
 *   - ECVRF-ELL2: forked from the RFC 9381 reference C implementation
 *     with the Elligator 2 hash-to-curve port.
 *
 * Status: implemented — BLAKE3, SHA-256/384/512, Ed25519, BLS12-381,
 * ECVRF, ECDSA P-256/P-384 verify, and RSA-PSS verify are all live.
 *
 * All memory is caller-provided. The library never calls malloc.
 */

#ifndef ANTS_CRYPTO_H
#define ANTS_CRYPTO_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* BLAKE3 — Hashing                                                         */
/*                                                                          */
/* Per RFC-0008 §2.1, all protocol-internal hashing uses BLAKE3 with a      */
/* 32-byte output (256-bit security) in default mode. derive_key mode       */
/* serves as the protocol's PRF (RFC-0008 §4.1) with domain-separation      */
/* context strings reserved in the spec.                                    */
/* ------------------------------------------------------------------------ */

/* Output size in bytes for the protocol's BLAKE3 usage. */
#define ANTS_BLAKE3_HASH_SIZE 32

/*
 * Opaque incremental-hash context. Caller allocates (typically on the
 * stack). The internal layout is defined by the vendored upstream
 * library and not part of the protocol ABI.
 *
 * Layout note: a union forces the struct's alignment to that of the
 * widest member (uint64_t), and `_opaque` overlaps `_align` so the
 * underlying buffer ALSO has uint64_t alignment. Without the union the
 * `uint8_t _opaque[2048]` field would only require byte alignment,
 * and a subsequent cast `(blake3_hasher *)ctx->_opaque` could be
 * undefined behaviour on alignment-strict targets.
 */
typedef union {
    /* Sized for the upstream BLAKE3 hasher state (currently 1912 bytes
     * for the reference impl). Over-sized so a future upstream growth
     * doesn't force an ABI break, with margin for internal alignment
     * padding. The compile-time check in crypto.c asserts the actual
     * size against this bound. */
    uint8_t _opaque[2048];
    /* Anchor member: forces the union's alignment to uint64_t. */
    uint64_t _align;
} ants_blake3_ctx_t;

/*
 * One-shot hash: BLAKE3(data) -> 32-byte output.
 */
ants_error_t ants_blake3_hash(const uint8_t *data, size_t len, uint8_t out[ANTS_BLAKE3_HASH_SIZE]);

/*
 * One-shot keyed PRF: BLAKE3.derive_key(context, key_material) -> 32-byte
 * output. The context string must come from RFC-0008 §4.1's reserved
 * domain-separation table; passing an unreserved context is a caller
 * error but is not validated here (callers are expected to use the
 * named constants).
 */
ants_error_t ants_blake3_derive_key(const char *context,
                                    const uint8_t *key_material,
                                    size_t key_material_len,
                                    uint8_t out[ANTS_BLAKE3_HASH_SIZE]);

/* Incremental API for streaming inputs.
 *
 * Per the BLAKE3 spec the context remains valid after `ants_blake3_final`:
 * subsequent `ants_blake3_update` and `ants_blake3_final` calls produce
 * a hash over the accumulated input (i.e. the streaming hash continues
 * exactly as if `final` had not been called). To start a fresh hash,
 * the caller MUST re-initialise via `ants_blake3_init` (or
 * `ants_blake3_init_derive`).
 */
ants_error_t ants_blake3_init(ants_blake3_ctx_t *ctx);
ants_error_t ants_blake3_init_derive(ants_blake3_ctx_t *ctx, const char *context);
ants_error_t ants_blake3_update(ants_blake3_ctx_t *ctx, const uint8_t *data, size_t len);
ants_error_t ants_blake3_final(ants_blake3_ctx_t *ctx, uint8_t out[ANTS_BLAKE3_HASH_SIZE]);

/* ------------------------------------------------------------------------ */
/* SHA-256 — external-interop hashing ONLY                                  */
/*                                                                          */
/* All protocol-internal hashing is BLAKE3 (above; RFC-0008 §2.1). SHA-256  */
/* exists solely to verify artifacts whose format is fixed by an external   */
/* protocol — concretely the drand randomness beacon (RFC-0008 §4.2): a     */
/* chained drand round signs SHA-256(prev_signature || round_be64) and      */
/* publishes randomness = SHA-256(signature). Do not use SHA-256 for        */
/* anything ANTS-internal.                                                  */
/* ------------------------------------------------------------------------ */

/* Output size in bytes. */
#define ANTS_SHA256_HASH_SIZE 32

/*
 * One-shot hash: SHA-256(data) -> 32-byte output. `data` may be NULL
 * only when `len` is 0.
 */
ants_error_t ants_sha256(const uint8_t *data, size_t len, uint8_t out[ANTS_SHA256_HASH_SIZE]);

/* ------------------------------------------------------------------------ */
/* SHA-512 — external-interop hashing ONLY                                  */
/*                                                                          */
/* Like SHA-256 (above), SHA-512 exists solely to verify artifacts whose    */
/* format is fixed by an external protocol — never for anything             */
/* ANTS-internal (protocol-internal hashing is BLAKE3; RFC-0008 §2.1). It   */
/* is the message digest under the vendor ECDSA signatures in TEE           */
/* attestation quotes (RFC-0005): the ECDSA P-384 verify path is keyed by   */
/* SHA-512/384 digests (AMD SEV-SNP signs P-384, the sibling of Intel TDX's */
/* P-256/SHA-256). Thin wrapper over the libsodium SHA-512 already linked   */
/* for ECVRF, so callers never include vendored headers directly.           */
/* ------------------------------------------------------------------------ */

/* Output size in bytes. */
#define ANTS_SHA512_HASH_SIZE 64

/*
 * One-shot hash: SHA-512(data) -> 64-byte output. `data` may be NULL
 * only when `len` is 0.
 */
ants_error_t ants_sha512(const uint8_t *data, size_t len, uint8_t out[ANTS_SHA512_HASH_SIZE]);

/* ------------------------------------------------------------------------ */
/* SHA-384 — external-interop hashing ONLY                                  */
/*                                                                          */
/* The AMD SEV-SNP attestation report is signed with ECDSA P-384 over a      */
/* SHA-384 digest (RFC-0005); this is that digest. Like SHA-256/512 it is    */
/* never used for anything ANTS-internal (that is BLAKE3; RFC-0008 §2.1).    */
/* libsodium exposes SHA-512 but not SHA-384 (a distinct IV + truncation),   */
/* so this leg is backed by the BearSSL subset already vendored for ECDSA    */
/* P-384 (deps/bearssl).                                                     */
/* ------------------------------------------------------------------------ */

/* Output size in bytes. */
#define ANTS_SHA384_HASH_SIZE 48

/*
 * One-shot hash: SHA-384(data) -> 48-byte output. `data` may be NULL
 * only when `len` is 0.
 */
ants_error_t ants_sha384(const uint8_t *data, size_t len, uint8_t out[ANTS_SHA384_HASH_SIZE]);

/* ------------------------------------------------------------------------ */
/* Ed25519 — Peer identity signatures                                       */
/*                                                                          */
/* Per RFC-0008 §3.1, all peer-to-peer signatures use Ed25519 (RFC 8032).   */
/* ------------------------------------------------------------------------ */

#define ANTS_ED25519_PUBKEY_SIZE  32
#define ANTS_ED25519_PRIVKEY_SIZE 32
#define ANTS_ED25519_SIG_SIZE     64

/*
 * Derive the public key from a 32-byte private key seed (RFC 8032
 * §5.1.5). Useful when storing only the seed and rebuilding the
 * public key at startup.
 */
ants_error_t ants_ed25519_pubkey_from_priv(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                                           uint8_t out_pub[ANTS_ED25519_PUBKEY_SIZE]);

/* Sign `msg` of length `len` with `priv`. Output is the 64-byte
 * signature. */
ants_error_t ants_ed25519_sign(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                               const uint8_t *msg,
                               size_t len,
                               uint8_t out_sig[ANTS_ED25519_SIG_SIZE]);

/* Verify `sig` against `pub` for `msg`. Returns ANTS_OK on valid
 * signature, ANTS_ERROR_MALFORMED on invalid signature, other error
 * codes for argument problems. */
ants_error_t ants_ed25519_verify(const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                                 const uint8_t *msg,
                                 size_t len,
                                 const uint8_t sig[ANTS_ED25519_SIG_SIZE]);

/* ------------------------------------------------------------------------ */
/* BLS12-381 — L2 PoUH committee aggregate signatures                       */
/*                                                                          */
/* Per RFC-0008 §3.3, BLS12-381 with the                                    */
/* BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_ ciphersuite. Aggregate-      */
/* signature usage is at K > BLS_TRANSITION_K (16).                         */
/* ------------------------------------------------------------------------ */

#define ANTS_BLS_PUBKEY_SIZE  48
#define ANTS_BLS_PRIVKEY_SIZE 32
#define ANTS_BLS_SIG_SIZE     96

/* Derive the BLS public key (G1 group) from a 32-byte private key. */
ants_error_t ants_bls_pubkey_from_priv(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                                       uint8_t out_pub[ANTS_BLS_PUBKEY_SIZE]);

/* Sign `msg` with `priv`. Output is a 96-byte signature (G2). */
ants_error_t ants_bls_sign(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                           const uint8_t *msg,
                           size_t len,
                           uint8_t out_sig[ANTS_BLS_SIG_SIZE]);

/* Verify a single signature. */
ants_error_t ants_bls_verify(const uint8_t pub[ANTS_BLS_PUBKEY_SIZE],
                             const uint8_t *msg,
                             size_t len,
                             const uint8_t sig[ANTS_BLS_SIG_SIZE]);

/*
 * Aggregate `n` BLS signatures into a single signature. All input
 * signatures must be over the same message (the L2 block hash). Used
 * by the PoUH committee to produce a single block-finalising
 * signature.
 */
ants_error_t ants_bls_aggregate(const uint8_t (*sigs)[ANTS_BLS_SIG_SIZE],
                                size_t n,
                                uint8_t out_sig[ANTS_BLS_SIG_SIZE]);

/* Verify an aggregate signature against `n` public keys (all signing
 * the same `msg`). */
ants_error_t ants_bls_verify_aggregate(const uint8_t (*pubs)[ANTS_BLS_PUBKEY_SIZE],
                                       size_t n,
                                       const uint8_t *msg,
                                       size_t msg_len,
                                       const uint8_t sig[ANTS_BLS_SIG_SIZE]);

/* ------------------------------------------------------------------------ */
/* ECVRF-EDWARDS25519-SHA512-ELL2 — Verifiable Random Function              */
/*                                                                          */
/* Per RFC-0008 §4.2 (revised to ELL2 in v0.3 to close the timing           */
/* side-channel of the original try-and-increment ciphersuite).             */
/* ------------------------------------------------------------------------ */

#define ANTS_VRF_PROOF_SIZE  80
#define ANTS_VRF_OUTPUT_SIZE 64

/*
 * Produce a VRF proof for input `alpha` using private key `priv`.
 *   - proof: 80-byte verifiable proof (Γ || c || s per RFC 9381 §3.3).
 *
 * The 32-byte `priv` is the same Ed25519 seed used by ants_ed25519_*.
 * (ECVRF reuses Ed25519 keys per RFC 9381 §5.5.)
 */
ants_error_t ants_vrf_prove(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                            const uint8_t *alpha,
                            size_t alpha_len,
                            uint8_t out_proof[ANTS_VRF_PROOF_SIZE]);

/*
 * Verify a VRF proof against public key `pub` and input `alpha`. On
 * success, the 64-byte output `beta` is the hash-to-string of the
 * proof; this is the value the protocol consumes for beacon-derived
 * selection.
 */
ants_error_t ants_vrf_verify(const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                             const uint8_t *alpha,
                             size_t alpha_len,
                             const uint8_t proof[ANTS_VRF_PROOF_SIZE],
                             uint8_t out_beta[ANTS_VRF_OUTPUT_SIZE]);

/* ------------------------------------------------------------------------ */
/* ECDSA P-256 — TEE attestation signature verification (verify-only)       */
/*                                                                          */
/* NIST P-256 (secp256r1) ECDSA verification, used to check the vendor      */
/* signature chains in TEE attestation quotes (RFC-0005). P-256 is Intel    */
/* TDX's curve; AMD SEV-SNP signs with P-384 (a later sibling primitive).   */
/*                                                                          */
/* Verify-only: ANTS never produces P-256 signatures (peer identity is      */
/* Ed25519). Inputs are the raw fixed-width encodings the verifier holds    */
/* after stripping container framing — a 64-byte uncompressed public key    */
/* (X || Y big-endian, no 0x04 prefix) and a 64-byte signature (r || s      */
/* big-endian). DER/SEC1 unwrapping is the TEE layer's job, not the         */
/* primitive's.                                                             */
/* ------------------------------------------------------------------------ */

#define ANTS_ECDSA_P256_PUBKEY_SIZE 64
#define ANTS_ECDSA_P256_SIG_SIZE    64

/*
 * Verify an ECDSA P-256 signature `sig` over the pre-computed message
 * digest `hash` (`hash_len` bytes; SHA-256 gives 32) against public key
 * `pub`. The caller supplies the digest — this function does not hash.
 *
 * Returns ANTS_OK on a valid signature, ANTS_ERROR_MALFORMED on an invalid
 * signature or invalid public key, ANTS_ERROR_INVALID_ARG on a null
 * pointer. Mirrors the ants_ed25519_verify return convention.
 */
ants_error_t ants_ecdsa_p256_verify(const uint8_t pub[ANTS_ECDSA_P256_PUBKEY_SIZE],
                                    const uint8_t *hash,
                                    size_t hash_len,
                                    const uint8_t sig[ANTS_ECDSA_P256_SIG_SIZE]);

/* ------------------------------------------------------------------------ */
/* ECDSA P-384 — TEE attestation signature verification (verify-only)       */
/*                                                                          */
/* NIST P-384 (secp384r1) ECDSA verification, the sibling of the P-256      */
/* primitive above: AMD SEV-SNP signs its attestation report with ECDSA     */
/* P-384 (RFC-0005), where Intel TDX uses P-256. Verify-only — ANTS never   */
/* produces P-384 signatures (peer identity is Ed25519). Inputs are the raw */
/* fixed-width encodings the verifier holds after stripping container       */
/* framing: a 96-byte uncompressed public key (X || Y big-endian, no 0x04   */
/* prefix) and a 96-byte signature (r || s big-endian). DER/SEC1 unwrapping  */
/* is the TEE layer's job, not the primitive's.                             */
/*                                                                          */
/* AMD SEV-SNP digests the report with SHA-384; this function does not hash */
/* — the caller supplies the digest (see ants_sha512 for the SHA-2-512      */
/* family). Backed by the vendored BearSSL EC subset (deps/bearssl).        */
/* ------------------------------------------------------------------------ */

#define ANTS_ECDSA_P384_PUBKEY_SIZE 96
#define ANTS_ECDSA_P384_SIG_SIZE    96

/*
 * Verify an ECDSA P-384 signature `sig` over the pre-computed message
 * digest `hash` (`hash_len` bytes; SHA-384 gives 48, SHA-512 gives 64)
 * against public key `pub`. The caller supplies the digest — this function
 * does not hash.
 *
 * Returns ANTS_OK on a valid signature, ANTS_ERROR_MALFORMED on an invalid
 * signature or invalid public key, ANTS_ERROR_INVALID_ARG on a null
 * pointer. Mirrors the ants_ecdsa_p256_verify return convention.
 */
ants_error_t ants_ecdsa_p384_verify(const uint8_t pub[ANTS_ECDSA_P384_PUBKEY_SIZE],
                                    const uint8_t *hash,
                                    size_t hash_len,
                                    const uint8_t sig[ANTS_ECDSA_P384_SIG_SIZE]);

/* ------------------------------------------------------------------------ */
/* RSA RSASSA-PSS — TEE attestation certificate-chain verification          */
/*                                                                          */
/* RSASSA-PSS signature verification (verify-only), the third TEE-chain     */
/* primitive after P-256 and P-384. AMD SEV-SNP's ASK/ARK certificate chain */
/* is RSA-4096 RSASSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt     */
/* (RFC-0005); the report itself is ECDSA P-384 (above). This is the only   */
/* RSA in the protocol — Intel TDX's PKI is all-ECDSA and peer identity is  */
/* Ed25519. Verify-only: ANTS never produces RSA signatures.                */
/*                                                                          */
/* The modulus and exponent are unsigned big-endian (the                    */
/* SubjectPublicKeyInfo encoding, leading zeros allowed); the signature is  */
/* the raw big-endian integer, the same byte-length as the modulus (512 for */
/* RSA-4096). DER/SPKI unwrapping is the TEE layer's job, not the           */
/* primitive's. As with the ECDSA verifiers the caller supplies the message */
/* digest — this function does not hash. Backed by the vendored BearSSL     */
/* RSA-PSS subset (deps/bearssl).                                           */
/* ------------------------------------------------------------------------ */

/* RSA-4096 — the largest modulus ANTS verifies (AMD ASK/ARK). */
#define ANTS_RSA_MAX_MODULUS_SIZE 512

/*
 * Verify a PKCS#1 RSASSA-PSS signature `sig` (`sig_len` bytes) over the
 * pre-computed message digest `hash` (`hash_len` bytes) against the RSA
 * public key (`modulus`/`modulus_len`, `exponent`/`exponent_len`, both
 * unsigned big-endian).
 *
 * The PSS parameters are derived from the digest length: hash_len == 48
 * selects SHA-384 as both the data hash and the MGF1 hash with a 48-byte
 * salt, matching AMD SEV-SNP's ASK/ARK chain. Other digest lengths are
 * rejected with ANTS_ERROR_INVALID_ARG (no other RSA-PSS profile is used by
 * the protocol). `sig_len` must equal the modulus byte-length.
 *
 * Returns ANTS_OK on a valid signature, ANTS_ERROR_MALFORMED on an invalid
 * signature or invalid public key, ANTS_ERROR_INVALID_ARG on a null pointer,
 * a zero-length input, an oversized modulus (> ANTS_RSA_MAX_MODULUS_SIZE), or
 * an unsupported digest length. Mirrors the ants_ecdsa_p384_verify return
 * convention.
 */
ants_error_t ants_rsa_pss_verify(const uint8_t *modulus,
                                 size_t modulus_len,
                                 const uint8_t *exponent,
                                 size_t exponent_len,
                                 const uint8_t *hash,
                                 size_t hash_len,
                                 const uint8_t *sig,
                                 size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CRYPTO_H */
