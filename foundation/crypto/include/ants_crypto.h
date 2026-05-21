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
 * Status: API surface declared; implementation is stubbed (returns
 * ANTS_ERROR_NOT_IMPLEMENTED) and lands per-primitive in subsequent PRs.
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

/* Incremental API for streaming inputs. */
ants_error_t ants_blake3_init(ants_blake3_ctx_t *ctx);
ants_error_t ants_blake3_init_derive(ants_blake3_ctx_t *ctx, const char *context);
ants_error_t ants_blake3_update(ants_blake3_ctx_t *ctx, const uint8_t *data, size_t len);
ants_error_t ants_blake3_final(ants_blake3_ctx_t *ctx, uint8_t out[ANTS_BLAKE3_HASH_SIZE]);

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

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CRYPTO_H */
