/*
 * crypto.c — Crypto primitives library.
 *
 * Status: BLAKE3 implemented via vendored deps/blake3 (v1.8.5).
 * Ed25519 implemented via vendored deps/ed25519 (libsodium 1.0.22
 * ref10 subset). BLS12-381 and ECVRF-ELL2 still stubbed.
 */

#include "ants_crypto.h"

#include "blake3.h"
#include "blst.h"
#include "crypto_sign_ed25519.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The opaque ctx exposed in ants_crypto.h must be at least as large
 * (and at least as well aligned) as the vendored blake3_hasher. The
 * trick below is a portable C99 compile-time assertion: if the
 * condition fails, the typedef declares an array of size -1, which is
 * a compile error. If blake3_hasher ever grows, the _opaque buffer in
 * ants_blake3_ctx_t must be enlarged accordingly. */
typedef char ants_blake3_ctx_size_check
    [(sizeof(blake3_hasher) <= sizeof(((ants_blake3_ctx_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* BLAKE3                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * One-shot hash. Initialises a temporary hasher on the stack, feeds the
 * input, finalises into the 32-byte output buffer.
 */
ants_error_t ants_blake3_hash(const uint8_t *data, size_t len, uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    if ((data == NULL && len > 0) || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blake3_hasher h;
    blake3_hasher_init(&h);
    if (len > 0) {
        blake3_hasher_update(&h, data, len);
    }
    blake3_hasher_finalize(&h, out, ANTS_BLAKE3_HASH_SIZE);
    return ANTS_OK;
}

/*
 * Derive-key one-shot. `context` is a NUL-terminated ASCII
 * domain-separation string from RFC-0008 §4.1's reserved table; the
 * library does not validate against the table (callers should use the
 * named constants but the upstream BLAKE3 accepts any context string).
 */
ants_error_t ants_blake3_derive_key(const char *context,
                                    const uint8_t *key_material,
                                    size_t key_material_len,
                                    uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    if (context == NULL || (key_material == NULL && key_material_len > 0) || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, context);
    if (key_material_len > 0) {
        blake3_hasher_update(&h, key_material, key_material_len);
    }
    blake3_hasher_finalize(&h, out, ANTS_BLAKE3_HASH_SIZE);
    return ANTS_OK;
}

ants_error_t ants_blake3_init(ants_blake3_ctx_t *ctx)
{
    if (ctx == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blake3_hasher_init((blake3_hasher *)(void *)ctx->_opaque);
    return ANTS_OK;
}

ants_error_t ants_blake3_init_derive(ants_blake3_ctx_t *ctx, const char *context)
{
    if (ctx == NULL || context == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blake3_hasher_init_derive_key((blake3_hasher *)(void *)ctx->_opaque, context);
    return ANTS_OK;
}

ants_error_t ants_blake3_update(ants_blake3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len > 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (len > 0) {
        blake3_hasher_update((blake3_hasher *)(void *)ctx->_opaque, data, len);
    }
    return ANTS_OK;
}

ants_error_t ants_blake3_final(ants_blake3_ctx_t *ctx, uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    if (ctx == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blake3_hasher_finalize(
        (const blake3_hasher *)(const void *)ctx->_opaque, out, ANTS_BLAKE3_HASH_SIZE);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Ed25519                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Note on the libsodium Ed25519 ABI: libsodium represents the secret
 * key as a 64-byte concatenation of the 32-byte seed and the 32-byte
 * public key, derived once at keypair time. Our public API exposes
 * only the 32-byte seed (`priv`) — the matching public key is derived
 * on demand from the seed in each call. This keeps the protocol's key
 * storage simple at the cost of a small per-call seed_keypair
 * expansion, which is negligible against the cost of the actual
 * sign/verify operation.
 */
ants_error_t ants_ed25519_pubkey_from_priv(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                                           uint8_t out_pub[ANTS_ED25519_PUBKEY_SIZE])
{
    if (priv == NULL || out_pub == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    if (crypto_sign_ed25519_seed_keypair(out_pub, sk, priv) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    /* Zero the derived 64-byte sk; we don't keep it. */
    memset(sk, 0, sizeof sk);
    return ANTS_OK;
}

ants_error_t ants_ed25519_sign(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                               const uint8_t *msg,
                               size_t len,
                               uint8_t out_sig[ANTS_ED25519_SIG_SIZE])
{
    if (priv == NULL || (msg == NULL && len > 0) || out_sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_seed_keypair(pk, sk, priv) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    int rc = crypto_sign_ed25519_detached(out_sig, NULL, msg, len, sk);
    memset(sk, 0, sizeof sk);
    if (rc != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

ants_error_t ants_ed25519_verify(const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                                 const uint8_t *msg,
                                 size_t len,
                                 const uint8_t sig[ANTS_ED25519_SIG_SIZE])
{
    if (pub == NULL || (msg == NULL && len > 0) || sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (crypto_sign_ed25519_verify_detached(sig, msg, len, pub) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* BLS12-381                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Variant: min-pubkey-size. Public keys are points on G1 (48 bytes
 * compressed); signatures are points on G2 (96 bytes compressed). This
 * is the variant blst calls `pk_in_g1` and the IETF BLS draft calls
 * "minimal-pubkey-size".
 *
 * Ciphersuite (RFC-0008 §3.3):
 *   BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
 * — Basic mode, no application augmentation. The DST is the
 * ciphersuite identifier itself, passed verbatim to `hash_to_curve`
 * (RFC 9380) which produces the message hash on G2.
 */
static const uint8_t ANTS_BLS_DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
#define ANTS_BLS_DST_LEN (sizeof ANTS_BLS_DST - 1)

ants_error_t ants_bls_pubkey_from_priv(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                                       uint8_t out_pub[ANTS_BLS_PUBKEY_SIZE])
{
    if (priv == NULL || out_pub == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_scalar sk;
    blst_p1 pk;
    blst_scalar_from_bendian(&sk, priv);
    if (!blst_sk_check(&sk)) {
        return ANTS_ERROR_MALFORMED;
    }
    blst_sk_to_pk_in_g1(&pk, &sk);
    blst_p1_compress(out_pub, &pk);
    memset(&sk, 0, sizeof sk);
    return ANTS_OK;
}

ants_error_t ants_bls_sign(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                           const uint8_t *msg,
                           size_t len,
                           uint8_t out_sig[ANTS_BLS_SIG_SIZE])
{
    if (priv == NULL || (msg == NULL && len > 0) || out_sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_scalar sk;
    blst_p2 hash;
    blst_p2 sig;
    blst_scalar_from_bendian(&sk, priv);
    if (!blst_sk_check(&sk)) {
        return ANTS_ERROR_MALFORMED;
    }
    blst_hash_to_g2(&hash, msg, len, ANTS_BLS_DST, ANTS_BLS_DST_LEN, NULL, 0);
    blst_sign_pk_in_g1(&sig, &hash, &sk);
    blst_p2_compress(out_sig, &sig);
    memset(&sk, 0, sizeof sk);
    return ANTS_OK;
}

ants_error_t ants_bls_verify(const uint8_t pub[ANTS_BLS_PUBKEY_SIZE],
                             const uint8_t *msg,
                             size_t len,
                             const uint8_t sig[ANTS_BLS_SIG_SIZE])
{
    if (pub == NULL || (msg == NULL && len > 0) || sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_p1_affine pk_aff;
    blst_p2_affine sig_aff;
    if (blst_p1_uncompress(&pk_aff, pub) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    if (blst_p2_uncompress(&sig_aff, sig) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    /* hash_or_encode=true selects RFC 9380 hash_to_curve (the RO
     * ciphersuite); encode_to_curve would be the NU variant. */
    if (blst_core_verify_pk_in_g1(
            &pk_aff, &sig_aff, true, msg, len, ANTS_BLS_DST, ANTS_BLS_DST_LEN, NULL, 0) !=
        BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/*
 * Aggregate `n` BLS signatures into a single 96-byte signature. The
 * group operation is point addition on G2. Each input is decompressed,
 * subgroup-checked (blst_aggregate_in_g2 does the in-G2 check), and
 * added to a running accumulator. n=0 is a caller error.
 */
ants_error_t ants_bls_aggregate(const uint8_t (*sigs)[ANTS_BLS_SIG_SIZE],
                                size_t n,
                                uint8_t out_sig[ANTS_BLS_SIG_SIZE])
{
    if (sigs == NULL || n == 0 || out_sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_p2_affine first;
    blst_p2 acc;
    if (blst_p2_uncompress(&first, sigs[0]) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    blst_p2_from_affine(&acc, &first);
    for (size_t i = 1; i < n; i++) {
        if (blst_aggregate_in_g2(&acc, &acc, sigs[i]) != BLST_SUCCESS) {
            return ANTS_ERROR_MALFORMED;
        }
    }
    blst_p2_compress(out_sig, &acc);
    return ANTS_OK;
}

/*
 * Verify an aggregate signature: FastAggregateVerify from
 * draft-irtf-cfrg-bls-signature-05 §3.3.4. All n public keys MUST
 * correspond to signatures over the SAME `msg` — that is the L2 PoUH
 * committee case (every member signs the same block hash). Aggregates
 * the n pubkeys into one G1 point, then runs CoreVerify against the
 * single aggregated signature. n=0 is a caller error.
 */
ants_error_t ants_bls_verify_aggregate(const uint8_t (*pubs)[ANTS_BLS_PUBKEY_SIZE],
                                       size_t n,
                                       const uint8_t *msg,
                                       size_t msg_len,
                                       const uint8_t sig[ANTS_BLS_SIG_SIZE])
{
    if (pubs == NULL || n == 0 || (msg == NULL && msg_len > 0) || sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_p1_affine first;
    blst_p1 acc_pk;
    if (blst_p1_uncompress(&first, pubs[0]) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    blst_p1_from_affine(&acc_pk, &first);
    for (size_t i = 1; i < n; i++) {
        if (blst_aggregate_in_g1(&acc_pk, &acc_pk, pubs[i]) != BLST_SUCCESS) {
            return ANTS_ERROR_MALFORMED;
        }
    }
    blst_p1_affine acc_pk_aff;
    blst_p1_to_affine(&acc_pk_aff, &acc_pk);

    blst_p2_affine sig_aff;
    if (blst_p2_uncompress(&sig_aff, sig) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    if (blst_core_verify_pk_in_g1(
            &acc_pk_aff, &sig_aff, true, msg, msg_len, ANTS_BLS_DST, ANTS_BLS_DST_LEN, NULL, 0) !=
        BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* ECVRF-EDWARDS25519-SHA512-ELL2                                           */
/* ------------------------------------------------------------------------ */

ants_error_t ants_vrf_prove(const uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE],
                            const uint8_t *alpha,
                            size_t alpha_len,
                            uint8_t out_proof[ANTS_VRF_PROOF_SIZE])
{
    (void)sk;
    (void)alpha;
    (void)alpha_len;
    (void)out_proof;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_vrf_verify(const uint8_t pk[ANTS_ED25519_PUBKEY_SIZE],
                             const uint8_t *alpha,
                             size_t alpha_len,
                             const uint8_t proof[ANTS_VRF_PROOF_SIZE],
                             uint8_t out_beta[ANTS_VRF_OUTPUT_SIZE])
{
    (void)pk;
    (void)alpha;
    (void)alpha_len;
    (void)proof;
    (void)out_beta;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
