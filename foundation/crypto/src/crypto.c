/*
 * crypto.c — Crypto primitives library.
 *
 * Status: BLAKE3 implemented via vendored deps/blake3 (v1.8.5).
 * Ed25519 implemented via vendored deps/ed25519 (libsodium 1.0.22
 * ref10 subset). BLS12-381 and ECVRF-ELL2 still stubbed.
 */

#include "ants_crypto.h"

#include "blake3.h"
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

ants_error_t ants_bls_pubkey_from_priv(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                                       uint8_t out_pub[ANTS_BLS_PUBKEY_SIZE])
{
    (void)priv;
    (void)out_pub;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bls_sign(const uint8_t priv[ANTS_BLS_PRIVKEY_SIZE],
                           const uint8_t *msg,
                           size_t len,
                           uint8_t out_sig[ANTS_BLS_SIG_SIZE])
{
    (void)priv;
    (void)msg;
    (void)len;
    (void)out_sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bls_verify(const uint8_t pub[ANTS_BLS_PUBKEY_SIZE],
                             const uint8_t *msg,
                             size_t len,
                             const uint8_t sig[ANTS_BLS_SIG_SIZE])
{
    (void)pub;
    (void)msg;
    (void)len;
    (void)sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bls_aggregate(const uint8_t (*sigs)[ANTS_BLS_SIG_SIZE],
                                size_t n,
                                uint8_t out_sig[ANTS_BLS_SIG_SIZE])
{
    (void)sigs;
    (void)n;
    (void)out_sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bls_verify_aggregate(const uint8_t (*pubs)[ANTS_BLS_PUBKEY_SIZE],
                                       size_t n,
                                       const uint8_t *msg,
                                       size_t msg_len,
                                       const uint8_t sig[ANTS_BLS_SIG_SIZE])
{
    (void)pubs;
    (void)n;
    (void)msg;
    (void)msg_len;
    (void)sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
