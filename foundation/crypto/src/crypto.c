/*
 * crypto.c — Crypto primitives library.
 *
 * Status: API surface only. All primitives return
 * ANTS_ERROR_NOT_IMPLEMENTED. Implementation lands per-primitive in
 * subsequent PRs:
 *
 *   PR: vendor BLAKE3 (BLAKE3-team/BLAKE3) + implement ants_blake3_*.
 *   PR: vendor ed25519-donna + implement ants_ed25519_*.
 *   PR: vendor blst + implement ants_bls_*.
 *   PR: port RFC 9381 ECVRF-ELL2 + implement ants_vrf_*.
 */

#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ */
/* BLAKE3                                                                   */
/* ------------------------------------------------------------------------ */

ants_error_t ants_blake3_hash(const uint8_t *data, size_t len, uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    (void)data;
    (void)len;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_blake3_derive_key(const char *context,
                                    const uint8_t *key_material,
                                    size_t key_material_len,
                                    uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    (void)context;
    (void)key_material;
    (void)key_material_len;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_blake3_init(ants_blake3_ctx_t *ctx)
{
    (void)ctx;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_blake3_init_derive(ants_blake3_ctx_t *ctx, const char *context)
{
    (void)ctx;
    (void)context;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_blake3_update(ants_blake3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    (void)ctx;
    (void)data;
    (void)len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_blake3_final(ants_blake3_ctx_t *ctx, uint8_t out[ANTS_BLAKE3_HASH_SIZE])
{
    (void)ctx;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------------ */
/* Ed25519                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_ed25519_pubkey_from_priv(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                                           uint8_t out_pub[ANTS_ED25519_PUBKEY_SIZE])
{
    (void)priv;
    (void)out_pub;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_ed25519_sign(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                               const uint8_t *msg,
                               size_t len,
                               uint8_t out_sig[ANTS_ED25519_SIG_SIZE])
{
    (void)priv;
    (void)msg;
    (void)len;
    (void)out_sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_ed25519_verify(const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                                 const uint8_t *msg,
                                 size_t len,
                                 const uint8_t sig[ANTS_ED25519_SIG_SIZE])
{
    (void)pub;
    (void)msg;
    (void)len;
    (void)sig;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
