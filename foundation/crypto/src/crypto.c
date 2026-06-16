/*
 * crypto.c — Crypto primitives library.
 *
 * Status: BLAKE3 implemented via vendored deps/blake3 (v1.8.5).
 * Ed25519 implemented via vendored deps/ed25519 (libsodium 1.0.22
 * ref10 subset). BLS12-381 implemented via vendored deps/blst (0.3.15,
 * portable C). ECVRF-EDWARDS25519-SHA512-ELL2 implemented in-tree
 * against the libsodium ref10 fe25519/ge25519/sc25519 primitives per
 * RFC 9381.
 */

#include "ants_crypto.h"

#include "bearssl.h"
#include "blake3.h"
#include "blst.h"
#include "p256-m.h"

#include "crypto_hash_sha512.h"
#include "crypto_sign_ed25519.h"
#include "private/ed25519_ref10.h"
#include "utils.h" /* sodium_memzero */

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
/* SHA-256                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Thin wrapper over blst's portable SHA-256 (deps/blst, exposed via
 * blst_aux.h, already linked for BLS12-381). Kept here so callers never
 * include vendored headers directly; see the header for the
 * external-interop-only usage rule.
 */
ants_error_t ants_sha256(const uint8_t *data, size_t len, uint8_t out[ANTS_SHA256_HASH_SIZE])
{
    if ((data == NULL && len > 0) || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    blst_sha256(out, data, len);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* SHA-512                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Thin wrapper over the libsodium SHA-512 (deps/ed25519, already linked and
 * exercised by ECVRF below). Kept here so callers never include vendored
 * headers directly; see the header for the external-interop-only usage rule.
 * Verifies the vendor ECDSA signature chains in TEE attestation quotes
 * (RFC-0005), whose message digests are SHA-2.
 */
ants_error_t ants_sha512(const uint8_t *data, size_t len, uint8_t out[ANTS_SHA512_HASH_SIZE])
{
    if ((data == NULL && len > 0) || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, data, len);
    crypto_hash_sha512_final(&st, out);
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
    /* Zero the derived 64-byte sk; we don't keep it. sodium_memzero
     * carries a compiler barrier so this isn't dead-store-eliminated. */
    sodium_memzero(sk, sizeof sk);
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
    sodium_memzero(sk, sizeof sk);
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
/* The ciphersuite ID as a C99-conformant byte array. We can't write
 * `static const uint8_t X[] = "..."` because string literals have
 * type `char[]` and initialising an `unsigned char[]` from a string
 * literal is a C99 constraint violation (the GCC/Clang extension
 * accepts it; MSVC and strict-pedantic builds reject). */
static const char ANTS_BLS_DST_STR[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
#define ANTS_BLS_DST     ((const uint8_t *)ANTS_BLS_DST_STR)
#define ANTS_BLS_DST_LEN (sizeof ANTS_BLS_DST_STR - 1)

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
    sodium_memzero(&sk, sizeof sk);
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
    sodium_memzero(&sk, sizeof sk);
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
    /* blst_aggregate_in_g2 with `in == NULL` treats the accumulator as
     * the identity, decompresses zwire, performs an in-subgroup check
     * (which blst_p2_uncompress alone does NOT), and stores the
     * result. We use this for the first element so that subgroup
     * membership is checked uniformly across all n inputs. */
    blst_p2 acc;
    if (blst_aggregate_in_g2(&acc, NULL, sigs[0]) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
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
    /* See note in ants_bls_aggregate: use the NULL-accumulator pattern
     * so blst_aggregate_in_g1 subgroup-checks the first pubkey. */
    blst_p1 acc_pk;
    if (blst_aggregate_in_g1(&acc_pk, NULL, pubs[0]) != BLST_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
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
/*                                                                          */
/* Implementation follows RFC 9381 §5 with the ELL2 ciphersuite of §5.5.    */
/* The Elligator2-with-cofactor-clear primitive is libsodium's              */
/* ge25519_from_uniform, which is exactly the RFC 9381 §5.4.1.2 mapping     */
/* once the input's high bit has been masked to zero. Curve, field, and     */
/* scalar arithmetic come from libsodium's ref10. The construction is       */
/* split into helpers (hash_to_curve, nonce, challenge, proof_to_hash) so   */
/* prove and verify can share them.                                         */
/* ------------------------------------------------------------------------ */

#define VRF_SUITE_STRING 0x04
#define VRF_C_LEN        16 /* truncated challenge length in bytes */

/*
 * RFC 9381 §5.4.2.2 ECVRF_nonce_generation_RFC8032: derive a
 * 32-byte scalar `k` from the Ed25519 expanded secret's upper half
 * and the hash point H. We re-derive the SHA-512 expansion from the
 * 32-byte seed each time to keep the public API seed-only.
 */
static void vrf_nonce_generation(const uint8_t hashed_sk_upper[32],
                                 const uint8_t H_bytes[32],
                                 uint8_t out_k[32])
{
    crypto_hash_sha512_state st;
    uint8_t k_full[64];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, hashed_sk_upper, 32);
    crypto_hash_sha512_update(&st, H_bytes, 32);
    crypto_hash_sha512_final(&st, k_full);
    sc25519_reduce(k_full);
    memcpy(out_k, k_full, 32);
    sodium_memzero(k_full, sizeof k_full);
}

/*
 * RFC 9381 §5.4.3 ECVRF_challenge_generation: c = first cLen bytes
 * of SHA-512(suite_string || 0x02 || Y || H || Gamma || U || V || 0x00).
 * The output is the 16-byte truncated `c_string`; callers zero-pad to
 * 32 bytes when using it as a scalar.
 */
static void vrf_challenge_generation(const uint8_t Y[32],
                                     const uint8_t H[32],
                                     const uint8_t Gamma[32],
                                     const uint8_t U[32],
                                     const uint8_t V[32],
                                     uint8_t out_c[VRF_C_LEN])
{
    crypto_hash_sha512_state st;
    uint8_t full[64];
    const uint8_t suite = VRF_SUITE_STRING;
    const uint8_t two = 0x02;
    const uint8_t zero = 0x00;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, &suite, 1);
    crypto_hash_sha512_update(&st, &two, 1);
    crypto_hash_sha512_update(&st, Y, 32);
    crypto_hash_sha512_update(&st, H, 32);
    crypto_hash_sha512_update(&st, Gamma, 32);
    crypto_hash_sha512_update(&st, U, 32);
    crypto_hash_sha512_update(&st, V, 32);
    crypto_hash_sha512_update(&st, &zero, 1);
    crypto_hash_sha512_final(&st, full);
    memcpy(out_c, full, VRF_C_LEN);
}

/*
 * RFC 9380 §5.4.1 expand_message_xmd with SHA-512.
 *
 * Streaming variant: `msg` is supplied as two parts (msg1 || msg2) so
 * callers don't have to concatenate into a stack buffer of bounded
 * size. Used by RFC 9381 ELL2 with msg1 = PK_string (32 bytes) and
 * msg2 = alpha (arbitrary length); len_in_bytes = 48 (= L*m*count for
 * Edwards25519 with one field element).
 */
static void vrf_expand_message_xmd_sha512(const uint8_t *msg1,
                                          size_t msg1_len,
                                          const uint8_t *msg2,
                                          size_t msg2_len,
                                          const uint8_t *dst,
                                          size_t dst_len,
                                          uint8_t *out,
                                          size_t len_in_bytes)
{
    /* hLen = 64 for SHA-512. ell = ceil(len_in_bytes / hLen). For our
     * len_in_bytes = 48 ≤ 64, ell = 1, so only b_0 and b_1 are
     * produced and b_1 alone gives the output. */
    const size_t hLen = 64;
    /* RFC 9380 requires dst_len ≤ 255. Our DST is 41 bytes. */
    uint8_t dst_prime[256];
    if (dst_len > 255) {
        /* Out of spec; abort silently by zeroing output. */
        memset(out, 0, len_in_bytes);
        return;
    }
    memcpy(dst_prime, dst, dst_len);
    dst_prime[dst_len] = (uint8_t)dst_len;

    const size_t ell = (len_in_bytes + hLen - 1) / hLen;
    /* Z_pad = I2OSP(0, s_in_bytes). For SHA-512, s_in_bytes (input
     * block size) = 128. */
    static const uint8_t Z_pad[128] = {0};
    const uint8_t l_i_b_str[2] = {(uint8_t)(len_in_bytes >> 8), (uint8_t)(len_in_bytes & 0xFF)};
    const uint8_t I2OSP_0 = 0x00;

    /* b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || dst_prime). */
    crypto_hash_sha512_state st;
    uint8_t b_0[64];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, Z_pad, sizeof Z_pad);
    if (msg1_len > 0) {
        crypto_hash_sha512_update(&st, msg1, (unsigned long long)msg1_len);
    }
    if (msg2_len > 0) {
        crypto_hash_sha512_update(&st, msg2, (unsigned long long)msg2_len);
    }
    crypto_hash_sha512_update(&st, l_i_b_str, 2);
    crypto_hash_sha512_update(&st, &I2OSP_0, 1);
    crypto_hash_sha512_update(&st, dst_prime, dst_len + 1);
    crypto_hash_sha512_final(&st, b_0);

    /* b_1 = H(b_0 || I2OSP(1,1) || dst_prime). */
    uint8_t b_prev[64];
    uint8_t b_i[64];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, b_0, sizeof b_0);
    {
        const uint8_t i_str = 0x01;
        crypto_hash_sha512_update(&st, &i_str, 1);
    }
    crypto_hash_sha512_update(&st, dst_prime, dst_len + 1);
    crypto_hash_sha512_final(&st, b_i);
    memcpy(b_prev, b_i, sizeof b_i);

    size_t written = 0;
    size_t take = (len_in_bytes < hLen) ? len_in_bytes : hLen;
    memcpy(out, b_i, take);
    written = take;

    /* b_i = H(b_0 XOR b_{i-1} || I2OSP(i, 1) || dst_prime) for i = 2..ell. */
    for (size_t i = 2; i <= ell && written < len_in_bytes; i++) {
        uint8_t xor_buf[64];
        for (size_t j = 0; j < 64; j++) {
            xor_buf[j] = (uint8_t)(b_0[j] ^ b_prev[j]);
        }
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, xor_buf, sizeof xor_buf);
        {
            const uint8_t i_str = (uint8_t)i;
            crypto_hash_sha512_update(&st, &i_str, 1);
        }
        crypto_hash_sha512_update(&st, dst_prime, dst_len + 1);
        crypto_hash_sha512_final(&st, b_i);
        memcpy(b_prev, b_i, sizeof b_i);
        size_t remaining = len_in_bytes - written;
        take = remaining < hLen ? remaining : hLen;
        memcpy(out + written, b_i, take);
        written += take;
    }
}

/*
 * Reduce a 48-byte big-endian integer mod p = 2^255 - 19 and load
 * into an fe25519. Splits V = V_hi * 2^256 + V_lo (V_hi = top 16 BE
 * bytes, V_lo = remaining 32 BE bytes). Then V mod p = V_hi * 38 +
 * V_lo mod p since 2^256 ≡ 38 (mod p). V_lo's bit 255 (if set) is
 * handled by adding 19 once after the unreduced load, since
 * fe25519_frombytes silently masks bit 255.
 */
static void vrf_reduce_48_be_to_fe(const uint8_t v[48], fe25519 out)
{
    /* V_lo = v[16..47] interpreted as a 256-bit big-endian integer.
     * Byte-reverse to little-endian for fe25519_frombytes. */
    uint8_t lo_le[32];
    for (size_t i = 0; i < 32; i++) {
        lo_le[i] = v[16 + 31 - i];
    }
    uint8_t bit_255 = (uint8_t)(lo_le[31] >> 7);
    lo_le[31] &= 0x7F;
    fe25519 lo_fe;
    fe25519_frombytes(lo_fe, lo_le);
    if (bit_255) {
        /* Add 19 mod p to compensate for the silently-masked 2^255 bit. */
        fe25519 nineteen;
        uint8_t nineteen_bytes[32] = {0};
        nineteen_bytes[0] = 19;
        fe25519_frombytes(nineteen, nineteen_bytes);
        fe25519_add(lo_fe, lo_fe, nineteen);
    }

    /* V_hi = v[0..15] (128 bits, big-endian) → 32-byte LE with high
     * 16 bytes zero. */
    uint8_t hi_le[32] = {0};
    for (size_t i = 0; i < 16; i++) {
        hi_le[i] = v[15 - i];
    }
    fe25519 hi_fe;
    fe25519_frombytes(hi_fe, hi_le);
    /* V_hi * 38 fits within fe25519's pre-reduction range. */
    fe25519 hi_38;
    fe25519_mul32(hi_38, hi_fe, 38);

    fe25519 sum;
    fe25519_add(sum, lo_fe, hi_38);
    /* fe25519_reduce is static-inline inside the fe_25_5/fe_51
     * headers and not exposed; canonicalise by round-tripping through
     * the 32-byte serialisation, which internally reduces. The 32-byte
     * form is mod 2^255, and since p = 2^255 - 19, the worst case
     * after this is a value in [0, p+19); a single conditional sub of
     * p (via fe25519_tobytes' reduction) handles it. */
    uint8_t canonical[32];
    fe25519_tobytes(canonical, sum);
    fe25519_frombytes(out, canonical);
}

/*
 * RFC 9381 §§ 5.4.1.2 + 5.5 ECVRF_encode_to_curve_h2c_suite with
 * suite ID "edwards25519_XMD:SHA-512_ELL2_NU_" (RFC 9380 §G.2.2).
 *
 *   msg = PK_string || alpha
 *   DST = "ECVRF_" || suite_ID || suite_string (=0x04)
 *   uniform_bytes = expand_message_xmd_sha512(msg, DST, 48)
 *   u = OS2IP(uniform_bytes) mod p
 *   H_prelim = Elligator2(u)        (NU mode: single map call)
 *   H = clear_cofactor(H_prelim)
 *   return point_to_string(H)
 */
static void
vrf_hash_to_curve(const uint8_t Y[32], const uint8_t *alpha, size_t alpha_len, uint8_t out_H[32])
{
    /* DST for ECVRF-EDWARDS25519-SHA512-ELL2 per RFC 9381 §5.5.
     * Stored as `const char[]` (not `const uint8_t[]`) so the string
     * literal initialiser is C99-conformant; passed through a cast at
     * the use site. */
    static const char dst_str[] = "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04";
    const uint8_t *dst = (const uint8_t *)dst_str;
    const size_t dst_len = sizeof dst_str - 1; /* exclude the NUL terminator */

    /* expand_message_xmd takes msg as two parts (PK || alpha) so we
     * don't have to concatenate. The previous concat-into-stack-buffer
     * approach silently truncated alpha > 992 bytes, breaking VRF
     * injectivity (two distinct long alphas with the same prefix would
     * produce the same proof). */
    uint8_t uniform[48];
    vrf_expand_message_xmd_sha512(Y, 32, alpha, alpha_len, dst, dst_len, uniform, sizeof uniform);

    fe25519 u_fe;
    vrf_reduce_48_be_to_fe(uniform, u_fe);

    /* RFC 9380 NU mode: Elligator2 with sign convention derived
     * from the gx-is-square branch; see the patched variant in
     * deps/ed25519/src/ed25519_ref10_core.c. */
    ge25519_elligator2_rfc9380_nu(out_H, u_fe);
}

/*
 * RFC 9381 §5.2 proof_to_hash for ECVRF-EDWARDS25519-SHA512-ELL2:
 *   beta = SHA-512(suite || 0x03 || point_to_string(8 * Gamma) || 0x00)
 * where 8 is the Edwards25519 cofactor. Every Gamma we accept is
 * already cofactor-cleared (H is, so x*H is), but the spec applies
 * the multiplication unconditionally as a safety measure against
 * subgroup-membership oversights.
 */
static void vrf_proof_to_hash(const ge25519_p3 *Gamma_p3, uint8_t out_beta[64])
{
    ge25519_p3 eight_gamma;
    uint8_t eight[32] = {0};
    uint8_t eight_gamma_bytes[32];
    eight[0] = 8;
    ge25519_scalarmult(&eight_gamma, eight, Gamma_p3);
    ge25519_p3_tobytes(eight_gamma_bytes, &eight_gamma);

    crypto_hash_sha512_state st;
    const uint8_t suite = VRF_SUITE_STRING;
    const uint8_t three = 0x03;
    const uint8_t zero = 0x00;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, &suite, 1);
    crypto_hash_sha512_update(&st, &three, 1);
    crypto_hash_sha512_update(&st, eight_gamma_bytes, 32);
    crypto_hash_sha512_update(&st, &zero, 1);
    crypto_hash_sha512_final(&st, out_beta);
}

ants_error_t ants_vrf_prove(const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                            const uint8_t *alpha,
                            size_t alpha_len,
                            uint8_t out_proof[ANTS_VRF_PROOF_SIZE])
{
    if (priv == NULL || (alpha == NULL && alpha_len > 0) || out_proof == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* 1. Expand priv to (x, hashed_sk_upper) and derive Y = x*B. */
    uint8_t hashed_sk[64];
    uint8_t x_clamped[32];
    crypto_hash_sha512(hashed_sk, priv, ANTS_ED25519_PRIVKEY_SIZE);
    memcpy(x_clamped, hashed_sk, 32);
    x_clamped[0] &= 0xF8;
    x_clamped[31] &= 0x7F;
    x_clamped[31] |= 0x40;

    ge25519_p3 Y_p3;
    uint8_t Y_bytes[32];
    ge25519_scalarmult_base(&Y_p3, x_clamped);
    ge25519_p3_tobytes(Y_bytes, &Y_p3);

    /* 2. H = hash_to_curve_ell2(Y, alpha). */
    uint8_t H_bytes[32];
    vrf_hash_to_curve(Y_bytes, alpha, alpha_len, H_bytes);
    ge25519_p3 H_p3;
    if (ge25519_frombytes(&H_p3, H_bytes) != 0) {
        sodium_memzero(hashed_sk, sizeof hashed_sk);
        sodium_memzero(x_clamped, sizeof x_clamped);
        return ANTS_ERROR_MALFORMED;
    }

    /* 3. Gamma = x * H. */
    ge25519_p3 Gamma_p3;
    uint8_t Gamma_bytes[32];
    ge25519_scalarmult(&Gamma_p3, x_clamped, &H_p3);
    ge25519_p3_tobytes(Gamma_bytes, &Gamma_p3);

    /* 4. Nonce k. */
    uint8_t k[32];
    vrf_nonce_generation(hashed_sk + 32, H_bytes, k);

    /* 5. c = challenge_generation(Y, H, Gamma, kB, kH). */
    ge25519_p3 kB_p3;
    ge25519_p3 kH_p3;
    uint8_t kB_bytes[32];
    uint8_t kH_bytes[32];
    ge25519_scalarmult_base(&kB_p3, k);
    ge25519_scalarmult(&kH_p3, k, &H_p3);
    ge25519_p3_tobytes(kB_bytes, &kB_p3);
    ge25519_p3_tobytes(kH_bytes, &kH_p3);

    uint8_t c_string[VRF_C_LEN];
    vrf_challenge_generation(Y_bytes, H_bytes, Gamma_bytes, kB_bytes, kH_bytes, c_string);

    /* 6. s = c*x + k mod L (with c zero-padded to 32 bytes). */
    uint8_t c_padded[32];
    memcpy(c_padded, c_string, VRF_C_LEN);
    memset(c_padded + VRF_C_LEN, 0, 32 - VRF_C_LEN);
    uint8_t s_bytes[32];
    sc25519_muladd(s_bytes, c_padded, x_clamped, k);

    /* 7. pi = Gamma || c || s. */
    memcpy(out_proof, Gamma_bytes, 32);
    memcpy(out_proof + 32, c_string, VRF_C_LEN);
    memcpy(out_proof + 32 + VRF_C_LEN, s_bytes, 32);

    /* Zeroise every stack value that carries information about the
     * secret scalar x or the nonce k. Beyond x_clamped and k, the
     * Ed25519 expanded secret (hashed_sk) and the nonce-derived
     * point bytes (kB, kH) and the algebraically-secret-related
     * (c, s) need to be wiped too: kB = k*B leaks k; kH = k*H leaks
     * k relative to H; s = c*x + k mod L relates k and x. The proof
     * bytes (out_proof) are public and stay untouched. */
    sodium_memzero(hashed_sk, sizeof hashed_sk);
    sodium_memzero(x_clamped, sizeof x_clamped);
    sodium_memzero(k, sizeof k);
    sodium_memzero(&kB_p3, sizeof kB_p3);
    sodium_memzero(&kH_p3, sizeof kH_p3);
    sodium_memzero(kB_bytes, sizeof kB_bytes);
    sodium_memzero(kH_bytes, sizeof kH_bytes);
    sodium_memzero(c_padded, sizeof c_padded);
    sodium_memzero(s_bytes, sizeof s_bytes);
    return ANTS_OK;
}

ants_error_t ants_vrf_verify(const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                             const uint8_t *alpha,
                             size_t alpha_len,
                             const uint8_t proof[ANTS_VRF_PROOF_SIZE],
                             uint8_t out_beta[ANTS_VRF_OUTPUT_SIZE])
{
    if (pub == NULL || (alpha == NULL && alpha_len > 0) || proof == NULL || out_beta == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* 1. Validate Y. Reject non-canonical or low-order encodings. */
    if (!ge25519_is_canonical(pub) || ge25519_has_small_order(pub)) {
        return ANTS_ERROR_MALFORMED;
    }
    /* For step 4 we want -Y, so decompress with the _negate variant.
     * Variable-time is intentional: `pub` is a public input. */
    ge25519_p3 neg_Y;
    if (ge25519_frombytes_negate_vartime(&neg_Y, pub) != 0) {
        return ANTS_ERROR_MALFORMED;
    }

    /* 2. Decode pi. */
    const uint8_t *Gamma_bytes = proof;
    const uint8_t *c_string = proof + 32;
    const uint8_t *s_bytes = proof + 32 + VRF_C_LEN;

    /* Γ canonicity, on-curve, and subgroup-membership checks. RFC
     * 9381 §5.4.5 recommends a full-group check on Γ: without it, a
     * malicious prover could add a small-order point to a real Γ and
     * still get verify() to accept, breaking VRF determinism. The
     * proof_to_hash's 8·Γ cofactor multiplication is a fallback but
     * not a substitute for rejecting low-order points up front. */
    if (!ge25519_is_canonical(Gamma_bytes) || ge25519_has_small_order(Gamma_bytes)) {
        return ANTS_ERROR_MALFORMED;
    }
    ge25519_p3 Gamma_p3;
    if (ge25519_frombytes(&Gamma_p3, Gamma_bytes) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    /* s must be a canonical scalar in [0, L). The ref10 exposes
     * sc25519_is_canonical (a constant-time check); use that
     * rather than a hand-written byte compare. */
    if (sc25519_is_canonical(s_bytes) == 0) {
        return ANTS_ERROR_MALFORMED;
    }

    /* 3. H = hash_to_curve_ell2(Y, alpha). */
    uint8_t H_bytes[32];
    vrf_hash_to_curve(pub, alpha, alpha_len, H_bytes);
    ge25519_p3 H_p3;
    if (ge25519_frombytes(&H_p3, H_bytes) != 0) {
        return ANTS_ERROR_MALFORMED;
    }

    /* 4. U = s*B - c*Y. Using neg_Y: U = c*(-Y) + s*B. */
    uint8_t c_padded[32];
    memcpy(c_padded, c_string, VRF_C_LEN);
    memset(c_padded + VRF_C_LEN, 0, 32 - VRF_C_LEN);

    ge25519_p2 U_p2;
    uint8_t U_bytes[32];
    ge25519_double_scalarmult_vartime(&U_p2, c_padded, &neg_Y, s_bytes);
    ge25519_tobytes(U_bytes, &U_p2);

    /* 5. V = s*H - c*Gamma. */
    ge25519_p3 sH_p3;
    ge25519_p3 cGamma_p3;
    ge25519_cached cGamma_cached;
    ge25519_p1p1 V_p1p1;
    ge25519_p3 V_p3;
    uint8_t V_bytes[32];
    ge25519_scalarmult(&sH_p3, s_bytes, &H_p3);
    ge25519_scalarmult(&cGamma_p3, c_padded, &Gamma_p3);
    ge25519_p3_to_cached(&cGamma_cached, &cGamma_p3);
    ge25519_sub(&V_p1p1, &sH_p3, &cGamma_cached);
    ge25519_p1p1_to_p3(&V_p3, &V_p1p1);
    ge25519_p3_tobytes(V_bytes, &V_p3);

    /* 6. c' = challenge_generation(Y, H, Gamma, U, V). */
    uint8_t c_prime[VRF_C_LEN];
    vrf_challenge_generation(pub, H_bytes, Gamma_bytes, U_bytes, V_bytes, c_prime);

    /* 7. Constant-time compare c' against c_string. */
    {
        unsigned int diff = 0;
        for (size_t i = 0; i < VRF_C_LEN; i++) {
            diff |= (unsigned int)(c_prime[i] ^ c_string[i]);
        }
        if (diff != 0) {
            return ANTS_ERROR_MALFORMED;
        }
    }

    /* 8. beta = proof_to_hash(pi). */
    vrf_proof_to_hash(&Gamma_p3, out_beta);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* ECDSA P-256 — TEE attestation signature verification (verify-only)       */
/*                                                                          */
/* Implemented via vendored deps/p256-m (Apache-2.0, single-file,           */
/* constant-time). Verifies the vendor signature chains in TEE attestation  */
/* quotes (RFC-0005): Intel TDX is P-256; AMD SEV-SNP uses P-384, a later   */
/* sibling primitive.                                                       */
/* ------------------------------------------------------------------------ */

/*
 * p256-m declares `p256_generate_random` as an extern for the caller to
 * supply; it is referenced only on the sign/keygen code paths. ANTS uses
 * P-256 for attestation *verification* only — peer identity is Ed25519 and
 * we never produce a P-256 signature — so this is a deliberate fail-stub.
 * `p256_ecdsa_verify` never calls it; were a sign/keygen path ever reached
 * it fails closed (P256_RANDOM_FAILED) rather than emit a key from a
 * non-CSPRNG. Returning non-zero is the documented "RNG failed" contract.
 */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    (void)output;
    (void)output_size;
    return P256_RANDOM_FAILED;
}

ants_error_t ants_ecdsa_p256_verify(const uint8_t pub[ANTS_ECDSA_P256_PUBKEY_SIZE],
                                    const uint8_t *hash,
                                    size_t hash_len,
                                    const uint8_t sig[ANTS_ECDSA_P256_SIG_SIZE])
{
    if (pub == NULL || (hash == NULL && hash_len > 0) || sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* p256-m verifies (sig, pub, hash, hlen) and returns P256_SUCCESS,
     * P256_INVALID_SIGNATURE, or P256_INVALID_PUBKEY. The latter two both
     * mean the attestation signature did not verify — map to MALFORMED,
     * matching the ants_ed25519_verify convention. */
    if (p256_ecdsa_verify(sig, pub, hash, hash_len) != P256_SUCCESS) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* ECDSA P-384 — TEE attestation signature verification (verify-only)       */
/*                                                                          */
/* Implemented via the vendored BearSSL EC subset (deps/bearssl, MIT): the  */
/* generic-prime verifier br_ecdsa_i31_vrfy_raw over br_ec_prime_i31, raw   */
/* IEEE-P1363 (r||s) signatures. AMD SEV-SNP signs its attestation report   */
/* with ECDSA P-384 (RFC-0005); p256-m is P-256-only. Verify-only, no RNG.  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_ecdsa_p384_verify(const uint8_t pub[ANTS_ECDSA_P384_PUBKEY_SIZE],
                                    const uint8_t *hash,
                                    size_t hash_len,
                                    const uint8_t sig[ANTS_ECDSA_P384_SIG_SIZE])
{
    if (pub == NULL || (hash == NULL && hash_len > 0) || sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* BearSSL wants the public key as the uncompressed SEC1 point
     * 0x04 || X || Y (97 bytes for P-384). The wrapper takes the 96-byte
     * X || Y the verifier holds after stripping framing; prepend 0x04. */
    uint8_t q[1 + ANTS_ECDSA_P384_PUBKEY_SIZE];
    q[0] = 0x04;
    memcpy(q + 1, pub, ANTS_ECDSA_P384_PUBKEY_SIZE);

    br_ec_public_key pk;
    pk.curve = BR_EC_secp384r1;
    pk.q = q;
    pk.qlen = sizeof q;

    /* br_ecdsa_i31_vrfy_raw returns 1 on a valid signature, 0 otherwise
     * (bad signature or bad public key). Map 0 -> MALFORMED, matching the
     * ants_ecdsa_p256_verify / ants_ed25519_verify convention. */
    if (br_ecdsa_i31_vrfy_raw(
            &br_ec_prime_i31, hash, hash_len, &pk, sig, ANTS_ECDSA_P384_SIG_SIZE) != 1) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
