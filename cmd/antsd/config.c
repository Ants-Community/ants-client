/*
 * cmd/antsd/config.c — canonical-CBOR codec for the antsd node config.
 *
 * Schema (integer keys, ascending = canonical order):
 *   { 0: identity_priv (bstr/32),
 *     1: listen_multiaddr (tstr),
 *     2: seeds [ { 0: addr (tstr), 1: peer_id (bstr/32) }, ... ] }
 */
/* strnlen() is POSIX.1-2008; request it under -std=c99 on glibc. */
#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include "ants_cbor.h"

#include <string.h>

/* Copy a decoded text slice into a fixed NUL-terminated field. The slice
 * must leave room for the terminator. */
static ants_error_t copy_text(char *dst, size_t dst_cap, const char *src, size_t src_len)
{
    if (src_len >= dst_cap) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return ANTS_OK;
}

ants_error_t
antsd_config_encode(const antsd_config_t *cfg, uint8_t *buf, size_t cap, size_t *out_len)
{
    if (cfg == NULL || buf == NULL || out_len == NULL || cfg->seed_count > ANTSD_MAX_SEEDS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t listen_len = strnlen(cfg->listen_multiaddr, ANTSD_MULTIADDR_MAX);
    if (listen_len == ANTSD_MULTIADDR_MAX) {
        return ANTS_ERROR_INVALID_ARG; /* unterminated */
    }

    ants_cbor_enc_t enc;
    ants_error_t rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }

#define ENC(call)                                                                                  \
    do {                                                                                           \
        rc = (call);                                                                               \
        if (rc != ANTS_OK) {                                                                       \
            return rc;                                                                             \
        }                                                                                          \
    } while (0)

    ENC(ants_cbor_enc_map(&enc, 3));
    ENC(ants_cbor_enc_uint(&enc, 0));
    ENC(ants_cbor_enc_bytes(&enc, cfg->identity_priv, sizeof cfg->identity_priv));
    ENC(ants_cbor_enc_uint(&enc, 1));
    ENC(ants_cbor_enc_text(&enc, cfg->listen_multiaddr, listen_len));
    ENC(ants_cbor_enc_uint(&enc, 2));
    ENC(ants_cbor_enc_array(&enc, cfg->seed_count));
    for (size_t i = 0; i < cfg->seed_count; i++) {
        size_t alen = strnlen(cfg->seeds[i].addr, ANTSD_MULTIADDR_MAX);
        if (alen == ANTSD_MULTIADDR_MAX) {
            return ANTS_ERROR_INVALID_ARG;
        }
        ENC(ants_cbor_enc_map(&enc, 2));
        ENC(ants_cbor_enc_uint(&enc, 0));
        ENC(ants_cbor_enc_text(&enc, cfg->seeds[i].addr, alen));
        ENC(ants_cbor_enc_uint(&enc, 1));
        ENC(ants_cbor_enc_bytes(&enc, cfg->seeds[i].peer_id, sizeof cfg->seeds[i].peer_id));
    }
    ENC(ants_cbor_enc_finalise(&enc));
#undef ENC

    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* Expect the next item to be the unsigned integer `want` (a map key). */
static ants_error_t expect_key(ants_cbor_dec_t *dec, uint64_t want)
{
    uint64_t k;
    ants_error_t rc = ants_cbor_dec_uint(dec, &k);
    if (rc != ANTS_OK) {
        return rc;
    }
    return k == want ? ANTS_OK : ANTS_ERROR_MALFORMED;
}

/* Decode a byte string of exactly `n` bytes into `dst`. */
static ants_error_t decode_fixed_bytes(ants_cbor_dec_t *dec, uint8_t *dst, size_t n)
{
    const uint8_t *b;
    size_t blen;
    ants_error_t rc = ants_cbor_dec_bytes(dec, &b, &blen);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (blen != n) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(dst, b, n);
    return ANTS_OK;
}

ants_error_t antsd_config_decode(const uint8_t *buf, size_t len, antsd_config_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);

    ants_cbor_dec_t dec;
    ants_error_t rc = ants_cbor_dec_init(&dec, buf, len);
    if (rc != ANTS_OK) {
        return rc;
    }

#define DEC(call)                                                                                  \
    do {                                                                                           \
        rc = (call);                                                                               \
        if (rc != ANTS_OK) {                                                                       \
            return rc;                                                                             \
        }                                                                                          \
    } while (0)

    size_t n;
    DEC(ants_cbor_dec_map(&dec, &n));
    if (n != 3) {
        return ANTS_ERROR_MALFORMED;
    }

    DEC(expect_key(&dec, 0));
    DEC(decode_fixed_bytes(&dec, out->identity_priv, sizeof out->identity_priv));

    DEC(expect_key(&dec, 1));
    const char *txt;
    size_t txt_len;
    DEC(ants_cbor_dec_text(&dec, &txt, &txt_len));
    DEC(copy_text(out->listen_multiaddr, sizeof out->listen_multiaddr, txt, txt_len));

    DEC(expect_key(&dec, 2));
    size_t seed_n;
    DEC(ants_cbor_dec_array(&dec, &seed_n));
    if (seed_n > ANTSD_MAX_SEEDS) {
        return ANTS_ERROR_MALFORMED;
    }
    for (size_t i = 0; i < seed_n; i++) {
        size_t sn;
        DEC(ants_cbor_dec_map(&dec, &sn));
        if (sn != 2) {
            return ANTS_ERROR_MALFORMED;
        }
        DEC(expect_key(&dec, 0));
        const char *a;
        size_t alen;
        DEC(ants_cbor_dec_text(&dec, &a, &alen));
        DEC(copy_text(out->seeds[i].addr, sizeof out->seeds[i].addr, a, alen));
        DEC(expect_key(&dec, 1));
        DEC(decode_fixed_bytes(&dec, out->seeds[i].peer_id, sizeof out->seeds[i].peer_id));
    }
    out->seed_count = seed_n;
#undef DEC

    return ANTS_OK;
}
