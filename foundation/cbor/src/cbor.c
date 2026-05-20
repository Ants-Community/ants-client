/*
 * cbor.c — Deterministic CBOR codec.
 *
 * Status: API surface only. All encode/decode functions return
 * ANTS_ERROR_NOT_IMPLEMENTED. Implementation lands in subsequent PRs,
 * one major type at a time, with matching test vectors in
 * ants-test-vectors/vectors/cbor-canonical/.
 *
 * Spec reference: RFC-0008 §1.1.
 */

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ */
/* ants_strerror — defined here for now; will move to a shared common.c
 * when more components share it.                                           */
/* ------------------------------------------------------------------------ */

const char *ants_strerror(ants_error_t err)
{
    switch (err) {
    case ANTS_OK:
        return "ok";
    case ANTS_ERROR_INVALID_ARG:
        return "invalid argument";
    case ANTS_ERROR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case ANTS_ERROR_NOT_IMPLEMENTED:
        return "not implemented";
    case ANTS_ERROR_MALFORMED:
        return "malformed input";
    case ANTS_ERROR_NON_CANONICAL:
        return "non-canonical encoding";
    case ANTS_ERROR_UNSUPPORTED_TYPE:
        return "unsupported type";
    case ANTS_ERROR_OVERFLOW:
        return "overflow";
    case ANTS_ERROR__MAX:
    default:
        return "unknown";
    }
}

/* ------------------------------------------------------------------------ */
/* Encoder                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_cbor_enc_init(ants_cbor_enc_t *enc, uint8_t *buf, size_t cap)
{
    if (enc == NULL || buf == NULL || cap == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    enc->buf = buf;
    enc->cap = cap;
    enc->pos = 0;
    enc->depth = -1;
    for (int i = 0; i < ANTS_CBOR_MAX_DEPTH; i++) {
        enc->stack[i].kind = ANTS_CBOR_CTX_NONE;
        enc->stack[i].remaining = 0;
        enc->stack[i].last_key_begin = 0;
        enc->stack[i].last_key_end = 0;
    }
    return ANTS_OK;
}

ants_error_t ants_cbor_enc_uint(ants_cbor_enc_t *enc, uint64_t v)
{
    (void)enc;
    (void)v;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_int(ants_cbor_enc_t *enc, int64_t v)
{
    (void)enc;
    (void)v;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_bytes(ants_cbor_enc_t *enc, const uint8_t *b, size_t len)
{
    (void)enc;
    (void)b;
    (void)len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_text(ants_cbor_enc_t *enc, const char *s, size_t len)
{
    (void)enc;
    (void)s;
    (void)len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_array(ants_cbor_enc_t *enc, size_t n)
{
    (void)enc;
    (void)n;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_map(ants_cbor_enc_t *enc, size_t n)
{
    (void)enc;
    (void)n;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_bool(ants_cbor_enc_t *enc, bool v)
{
    (void)enc;
    (void)v;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_null(ants_cbor_enc_t *enc)
{
    (void)enc;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_enc_tag(ants_cbor_enc_t *enc, uint64_t tag)
{
    (void)enc;
    (void)tag;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

size_t ants_cbor_enc_size(const ants_cbor_enc_t *enc)
{
    if (enc == NULL) {
        return 0;
    }
    return enc->pos;
}

ants_error_t ants_cbor_enc_finalise(const ants_cbor_enc_t *enc)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (enc->depth != -1) {
        return ANTS_ERROR_MALFORMED;
    }
    if (enc->pos == 0) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Decoder                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_cbor_dec_init(ants_cbor_dec_t *dec, const uint8_t *buf, size_t len)
{
    if (dec == NULL || (buf == NULL && len > 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    dec->buf = buf;
    dec->len = len;
    dec->pos = 0;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_peek_type(const ants_cbor_dec_t *dec, ants_cbor_type_t *out)
{
    (void)dec;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_uint(ants_cbor_dec_t *dec, uint64_t *out)
{
    (void)dec;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_int(ants_cbor_dec_t *dec, int64_t *out)
{
    (void)dec;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_bytes(ants_cbor_dec_t *dec, const uint8_t **out_buf, size_t *out_len)
{
    (void)dec;
    (void)out_buf;
    (void)out_len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_text(ants_cbor_dec_t *dec, const char **out_buf, size_t *out_len)
{
    (void)dec;
    (void)out_buf;
    (void)out_len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_array(ants_cbor_dec_t *dec, size_t *out_n)
{
    (void)dec;
    (void)out_n;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_map(ants_cbor_dec_t *dec, size_t *out_n)
{
    (void)dec;
    (void)out_n;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_tag(ants_cbor_dec_t *dec, uint64_t *out_tag)
{
    (void)dec;
    (void)out_tag;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_bool(ants_cbor_dec_t *dec, bool *out)
{
    (void)dec;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_cbor_dec_null(ants_cbor_dec_t *dec)
{
    (void)dec;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

size_t ants_cbor_dec_pos(const ants_cbor_dec_t *dec)
{
    if (dec == NULL) {
        return 0;
    }
    return dec->pos;
}

bool ants_cbor_dec_eof(const ants_cbor_dec_t *dec)
{
    if (dec == NULL) {
        return true;
    }
    return dec->pos >= dec->len;
}

/* ------------------------------------------------------------------------ */
/* Validator                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_cbor_is_canonical(const uint8_t *buf, size_t len)
{
    (void)buf;
    (void)len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
