/*
 * cbor.c — Deterministic CBOR codec.
 *
 * Implements RFC 8949 §4.2.1 strict deterministic encoding, per
 * RFC-0008 §1.1.
 *
 * Status: major types 0 (unsigned int), 1 (negative int), 2 (byte
 * string), 3 (text string) implemented. Major types 4 (array), 5
 * (map), 6 (tag), and the bool/null subset of type 7 still stubbed
 * (return ANTS_ERROR_NOT_IMPLEMENTED). ants_cbor_is_canonical also
 * stubbed pending all major types.
 */

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
/* Internal helpers — shortest-form header encode / canonical-validated     */
/* header decode.                                                           */
/*                                                                          */
/* CBOR initial byte layout: bits 7..5 = major type (0..7), bits 4..0 =     */
/* additional info. For major types 0..6 the additional info encodes the   */
/* item's value or length in shortest-form per §4.2.1:                     */
/*   info < 24      : value is the info itself (1-byte total)              */
/*   info == 24     : next 1 byte holds the value (must be >= 24)          */
/*   info == 25     : next 2 bytes big-endian (must be >= 256)             */
/*   info == 26     : next 4 bytes big-endian (must be >= 65536)           */
/*   info == 27     : next 8 bytes big-endian (must be >= 2^32)            */
/*   info 28..30    : reserved — rejected as malformed                     */
/*   info == 31     : indefinite-length — rejected as non-canonical        */
/* ------------------------------------------------------------------------ */

static ants_error_t cbor_write_head(ants_cbor_enc_t *enc, uint8_t major, uint64_t value)
{
    if (enc == NULL || major > 7) {
        return ANTS_ERROR_INVALID_ARG;
    }
    uint8_t initial = (uint8_t)(major << 5);
    if (value < 24) {
        if (enc->pos + 1 > enc->cap) {
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        enc->buf[enc->pos++] = (uint8_t)(initial | (uint8_t)value);
        return ANTS_OK;
    }
    if (value < 256) {
        if (enc->pos + 2 > enc->cap) {
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        enc->buf[enc->pos++] = (uint8_t)(initial | 24);
        enc->buf[enc->pos++] = (uint8_t)value;
        return ANTS_OK;
    }
    if (value < 65536) {
        if (enc->pos + 3 > enc->cap) {
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        enc->buf[enc->pos++] = (uint8_t)(initial | 25);
        enc->buf[enc->pos++] = (uint8_t)(value >> 8);
        enc->buf[enc->pos++] = (uint8_t)(value & 0xff);
        return ANTS_OK;
    }
    if (value < (uint64_t)0x100000000ULL) {
        if (enc->pos + 5 > enc->cap) {
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        enc->buf[enc->pos++] = (uint8_t)(initial | 26);
        enc->buf[enc->pos++] = (uint8_t)(value >> 24);
        enc->buf[enc->pos++] = (uint8_t)((value >> 16) & 0xff);
        enc->buf[enc->pos++] = (uint8_t)((value >> 8) & 0xff);
        enc->buf[enc->pos++] = (uint8_t)(value & 0xff);
        return ANTS_OK;
    }
    if (enc->pos + 9 > enc->cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    enc->buf[enc->pos++] = (uint8_t)(initial | 27);
    for (int i = 7; i >= 0; i--) {
        enc->buf[enc->pos++] = (uint8_t)((value >> (i * 8)) & 0xff);
    }
    return ANTS_OK;
}

static ants_error_t cbor_read_head(ants_cbor_dec_t *dec, uint8_t *out_major, uint64_t *out_value)
{
    if (dec == NULL || out_major == NULL || out_value == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (dec->pos >= dec->len) {
        return ANTS_ERROR_MALFORMED;
    }

    uint8_t b = dec->buf[dec->pos++];
    uint8_t major = (uint8_t)(b >> 5);
    uint8_t info = (uint8_t)(b & 0x1f);
    *out_major = major;

    if (info < 24) {
        *out_value = info;
        return ANTS_OK;
    }
    if (info == 24) {
        if (dec->pos + 1 > dec->len) {
            return ANTS_ERROR_MALFORMED;
        }
        uint8_t v = dec->buf[dec->pos++];
        if (v < 24) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        *out_value = v;
        return ANTS_OK;
    }
    if (info == 25) {
        if (dec->pos + 2 > dec->len) {
            return ANTS_ERROR_MALFORMED;
        }
        uint64_t v = ((uint64_t)dec->buf[dec->pos] << 8) | (uint64_t)dec->buf[dec->pos + 1];
        dec->pos += 2;
        if (v < 256) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        *out_value = v;
        return ANTS_OK;
    }
    if (info == 26) {
        if (dec->pos + 4 > dec->len) {
            return ANTS_ERROR_MALFORMED;
        }
        uint64_t v = ((uint64_t)dec->buf[dec->pos] << 24) |
                     ((uint64_t)dec->buf[dec->pos + 1] << 16) |
                     ((uint64_t)dec->buf[dec->pos + 2] << 8) | (uint64_t)dec->buf[dec->pos + 3];
        dec->pos += 4;
        if (v < 65536) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        *out_value = v;
        return ANTS_OK;
    }
    if (info == 27) {
        if (dec->pos + 8 > dec->len) {
            return ANTS_ERROR_MALFORMED;
        }
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (uint64_t)dec->buf[dec->pos++];
        }
        if (v < (uint64_t)0x100000000ULL) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        *out_value = v;
        return ANTS_OK;
    }
    /* info 28..30 reserved; info == 31 indefinite-length. Both rejected
     * under §4.2.1. The protocol does not distinguish; treat as
     * non-canonical so the caller sees the deterministic-encoding error
     * rather than a generic malformed. */
    return ANTS_ERROR_NON_CANONICAL;
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
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return cbor_write_head(enc, 0, v);
}

ants_error_t ants_cbor_enc_int(ants_cbor_enc_t *enc, int64_t v)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (v >= 0) {
        return cbor_write_head(enc, 0, (uint64_t)v);
    }
    /* CBOR major type 1 encodes -1-n. For v = INT64_MIN, -(v+1) is
     * (uint64_t)INT64_MAX which fits in u64. */
    uint64_t encoded = (uint64_t)(-(v + 1));
    return cbor_write_head(enc, 1, encoded);
}

ants_error_t ants_cbor_enc_bytes(ants_cbor_enc_t *enc, const uint8_t *b, size_t len)
{
    if (enc == NULL || (len > 0 && b == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_error_t err = cbor_write_head(enc, 2, (uint64_t)len);
    if (err != ANTS_OK) {
        return err;
    }
    if (enc->pos + len > enc->cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        memcpy(enc->buf + enc->pos, b, len);
    }
    enc->pos += len;
    return ANTS_OK;
}

ants_error_t ants_cbor_enc_text(ants_cbor_enc_t *enc, const char *s, size_t len)
{
    if (enc == NULL || (len > 0 && s == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_error_t err = cbor_write_head(enc, 3, (uint64_t)len);
    if (err != ANTS_OK) {
        return err;
    }
    if (enc->pos + len > enc->cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        memcpy(enc->buf + enc->pos, s, len);
    }
    enc->pos += len;
    return ANTS_OK;
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
    if (dec == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (dec->pos >= dec->len) {
        return ANTS_ERROR_MALFORMED;
    }

    uint8_t b = dec->buf[dec->pos];
    uint8_t major = (uint8_t)(b >> 5);
    uint8_t info = (uint8_t)(b & 0x1f);

    switch (major) {
    case 0:
        *out = ANTS_CBOR_TYPE_UINT;
        return ANTS_OK;
    case 1:
        *out = ANTS_CBOR_TYPE_NEGINT;
        return ANTS_OK;
    case 2:
        *out = ANTS_CBOR_TYPE_BYTES;
        return ANTS_OK;
    case 3:
        *out = ANTS_CBOR_TYPE_TEXT;
        return ANTS_OK;
    case 4:
        *out = ANTS_CBOR_TYPE_ARRAY;
        return ANTS_OK;
    case 5:
        *out = ANTS_CBOR_TYPE_MAP;
        return ANTS_OK;
    case 6:
        *out = ANTS_CBOR_TYPE_TAG;
        return ANTS_OK;
    case 7:
        if (info == 20 || info == 21) {
            *out = ANTS_CBOR_TYPE_BOOL;
            return ANTS_OK;
        }
        if (info == 22) {
            *out = ANTS_CBOR_TYPE_NULL;
            return ANTS_OK;
        }
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    default:
        return ANTS_ERROR_MALFORMED;
    }
}

ants_error_t ants_cbor_dec_uint(ants_cbor_dec_t *dec, uint64_t *out)
{
    if (dec == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    uint8_t major;
    uint64_t value;
    ants_error_t err = cbor_read_head(dec, &major, &value);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    if (major != 0) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    *out = value;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_int(ants_cbor_dec_t *dec, int64_t *out)
{
    if (dec == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    uint8_t major;
    uint64_t value;
    ants_error_t err = cbor_read_head(dec, &major, &value);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    if (major == 0) {
        if (value > (uint64_t)INT64_MAX) {
            dec->pos = saved;
            return ANTS_ERROR_OVERFLOW;
        }
        *out = (int64_t)value;
        return ANTS_OK;
    }
    if (major == 1) {
        /* CBOR major type 1 encodes -1-v. The smallest representable
         * int64_t is -2^63 == -1 - (2^63 - 1) == -1 - INT64_MAX. So
         * value must satisfy value <= INT64_MAX. */
        if (value > (uint64_t)INT64_MAX) {
            dec->pos = saved;
            return ANTS_ERROR_OVERFLOW;
        }
        *out = -1 - (int64_t)value;
        return ANTS_OK;
    }
    dec->pos = saved;
    return ANTS_ERROR_UNSUPPORTED_TYPE;
}

ants_error_t ants_cbor_dec_bytes(ants_cbor_dec_t *dec, const uint8_t **out_buf, size_t *out_len)
{
    if (dec == NULL || out_buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    uint8_t major;
    uint64_t value;
    ants_error_t err = cbor_read_head(dec, &major, &value);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    if (major != 2) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (value > (uint64_t)SIZE_MAX) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }
    size_t len = (size_t)value;
    if (dec->pos + len > dec->len) {
        dec->pos = saved;
        return ANTS_ERROR_MALFORMED;
    }
    *out_buf = (len > 0) ? (dec->buf + dec->pos) : NULL;
    *out_len = len;
    dec->pos += len;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_text(ants_cbor_dec_t *dec, const char **out_buf, size_t *out_len)
{
    if (dec == NULL || out_buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    uint8_t major;
    uint64_t value;
    ants_error_t err = cbor_read_head(dec, &major, &value);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    if (major != 3) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (value > (uint64_t)SIZE_MAX) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }
    size_t len = (size_t)value;
    if (dec->pos + len > dec->len) {
        dec->pos = saved;
        return ANTS_ERROR_MALFORMED;
    }
    *out_buf = (len > 0) ? (const char *)(dec->buf + dec->pos) : NULL;
    *out_len = len;
    dec->pos += len;
    return ANTS_OK;
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
