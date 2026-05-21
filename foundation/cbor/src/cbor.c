/*
 * cbor.c — Deterministic CBOR codec.
 *
 * Implements RFC 8949 §4.2.1 strict deterministic encoding, per
 * RFC-0008 §1.1.
 *
 * Status: **feature-complete**. All major types 0-6 and the bool/null
 * subset of type 7 implemented. ants_cbor_is_canonical implemented as
 * a walk-every-item function that requires exactly len bytes consumed.
 *
 * Canonical-encoding discipline lives in cbor_read_head (shortest-form
 * + indefinite + reserved rejection) and in the enc_track_item /
 * dec_track_item helpers (canonical key order in maps).
 */

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* ants_strerror                                                            */
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
    case ANTS_ERROR_PEER_UNREACHABLE:
        return "peer unreachable";
    case ANTS_ERROR_HANDSHAKE_FAILED:
        return "handshake failed";
    case ANTS_ERROR_PEER_MISMATCH:
        return "peer pubkey mismatch";
    case ANTS_ERROR_STREAM_RESET:
        return "stream reset";
    default:
        return "unknown";
    }
}

/* ------------------------------------------------------------------------ */
/* Internal helpers — shortest-form header encode / canonical-validated     */
/* header decode.                                                           */
/*                                                                          */
/* CBOR initial byte layout: bits 7..5 = major type (0..7), bits 4..0 =     */
/* additional info. For major types 0..6 the additional info encodes the    */
/* item's value or length in shortest-form per §4.2.1:                      */
/*   info < 24      : value is the info itself (1-byte total)               */
/*   info == 24     : next 1 byte holds the value (must be >= 24)           */
/*   info == 25     : next 2 bytes big-endian (must be >= 256)              */
/*   info == 26     : next 4 bytes big-endian (must be >= 65536)            */
/*   info == 27     : next 8 bytes big-endian (must be >= 2^32)             */
/*   info 28..30    : reserved — rejected as non-canonical                  */
/*   info == 31     : indefinite-length — rejected as non-canonical         */
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
    /* info 28..30 reserved; info == 31 indefinite-length. Both rejected. */
    return ANTS_ERROR_NON_CANONICAL;
}

/* ------------------------------------------------------------------------ */
/* Container tracking — keeps depth/stack consistent as items are added or  */
/* consumed.                                                                */
/*                                                                          */
/* compare_keys: bytewise lexicographic ordering with length tiebreak per   */
/* RFC 8949 §4.2.1. Returns negative if a < b, positive if a > b, 0 if      */
/* equal. Required for map canonical-key-order enforcement.                 */
/* ------------------------------------------------------------------------ */

static int compare_keys(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    size_t min_len = a_len < b_len ? a_len : b_len;
    if (min_len > 0) {
        int c = memcmp(a, b, min_len);
        if (c != 0) {
            return c;
        }
    }
    if (a_len < b_len) {
        return -1;
    }
    if (a_len > b_len) {
        return 1;
    }
    return 0;
}

/*
 * enc_track_item: called after a successful write to register the just-
 * written item (item_begin..enc->pos) in the current open container. Walks
 * up the stack, closing containers as they fill; a closed container is
 * recursively registered as a single item in its parent.
 *
 * On any failure the encoder's depth/stack are restored to their state at
 * entry. The caller is responsible for restoring enc->pos.
 */
static ants_error_t enc_track_item(ants_cbor_enc_t *enc, size_t item_begin)
{
    int saved_depth = enc->depth;
    ants_cbor_ctx_t saved_stack[ANTS_CBOR_MAX_DEPTH];
    memcpy(saved_stack, enc->stack, sizeof saved_stack);

#define ENC_TRACK_FAIL(code)                                                                       \
    do {                                                                                           \
        enc->depth = saved_depth;                                                                  \
        memcpy(enc->stack, saved_stack, sizeof saved_stack);                                       \
        return (code);                                                                             \
    } while (0)

    while (enc->depth >= 0) {
        ants_cbor_ctx_t *ctx = &enc->stack[enc->depth];
        bool closed = false;

        switch (ctx->kind) {
        case ANTS_CBOR_CTX_ARRAY:
            if (ctx->remaining == 0) {
                ENC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            }
            break;
        case ANTS_CBOR_CTX_MAP_KEY:
            if (ctx->remaining == 0) {
                ENC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            if (ctx->last_key_end > 0) {
                int cmp = compare_keys(enc->buf + ctx->last_key_begin,
                                       ctx->last_key_end - ctx->last_key_begin,
                                       enc->buf + item_begin,
                                       enc->pos - item_begin);
                if (cmp >= 0) {
                    ENC_TRACK_FAIL(ANTS_ERROR_NON_CANONICAL);
                }
            }
            ctx->last_key_begin = item_begin;
            ctx->last_key_end = enc->pos;
            ctx->kind = ANTS_CBOR_CTX_MAP_VALUE;
            return ANTS_OK;
        case ANTS_CBOR_CTX_MAP_VALUE:
            if (ctx->remaining == 0) {
                ENC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            } else {
                ctx->kind = ANTS_CBOR_CTX_MAP_KEY;
                return ANTS_OK;
            }
            break;
        case ANTS_CBOR_CTX_TAG:
            /* TAG always has remaining=1 when opened; tagged item closes it. */
            if (ctx->remaining == 0) {
                ENC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            }
            break;
        case ANTS_CBOR_CTX_NONE:
        default:
            ENC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
        }

        if (closed) {
            size_t closed_begin = ctx->container_begin;
            enc->depth--;
            item_begin = closed_begin;
            /* loop: register the closed container as a single item in parent. */
        } else {
            return ANTS_OK;
        }
    }

#undef ENC_TRACK_FAIL
    return ANTS_OK;
}

/*
 * dec_track_item: symmetric to enc_track_item but operates on the
 * decoder's view of the buffer. Called by decode_* functions immediately
 * after consuming an item.
 */
static ants_error_t dec_track_item(ants_cbor_dec_t *dec, size_t item_begin)
{
    int saved_depth = dec->depth;
    ants_cbor_ctx_t saved_stack[ANTS_CBOR_MAX_DEPTH];
    memcpy(saved_stack, dec->stack, sizeof saved_stack);

#define DEC_TRACK_FAIL(code)                                                                       \
    do {                                                                                           \
        dec->depth = saved_depth;                                                                  \
        memcpy(dec->stack, saved_stack, sizeof saved_stack);                                       \
        return (code);                                                                             \
    } while (0)

    while (dec->depth >= 0) {
        ants_cbor_ctx_t *ctx = &dec->stack[dec->depth];
        bool closed = false;

        switch (ctx->kind) {
        case ANTS_CBOR_CTX_ARRAY:
            if (ctx->remaining == 0) {
                DEC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            }
            break;
        case ANTS_CBOR_CTX_MAP_KEY:
            if (ctx->remaining == 0) {
                DEC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            if (ctx->last_key_end > 0) {
                int cmp = compare_keys(dec->buf + ctx->last_key_begin,
                                       ctx->last_key_end - ctx->last_key_begin,
                                       dec->buf + item_begin,
                                       dec->pos - item_begin);
                if (cmp >= 0) {
                    DEC_TRACK_FAIL(ANTS_ERROR_NON_CANONICAL);
                }
            }
            ctx->last_key_begin = item_begin;
            ctx->last_key_end = dec->pos;
            ctx->kind = ANTS_CBOR_CTX_MAP_VALUE;
            return ANTS_OK;
        case ANTS_CBOR_CTX_MAP_VALUE:
            if (ctx->remaining == 0) {
                DEC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            } else {
                ctx->kind = ANTS_CBOR_CTX_MAP_KEY;
                return ANTS_OK;
            }
            break;
        case ANTS_CBOR_CTX_TAG:
            if (ctx->remaining == 0) {
                DEC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
            }
            ctx->remaining--;
            if (ctx->remaining == 0) {
                closed = true;
            }
            break;
        case ANTS_CBOR_CTX_NONE:
        default:
            DEC_TRACK_FAIL(ANTS_ERROR_MALFORMED);
        }

        if (closed) {
            size_t closed_begin = ctx->container_begin;
            dec->depth--;
            item_begin = closed_begin;
        } else {
            return ANTS_OK;
        }
    }

#undef DEC_TRACK_FAIL
    return ANTS_OK;
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
        enc->stack[i].container_begin = 0;
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
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 0, v);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

ants_error_t ants_cbor_enc_int(ants_cbor_enc_t *enc, int64_t v)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    ants_error_t err;
    if (v >= 0) {
        err = cbor_write_head(enc, 0, (uint64_t)v);
    } else {
        /* CBOR major type 1 encodes -1-n where v is negative, so
         * n = -1 - v. For v = INT64_MIN, `v + 1` is signed overflow
         * (UB). Compute -1 - v in unsigned arithmetic to avoid the
         * trap: ~(uint64_t)v is exactly -1 - v for negative v
         * (two's-complement bit-pattern identity, defined for any
         * uint64_t input). */
        err = cbor_write_head(enc, 1, ~(uint64_t)v);
    }
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

ants_error_t ants_cbor_enc_bytes(ants_cbor_enc_t *enc, const uint8_t *b, size_t len)
{
    if (enc == NULL || (len > 0 && b == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 2, (uint64_t)len);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    if (len > enc->cap - enc->pos) {
        enc->pos = item_begin;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        memcpy(enc->buf + enc->pos, b, len);
    }
    enc->pos += len;
    err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

ants_error_t ants_cbor_enc_text(ants_cbor_enc_t *enc, const char *s, size_t len)
{
    if (enc == NULL || (len > 0 && s == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 3, (uint64_t)len);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    if (len > enc->cap - enc->pos) {
        enc->pos = item_begin;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (len > 0) {
        memcpy(enc->buf + enc->pos, s, len);
    }
    enc->pos += len;
    err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

ants_error_t ants_cbor_enc_array(ants_cbor_enc_t *enc, size_t n)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 4, (uint64_t)n);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    if (n == 0) {
        /* Empty array — close immediately as a single item in parent. */
        err = enc_track_item(enc, item_begin);
        if (err != ANTS_OK) {
            enc->pos = item_begin;
        }
        return err;
    }
    if (enc->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        enc->pos = item_begin;
        return ANTS_ERROR_OVERFLOW;
    }
    enc->depth++;
    enc->stack[enc->depth].kind = ANTS_CBOR_CTX_ARRAY;
    enc->stack[enc->depth].remaining = n;
    enc->stack[enc->depth].container_begin = item_begin;
    enc->stack[enc->depth].last_key_begin = 0;
    enc->stack[enc->depth].last_key_end = 0;
    return ANTS_OK;
}

ants_error_t ants_cbor_enc_map(ants_cbor_enc_t *enc, size_t n)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 5, (uint64_t)n);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    if (n == 0) {
        err = enc_track_item(enc, item_begin);
        if (err != ANTS_OK) {
            enc->pos = item_begin;
        }
        return err;
    }
    if (enc->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        enc->pos = item_begin;
        return ANTS_ERROR_OVERFLOW;
    }
    enc->depth++;
    enc->stack[enc->depth].kind = ANTS_CBOR_CTX_MAP_KEY;
    enc->stack[enc->depth].remaining = n;
    enc->stack[enc->depth].container_begin = item_begin;
    enc->stack[enc->depth].last_key_begin = 0;
    enc->stack[enc->depth].last_key_end = 0;
    return ANTS_OK;
}

/*
 * Major type 7 simple values:
 *   false: 0xf4 (info 20)
 *   true:  0xf5 (info 21)
 *   null:  0xf6 (info 22)
 *
 * RFC 8949 §4.2.1 requires single-byte form (info < 24) for the simple
 * values 0..23. The encoder always emits the 1-byte form; the decoder
 * rejects the 2-byte form (info==24) for values <24 as non-canonical
 * (already handled by cbor_read_head's shortest-form check, which we
 * deliberately reuse via a thin wrapper for symmetry).
 */
ants_error_t ants_cbor_enc_bool(ants_cbor_enc_t *enc, bool v)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    if (enc->pos + 1 > enc->cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    enc->buf[enc->pos++] = v ? (uint8_t)0xf5 : (uint8_t)0xf4;
    ants_error_t err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

ants_error_t ants_cbor_enc_null(ants_cbor_enc_t *enc)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t item_begin = enc->pos;
    if (enc->pos + 1 > enc->cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    enc->buf[enc->pos++] = (uint8_t)0xf6;
    ants_error_t err = enc_track_item(enc, item_begin);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
    }
    return err;
}

/*
 * Tag encoder. Per RFC-0008 §1.1, only reserved tags 0, 32, 42 are
 * accepted. A TAG context is pushed expecting exactly one tagged item
 * to follow; the tracker closes the TAG and registers the combined
 * (tag header + tagged item) byte range as a single item in the parent.
 */
ants_error_t ants_cbor_enc_tag(ants_cbor_enc_t *enc, uint64_t tag)
{
    if (enc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (tag != 0 && tag != 32 && tag != 42) {
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (enc->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        return ANTS_ERROR_OVERFLOW;
    }
    size_t item_begin = enc->pos;
    ants_error_t err = cbor_write_head(enc, 6, tag);
    if (err != ANTS_OK) {
        enc->pos = item_begin;
        return err;
    }
    enc->depth++;
    enc->stack[enc->depth].kind = ANTS_CBOR_CTX_TAG;
    enc->stack[enc->depth].remaining = 1;
    enc->stack[enc->depth].container_begin = item_begin;
    enc->stack[enc->depth].last_key_begin = 0;
    enc->stack[enc->depth].last_key_end = 0;
    return ANTS_OK;
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
    dec->depth = -1;
    for (int i = 0; i < ANTS_CBOR_MAX_DEPTH; i++) {
        dec->stack[i].kind = ANTS_CBOR_CTX_NONE;
        dec->stack[i].remaining = 0;
        dec->stack[i].container_begin = 0;
        dec->stack[i].last_key_begin = 0;
        dec->stack[i].last_key_end = 0;
    }
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
    err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
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
    int64_t result;
    if (major == 0) {
        if (value > (uint64_t)INT64_MAX) {
            dec->pos = saved;
            return ANTS_ERROR_OVERFLOW;
        }
        result = (int64_t)value;
    } else if (major == 1) {
        /* CBOR major type 1 encodes -1-v. Smallest representable int64_t
         * is INT64_MIN = -2^63 = -1 - (2^63 - 1). So value <= INT64_MAX. */
        if (value > (uint64_t)INT64_MAX) {
            dec->pos = saved;
            return ANTS_ERROR_OVERFLOW;
        }
        result = -1 - (int64_t)value;
    } else {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    *out = result;
    return ANTS_OK;
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
    if (len > dec->len - dec->pos) {
        dec->pos = saved;
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *bp = (len > 0) ? (dec->buf + dec->pos) : NULL;
    dec->pos += len;
    err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    *out_buf = bp;
    *out_len = len;
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
    if (len > dec->len - dec->pos) {
        dec->pos = saved;
        return ANTS_ERROR_MALFORMED;
    }
    const char *sp = (len > 0) ? (const char *)(dec->buf + dec->pos) : NULL;
    dec->pos += len;
    err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    *out_buf = sp;
    *out_len = len;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_array(ants_cbor_dec_t *dec, size_t *out_n)
{
    if (dec == NULL || out_n == NULL) {
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
    if (major != 4) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (value > (uint64_t)SIZE_MAX) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }
    size_t n = (size_t)value;

    if (n == 0) {
        /* Empty array — register as a complete item in parent. */
        err = dec_track_item(dec, saved);
        if (err != ANTS_OK) {
            dec->pos = saved;
            return err;
        }
        *out_n = 0;
        return ANTS_OK;
    }

    if (dec->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }

    /* Snapshot for transactional push. */
    int saved_depth = dec->depth;
    ants_cbor_ctx_t saved_stack[ANTS_CBOR_MAX_DEPTH];
    memcpy(saved_stack, dec->stack, sizeof saved_stack);

    dec->depth++;
    dec->stack[dec->depth].kind = ANTS_CBOR_CTX_ARRAY;
    dec->stack[dec->depth].remaining = n;
    dec->stack[dec->depth].container_begin = saved;
    dec->stack[dec->depth].last_key_begin = 0;
    dec->stack[dec->depth].last_key_end = 0;

    *out_n = n;
    return ANTS_OK;

    /* (No explicit fail-restore path needed here: we've already pushed the
     * new context successfully and dec->pos points past the array header.
     * The caller proceeds to decode n items.) */
    (void)saved_depth;
    (void)saved_stack;
}

ants_error_t ants_cbor_dec_map(ants_cbor_dec_t *dec, size_t *out_n)
{
    if (dec == NULL || out_n == NULL) {
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
    if (major != 5) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (value > (uint64_t)SIZE_MAX) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }
    size_t n = (size_t)value;

    if (n == 0) {
        err = dec_track_item(dec, saved);
        if (err != ANTS_OK) {
            dec->pos = saved;
            return err;
        }
        *out_n = 0;
        return ANTS_OK;
    }

    if (dec->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }

    dec->depth++;
    dec->stack[dec->depth].kind = ANTS_CBOR_CTX_MAP_KEY;
    dec->stack[dec->depth].remaining = n;
    dec->stack[dec->depth].container_begin = saved;
    dec->stack[dec->depth].last_key_begin = 0;
    dec->stack[dec->depth].last_key_end = 0;

    *out_n = n;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_tag(ants_cbor_dec_t *dec, uint64_t *out_tag)
{
    if (dec == NULL || out_tag == NULL) {
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
    if (major != 6) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    /* Per RFC-0008 §1.1, only reserved tags 0, 32, 42 are accepted. */
    if (value != 0 && value != 32 && value != 42) {
        dec->pos = saved;
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (dec->depth + 1 >= ANTS_CBOR_MAX_DEPTH) {
        dec->pos = saved;
        return ANTS_ERROR_OVERFLOW;
    }
    dec->depth++;
    dec->stack[dec->depth].kind = ANTS_CBOR_CTX_TAG;
    dec->stack[dec->depth].remaining = 1;
    dec->stack[dec->depth].container_begin = saved;
    dec->stack[dec->depth].last_key_begin = 0;
    dec->stack[dec->depth].last_key_end = 0;
    *out_tag = value;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_bool(ants_cbor_dec_t *dec, bool *out)
{
    if (dec == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    if (dec->pos + 1 > dec->len) {
        return ANTS_ERROR_MALFORMED;
    }
    uint8_t b = dec->buf[dec->pos];
    if (b != (uint8_t)0xf4 && b != (uint8_t)0xf5) {
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    dec->pos++;
    bool v = (b == (uint8_t)0xf5);
    ants_error_t err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    *out = v;
    return ANTS_OK;
}

ants_error_t ants_cbor_dec_null(ants_cbor_dec_t *dec)
{
    if (dec == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t saved = dec->pos;
    if (dec->pos + 1 > dec->len) {
        return ANTS_ERROR_MALFORMED;
    }
    if (dec->buf[dec->pos] != (uint8_t)0xf6) {
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    dec->pos++;
    ants_error_t err = dec_track_item(dec, saved);
    if (err != ANTS_OK) {
        dec->pos = saved;
        return err;
    }
    return ANTS_OK;
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
/*                                                                          */
/* The top-level validator walks every item in the input, exercising each   */
/* dec_* function (which already enforces shortest-form, canonical-key      */
/* order, reserved-info rejection, etc.). After the walk it requires:       */
/*   - exactly len bytes consumed (no trailing data);                       */
/*   - depth back to -1 (every container closed).                           */
/*                                                                          */
/* Maximum recursion depth is bounded by ANTS_CBOR_MAX_DEPTH because the    */
/* underlying decoder rejects deeper nesting via dec_track_item.            */
/* ------------------------------------------------------------------------ */

static ants_error_t walk_one_item(ants_cbor_dec_t *dec)
{
    if (ants_cbor_dec_eof(dec)) {
        return ANTS_ERROR_MALFORMED;
    }

    ants_cbor_type_t t;
    ants_error_t err = ants_cbor_dec_peek_type(dec, &t);
    if (err != ANTS_OK) {
        return err;
    }

    switch (t) {
    case ANTS_CBOR_TYPE_UINT: {
        uint64_t v;
        return ants_cbor_dec_uint(dec, &v);
    }
    case ANTS_CBOR_TYPE_NEGINT: {
        int64_t v;
        return ants_cbor_dec_int(dec, &v);
    }
    case ANTS_CBOR_TYPE_BYTES: {
        const uint8_t *b;
        size_t l;
        return ants_cbor_dec_bytes(dec, &b, &l);
    }
    case ANTS_CBOR_TYPE_TEXT: {
        const char *s;
        size_t l;
        return ants_cbor_dec_text(dec, &s, &l);
    }
    case ANTS_CBOR_TYPE_ARRAY: {
        size_t n;
        err = ants_cbor_dec_array(dec, &n);
        if (err != ANTS_OK) {
            return err;
        }
        for (size_t i = 0; i < n; i++) {
            err = walk_one_item(dec);
            if (err != ANTS_OK) {
                return err;
            }
        }
        return ANTS_OK;
    }
    case ANTS_CBOR_TYPE_MAP: {
        size_t n;
        err = ants_cbor_dec_map(dec, &n);
        if (err != ANTS_OK) {
            return err;
        }
        for (size_t i = 0; i < n; i++) {
            err = walk_one_item(dec); /* key */
            if (err != ANTS_OK) {
                return err;
            }
            err = walk_one_item(dec); /* value */
            if (err != ANTS_OK) {
                return err;
            }
        }
        return ANTS_OK;
    }
    case ANTS_CBOR_TYPE_TAG: {
        uint64_t tag;
        err = ants_cbor_dec_tag(dec, &tag);
        if (err != ANTS_OK) {
            return err;
        }
        return walk_one_item(dec); /* tagged item */
    }
    case ANTS_CBOR_TYPE_BOOL: {
        bool b;
        return ants_cbor_dec_bool(dec, &b);
    }
    case ANTS_CBOR_TYPE_NULL:
        return ants_cbor_dec_null(dec);
    default:
        return ANTS_ERROR_MALFORMED;
    }
}

ants_error_t ants_cbor_is_canonical(const uint8_t *buf, size_t len)
{
    if (buf == NULL && len > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (len == 0) {
        return ANTS_ERROR_MALFORMED;
    }

    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    err = walk_one_item(&dec);
    if (err != ANTS_OK) {
        return err;
    }
    if (!ants_cbor_dec_eof(&dec)) {
        /* Trailing bytes after the top-level item. */
        return ANTS_ERROR_MALFORMED;
    }
    if (dec.depth != -1) {
        /* Should not happen if walk completed successfully — defence in
         * depth. */
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
