/*
 * ants_cbor.h — Deterministic CBOR codec.
 *
 * Implements RFC 8949 §4.2.1 strict deterministic encoding, per
 * RFC-0008 §1.1 of the ANTS spec.
 *
 * Invariants the codec enforces:
 *   - shortest-form integer encoding;
 *   - definite-length encoding for arrays, maps, byte strings, text;
 *   - map keys sorted by bytewise lexicographic order of their canonical
 *     CBOR encoding (caller must add keys in canonical order; the
 *     encoder validates the order and returns ANTS_ERROR_NON_CANONICAL
 *     on violation);
 *   - no indefinite-length items;
 *   - no tags except the reserved set in RFC-0008 §1.1 (tag 0
 *     date-time, tag 32 URI, tag 42 IPLD CID).
 *   - no floats (forbidden in protocol-level objects per RFC-0008 §1.3).
 *
 * The decoder is *strict*: any input violating the rules above is
 * rejected with ANTS_ERROR_NON_CANONICAL, not parsed leniently. This is
 * the security-load-bearing property of the component — a permissive
 * decoder opens hash-malleability across the whole protocol.
 *
 * All memory is caller-provided. The library never calls malloc.
 *
 * Spec reference: RFC-0008 §1.1.
 * Component README: ants-client/foundation/cbor/README.md.
 * Status: API surface declared; implementation is stubbed
 *         (returns ANTS_ERROR_NOT_IMPLEMENTED).
 */

#ifndef ANTS_CBOR_H
#define ANTS_CBOR_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Encoder                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Maximum nesting depth (arrays + maps combined). A fixed limit avoids
 * runtime allocation and bounds the worst-case decoder stack usage.
 * The protocol does not require deeper nesting; 16 is comfortable.
 */
#define ANTS_CBOR_MAX_DEPTH 16

typedef enum {
    ANTS_CBOR_CTX_NONE = 0,
    ANTS_CBOR_CTX_ARRAY,
    ANTS_CBOR_CTX_MAP_KEY,
    ANTS_CBOR_CTX_MAP_VALUE,
} ants_cbor_ctx_kind_t;

typedef struct {
    ants_cbor_ctx_kind_t kind;
    size_t               remaining; /* items left to add at this level */
    /* For maps: the byte range of the most recently added key, so the
     * encoder can validate canonical-key-order on the next key. */
    size_t               last_key_begin;
    size_t               last_key_end;
} ants_cbor_ctx_t;

/*
 * Encoder state. Caller allocates (typically on the stack) and passes
 * to every encode function. The buf is also caller-provided and not
 * owned by the encoder.
 */
typedef struct {
    uint8_t *buf; /* caller-provided write buffer */
    size_t   cap; /* total capacity in bytes */
    size_t   pos; /* current write position */

    ants_cbor_ctx_t stack[ANTS_CBOR_MAX_DEPTH];
    int             depth; /* current stack index; -1 means top level */
} ants_cbor_enc_t;

/*
 * Initialise an encoder with a caller-provided buffer.
 *
 * On success the encoder is at depth -1 (top level), pos 0, and ready
 * to accept the first item.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG if enc or buf is NULL, or cap is 0.
 */
ants_error_t ants_cbor_enc_init(ants_cbor_enc_t *enc, uint8_t *buf, size_t cap);

/* Encode an unsigned integer (CBOR major type 0). */
ants_error_t ants_cbor_enc_uint(ants_cbor_enc_t *enc, uint64_t v);

/* Encode a signed integer. Uses major type 0 for v >= 0, major type 1
 * otherwise. The encoder picks the shortest-form representation
 * automatically. */
ants_error_t ants_cbor_enc_int(ants_cbor_enc_t *enc, int64_t v);

/* Encode a byte string (CBOR major type 2). `b` may be NULL only if
 * `len` is 0. */
ants_error_t ants_cbor_enc_bytes(ants_cbor_enc_t *enc, const uint8_t *b, size_t len);

/* Encode a UTF-8 text string (CBOR major type 3). The encoder does NOT
 * validate UTF-8 well-formedness; that is the caller's responsibility
 * (the encoder will accept any byte sequence). */
ants_error_t ants_cbor_enc_text(ants_cbor_enc_t *enc, const char *s, size_t len);

/* Open an array container of exactly `n` items (CBOR major type 4).
 * The caller must add exactly `n` items before adding any item at the
 * parent level. The encoder tracks this via the context stack and
 * returns ANTS_ERROR_MALFORMED on under- or over-fill. */
ants_error_t ants_cbor_enc_array(ants_cbor_enc_t *enc, size_t n);

/* Open a map container of exactly `n` key-value pairs (CBOR major type
 * 5). The caller must add 2*n items (keys interleaved with values).
 * The encoder validates that each key, after the first, is strictly
 * greater than the previous key in bytewise lexicographic order and
 * returns ANTS_ERROR_NON_CANONICAL otherwise. */
ants_error_t ants_cbor_enc_map(ants_cbor_enc_t *enc, size_t n);

/* Encode a boolean. CBOR major type 7, simple values 20 (false) and 21
 * (true). */
ants_error_t ants_cbor_enc_bool(ants_cbor_enc_t *enc, bool v);

/* Encode a null value. CBOR major type 7, simple value 22. */
ants_error_t ants_cbor_enc_null(ants_cbor_enc_t *enc);

/* Emit a tag header. The next item written becomes the tagged item.
 * Only RFC-0008 §1.1 reserved tags are accepted: 0, 32, 42.
 * Returns ANTS_ERROR_UNSUPPORTED_TYPE for any other tag. */
ants_error_t ants_cbor_enc_tag(ants_cbor_enc_t *enc, uint64_t tag);

/* Bytes written so far. Equal to the canonical CBOR encoding's length
 * once the top-level item is complete. */
size_t ants_cbor_enc_size(const ants_cbor_enc_t *enc);

/* Check that the encoder is at a complete top-level state: depth == -1
 * and at least one top-level item has been written. Returns ANTS_OK if
 * complete, ANTS_ERROR_MALFORMED if a container is still open. */
ants_error_t ants_cbor_enc_finalise(const ants_cbor_enc_t *enc);

/* ------------------------------------------------------------------------ */
/* Decoder                                                                  */
/* ------------------------------------------------------------------------ */

typedef enum {
    ANTS_CBOR_TYPE_UINT = 0,
    ANTS_CBOR_TYPE_NEGINT,
    ANTS_CBOR_TYPE_BYTES,
    ANTS_CBOR_TYPE_TEXT,
    ANTS_CBOR_TYPE_ARRAY,
    ANTS_CBOR_TYPE_MAP,
    ANTS_CBOR_TYPE_TAG,
    ANTS_CBOR_TYPE_BOOL,
    ANTS_CBOR_TYPE_NULL,
} ants_cbor_type_t;

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} ants_cbor_dec_t;

/*
 * Initialise a decoder over a caller-provided input buffer.
 *
 * The decoder does not copy the buffer. It must outlive the decoder.
 */
ants_error_t ants_cbor_dec_init(ants_cbor_dec_t *dec, const uint8_t *buf, size_t len);

/* Peek the type of the next item without consuming it. Returns
 * ANTS_ERROR_MALFORMED if the buffer is exhausted or the next item is
 * structurally invalid. */
ants_error_t ants_cbor_dec_peek_type(const ants_cbor_dec_t *dec, ants_cbor_type_t *out);

/* Decode the next item as an unsigned integer. */
ants_error_t ants_cbor_dec_uint(ants_cbor_dec_t *dec, uint64_t *out);

/* Decode the next item as a signed integer. Both major types 0 and 1
 * are accepted; the result is widened to int64_t. Returns
 * ANTS_ERROR_OVERFLOW if the parsed value does not fit. */
ants_error_t ants_cbor_dec_int(ants_cbor_dec_t *dec, int64_t *out);

/* Decode the next item as a byte string. On success, *out_buf points
 * into the decoder's input buffer (no copy), and *out_len is the
 * length. */
ants_error_t ants_cbor_dec_bytes(ants_cbor_dec_t *dec, const uint8_t **out_buf, size_t *out_len);

/* Decode the next item as a UTF-8 text string. Like ants_cbor_dec_bytes
 * (no copy, no UTF-8 validation). */
ants_error_t ants_cbor_dec_text(ants_cbor_dec_t *dec, const char **out_buf, size_t *out_len);

/* Open an array. On success, *out_n is the declared item count. The
 * decoder is positioned at the first item. */
ants_error_t ants_cbor_dec_array(ants_cbor_dec_t *dec, size_t *out_n);

/* Open a map. On success, *out_n is the declared pair count. The
 * decoder is positioned at the first key. */
ants_error_t ants_cbor_dec_map(ants_cbor_dec_t *dec, size_t *out_n);

/* Decode a tag header. The next item becomes the tagged item. Only
 * tags 0, 32, 42 are accepted. */
ants_error_t ants_cbor_dec_tag(ants_cbor_dec_t *dec, uint64_t *out_tag);

/* Decode a boolean. */
ants_error_t ants_cbor_dec_bool(ants_cbor_dec_t *dec, bool *out);

/* Decode a null value. */
ants_error_t ants_cbor_dec_null(ants_cbor_dec_t *dec);

/* Bytes consumed so far. */
size_t ants_cbor_dec_pos(const ants_cbor_dec_t *dec);

/* True if the decoder is at end-of-buffer (all bytes consumed). */
bool ants_cbor_dec_eof(const ants_cbor_dec_t *dec);

/* ------------------------------------------------------------------------ */
/* Canonical-encoding validator                                             */
/* ------------------------------------------------------------------------ */

/*
 * Top-level validator: decode every item in `buf`, validating canonical
 * encoding at each step, and require that exactly `len` bytes are
 * consumed.
 *
 * Returns:
 *   ANTS_OK if the input is well-formed canonical CBOR;
 *   ANTS_ERROR_MALFORMED if the input is not well-formed CBOR;
 *   ANTS_ERROR_NON_CANONICAL if well-formed but violates §4.2.1.
 *
 * Equivalent to walking the input with ants_cbor_dec_* functions and
 * checking that all items are consumed without error.
 */
ants_error_t ants_cbor_is_canonical(const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CBOR_H */
