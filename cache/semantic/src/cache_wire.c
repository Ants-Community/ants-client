/*
 * cache_wire.c — CBOR encode/decode for the cache-entry record
 * (Component #10 step 4).
 *
 * Implements ants_semantic_cache_entry_encode / _decode per
 * RFC-0002 §The cache entry schema and RFC-0008 §3 canonical CBOR.
 *
 * Wire format: a CBOR map with integer keys 1..10 in canonical
 * (ascending) order:
 *
 *   1 : embedding         bytes(4096)    raw IEEE-754 LE floats
 *   2 : embedding_model   text
 *   3 : prompt_hash       bytes(32)      SHA-256 of the prompt
 *   4 : response          bytes
 *   5 : response_model    text
 *   6 : producer          bytes(32)      Ed25519 pubkey
 *   7 : created           uint           Unix timestamp seconds
 *   8 : validity_class    uint           0..4 per the enum
 *   9 : attestation       bytes          RFC-0003 attestation (opaque,
 *                                         may be zero-length in v0.x)
 *   10: signature         bytes(64)      Ed25519 sig over canonical
 *                                         CBOR of fields 1..9
 *
 * The embedding is exchanged as raw bytes, NOT as a CBOR float array.
 * RFC-0008 §canonical-numerics treats the binary representation as
 * protocol-defined: 4 bytes per float, little-endian IEEE-754. This
 * sidesteps CBOR's half/single/double ambiguity and matches the
 * binary footprint of the embedding service's output.
 *
 * Decoder produces pointers aliased into the source buffer (zero-copy)
 * for the variable-length text/bytes fields; the embedding is the one
 * exception, unpacked into a caller-supplied float buffer because the
 * raw LE bytes need to be byte-swapped on big-endian hosts.
 */

#include "ants_cbor.h"
#include "ants_semantic_cache.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KEY_EMBEDDING       1u
#define KEY_EMBEDDING_MODEL 2u
#define KEY_PROMPT_HASH     3u
#define KEY_RESPONSE        4u
#define KEY_RESPONSE_MODEL  5u
#define KEY_PRODUCER        6u
#define KEY_CREATED         7u
#define KEY_VALIDITY_CLASS  8u
#define KEY_ATTESTATION     9u
#define KEY_SIGNATURE       10u

#define EMBEDDING_WIRE_LEN  ((size_t)ANTS_EMBED_DIM * 4u) /* 4096 bytes */

/* Pack ANTS_EMBED_DIM floats into 4096 LE bytes. Bit-exact on any
 * IEEE-754 host regardless of native endianness: we always emit bytes
 * in increasing significance, so a big-endian host produces the same
 * wire bytes as a little-endian host. */
static void floats_to_le_bytes(const float *in, uint8_t *out)
{
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        uint32_t bits = 0;
        memcpy(&bits, &in[i], sizeof(uint32_t));
        out[i * 4u + 0u] = (uint8_t)(bits & 0xFFu);
        out[i * 4u + 1u] = (uint8_t)((bits >> 8) & 0xFFu);
        out[i * 4u + 2u] = (uint8_t)((bits >> 16) & 0xFFu);
        out[i * 4u + 3u] = (uint8_t)((bits >> 24) & 0xFFu);
    }
}

static void le_bytes_to_floats(const uint8_t *in, float *out)
{
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        uint32_t bits = (uint32_t)in[i * 4u + 0u] | ((uint32_t)in[i * 4u + 1u] << 8) |
                        ((uint32_t)in[i * 4u + 2u] << 16) | ((uint32_t)in[i * 4u + 3u] << 24);
        memcpy(&out[i], &bits, sizeof(uint32_t));
    }
}

/* Pack a single float into 4 LE bytes — same canonical-numerics
 * discipline as the embedding bytes. */
static void float_to_le_bytes(float in, uint8_t out[4])
{
    uint32_t bits = 0;
    memcpy(&bits, &in, sizeof(uint32_t));
    out[0] = (uint8_t)(bits & 0xFFu);
    out[1] = (uint8_t)((bits >> 8) & 0xFFu);
    out[2] = (uint8_t)((bits >> 16) & 0xFFu);
    out[3] = (uint8_t)((bits >> 24) & 0xFFu);
}

static float le_bytes_to_float(const uint8_t in[4])
{
    uint32_t bits = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
                    ((uint32_t)in[3] << 24);
    float out = 0.0f;
    memcpy(&out, &bits, sizeof(uint32_t));
    return out;
}

/* Validate an entry's pointers/lengths/range. Returns INVALID_ARG on
 * any failure so the encoder can bail before touching the buffer. */
static ants_error_t entry_validate(const ants_semantic_cache_entry_t *entry)
{
    if (entry->embedding == NULL || entry->embedding_model == NULL ||
        entry->response_model == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (entry->response_len > 0 && entry->response == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (entry->attestation_len > 0 && entry->attestation == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((unsigned)entry->validity_class > 4u) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_OK;
}

/* Emit one cache-entry record as a nested CBOR map onto an already-
 * open encoder. Used by:
 *   - the public entry_encode (top-level map, include_signature=true);
 *   - the lookup response encoder (nested per-match map, true);
 *   - cache_entry_emit_signing_payload (false → emits map(9) without
 *     the signature field, i.e. the canonical bytes a producer signs).
 * Caller has already validated `entry`. */
static ants_error_t
entry_emit(ants_cbor_enc_t *enc, const ants_semantic_cache_entry_t *entry, bool include_signature)
{
    uint8_t emb_le[EMBEDDING_WIRE_LEN];
    floats_to_le_bytes(entry->embedding, emb_le);

    ants_error_t err = ants_cbor_enc_map(enc, include_signature ? 10 : 9);
    if (err != ANTS_OK) {
        return err;
    }

#define EMIT_KEY(k)                                                                                \
    do {                                                                                           \
        err = ants_cbor_enc_uint(enc, (k));                                                        \
        if (err != ANTS_OK) {                                                                      \
            return err;                                                                            \
        }                                                                                          \
    } while (0)

    EMIT_KEY(KEY_EMBEDDING);
    err = ants_cbor_enc_bytes(enc, emb_le, EMBEDDING_WIRE_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_EMBEDDING_MODEL);
    err = ants_cbor_enc_text(enc, entry->embedding_model, entry->embedding_model_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_PROMPT_HASH);
    err = ants_cbor_enc_bytes(enc, entry->prompt_hash, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_RESPONSE);
    err = ants_cbor_enc_bytes(enc, entry->response, entry->response_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_RESPONSE_MODEL);
    err = ants_cbor_enc_text(enc, entry->response_model, entry->response_model_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_PRODUCER);
    err = ants_cbor_enc_bytes(enc, entry->producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_CREATED);
    err = ants_cbor_enc_uint(enc, entry->created);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_VALIDITY_CLASS);
    err = ants_cbor_enc_uint(enc, (uint64_t)entry->validity_class);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_ATTESTATION);
    err = ants_cbor_enc_bytes(enc, entry->attestation, entry->attestation_len);
    if (err != ANTS_OK) {
        return err;
    }

    if (include_signature) {
        EMIT_KEY(KEY_SIGNATURE);
        err = ants_cbor_enc_bytes(enc, entry->signature, ANTS_SEMANTIC_CACHE_SIG_LEN);
        if (err != ANTS_OK) {
            return err;
        }
    }

#undef EMIT_KEY
    return ANTS_OK;
}

/* Consume one cache-entry record (CBOR map(10) plus its 10 KVs) from an
 * already-open decoder into out_entry. Variable-length text/bytes
 * pointers alias into the decoder's source buffer; the embedding is
 * unpacked into the caller-supplied embedding_out. The caller is
 * responsible for any post-decode EOF / trailing-bytes checks. */
static ants_error_t entry_consume(ants_cbor_dec_t *dec,
                                  ants_semantic_cache_entry_t *out_entry,
                                  float embedding_out[ANTS_EMBED_DIM])
{
    memset(out_entry, 0, sizeof *out_entry);

    size_t n_kv = 0;
    ants_error_t err = ants_cbor_dec_map(dec, &n_kv);
    if (err != ANTS_OK) {
        return err;
    }
    if (n_kv != 10) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Canonical decode: keys MUST appear in ascending order 1..10. */
    for (size_t i = 0; i < 10; i++) {
        uint64_t key = 0;
        err = ants_cbor_dec_uint(dec, &key);
        if (err != ANTS_OK) {
            return err;
        }
        if (key != (uint64_t)(i + 1)) {
            return ANTS_ERROR_NON_CANONICAL;
        }

        const uint8_t *bytes_ptr = NULL;
        size_t bytes_len = 0;
        const char *text_ptr = NULL;
        size_t text_len = 0;
        uint64_t uval = 0;

        switch (key) {
        case KEY_EMBEDDING:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != EMBEDDING_WIRE_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            le_bytes_to_floats(bytes_ptr, embedding_out);
            out_entry->embedding = embedding_out;
            break;

        case KEY_EMBEDDING_MODEL:
            err = ants_cbor_dec_text(dec, &text_ptr, &text_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->embedding_model = text_ptr;
            out_entry->embedding_model_len = text_len;
            break;

        case KEY_PROMPT_HASH:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            memcpy(out_entry->prompt_hash, bytes_ptr, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN);
            break;

        case KEY_RESPONSE:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->response = bytes_ptr;
            out_entry->response_len = bytes_len;
            break;

        case KEY_RESPONSE_MODEL:
            err = ants_cbor_dec_text(dec, &text_ptr, &text_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->response_model = text_ptr;
            out_entry->response_model_len = text_len;
            break;

        case KEY_PRODUCER:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != ANTS_SEMANTIC_CACHE_PEER_ID_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            memcpy(out_entry->producer, bytes_ptr, ANTS_SEMANTIC_CACHE_PEER_ID_LEN);
            break;

        case KEY_CREATED:
            err = ants_cbor_dec_uint(dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->created = uval;
            break;

        case KEY_VALIDITY_CLASS:
            err = ants_cbor_dec_uint(dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            if (uval > 4u) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            out_entry->validity_class = (ants_semantic_cache_validity_t)uval;
            break;

        case KEY_ATTESTATION:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->attestation = bytes_ptr;
            out_entry->attestation_len = bytes_len;
            break;

        case KEY_SIGNATURE:
            err = ants_cbor_dec_bytes(dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != ANTS_SEMANTIC_CACHE_SIG_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            memcpy(out_entry->signature, bytes_ptr, ANTS_SEMANTIC_CACHE_SIG_LEN);
            break;

        default:
            /* Unreachable: key range was checked above. */
            return ANTS_ERROR_MALFORMED;
        }
    }
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_entry_encode(const ants_semantic_cache_entry_t *entry,
                                              uint8_t *buf,
                                              size_t out_cap,
                                              size_t *out_len)
{
    if (entry == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_error_t err = entry_validate(entry);
    if (err != ANTS_OK) {
        return err;
    }

    ants_cbor_enc_t enc;
    err = ants_cbor_enc_init(&enc, buf, out_cap);
    if (err != ANTS_OK) {
        return err;
    }
    err = entry_emit(&enc, entry, true);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_finalise(&enc);
    if (err != ANTS_OK) {
        return err;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_entry_decode(const uint8_t *buf,
                                              size_t len,
                                              ants_semantic_cache_entry_t *out_entry,
                                              float embedding_out[ANTS_EMBED_DIM])
{
    if (buf == NULL || out_entry == NULL || embedding_out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    err = entry_consume(&dec, out_entry, embedding_out);
    if (err != ANTS_OK) {
        return err;
    }
    if (!ants_cbor_dec_eof(&dec)) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* Emit the canonical signing payload — CBOR map(9) covering fields
 * 1..9 of the cache entry, in ascending key order. This is the exact
 * byte sequence the producer signs with their Ed25519 private key
 * (per RFC-0002 §The cache entry); receivers re-emit it via this
 * helper and pass the resulting bytes to ants_ed25519_verify against
 * entry.producer / entry.signature.
 *
 * Module-scope (not in the public header): used by cache.c's
 * handle_inbound_entry. Caller supplies a buffer at least as large as
 * the full entry's CBOR encoding (the signing payload is always
 * smaller — it drops the 67-byte signature field). The matching
 * forward declaration lives in cache.c (extern); we repeat the
 * prototype here to silence -Wmissing-prototypes. */
ants_error_t cache_entry_emit_signing_payload(const ants_semantic_cache_entry_t *entry,
                                              uint8_t *buf,
                                              size_t out_cap,
                                              size_t *out_len);

ants_error_t cache_entry_emit_signing_payload(const ants_semantic_cache_entry_t *entry,
                                              uint8_t *buf,
                                              size_t out_cap,
                                              size_t *out_len)
{
    if (entry == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_error_t err = entry_validate(entry);
    if (err != ANTS_OK) {
        return err;
    }

    ants_cbor_enc_t enc;
    err = ants_cbor_enc_init(&enc, buf, out_cap);
    if (err != ANTS_OK) {
        return err;
    }
    err = entry_emit(&enc, entry, false /* include_signature */);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_finalise(&enc);
    if (err != ANTS_OK) {
        return err;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lookup request wire format (RFC-0002 §The lookup protocol)               */
/*                                                                          */
/* CBOR map with integer keys 1..4 in canonical order:                      */
/*   1: embedding        bytes(4096)   raw LE floats                        */
/*   2: threshold        bytes(4)      raw LE float                         */
/*   3: top_k            uint          0 = unbounded                        */
/*   4: hamming_radius   uint          0..MAX_HAMMING_RADIUS (3)            */
/* ------------------------------------------------------------------------ */

#define LR_KEY_EMBEDDING      1u
#define LR_KEY_THRESHOLD      2u
#define LR_KEY_TOP_K          3u
#define LR_KEY_HAMMING_RADIUS 4u

ants_error_t ants_semantic_cache_lookup_request_encode(const float embedding[ANTS_EMBED_DIM],
                                                       float similarity_threshold,
                                                       uint32_t top_k,
                                                       uint32_t hamming_radius,
                                                       uint8_t *buf,
                                                       size_t out_cap,
                                                       size_t *out_len)
{
    if (embedding == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (hamming_radius > ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
        return ANTS_ERROR_INVALID_ARG;
    }

    uint8_t emb_le[EMBEDDING_WIRE_LEN];
    floats_to_le_bytes(embedding, emb_le);

    uint8_t threshold_le[4];
    float_to_le_bytes(similarity_threshold, threshold_le);

    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, out_cap);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_map(&enc, 4);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_uint(&enc, LR_KEY_EMBEDDING);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_bytes(&enc, emb_le, EMBEDDING_WIRE_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_uint(&enc, LR_KEY_THRESHOLD);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_bytes(&enc, threshold_le, 4);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_uint(&enc, LR_KEY_TOP_K);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_uint(&enc, (uint64_t)top_k);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_uint(&enc, LR_KEY_HAMMING_RADIUS);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_uint(&enc, (uint64_t)hamming_radius);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_finalise(&enc);
    if (err != ANTS_OK) {
        return err;
    }

    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_lookup_request_decode(const uint8_t *buf,
                                                       size_t len,
                                                       float embedding_out[ANTS_EMBED_DIM],
                                                       float *out_threshold,
                                                       uint32_t *out_top_k,
                                                       uint32_t *out_hamming_radius)
{
    if (buf == NULL || embedding_out == NULL || out_threshold == NULL || out_top_k == NULL ||
        out_hamming_radius == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_threshold = 0.0f;
    *out_top_k = 0;
    *out_hamming_radius = 0;

    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }

    size_t n_kv = 0;
    err = ants_cbor_dec_map(&dec, &n_kv);
    if (err != ANTS_OK) {
        return err;
    }
    if (n_kv != 4) {
        return ANTS_ERROR_MALFORMED;
    }

    for (size_t i = 0; i < 4; i++) {
        uint64_t key = 0;
        err = ants_cbor_dec_uint(&dec, &key);
        if (err != ANTS_OK) {
            return err;
        }
        if (key != (uint64_t)(i + 1)) {
            return ANTS_ERROR_NON_CANONICAL;
        }

        const uint8_t *bytes_ptr = NULL;
        size_t bytes_len = 0;
        uint64_t uval = 0;

        switch (key) {
        case LR_KEY_EMBEDDING:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != EMBEDDING_WIRE_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            le_bytes_to_floats(bytes_ptr, embedding_out);
            break;

        case LR_KEY_THRESHOLD:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != 4) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            *out_threshold = le_bytes_to_float(bytes_ptr);
            break;

        case LR_KEY_TOP_K:
            err = ants_cbor_dec_uint(&dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            if (uval > 0xFFFFFFFFull) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            *out_top_k = (uint32_t)uval;
            break;

        case LR_KEY_HAMMING_RADIUS:
            err = ants_cbor_dec_uint(&dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            if (uval > (uint64_t)ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            *out_hamming_radius = (uint32_t)uval;
            break;

        default:
            return ANTS_ERROR_MALFORMED;
        }
    }

    if (!ants_cbor_dec_eof(&dec)) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lookup response wire format (RFC-0002 §The lookup protocol)              */
/*                                                                          */
/* Top-level: CBOR map { 1: matches[] }                                      */
/* Each match: CBOR map { 1: similarity_bytes(4), 2: <entry-map(10)> }      */
/* ------------------------------------------------------------------------ */

#define LRESP_KEY_MATCHES 1u
#define LMATCH_KEY_SIM    1u
#define LMATCH_KEY_ENTRY  2u

ants_error_t
ants_semantic_cache_lookup_response_encode(const ants_semantic_cache_lookup_match_t *matches,
                                           size_t n_matches,
                                           uint8_t *buf,
                                           size_t out_cap,
                                           size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_matches > 0 && matches == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Validate every entry up front so the encoder doesn't get half-
     * way through emitting before failing. */
    for (size_t i = 0; i < n_matches; i++) {
        ants_error_t err = entry_validate(&matches[i].entry);
        if (err != ANTS_OK) {
            return err;
        }
    }

    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, out_cap);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_map(&enc, 1);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_uint(&enc, LRESP_KEY_MATCHES);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_cbor_enc_array(&enc, n_matches);
    if (err != ANTS_OK) {
        return err;
    }

    for (size_t i = 0; i < n_matches; i++) {
        uint8_t sim_bytes[4];
        float_to_le_bytes(matches[i].similarity, sim_bytes);

        err = ants_cbor_enc_map(&enc, 2);
        if (err != ANTS_OK) {
            return err;
        }
        err = ants_cbor_enc_uint(&enc, LMATCH_KEY_SIM);
        if (err != ANTS_OK) {
            return err;
        }
        err = ants_cbor_enc_bytes(&enc, sim_bytes, 4);
        if (err != ANTS_OK) {
            return err;
        }
        err = ants_cbor_enc_uint(&enc, LMATCH_KEY_ENTRY);
        if (err != ANTS_OK) {
            return err;
        }
        err = entry_emit(&enc, &matches[i].entry, true);
        if (err != ANTS_OK) {
            return err;
        }
    }

    err = ants_cbor_enc_finalise(&enc);
    if (err != ANTS_OK) {
        return err;
    }

    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t
ants_semantic_cache_lookup_response_decode(const uint8_t *buf,
                                           size_t len,
                                           ants_semantic_cache_lookup_match_t *out_matches,
                                           float *out_embeddings,
                                           size_t cap_matches,
                                           size_t *out_n)
{
    if (buf == NULL || out_n == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (cap_matches > 0 && (out_matches == NULL || out_embeddings == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_n = 0;

    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }

    size_t top_kv = 0;
    err = ants_cbor_dec_map(&dec, &top_kv);
    if (err != ANTS_OK) {
        return err;
    }
    if (top_kv != 1) {
        return ANTS_ERROR_MALFORMED;
    }
    uint64_t top_key = 0;
    err = ants_cbor_dec_uint(&dec, &top_key);
    if (err != ANTS_OK) {
        return err;
    }
    if (top_key != LRESP_KEY_MATCHES) {
        return ANTS_ERROR_NON_CANONICAL;
    }

    size_t n_matches = 0;
    err = ants_cbor_dec_array(&dec, &n_matches);
    if (err != ANTS_OK) {
        return err;
    }
    *out_n = n_matches;

    /* Decode up to cap_matches into the caller's buffers. The remaining
     * wire bytes are not consumed when cap is short; skip the trailing-
     * EOF check in that case and return BUFFER_TOO_SMALL. */
    size_t to_decode = (n_matches < cap_matches) ? n_matches : cap_matches;

    for (size_t i = 0; i < to_decode; i++) {
        size_t mkv = 0;
        err = ants_cbor_dec_map(&dec, &mkv);
        if (err != ANTS_OK) {
            return err;
        }
        if (mkv != 2) {
            return ANTS_ERROR_MALFORMED;
        }

        /* match key 1: similarity bytes(4) */
        uint64_t mk = 0;
        err = ants_cbor_dec_uint(&dec, &mk);
        if (err != ANTS_OK) {
            return err;
        }
        if (mk != LMATCH_KEY_SIM) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        const uint8_t *sim_bytes = NULL;
        size_t sim_len = 0;
        err = ants_cbor_dec_bytes(&dec, &sim_bytes, &sim_len);
        if (err != ANTS_OK) {
            return err;
        }
        if (sim_len != 4) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        out_matches[i].similarity = le_bytes_to_float(sim_bytes);

        /* match key 2: entry (nested map(10)) */
        err = ants_cbor_dec_uint(&dec, &mk);
        if (err != ANTS_OK) {
            return err;
        }
        if (mk != LMATCH_KEY_ENTRY) {
            return ANTS_ERROR_NON_CANONICAL;
        }

        float *emb_slot = &out_embeddings[i * (size_t)ANTS_EMBED_DIM];
        err = entry_consume(&dec, &out_matches[i].entry, emb_slot);
        if (err != ANTS_OK) {
            return err;
        }
    }

    if (cap_matches < n_matches) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    if (!ants_cbor_dec_eof(&dec)) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
