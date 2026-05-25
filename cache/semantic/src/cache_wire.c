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

ants_error_t ants_semantic_cache_entry_encode(const ants_semantic_cache_entry_t *entry,
                                              uint8_t *buf,
                                              size_t out_cap,
                                              size_t *out_len)
{
    if (entry == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
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

    /* 4 KB stack buffer for the packed embedding. The caller's
     * float[1024] stays untouched. */
    uint8_t emb_le[EMBEDDING_WIRE_LEN];
    floats_to_le_bytes(entry->embedding, emb_le);

    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, out_cap);
    if (err != ANTS_OK) {
        return err;
    }

    err = ants_cbor_enc_map(&enc, 10);
    if (err != ANTS_OK) {
        return err;
    }

#define EMIT_KEY(k)                                                                                \
    do {                                                                                           \
        err = ants_cbor_enc_uint(&enc, (k));                                                       \
        if (err != ANTS_OK) {                                                                      \
            return err;                                                                            \
        }                                                                                          \
    } while (0)

    EMIT_KEY(KEY_EMBEDDING);
    err = ants_cbor_enc_bytes(&enc, emb_le, EMBEDDING_WIRE_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_EMBEDDING_MODEL);
    err = ants_cbor_enc_text(&enc, entry->embedding_model, entry->embedding_model_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_PROMPT_HASH);
    err = ants_cbor_enc_bytes(&enc, entry->prompt_hash, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_RESPONSE);
    err = ants_cbor_enc_bytes(&enc, entry->response, entry->response_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_RESPONSE_MODEL);
    err = ants_cbor_enc_text(&enc, entry->response_model, entry->response_model_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_PRODUCER);
    err = ants_cbor_enc_bytes(&enc, entry->producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_CREATED);
    err = ants_cbor_enc_uint(&enc, entry->created);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_VALIDITY_CLASS);
    err = ants_cbor_enc_uint(&enc, (uint64_t)entry->validity_class);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_ATTESTATION);
    err = ants_cbor_enc_bytes(&enc, entry->attestation, entry->attestation_len);
    if (err != ANTS_OK) {
        return err;
    }

    EMIT_KEY(KEY_SIGNATURE);
    err = ants_cbor_enc_bytes(&enc, entry->signature, ANTS_SEMANTIC_CACHE_SIG_LEN);
    if (err != ANTS_OK) {
        return err;
    }

#undef EMIT_KEY

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
    memset(out_entry, 0, sizeof *out_entry);

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
    if (n_kv != 10) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Canonical decode: keys MUST appear in ascending order 1..10.
     * Any deviation is a non-canonical encoding. */
    for (size_t i = 0; i < 10; i++) {
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
        const char *text_ptr = NULL;
        size_t text_len = 0;
        uint64_t uval = 0;

        switch (key) {
        case KEY_EMBEDDING:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
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
            err = ants_cbor_dec_text(&dec, &text_ptr, &text_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->embedding_model = text_ptr;
            out_entry->embedding_model_len = text_len;
            break;

        case KEY_PROMPT_HASH:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            memcpy(out_entry->prompt_hash, bytes_ptr, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN);
            break;

        case KEY_RESPONSE:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->response = bytes_ptr;
            out_entry->response_len = bytes_len;
            break;

        case KEY_RESPONSE_MODEL:
            err = ants_cbor_dec_text(&dec, &text_ptr, &text_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->response_model = text_ptr;
            out_entry->response_model_len = text_len;
            break;

        case KEY_PRODUCER:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            if (bytes_len != ANTS_SEMANTIC_CACHE_PEER_ID_LEN) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            memcpy(out_entry->producer, bytes_ptr, ANTS_SEMANTIC_CACHE_PEER_ID_LEN);
            break;

        case KEY_CREATED:
            err = ants_cbor_dec_uint(&dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->created = uval;
            break;

        case KEY_VALIDITY_CLASS:
            err = ants_cbor_dec_uint(&dec, &uval);
            if (err != ANTS_OK) {
                return err;
            }
            if (uval > 4u) {
                return ANTS_ERROR_NON_CANONICAL;
            }
            out_entry->validity_class = (ants_semantic_cache_validity_t)uval;
            break;

        case KEY_ATTESTATION:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
            if (err != ANTS_OK) {
                return err;
            }
            out_entry->attestation = bytes_ptr;
            out_entry->attestation_len = bytes_len;
            break;

        case KEY_SIGNATURE:
            err = ants_cbor_dec_bytes(&dec, &bytes_ptr, &bytes_len);
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

    if (!ants_cbor_dec_eof(&dec)) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
