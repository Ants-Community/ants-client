/*
 * ants_semantic_cache.h — Distributed semantic cache (Component #10).
 *
 * The cache layer's content-addressable storage. Caller computes an
 * embedding via ants_embed; the cache maps that embedding to a 64-bit
 * shard key via LSH and routes it through the DHT for lookup or
 * insertion.
 *
 * Spec references:
 *   - RFC-0002 §DHT routing — LSH shard-key scheme (64 hyperplanes
 *     projected over the 1024-dim embedding, sign-bits → shard key).
 *   - RFC-0002 §The write protocol — producer constructs signed
 *     cache-entry, replicates to N shard-holders.
 *   - RFC-0002 §The lookup protocol — query the DHT for the shard +
 *     near-neighbour Hamming-1/2/3 keys, aggregate matches with
 *     similarity ≥ threshold.
 *   - RFC-0002 §Quality, decay, and invalidation — eviction by
 *     validity class, challenge-based invalidation, reputation
 *     downweighting.
 *
 * Scaffold stage (step 0): API surface is declared, every entry
 * point returns ANTS_ERROR_NOT_IMPLEMENTED. Subsequent steps land
 * the LSH function, the local-shard store, the DHT-routed write
 * and lookup protocols, eviction, and quality-signal aggregation.
 *
 * API model: caller-allocated context, no internal threads. Heap
 * allocations for the bucket store + entry metadata live behind
 * pointers in the opaque ctx; the ctx itself is bounded-size so it
 * can be stack-allocated by the caller.
 */

#ifndef ANTS_SEMANTIC_CACHE_H
#define ANTS_SEMANTIC_CACHE_H

#include "ants_common.h"
#include "ants_embed.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Protocol-pinned constants (RFC-0002 §DHT routing, §Write, §Lookup)       */
/* ------------------------------------------------------------------------ */

/* The shard-key bit width. RFC-0002 specifies 64 random hyperplanes
 * (one bit per projection sign). Changing this is a protocol break. */
#define ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS 64

/* Default cosine-similarity threshold for cache hits. RFC-0002
 * §Lookup uses 0.92 as the illustrative value; callers may pass a
 * different threshold per-query. */
#define ANTS_SEMANTIC_CACHE_DEFAULT_THRESHOLD 0.92f

/* Default DHT replication factor for write protocol per RFC-0002
 * §Write: "replicated to N (typically 3-5) shard-holders". */
#define ANTS_SEMANTIC_CACHE_DEFAULT_REPLICATION 3u

/* The 64-bit shard key derived from an embedding. Matches the
 * `ants_dht_shard_key_t` typedef in network/dht so the two layers
 * speak the same wire type; we re-declare here so callers don't
 * have to pull in the DHT header just to hold a shard key. */
typedef uint64_t ants_semantic_cache_shard_key_t;

/* Per RFC-0002 §The cache entry: producer-declared validity class.
 * Producers who systematically over-declare (e.g. mark ephemeral
 * content as perennial) get reputation-downweighted by the
 * verification system. Wire encoding: CBOR uint 0..4. */
typedef enum {
    ANTS_SEMANTIC_CACHE_VALIDITY_EPHEMERAL = 0,
    ANTS_SEMANTIC_CACHE_VALIDITY_WEEKS = 1,
    ANTS_SEMANTIC_CACHE_VALIDITY_MONTHS = 2,
    ANTS_SEMANTIC_CACHE_VALIDITY_YEARS = 3,
    ANTS_SEMANTIC_CACHE_VALIDITY_PERENNIAL = 4
} ants_semantic_cache_validity_t;

/* Length of an Ed25519 public key (peer ID) in bytes. */
#define ANTS_SEMANTIC_CACHE_PEER_ID_LEN 32

/* Length of an Ed25519 signature in bytes. */
#define ANTS_SEMANTIC_CACHE_SIG_LEN 64

/* Length of a SHA-256 prompt hash in bytes per RFC-0002 §The cache entry. */
#define ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN 32

/* ------------------------------------------------------------------------ */
/* Cache-entry wire record (RFC-0002 §The cache entry, RFC-0008 §5)         */
/*                                                                          */
/* The producer-signed record that flows over the DHT write protocol.       */
/* All pointer fields are caller-owned for the duration of an encode call;  */
/* the encoder copies into the output buffer. After a decode, pointer       */
/* fields alias into the caller-supplied source buffer (zero-copy) — the    */
/* source buffer MUST remain valid until the entry is no longer accessed.  */
/*                                                                          */
/* The embedding is exchanged as 4096 raw little-endian IEEE-754 bytes,    */
/* not a CBOR float array — RFC-0008 §canonical-numerics treats the binary */
/* representation as protocol-defined to avoid CBOR's half/single/double   */
/* ambiguity. Encoders pack from a float[ANTS_EMBED_DIM]; decoders unpack  */
/* into a caller-supplied float[ANTS_EMBED_DIM].                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Pointer to ANTS_EMBED_DIM L2-normalised float32 values. Caller-
     * owned. The encoder converts to 4096 LE bytes; the decoder
     * unpacks into a caller-supplied buffer (see _entry_decode). */
    const float *embedding;

    /* Embedding model identifier — must be "ants-embed-v1" for v1
     * conformance per RFC-0008 §5. UTF-8 bytes + length; not
     * NUL-terminated on the wire. */
    const char *embedding_model;
    size_t embedding_model_len;

    /* SHA-256 of the prompt bytes per RFC-0002. The prompt itself
     * is NOT stored — this is a privacy default; the prompt is
     * recoverable only by whoever already has it. */
    uint8_t prompt_hash[ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN];

    /* The cached response payload. Opaque bytes — the protocol
     * does not interpret it; the response_model identifies the
     * format. */
    const uint8_t *response;
    size_t response_len;

    /* Model that generated the response (e.g. "llama-3.3-70b-instruct"). */
    const char *response_model;
    size_t response_model_len;

    /* Ed25519 public key of the attested producer (peer ID). */
    uint8_t producer[ANTS_SEMANTIC_CACHE_PEER_ID_LEN];

    /* Unix timestamp (seconds) when the entry was minted. */
    uint64_t created;

    /* Producer-declared validity class. */
    ants_semantic_cache_validity_t validity_class;

    /* Hardware/TEE attestation bytes per RFC-0003. Opaque to this
     * layer — the verification engine validates them out-of-band.
     * May be NULL with len=0 in v0.x; production requires at least
     * one tier of attestation. */
    const uint8_t *attestation;
    size_t attestation_len;

    /* Ed25519 signature over the canonical CBOR encoding of fields
     * 1..9 (every field above except this one). Verified by the
     * receiver against the producer pubkey before the entry is
     * admitted to the local shard. */
    uint8_t signature[ANTS_SEMANTIC_CACHE_SIG_LEN];
} ants_semantic_cache_entry_t;

/*
 * Serialise a cache-entry record into a buffer using canonical CBOR
 * (RFC-0008 §3 deterministic encoding, integer map keys 1..10).
 *
 * Returns:
 *   ANTS_OK                       — *out_len bytes written to buf;
 *   ANTS_ERROR_INVALID_ARG        — NULL args, NULL embedding, NULL
 *                                   response with non-zero len, etc.;
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap insufficient; *out_len set
 *                                   to required size (probe call:
 *                                   buf=NULL, out_cap=0).
 */
ants_error_t ants_semantic_cache_entry_encode(const ants_semantic_cache_entry_t *entry,
                                              uint8_t *buf,
                                              size_t out_cap,
                                              size_t *out_len);

/*
 * Parse a cache-entry record from canonical CBOR bytes.
 *
 * `embedding_out` is a caller-supplied buffer of ANTS_EMBED_DIM
 * floats; the decoder unpacks the wire's 4096 LE bytes into it and
 * sets `out_entry->embedding = embedding_out`. Every other pointer
 * field in *out_entry aliases into `buf`; `buf` MUST remain valid
 * while *out_entry is in use.
 *
 * Returns:
 *   ANTS_OK             — entry populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args;
 *   ANTS_ERROR_MALFORMED   — CBOR parse error, missing required key,
 *                            wrong type, or wrong fixed-length field;
 *   ANTS_ERROR_NON_CANONICAL — wrong embedding byte length, invalid
 *                              validity_class value, or non-canonical
 *                              CBOR ordering.
 */
ants_error_t ants_semantic_cache_entry_decode(const uint8_t *buf,
                                              size_t len,
                                              ants_semantic_cache_entry_t *out_entry,
                                              float embedding_out[ANTS_EMBED_DIM]);

/* ------------------------------------------------------------------------ */
/* Lookup request wire format (RFC-0002 §The lookup protocol)               */
/*                                                                          */
/* The consumer's client computes the embedding of its prompt, computes    */
/* the shard key, queries the DHT for the responsible peers, and sends     */
/* this request to each candidate in parallel. The receiving peer searches */
/* its local shard for entries with cosine similarity ≥ threshold and      */
/* returns up to top_k matches (response wire format lands in step 6).    */
/*                                                                          */
/* Wire format (CBOR map with ascending integer keys 1..3):                */
/*   1 : embedding         bytes(4096)    raw IEEE-754 LE floats           */
/*   2 : threshold         bytes(4)       raw IEEE-754 LE float            */
/*   3 : top_k             uint           0 = unbounded                    */
/*                                                                          */
/* Threshold + embedding use raw byte representation (not CBOR float       */
/* native encoding) for the same canonical-numerics rationale as the       */
/* cache entry record: CBOR's half/single/double "shortest form" choice is */
/* ambiguous, and the protocol pins the binary footprint instead.          */
/* ------------------------------------------------------------------------ */

/*
 * Serialise a cache lookup request into a buffer using canonical CBOR.
 *
 * embedding:           ANTS_EMBED_DIM L2-normalised float32 values
 * similarity_threshold: minimum cosine similarity for a match
 * top_k:               max entries the responder should return; 0 means
 *                       the responder picks (typically all matches above
 *                       threshold up to a server-side cap)
 *
 * Returns:
 *   ANTS_OK                       — *out_len bytes written;
 *   ANTS_ERROR_INVALID_ARG        — NULL args;
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap < required.
 */
ants_error_t ants_semantic_cache_lookup_request_encode(const float embedding[ANTS_EMBED_DIM],
                                                       float similarity_threshold,
                                                       uint32_t top_k,
                                                       uint8_t *buf,
                                                       size_t out_cap,
                                                       size_t *out_len);

/*
 * Parse a cache lookup request from canonical CBOR bytes.
 *
 * embedding_out: caller buffer for ANTS_EMBED_DIM floats; decoder
 *                unpacks the wire's 4096 LE bytes into it.
 * out_threshold / out_top_k: populated from the decoded fields.
 *
 * Returns:
 *   ANTS_OK             — fields populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args;
 *   ANTS_ERROR_MALFORMED   — CBOR parse error, missing required key,
 *                            wrong type, or trailing bytes;
 *   ANTS_ERROR_NON_CANONICAL — wrong byte length on a fixed-length
 *                              field or non-canonical key order.
 */
ants_error_t ants_semantic_cache_lookup_request_decode(const uint8_t *buf,
                                                       size_t len,
                                                       float embedding_out[ANTS_EMBED_DIM],
                                                       float *out_threshold,
                                                       uint32_t *out_top_k);

/* ------------------------------------------------------------------------ */
/* Lookup response wire format (RFC-0002 §The lookup protocol)              */
/*                                                                          */
/* The receiving peer searches its local shard for entries with cosine     */
/* similarity ≥ threshold and returns up to top_k matches in this format.  */
/*                                                                          */
/* Wire format (CBOR map with one integer key):                            */
/*   1 : matches    array of N match objects                               */
/*                                                                          */
/* Each match object is a CBOR map with two ascending integer keys:        */
/*   1 : similarity   bytes(4)        raw IEEE-754 LE float                */
/*   2 : entry        map(10)         nested cache-entry record (step 4   */
/*                                     wire format, inlined here)          */
/* ------------------------------------------------------------------------ */

/* A single (similarity, entry) pair. For encode: caller populates both
 * fields (pointers in `entry` reference caller-owned data). For decode:
 * decoder fills both; pointer fields in `entry` alias into the source
 * buffer (zero-copy), the embedding lives in the caller-supplied
 * embedding-buffer slice for this match. */
typedef struct {
    float similarity;
    ants_semantic_cache_entry_t entry;
} ants_semantic_cache_lookup_match_t;

/*
 * Serialise a list of matches into a buffer using canonical CBOR.
 *
 * matches:     array of n_matches entries (caller fills entry pointers)
 * n_matches:   may be 0 (empty result is a valid response)
 *
 * Returns:
 *   ANTS_OK                       — *out_len bytes written;
 *   ANTS_ERROR_INVALID_ARG        — NULL args, NULL entry pointer in any
 *                                   match, or invalid entry fields
 *                                   (NULL pointers, out-of-range
 *                                   validity_class, etc.);
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap < required.
 */
ants_error_t
ants_semantic_cache_lookup_response_encode(const ants_semantic_cache_lookup_match_t *matches,
                                           size_t n_matches,
                                           uint8_t *buf,
                                           size_t out_cap,
                                           size_t *out_len);

/*
 * Parse a lookup response from canonical CBOR bytes.
 *
 * out_matches:    array of cap_matches match slots filled by the decoder
 * out_embeddings: contiguous buffer of cap_matches × ANTS_EMBED_DIM
 *                 floats; out_matches[i].entry.embedding points into
 *                 out_embeddings[i * ANTS_EMBED_DIM]
 * cap_matches:    capacity of the two caller buffers
 * *out_n:         set to the wire's actual match count
 *
 * Returns:
 *   ANTS_OK                       — full payload decoded; *out_n
 *                                   matches written;
 *   ANTS_ERROR_INVALID_ARG        — NULL args (or NULL out_matches /
 *                                   out_embeddings with cap_matches > 0);
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — *out_n > cap_matches; out_matches
 *                                   holds the first cap_matches matches,
 *                                   caller may re-call with a bigger
 *                                   buffer;
 *   ANTS_ERROR_MALFORMED          — CBOR parse error or trailing bytes;
 *   ANTS_ERROR_NON_CANONICAL      — wrong key order, wrong fixed-length
 *                                   field, etc.
 */
ants_error_t
ants_semantic_cache_lookup_response_decode(const uint8_t *buf,
                                           size_t len,
                                           ants_semantic_cache_lookup_match_t *out_matches,
                                           float *out_embeddings,
                                           size_t cap_matches,
                                           size_t *out_n);

/* ------------------------------------------------------------------------ */
/* Opaque context                                                           */
/*                                                                          */
/* The state struct holds heap pointers (bucket store, LSH projection      */
/* matrix reference, etc.), not the entries themselves. 4 KiB is enough    */
/* for the scaffold state with comfortable headroom for the LSH matrix    */
/* pointer + per-shard book-keeping landing in step 1+.                    */
/* ------------------------------------------------------------------------ */

#define ANTS_SEMANTIC_CACHE_CTX_SIZE 4096

typedef union {
    uint8_t _opaque[ANTS_SEMANTIC_CACHE_CTX_SIZE];
    uint64_t _align;
} ants_semantic_cache_t;

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Maximum entries retained per shard before LRU eviction kicks in.
     * 0 = unbounded (subject to total_max). */
    size_t per_shard_max;

    /* Hard cap on total entries across all shards. 0 = no global cap.
     * When both per_shard_max and total_max are 0 the cache grows
     * without bound until ants_semantic_cache_destroy. */
    size_t total_max;
} ants_semantic_cache_config_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Initialise an in-memory semantic cache.
 *
 * Returns:
 *   ANTS_OK                    — ctx ready for put/get;
 *   ANTS_ERROR_INVALID_ARG     — NULL args;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold stage (current).
 */
ants_error_t ants_semantic_cache_init(ants_semantic_cache_t *cache,
                                      const ants_semantic_cache_config_t *config);

/*
 * Tear down. Safe on a zeroed (never-initialised) ctx.
 */
ants_error_t ants_semantic_cache_destroy(ants_semantic_cache_t *cache);

/* ------------------------------------------------------------------------ */
/* Insertion (RFC-0002 §The write protocol — local side)                    */
/* ------------------------------------------------------------------------ */

/*
 * Insert a (embedding, value) pair into the local shard. The value
 * bytes are copied into the cache's heap; the caller may free
 * `value` immediately on return.
 *
 * The cache derives the shard key from `embedding` internally
 * (ants_semantic_cache_shard_key); callers writing into the DHT
 * directly may pre-compute the same key and route the entry to
 * the shard-holders themselves.
 *
 * Returns:
 *   ANTS_OK                    — entry stored;
 *   ANTS_ERROR_INVALID_ARG     — NULL args or zero-length value;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold stage.
 */
ants_error_t ants_semantic_cache_put(ants_semantic_cache_t *cache,
                                     const float embedding[ANTS_EMBED_DIM],
                                     const uint8_t *value,
                                     size_t value_len);

/* ------------------------------------------------------------------------ */
/* Lookup (RFC-0002 §The lookup protocol — local side)                      */
/* ------------------------------------------------------------------------ */

/*
 * Look up the most-similar entry in the local shard whose cosine
 * similarity with `embedding` is ≥ `similarity_threshold`.
 *
 * On match:
 *   - copies up to `out_cap` bytes of the matched value into `out_value`;
 *   - sets `*out_len` to the actual size (or required size if buffer
 *     is too small);
 *   - sets `*out_similarity` to the cosine of the match (in [-1, 1]).
 *
 * Returns:
 *   ANTS_OK                       — match found above threshold;
 *   ANTS_ERROR_INVALID_ARG        — NULL args or zero out_cap when
 *                                   out_value is non-NULL;
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap < matched value size;
 *                                   *out_len set to required size;
 *   ANTS_ERROR_NOT_IMPLEMENTED    — scaffold stage.
 *
 * For "no match above threshold" semantics (when the lookup logic
 * lands), this header reserves the ANTS_OK return path for hits
 * only; misses will be signalled by a typed error. The exact code
 * is finalised in the lookup-protocol step.
 */
ants_error_t ants_semantic_cache_get(ants_semantic_cache_t *cache,
                                     const float embedding[ANTS_EMBED_DIM],
                                     float similarity_threshold,
                                     uint8_t *out_value,
                                     size_t out_cap,
                                     size_t *out_len,
                                     float *out_similarity);

/*
 * Look up the top-K matching entries in the local shard above
 * similarity_threshold, sorted descending by cosine similarity.
 *
 * top_k:           0 = unbounded (caller buffer is the only cap)
 * out_matches:     caller buffer for at most cap_matches entries
 * out_embeddings:  contiguous buffer of cap_matches × ANTS_EMBED_DIM
 *                  floats; each match.entry.embedding points into
 *                  out_embeddings[i * ANTS_EMBED_DIM]. The match
 *                  views' response field aliases the cache's internal
 *                  heap copy — valid until the next mutation of the
 *                  cache (put / clear / destroy).
 * *out_n:          set to the number of matches written
 *
 * Limitation in this step: the local store currently persists only
 * (embedding, value-as-response); the other entry fields
 * (embedding_model, prompt_hash, producer, response_model, created,
 * validity_class, attestation, signature) come out zero/empty in
 * the match views. Full-record storage + population lands when the
 * inbound write handler lands (step 7a.2).
 *
 * Returns:
 *   ANTS_OK                     — *out_n matches written;
 *   ANTS_ERROR_NOT_FOUND        — no entries in the local shard
 *                                 above threshold;
 *   ANTS_ERROR_INVALID_ARG      — NULL args; cap_matches > 0 with
 *                                 NULL out_matches or out_embeddings;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — caller buffers held fewer entries
 *                                 than min(top_k, n_eligible);
 *                                 *out_n holds the cap actually used.
 */
ants_error_t ants_semantic_cache_get_topk(ants_semantic_cache_t *cache,
                                          const float embedding[ANTS_EMBED_DIM],
                                          float similarity_threshold,
                                          uint32_t top_k,
                                          ants_semantic_cache_lookup_match_t *out_matches,
                                          float *out_embeddings,
                                          size_t cap_matches,
                                          size_t *out_n);

/* ------------------------------------------------------------------------ */
/* LSH shard-key derivation (RFC-0002 §DHT routing)                         */
/* ------------------------------------------------------------------------ */

/*
 * Compute the 64-bit shard key from an L2-normalised 1024-dim
 * embedding via the protocol's LSH scheme: project onto 64
 * pseudorandom hyperplanes, take the sign-bit of each projection.
 *
 * The projection matrix is part of the protocol spec and fixed
 * once per canonical embedding model version (ants-embed-v1). It
 * is NOT caller-supplied — embedding it as a constant in the
 * implementation is what makes "the same embedding produces the
 * same shard key on every peer" true.
 *
 * Returns:
 *   ANTS_OK                    — *out_key populated;
 *   ANTS_ERROR_INVALID_ARG     — NULL args;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold stage.
 */
ants_error_t ants_semantic_cache_shard_key(const float embedding[ANTS_EMBED_DIM],
                                           ants_semantic_cache_shard_key_t *out_key);

/* ------------------------------------------------------------------------ */
/* Diagnostics                                                              */
/* ------------------------------------------------------------------------ */

/*
 * Total number of entries currently held across all shards. Returns
 * 0 on a NULL or uninitialised ctx; that's a diagnostic accessor,
 * not a hot path, so it never errors.
 */
size_t ants_semantic_cache_entries(const ants_semantic_cache_t *cache);

/*
 * Drop every entry but keep the cache initialised. After clear the
 * ctx is still usable; only entries are freed.
 *
 * Returns:
 *   ANTS_OK                    — cleared (or no-op on empty);
 *   ANTS_ERROR_INVALID_ARG     — NULL ctx;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold stage.
 */
ants_error_t ants_semantic_cache_clear(ants_semantic_cache_t *cache);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_SEMANTIC_CACHE_H */
