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
#include "ants_dht.h"
#include "ants_embed.h"
#include "ants_transport.h"

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

/* Maximum Hamming radius accepted on lookup requests + local top-K
 * scans. RFC-0002 §The lookup protocol bounds the neighbour expansion
 * at 3 bits — three flips give C(64,0)+C(64,1)+C(64,2)+C(64,3) =
 * ~43k addressable shard keys, an envelope wide enough for high-recall
 * semantic search and tight enough that the upper-bound DHT query
 * fan-out stays bounded. Requests / scans with radius > 3 are
 * rejected with ANTS_ERROR_INVALID_ARG. */
#define ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS 3u

/* Decay horizons per RFC-0002 §Quality, decay, and invalidation. Each
 * validity class maps to a useful-lifetime horizon in seconds; lookup
 * scoring downweights entries proportionally to age via the recency
 * factor, and after EVICTION_MULTIPLIER × horizon the entry is
 * excluded from lookup results entirely (still_valid = false).
 * Perennial entries never expire. Values from RFC-0002's reference
 * implementation appendix; changing them is a protocol break. */
#define ANTS_SEMANTIC_CACHE_HORIZON_EPHEMERAL_SEC 300ull      /* 5 minutes */
#define ANTS_SEMANTIC_CACHE_HORIZON_WEEKS_SEC     1200000ull  /* ~14 days */
#define ANTS_SEMANTIC_CACHE_HORIZON_MONTHS_SEC    7000000ull  /* ~81 days */
#define ANTS_SEMANTIC_CACHE_HORIZON_YEARS_SEC     60000000ull /* ~1.9 years */
#define ANTS_SEMANTIC_CACHE_EVICTION_MULTIPLIER   4u

/* Composite lookup-score parameters per RFC-0002 §Quality:
 *   score = similarity · signal_ratio · recency
 *   signal_ratio = (positive_count + 1) / (negative_count + 1)
 *   recency = max(RECENCY_FLOOR, 1.0 - age_sec / RECENCY_DECAY_SEC)
 * The wire-level match.similarity field carries raw cosine
 * similarity (what the threshold filters against); the composite
 * score is local-ranking only. */
#define ANTS_SEMANTIC_CACHE_RECENCY_DECAY_SEC 31500000ull /* 1 year */
#define ANTS_SEMANTIC_CACHE_RECENCY_FLOOR     0.1f

/* Number of independent challenges (re-execution with attestation
 * that yields a substantively different response) needed to
 * invalidate a cache entry per RFC-0002 §Quality. Each challenge
 * advances the entry's challenge_count; on reaching this threshold
 * the entry is marked invalidated and excluded from every future
 * lookup. The producer's reputation downweighting on invalidation
 * is cross-component work (Component #9) and not implemented in
 * v0.x — the local invalidation gate alone closes the cache-side
 * mechanism. */
#define ANTS_SEMANTIC_CACHE_CHALLENGE_INVALIDATION_THRESHOLD 3u

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
 * `buf` MUST be non-NULL and `out_cap` MUST be non-zero. The underlying
 * CBOR encoder does NOT support probe-mode (NULL/0 → INVALID_ARG); to
 * size-probe a record, pass a generously-sized buffer and retry with
 * `realloc(buf, *out_len)` on `BUFFER_TOO_SMALL` (cache_publish.c uses
 * this pattern with an 8 KiB starting cap).
 *
 * Returns:
 *   ANTS_OK                       — *out_len bytes written to buf;
 *   ANTS_ERROR_INVALID_ARG        — NULL args (including NULL buf or
 *                                   zero out_cap), NULL embedding, NULL
 *                                   response with non-zero len, etc.;
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap insufficient; *out_len set
 *                                   to required size, caller may retry
 *                                   with a bigger buffer.
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
/* the shard key, queries the DHT for the responsible peers + the          */
/* Hamming-radius neighbour shards, and sends this request to each         */
/* candidate in parallel. The receiving peer searches its local shard      */
/* (and any neighbour-shard entries it happens to hold) for entries with   */
/* cosine similarity ≥ threshold and returns up to top_k matches.          */
/*                                                                          */
/* Wire format (CBOR map with ascending integer keys 1..4):                */
/*   1 : embedding         bytes(4096)    raw IEEE-754 LE floats           */
/*   2 : threshold         bytes(4)       raw IEEE-754 LE float            */
/*   3 : top_k             uint           0 = unbounded                    */
/*   4 : hamming_radius    uint           0..MAX_HAMMING_RADIUS (3)        */
/*                                                                          */
/* Threshold + embedding use raw byte representation (not CBOR float       */
/* native encoding) for the same canonical-numerics rationale as the       */
/* cache entry record: CBOR's half/single/double "shortest form" choice is */
/* ambiguous, and the protocol pins the binary footprint instead.          */
/*                                                                          */
/* The hamming_radius field lets a consumer trade recall for fan-out: 0   */
/* searches only the exact shard, 1 includes the 64 single-bit-flip        */
/* neighbours, 2 adds ~2k two-flip neighbours, 3 adds ~43k three-flip      */
/* neighbours. Radius > 3 is rejected on encode + decode.                 */
/* ------------------------------------------------------------------------ */

/*
 * Serialise a cache lookup request into a buffer using canonical CBOR.
 *
 * embedding:           ANTS_EMBED_DIM L2-normalised float32 values
 * similarity_threshold: minimum cosine similarity for a match
 * top_k:               max entries the responder should return; 0 means
 *                       the responder picks (typically all matches above
 *                       threshold up to a server-side cap)
 * hamming_radius:      0..ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS; the
 *                       receiver expands its scan to every entry whose
 *                       shard_key is within this Hamming distance of the
 *                       query's shard_key. 0 = exact-shard only.
 *
 * Returns:
 *   ANTS_OK                       — *out_len bytes written;
 *   ANTS_ERROR_INVALID_ARG        — NULL args or
 *                                   hamming_radius > MAX_HAMMING_RADIUS;
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — out_cap < required.
 */
ants_error_t ants_semantic_cache_lookup_request_encode(const float embedding[ANTS_EMBED_DIM],
                                                       float similarity_threshold,
                                                       uint32_t top_k,
                                                       uint32_t hamming_radius,
                                                       uint8_t *buf,
                                                       size_t out_cap,
                                                       size_t *out_len);

/*
 * Parse a cache lookup request from canonical CBOR bytes.
 *
 * embedding_out: caller buffer for ANTS_EMBED_DIM floats; decoder
 *                unpacks the wire's 4096 LE bytes into it.
 * out_threshold / out_top_k / out_hamming_radius: populated from the
 *                decoded fields.
 *
 * Returns:
 *   ANTS_OK             — fields populated;
 *   ANTS_ERROR_INVALID_ARG — NULL args;
 *   ANTS_ERROR_MALFORMED   — CBOR parse error, missing required key,
 *                            wrong type, or trailing bytes;
 *   ANTS_ERROR_NON_CANONICAL — wrong byte length on a fixed-length
 *                              field, non-canonical key order, or
 *                              hamming_radius > MAX_HAMMING_RADIUS.
 */
ants_error_t ants_semantic_cache_lookup_request_decode(const uint8_t *buf,
                                                       size_t len,
                                                       float embedding_out[ANTS_EMBED_DIM],
                                                       float *out_threshold,
                                                       uint32_t *out_top_k,
                                                       uint32_t *out_hamming_radius);

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

/*
 * Optional clock override for deterministic decay testing. Returns the
 * current time in seconds since the Unix epoch (matching the resolution
 * of `ants_semantic_cache_entry_t.created`). NULL on the config falls
 * back to `time(NULL)`. Tests drive deterministic ages by closing over
 * a mutable counter via `ctx`.
 */
typedef uint64_t (*ants_semantic_cache_clock_sec_fn_t)(void *ctx);

typedef struct {
    /* Maximum entries retained per shard before LRU eviction kicks in.
     * 0 = unbounded (subject to total_max). */
    size_t per_shard_max;

    /* Hard cap on total entries across all shards. 0 = no global cap.
     * When both per_shard_max and total_max are 0 the cache grows
     * without bound until ants_semantic_cache_destroy. */
    size_t total_max;

    /* Optional clock override. NULL = default to time(NULL). Used by
     * the decay scoring path (get_topk) and recorded onto entries at
     * challenge time. Tests pass a callback so they can drive entries
     * past their horizon deterministically without sleeping. */
    ants_semantic_cache_clock_sec_fn_t clock_sec_fn;
    void *clock_ctx;
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

/*
 * Insert a full producer-signed cache-entry record (e.g. one
 * received over the DHT write protocol) into the local shard.
 * Every field of `entry` is copied into the cache's heap; the
 * caller may free its `entry` buffers immediately on return.
 *
 * Compared to ants_semantic_cache_put, this persists ALL metadata
 * (embedding_model, prompt_hash, producer, response_model,
 * attestation, signature, created, validity_class) — required for
 * inbound DHT publishes whose responses re-emit the same record
 * to lookup clients.
 *
 * Returns:
 *   ANTS_OK                — entry stored;
 *   ANTS_ERROR_INVALID_ARG — NULL args, NULL embedding, NULL
 *                            embedding_model/response_model, NULL
 *                            response with non-zero len, etc.
 *                            (same validation as the encoder);
 *   ANTS_ERROR_MALFORMED   — malloc failure.
 */
ants_error_t ants_semantic_cache_put_record(ants_semantic_cache_t *cache,
                                            const ants_semantic_cache_entry_t *entry);

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
 * Look up the top-K matching entries above similarity_threshold,
 * sorted descending by composite score (RFC-0002 §Quality):
 *   score = cosine_similarity · signal_ratio · recency
 *   signal_ratio = (positive_count + 1) / (negative_count + 1)
 *   recency = max(RECENCY_FLOOR, 1.0 - age_sec / RECENCY_DECAY_SEC)
 * Entries past 4× their validity_class horizon are excluded entirely
 * (still_valid = false); invalidated entries (challenge_count ≥
 * INVALIDATION_THRESHOLD) are also excluded. The wire-level
 * match.similarity field carries raw cosine similarity (what the
 * caller-side threshold filters against); the composite score is
 * for local ranking only.
 *
 * The candidate set is every entry whose shard_key is within
 * `hamming_radius` bit-flips of the query embedding's shard_key —
 * radius 0 restricts to the exact shard (the step 7a behaviour);
 * radius 1/2/3 widens the search to ~64, ~2k, ~43k addressable
 * shards.
 *
 * top_k:           0 = unbounded (caller buffer is the only cap)
 * hamming_radius:  0..ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS
 * out_matches:     caller buffer for at most cap_matches entries
 * out_embeddings:  contiguous buffer of cap_matches × ANTS_EMBED_DIM
 *                  floats; each match.entry.embedding points into
 *                  out_embeddings[i * ANTS_EMBED_DIM]. The match
 *                  views' response field aliases the cache's internal
 *                  heap copy — valid until the next mutation of the
 *                  cache (put / clear / destroy).
 * *out_n:          set to the number of matches written
 *
 **Note (step 7a.2 onward)**: the local store persists every entry
 * field, and the match views reflect the full record. Pointer fields
 * (embedding_model / response / response_model / attestation) alias
 * the cache's internal heap copies; fixed-length fields (prompt_hash,
 * producer, signature, plus scalars created / validity_class) are
 * copied in. All caveats about validity-on-mutation apply.
 *
 * Returns:
 *   ANTS_OK                     — *out_n matches written;
 *   ANTS_ERROR_NOT_FOUND        — no entries within the hamming
 *                                 envelope above threshold;
 *   ANTS_ERROR_INVALID_ARG      — NULL args; cap_matches > 0 with
 *                                 NULL out_matches or out_embeddings;
 *                                 hamming_radius > MAX_HAMMING_RADIUS;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — caller buffers held fewer entries
 *                                 than min(top_k, n_eligible);
 *                                 *out_n holds the cap actually used.
 */
ants_error_t ants_semantic_cache_get_topk(ants_semantic_cache_t *cache,
                                          const float embedding[ANTS_EMBED_DIM],
                                          float similarity_threshold,
                                          uint32_t top_k,
                                          uint32_t hamming_radius,
                                          ants_semantic_cache_lookup_match_t *out_matches,
                                          float *out_embeddings,
                                          size_t cap_matches,
                                          size_t *out_n);

/* ------------------------------------------------------------------------ */
/* Server-side inbound handlers (RFC-0002 §Write / §Lookup protocols)       */
/*                                                                          */
/* When a peer receives a cache-entry record (write path) or a lookup       */
/* request (read path) on a bidi stream, the transport hands the raw       */
/* CBOR bytes to these handlers. They are pure local operations — no      */
/* network I/O — so they're trivial to test end-to-end against synthetic   */
/* wire payloads. The DHT-routed publish + query paths that drive these   */
/* handlers from the outside land in steps 7b/7c.                          */
/* ------------------------------------------------------------------------ */

/*
 * Handle an inbound cache-entry write: decode the CBOR record per
 * step 4, verify the producer's Ed25519 signature over the canonical
 * signing payload (fields 1..9) BEFORE the record touches the local
 * shard, and — only on a valid signature — persist the full record via
 * put_record. A forged or tampered record is rejected and never stored.
 *
 * Returns:
 *   ANTS_OK                  — entry admitted;
 *   ANTS_ERROR_INVALID_ARG   — NULL args or zero-length buffer;
 *   ANTS_ERROR_MALFORMED     — CBOR parse failure, malloc failure, or
 *                              an invalid producer signature;
 *   ANTS_ERROR_NON_CANONICAL — wrong fixed-length field or wrong
 *                              CBOR ordering on the wire.
 */
ants_error_t ants_semantic_cache_handle_inbound_entry(ants_semantic_cache_t *cache,
                                                      const uint8_t *entry_cbor,
                                                      size_t cbor_len);

/*
 * Handle an inbound cache lookup request: decode the CBOR request
 * per step 5, run a top-K scan over the local shard (capped at
 * 15 entries server-side per RFC-0002 §Lookup), encode the matching
 * results per step 6 into the caller-supplied response buffer.
 *
 * Returns:
 *   ANTS_OK                     — *out_resp_len bytes of encoded
 *                                 response written (zero matches is
 *                                 a valid response);
 *   ANTS_ERROR_INVALID_ARG      — NULL args or zero-length req;
 *   ANTS_ERROR_MALFORMED /
 *   ANTS_ERROR_NON_CANONICAL    — request decode failure;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — resp_cap insufficient.
 */
ants_error_t ants_semantic_cache_handle_inbound_lookup(ants_semantic_cache_t *cache,
                                                       const uint8_t *req_cbor,
                                                       size_t req_len,
                                                       uint8_t *resp_buf,
                                                       size_t resp_cap,
                                                       size_t *out_resp_len);

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

/* ------------------------------------------------------------------------ */
/* Quality signals + challenge invalidation (RFC-0002 §Quality, decay)      */
/*                                                                          */
/* Each shard-holder locally tracks per-entry signals:                      */
/*   - positive_count: feedback that the entry served well                  */
/*   - negative_count: feedback that the entry served poorly                */
/*   - challenge_count: independent re-executions whose result              */
/*     substantively differed from the cached one (per RFC-0002 §Quality   */
/*     §Explicit invalidation by challenge)                                 */
/*                                                                          */
/* The cache uses these locally to bias `get_topk` ranking:                 */
/*   composite_score = sim · (positive+1)/(negative+1) · recency           */
/* The wire-level `match.similarity` carries raw cosine similarity (what   */
/* the threshold filters against); the composite score is local-ranking   */
/* only.                                                                    */
/*                                                                          */
/* On reaching ANTS_SEMANTIC_CACHE_CHALLENGE_INVALIDATION_THRESHOLD = 3     */
/* challenges, the entry is marked invalidated and excluded from every    */
/* future lookup. The producer's reputation downweighting on invalidation  */
/* is cross-component work (Component #9) and is NOT implemented in v0.x — */
/* the local invalidation gate alone closes the cache-side mechanism.      */
/*                                                                          */
/* Signals are NOT on the wire format. Each peer accumulates its own       */
/* view; the network's quality emerges from the aggregate of locally-      */
/* resolved decisions over time per RFC-0002.                              */
/* ------------------------------------------------------------------------ */

/*
 * Record a positive quality signal for the entry identified by
 * (prompt_hash, producer). Increments the entry's positive_count;
 * saturates at UINT32_MAX (no wrap-around).
 *
 * Returns:
 *   ANTS_OK                — entry found, count incremented;
 *   ANTS_ERROR_INVALID_ARG — NULL ctx or NULL key args, or
 *                            uninitialised cache;
 *   ANTS_ERROR_NOT_FOUND   — no entry matches (prompt_hash, producer).
 */
ants_error_t
ants_semantic_cache_record_positive(ants_semantic_cache_t *cache,
                                    const uint8_t prompt_hash[ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN],
                                    const uint8_t producer[ANTS_SEMANTIC_CACHE_PEER_ID_LEN]);

/*
 * Record a negative quality signal for (prompt_hash, producer).
 * Increments negative_count; saturates at UINT32_MAX. Same error
 * semantics as _record_positive.
 */
ants_error_t
ants_semantic_cache_record_negative(ants_semantic_cache_t *cache,
                                    const uint8_t prompt_hash[ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN],
                                    const uint8_t producer[ANTS_SEMANTIC_CACHE_PEER_ID_LEN]);

/*
 * Record a challenge against (prompt_hash, producer). Increments
 * challenge_count and stamps last_challenged_sec with the cache's
 * current clock. On reaching
 * ANTS_SEMANTIC_CACHE_CHALLENGE_INVALIDATION_THRESHOLD, the entry is
 * marked invalidated and will be excluded from every future
 * `get_topk` result. The entry's heap allocations remain until LRU
 * eviction or _clear — invalidation is a soft-delete in v0.x.
 *
 * Returns:
 *   ANTS_OK                — challenge recorded;
 *   ANTS_ERROR_INVALID_ARG — NULL args / uninitialised cache;
 *   ANTS_ERROR_NOT_FOUND   — no matching entry.
 */
ants_error_t
ants_semantic_cache_record_challenge(ants_semantic_cache_t *cache,
                                     const uint8_t prompt_hash[ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN],
                                     const uint8_t producer[ANTS_SEMANTIC_CACHE_PEER_ID_LEN]);

/* ------------------------------------------------------------------------ */
/* Client-side publish (RFC-0002 §The write protocol — DHT-routed)          */
/*                                                                          */
/* A producer-signed cache entry is replicated to N shard-holders selected   */
/* via a DHT lookup on the entry's shard_key. The publish API drives the    */
/* full pipeline:                                                            */
/*                                                                            */
/*   1. Derive shard_key from entry.embedding (LSH);                        */
/*   2. Issue ants_dht_lookup(shard_key) to find responsible peers;         */
/*   3. For each of the top-N peers, dial via transport and open a bidi    */
/*      stream;                                                              */
/*   4. Send the CBOR-encoded entry on each stream with FIN;                */
/*   5. Each peer's ants_semantic_cache_handle_inbound_entry decodes +      */
/*      Ed25519-verifies + persists; clean stream-close from the peer      */
/*      is treated as ack;                                                   */
/*   6. Once every slot is acked-or-failed, the completion callback fires. */
/*                                                                            */
/* The publish_t is caller-allocated and MUST remain valid until either    */
/* the completion callback fires or the caller calls _destroy(). The       */
/* caller is responsible for forwarding DHT + transport events to the      */
/* publish state machine via _handle_dht_event and                          */
/* _handle_transport_event, alongside their forwarding to ants_dht and    */
/* their own logic (the singleton-event-fn pattern documented in           */
/* ants_dht.h). Calls with non-publish events are cheap no-ops.            */
/* ------------------------------------------------------------------------ */

/* Maximum replication factor accepted by _publish_init. Beyond this the
 * DHT lookup result tail is ignored even if the caller requested more. */
#define ANTS_SEMANTIC_CACHE_PUBLISH_MAX_REPLICATION 8u

/* Opaque publish context. Sized to fit:
 *   - 16 KiB embedded ants_dht_lookup_t
 *   - 8 slots × (ants_dht_peer_t + scalars + heap-ptr bookkeeping)
 *   - Bookkeeping (magic, status, callback, heap-pointers for entry CBOR)
 * Headroom is conservative; the .c file pins the exact bound via the
 * compile-time-assertion idiom shared with the rest of the codebase. */
#define ANTS_SEMANTIC_CACHE_PUBLISH_CTX_SIZE 32768

typedef union {
    uint8_t _opaque[ANTS_SEMANTIC_CACHE_PUBLISH_CTX_SIZE];
    uint64_t _align;
} ants_semantic_cache_publish_t;

/*
 * Completion callback. Invoked exactly once, from inside _tick or one of
 * the _handle_* event hooks, on the same thread that drove the state
 * machine forward. After this fires the publish_t is logically done; the
 * caller may safely _destroy it (and reuse the buffer) at any point.
 *
 * status:
 *   ANTS_OK                       — peers_acked ≥ 1; at least one peer
 *                                   acknowledged receipt of the entry;
 *   ANTS_ERROR_PEER_UNREACHABLE   — DHT lookup returned no peers, or
 *                                   every peer failed (dial / handshake /
 *                                   stream reset / connection drop);
 *   ANTS_ERROR_*                  — internal failure (entry encode,
 *                                   shard-key derivation, heap exhaustion).
 *
 * peers_acked: number of peers that received the entry cleanly (FIN
 * observed on the bidi stream). May be 0 < peers_acked < replication
 * when partial publish succeeds.
 */
typedef void (*ants_semantic_cache_publish_complete_fn_t)(ants_error_t status,
                                                          uint32_t peers_acked,
                                                          void *user_ctx);

/*
 * Initialise + start a publish. The entry is encoded to CBOR internally;
 * the caller may free the source entry buffers immediately on return.
 * The publish state machine begins by issuing a DHT lookup on the
 * entry's shard_key.
 *
 * replication_factor: 0 means "use the default
 *   (ANTS_SEMANTIC_CACHE_DEFAULT_REPLICATION)". Values >
 *   ANTS_SEMANTIC_CACHE_PUBLISH_MAX_REPLICATION are rejected.
 *
 * Returns:
 *   ANTS_OK                       — publish queued; completion fires later;
 *   ANTS_ERROR_INVALID_ARG        — NULL args, NULL embedding, bad
 *                                   replication factor, or invalid entry
 *                                   fields (same validation as
 *                                   _entry_encode);
 *   ANTS_ERROR_MALFORMED          — entry encode failed (malloc or
 *                                   internal CBOR error);
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — too many concurrent lookups in the
 *                                   underlying dht for a new one to start.
 */
ants_error_t ants_semantic_cache_publish_init(ants_semantic_cache_publish_t *publish,
                                              ants_dht_t *dht,
                                              ants_transport_t *transport,
                                              const ants_semantic_cache_entry_t *entry,
                                              uint32_t replication_factor,
                                              ants_semantic_cache_publish_complete_fn_t complete_fn,
                                              void *complete_ctx);

/*
 * Drive the publish state machine forward. Should be invoked from the
 * same loop that ticks the transport + dht. The publish issues dial
 * requests from this entry point (event-driven transitions, like
 * STREAM_FIN, are handled from _handle_transport_event).
 *
 * Returns ANTS_OK on success, including the case where the publish is
 * already completed (in which case _tick is a no-op).
 */
ants_error_t ants_semantic_cache_publish_tick(ants_semantic_cache_publish_t *publish);

/*
 * Forward a DHT event to the publish state machine. The publish
 * consumes LOOKUP_COMPLETE / LOOKUP_TIMEOUT events whose `lookup`
 * pointer matches its internal lookup handle; all other events are
 * ignored. Safe to call from inside the caller's dht event_fn.
 */
ants_error_t ants_semantic_cache_publish_handle_dht_event(ants_semantic_cache_publish_t *publish,
                                                          const ants_dht_event_t *event);

/*
 * Forward a transport event to the publish state machine. The publish
 * consumes events whose `conn` or `stream` pointer matches one of its
 * heap-owned per-slot handles; all other events are ignored. Safe to
 * call from inside the caller's transport event_fn.
 */
ants_error_t
ants_semantic_cache_publish_handle_transport_event(ants_semantic_cache_publish_t *publish,
                                                   const ants_transport_event_t *event);

/*
 * Cancel + free a publish. Cancels any in-flight DHT lookup, closes
 * any in-flight streams + connections, frees the encoded entry CBOR.
 * Idempotent: safe on a zeroed (never-initialised) ctx or on a
 * completed publish.
 *
 * No completion callback fires from _destroy — the caller has already
 * elected to stop waiting.
 *
 * MUST NOT be called from inside the publish's own completion callback
 * or from inside an event-forwarding entry point (defer to the next
 * tick).
 */
ants_error_t ants_semantic_cache_publish_destroy(ants_semantic_cache_publish_t *publish);

/* ------------------------------------------------------------------------ */
/* Client-side query (RFC-0002 §The lookup protocol — DHT-routed)           */
/*                                                                          */
/* A consumer with an embedding asks the network for entries with cosine    */
/* similarity ≥ threshold. The query API drives the full pipeline:          */
/*                                                                          */
/*   1. Derive shard_key from the query embedding (LSH);                    */
/*   2. Issue ants_dht_lookup(shard_key) to find responsible peers;         */
/*   3. For each of the top-N (fanout) peers, dial via transport, open a    */
/*      bidi stream, and send a CBOR-encoded lookup_request with FIN;       */
/*   4. Each peer's cache_server runs handle_inbound_lookup and returns a   */
/*      lookup_response (up to HANDLE_LOOKUP_SERVER_CAP=15 matches) with    */
/*      FIN;                                                                */
/*   5. Accumulate per-slot recv buffers, decode each response, aggregate   */
/*      across all peers (dedup by producer+prompt_hash, sort desc by       */
/*      similarity, cap at min(cap_matches, top_k));                        */
/*   6. Copy aggregated matches into the caller's out_matches buffer        */
/*      (entry.embedding floats deep-copied into out_embeddings; other      */
/*      pointer fields alias into per-slot recv buffers that stay alive     */
/*      until _destroy()); fire the completion callback with the count.    */
/*                                                                          */
/* Memory lifetime: out_matches[i].entry.embedding points into the caller-  */
/* owned out_embeddings buffer (safe past _destroy). All other pointer     */
/* fields (response, embedding_model, response_model, attestation) ALIAS    */
/* into query-owned recv buffers and BECOME INVALID after _destroy. The     */
/* caller MUST finish reading aggregated matches before calling _destroy.   */
/*                                                                          */
/* The query_t is caller-allocated; MUST be destroyed BEFORE the underlying */
/* transport — same convention as publish, dht bootstrap_entries, and       */
/* dht pending_dials. */
/* ------------------------------------------------------------------------ */

/* Maximum query fanout. Bounds the DHT lookup tail and the per-query heap */
/* footprint. 8 matches publish's MAX_REPLICATION; the two layers use      */
/* the same upper envelope so a single transport+dht can host both. */
#define ANTS_SEMANTIC_CACHE_QUERY_MAX_FANOUT 8u

/* Default query fanout when caller passes 0. Mirrors the write-protocol    */
/* default replication factor — three shard-holders is the typical lookup   */
/* breadth too. */
#define ANTS_SEMANTIC_CACHE_QUERY_DEFAULT_FANOUT 3u

/* Opaque query context. Sized to fit:
 *   - 16 KiB embedded ants_dht_lookup_t
 *   - 8 slots × (ants_dht_peer_t + scalars + heap-ptr bookkeeping)
 *   - Bookkeeping (magic, phase, callback, heap-pointers for request CBOR
 *     and caller-buffer aliases)
 * Headroom is conservative; the .c file pins the exact bound via the
 * compile-time-assertion idiom shared with the rest of the codebase. */
#define ANTS_SEMANTIC_CACHE_QUERY_CTX_SIZE 32768

typedef union {
    uint8_t _opaque[ANTS_SEMANTIC_CACHE_QUERY_CTX_SIZE];
    uint64_t _align;
} ants_semantic_cache_query_t;

/*
 * Completion callback. Invoked exactly once, from inside _tick or one of
 * the _handle_* event hooks, on the same thread that drove the state
 * machine forward. After this fires the caller's out_matches buffer holds
 * the aggregated result (first n_matches entries valid). The query_t is
 * logically done; the caller may safely _destroy it (and reuse the buffer)
 * at any point AFTER reading out_matches.
 *
 * status:
 *   ANTS_OK                       — at least one peer responded; out_matches
 *                                   holds n_matches aggregated entries
 *                                   (n_matches MAY be 0 if peers responded
 *                                   with empty match lists — that is a
 *                                   legitimate "cache miss above threshold"
 *                                   result, not a failure);
 *   ANTS_ERROR_PEER_UNREACHABLE   — DHT lookup returned no peers, or every
 *                                   peer failed (dial / handshake / stream
 *                                   reset / connection drop / decode error);
 *   ANTS_ERROR_*                  — internal failure (request encode,
 *                                   shard-key derivation, heap exhaustion).
 *
 * peers_responded: number of peers that returned a decodable response
 * (regardless of how many matches each one had). May be 0 < responded <
 * fanout when partial query succeeds.
 *
 * n_matches: number of entries written into out_matches (0 ≤ n_matches ≤
 * min(cap_matches, top_k>0?top_k:∞)).
 */
typedef void (*ants_semantic_cache_query_complete_fn_t)(ants_error_t status,
                                                        uint32_t peers_responded,
                                                        size_t n_matches,
                                                        void *user_ctx);

/*
 * Initialise + start a query.
 *
 * The query takes the consumer's embedding, derives the LSH shard_key,
 * issues a DHT lookup, and fans the encoded lookup_request out to the
 * top `fanout` peers in parallel. Each peer responds with up to
 * HANDLE_LOOKUP_SERVER_CAP matches; the query aggregates across peers and
 * writes the top-K into the caller's buffers before firing complete_fn.
 *
 * embedding:           ANTS_EMBED_DIM L2-normalised float32 values
 * similarity_threshold: minimum cosine similarity for a match (forwarded
 *                       to each peer in the lookup_request)
 * top_k:               0 = unbounded (cap_matches is the only limit);
 *                       otherwise the aggregator returns at most top_k
 * hamming_radius:      0..ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS (3)
 * fanout:              0 = use ANTS_SEMANTIC_CACHE_QUERY_DEFAULT_FANOUT;
 *                       > MAX_FANOUT rejected
 * out_matches:         caller buffer for at most cap_matches matches
 * out_embeddings:      contiguous buffer of cap_matches × ANTS_EMBED_DIM
 *                       floats; each match.entry.embedding points into
 *                       out_embeddings[i * ANTS_EMBED_DIM] after completion
 * cap_matches:         capacity of both caller buffers (MUST be > 0)
 *
 * Returns:
 *   ANTS_OK                       — query queued; completion fires later;
 *   ANTS_ERROR_INVALID_ARG        — NULL args, NULL embedding, cap_matches
 *                                   == 0, fanout > MAX_FANOUT,
 *                                   hamming_radius > MAX_HAMMING_RADIUS;
 *   ANTS_ERROR_MALFORMED          — request encode failed (heap exhaustion
 *                                   or internal CBOR error);
 *   ANTS_ERROR_BUFFER_TOO_SMALL   — too many concurrent lookups in the
 *                                   underlying dht for a new one to start.
 */
ants_error_t ants_semantic_cache_query_init(ants_semantic_cache_query_t *query,
                                            ants_dht_t *dht,
                                            ants_transport_t *transport,
                                            const float embedding[ANTS_EMBED_DIM],
                                            float similarity_threshold,
                                            uint32_t top_k,
                                            uint32_t hamming_radius,
                                            uint32_t fanout,
                                            ants_semantic_cache_lookup_match_t *out_matches,
                                            float *out_embeddings,
                                            size_t cap_matches,
                                            ants_semantic_cache_query_complete_fn_t complete_fn,
                                            void *complete_ctx);

/*
 * Drive the query state machine forward. Should be invoked from the same
 * loop that ticks the transport + dht. Issues dial requests after the
 * DHT lookup completes; event-driven transitions (CONN_READY, STREAM_FIN,
 * etc.) are handled from _handle_transport_event.
 *
 * Returns ANTS_OK on success, including no-op cases for already-completed
 * queries or zeroed ctxs.
 */
ants_error_t ants_semantic_cache_query_tick(ants_semantic_cache_query_t *query);

/*
 * Forward a DHT event to the query state machine. The query consumes
 * LOOKUP_COMPLETE / LOOKUP_TIMEOUT events whose `lookup` pointer matches
 * its internal lookup handle; all other events are ignored. Safe to call
 * from inside the caller's dht event_fn.
 */
ants_error_t ants_semantic_cache_query_handle_dht_event(ants_semantic_cache_query_t *query,
                                                        const ants_dht_event_t *event);

/*
 * Forward a transport event to the query state machine. The query
 * consumes events whose `conn` or `stream` pointer matches one of its
 * heap-owned per-slot handles; all other events are ignored. Safe to
 * call from inside the caller's transport event_fn.
 */
ants_error_t ants_semantic_cache_query_handle_transport_event(ants_semantic_cache_query_t *query,
                                                              const ants_transport_event_t *event);

/*
 * Cancel + free a query. Cancels any in-flight DHT lookup, closes any
 * in-flight streams + connections, frees the encoded request CBOR + all
 * per-slot recv/decoded heaps. Idempotent: safe on a zeroed (never-
 * initialised) ctx or on a completed query.
 *
 * After _destroy fires the caller's out_matches aliased pointer fields
 * (response, embedding_model, response_model, attestation) BECOME
 * INVALID — only entry.embedding (which points into the caller-owned
 * out_embeddings) remains usable. Read the matches BEFORE _destroy.
 *
 * No completion callback fires from _destroy — the caller has already
 * elected to stop waiting.
 *
 * MUST NOT be called from inside the query's own completion callback
 * or from inside an event-forwarding entry point (defer to the next
 * tick).
 */
ants_error_t ants_semantic_cache_query_destroy(ants_semantic_cache_query_t *query);

/* ------------------------------------------------------------------------ */
/* Server-side stream dispatch (RFC-0002 §Write protocol, §Lookup protocol) */
/*                                                                          */
/* The publish + query sides (steps 7b/7c) replicate or fetch records over  */
/* bidi transport streams. The receiving peer needs to recognise inbound    */
/* cache streams, accumulate the request, decode it as either an entry      */
/* write or a lookup query, dispatch to handle_inbound_entry /              */
/* handle_inbound_lookup, and reply on the same stream.                     */
/*                                                                          */
/* The cache_server_t holds an inbound-stream registry parallel to (but     */
/* independent of) the DHT server's. The caller forwards every transport    */
/* event to BOTH dispatchers: ants_dht_handle_transport_event runs first,   */
/* releases its slot silently if peek_type fails (DHT envelopes start with  */
/* a map of size 2 or 3 with key 0; cache messages don't match), and the    */
/* cache server's dispatcher then claims the stream by map size — 10 for    */
/* an entry write (map(9) without signature is only the signing payload     */
/* form; the on-wire record carries the signature so the top-level map      */
/* size is 10), 4 for a lookup request.                                     */
/*                                                                          */
/* The server emits the lookup response on the same stream with FIN; for    */
/* entry writes, it sends an empty FIN as ack so the publish-side state    */
/* machine sees STREAM_FIN and marks the slot ACKED.                        */
/*                                                                          */
/* The cache_server_t is caller-allocated; MUST be destroyed BEFORE the     */
/* underlying transport (server slots reference transport-owned stream     */
/* pointers that the transport itself cleans up on CONN_CLOSED).           */
/* ------------------------------------------------------------------------ */

/* Maximum concurrent inbound cache streams a server tracks. Streams      */
/* opened past this cap are dropped (no slot allocated) and the request    */
/* never decodes — the sender's publish observes a transport-level close   */
/* without ACK and counts it as a failed slot. */
#define ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS 16u

/* Per-stream recv buffer cap. The largest legitimate inbound message is  */
/* an entry write: 4 KiB embedding + producer/signature/prompt-hash (~96  */
/* bytes) + response text (up to a few KiB) + model strings + scalars.    */
/* 16 KiB covers realistic protocol traffic with headroom; oversized      */
/* payloads release the slot silently and the stream is left to the       */
/* transport's natural close. */
#define ANTS_SEMANTIC_CACHE_SERVER_INBOUND_RECV_CAP (16u * 1024u)

/* Opaque cache-server context. Sized to fit:
 *   - magic + cache* + padding
 *   - inbound_streams[MAX] array (in_use + conn + stream + recv_buf* + lens)
 * 4 KiB is generous (16 slots × ~64 bytes ≈ 1 KiB; rest is headroom). */
#define ANTS_SEMANTIC_CACHE_SERVER_CTX_SIZE 4096u

typedef union {
    uint8_t _opaque[ANTS_SEMANTIC_CACHE_SERVER_CTX_SIZE];
    uint64_t _align;
} ants_semantic_cache_server_t;

/*
 * Initialise a cache server bound to `cache`. The server holds a
 * non-owning pointer to the cache — the cache MUST outlive the server.
 *
 * Returns:
 *   ANTS_OK                — server ready;
 *   ANTS_ERROR_INVALID_ARG — NULL args.
 */
ants_error_t ants_semantic_cache_server_init(ants_semantic_cache_server_t *server,
                                             ants_semantic_cache_t *cache);

/*
 * Forward a transport event to the cache server. The server inspects
 * the event's stream/conn pointers against its inbound registry and
 * takes no action on foreign events (so it can run in the same event-
 * dispatch chain as ants_dht_handle_transport_event and any publish
 * state machines).
 *
 * Returns ANTS_OK on success, including no-op cases for foreign events
 * or zeroed (never-init) ctxs. ANTS_ERROR_INVALID_ARG on NULL args.
 */
ants_error_t ants_semantic_cache_server_handle_transport_event(ants_semantic_cache_server_t *server,
                                                               const ants_transport_event_t *event);

/*
 * Release all slots + recv buffers held by the server. Idempotent.
 * MUST be called BEFORE destroying the underlying transport (the
 * transport's CONN_CLOSED callback would otherwise fire after the
 * server's slots are gone and attempt to release them again).
 */
ants_error_t ants_semantic_cache_server_destroy(ants_semantic_cache_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_SEMANTIC_CACHE_H */
