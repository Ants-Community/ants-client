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
