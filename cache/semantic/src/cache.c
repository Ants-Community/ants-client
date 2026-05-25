/*
 * cache.c — Semantic cache (Component #10).
 *
 * Step 3 (this PR): LRU eviction now enforces the per_shard_max +
 * total_max caps from ants_semantic_cache_config_t. Remaining steps:
 * DHT-routed write protocol (4), DHT-routed lookup with Hamming-
 * neighbour expansion (5), quality-signal aggregation + challenge
 * invalidation (6). Decay by validity class — also part of RFC-0002
 * §Quality — composes with the eviction logic in step 6.
 *
 * Storage layout:
 *   - state.entries is a flat heap array of cache_entry_t, grown
 *     geometrically on put.
 *   - Each entry holds the L2-normalised embedding (4 KB) + a copy
 *     of the value bytes + the precomputed shard key + a monotonic
 *     last_access counter set on every put and every get hit.
 *   - Lookup is a linear scan filtered by shard_key, ranked by cosine
 *     similarity (dot product on the already-normalised vectors).
 *   - Eviction picks the entry with the smallest last_access and
 *     swap-with-last-removes it (O(1) once the LRU is identified;
 *     the find itself is O(n) or O(n_in_shard)).
 *
 * Cap semantics:
 *   - total_max  = 0 → unbounded across all shards.
 *   - per_shard_max = 0 → unbounded within any single shard.
 *   - Both caps are pre-insert: when a put would push n_entries past
 *     total_max OR the shard's count past per_shard_max, the LRU
 *     candidate is evicted FIRST and the new entry takes its slot.
 *   - Order: total_max check first (may incidentally free a slot in
 *     the shard); then per_shard_max check.
 */

#include "ants_semantic_cache.h"

#include "ants_crypto.h"

#include <math.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* M_PI is gated behind _BSD_SOURCE / _XOPEN_SOURCE on some libcs.
 * Always define our own to keep the project's strict C99 + no-extensions
 * discipline intact. */
#ifndef ANTS_M_PI
#define ANTS_M_PI 3.14159265358979323846
#endif

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* The shard-key projection matrix is a process-global constant (not a     */
/* per-cache resource) so it lives in static storage outside this struct.  */
/* The per-instance state holds the entry store + caps + LRU counter.     */
/* ------------------------------------------------------------------------ */

/* Magic ("CNCS" = Cache, semaNtic) distinguishes a fully-init state from
 * a zeroed (never-init) ctx so the public destroy/get/put entry points
 * can detect uninitialised callers without crashing. Same pattern as
 * ants_embed_state ("ANSE") and ants_transport_state ("ANTS"). */
#define ANTS_SEMANTIC_CACHE_STATE_MAGIC 0x434E4353u

#define INITIAL_ENTRY_CAPACITY          16

typedef struct {
    /* Precomputed shard key for this entry's embedding. Cached so
     * lookups don't re-project at scan time. */
    ants_semantic_cache_shard_key_t shard_key;

    /* L2-normalised embedding (4 KB). Stored inline so the lookup
     * dot-product is one contiguous read per entry. */
    float embedding[ANTS_EMBED_DIM];

    /* Heap-allocated copy of the caller's value bytes. Owned by the
     * cache, freed on destroy / clear / future LRU eviction. */
    uint8_t *value;
    size_t value_len;

    /* Monotonic LRU counter set on each put and on each get hit.
     * Unused in step 2; step 3 reads it for eviction. */
    uint64_t last_access;
} cache_entry_t;

struct ants_semantic_cache_state {
    uint32_t magic;
    uint8_t _pad[4];

    /* Config caps mirrored from ants_semantic_cache_config_t.
     * Advisory in step 2; step 3 enforces via LRU eviction. */
    size_t per_shard_max;
    size_t total_max;

    /* Flat entry array; grown geometrically on put. */
    cache_entry_t *entries;
    size_t n_entries;
    size_t cap_entries;

    /* Monotonic counter; advanced on every put + on every get hit.
     * Used by step 3 to identify the eviction candidate. */
    uint64_t lru_counter;
};

typedef char ants_semantic_cache_state_size_check[(sizeof(struct ants_semantic_cache_state) <=
                                                   sizeof(((ants_semantic_cache_t *)0)->_opaque))
                                                      ? 1
                                                      : -1];

/* ------------------------------------------------------------------------ */
/* LSH projection matrix                                                    */
/*                                                                          */
/* RFC-0002 §DHT routing: each embedding is projected onto 64 pseudorandom */
/* hyperplanes; the sign of each projection forms one bit of the shard key.*/
/* The projection matrix is part of the protocol spec and must be          */
/* identical on every conformant peer, so we derive it deterministically  */
/* from a fixed BLAKE3-hashed seed label rather than embedding a binary   */
/* blob. The result is a 64 × 1024 array of Gaussian(0, 1) floats         */
/* generated via Box-Muller from BLAKE3-derived uniform u32s.             */
/*                                                                          */
/* Layout: row-major, hyperplane-first. g_projection[j * 1024 + i] is the */
/* coefficient of dimension i for hyperplane j. Reading consecutively      */
/* during a dot-product sweep is the cache-friendly order.                 */
/* ------------------------------------------------------------------------ */

static float g_projection[ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS * ANTS_EMBED_DIM];

/* Lazy init state. 0 = uninit, 1 = currently initing, 2 = ready.
 * Acquire/release ordering makes the written matrix visible to readers
 * the moment the writer publishes state == 2. */
static atomic_int g_projection_state = 0;

/* Read a little-endian uint32 from a byte buffer (any alignment). */
static uint32_t le_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Box-Muller transform: a pair of independent uniforms over [0, 1) ×
 * [0, 1) yields a Gaussian(0, 1). We only consume the cos() branch;
 * the sin() pair would double output per pair of inputs but costs an
 * extra static counter / book-keeping, and at 16K BLAKE3 calls the
 * init runs in single-digit ms regardless. */
static float box_muller_one(uint32_t u32_0, uint32_t u32_1)
{
    /* Map u32_0 to (0, 1] so log() never sees 0. Adding 1 then dividing
     * by 2^32 + 1 keeps the value strictly positive for every u32_0. */
    double u = ((double)u32_0 + 1.0) / 4294967297.0;
    double v = (double)u32_1 / 4294967296.0;
    double r = sqrt(-2.0 * log(u));
    double theta = 2.0 * ANTS_M_PI * v;
    return (float)(r * cos(theta));
}

/* Fill g_projection deterministically from BLAKE3-derived bytes.
 *
 * Algorithm:
 *   seed = BLAKE3("ants-semantic-cache/v1/projection-matrix")
 *   for chunk_idx in 0..16383:
 *     bytes = BLAKE3(seed || chunk_idx_LE32)        (32 bytes)
 *     for g in 0..3:
 *       g_projection[chunk_idx * 4 + g] =
 *           box_muller(LE_u32(bytes[g*8..]), LE_u32(bytes[g*8+4..]))
 *
 * 16384 BLAKE3 calls × 4 Gaussians per call = 65536 Gaussians, which
 * is exactly 64 × 1024 — the projection matrix. */
/* File-scope compile-time sanity for the populate_projection() chunk
 * loop. Lifted out of function scope to avoid clang's
 * -Wunused-local-typedef noise. */
typedef char ants_lsh_projection_divides_check
    [((ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS * ANTS_EMBED_DIM) % (ANTS_BLAKE3_HASH_SIZE / 8) == 0)
         ? 1
         : -1];

static void populate_projection(void)
{
    static const uint8_t SEED_LABEL[] = "ants-semantic-cache/v1/projection-matrix";
    enum {
        TOTAL_GAUSSIANS = ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS * ANTS_EMBED_DIM,
        BYTES_PER_GAUSSIAN = 8,
        GAUSSIANS_PER_CHUNK = ANTS_BLAKE3_HASH_SIZE / BYTES_PER_GAUSSIAN,
        CHUNK_COUNT = TOTAL_GAUSSIANS / GAUSSIANS_PER_CHUNK
    };

    uint8_t seed[ANTS_BLAKE3_HASH_SIZE];
    (void)ants_blake3_hash(SEED_LABEL, sizeof SEED_LABEL - 1, seed);

    uint8_t input[ANTS_BLAKE3_HASH_SIZE + 4];
    memcpy(input, seed, ANTS_BLAKE3_HASH_SIZE);

    for (uint32_t chunk_idx = 0; chunk_idx < (uint32_t)CHUNK_COUNT; chunk_idx++) {
        input[ANTS_BLAKE3_HASH_SIZE + 0] = (uint8_t)(chunk_idx & 0xFFu);
        input[ANTS_BLAKE3_HASH_SIZE + 1] = (uint8_t)((chunk_idx >> 8) & 0xFFu);
        input[ANTS_BLAKE3_HASH_SIZE + 2] = (uint8_t)((chunk_idx >> 16) & 0xFFu);
        input[ANTS_BLAKE3_HASH_SIZE + 3] = (uint8_t)((chunk_idx >> 24) & 0xFFu);

        uint8_t bytes[ANTS_BLAKE3_HASH_SIZE];
        (void)ants_blake3_hash(input, sizeof input, bytes);

        for (uint32_t g = 0; g < (uint32_t)GAUSSIANS_PER_CHUNK; g++) {
            uint32_t u0 = le_u32(&bytes[g * BYTES_PER_GAUSSIAN]);
            uint32_t u1 = le_u32(&bytes[g * BYTES_PER_GAUSSIAN + 4]);
            size_t pos = (size_t)chunk_idx * (size_t)GAUSSIANS_PER_CHUNK + (size_t)g;
            g_projection[pos] = box_muller_one(u0, u1);
        }
    }
}

/* Double-checked-locking-style guard for the projection matrix.
 *
 * The fast path (state == 2) is a single acquire-load. The slow path
 * CAS-claims the right to initialise; whoever loses the CAS spins on
 * acquire-loads until the winner publishes state = 2 with a release
 * store. populate_projection() runs in single-digit milliseconds, so
 * the spin window is short. */
static void ensure_projection_initialised(void)
{
    int state = atomic_load_explicit(&g_projection_state, memory_order_acquire);
    if (state == 2) {
        return;
    }
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &g_projection_state, &expected, 1, memory_order_acq_rel, memory_order_acquire)) {
        populate_projection();
        atomic_store_explicit(&g_projection_state, 2, memory_order_release);
        return;
    }
    while (atomic_load_explicit(&g_projection_state, memory_order_acquire) != 2) {
        /* spin */
    }
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

static void free_all_entries(struct ants_semantic_cache_state *state)
{
    for (size_t i = 0; i < state->n_entries; i++) {
        free(state->entries[i].value);
        state->entries[i].value = NULL;
    }
    state->n_entries = 0;
}

/* ------------------------------------------------------------------------ */
/* LRU eviction                                                             */
/* ------------------------------------------------------------------------ */

/* Count entries whose shard_key matches `key`. O(n_entries) linear scan;
 * step 5 will swap this for a hash-table bucket index. */
static size_t count_in_shard(const struct ants_semantic_cache_state *state,
                             ants_semantic_cache_shard_key_t key)
{
    size_t count = 0;
    for (size_t i = 0; i < state->n_entries; i++) {
        if (state->entries[i].shard_key == key) {
            count++;
        }
    }
    return count;
}

/* Find the entry with the smallest last_access. When `filter_by_shard`
 * is true, only entries with shard_key == `key` are considered.
 * Returns true and sets *out_idx on success, false if no matching
 * entry exists (e.g. shard empty). */
static bool find_lru(const struct ants_semantic_cache_state *state,
                     bool filter_by_shard,
                     ants_semantic_cache_shard_key_t key,
                     size_t *out_idx)
{
    uint64_t min_access = UINT64_MAX;
    size_t min_idx = 0;
    bool found = false;
    for (size_t i = 0; i < state->n_entries; i++) {
        if (filter_by_shard && state->entries[i].shard_key != key) {
            continue;
        }
        if (state->entries[i].last_access < min_access) {
            min_access = state->entries[i].last_access;
            min_idx = i;
            found = true;
        }
    }
    if (found) {
        *out_idx = min_idx;
    }
    return found;
}

/* Free the entry at `idx` and swap the last entry into its slot.
 * O(1); the entries[] order is internal so the swap is fine. */
static void evict_at(struct ants_semantic_cache_state *state, size_t idx)
{
    free(state->entries[idx].value);
    state->entries[idx].value = NULL;
    size_t last = state->n_entries - 1;
    if (idx != last) {
        state->entries[idx] = state->entries[last];
    }
    memset(&state->entries[last], 0, sizeof state->entries[last]);
    state->n_entries--;
}

/* Pre-insert cap enforcement. Called by put() right before appending
 * a new entry for shard_key `key`. Evicts the global LRU if total_max
 * would be exceeded, then the shard LRU if per_shard_max would. */
static void enforce_caps_on_insert(struct ants_semantic_cache_state *state,
                                   ants_semantic_cache_shard_key_t key)
{
    if (state->total_max > 0 && state->n_entries >= state->total_max) {
        size_t idx = 0;
        if (find_lru(state, false, 0, &idx)) {
            evict_at(state, idx);
        }
    }
    if (state->per_shard_max > 0) {
        size_t shard_count = count_in_shard(state, key);
        if (shard_count >= state->per_shard_max) {
            size_t idx = 0;
            if (find_lru(state, true, key, &idx)) {
                evict_at(state, idx);
            }
        }
    }
}

ants_error_t ants_semantic_cache_init(ants_semantic_cache_t *cache,
                                      const ants_semantic_cache_config_t *config)
{
    if (cache == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    memset(cache->_opaque, 0, sizeof cache->_opaque);
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;

    state->entries = (cache_entry_t *)calloc(INITIAL_ENTRY_CAPACITY, sizeof(cache_entry_t));
    if (state->entries == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    state->cap_entries = INITIAL_ENTRY_CAPACITY;
    state->n_entries = 0;
    state->per_shard_max = config->per_shard_max;
    state->total_max = config->total_max;
    state->lru_counter = 0;
    state->magic = ANTS_SEMANTIC_CACHE_STATE_MAGIC;
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_destroy(ants_semantic_cache_t *cache)
{
    if (cache == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;
    if (state->magic == ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        free_all_entries(state);
        free(state->entries);
        state->entries = NULL;
    }
    memset(cache->_opaque, 0, sizeof cache->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Put / Get                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_put(ants_semantic_cache_t *cache,
                                     const float embedding[ANTS_EMBED_DIM],
                                     const uint8_t *value,
                                     size_t value_len)
{
    if (cache == NULL || embedding == NULL || value == NULL || value_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;
    if (state->magic != ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }

    ants_semantic_cache_shard_key_t key = 0;
    ants_error_t err = ants_semantic_cache_shard_key(embedding, &key);
    if (err != ANTS_OK) {
        return err;
    }

    /* Enforce caps BEFORE growth + insert: an eviction here may free
     * a slot that would otherwise push the array past its capacity.
     * Order: total_max first (the global cap may incidentally free a
     * slot in this shard), then per_shard_max. */
    enforce_caps_on_insert(state, key);

    /* Geometric growth of the flat entry array. */
    if (state->n_entries == state->cap_entries) {
        size_t new_cap = state->cap_entries * 2u;
        cache_entry_t *grown =
            (cache_entry_t *)realloc(state->entries, new_cap * sizeof(cache_entry_t));
        if (grown == NULL) {
            return ANTS_ERROR_MALFORMED;
        }
        /* Zero the new slots so a partial-write failure below leaves
         * deterministic state. */
        memset(
            &grown[state->cap_entries], 0, (new_cap - state->cap_entries) * sizeof(cache_entry_t));
        state->entries = grown;
        state->cap_entries = new_cap;
    }

    cache_entry_t *slot = &state->entries[state->n_entries];
    uint8_t *copy = (uint8_t *)malloc(value_len);
    if (copy == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(copy, value, value_len);

    slot->shard_key = key;
    memcpy(slot->embedding, embedding, ANTS_EMBED_DIM * sizeof(float));
    slot->value = copy;
    slot->value_len = value_len;
    slot->last_access = ++state->lru_counter;
    state->n_entries++;
    return ANTS_OK;
}

/* Cosine similarity for two L2-normalised vectors reduces to a dot
 * product. Accumulated in double for the 1024-term sum — same
 * discipline as the LSH dot-product reduction. */
static double cosine_l2_normalised(const float *a, const float *b)
{
    double dot = 0.0;
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        dot += (double)a[i] * (double)b[i];
    }
    return dot;
}

ants_error_t ants_semantic_cache_get(ants_semantic_cache_t *cache,
                                     const float embedding[ANTS_EMBED_DIM],
                                     float similarity_threshold,
                                     uint8_t *out_value,
                                     size_t out_cap,
                                     size_t *out_len,
                                     float *out_similarity)
{
    if (cache == NULL || embedding == NULL || out_len == NULL || out_similarity == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (out_value != NULL && out_cap == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;
    if (state->magic != ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }

    ants_semantic_cache_shard_key_t key = 0;
    ants_error_t err = ants_semantic_cache_shard_key(embedding, &key);
    if (err != ANTS_OK) {
        return err;
    }

    /* Linear scan over the entries array, filtered by matching shard
     * key. The bucket count per shard is small in practice (RFC-0002's
     * LSH puts only semantically-similar entries together); step 5
     * will add a hash-table bucket index when the entry count grows. */
    size_t best_idx = 0;
    bool best_found = false;
    double best_sim = -2.0; /* below the [-1, 1] cosine range */
    for (size_t i = 0; i < state->n_entries; i++) {
        if (state->entries[i].shard_key != key) {
            continue;
        }
        double sim = cosine_l2_normalised(state->entries[i].embedding, embedding);
        if (sim > best_sim) {
            best_sim = sim;
            best_idx = i;
            best_found = true;
        }
    }

    if (!best_found || best_sim < (double)similarity_threshold) {
        return ANTS_ERROR_NOT_FOUND;
    }

    cache_entry_t *hit = &state->entries[best_idx];
    *out_similarity = (float)best_sim;
    hit->last_access = ++state->lru_counter;

    if (hit->value_len > out_cap) {
        *out_len = hit->value_len;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (out_value != NULL) {
        memcpy(out_value, hit->value, hit->value_len);
    }
    *out_len = hit->value_len;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Top-K lookup                                                             */
/*                                                                          */
/* Linear scan filtered by shard_key, collect every entry above the         */
/* threshold into a stack-resident candidate array (capped at               */
/* TOPK_MAX_CANDIDATES for safety), insertion-sort by similarity desc,      */
/* then emit min(top_k, cap_matches, n_candidates) matches into the         */
/* caller buffers. *out_n is always set to min(top_k, n_candidates) —      */
/* i.e. the size the caller would need to receive every eligible match —   */
/* so BUFFER_TOO_SMALL can drive a retry with a bigger buffer.              */
/* ------------------------------------------------------------------------ */

#define TOPK_MAX_CANDIDATES 256u

typedef struct {
    size_t entry_idx;
    double similarity;
} topk_candidate_t;

ants_error_t ants_semantic_cache_get_topk(ants_semantic_cache_t *cache,
                                          const float embedding[ANTS_EMBED_DIM],
                                          float similarity_threshold,
                                          uint32_t top_k,
                                          ants_semantic_cache_lookup_match_t *out_matches,
                                          float *out_embeddings,
                                          size_t cap_matches,
                                          size_t *out_n)
{
    if (cache == NULL || embedding == NULL || out_n == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (cap_matches > 0 && (out_matches == NULL || out_embeddings == NULL)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;
    if (state->magic != ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_n = 0;

    ants_semantic_cache_shard_key_t key = 0;
    ants_error_t err = ants_semantic_cache_shard_key(embedding, &key);
    if (err != ANTS_OK) {
        return err;
    }

    /* Collect eligible candidates. */
    topk_candidate_t cands[TOPK_MAX_CANDIDATES];
    size_t n_cands = 0;
    for (size_t i = 0; i < state->n_entries; i++) {
        if (state->entries[i].shard_key != key) {
            continue;
        }
        double sim = cosine_l2_normalised(state->entries[i].embedding, embedding);
        if (sim < (double)similarity_threshold) {
            continue;
        }
        if (n_cands >= TOPK_MAX_CANDIDATES) {
            /* In practice this overflow is unreachable for any plausible
             * shard size; if a future regime makes it reachable we'll
             * promote cands[] to a heap allocation. */
            break;
        }
        cands[n_cands].entry_idx = i;
        cands[n_cands].similarity = sim;
        n_cands++;
    }

    if (n_cands == 0) {
        return ANTS_ERROR_NOT_FOUND;
    }

    /* Insertion-sort desc by similarity. n_cands is bounded by
     * TOPK_MAX_CANDIDATES so O(n²) is fine. */
    for (size_t i = 1; i < n_cands; i++) {
        topk_candidate_t pivot = cands[i];
        size_t j = i;
        while (j > 0 && cands[j - 1].similarity < pivot.similarity) {
            cands[j] = cands[j - 1];
            j--;
        }
        cands[j] = pivot;
    }

    /* Effective output size: cap by top_k (if non-zero) and by n_cands. */
    size_t effective_n = n_cands;
    if (top_k > 0 && (size_t)top_k < effective_n) {
        effective_n = (size_t)top_k;
    }
    *out_n = effective_n;

    /* Write up to cap_matches into the caller buffers. */
    size_t to_emit = (cap_matches < effective_n) ? cap_matches : effective_n;
    for (size_t i = 0; i < to_emit; i++) {
        size_t e_idx = cands[i].entry_idx;
        cache_entry_t *src = &state->entries[e_idx];

        /* Reset the match's entry view; we populate only the fields
         * the local store actually knows about (embedding + response). */
        memset(&out_matches[i].entry, 0, sizeof out_matches[i].entry);

        float *emb_slot = &out_embeddings[i * (size_t)ANTS_EMBED_DIM];
        memcpy(emb_slot, src->embedding, (size_t)ANTS_EMBED_DIM * sizeof(float));
        out_matches[i].entry.embedding = emb_slot;

        out_matches[i].entry.response = src->value;
        out_matches[i].entry.response_len = src->value_len;
        out_matches[i].similarity = (float)cands[i].similarity;

        /* Bump LRU on every hit returned. */
        src->last_access = ++state->lru_counter;
    }

    if (cap_matches < effective_n) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* LSH shard key (RFC-0002 §DHT routing)                                    */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_shard_key(const float embedding[ANTS_EMBED_DIM],
                                           ants_semantic_cache_shard_key_t *out_key)
{
    if (embedding == NULL || out_key == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ensure_projection_initialised();

    uint64_t key = 0;
    for (uint32_t j = 0; j < (uint32_t)ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS; j++) {
        const float *hp = &g_projection[(size_t)j * (size_t)ANTS_EMBED_DIM];
        /* Accumulate in double to reduce rounding noise from the 1024-
         * term sum. Iteration order is fixed left-to-right with no
         * vectorisation hints — RFC-0009 canonical numerics will
         * eventually pin this against a bit-exact reduction tree;
         * for now this is deterministic on any IEEE-754 host with
         * matching float→double promotion semantics. */
        double dot = 0.0;
        for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
            dot += (double)embedding[i] * (double)hp[i];
        }
        if (dot >= 0.0) {
            key |= ((uint64_t)1 << j);
        }
    }
    *out_key = key;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Diagnostics                                                              */
/* ------------------------------------------------------------------------ */

size_t ants_semantic_cache_entries(const ants_semantic_cache_t *cache)
{
    if (cache == NULL) {
        return 0;
    }
    const struct ants_semantic_cache_state *state =
        (const struct ants_semantic_cache_state *)(const void *)cache->_opaque;
    if (state->magic != ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        return 0;
    }
    return state->n_entries;
}

ants_error_t ants_semantic_cache_clear(ants_semantic_cache_t *cache)
{
    if (cache == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_semantic_cache_state *state =
        (struct ants_semantic_cache_state *)(void *)cache->_opaque;
    if (state->magic != ANTS_SEMANTIC_CACHE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }
    free_all_entries(state);
    return ANTS_OK;
}
