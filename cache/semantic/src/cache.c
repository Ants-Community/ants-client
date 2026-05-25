/*
 * cache.c — Semantic cache (Component #10).
 *
 * Step 1 (this PR): LSH shard-key lands. The projection matrix is
 * generated lazily on first use from a fixed BLAKE3-derived seed.
 * Every other entry point still returns ANTS_ERROR_NOT_IMPLEMENTED;
 * subsequent steps land:
 *
 *   - step 2: Local-shard storage with cosine-similarity lookup.
 *   - step 3: Eviction policy (LRU per shard + decay by validity class).
 *   - step 4: DHT-routed write protocol (replicate to N shard-holders).
 *   - step 5: DHT-routed lookup with Hamming-1/2/3 neighbour expansion
 *             and multi-shard aggregation.
 *   - step 6: Quality-signal aggregation + challenge-based invalidation.
 *
 * Destroy is a safe no-op even at scaffold; the rest is gated.
 */

#include "ants_semantic_cache.h"

#include "ants_crypto.h"

#include <math.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
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
/* per-cache resource), so it lives in static storage outside the          */
/* ants_semantic_cache_state struct. The state struct is reserved for     */
/* per-instance data (bucket store, config copy, etc.) landing in step 2+. */
/* ------------------------------------------------------------------------ */

struct ants_semantic_cache_state {
    uint32_t magic;
    uint8_t _pad[4];
    /* Heap pointers land here in step 2+. */
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

ants_error_t ants_semantic_cache_init(ants_semantic_cache_t *cache,
                                      const ants_semantic_cache_config_t *config)
{
    if (cache == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_semantic_cache_destroy(ants_semantic_cache_t *cache)
{
    if (cache == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Zero the ctx so a destroyed-then-re-init cycle starts clean.
     * Safe on a never-initialised ctx (it's all zero already). */
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
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
    (void)similarity_threshold;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
    return 0;
}

ants_error_t ants_semantic_cache_clear(ants_semantic_cache_t *cache)
{
    if (cache == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
