/*
 * test_cache.c — contract tests for the semantic-cache scaffold
 * (Component #10, step 0).
 *
 * Covers the API surface declared in ants_semantic_cache.h:
 *   - Public constants match RFC-0002 (shard-key bits, default
 *     threshold, default replication factor).
 *   - Opaque ctx size + alignment match the documented constants.
 *   - NULL-arg validation on every entry point.
 *   - Every implementation path returns ANTS_ERROR_NOT_IMPLEMENTED
 *     at the scaffold stage (except destroy, which is a safe no-op
 *     so it can run on zeroed ctxs).
 *
 * As subsequent steps land the LSH, the local-shard store, and the
 * DHT-routed protocols, these tests pivot to behavioural assertions;
 * the contract checks (constants, alignment, NULL safety) stay.
 */

#include "ants_common.h"
#include "ants_embed.h"
#include "ants_semantic_cache.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                 \
    do {                                                                                           \
        ants_error_t _a = (actual);                                                                \
        ants_error_t _e = (expected);                                                              \
        if (_a != _e) {                                                                            \
            failures++;                                                                            \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

static void test_protocol_constants(void)
{
    /* RFC-0002 §DHT routing: 64-bit shard key from 64 hyperplanes. */
    CHECK(ANTS_SEMANTIC_CACHE_SHARD_KEY_BITS == 64);

    /* RFC-0002 §Lookup illustrates 0.92 as the default threshold. */
    CHECK(ANTS_SEMANTIC_CACHE_DEFAULT_THRESHOLD == 0.92f);

    /* RFC-0002 §Write: typical replication 3-5; we default 3. */
    CHECK(ANTS_SEMANTIC_CACHE_DEFAULT_REPLICATION == 3u);

    /* Shard-key type must be 8 bytes for the 64-bit bitmask scheme. */
    CHECK(sizeof(ants_semantic_cache_shard_key_t) == 8);
}

static void test_opaque_ctx_layout(void)
{
    ants_semantic_cache_t c;
    CHECK(((uintptr_t)&c & 7u) == 0);
    CHECK(sizeof c == ANTS_SEMANTIC_CACHE_CTX_SIZE);
    CHECK(ANTS_SEMANTIC_CACHE_CTX_SIZE == 4096);
}

static void test_init_null_args(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};

    CHECK_EQ(ants_semantic_cache_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_init(&c, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_init_succeeds(void)
{
    /* init with zeroed config (unbounded caps) must succeed and
     * leave the ctx ready to put/get. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 0);
    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_destroy_safe_on_zero_ctx(void)
{
    /* destroy on a never-initialised (zeroed) ctx must succeed and
     * leave the ctx in a safe state. */
    ants_semantic_cache_t c = {{0}};
    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_destroy(NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_put_null_args(void)
{
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    const uint8_t value[] = {'v'};

    CHECK_EQ(ants_semantic_cache_put(NULL, emb, value, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_put(&c, NULL, value, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_put(&c, emb, NULL, 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_put(&c, emb, value, 0), ANTS_ERROR_INVALID_ARG);
}

static void test_put_rejects_uninitialised(void)
{
    /* put on a zeroed (never-init) ctx is an INVALID_ARG, not a
     * crash. The magic field must be valid before any heap work. */
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    const uint8_t value[] = {'v', 'a', 'l'};
    CHECK_EQ(ants_semantic_cache_put(&c, emb, value, 3), ANTS_ERROR_INVALID_ARG);
}

static void test_get_null_args(void)
{
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;

    CHECK_EQ(ants_semantic_cache_get(NULL, emb, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get(&c, NULL, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, NULL, &sim),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, NULL),
             ANTS_ERROR_INVALID_ARG);
    /* out_value non-NULL but out_cap == 0 is an INVALID_ARG. */
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, 0, &out_len, &sim),
             ANTS_ERROR_INVALID_ARG);
}

static void test_get_rejects_uninitialised(void)
{
    /* get on a zeroed ctx is an INVALID_ARG (magic absent). */
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_INVALID_ARG);
}

static void test_shard_key_null_args(void)
{
    float emb[ANTS_EMBED_DIM] = {0};
    ants_semantic_cache_shard_key_t key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(NULL, &key), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_shard_key(emb, NULL), ANTS_ERROR_INVALID_ARG);
}

/* -- LSH behavioural tests ------------------------------------------------
 *
 * Generate deterministic L2-normalised 1024-d embeddings from a seed
 * (LCG-driven so cross-platform bit-identical), then check that the
 * shard-key satisfies the locality property: similar embeddings produce
 * keys with low Hamming distance; orthogonal-ish embeddings produce
 * keys with Hamming distance near 32 (half the bit width).
 */

static void make_random_embedding(uint32_t seed, float out[ANTS_EMBED_DIM])
{
    uint32_t s = seed;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        s = s * 1664525u + 1013904223u;
        out[i] = ((float)s * (2.0f / 4294967296.0f)) - 1.0f;
    }
    double sumsq = 0.0;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        sumsq += (double)out[i] * (double)out[i];
    }
    float inv_norm = (float)(1.0 / sqrt(sumsq));
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        out[i] *= inv_norm;
    }
}

/* Make `out` ≈ `base` plus small bounded noise, re-L2-normalised.
 * noise_scale = 0.02 → cosine similarity ≈ 0.9998. */
static void make_near_embedding(const float base[ANTS_EMBED_DIM],
                                uint32_t noise_seed,
                                float noise_scale,
                                float out[ANTS_EMBED_DIM])
{
    uint32_t s = noise_seed;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        s = s * 1664525u + 1013904223u;
        float noise = (((float)s * (2.0f / 4294967296.0f)) - 1.0f) * noise_scale;
        out[i] = base[i] + noise;
    }
    double sumsq = 0.0;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        sumsq += (double)out[i] * (double)out[i];
    }
    float inv_norm = (float)(1.0 / sqrt(sumsq));
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        out[i] *= inv_norm;
    }
}

static int hamming64(uint64_t a, uint64_t b)
{
    uint64_t x = a ^ b;
    int count = 0;
    while (x) {
        count++;
        x &= x - 1; /* clear lowest set bit */
    }
    return count;
}

static void test_shard_key_runs_and_is_nontrivial(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(42, emb);

    ants_semantic_cache_shard_key_t key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(emb, &key), ANTS_OK);
    /* For a random Gaussian-projected unit vector, each of the 64
     * sign-bits is roughly 50/50 — neither all-zero nor all-ones with
     * overwhelming probability. */
    CHECK(key != 0);
    CHECK(key != ~(uint64_t)0);
}

static void test_shard_key_idempotent(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7, emb);

    ants_semantic_cache_shard_key_t k1 = 0;
    ants_semantic_cache_shard_key_t k2 = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(emb, &k1), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_shard_key(emb, &k2), ANTS_OK);
    CHECK(k1 == k2);
}

static void test_shard_key_distinct_for_distinct_inputs(void)
{
    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    make_random_embedding(1, a);
    make_random_embedding(2, b);

    ants_semantic_cache_shard_key_t ka = 0;
    ants_semantic_cache_shard_key_t kb = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(a, &ka), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_shard_key(b, &kb), ANTS_OK);
    CHECK(ka != kb);
}

static void test_shard_key_locality(void)
{
    /* Locality property (RFC-0002 §DHT routing): similar embeddings
     * land in the same or adjacent shard. Concretely: H(base, near)
     * with near = base + 2% noise should be much smaller than H(base,
     * far) with far an unrelated random vector. */
    float base[ANTS_EMBED_DIM];
    float near[ANTS_EMBED_DIM];
    float far[ANTS_EMBED_DIM];
    make_random_embedding(100, base);
    make_near_embedding(base, 555, 0.02f, near);
    make_random_embedding(101, far);

    ants_semantic_cache_shard_key_t k_base = 0;
    ants_semantic_cache_shard_key_t k_near = 0;
    ants_semantic_cache_shard_key_t k_far = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &k_base), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_shard_key(near, &k_near), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_shard_key(far, &k_far), ANTS_OK);

    int h_near = hamming64(k_base, k_near);
    int h_far = hamming64(k_base, k_far);

    /* The locality property: near is closer in Hamming than far. */
    CHECK(h_near < h_far);

    /* Cosine sim ≈ 0.9998 for a 2% perturbation. Expected Hamming
     * ≈ 64 · acos(0.9998) / π ≈ 0.4 bits. Allow up to 8 to absorb
     * variance over the 64 hyperplanes. */
    CHECK(h_near <= 8);

    /* Two unrelated unit vectors in 1024-d are nearly orthogonal
     * (concentration of measure). Expected Hamming ≈ 32 with σ ≈ 4. */
    CHECK(h_far >= 20 && h_far <= 44);
}

static void test_entries_safe_on_zero_or_null(void)
{
    /* Diagnostic accessor never errors — returns 0 on null/zeroed ctx. */
    CHECK(ants_semantic_cache_entries(NULL) == 0);
    ants_semantic_cache_t c = {{0}};
    CHECK(ants_semantic_cache_entries(&c) == 0);
}

static void test_clear_null_safety(void)
{
    /* clear on NULL → INVALID_ARG; on never-init zeroed ctx → also
     * INVALID_ARG (magic absent — clear is not safe-no-op like destroy
     * because we can't tell apart "valid empty" from "uninitialised"
     * without the magic check). */
    ants_semantic_cache_t c = {{0}};
    CHECK_EQ(ants_semantic_cache_clear(NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_clear(&c), ANTS_ERROR_INVALID_ARG);
}

/* -- Storage + lookup behavioural tests -----------------------------------
 *
 * init → put → get round-trips with the LSH+cosine pipeline. The
 * fixture helpers (make_random_embedding / make_near_embedding / etc.)
 * defined above are reused.
 */

static void test_put_then_get_round_trip(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(200, emb);
    const uint8_t val[] = "the cached response bytes";
    CHECK_EQ(ants_semantic_cache_put(&c, emb, val, sizeof val - 1), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 1);

    uint8_t out[64];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == sizeof val - 1);
    CHECK(memcmp(out, val, sizeof val - 1) == 0);
    /* Self-similarity is 1.0 (L2-normalised embedding · itself = 1). */
    CHECK(fabs((double)sim - 1.0) < 1e-5);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_returns_not_found_on_empty(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(201, emb);

    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_NOT_FOUND);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_below_threshold_returns_not_found(void)
{
    /* Insert one entry, query with the SAME embedding (so the shard
     * key matches deterministically, sidestepping the LSH-cell
     * boundary that a near-but-not-identical query could land across),
     * but with an impossibly-high threshold so the lookup misses on
     * the similarity check rather than the shard-key check. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(300, emb);
    const uint8_t val[] = "v";
    CHECK_EQ(ants_semantic_cache_put(&c, emb, val, sizeof val - 1), ANTS_OK);

    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    /* Self-similarity is 1.0; threshold 1.01 cannot be met. */
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 1.01f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_NOT_FOUND);

    /* And with a sane threshold the same query DOES hit. */
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(fabs((double)sim - 1.0) < 1e-5);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_buffer_too_small_reports_required(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(400, emb);
    const uint8_t val[] = "a longer-than-eight-byte payload";
    CHECK_EQ(ants_semantic_cache_put(&c, emb, val, sizeof val - 1), ANTS_OK);

    uint8_t small_out[8];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, small_out, sizeof small_out, &out_len, &sim),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_len == sizeof val - 1);

    /* Probe with out_value=NULL (out_cap=0) to discover required size. */
    out_len = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, NULL, 0, &out_len, &sim),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_len == sizeof val - 1);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_ranks_by_similarity(void)
{
    /* Two entries with the same shard key but different similarity
     * to the query embedding: the closer one wins. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    float near[ANTS_EMBED_DIM];
    make_random_embedding(500, base);
    /* `near` shares the same shard key as `base` for a 2% perturbation
     * (locality test above already verifies this with high probability). */
    make_near_embedding(base, 777, 0.02f, near);

    const uint8_t val_base[] = "BASE";
    const uint8_t val_near[] = "NEAR";
    CHECK_EQ(ants_semantic_cache_put(&c, base, val_base, sizeof val_base - 1), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_put(&c, near, val_near, sizeof val_near - 1), ANTS_OK);

    /* Query with `base` itself: cosine with base = 1.0, with near ≈ 0.9998.
     * Highest-sim must be BASE. */
    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, base, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 4);
    CHECK(memcmp(out, "BASE", 4) == 0);

    /* Query with `near`: highest-sim must be NEAR. */
    CHECK_EQ(ants_semantic_cache_get(&c, near, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 4);
    CHECK(memcmp(out, "NEAR", 4) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_entries_grows_with_puts(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 0);

    /* Put 30 random embeddings — forces the geometric-grow path
     * (initial cap = 16). */
    for (uint32_t i = 0; i < 30; i++) {
        float emb[ANTS_EMBED_DIM];
        make_random_embedding(1000 + i, emb);
        const uint8_t v = (uint8_t)('a' + (i % 26));
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }
    CHECK(ants_semantic_cache_entries(&c) == 30);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

/* -- LRU eviction (step 3) ------------------------------------------------
 *
 * These exercise the per_shard_max + total_max caps. Both default to 0
 * (unbounded) in earlier tests, so the existing 30-put grow test still
 * holds; here we explicitly set the caps and verify eviction picks the
 * LRU candidate. */

static void test_total_cap_enforced(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    cfg.total_max = 3;
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    for (uint32_t i = 0; i < 10; i++) {
        float emb[ANTS_EMBED_DIM];
        make_random_embedding(2000 + i, emb);
        uint8_t v = (uint8_t)('a' + i);
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }
    /* Total cap holds: entries stays at 3 after 10 puts. */
    CHECK(ants_semantic_cache_entries(&c) == 3);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_total_cap_evicts_lru_and_recency_is_bumped_by_get(void)
{
    /* Cap = 2. Sequence:
     *   put A     -> entries = {A}              (A.last_access = 1)
     *   put B     -> entries = {A, B}           (B.last_access = 2)
     *   get A     -> hit, bumps A               (A.last_access = 3)
     *   put C     -> cap exceeded; B is LRU     (evict B; C.last_access = 4)
     * Expectations after: A + C present, B gone. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    cfg.total_max = 2;
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    float d[ANTS_EMBED_DIM];
    make_random_embedding(3001, a);
    make_random_embedding(3002, b);
    make_random_embedding(3003, d);
    CHECK_EQ(ants_semantic_cache_put(&c, a, (const uint8_t *)"A", 1), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_put(&c, b, (const uint8_t *)"B", 1), ANTS_OK);

    uint8_t out[8];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, a, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);

    CHECK_EQ(ants_semantic_cache_put(&c, d, (const uint8_t *)"D", 1), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 2);

    /* A is still present. */
    CHECK_EQ(ants_semantic_cache_get(&c, a, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 1 && out[0] == 'A');

    /* B is gone. */
    CHECK_EQ(ants_semantic_cache_get(&c, b, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_NOT_FOUND);

    /* D is present. */
    CHECK_EQ(ants_semantic_cache_get(&c, d, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 1 && out[0] == 'D');

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_per_shard_cap_enforced(void)
{
    /* Put 5 entries that all share the same shard key (same embedding,
     * different values). With per_shard_max = 2 only 2 should remain. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    cfg.per_shard_max = 2;
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(4000, emb);
    for (uint32_t i = 0; i < 5; i++) {
        uint8_t v = (uint8_t)('0' + i);
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }
    CHECK(ants_semantic_cache_entries(&c) == 2);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_per_shard_cap_does_not_evict_other_shards(void)
{
    /* per_shard_max = 1 on two different shards. After 3 puts (2 in
     * shard A, 1 in shard B), entries should be 2 (one per shard).
     * The shard-B entry is NOT evicted by puts into shard A. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    cfg.per_shard_max = 1;
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb_a[ANTS_EMBED_DIM];
    float emb_b[ANTS_EMBED_DIM];
    make_random_embedding(5001, emb_a);
    make_random_embedding(5002, emb_b);

    /* Two unrelated unit vectors in 1024-d are almost certainly in
     * different LSH cells (probability of same 64-bit shard key over
     * a Gaussian-hyperplane random LSH is ~ 2^-32 with concentration
     * of measure; this is testably zero in practice). */
    ants_semantic_cache_shard_key_t ka = 0;
    ants_semantic_cache_shard_key_t kb = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(emb_a, &ka), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_shard_key(emb_b, &kb), ANTS_OK);
    CHECK(ka != kb);

    CHECK_EQ(ants_semantic_cache_put(&c, emb_a, (const uint8_t *)"A1", 2), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_put(&c, emb_b, (const uint8_t *)"B1", 2), ANTS_OK);
    /* Second put into shard A: evicts the older shard-A entry, leaves
     * shard B alone. */
    CHECK_EQ(ants_semantic_cache_put(&c, emb_a, (const uint8_t *)"A2", 2), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 2);

    /* Shard B is intact. */
    uint8_t out[8];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb_b, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 2 && memcmp(out, "B1", 2) == 0);

    /* Shard A now holds A2 (A1 was evicted). */
    CHECK_EQ(ants_semantic_cache_get(&c, emb_a, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == 2 && memcmp(out, "A2", 2) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

/* -- Cache-entry wire format (step 4) -------------------------------------
 *
 * Round-trip + malformed/non-canonical rejection for
 * ants_semantic_cache_entry_encode / _decode. */

static void fill_test_entry(ants_semantic_cache_entry_t *e,
                            const float *emb,
                            const char *response,
                            const char *resp_model)
{
    memset(e, 0, sizeof *e);
    e->embedding = emb;
    e->embedding_model = "ants-embed-v1";
    e->embedding_model_len = strlen("ants-embed-v1");
    for (uint32_t i = 0; i < ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN; i++) {
        e->prompt_hash[i] = (uint8_t)(0xA0u + (i & 0x0Fu));
    }
    e->response = (const uint8_t *)response;
    e->response_len = strlen(response);
    e->response_model = resp_model;
    e->response_model_len = strlen(resp_model);
    for (uint32_t i = 0; i < ANTS_SEMANTIC_CACHE_PEER_ID_LEN; i++) {
        e->producer[i] = (uint8_t)(0xB0u + (i & 0x0Fu));
    }
    e->created = 1717000000ull;
    e->validity_class = ANTS_SEMANTIC_CACHE_VALIDITY_MONTHS;
    static const uint8_t att[] = {0xC0, 0xDE, 0xCA, 0xFE};
    e->attestation = att;
    e->attestation_len = sizeof att;
    for (uint32_t i = 0; i < ANTS_SEMANTIC_CACHE_SIG_LEN; i++) {
        e->signature[i] = (uint8_t)(0xD0u + (i & 0x0Fu));
    }
}

static void test_entry_wire_round_trip(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7000, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "the response payload", "llama-3.3-70b-instruct");

    /* 8 KB is plenty for this payload (4 KB embedding + < 1 KB metadata
     * + small response). */
    uint8_t buf[8192];
    size_t encoded_len = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, buf, sizeof buf, &encoded_len), ANTS_OK);
    CHECK(encoded_len > 4096);
    CHECK(encoded_len < sizeof buf);

    ants_semantic_cache_entry_t out_e;
    float out_emb[ANTS_EMBED_DIM];
    CHECK_EQ(ants_semantic_cache_entry_decode(buf, encoded_len, &out_e, out_emb), ANTS_OK);

    /* Compare every field. */
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        CHECK(out_emb[i] == emb[i]);
    }
    CHECK(out_e.embedding_model_len == strlen("ants-embed-v1"));
    CHECK(memcmp(out_e.embedding_model, "ants-embed-v1", out_e.embedding_model_len) == 0);
    CHECK(memcmp(out_e.prompt_hash, in_e.prompt_hash, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN) == 0);
    CHECK(out_e.response_len == strlen("the response payload"));
    CHECK(memcmp(out_e.response, "the response payload", out_e.response_len) == 0);
    CHECK(out_e.response_model_len == strlen("llama-3.3-70b-instruct"));
    CHECK(memcmp(out_e.response_model, "llama-3.3-70b-instruct", out_e.response_model_len) == 0);
    CHECK(memcmp(out_e.producer, in_e.producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN) == 0);
    CHECK(out_e.created == 1717000000ull);
    CHECK(out_e.validity_class == ANTS_SEMANTIC_CACHE_VALIDITY_MONTHS);
    CHECK(out_e.attestation_len == in_e.attestation_len);
    CHECK(memcmp(out_e.attestation, in_e.attestation, out_e.attestation_len) == 0);
    CHECK(memcmp(out_e.signature, in_e.signature, ANTS_SEMANTIC_CACHE_SIG_LEN) == 0);
}

static void test_entry_wire_empty_attestation(void)
{
    /* v0.x allows a zero-length attestation; round-trip must preserve it. */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7001, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "r", "rm");
    in_e.attestation = NULL;
    in_e.attestation_len = 0;

    uint8_t buf[8192];
    size_t n = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, buf, sizeof buf, &n), ANTS_OK);

    ants_semantic_cache_entry_t out_e;
    float out_emb[ANTS_EMBED_DIM];
    CHECK_EQ(ants_semantic_cache_entry_decode(buf, n, &out_e, out_emb), ANTS_OK);
    CHECK(out_e.attestation_len == 0);
}

static void test_entry_wire_buffer_too_small(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7002, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "r", "rm");

    /* 100 bytes can't hold the embedding alone (4096). */
    uint8_t small[100];
    size_t n = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, small, sizeof small, &n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_entry_wire_null_args(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7003, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "r", "rm");

    uint8_t buf[8192];
    size_t n = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(NULL, buf, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, NULL, sizeof buf, &n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, buf, sizeof buf, NULL),
             ANTS_ERROR_INVALID_ARG);

    ants_semantic_cache_entry_t out_e;
    float out_emb[ANTS_EMBED_DIM];
    CHECK_EQ(ants_semantic_cache_entry_decode(NULL, 1, &out_e, out_emb), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_entry_decode(buf, 1, NULL, out_emb), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_entry_decode(buf, 1, &out_e, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_entry_wire_decode_truncated(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7004, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "x", "y");

    uint8_t buf[8192];
    size_t n = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, buf, sizeof buf, &n), ANTS_OK);

    /* Truncate to half — decode must fail. */
    ants_semantic_cache_entry_t out_e;
    float out_emb[ANTS_EMBED_DIM];
    ants_error_t e = ants_semantic_cache_entry_decode(buf, n / 2, &out_e, out_emb);
    CHECK(e == ANTS_ERROR_MALFORMED || e == ANTS_ERROR_NON_CANONICAL);
}

static void test_entry_wire_decode_invalid_validity(void)
{
    /* Encode with valid validity, then patch the CBOR to set
     * validity_class = 99. The map order is 1..10; key 8 (validity)
     * is followed by its uint value. Find the byte and overwrite. */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(7005, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "x", "y");

    uint8_t buf[8192];
    size_t n = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, buf, sizeof buf, &n), ANTS_OK);

    /* The validity byte: search for the sequence [0x08, 0x02] which is
     * "uint 8 (key) followed by uint 2 (value = MONTHS)". Replace the
     * second byte with 0x18 0x63 (uint 99 in 1-byte extended form). */
    size_t patch_off = 0;
    bool found = false;
    for (size_t i = 0; i + 1 < n; i++) {
        if (buf[i] == 0x08 && buf[i + 1] == 0x02) {
            patch_off = i + 1;
            found = true;
            break;
        }
    }
    CHECK(found);
    /* CBOR encodes uint 99 as [0x18, 0x63] (2 bytes). Our original
     * value is 1 byte [0x02]. Re-encoding inline would extend the
     * map; easier path: overwrite 0x02 with 0x05 (= 5, just past the
     * 4 max). Decoder rejects 5 with NON_CANONICAL. */
    buf[patch_off] = 0x05;

    ants_semantic_cache_entry_t out_e;
    float out_emb[ANTS_EMBED_DIM];
    CHECK_EQ(ants_semantic_cache_entry_decode(buf, n, &out_e, out_emb), ANTS_ERROR_NON_CANONICAL);
}

/* -- Lookup request wire format (step 5) ----------------------------------
 *
 * Round-trip + malformed/non-canonical rejection for the cache lookup
 * request CBOR codec (3 fields: embedding, threshold, top_k). */

static void test_lookup_request_round_trip(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8000, emb);

    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.92f, 5, buf, sizeof buf, &encoded),
             ANTS_OK);
    CHECK(encoded > 4096); /* embedding alone is 4096 bytes */
    CHECK(encoded < sizeof buf);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0xFFFFFFFFu;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, encoded, out_emb, &out_thr, &out_topk),
             ANTS_OK);

    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        CHECK(out_emb[i] == emb[i]);
    }
    CHECK(out_thr == 0.92f);
    CHECK(out_topk == 5u);
}

static void test_lookup_request_top_k_zero(void)
{
    /* top_k = 0 means "unbounded; responder picks". Round-trips fine. */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8001, emb);

    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.5f, 0, buf, sizeof buf, &encoded),
             ANTS_OK);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 1.0f;
    uint32_t out_topk = 42;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, encoded, out_emb, &out_thr, &out_topk),
             ANTS_OK);
    CHECK(out_thr == 0.5f);
    CHECK(out_topk == 0u);
}

static void test_lookup_request_buffer_too_small(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8002, emb);

    /* 100 bytes can't hold the embedding alone. */
    uint8_t small[100];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, small, sizeof small, &encoded),
             ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_lookup_request_null_args(void)
{
    float emb[ANTS_EMBED_DIM] = {0};
    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(NULL, 0.9f, 1, buf, sizeof buf, &encoded),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, NULL, sizeof buf, &encoded),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, buf, sizeof buf, NULL),
             ANTS_ERROR_INVALID_ARG);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(NULL, 1, out_emb, &out_thr, &out_topk),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, 1, NULL, &out_thr, &out_topk),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, 1, out_emb, NULL, &out_topk),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, 1, out_emb, &out_thr, NULL),
             ANTS_ERROR_INVALID_ARG);
}

static void test_lookup_request_decode_truncated(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8003, emb);

    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 3, buf, sizeof buf, &encoded),
             ANTS_OK);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0;
    ants_error_t e =
        ants_semantic_cache_lookup_request_decode(buf, encoded / 2, out_emb, &out_thr, &out_topk);
    CHECK(e == ANTS_ERROR_MALFORMED || e == ANTS_ERROR_NON_CANONICAL);
}

/* -- Lookup response wire format (step 6) ---------------------------------
 *
 * Round-trip + partial-cap behaviour + malformed rejection for the
 * cache lookup response CBOR codec (array of {similarity, entry}). */

static void
fill_match(ants_semantic_cache_lookup_match_t *m, const float *emb, float sim, const char *resp)
{
    fill_test_entry(&m->entry, emb, resp, "resp-model");
    m->similarity = sim;
}

static void test_lookup_response_round_trip_zero_matches(void)
{
    uint8_t buf[128];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(NULL, 0, buf, sizeof buf, &encoded),
             ANTS_OK);
    CHECK(encoded < sizeof buf);

    size_t out_n = 999;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, encoded, NULL, NULL, 0, &out_n),
             ANTS_OK);
    CHECK(out_n == 0);
}

static void test_lookup_response_round_trip_three(void)
{
    /* Build 3 matches with distinct embeddings + similarities. */
    float embs[3][ANTS_EMBED_DIM];
    ants_semantic_cache_lookup_match_t in[3];
    make_random_embedding(9000, embs[0]);
    make_random_embedding(9001, embs[1]);
    make_random_embedding(9002, embs[2]);
    fill_match(&in[0], embs[0], 0.95f, "alpha-response");
    fill_match(&in[1], embs[1], 0.80f, "beta-response");
    fill_match(&in[2], embs[2], 0.75f, "gamma-response");

    /* 3 entries × ~4.2 KB each → ~13 KB. 32 KB buffer is comfortable. */
    uint8_t buf[32768];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(in, 3, buf, sizeof buf, &encoded), ANTS_OK);
    CHECK(encoded > 12000);
    CHECK(encoded < sizeof buf);

    ants_semantic_cache_lookup_match_t out[3];
    float out_embs[3 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, encoded, out, out_embs, 3, &out_n),
             ANTS_OK);
    CHECK(out_n == 3);

    for (size_t i = 0; i < 3; i++) {
        CHECK(out[i].similarity == in[i].similarity);
        CHECK(out[i].entry.response_len == in[i].entry.response_len);
        CHECK(memcmp(out[i].entry.response, in[i].entry.response, out[i].entry.response_len) == 0);
        /* Embedding round-trip. */
        const float *out_emb_i = &out_embs[i * (size_t)ANTS_EMBED_DIM];
        for (uint32_t k = 0; k < (uint32_t)ANTS_EMBED_DIM; k++) {
            CHECK(out_emb_i[k] == embs[i][k]);
        }
    }
}

static void test_lookup_response_decode_partial_cap(void)
{
    /* Encode 3 matches; decode with cap_matches = 2. Decoder should
     * return BUFFER_TOO_SMALL with out_n = 3 and the first two slots
     * filled. Caller may then re-call with a bigger buffer. */
    float embs[3][ANTS_EMBED_DIM];
    ants_semantic_cache_lookup_match_t in[3];
    make_random_embedding(9100, embs[0]);
    make_random_embedding(9101, embs[1]);
    make_random_embedding(9102, embs[2]);
    fill_match(&in[0], embs[0], 0.9f, "x");
    fill_match(&in[1], embs[1], 0.8f, "y");
    fill_match(&in[2], embs[2], 0.7f, "z");

    uint8_t buf[32768];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(in, 3, buf, sizeof buf, &encoded), ANTS_OK);

    ants_semantic_cache_lookup_match_t out[2];
    float out_embs[2 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, encoded, out, out_embs, 2, &out_n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 3);
    CHECK(out[0].similarity == 0.9f);
    CHECK(out[1].similarity == 0.8f);
}

static void test_lookup_response_null_args(void)
{
    uint8_t buf[128];
    size_t out_len = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(NULL, 1, buf, sizeof buf, &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(NULL, 0, NULL, sizeof buf, &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(NULL, 0, buf, sizeof buf, NULL),
             ANTS_ERROR_INVALID_ARG);

    ants_semantic_cache_lookup_match_t out[1];
    float out_embs[ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(NULL, 1, out, out_embs, 1, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, 1, out, out_embs, 1, NULL),
             ANTS_ERROR_INVALID_ARG);
    /* cap > 0 with NULL out_matches must reject. */
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, 1, NULL, out_embs, 1, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(buf, 1, out, NULL, 1, &out_n),
             ANTS_ERROR_INVALID_ARG);
}

static void test_lookup_response_decode_truncated(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(9200, emb);
    ants_semantic_cache_lookup_match_t in[1];
    fill_match(&in[0], emb, 0.9f, "v");

    uint8_t buf[16384];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_encode(in, 1, buf, sizeof buf, &encoded), ANTS_OK);

    ants_semantic_cache_lookup_match_t out[1];
    float out_embs[ANTS_EMBED_DIM];
    size_t out_n = 0;
    ants_error_t e =
        ants_semantic_cache_lookup_response_decode(buf, encoded / 2, out, out_embs, 1, &out_n);
    CHECK(e == ANTS_ERROR_MALFORMED || e == ANTS_ERROR_NON_CANONICAL);
}

static void test_clear_removes_entries(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(600, emb);
    const uint8_t v[] = "stuff";
    CHECK_EQ(ants_semantic_cache_put(&c, emb, v, sizeof v - 1), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 1);

    CHECK_EQ(ants_semantic_cache_clear(&c), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 0);

    /* After clear, get returns NOT_FOUND. */
    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_NOT_FOUND);

    /* The ctx is still usable after clear: another put + get works. */
    const uint8_t w[] = "again";
    CHECK_EQ(ants_semantic_cache_put(&c, emb, w, sizeof w - 1), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(memcmp(out, "again", 5) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

int main(void)
{
    test_protocol_constants();
    test_opaque_ctx_layout();
    test_init_null_args();
    test_init_succeeds();
    test_destroy_safe_on_zero_ctx();
    test_put_null_args();
    test_put_rejects_uninitialised();
    test_get_null_args();
    test_get_rejects_uninitialised();
    test_shard_key_null_args();
    test_shard_key_runs_and_is_nontrivial();
    test_shard_key_idempotent();
    test_shard_key_distinct_for_distinct_inputs();
    test_shard_key_locality();
    test_entries_safe_on_zero_or_null();
    test_clear_null_safety();
    test_put_then_get_round_trip();
    test_get_returns_not_found_on_empty();
    test_get_below_threshold_returns_not_found();
    test_get_buffer_too_small_reports_required();
    test_get_ranks_by_similarity();
    test_entries_grows_with_puts();
    test_total_cap_enforced();
    test_total_cap_evicts_lru_and_recency_is_bumped_by_get();
    test_per_shard_cap_enforced();
    test_per_shard_cap_does_not_evict_other_shards();
    test_entry_wire_round_trip();
    test_entry_wire_empty_attestation();
    test_entry_wire_buffer_too_small();
    test_entry_wire_null_args();
    test_entry_wire_decode_truncated();
    test_entry_wire_decode_invalid_validity();
    test_lookup_request_round_trip();
    test_lookup_request_top_k_zero();
    test_lookup_request_buffer_too_small();
    test_lookup_request_null_args();
    test_lookup_request_decode_truncated();
    test_lookup_response_round_trip_zero_matches();
    test_lookup_response_round_trip_three();
    test_lookup_response_decode_partial_cap();
    test_lookup_response_null_args();
    test_lookup_response_decode_truncated();
    test_clear_removes_entries();

    if (failures > 0) {
        fprintf(stderr, "test_cache: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_cache: all checks passed\n");
    return 0;
}
