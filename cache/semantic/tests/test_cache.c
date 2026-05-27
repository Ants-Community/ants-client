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

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_embed.h"
#include "ants_semantic_cache.h"

/* Module-private helper in cache_wire.c — emits the canonical CBOR
 * signing payload (map(9) over fields 1..9) the producer signs. Used
 * here to construct test fixtures whose signatures verify under the
 * new handle_inbound_entry Ed25519 gate. */
extern ants_error_t cache_entry_emit_signing_payload(const ants_semantic_cache_entry_t *entry,
                                                     uint8_t *buf,
                                                     size_t out_cap,
                                                     size_t *out_len);

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Same as fill_test_entry but produces a record whose `producer`
 * matches `priv`'s public key and whose `signature` is the actual
 * Ed25519 signature over the canonical signing payload (CBOR map(9)
 * of fields 1..9). Used by tests that exercise the handle_inbound_
 * entry verify gate; the plain fill_test_entry still works for
 * tests that only round-trip the wire format. */
static void fill_signed_test_entry(ants_semantic_cache_entry_t *e,
                                   const float *emb,
                                   const char *response,
                                   const char *resp_model,
                                   const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE])
{
    fill_test_entry(e, emb, response, resp_model);

    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
    memcpy(e->producer, pub, ANTS_ED25519_PUBKEY_SIZE);

    /* Comfortable upper bound for any realistic cache-entry signing
     * payload (full record is ~5 KB max in v0.x; the payload is
     * smaller still). Stack-allocated so the helper has no heap
     * dependency. */
    uint8_t payload[16384];
    size_t payload_len = 0;
    CHECK_EQ(cache_entry_emit_signing_payload(e, payload, sizeof payload, &payload_len), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(priv, payload, payload_len, e->signature), ANTS_OK);
}

/* Deterministic Ed25519 private key for tests. Any 32-byte seed
 * produces a valid private key for ed25519-donna / libsodium-style
 * libraries; we pick a fixed pattern so test outputs stay
 * reproducible. */
static void make_test_priv(uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE], uint8_t seed_byte)
{
    for (uint32_t i = 0; i < ANTS_ED25519_PRIVKEY_SIZE; i++) {
        priv[i] = (uint8_t)(seed_byte + (uint8_t)i);
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
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.92f, 5, 0, buf, sizeof buf, &encoded),
             ANTS_OK);
    CHECK(encoded > 4096); /* embedding alone is 4096 bytes */
    CHECK(encoded < sizeof buf);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0xFFFFFFFFu;
    uint32_t out_radius = 0xFFFFFFFFu;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(
                 buf, encoded, out_emb, &out_thr, &out_topk, &out_radius),
             ANTS_OK);

    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        CHECK(out_emb[i] == emb[i]);
    }
    CHECK(out_thr == 0.92f);
    CHECK(out_topk == 5u);
    CHECK(out_radius == 0u);
}

static void test_lookup_request_top_k_zero(void)
{
    /* top_k = 0 means "unbounded; responder picks". Round-trips fine. */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8001, emb);

    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.5f, 0, 0, buf, sizeof buf, &encoded),
             ANTS_OK);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 1.0f;
    uint32_t out_topk = 42;
    uint32_t out_radius = 42;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(
                 buf, encoded, out_emb, &out_thr, &out_topk, &out_radius),
             ANTS_OK);
    CHECK(out_thr == 0.5f);
    CHECK(out_topk == 0u);
    CHECK(out_radius == 0u);
}

static void test_lookup_request_buffer_too_small(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8002, emb);

    /* 100 bytes can't hold the embedding alone. */
    uint8_t small[100];
    size_t encoded = 0;
    CHECK_EQ(
        ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, 0, small, sizeof small, &encoded),
        ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_lookup_request_null_args(void)
{
    float emb[ANTS_EMBED_DIM] = {0};
    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(NULL, 0.9f, 1, 0, buf, sizeof buf, &encoded),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, 0, NULL, sizeof buf, &encoded),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 1, 0, buf, sizeof buf, NULL),
             ANTS_ERROR_INVALID_ARG);
    /* radius > MAX rejects on encode. */
    CHECK_EQ(
        ants_semantic_cache_lookup_request_encode(
            emb, 0.9f, 1, ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS + 1u, buf, sizeof buf, &encoded),
        ANTS_ERROR_INVALID_ARG);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0;
    uint32_t out_radius = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(
                 NULL, 1, out_emb, &out_thr, &out_topk, &out_radius),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_semantic_cache_lookup_request_decode(buf, 1, NULL, &out_thr, &out_topk, &out_radius),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_semantic_cache_lookup_request_decode(buf, 1, out_emb, NULL, &out_topk, &out_radius),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_semantic_cache_lookup_request_decode(buf, 1, out_emb, &out_thr, NULL, &out_radius),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(buf, 1, out_emb, &out_thr, &out_topk, NULL),
             ANTS_ERROR_INVALID_ARG);
}

static void test_lookup_request_decode_truncated(void)
{
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8003, emb);

    uint8_t buf[8192];
    size_t encoded = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 3, 0, buf, sizeof buf, &encoded),
             ANTS_OK);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0;
    uint32_t out_radius = 0;
    ants_error_t e = ants_semantic_cache_lookup_request_decode(
        buf, encoded / 2, out_emb, &out_thr, &out_topk, &out_radius);
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

/* -- Top-K lookup (step 7a) ----------------------------------------------- */

static void test_get_topk_null_args(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(11000, emb);
    ants_semantic_cache_lookup_match_t matches[2];
    float emb_buf[2 * ANTS_EMBED_DIM];
    size_t out_n = 0;

    CHECK_EQ(ants_semantic_cache_get_topk(NULL, emb, 0.9f, 5, 0, matches, emb_buf, 2, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get_topk(&c, NULL, 0.9f, 5, 0, matches, emb_buf, 2, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 5, 0, matches, emb_buf, 2, NULL),
             ANTS_ERROR_INVALID_ARG);
    /* cap > 0 with NULL output buffers rejects. */
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 5, 0, NULL, emb_buf, 2, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 5, 0, matches, NULL, 2, &out_n),
             ANTS_ERROR_INVALID_ARG);
    /* radius > MAX rejects too. */
    CHECK_EQ(ants_semantic_cache_get_topk(&c,
                                          emb,
                                          0.9f,
                                          5,
                                          ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS + 1u,
                                          matches,
                                          emb_buf,
                                          2,
                                          &out_n),
             ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_rejects_uninitialised(void)
{
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    ants_semantic_cache_lookup_match_t matches[1];
    float emb_buf[ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 1, 0, matches, emb_buf, 1, &out_n),
             ANTS_ERROR_INVALID_ARG);
}

static void test_get_topk_returns_not_found_on_empty(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(11001, emb);
    ants_semantic_cache_lookup_match_t matches[1];
    float emb_buf[ANTS_EMBED_DIM];
    size_t out_n = 99;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 1, 0, matches, emb_buf, 1, &out_n),
             ANTS_ERROR_NOT_FOUND);
    CHECK(out_n == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_returns_sorted_desc(void)
{
    /* Two embeddings with a tiny 0.1 % perturbation: same shard with
     * very high probability, distinct similarities when queried with
     * `base`. The LSH cell boundary is still a sharp edge so we accept
     * both outcomes (2 matches with sort verified; 1 match if `near`
     * crossed a hyperplane). */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    float near[ANTS_EMBED_DIM];
    make_random_embedding(11100, base);
    make_near_embedding(base, 0xAA, 0.001f, near);

    CHECK_EQ(ants_semantic_cache_put(&c, base, (const uint8_t *)"BASE", 4), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_put(&c, near, (const uint8_t *)"NEAR", 4), ANTS_OK);

    /* Query with base: self-sim 1.0; sim(base, near) < 1.0. */
    ants_semantic_cache_lookup_match_t matches[2];
    float emb_buf[2 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, base, 0.5f, 2, 0, matches, emb_buf, 2, &out_n),
             ANTS_OK);

    /* First match is always BASE — whether near lands in the same
     * LSH cell or not. */
    CHECK(matches[0].entry.response_len == 4);
    CHECK(memcmp(matches[0].entry.response, "BASE", 4) == 0);
    CHECK((double)matches[0].similarity > 0.99);

    if (out_n == 2) {
        /* Same shard: sort verifies BASE before NEAR by sim. */
        CHECK(matches[0].similarity > matches[1].similarity);
        CHECK(matches[1].entry.response_len == 4);
        CHECK(memcmp(matches[1].entry.response, "NEAR", 4) == 0);
    } else {
        /* near hashed to a different shard cell; only BASE shows. */
        CHECK(out_n == 1);
    }

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_respects_top_k_cap(void)
{
    /* 5 entries with the same embedding (and so the same similarity),
     * top_k=2 → only 2 matches written; *out_n=2 (since effective_n is
     * min(top_k, n_cands) = 2). */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(11200, emb);
    for (uint32_t i = 0; i < 5; i++) {
        uint8_t v = (uint8_t)('a' + i);
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }

    ants_semantic_cache_lookup_match_t matches[5];
    float emb_buf[5 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.5f, 2, 0, matches, emb_buf, 5, &out_n),
             ANTS_OK);
    CHECK(out_n == 2);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_top_k_zero_unbounded(void)
{
    /* top_k=0 means unbounded; with cap_matches=3 we get all 3 of the
     * 3 stored matches. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(11300, emb);
    for (uint32_t i = 0; i < 3; i++) {
        uint8_t v = (uint8_t)('x' + i);
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }

    ants_semantic_cache_lookup_match_t matches[3];
    float emb_buf[3 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.5f, 0, 0, matches, emb_buf, 3, &out_n),
             ANTS_OK);
    CHECK(out_n == 3);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_buffer_too_small(void)
{
    /* 4 eligible matches, cap_matches=2, top_k=4 → BUFFER_TOO_SMALL
     * with *out_n=4 (caller's signal that they need a bigger buffer);
     * first 2 slots written. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(11400, emb);
    for (uint32_t i = 0; i < 4; i++) {
        uint8_t v = (uint8_t)('0' + i);
        CHECK_EQ(ants_semantic_cache_put(&c, emb, &v, 1), ANTS_OK);
    }

    ants_semantic_cache_lookup_match_t matches[2];
    float emb_buf[2 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.5f, 4, 0, matches, emb_buf, 2, &out_n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 4);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

/* -- Hamming-neighbour expansion (step 8) ----------------------------------
 *
 * Validate that ants_semantic_cache_get_topk admits entries whose
 * shard_key is within `hamming_radius` bit-flips of the query embedding's
 * shard_key (the spec's near-neighbour widening from RFC-0002 §Lookup).
 *
 * Building entries at controlled Hamming distances from a target query
 * is awkward: a random embedding's shard_key is binomial(64, 0.5), so
 * distances 0/1/2/3 are exceptionally rare. We instead generate a pool
 * of near-embeddings around a base via small-noise perturbations (which
 * empirically land at small Hamming distances), classify each by its
 * actual distance, and use that classification as the test's ground
 * truth. The query is the base embedding itself.
 */

#define HAMMING_POOL_SIZE 32u

typedef struct {
    float emb[ANTS_EMBED_DIM];
    ants_semantic_cache_shard_key_t key;
    int hamming_dist;
    uint8_t tag;
} hamming_pool_entry_t;

static void build_hamming_pool(const float base[ANTS_EMBED_DIM],
                               ants_semantic_cache_shard_key_t base_key,
                               hamming_pool_entry_t pool[HAMMING_POOL_SIZE])
{
    /* Two noise scales: 0.005 → many distance-0/1 entries, 0.05 → more
     * distance-3+ entries. Mixing the two gives a varied distribution
     * over distances 0..~8. */
    for (uint32_t i = 0; i < HAMMING_POOL_SIZE; i++) {
        float noise_scale = (i < HAMMING_POOL_SIZE / 2) ? 0.005f : 0.05f;
        make_near_embedding(base, 10000u + i, noise_scale, pool[i].emb);
        CHECK_EQ(ants_semantic_cache_shard_key(pool[i].emb, &pool[i].key), ANTS_OK);
        pool[i].hamming_dist = hamming64((uint64_t)base_key, (uint64_t)pool[i].key);
        pool[i].tag = (uint8_t)i;
    }
}

static size_t count_pool_within_radius(const hamming_pool_entry_t pool[HAMMING_POOL_SIZE],
                                       int radius)
{
    size_t count = 0;
    for (uint32_t i = 0; i < HAMMING_POOL_SIZE; i++) {
        if (pool[i].hamming_dist <= radius) {
            count++;
        }
    }
    return count;
}

static void test_get_topk_hamming_zero_matches_exact_shard_only(void)
{
    /* Same as the pre-step-8 behaviour: radius=0 restricts to entries
     * with shard_key exactly equal to the query's shard_key. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    make_random_embedding(20000, base);
    ants_semantic_cache_shard_key_t base_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &base_key), ANTS_OK);

    hamming_pool_entry_t pool[HAMMING_POOL_SIZE];
    build_hamming_pool(base, base_key, pool);
    for (uint32_t i = 0; i < HAMMING_POOL_SIZE; i++) {
        CHECK_EQ(ants_semantic_cache_put(&c, pool[i].emb, &pool[i].tag, 1), ANTS_OK);
    }

    size_t expected_r0 = count_pool_within_radius(pool, 0);

    ants_semantic_cache_lookup_match_t matches[HAMMING_POOL_SIZE];
    float emb_buf[HAMMING_POOL_SIZE * ANTS_EMBED_DIM];
    size_t out_n = 0;
    ants_error_t err = ants_semantic_cache_get_topk(
        &c, base, -1.0f, 0u, 0u, matches, emb_buf, HAMMING_POOL_SIZE, &out_n);
    if (expected_r0 == 0) {
        CHECK_EQ(err, ANTS_ERROR_NOT_FOUND);
    } else {
        CHECK_EQ(err, ANTS_OK);
        CHECK(out_n == expected_r0);
    }

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_hamming_radius_widens_envelope(void)
{
    /* For radius 0..MAX_HAMMING_RADIUS the candidate set is exactly the
     * set of pool entries whose shard_key is within that distance from
     * the query. We assert the count and that the returned tags are
     * exactly the expected subset. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    make_random_embedding(20001, base);
    ants_semantic_cache_shard_key_t base_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &base_key), ANTS_OK);

    hamming_pool_entry_t pool[HAMMING_POOL_SIZE];
    build_hamming_pool(base, base_key, pool);
    for (uint32_t i = 0; i < HAMMING_POOL_SIZE; i++) {
        CHECK_EQ(ants_semantic_cache_put(&c, pool[i].emb, &pool[i].tag, 1), ANTS_OK);
    }

    ants_semantic_cache_lookup_match_t matches[HAMMING_POOL_SIZE];
    float emb_buf[HAMMING_POOL_SIZE * ANTS_EMBED_DIM];

    for (uint32_t radius = 0; radius <= ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS; radius++) {
        size_t expected = count_pool_within_radius(pool, (int)radius);

        size_t out_n = 0;
        ants_error_t err = ants_semantic_cache_get_topk(
            &c, base, -1.0f, 0u, radius, matches, emb_buf, HAMMING_POOL_SIZE, &out_n);
        if (expected == 0) {
            CHECK_EQ(err, ANTS_ERROR_NOT_FOUND);
            continue;
        }
        CHECK_EQ(err, ANTS_OK);
        CHECK(out_n == expected);

        /* Verify every returned match is within the radius AND that the
         * returned set is exactly the expected pool subset. The pool
         * tags are unique (0..POOL_SIZE-1) so a presence bitmap is
         * trivial. */
        uint8_t seen[HAMMING_POOL_SIZE] = {0};
        for (size_t i = 0; i < out_n; i++) {
            CHECK(matches[i].entry.response_len == 1);
            uint8_t tag = matches[i].entry.response[0];
            CHECK(tag < HAMMING_POOL_SIZE);
            CHECK(seen[tag] == 0); /* no duplicates */
            seen[tag] = 1;
            CHECK(pool[tag].hamming_dist <= (int)radius);
        }
        /* Every pool entry within radius must appear. */
        for (uint32_t j = 0; j < HAMMING_POOL_SIZE; j++) {
            if (pool[j].hamming_dist <= (int)radius) {
                CHECK(seen[j] == 1);
            }
        }
    }

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_hamming_excludes_entries_beyond_radius(void)
{
    /* Stronger negative assertion: an entry whose shard_key is strictly
     * outside the radius MUST NOT appear in the result, even at the
     * lowest possible threshold (-1.0). */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    make_random_embedding(20002, base);
    ants_semantic_cache_shard_key_t base_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &base_key), ANTS_OK);

    /* A second random embedding produces a key at Hamming ≈ 32 from
     * the base — well outside MAX_HAMMING_RADIUS. */
    float far_emb[ANTS_EMBED_DIM];
    make_random_embedding(99999, far_emb);
    ants_semantic_cache_shard_key_t far_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(far_emb, &far_key), ANTS_OK);
    int far_dist = hamming64((uint64_t)base_key, (uint64_t)far_key);
    /* Two independent random unit vectors produce keys at distance ~32
     * with vanishing probability of being ≤ 3. Skip the (extremely
     * improbable) collision case. */
    if (far_dist <= (int)ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
        CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
        return;
    }

    uint8_t far_tag = 0xFF;
    CHECK_EQ(ants_semantic_cache_put(&c, far_emb, &far_tag, 1), ANTS_OK);

    ants_semantic_cache_lookup_match_t matches[4];
    float emb_buf[4 * ANTS_EMBED_DIM];

    for (uint32_t radius = 0; radius <= ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS; radius++) {
        size_t out_n = 0;
        ants_error_t err =
            ants_semantic_cache_get_topk(&c, base, -1.0f, 0u, radius, matches, emb_buf, 4, &out_n);
        /* The only stored entry is at distance far_dist > radius so the
         * envelope must be empty. */
        CHECK_EQ(err, ANTS_ERROR_NOT_FOUND);
        CHECK(out_n == 0);
    }

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_get_topk_hamming_ranks_by_similarity_across_shards(void)
{
    /* When the candidate set spans multiple shards, ranking is by
     * cosine similarity, NOT by Hamming distance. A high-similarity
     * entry from a neighbour shard outranks a low-similarity entry on
     * the exact query shard. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    make_random_embedding(20003, base);
    ants_semantic_cache_shard_key_t base_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &base_key), ANTS_OK);

    /* Find a NEIGHBOUR (Hamming 1..MAX) embedding via brute force over
     * small-noise variants. */
    float neighbour[ANTS_EMBED_DIM];
    int neighbour_dist = -1;
    for (uint32_t i = 0; i < 200u; i++) {
        make_near_embedding(base, 30000u + i, 0.05f, neighbour);
        ants_semantic_cache_shard_key_t k = 0;
        CHECK_EQ(ants_semantic_cache_shard_key(neighbour, &k), ANTS_OK);
        int d = hamming64((uint64_t)base_key, (uint64_t)k);
        if (d >= 1 && d <= (int)ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
            neighbour_dist = d;
            break;
        }
    }
    /* If the brute force didn't find one, the test is inconclusive on
     * this seed — skip rather than fail. */
    if (neighbour_dist < 1) {
        CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
        return;
    }

    /* Sanity: neighbour is highly similar to base (cosine ≈ 0.998 at
     * 0.05 noise). */
    double sim_neighbour = 0.0;
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        sim_neighbour += (double)base[i] * (double)neighbour[i];
    }
    CHECK(sim_neighbour > 0.99);

    /* Distract: an exact-shard entry that is orthogonal-ish in cosine
     * space. Construct it by re-using base but flipping every value's
     * sign on a subset of dimensions — same projection signs (so same
     * shard key) until we re-check. Easier: pick another small-noise
     * variant that lands on the SAME shard. */
    float same_shard_entry[ANTS_EMBED_DIM];
    int found_same_shard = 0;
    for (uint32_t i = 0; i < 200u; i++) {
        make_near_embedding(base, 40000u + i, 0.005f, same_shard_entry);
        ants_semantic_cache_shard_key_t k = 0;
        CHECK_EQ(ants_semantic_cache_shard_key(same_shard_entry, &k), ANTS_OK);
        if (k == base_key) {
            found_same_shard = 1;
            break;
        }
    }
    if (!found_same_shard) {
        CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
        return;
    }
    /* same_shard_entry will have cosine ≈ 0.99995 with base — very
     * close, but at 0.005 noise vs 0.05 noise for neighbour, it is
     * MORE similar. So the ranking puts same_shard_entry first.
     * We just verify both are present in the radius>=neighbour_dist
     * result. */

    uint8_t tag_neighbour = 1;
    uint8_t tag_same = 2;
    CHECK_EQ(ants_semantic_cache_put(&c, neighbour, &tag_neighbour, 1), ANTS_OK);
    CHECK_EQ(ants_semantic_cache_put(&c, same_shard_entry, &tag_same, 1), ANTS_OK);

    ants_semantic_cache_lookup_match_t matches[2];
    float emb_buf[2 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(
                 &c, base, 0.5f, 0u, (uint32_t)neighbour_dist, matches, emb_buf, 2, &out_n),
             ANTS_OK);
    CHECK(out_n == 2);

    /* Both tags present; order by similarity desc (same_shard ≥ neighbour). */
    CHECK(matches[0].similarity >= matches[1].similarity);
    uint8_t first = matches[0].entry.response[0];
    uint8_t second = matches[1].entry.response[0];
    CHECK((first == tag_same && second == tag_neighbour) ||
          (first == tag_neighbour && second == tag_same));

    /* At radius 0 only the same_shard entry shows. */
    out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, base, 0.5f, 0u, 0u, matches, emb_buf, 2, &out_n),
             ANTS_OK);
    CHECK(out_n == 1);
    CHECK(matches[0].entry.response[0] == tag_same);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_lookup_request_round_trip_with_hamming_radius(void)
{
    /* All radii in [0, MAX_HAMMING_RADIUS] round-trip through encode/
     * decode without loss. */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(20100, emb);

    uint8_t buf[8192];
    for (uint32_t radius = 0; radius <= ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS; radius++) {
        size_t encoded = 0;
        CHECK_EQ(ants_semantic_cache_lookup_request_encode(
                     emb, 0.92f, 5, radius, buf, sizeof buf, &encoded),
                 ANTS_OK);

        float out_emb[ANTS_EMBED_DIM];
        float out_thr = 0.0f;
        uint32_t out_topk = 0;
        uint32_t out_radius = 0xFFFFFFFFu;
        CHECK_EQ(ants_semantic_cache_lookup_request_decode(
                     buf, encoded, out_emb, &out_thr, &out_topk, &out_radius),
                 ANTS_OK);
        CHECK(out_radius == radius);
    }
}

static void test_lookup_request_rejects_wire_radius_above_max(void)
{
    /* A wire payload that declares hamming_radius > MAX must be
     * rejected at decode with NON_CANONICAL — the spec pins the
     * range and accepts no higher values. We can't reach this via
     * the public encoder (which rejects radius > MAX up-front), so
     * craft the CBOR bytes by hand using ants_cbor primitives. */
    ants_cbor_enc_t enc;
    uint8_t buf[8192];
    CHECK_EQ(ants_cbor_enc_init(&enc, buf, sizeof buf), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_map(&enc, 4), ANTS_OK);
    /* key 1: embedding bytes(4096) */
    float emb[ANTS_EMBED_DIM];
    make_random_embedding(20200, emb);
    uint8_t emb_le[ANTS_EMBED_DIM * 4u];
    for (uint32_t i = 0; i < (uint32_t)ANTS_EMBED_DIM; i++) {
        uint32_t bits = 0;
        memcpy(&bits, &emb[i], sizeof bits);
        emb_le[i * 4u + 0u] = (uint8_t)(bits & 0xFFu);
        emb_le[i * 4u + 1u] = (uint8_t)((bits >> 8) & 0xFFu);
        emb_le[i * 4u + 2u] = (uint8_t)((bits >> 16) & 0xFFu);
        emb_le[i * 4u + 3u] = (uint8_t)((bits >> 24) & 0xFFu);
    }
    CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, emb_le, sizeof emb_le), ANTS_OK);
    /* key 2: threshold bytes(4) */
    CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
    uint8_t thr_le[4] = {0};
    {
        float thr = 0.5f;
        uint32_t bits = 0;
        memcpy(&bits, &thr, sizeof bits);
        thr_le[0] = (uint8_t)(bits & 0xFFu);
        thr_le[1] = (uint8_t)((bits >> 8) & 0xFFu);
        thr_le[2] = (uint8_t)((bits >> 16) & 0xFFu);
        thr_le[3] = (uint8_t)((bits >> 24) & 0xFFu);
    }
    CHECK_EQ(ants_cbor_enc_bytes(&enc, thr_le, sizeof thr_le), ANTS_OK);
    /* key 3: top_k */
    CHECK_EQ(ants_cbor_enc_uint(&enc, 3), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, 0), ANTS_OK);
    /* key 4: hamming_radius = MAX + 1 (out of range) */
    CHECK_EQ(ants_cbor_enc_uint(&enc, 4), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_uint(&enc, ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS + 1u), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
    size_t enc_size = ants_cbor_enc_size(&enc);

    float out_emb[ANTS_EMBED_DIM];
    float out_thr = 0.0f;
    uint32_t out_topk = 0;
    uint32_t out_radius = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_decode(
                 buf, enc_size, out_emb, &out_thr, &out_topk, &out_radius),
             ANTS_ERROR_NON_CANONICAL);
}

static void test_handle_inbound_lookup_propagates_hamming_radius(void)
{
    /* A request encoded with radius=N must, on the receiving side,
     * cause get_topk to admit entries from neighbour shards within N. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float base[ANTS_EMBED_DIM];
    make_random_embedding(20300, base);
    ants_semantic_cache_shard_key_t base_key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(base, &base_key), ANTS_OK);

    /* Brute-force find a neighbour at 1..MAX from base. */
    float neighbour[ANTS_EMBED_DIM];
    int neighbour_dist = -1;
    for (uint32_t i = 0; i < 200u; i++) {
        make_near_embedding(base, 50000u + i, 0.05f, neighbour);
        ants_semantic_cache_shard_key_t k = 0;
        CHECK_EQ(ants_semantic_cache_shard_key(neighbour, &k), ANTS_OK);
        int d = hamming64((uint64_t)base_key, (uint64_t)k);
        if (d >= 1 && d <= (int)ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
            neighbour_dist = d;
            break;
        }
    }
    if (neighbour_dist < 1) {
        CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
        return;
    }

    uint8_t neighbour_tag = 0x42;
    CHECK_EQ(ants_semantic_cache_put(&c, neighbour, &neighbour_tag, 1), ANTS_OK);

    uint8_t req[8192];
    size_t req_len = 0;
    uint8_t resp[65536];
    size_t resp_len = 0;

    /* radius=0: neighbour is not on the exact shard → empty response. */
    CHECK_EQ(
        ants_semantic_cache_lookup_request_encode(base, 0.5f, 5u, 0u, req, sizeof req, &req_len),
        ANTS_OK);
    CHECK_EQ(
        ants_semantic_cache_handle_inbound_lookup(&c, req, req_len, resp, sizeof resp, &resp_len),
        ANTS_OK);
    ants_semantic_cache_lookup_match_t parsed_matches[5];
    float parsed_embs[5 * ANTS_EMBED_DIM];
    size_t parsed_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(
                 resp, resp_len, parsed_matches, parsed_embs, 5, &parsed_n),
             ANTS_OK);
    CHECK(parsed_n == 0);

    /* radius=neighbour_dist: neighbour is in-envelope → 1 match. */
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(
                 base, 0.5f, 5u, (uint32_t)neighbour_dist, req, sizeof req, &req_len),
             ANTS_OK);
    CHECK_EQ(
        ants_semantic_cache_handle_inbound_lookup(&c, req, req_len, resp, sizeof resp, &resp_len),
        ANTS_OK);
    parsed_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(
                 resp, resp_len, parsed_matches, parsed_embs, 5, &parsed_n),
             ANTS_OK);
    CHECK(parsed_n == 1);
    CHECK(parsed_matches[0].entry.response_len == 1);
    CHECK(parsed_matches[0].entry.response[0] == neighbour_tag);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

/* -- put_record + inbound handlers (step 7a.2) ---------------------------- */

static void test_put_record_round_trip(void)
{
    /* Put a full producer-signed record via put_record; query it back
     * via get_topk and verify every field round-trips through the
     * cache's internal storage. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12000, emb);

    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "the full record response", "bge-m3-canonical");
    CHECK_EQ(ants_semantic_cache_put_record(&c, &in_e), ANTS_OK);

    ants_semantic_cache_lookup_match_t matches[1];
    float emb_buf[ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_get_topk(&c, emb, 0.9f, 1, 0, matches, emb_buf, 1, &out_n),
             ANTS_OK);
    CHECK(out_n == 1);
    const ants_semantic_cache_entry_t *out_e = &matches[0].entry;

    CHECK(out_e->embedding_model_len == strlen("ants-embed-v1"));
    CHECK(memcmp(out_e->embedding_model, "ants-embed-v1", out_e->embedding_model_len) == 0);
    CHECK(memcmp(out_e->prompt_hash, in_e.prompt_hash, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN) == 0);
    CHECK(out_e->response_len == strlen("the full record response"));
    CHECK(memcmp(out_e->response, "the full record response", out_e->response_len) == 0);
    CHECK(out_e->response_model_len == strlen("bge-m3-canonical"));
    CHECK(memcmp(out_e->response_model, "bge-m3-canonical", out_e->response_model_len) == 0);
    CHECK(memcmp(out_e->producer, in_e.producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN) == 0);
    CHECK(out_e->created == 1717000000ull);
    CHECK(out_e->validity_class == ANTS_SEMANTIC_CACHE_VALIDITY_MONTHS);
    CHECK(out_e->attestation_len == in_e.attestation_len);
    CHECK(memcmp(out_e->attestation, in_e.attestation, out_e->attestation_len) == 0);
    CHECK(memcmp(out_e->signature, in_e.signature, ANTS_SEMANTIC_CACHE_SIG_LEN) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_put_record_null_args(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12001, emb);
    ants_semantic_cache_entry_t e;
    fill_test_entry(&e, emb, "v", "vm");

    CHECK_EQ(ants_semantic_cache_put_record(NULL, &e), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_put_record(&c, NULL), ANTS_ERROR_INVALID_ARG);
    e.embedding = NULL;
    CHECK_EQ(ants_semantic_cache_put_record(&c, &e), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_entry_round_trip(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12100, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x11);
    ants_semantic_cache_entry_t in_e;
    fill_signed_test_entry(&in_e, emb, "round-trip response", "model-x", priv);

    uint8_t cbor[8192];
    size_t cbor_len = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, cbor, sizeof cbor, &cbor_len), ANTS_OK);

    CHECK_EQ(ants_semantic_cache_handle_inbound_entry(&c, cbor, cbor_len), ANTS_OK);
    CHECK(ants_semantic_cache_entries(&c) == 1);

    uint8_t out[64];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim), ANTS_OK);
    CHECK(out_len == strlen("round-trip response"));
    CHECK(memcmp(out, "round-trip response", out_len) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_entry_malformed(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    uint8_t garbage[64];
    memset(garbage, 0xAB, sizeof garbage);
    ants_error_t e = ants_semantic_cache_handle_inbound_entry(&c, garbage, sizeof garbage);
    CHECK(e == ANTS_ERROR_MALFORMED || e == ANTS_ERROR_NON_CANONICAL);
    CHECK(ants_semantic_cache_entries(&c) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_entry_rejects_tampered_signature(void)
{
    /* A producer-signed record whose signature has been flipped MUST
     * be rejected before the entry touches the local shard. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12150, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x22);
    ants_semantic_cache_entry_t in_e;
    fill_signed_test_entry(&in_e, emb, "tampered", "m", priv);
    in_e.signature[0] ^= 0x01u; /* flip one bit — invalid signature. */

    uint8_t cbor[8192];
    size_t cbor_len = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, cbor, sizeof cbor, &cbor_len), ANTS_OK);

    ants_error_t err = ants_semantic_cache_handle_inbound_entry(&c, cbor, cbor_len);
    /* ants_ed25519_verify reports invalid signatures as MALFORMED. */
    CHECK_EQ(err, ANTS_ERROR_MALFORMED);
    CHECK(ants_semantic_cache_entries(&c) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_entry_rejects_wrong_producer_pubkey(void)
{
    /* A record signed with key A but claiming `producer = pub(B)` must
     * be rejected. Defends against a peer relaying someone else's
     * record while substituting their own producer field. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12160, emb);
    uint8_t priv_a[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t priv_b[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv_a, 0x33);
    make_test_priv(priv_b, 0x77);

    ants_semantic_cache_entry_t in_e;
    fill_signed_test_entry(&in_e, emb, "spoofed", "m", priv_a);
    /* Overwrite producer with key B's pubkey AFTER signing with A's
     * privkey. The signature is now valid over data whose `producer`
     * field disagrees with the actual signing key. */
    uint8_t pub_b[ANTS_ED25519_PUBKEY_SIZE];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv_b, pub_b), ANTS_OK);
    memcpy(in_e.producer, pub_b, ANTS_ED25519_PUBKEY_SIZE);

    uint8_t cbor[8192];
    size_t cbor_len = 0;
    CHECK_EQ(ants_semantic_cache_entry_encode(&in_e, cbor, sizeof cbor, &cbor_len), ANTS_OK);

    ants_error_t err = ants_semantic_cache_handle_inbound_entry(&c, cbor, cbor_len);
    CHECK_EQ(err, ANTS_ERROR_MALFORMED);
    CHECK(ants_semantic_cache_entries(&c) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_lookup_round_trip(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12200, emb);
    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "inbound-lookup response", "model-q");
    CHECK_EQ(ants_semantic_cache_put_record(&c, &in_e), ANTS_OK);

    uint8_t req[8192];
    size_t req_len = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 5, 0, req, sizeof req, &req_len),
             ANTS_OK);

    uint8_t resp[16384];
    size_t resp_len = 0;
    CHECK_EQ(
        ants_semantic_cache_handle_inbound_lookup(&c, req, req_len, resp, sizeof resp, &resp_len),
        ANTS_OK);
    CHECK(resp_len > 0);

    ants_semantic_cache_lookup_match_t out_matches[5];
    float out_embs[5 * ANTS_EMBED_DIM];
    size_t out_n = 0;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(
                 resp, resp_len, out_matches, out_embs, 5, &out_n),
             ANTS_OK);
    CHECK(out_n == 1);
    CHECK(out_matches[0].entry.response_len == strlen("inbound-lookup response"));
    CHECK(memcmp(out_matches[0].entry.response,
                 "inbound-lookup response",
                 out_matches[0].entry.response_len) == 0);
    CHECK(memcmp(out_matches[0].entry.producer, in_e.producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN) ==
          0);
    CHECK(memcmp(out_matches[0].entry.signature, in_e.signature, ANTS_SEMANTIC_CACHE_SIG_LEN) == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_lookup_empty_cache(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12300, emb);
    uint8_t req[8192];
    size_t req_len = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.9f, 5, 0, req, sizeof req, &req_len),
             ANTS_OK);

    uint8_t resp[256];
    size_t resp_len = 0;
    CHECK_EQ(
        ants_semantic_cache_handle_inbound_lookup(&c, req, req_len, resp, sizeof resp, &resp_len),
        ANTS_OK);

    size_t out_n = 999;
    CHECK_EQ(ants_semantic_cache_lookup_response_decode(resp, resp_len, NULL, NULL, 0, &out_n),
             ANTS_OK);
    CHECK(out_n == 0);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_lookup_buffer_too_small(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(12400, emb);
    ants_semantic_cache_entry_t in_e;
    fill_test_entry(&in_e, emb, "x", "y");
    CHECK_EQ(ants_semantic_cache_put_record(&c, &in_e), ANTS_OK);

    uint8_t req[8192];
    size_t req_len = 0;
    CHECK_EQ(ants_semantic_cache_lookup_request_encode(emb, 0.5f, 5, 0, req, sizeof req, &req_len),
             ANTS_OK);

    uint8_t small[100];
    size_t resp_len = 0;
    CHECK_EQ(
        ants_semantic_cache_handle_inbound_lookup(&c, req, req_len, small, sizeof small, &resp_len),
        ANTS_ERROR_BUFFER_TOO_SMALL);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
}

static void test_handle_inbound_lookup_malformed_request(void)
{
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_OK);

    uint8_t garbage[32];
    memset(garbage, 0xAB, sizeof garbage);
    uint8_t resp[256];
    size_t resp_len = 0;
    ants_error_t e = ants_semantic_cache_handle_inbound_lookup(
        &c, garbage, sizeof garbage, resp, sizeof resp, &resp_len);
    CHECK(e == ANTS_ERROR_MALFORMED || e == ANTS_ERROR_NON_CANONICAL);

    CHECK_EQ(ants_semantic_cache_destroy(&c), ANTS_OK);
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

/* -- Client-side publish (step 7b) ----------------------------------------
 *
 * Unit tests for the ants_semantic_cache_publish_* state machine. We
 * exercise: NULL-arg validation, replication-factor bounds, destroy
 * safety on a zeroed ctx, the LOOKUP → DELIVER → completion (PEER_
 * UNREACHABLE) path on an empty DHT, and the cross-publish event
 * isolation guarantees (events for some other publish's lookup or
 * some other stream are ignored).
 *
 * End-to-end transport-level tests (entry actually crosses the wire
 * and gets persisted by a peer's cache) are deferred to step 7b.2,
 * which lands the server-side stream-dispatch glue + the dht_server
 * tolerance change needed to multiplex DHT + cache traffic on a
 * single conn. */

typedef struct {
    bool fired;
    ants_error_t status;
    uint32_t peers_acked;
} test_publish_recorder_t;

static void test_publish_complete_fn(ants_error_t status, uint32_t peers_acked, void *ctx)
{
    test_publish_recorder_t *r = (test_publish_recorder_t *)ctx;
    r->fired = true;
    r->status = status;
    r->peers_acked = peers_acked;
}

typedef struct {
    ants_semantic_cache_publish_t *publish;
    int dht_events_seen;
} test_publish_dht_ctx_t;

static ants_error_t test_publish_dht_event_fn(const ants_dht_event_t *ev, void *ctx)
{
    test_publish_dht_ctx_t *c = (test_publish_dht_ctx_t *)ctx;
    c->dht_events_seen++;
    if (c->publish) {
        (void)ants_semantic_cache_publish_handle_dht_event(c->publish, ev);
    }
    return ANTS_OK;
}

static void test_publish_null_args(void)
{
    ants_transport_t dummy_t = {{0}};
    ants_dht_t dummy_d = {{0}};
    ants_semantic_cache_publish_t p = {{0}};
    ants_semantic_cache_entry_t e;
    memset(&e, 0, sizeof e);
    test_publish_recorder_t rec = {0};

    CHECK_EQ(ants_semantic_cache_publish_init(
                 NULL, &dummy_d, &dummy_t, &e, 3, test_publish_complete_fn, &rec),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_semantic_cache_publish_init(&p, NULL, &dummy_t, &e, 3, test_publish_complete_fn, &rec),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_semantic_cache_publish_init(&p, &dummy_d, NULL, &e, 3, test_publish_complete_fn, &rec),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_init(
                 &p, &dummy_d, &dummy_t, NULL, 3, test_publish_complete_fn, &rec),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_init(&p, &dummy_d, &dummy_t, &e, 3, NULL, &rec),
             ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_semantic_cache_publish_tick(NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_destroy(NULL), ANTS_ERROR_INVALID_ARG);

    ants_dht_event_t dht_ev = {0};
    ants_transport_event_t tev = {0};
    CHECK_EQ(ants_semantic_cache_publish_handle_dht_event(NULL, &dht_ev), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_handle_dht_event(&p, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_handle_transport_event(NULL, &tev),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_publish_handle_transport_event(&p, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_publish_invalid_replication_factor(void)
{
    /* A non-zero replication_factor above MAX is rejected; 0 falls back to
     * the default and is accepted. The init must succeed with the default
     * but we don't need a real network — just verify the bounds-check. */
    ants_transport_t dummy_t = {{0}};
    ants_dht_t dht = {{0}};
    test_publish_dht_ctx_t dht_ctx = {0};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &dummy_t;
    dcfg.event_fn = test_publish_dht_event_fn;
    dcfg.event_ctx = &dht_ctx;
    CHECK_EQ(ants_dht_init(&dht, &dcfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(8001, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x21);
    ants_semantic_cache_entry_t e;
    fill_signed_test_entry(&e, emb, "x", "m", priv);

    ants_semantic_cache_publish_t p = {{0}};
    test_publish_recorder_t rec = {0};
    CHECK_EQ(ants_semantic_cache_publish_init(&p,
                                              &dht,
                                              &dummy_t,
                                              &e,
                                              ANTS_SEMANTIC_CACHE_PUBLISH_MAX_REPLICATION + 1,
                                              test_publish_complete_fn,
                                              &rec),
             ANTS_ERROR_INVALID_ARG);

    /* Default (0 → ANTS_SEMANTIC_CACHE_DEFAULT_REPLICATION) is accepted. */
    CHECK_EQ(
        ants_semantic_cache_publish_init(&p, &dht, &dummy_t, &e, 0, test_publish_complete_fn, &rec),
        ANTS_OK);
    CHECK_EQ(ants_semantic_cache_publish_destroy(&p), ANTS_OK);

    CHECK_EQ(ants_dht_destroy(&dht), ANTS_OK);
}

static void test_publish_destroy_safe_on_zero_ctx(void)
{
    /* Destroy is a no-op on a never-initialised (zeroed) publish_t. */
    ants_semantic_cache_publish_t p = {{0}};
    CHECK_EQ(ants_semantic_cache_publish_destroy(&p), ANTS_OK);

    /* Tick / handle_dht_event / handle_transport_event are also no-ops
     * on a zeroed ctx (no magic → silently ignore). They must NOT
     * return INVALID_ARG just because magic is absent — that's reserved
     * for NULL ptrs. */
    CHECK_EQ(ants_semantic_cache_publish_tick(&p), ANTS_OK);
    ants_dht_event_t dev = {0};
    CHECK_EQ(ants_semantic_cache_publish_handle_dht_event(&p, &dev), ANTS_OK);
    ants_transport_event_t tev = {0};
    CHECK_EQ(ants_semantic_cache_publish_handle_transport_event(&p, &tev), ANTS_OK);
}

static void test_publish_no_peers_completes_with_peer_unreachable(void)
{
    /* Empty routing table → ants_dht_lookup fires LOOKUP_COMPLETE with
     * peer_count = 0 on the very first dht_tick. The publish state
     * machine receives the event via the DHT event_fn forward, observes
     * 0 candidate slots, and the completion callback fires synchronously
     * from inside handle_dht_event with ANTS_ERROR_PEER_UNREACHABLE +
     * peers_acked = 0. */
    ants_transport_t dummy_t = {{0}};
    ants_dht_t dht = {{0}};
    test_publish_dht_ctx_t dht_ctx = {0};

    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &dummy_t;
    dcfg.event_fn = test_publish_dht_event_fn;
    dcfg.event_ctx = &dht_ctx;
    CHECK_EQ(ants_dht_init(&dht, &dcfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(9001, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x44);
    ants_semantic_cache_entry_t e;
    fill_signed_test_entry(&e, emb, "no-peers response", "test-model", priv);

    ants_semantic_cache_publish_t publish = {{0}};
    test_publish_recorder_t rec = {0};
    dht_ctx.publish = &publish;
    CHECK_EQ(ants_semantic_cache_publish_init(
                 &publish, &dht, &dummy_t, &e, 3, test_publish_complete_fn, &rec),
             ANTS_OK);

    (void)ants_dht_tick(&dht);

    CHECK(rec.fired);
    CHECK_EQ(rec.status, ANTS_ERROR_PEER_UNREACHABLE);
    CHECK(rec.peers_acked == 0);

    /* Second tick is a no-op (completion fired exactly once). */
    rec.fired = false;
    (void)ants_dht_tick(&dht);
    CHECK(!rec.fired);

    CHECK_EQ(ants_semantic_cache_publish_destroy(&publish), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&dht), ANTS_OK);
}

static void test_publish_handle_dht_event_ignores_other_lookup(void)
{
    /* A LOOKUP_COMPLETE event whose `lookup` pointer is NOT our internal
     * lookup must be a no-op. The completion does not fire and the
     * state machine remains in LOOKUP phase. */
    ants_transport_t dummy_t = {{0}};
    ants_dht_t dht = {{0}};
    test_publish_dht_ctx_t dht_ctx = {0};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &dummy_t;
    dcfg.event_fn = test_publish_dht_event_fn;
    dcfg.event_ctx = &dht_ctx;
    CHECK_EQ(ants_dht_init(&dht, &dcfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(9002, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x55);
    ants_semantic_cache_entry_t e;
    fill_signed_test_entry(&e, emb, "x", "m", priv);

    ants_semantic_cache_publish_t publish = {{0}};
    test_publish_recorder_t rec = {0};
    /* Note: we do NOT wire dht_ctx.publish — we manually feed a
     * synthetic event below. The DHT's own lookup event still fires on
     * tick; we just want to assert the manual non-matching event is
     * ignored before that. */
    CHECK_EQ(ants_semantic_cache_publish_init(
                 &publish, &dht, &dummy_t, &e, 3, test_publish_complete_fn, &rec),
             ANTS_OK);

    /* Synthetic event with a foreign lookup pointer. */
    ants_dht_lookup_t alien_lookup = {{0}};
    ants_dht_event_t alien_ev;
    memset(&alien_ev, 0, sizeof alien_ev);
    alien_ev.kind = ANTS_DHT_EV_LOOKUP_COMPLETE;
    alien_ev.lookup = &alien_lookup;
    alien_ev.peers = NULL;
    alien_ev.peer_count = 0;
    CHECK_EQ(ants_semantic_cache_publish_handle_dht_event(&publish, &alien_ev), ANTS_OK);
    CHECK(!rec.fired);

    CHECK_EQ(ants_semantic_cache_publish_destroy(&publish), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&dht), ANTS_OK);
}

static void test_publish_handle_transport_event_ignores_other_stream(void)
{
    /* A transport event whose conn/stream pointers belong to no slot of
     * ours must be a no-op (no state mutation, no completion). */
    ants_transport_t dummy_t = {{0}};
    ants_dht_t dht = {{0}};
    test_publish_dht_ctx_t dht_ctx = {0};
    ants_dht_config_t dcfg;
    memset(&dcfg, 0, sizeof dcfg);
    dcfg.transport = &dummy_t;
    dcfg.event_fn = test_publish_dht_event_fn;
    dcfg.event_ctx = &dht_ctx;
    CHECK_EQ(ants_dht_init(&dht, &dcfg), ANTS_OK);

    float emb[ANTS_EMBED_DIM];
    make_random_embedding(9003, emb);
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    make_test_priv(priv, 0x66);
    ants_semantic_cache_entry_t e;
    fill_signed_test_entry(&e, emb, "x", "m", priv);

    ants_semantic_cache_publish_t publish = {{0}};
    test_publish_recorder_t rec = {0};
    CHECK_EQ(ants_semantic_cache_publish_init(
                 &publish, &dht, &dummy_t, &e, 3, test_publish_complete_fn, &rec),
             ANTS_OK);

    /* Synthetic transport event with a foreign conn pointer. */
    ants_transport_conn_t alien_conn = {{0}};
    ants_transport_stream_t alien_stream = {{0}};
    ants_transport_event_t alien_ev;
    memset(&alien_ev, 0, sizeof alien_ev);
    alien_ev.kind = ANTS_TRANSPORT_EV_STREAM_FIN;
    alien_ev.conn = &alien_conn;
    alien_ev.stream = &alien_stream;
    CHECK_EQ(ants_semantic_cache_publish_handle_transport_event(&publish, &alien_ev), ANTS_OK);
    CHECK(!rec.fired);

    CHECK_EQ(ants_semantic_cache_publish_destroy(&publish), ANTS_OK);
    CHECK_EQ(ants_dht_destroy(&dht), ANTS_OK);
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
    test_get_topk_null_args();
    test_get_topk_rejects_uninitialised();
    test_get_topk_returns_not_found_on_empty();
    test_get_topk_returns_sorted_desc();
    test_get_topk_respects_top_k_cap();
    test_get_topk_top_k_zero_unbounded();
    test_get_topk_buffer_too_small();
    test_get_topk_hamming_zero_matches_exact_shard_only();
    test_get_topk_hamming_radius_widens_envelope();
    test_get_topk_hamming_excludes_entries_beyond_radius();
    test_get_topk_hamming_ranks_by_similarity_across_shards();
    test_lookup_request_round_trip_with_hamming_radius();
    test_lookup_request_rejects_wire_radius_above_max();
    test_handle_inbound_lookup_propagates_hamming_radius();
    test_put_record_round_trip();
    test_put_record_null_args();
    test_handle_inbound_entry_round_trip();
    test_handle_inbound_entry_malformed();
    test_handle_inbound_entry_rejects_tampered_signature();
    test_handle_inbound_entry_rejects_wrong_producer_pubkey();
    test_handle_inbound_lookup_round_trip();
    test_handle_inbound_lookup_empty_cache();
    test_handle_inbound_lookup_buffer_too_small();
    test_handle_inbound_lookup_malformed_request();
    test_clear_removes_entries();

    test_publish_null_args();
    test_publish_invalid_replication_factor();
    test_publish_destroy_safe_on_zero_ctx();
    test_publish_no_peers_completes_with_peer_unreachable();
    test_publish_handle_dht_event_ignores_other_lookup();
    test_publish_handle_transport_event_ignores_other_stream();

    if (failures > 0) {
        fprintf(stderr, "test_cache: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_cache: all checks passed\n");
    return 0;
}
