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

static void test_init_scaffold_returns_not_implemented(void)
{
    /* At scaffold, init with valid args still bails NOT_IMPLEMENTED.
     * Subsequent steps will flip this to ANTS_OK. */
    ants_semantic_cache_t c = {{0}};
    ants_semantic_cache_config_t cfg = {0};
    CHECK_EQ(ants_semantic_cache_init(&c, &cfg), ANTS_ERROR_NOT_IMPLEMENTED);
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

static void test_put_scaffold_returns_not_implemented(void)
{
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    const uint8_t value[] = {'v', 'a', 'l'};
    CHECK_EQ(ants_semantic_cache_put(&c, emb, value, 3), ANTS_ERROR_NOT_IMPLEMENTED);
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

static void test_get_scaffold_returns_not_implemented(void)
{
    ants_semantic_cache_t c = {{0}};
    float emb[ANTS_EMBED_DIM] = {0};
    uint8_t out[16];
    size_t out_len = 0;
    float sim = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, out, sizeof out, &out_len, &sim),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* out_value == NULL is allowed (caller may probe required size). */
    out_len = 0;
    CHECK_EQ(ants_semantic_cache_get(&c, emb, 0.9f, NULL, 0, &out_len, &sim),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_shard_key_null_args(void)
{
    float emb[ANTS_EMBED_DIM] = {0};
    ants_semantic_cache_shard_key_t key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(NULL, &key), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_shard_key(emb, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_shard_key_scaffold_returns_not_implemented(void)
{
    float emb[ANTS_EMBED_DIM] = {0};
    ants_semantic_cache_shard_key_t key = 0;
    CHECK_EQ(ants_semantic_cache_shard_key(emb, &key), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_entries_safe_on_zero_or_null(void)
{
    /* Diagnostic accessor never errors — returns 0 on null/zeroed ctx. */
    CHECK(ants_semantic_cache_entries(NULL) == 0);
    ants_semantic_cache_t c = {{0}};
    CHECK(ants_semantic_cache_entries(&c) == 0);
}

static void test_clear_null_and_scaffold(void)
{
    ants_semantic_cache_t c = {{0}};
    CHECK_EQ(ants_semantic_cache_clear(NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_semantic_cache_clear(&c), ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_protocol_constants();
    test_opaque_ctx_layout();
    test_init_null_args();
    test_init_scaffold_returns_not_implemented();
    test_destroy_safe_on_zero_ctx();
    test_put_null_args();
    test_put_scaffold_returns_not_implemented();
    test_get_null_args();
    test_get_scaffold_returns_not_implemented();
    test_shard_key_null_args();
    test_shard_key_scaffold_returns_not_implemented();
    test_entries_safe_on_zero_or_null();
    test_clear_null_and_scaffold();

    if (failures > 0) {
        fprintf(stderr, "test_cache: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_cache: all checks passed\n");
    return 0;
}
