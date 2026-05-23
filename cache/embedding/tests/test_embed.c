/*
 * test_embed.c — tests for the canonical embedding service (Component #11).
 *
 * Phase 0 scaffold: pins the API contract via constants and stub
 * return values so subsequent implementation PRs can't silently change
 * shape. Same pattern as foundation/cbor's early phase and
 * foundation/tee's stub PRs.
 *
 *   - Public constants match the RFC-0008 §5 spec.
 *   - Opaque ctx size + alignment match documented constants.
 *   - Stub return values match what ants_embed.h documents
 *     (NOT_IMPLEMENTED for actions; INVALID_ARG for NULL/zero-shape
 *     inputs).
 *   - Pinned hashes are placeholder all-zero per RFC-0008 §5 (the v1
 *     values land in a phase-5 PR jointly with the ants-test-vectors
 *     bundle publication).
 */

#include "ants_common.h"
#include "ants_embed.h"

#include <stdbool.h>
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

static void test_pinned_constants(void)
{
    /* RFC-0008 §5 — these constants are protocol-level cross-peer
     * agreement; any change is a protocol break. */
    CHECK(ANTS_EMBED_DIM == 1024);

    /* model_id is "ants-embed-v1" per RFC-0002 §The canonical
     * embedding model. */
    CHECK(ANTS_EMBED_MODEL_ID != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ID, "ants-embed-v1") == 0);

    /* arch is "bge-m3" per RFC-0002 v0.1 selection. */
    CHECK(ANTS_EMBED_MODEL_ARCH != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ARCH, "bge-m3") == 0);

    /* Pinned hashes are placeholder all-zero per RFC-0008 §5: "the
     * specific 32-byte values for v1 will be set when the reference
     * client is published". Until then, ants_embed_init refuses to
     * start (NOT_IMPLEMENTED). */
    uint8_t zero[32] = {0};
    CHECK(memcmp(ANTS_EMBED_WEIGHTS_HASH_PINNED, zero, 32) == 0);
    CHECK(memcmp(ANTS_EMBED_TOKENIZER_HASH_PINNED, zero, 32) == 0);
}

static void test_opaque_ctx_layout(void)
{
    /* ants_embed_t is uint64_t-aligned via the union's _align member.
     * Verify by checking that a stack-allocated instance's address is
     * 8-byte aligned and the sizeof matches the constant. */
    ants_embed_t e;
    CHECK(((uintptr_t)&e & 7u) == 0);
    CHECK(sizeof e == ANTS_EMBED_CTX_SIZE);
    /* Starting estimate is 64 KiB; tightening or growing it is a
     * binary-compat break for downstream consumers compiled against
     * this header — recorded here so a shrink in a future PR forces
     * the conversation. */
    CHECK(ANTS_EMBED_CTX_SIZE == 65536);
}

static void test_init_rejects_invalid_args(void)
{
    ants_embed_t e = {{0}};
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);

    /* NULL ctx or config. */
    CHECK_EQ(ants_embed_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed_init(&e, NULL), ANTS_ERROR_INVALID_ARG);

    /* NULL or zero-length weights. */
    cfg.weights = NULL;
    cfg.weights_len = 0;
    cfg.tokenizer = (const uint8_t *)"x";
    cfg.tokenizer_len = 1;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    cfg.weights = (const uint8_t *)"w";
    cfg.weights_len = 0;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    /* NULL or zero-length tokenizer. */
    cfg.weights = (const uint8_t *)"w";
    cfg.weights_len = 1;
    cfg.tokenizer = NULL;
    cfg.tokenizer_len = 1;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    cfg.tokenizer = (const uint8_t *)"x";
    cfg.tokenizer_len = 0;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);
}

static void test_init_returns_not_implemented(void)
{
    /* Well-shaped args: still returns NOT_IMPLEMENTED in the scaffold
     * phase. The next implementation PR will make this return ANTS_OK
     * when the buffers match the pinned hashes (and NON_CANONICAL
     * when they don't). */
    ants_embed_t e = {{0}};
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = (const uint8_t *)"weights";
    cfg.weights_len = 7;
    cfg.tokenizer = (const uint8_t *)"tokenizer";
    cfg.tokenizer_len = 9;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_destroy_rejects_null(void)
{
    CHECK_EQ(ants_embed_destroy(NULL), ANTS_ERROR_INVALID_ARG);

    /* destroy on a zeroed ctx is a no-op (the docstring guarantees
     * safe re-init pattern). */
    ants_embed_t e = {{0}};
    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

static void test_embed_rejects_invalid_args(void)
{
    ants_embed_t e = {{0}};
    float out[ANTS_EMBED_DIM];
    memset(out, 0, sizeof out);

    /* NULL guards. */
    CHECK_EQ(ants_embed(NULL, (const uint8_t *)"in", 2, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed(&e, NULL, 2, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"in", 2, NULL), ANTS_ERROR_INVALID_ARG);

    /* Zero-length input. */
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"in", 0, out), ANTS_ERROR_INVALID_ARG);
}

static void test_embed_returns_not_implemented(void)
{
    /* Well-shaped args on a zeroed ctx: stub returns NOT_IMPLEMENTED.
     * The phase-4 ggml-backed implementation will require init first
     * (a future test will check that an uninitialised ctx is rejected
     * with INVALID_ARG even on well-shaped args; for now the stub
     * doesn't distinguish — same NOT_IMPLEMENTED either way). */
    ants_embed_t e = {{0}};
    float out[ANTS_EMBED_DIM];
    memset(out, 0, sizeof out);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"the canonical input", 19, out),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_init_returns_not_implemented();
    test_destroy_rejects_null();
    test_embed_rejects_invalid_args();
    test_embed_returns_not_implemented();

    if (failures > 0) {
        fprintf(stderr, "test_embed: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_embed: all checks passed\n");
    return 0;
}
