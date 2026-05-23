/*
 * test_embed.c — tests for the canonical embedding service (Component #11).
 *
 * Phase 3 + phase 4-stub. Covers:
 *
 *   - Public constants match RFC-0008 §5 spec (model_id, arch,
 *     dim, placeholder hashes).
 *   - Opaque ctx size + alignment match documented constants.
 *   - Init NULL/zero-shape arg validation (unchanged from scaffold).
 *   - Init verify path: placeholder hashes → OK; mismatched non-zero
 *     pinned hash → NON_CANONICAL (exercised via the
 *     __test_verify hook so the path is covered before phase 5
 *     pins the real BGE-M3 hashes).
 *   - Embed determinism: same input → same 1024-dim output.
 *   - Embed distinctness: different input → different output.
 *   - Embed normalisation: output is L2-unit-norm.
 *   - Embed rejects an uninitialised ctx.
 *   - Destroy safety on a zeroed ctx.
 */

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_embed.h"

#include <math.h>
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

/* Test hook from embed.c — exposes the verify path so we can test
 * both code paths (placeholder + non-zero pinned) even while the
 * public ANTS_EMBED_*_HASH_PINNED constants are still all-zero. */
extern ants_error_t
ants_embed__test_verify(const uint8_t *buf, size_t len, const uint8_t pinned[32]);

static void test_pinned_constants(void)
{
    CHECK(ANTS_EMBED_DIM == 1024);
    CHECK(ANTS_EMBED_MODEL_ID != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ID, "ants-embed-v1") == 0);
    CHECK(ANTS_EMBED_MODEL_ARCH != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ARCH, "bge-m3") == 0);

    /* Pinned hashes are placeholder all-zero per RFC-0008 §5. */
    uint8_t zero[32] = {0};
    CHECK(memcmp(ANTS_EMBED_WEIGHTS_HASH_PINNED, zero, 32) == 0);
    CHECK(memcmp(ANTS_EMBED_TOKENIZER_HASH_PINNED, zero, 32) == 0);
}

static void test_opaque_ctx_layout(void)
{
    ants_embed_t e;
    CHECK(((uintptr_t)&e & 7u) == 0);
    CHECK(sizeof e == ANTS_EMBED_CTX_SIZE);
    CHECK(ANTS_EMBED_CTX_SIZE == 65536);
}

static void test_init_rejects_invalid_args(void)
{
    ants_embed_t e = {{0}};
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);

    CHECK_EQ(ants_embed_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed_init(&e, NULL), ANTS_ERROR_INVALID_ARG);

    cfg.weights = NULL;
    cfg.weights_len = 0;
    cfg.tokenizer = (const uint8_t *)"x";
    cfg.tokenizer_len = 1;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    cfg.weights = (const uint8_t *)"w";
    cfg.weights_len = 0;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    cfg.weights = (const uint8_t *)"w";
    cfg.weights_len = 1;
    cfg.tokenizer = NULL;
    cfg.tokenizer_len = 1;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);

    cfg.tokenizer = (const uint8_t *)"x";
    cfg.tokenizer_len = 0;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_INVALID_ARG);
}

static void test_init_succeeds_with_placeholder_hashes(void)
{
    /* While the pinned hashes are all-zero placeholders (the v0.x
     * scaffold phase per RFC-0008 §5), verification is skipped and
     * init succeeds against any non-empty buffers. */
    ants_embed_t e = {{0}};
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = (const uint8_t *)"weights-bundle-placeholder";
    cfg.weights_len = 26;
    cfg.tokenizer = (const uint8_t *)"tokenizer-bundle-placeholder";
    cfg.tokenizer_len = 28;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_OK);
    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

static void test_verify_placeholder_skips(void)
{
    /* Verify hook with an all-zero pinned hash returns OK regardless
     * of buffer contents — the v0.x placeholder semantics. */
    uint8_t zero[32] = {0};
    uint8_t buf[] = "anything";
    CHECK_EQ(ants_embed__test_verify(buf, sizeof buf - 1, zero), ANTS_OK);
}

static void test_verify_matches_real_hash(void)
{
    /* Compute the real BLAKE3 of a buffer, then verify against that
     * value succeeds; tamper one bit and verify rejects. Covers the
     * non-placeholder code path before phase 5 pins the real hashes. */
    const uint8_t buf[] = "ants-embed-v1 reference vector input";
    const size_t len = sizeof buf - 1;
    uint8_t pinned[32];
    CHECK_EQ(ants_blake3_hash(buf, len, pinned), ANTS_OK);
    CHECK_EQ(ants_embed__test_verify(buf, len, pinned), ANTS_OK);

    /* Tamper the pinned value and re-verify — MUST reject. */
    pinned[0] ^= 0x01;
    CHECK_EQ(ants_embed__test_verify(buf, len, pinned), ANTS_ERROR_NON_CANONICAL);
}

static void test_destroy_rejects_null(void)
{
    CHECK_EQ(ants_embed_destroy(NULL), ANTS_ERROR_INVALID_ARG);
    ants_embed_t e = {{0}};
    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

static void test_embed_rejects_invalid_args(void)
{
    ants_embed_t e = {{0}};
    float out[ANTS_EMBED_DIM];
    memset(out, 0, sizeof out);

    CHECK_EQ(ants_embed(NULL, (const uint8_t *)"in", 2, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed(&e, NULL, 2, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"in", 2, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"in", 0, out), ANTS_ERROR_INVALID_ARG);
}

static void test_embed_rejects_uninitialised(void)
{
    /* embed on a zeroed ctx (init never called) → INVALID_ARG. */
    ants_embed_t e = {{0}};
    float out[ANTS_EMBED_DIM];
    memset(out, 0, sizeof out);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"hello", 5, out), ANTS_ERROR_INVALID_ARG);
}

/* Bring up a ready-to-embed ctx with placeholder-hash buffers. */
static void embed_init_default(ants_embed_t *e)
{
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = (const uint8_t *)"placeholder-weights";
    cfg.weights_len = 19;
    cfg.tokenizer = (const uint8_t *)"placeholder-tokenizer";
    cfg.tokenizer_len = 21;
    CHECK_EQ(ants_embed_init(e, &cfg), ANTS_OK);
}

static void test_embed_deterministic_same_input(void)
{
    /* Calling embed twice with the same input on the same ctx
     * returns bit-identical floats. This is the property cache/semantic
     * relies on for LSH-routing stability. */
    ants_embed_t e = {{0}};
    embed_init_default(&e);

    const uint8_t in[] = "the canonical input for the determinism test";
    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, a), ANTS_OK);
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, b), ANTS_OK);
    CHECK(memcmp(a, b, sizeof a) == 0);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

static void test_embed_distinct_inputs_distinct_outputs(void)
{
    /* Two different inputs produce two different outputs (BLAKE3
     * collision resistance carries through the stub's expansion). */
    ants_embed_t e = {{0}};
    embed_init_default(&e);

    const uint8_t in1[] = "input one";
    const uint8_t in2[] = "input two";
    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in1, sizeof in1 - 1, a), ANTS_OK);
    CHECK_EQ(ants_embed(&e, in2, sizeof in2 - 1, b), ANTS_OK);
    CHECK(memcmp(a, b, sizeof a) != 0);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

static void test_embed_l2_normalised(void)
{
    /* Sum-of-squares of the output must be very close to 1.0. We
     * tolerate ~1e-5 absolute error to account for the float32
     * rounding in the 1024-term sum + the final divide. */
    ants_embed_t e = {{0}};
    embed_init_default(&e);

    const uint8_t in[] = "normalisation check";
    float out[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, out), ANTS_OK);

    double sum_sq = 0.0;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        sum_sq += (double)out[i] * (double)out[i];
    }
    /* ||out||_2 ≈ 1 ± few-ulp. */
    CHECK(fabs(sum_sq - 1.0) < 1e-5);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_init_succeeds_with_placeholder_hashes();
    test_verify_placeholder_skips();
    test_verify_matches_real_hash();
    test_destroy_rejects_null();
    test_embed_rejects_invalid_args();
    test_embed_rejects_uninitialised();
    test_embed_deterministic_same_input();
    test_embed_distinct_inputs_distinct_outputs();
    test_embed_l2_normalised();

    if (failures > 0) {
        fprintf(stderr, "test_embed: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_embed: all checks passed\n");
    return 0;
}
