/*
 * test_embed.c — tests for the canonical embedding service (Component #11).
 *
 * Phase 4-real step 5d. The stub is gone; ants_embed_init now expects
 * a real GGUF + tokenizer.json. The fixture builder constructs a tiny
 * BGE-M3-shaped model (1 layer × 1024-embd × 64-ffn × 8-heads × 8-ctx
 * × 50-vocab) in memory with FNV-1a-keyed pattern weights, plus a
 * matching Unigram tokenizer.json that covers the test inputs.
 *
 * The 1024-dim embedding length matches the canonical
 * ANTS_EMBED_DIM, so init reaches the protocol-pinned dim check.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_embed.h"

#include "ggml.h"
#include "gguf.h"

#include <math.h>
#include <stdbool.h>
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

extern ants_error_t
ants_embed__test_verify(const uint8_t *buf, size_t len, const uint8_t pinned[32]);

/* ------------------------------------------------------------------------ */
/* Fixture builder                                                          */
/*                                                                          */
/* Constructs an in-memory GGUF + tokenizer.json pair suitable for          */
/* ants_embed_init. Same FNV-1a-keyed pattern-weight technique as           */
/* test_embed_forward — bit-deterministic on a single platform.             */
/* ------------------------------------------------------------------------ */

#define FX_N_LAYERS 1u
#define FX_N_HEADS  8u
#define FX_N_EMBD   ANTS_EMBED_DIM /* 1024 — matches the protocol pin */
#define FX_N_FFN    64u
#define FX_N_CTX    8u
#define FX_N_VOCAB  50u

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s != '\0') {
        h ^= (uint32_t)(uint8_t)*s;
        h *= 16777619u;
        s++;
    }
    return h;
}

static uint32_t lcg_next(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

static float lcg_float(uint32_t *state, float scale)
{
    uint32_t r = lcg_next(state);
    float u = ((float)r * (2.0f / 4294967296.0f)) - 1.0f;
    return u * scale;
}

static void fill_pattern(struct ggml_tensor *t)
{
    if (t == NULL || t->data == NULL) {
        return;
    }
    uint32_t state = fnv1a(t->name);
    float *d = (float *)t->data;
    size_t n = (size_t)ggml_nbytes(t) / sizeof(float);
    for (size_t i = 0; i < n; i++) {
        d[i] = lcg_float(&state, 0.1f);
    }
}

static void
add_2d(struct ggml_context *gg, struct gguf_context *gf, const char *name, int64_t ne0, int64_t ne1)
{
    struct ggml_tensor *t = ggml_new_tensor_2d(gg, GGML_TYPE_F32, ne0, ne1);
    if (t == NULL) {
        return;
    }
    ggml_set_name(t, name);
    fill_pattern(t);
    gguf_add_tensor(gf, t);
}

static void add_1d(struct ggml_context *gg, struct gguf_context *gf, const char *name, int64_t ne0)
{
    struct ggml_tensor *t = ggml_new_tensor_1d(gg, GGML_TYPE_F32, ne0);
    if (t == NULL) {
        return;
    }
    ggml_set_name(t, name);
    fill_pattern(t);
    gguf_add_tensor(gf, t);
}

/* Build the GGUF weights blob. Returns malloc'd buffer in *out_buf. */
static int build_gguf(uint8_t **out_buf, size_t *out_len)
{
    /* Conservative scratch: token_embd alone is 1024 × 50 × 4 = 200 KB;
     * the q/k/v/o matrices are 1024² × 4 ≈ 4 MB each. Plus FFN, embeds,
     * LN. ~25 MB upper bound; 64 MB scratch is comfortable. */
    struct ggml_init_params gp = {
        /* clang-format off */
        .mem_size   = (size_t)64 << 20,
        .mem_buffer = NULL,
        .no_alloc   = false,
        /* clang-format on */
    };
    struct ggml_context *gg = ggml_init(gp);
    if (gg == NULL) {
        return -1;
    }
    struct gguf_context *gf = gguf_init_empty();
    if (gf == NULL) {
        ggml_free(gg);
        return -1;
    }

    add_2d(gg, gf, "token_embd.weight", (int64_t)FX_N_EMBD, (int64_t)FX_N_VOCAB);
    add_2d(gg, gf, "position_embd.weight", (int64_t)FX_N_EMBD, (int64_t)FX_N_CTX);
    add_1d(gg, gf, "token_embd_norm.weight", (int64_t)FX_N_EMBD);
    add_1d(gg, gf, "token_embd_norm.bias", (int64_t)FX_N_EMBD);

    int64_t E = (int64_t)FX_N_EMBD;
    int64_t F = (int64_t)FX_N_FFN;
    for (uint32_t i = 0; i < FX_N_LAYERS; i++) {
        char nm[128];

        (void)snprintf(nm, sizeof nm, "blk.%u.attn_q.weight", (unsigned)i);
        add_2d(gg, gf, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_q.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_k.weight", (unsigned)i);
        add_2d(gg, gf, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_k.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_v.weight", (unsigned)i);
        add_2d(gg, gf, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_v.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output.weight", (unsigned)i);
        add_2d(gg, gf, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output_norm.weight", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output_norm.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_up.weight", (unsigned)i);
        add_2d(gg, gf, nm, E, F);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_up.bias", (unsigned)i);
        add_1d(gg, gf, nm, F);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_down.weight", (unsigned)i);
        add_2d(gg, gf, nm, F, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_down.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.layer_output_norm.weight", (unsigned)i);
        add_1d(gg, gf, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.layer_output_norm.bias", (unsigned)i);
        add_1d(gg, gf, nm, E);
    }

    gguf_set_val_str(gf, "general.architecture", "bert");
    gguf_set_val_u32(gf, "bert.block_count", FX_N_LAYERS);
    gguf_set_val_u32(gf, "bert.embedding_length", FX_N_EMBD);
    gguf_set_val_u32(gf, "bert.feed_forward_length", FX_N_FFN);
    gguf_set_val_u32(gf, "bert.attention.head_count", FX_N_HEADS);
    gguf_set_val_u32(gf, "bert.context_length", FX_N_CTX);
    gguf_set_val_f32(gf, "bert.attention.layer_norm_epsilon", 1e-5f);

    FILE *fp = tmpfile();
    if (fp == NULL) {
        gguf_free(gf);
        ggml_free(gg);
        return -1;
    }
    if (!gguf_write_to_file_ptr(gf, fp, false)) {
        fclose(fp);
        gguf_free(gf);
        ggml_free(gg);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        gguf_free(gf);
        ggml_free(gg);
        return -1;
    }
    long sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        gguf_free(gf);
        ggml_free(gg);
        return -1;
    }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(fp);
        gguf_free(gf);
        ggml_free(gg);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    gguf_free(gf);
    ggml_free(gg);
    if (got != (size_t)sz) {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

/* Minimal tokenizer.json — 10 entries cover the test inputs. The ▁
 * (U+2581) prefix is the SentencePiece word-boundary marker; raw \u
 * escapes used so the JSON stays ASCII. */
static const char tokenizer_json[] = "{\"model\":{\"vocab\":["
                                     "[\"<unk>\",0.0],"
                                     "[\"\\u2581the\",-1.0],"
                                     "[\"\\u2581hello\",-1.0],"
                                     "[\"\\u2581world\",-1.0],"
                                     "[\"\\u2581test\",-1.0],"
                                     "[\"\\u2581input\",-1.0],"
                                     "[\"\\u2581is\",-1.0],"
                                     "[\"\\u2581a\",-1.0],"
                                     "[\"\\u2581canonical\",-1.0],"
                                     "[\"\\u2581different\",-1.0]"
                                     "]}}";

/* Bring up an ants_embed_t with the fixture. Caller is responsible
 * for free()-ing the returned weights blob via *out_weights, and for
 * calling ants_embed_destroy(e). */
static int fixture_init(ants_embed_t *e, uint8_t **out_weights, size_t *out_weights_len)
{
    if (build_gguf(out_weights, out_weights_len) != 0) {
        return -1;
    }
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = *out_weights;
    cfg.weights_len = *out_weights_len;
    cfg.tokenizer = (const uint8_t *)tokenizer_json;
    cfg.tokenizer_len = sizeof tokenizer_json - 1;
    ants_error_t err = ants_embed_init(e, &cfg);
    if (err != ANTS_OK) {
        fprintf(stderr, "fixture_init: ants_embed_init -> %s (%d)\n", ants_strerror(err), (int)err);
        free(*out_weights);
        *out_weights = NULL;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Tests                                                                    */
/* ------------------------------------------------------------------------ */

static void test_pinned_constants(void)
{
    CHECK(ANTS_EMBED_DIM == 1024);
    CHECK(ANTS_EMBED_MODEL_ID != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ID, "ants-embed-v1") == 0);
    CHECK(ANTS_EMBED_MODEL_ARCH != NULL);
    CHECK(strcmp(ANTS_EMBED_MODEL_ARCH, "bge-m3") == 0);

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

static void test_init_rejects_bad_weights(void)
{
    /* Random bytes that are not a valid GGUF blob: init should fail
     * MALFORMED (the wrapper's parse-error path). */
    ants_embed_t e = {{0}};
    uint8_t bogus_weights[64];
    memset(bogus_weights, 0xAB, sizeof bogus_weights);
    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = bogus_weights;
    cfg.weights_len = sizeof bogus_weights;
    cfg.tokenizer = (const uint8_t *)tokenizer_json;
    cfg.tokenizer_len = sizeof tokenizer_json - 1;
    CHECK_EQ(ants_embed_init(&e, &cfg), ANTS_ERROR_MALFORMED);
}

static void test_verify_placeholder_skips(void)
{
    uint8_t zero[32] = {0};
    uint8_t buf[] = "anything";
    CHECK_EQ(ants_embed__test_verify(buf, sizeof buf - 1, zero), ANTS_OK);
}

static void test_verify_matches_real_hash(void)
{
    const uint8_t buf[] = "ants-embed-v1 reference vector input";
    const size_t len = sizeof buf - 1;
    uint8_t pinned[32];
    CHECK_EQ(ants_blake3_hash(buf, len, pinned), ANTS_OK);
    CHECK_EQ(ants_embed__test_verify(buf, len, pinned), ANTS_OK);
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
    ants_embed_t e = {{0}};
    float out[ANTS_EMBED_DIM];
    memset(out, 0, sizeof out);
    CHECK_EQ(ants_embed(&e, (const uint8_t *)"hello", 5, out), ANTS_ERROR_INVALID_ARG);
}

static void test_embed_deterministic_same_input(void)
{
    ants_embed_t e = {{0}};
    uint8_t *weights = NULL;
    size_t weights_len = 0;
    if (fixture_init(&e, &weights, &weights_len) != 0) {
        failures++;
        return;
    }

    const uint8_t in[] = "hello world";
    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, a), ANTS_OK);
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, b), ANTS_OK);
    CHECK(memcmp(a, b, sizeof a) == 0);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
    free(weights);
}

static void test_embed_distinct_inputs_distinct_outputs(void)
{
    ants_embed_t e = {{0}};
    uint8_t *weights = NULL;
    size_t weights_len = 0;
    if (fixture_init(&e, &weights, &weights_len) != 0) {
        failures++;
        return;
    }

    const uint8_t in1[] = "hello world";
    const uint8_t in2[] = "the test input";
    float a[ANTS_EMBED_DIM];
    float b[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in1, sizeof in1 - 1, a), ANTS_OK);
    CHECK_EQ(ants_embed(&e, in2, sizeof in2 - 1, b), ANTS_OK);
    CHECK(memcmp(a, b, sizeof a) != 0);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
    free(weights);
}

static void test_embed_l2_normalised(void)
{
    ants_embed_t e = {{0}};
    uint8_t *weights = NULL;
    size_t weights_len = 0;
    if (fixture_init(&e, &weights, &weights_len) != 0) {
        failures++;
        return;
    }

    const uint8_t in[] = "a canonical input";
    float out[ANTS_EMBED_DIM];
    CHECK_EQ(ants_embed(&e, in, sizeof in - 1, out), ANTS_OK);

    double sum_sq = 0.0;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        sum_sq += (double)out[i] * (double)out[i];
    }
    CHECK(fabs(sum_sq - 1.0) < 1e-4);

    CHECK_EQ(ants_embed_destroy(&e), ANTS_OK);
    free(weights);
}

int main(void)
{
    test_pinned_constants();
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_init_rejects_bad_weights();
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
