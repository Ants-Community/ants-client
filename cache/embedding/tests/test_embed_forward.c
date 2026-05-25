/*
 * test_embed_forward.c — exercises bge_m3_forward end-to-end on a
 * tiny BGE-M3 fixture.
 *
 * Each fixture has FNV-1a-keyed pseudo-random weights (scaled to
 * a small range so the FFN GeLU and softmax don't blow up). The
 * tests don't compare against an external reference — they verify
 * (1) the forward executes without error, (2) the output is
 * L2-normalised, (3) it's deterministic across runs, and
 * (4) distinct inputs produce distinct outputs.
 *
 * Bit-exact correctness against HuggingFace lands in phase 5 once
 * a real BGE-M3 GGUF is pinned.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "embed_forward.h"
#include "embed_gguf.h"
#include "embed_model.h"

#include "ggml.h"
#include "gguf.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define ASSERT_OK(expr)                                                                            \
    do {                                                                                           \
        ants_error_t _e = (expr);                                                                  \
        if (_e != ANTS_OK) {                                                                       \
            fprintf(stderr, "FAIL %s:%d: %s -> %d\n", __FILE__, __LINE__, #expr, (int)_e);         \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define ASSERT_ERR(expr, want)                                                                     \
    do {                                                                                           \
        ants_error_t _r = (expr);                                                                  \
        if (_r != (want)) {                                                                        \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d: %s -> %d (want %d)\n",                                            \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    #expr,                                                                         \
                    (int)_r,                                                                       \
                    (int)(want));                                                                  \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* FNV-1a hash of a tensor name; used as the LCG seed so each
 * tensor has a deterministic but unique fill. */
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

/* Minimal LCG. Constants are the classic Numerical Recipes values. */
static uint32_t lcg_next(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

/* Returns a float in [-scale, +scale). */
static float lcg_float(uint32_t *state, float scale)
{
    uint32_t r = lcg_next(state);
    float u = ((float)r * (2.0f / 4294967296.0f)) - 1.0f; /* [-1, +1) */
    return u * scale;
}

/* Fill a tensor with values seeded from its name. Small range so
 * the FFN GeLU activations don't blow up on a 2-layer fixture. */
static void fill_tensor(struct ggml_tensor *t)
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

static void add_2d_pattern(struct ggml_context *gg,
                           struct gguf_context *gf,
                           const char *name,
                           int64_t ne0,
                           int64_t ne1)
{
    struct ggml_tensor *t = ggml_new_tensor_2d(gg, GGML_TYPE_F32, ne0, ne1);
    if (t == NULL) {
        return;
    }
    ggml_set_name(t, name);
    fill_tensor(t);
    gguf_add_tensor(gf, t);
}

static void
add_1d_pattern(struct ggml_context *gg, struct gguf_context *gf, const char *name, int64_t ne0)
{
    struct ggml_tensor *t = ggml_new_tensor_1d(gg, GGML_TYPE_F32, ne0);
    if (t == NULL) {
        return;
    }
    ggml_set_name(t, name);
    fill_tensor(t);
    gguf_add_tensor(gf, t);
}

typedef struct {
    uint32_t n_layers;
    uint32_t n_heads;
    uint32_t n_embd;
    uint32_t n_ffn;
    uint32_t n_ctx;
    uint32_t n_vocab;
    int include_type_embd;
    /* output */
    uint8_t *buf;
    size_t len;
} fixture_t;

static int build_fixture(fixture_t *f)
{
    struct ggml_init_params gp = {
        /* clang-format off */
        .mem_size   = (size_t)32 << 20,
        .mem_buffer = NULL,
        .no_alloc   = false,
        /* clang-format on */
    };
    struct ggml_context *gg = ggml_init(gp);
    if (gg == NULL) {
        return -1;
    }
    struct gguf_context *gfile = gguf_init_empty();
    if (gfile == NULL) {
        ggml_free(gg);
        return -1;
    }

    add_2d_pattern(gg, gfile, "token_embd.weight", (int64_t)f->n_embd, (int64_t)f->n_vocab);
    add_2d_pattern(gg, gfile, "position_embd.weight", (int64_t)f->n_embd, (int64_t)f->n_ctx);
    if (f->include_type_embd) {
        add_2d_pattern(gg, gfile, "token_types.weight", (int64_t)f->n_embd, 1);
    }
    add_1d_pattern(gg, gfile, "token_embd_norm.weight", (int64_t)f->n_embd);
    add_1d_pattern(gg, gfile, "token_embd_norm.bias", (int64_t)f->n_embd);

    int64_t E = (int64_t)f->n_embd;
    int64_t F = (int64_t)f->n_ffn;
    for (uint32_t i = 0; i < f->n_layers; i++) {
        char nm[128];

        (void)snprintf(nm, sizeof nm, "blk.%u.attn_q.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_q.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_k.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_k.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_v.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_v.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, E, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output_norm.weight", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.attn_output_norm.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_up.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, E, F);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_up.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, F);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_down.weight", (unsigned)i);
        add_2d_pattern(gg, gfile, nm, F, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.ffn_down.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.layer_output_norm.weight", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
        (void)snprintf(nm, sizeof nm, "blk.%u.layer_output_norm.bias", (unsigned)i);
        add_1d_pattern(gg, gfile, nm, E);
    }

    gguf_set_val_str(gfile, "general.architecture", "bert");
    gguf_set_val_u32(gfile, "bert.block_count", f->n_layers);
    gguf_set_val_u32(gfile, "bert.embedding_length", f->n_embd);
    gguf_set_val_u32(gfile, "bert.feed_forward_length", f->n_ffn);
    gguf_set_val_u32(gfile, "bert.attention.head_count", f->n_heads);
    gguf_set_val_u32(gfile, "bert.context_length", f->n_ctx);
    gguf_set_val_f32(gfile, "bert.attention.layer_norm_epsilon", 1e-5f);

    FILE *fp = tmpfile();
    if (fp == NULL) {
        gguf_free(gfile);
        ggml_free(gg);
        return -1;
    }
    if (!gguf_write_to_file_ptr(gfile, fp, false)) {
        fclose(fp);
        gguf_free(gfile);
        ggml_free(gg);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        gguf_free(gfile);
        ggml_free(gg);
        return -1;
    }
    long sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        gguf_free(gfile);
        ggml_free(gg);
        return -1;
    }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(fp);
        gguf_free(gfile);
        ggml_free(gg);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    gguf_free(gfile);
    ggml_free(gg);
    if (got != (size_t)sz) {
        free(buf);
        return -1;
    }
    f->buf = buf;
    f->len = (size_t)sz;
    return 0;
}

static void free_fixture(fixture_t *f)
{
    if (f->buf != NULL) {
        free(f->buf);
        f->buf = NULL;
    }
    f->len = 0;
}

static void default_fixture(fixture_t *p)
{
    memset(p, 0, sizeof(*p));
    p->n_layers = 2;
    p->n_heads = 2;
    p->n_embd = 16;
    p->n_ffn = 32;
    p->n_ctx = 8;
    p->n_vocab = 50;
}

/* Run a forward and return ANTS_OK with `out` populated (caller-owned). */
static ants_error_t run_forward(const fixture_t *f,
                                const int32_t *ids,
                                uint32_t n,
                                const int32_t *type_ids,
                                float *out,
                                embed_gguf_loader_t **save_loader,
                                bge_m3_model_t **save_model)
{
    embed_gguf_loader_t *loader = NULL;
    ants_error_t e = embed_gguf_load(f->buf, f->len, &loader);
    if (e != ANTS_OK) {
        return e;
    }
    bge_m3_model_t *model = NULL;
    e = bge_m3_load_from_gguf(loader, &model);
    if (e != ANTS_OK) {
        embed_gguf_free(loader);
        return e;
    }
    e = bge_m3_forward(model, ids, n, type_ids, out);
    if (save_loader != NULL && save_model != NULL) {
        *save_loader = loader;
        *save_model = model;
    } else {
        bge_m3_free(model);
        embed_gguf_free(loader);
    }
    return e;
}

static int is_unit_norm(const float *v, uint32_t n)
{
    double sumsq = 0.0;
    for (uint32_t i = 0; i < n; i++) {
        sumsq += (double)v[i] * (double)v[i];
    }
    /* Allow ±1e-4 to absorb FP rounding noise from the 1024-term-ish
     * reduction (here only 16 terms, so this is generous). */
    return fabs(sumsq - 1.0) < 1e-4;
}

static int test_forward_basic(void)
{
    fixture_t f;
    default_fixture(&f);
    ASSERT(build_fixture(&f) == 0);

    int32_t ids[] = {1, 2, 3, 4};
    float out[16] = {0};
    ASSERT_OK(run_forward(&f, ids, 4, NULL, out, NULL, NULL));
    ASSERT(is_unit_norm(out, 16));

    free_fixture(&f);
    return 0;
}

static int test_forward_with_type_embd(void)
{
    fixture_t f;
    default_fixture(&f);
    f.include_type_embd = 1;
    ASSERT(build_fixture(&f) == 0);

    int32_t ids[] = {0, 1, 2, 3};
    float out[16] = {0};
    ASSERT_OK(run_forward(&f, ids, 4, NULL, out, NULL, NULL));
    ASSERT(is_unit_norm(out, 16));

    free_fixture(&f);
    return 0;
}

static int test_forward_deterministic(void)
{
    fixture_t f;
    default_fixture(&f);
    ASSERT(build_fixture(&f) == 0);

    int32_t ids[] = {5, 6, 7};
    float out1[16] = {0};
    float out2[16] = {0};
    ASSERT_OK(run_forward(&f, ids, 3, NULL, out1, NULL, NULL));
    ASSERT_OK(run_forward(&f, ids, 3, NULL, out2, NULL, NULL));

    for (uint32_t i = 0; i < 16; i++) {
        ASSERT(out1[i] == out2[i]);
    }

    free_fixture(&f);
    return 0;
}

static int test_forward_distinct_inputs(void)
{
    fixture_t f;
    default_fixture(&f);
    ASSERT(build_fixture(&f) == 0);

    int32_t ids_a[] = {1, 2, 3, 4};
    int32_t ids_b[] = {5, 6, 7, 8};
    float out_a[16] = {0};
    float out_b[16] = {0};
    ASSERT_OK(run_forward(&f, ids_a, 4, NULL, out_a, NULL, NULL));
    ASSERT_OK(run_forward(&f, ids_b, 4, NULL, out_b, NULL, NULL));

    /* At least one coordinate must differ; with random weights this
     * is overwhelmingly likely. */
    int differs = 0;
    for (uint32_t i = 0; i < 16; i++) {
        if (out_a[i] != out_b[i]) {
            differs = 1;
            break;
        }
    }
    ASSERT(differs);

    free_fixture(&f);
    return 0;
}

static int test_forward_bad_args(void)
{
    fixture_t f;
    default_fixture(&f);
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_OK(bge_m3_load_from_gguf(loader, &model));

    int32_t ids[] = {1, 2};
    float out[16] = {0};

    ASSERT_ERR(bge_m3_forward(NULL, ids, 2, NULL, out), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(bge_m3_forward(model, NULL, 2, NULL, out), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(bge_m3_forward(model, ids, 2, NULL, NULL), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(bge_m3_forward(model, ids, 0, NULL, out), ANTS_ERROR_INVALID_ARG);
    /* n_tokens > n_ctx (which is 8 for the default fixture). */
    int32_t big_ids[16] = {0};
    ASSERT_ERR(bge_m3_forward(model, big_ids, 16, NULL, out), ANTS_ERROR_INVALID_ARG);

    bge_m3_free(model);
    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        {"forward_basic", test_forward_basic},
        {"forward_with_type_embd", test_forward_with_type_embd},
        {"forward_deterministic", test_forward_deterministic},
        {"forward_distinct_inputs", test_forward_distinct_inputs},
        {"forward_bad_args", test_forward_bad_args},
    };
    size_t n = sizeof(tests) / sizeof(tests[0]);
    int failed = 0;
    for (size_t i = 0; i < n; i++) {
        printf("[ RUN ] %s\n", tests[i].name);
        if (tests[i].fn() != 0) {
            printf("[FAIL ] %s\n", tests[i].name);
            failed++;
        } else {
            printf("[ OK  ] %s\n", tests[i].name);
        }
    }
    printf("\n%zu tests, %d failed\n", n, failed);
    return failed == 0 ? 0 : 1;
}
