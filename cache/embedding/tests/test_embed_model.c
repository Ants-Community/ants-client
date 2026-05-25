/*
 * test_embed_model.c — exercises bge_m3_load_from_gguf against
 * synthetic GGUF fixtures.
 *
 * Each test builds a tiny BERT-style GGUF in memory (tiny dims so
 * the whole transformer fits in a few KB), loads it through the
 * GGUF buffer wrapper, then asks bge_m3_load_from_gguf to bind
 * its tensors. Variants drop / corrupt one piece of the model to
 * exercise the validation paths.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "embed_gguf.h"
#include "embed_model.h"

#include "ggml.h"
#include "gguf.h"

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

/* Fixture parameters. Defaults give a tiny but well-formed BERT
 * file: 2 layers, 32-dim embedding, 64-dim FFN, 4 attention heads,
 * 16-token context, 100-entry vocab. Flags disable / corrupt one
 * specific piece for negative tests. */
typedef struct {
    uint32_t n_layers;
    uint32_t n_heads;
    uint32_t n_embd;
    uint32_t n_ffn;
    uint32_t n_ctx;
    uint32_t n_vocab;
    const char *arch;           /* NULL → omit general.architecture entirely */
    int skip_block_count_kv;    /* drop bert.block_count */
    int include_type_embd;      /* add token_types.weight */
    int skip_token_embd_tensor; /* drop token_embd.weight */
    int skip_layer0_q_w;        /* drop blk.0.attn_q.weight */
    int wrong_shape_layer0_q_w; /* allocate blk.0.attn_q.weight with wrong dims */
    /* output (set by build_fixture, owned by caller) */
    uint8_t *buf;
    size_t len;
} fixture_t;

static void add_2d_zero(struct ggml_context *gg,
                        struct gguf_context *gf,
                        const char *name,
                        int64_t ne0,
                        int64_t ne1)
{
    struct ggml_tensor *t = ggml_new_tensor_2d(gg, GGML_TYPE_F32, ne0, ne1);
    if (t == NULL) {
        return; /* caller will notice via gguf shape mismatch */
    }
    ggml_set_name(t, name);
    /* The mem buffer was zero-initialised by ggml_init; explicit memset
     * defends against future changes to that contract. */
    memset(t->data, 0, ggml_nbytes(t));
    gguf_add_tensor(gf, t);
}

static void
add_1d_zero(struct ggml_context *gg, struct gguf_context *gf, const char *name, int64_t ne0)
{
    struct ggml_tensor *t = ggml_new_tensor_1d(gg, GGML_TYPE_F32, ne0);
    if (t == NULL) {
        return;
    }
    ggml_set_name(t, name);
    memset(t->data, 0, ggml_nbytes(t));
    gguf_add_tensor(gf, t);
}

static int build_fixture(fixture_t *f)
{
    /* ~8 MB ggml scratch — more than enough for 24 layers @ 32-embd. */
    struct ggml_init_params gp = {
        /* clang-format off */
        .mem_size   = (size_t)8 << 20,
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

    /* ---- Tensors ---- */
    if (!f->skip_token_embd_tensor) {
        add_2d_zero(gg, gf, "token_embd.weight", (int64_t)f->n_embd, (int64_t)f->n_vocab);
    }
    add_2d_zero(gg, gf, "position_embd.weight", (int64_t)f->n_embd, (int64_t)f->n_ctx);
    if (f->include_type_embd) {
        add_2d_zero(gg, gf, "token_types.weight", (int64_t)f->n_embd, 1);
    }
    add_1d_zero(gg, gf, "token_embd_norm.weight", (int64_t)f->n_embd);
    add_1d_zero(gg, gf, "token_embd_norm.bias", (int64_t)f->n_embd);

    for (uint32_t i = 0; i < f->n_layers; i++) {
        char name[128];
        int64_t E = (int64_t)f->n_embd;
        int64_t F = (int64_t)f->n_ffn;

        /* attn_q.weight — the one we can selectively drop / corrupt
         * to drive the negative tests. */
        (void)snprintf(name, sizeof name, "blk.%u.attn_q.weight", (unsigned)i);
        if (i == 0 && f->skip_layer0_q_w) {
            /* skip */
        } else if (i == 0 && f->wrong_shape_layer0_q_w) {
            /* Allocate with wrong dims (E+1, E) so the shape check fails. */
            add_2d_zero(gg, gf, name, E + 1, E);
        } else {
            add_2d_zero(gg, gf, name, E, E);
        }

        (void)snprintf(name, sizeof name, "blk.%u.attn_q.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.attn_k.weight", (unsigned)i);
        add_2d_zero(gg, gf, name, E, E);
        (void)snprintf(name, sizeof name, "blk.%u.attn_k.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.attn_v.weight", (unsigned)i);
        add_2d_zero(gg, gf, name, E, E);
        (void)snprintf(name, sizeof name, "blk.%u.attn_v.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.attn_output.weight", (unsigned)i);
        add_2d_zero(gg, gf, name, E, E);
        (void)snprintf(name, sizeof name, "blk.%u.attn_output.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.attn_output_norm.weight", (unsigned)i);
        add_1d_zero(gg, gf, name, E);
        (void)snprintf(name, sizeof name, "blk.%u.attn_output_norm.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.ffn_up.weight", (unsigned)i);
        add_2d_zero(gg, gf, name, E, F);
        (void)snprintf(name, sizeof name, "blk.%u.ffn_up.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, F);

        (void)snprintf(name, sizeof name, "blk.%u.ffn_down.weight", (unsigned)i);
        add_2d_zero(gg, gf, name, F, E);
        (void)snprintf(name, sizeof name, "blk.%u.ffn_down.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);

        (void)snprintf(name, sizeof name, "blk.%u.layer_output_norm.weight", (unsigned)i);
        add_1d_zero(gg, gf, name, E);
        (void)snprintf(name, sizeof name, "blk.%u.layer_output_norm.bias", (unsigned)i);
        add_1d_zero(gg, gf, name, E);
    }

    /* ---- Metadata KVs ---- */
    if (f->arch != NULL) {
        gguf_set_val_str(gf, "general.architecture", f->arch);
    }
    if (!f->skip_block_count_kv) {
        gguf_set_val_u32(gf, "bert.block_count", f->n_layers);
    }
    gguf_set_val_u32(gf, "bert.embedding_length", f->n_embd);
    gguf_set_val_u32(gf, "bert.feed_forward_length", f->n_ffn);
    gguf_set_val_u32(gf, "bert.attention.head_count", f->n_heads);
    gguf_set_val_u32(gf, "bert.context_length", f->n_ctx);
    gguf_set_val_f32(gf, "bert.attention.layer_norm_epsilon", 1e-5f);

    /* ---- Serialise to a tmpfile and read back. ---- */
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

/* Fill p with the canonical small dims. */
static void default_params(fixture_t *p)
{
    memset(p, 0, sizeof(*p));
    p->n_layers = 2;
    p->n_heads = 4;
    p->n_embd = 32;
    p->n_ffn = 64;
    p->n_ctx = 16;
    p->n_vocab = 100;
    p->arch = "bert";
}

static int test_valid(void)
{
    fixture_t f;
    default_params(&f);
    f.include_type_embd = 1;
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));

    bge_m3_model_t *model = NULL;
    ASSERT_OK(bge_m3_load_from_gguf(loader, &model));
    ASSERT(model != NULL);

    /* Metadata. */
    ASSERT(model->n_layers == f.n_layers);
    ASSERT(model->n_heads == f.n_heads);
    ASSERT(model->n_embd == f.n_embd);
    ASSERT(model->n_ffn == f.n_ffn);
    ASSERT(model->n_ctx == f.n_ctx);
    ASSERT(model->n_vocab == f.n_vocab);
    ASSERT(model->ln_eps == 1e-5f);

    /* Top-level tensors. */
    ASSERT(model->token_embd != NULL);
    ASSERT(model->position_embd != NULL);
    ASSERT(model->type_embd != NULL); /* include_type_embd was set */
    ASSERT(model->token_embd_norm_w != NULL && model->token_embd_norm_b != NULL);

    /* Per-layer. */
    ASSERT(model->layers != NULL);
    for (uint32_t i = 0; i < model->n_layers; i++) {
        const bge_m3_layer_t *L = &model->layers[i];
        ASSERT(L->attn_q_w != NULL && L->attn_q_b != NULL);
        ASSERT(L->attn_k_w != NULL && L->attn_k_b != NULL);
        ASSERT(L->attn_v_w != NULL && L->attn_v_b != NULL);
        ASSERT(L->attn_out_w != NULL && L->attn_out_b != NULL);
        ASSERT(L->attn_out_norm_w != NULL && L->attn_out_norm_b != NULL);
        ASSERT(L->ffn_up_w != NULL && L->ffn_up_b != NULL);
        ASSERT(L->ffn_down_w != NULL && L->ffn_down_b != NULL);
        ASSERT(L->layer_out_norm_w != NULL && L->layer_out_norm_b != NULL);
    }

    bge_m3_free(model);
    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_valid_no_type_embd(void)
{
    fixture_t f;
    default_params(&f);
    /* include_type_embd stays 0; type_embd should be NULL on the model. */
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));

    bge_m3_model_t *model = NULL;
    ASSERT_OK(bge_m3_load_from_gguf(loader, &model));
    ASSERT(model->type_embd == NULL);

    bge_m3_free(model);
    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_wrong_arch(void)
{
    fixture_t f;
    default_params(&f);
    f.arch = "rope-llama";
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_MALFORMED);
    ASSERT(model == NULL);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_missing_arch_kv(void)
{
    fixture_t f;
    default_params(&f);
    f.arch = NULL; /* skip general.architecture entirely */
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_MALFORMED);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_missing_block_count(void)
{
    fixture_t f;
    default_params(&f);
    f.skip_block_count_kv = 1;
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_MALFORMED);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_n_embd_not_divisible_by_heads(void)
{
    fixture_t f;
    default_params(&f);
    f.n_heads = 3; /* 32 % 3 != 0 */
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_MALFORMED);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_missing_token_embd(void)
{
    fixture_t f;
    default_params(&f);
    f.skip_token_embd_tensor = 1;
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_NON_CANONICAL);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_missing_layer0_q(void)
{
    fixture_t f;
    default_params(&f);
    f.skip_layer0_q_w = 1;
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_NON_CANONICAL);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_wrong_shape_layer0_q(void)
{
    fixture_t f;
    default_params(&f);
    f.wrong_shape_layer0_q_w = 1;
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));
    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(loader, &model), ANTS_ERROR_NON_CANONICAL);

    embed_gguf_free(loader);
    free_fixture(&f);
    return 0;
}

static int test_bad_args(void)
{
    fixture_t f;
    default_params(&f);
    ASSERT(build_fixture(&f) == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(f.buf, f.len, &loader));

    bge_m3_model_t *model = NULL;
    ASSERT_ERR(bge_m3_load_from_gguf(NULL, &model), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(bge_m3_load_from_gguf(loader, NULL), ANTS_ERROR_INVALID_ARG);

    bge_m3_free(NULL); /* must not crash */

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
        {"valid", test_valid},
        {"valid_no_type_embd", test_valid_no_type_embd},
        {"wrong_arch", test_wrong_arch},
        {"missing_arch_kv", test_missing_arch_kv},
        {"missing_block_count", test_missing_block_count},
        {"n_embd_not_divisible_by_heads", test_n_embd_not_divisible_by_heads},
        {"missing_token_embd", test_missing_token_embd},
        {"missing_layer0_q", test_missing_layer0_q},
        {"wrong_shape_layer0_q", test_wrong_shape_layer0_q},
        {"bad_args", test_bad_args},
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
