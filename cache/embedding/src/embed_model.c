/*
 * embed_model.c — BGE-M3 tensor binding.
 *
 * Resolves the tensors a BERT-family transformer needs from a loaded
 * GGUF, validating shapes against the declared dims. See embed_model.h
 * for naming convention.
 */

#include "embed_model.h"

#include "embed_gguf.h"
#include "ggml.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECTED_ARCH "bert"

static int tensor_is_2d(const struct ggml_tensor *t, int64_t d0, int64_t d1)
{
    return t != NULL && t->ne[0] == d0 && t->ne[1] == d1 && t->ne[2] == 1 && t->ne[3] == 1;
}

static int tensor_is_1d(const struct ggml_tensor *t, int64_t d0)
{
    return t != NULL && t->ne[0] == d0 && t->ne[1] == 1 && t->ne[2] == 1 && t->ne[3] == 1;
}

static ants_error_t
require_named(const embed_gguf_loader_t *loader, const char *name, struct ggml_tensor **out)
{
    struct ggml_tensor *t = embed_gguf_find_tensor(loader, name);
    if (t == NULL) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    *out = t;
    return ANTS_OK;
}

static ants_error_t bind_layer(const embed_gguf_loader_t *loader,
                               uint32_t i,
                               uint32_t n_embd,
                               uint32_t n_ffn,
                               bge_m3_layer_t *L)
{
    char name[128];
    /* All "blk.%u.<suffix>" names. The require_named lookups bail to
     * NON_CANONICAL on miss; shape checks run after every successful
     * resolve so a wrong-dim tensor is also NON_CANONICAL. */
#define BIND(field, suffix)                                                                        \
    do {                                                                                           \
        (void)snprintf(name, sizeof name, "blk.%u." suffix, (unsigned)i);                          \
        if (require_named(loader, name, &L->field) != ANTS_OK) {                                   \
            return ANTS_ERROR_NON_CANONICAL;                                                       \
        }                                                                                          \
    } while (0)

    BIND(attn_q_w, "attn_q.weight");
    BIND(attn_q_b, "attn_q.bias");
    BIND(attn_k_w, "attn_k.weight");
    BIND(attn_k_b, "attn_k.bias");
    BIND(attn_v_w, "attn_v.weight");
    BIND(attn_v_b, "attn_v.bias");
    BIND(attn_out_w, "attn_output.weight");
    BIND(attn_out_b, "attn_output.bias");
    BIND(attn_out_norm_w, "attn_output_norm.weight");
    BIND(attn_out_norm_b, "attn_output_norm.bias");
    BIND(ffn_up_w, "ffn_up.weight");
    BIND(ffn_up_b, "ffn_up.bias");
    BIND(ffn_down_w, "ffn_down.weight");
    BIND(ffn_down_b, "ffn_down.bias");
    BIND(layer_out_norm_w, "layer_output_norm.weight");
    BIND(layer_out_norm_b, "layer_output_norm.bias");

#undef BIND

    /* Shape checks. Linear weight tensors in ggml follow llama.cpp's
     * convention: ne[0] = input dim, ne[1] = output dim, so a Linear
     * with HF shape [out, in] is stored as ne=[in, out]. */
    int64_t E = (int64_t)n_embd;
    int64_t F = (int64_t)n_ffn;

    if (!tensor_is_2d(L->attn_q_w, E, E) || !tensor_is_1d(L->attn_q_b, E) ||
        !tensor_is_2d(L->attn_k_w, E, E) || !tensor_is_1d(L->attn_k_b, E) ||
        !tensor_is_2d(L->attn_v_w, E, E) || !tensor_is_1d(L->attn_v_b, E) ||
        !tensor_is_2d(L->attn_out_w, E, E) || !tensor_is_1d(L->attn_out_b, E) ||
        !tensor_is_1d(L->attn_out_norm_w, E) || !tensor_is_1d(L->attn_out_norm_b, E)) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (!tensor_is_2d(L->ffn_up_w, E, F) || !tensor_is_1d(L->ffn_up_b, F) ||
        !tensor_is_2d(L->ffn_down_w, F, E) || !tensor_is_1d(L->ffn_down_b, E) ||
        !tensor_is_1d(L->layer_out_norm_w, E) || !tensor_is_1d(L->layer_out_norm_b, E)) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ANTS_OK;
}

ants_error_t bge_m3_load_from_gguf(const embed_gguf_loader_t *loader, bge_m3_model_t **out_model)
{
    if (loader == NULL || out_model == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_model = NULL;

    /* Architecture gate. */
    const char *arch = embed_gguf_get_str(loader, "general.architecture");
    if (arch == NULL || strcmp(arch, EXPECTED_ARCH) != 0) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Metadata. All five integer KVs are required; missing any of them
     * is a MALFORMED model file, not a shape mismatch. */
    uint32_t n_layers = 0;
    uint32_t n_heads = 0;
    uint32_t n_embd = 0;
    uint32_t n_ffn = 0;
    uint32_t n_ctx = 0;
    if (embed_gguf_get_u32(loader, "bert.block_count", &n_layers) != ANTS_OK ||
        embed_gguf_get_u32(loader, "bert.embedding_length", &n_embd) != ANTS_OK ||
        embed_gguf_get_u32(loader, "bert.feed_forward_length", &n_ffn) != ANTS_OK ||
        embed_gguf_get_u32(loader, "bert.attention.head_count", &n_heads) != ANTS_OK ||
        embed_gguf_get_u32(loader, "bert.context_length", &n_ctx) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }

    float ln_eps = 0.0f;
    if (embed_gguf_get_f32(loader, "bert.attention.layer_norm_epsilon", &ln_eps) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Internal-consistency checks on metadata. */
    if (n_layers == 0 || n_heads == 0 || n_embd == 0 || n_ffn == 0 || n_ctx == 0) {
        return ANTS_ERROR_MALFORMED;
    }
    if (n_embd % n_heads != 0) {
        return ANTS_ERROR_MALFORMED;
    }

    bge_m3_model_t *m = (bge_m3_model_t *)calloc(1, sizeof(*m));
    if (m == NULL) {
        return ANTS_ERROR_MALFORMED;
    }

    m->n_layers = n_layers;
    m->n_heads = n_heads;
    m->n_embd = n_embd;
    m->n_ffn = n_ffn;
    m->n_ctx = n_ctx;
    m->ln_eps = ln_eps;

    /* Token embedding (required); also derives n_vocab. */
    if (require_named(loader, "token_embd.weight", &m->token_embd) != ANTS_OK) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (m->token_embd->ne[0] != (int64_t)n_embd || m->token_embd->ne[1] <= 0) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }
    m->n_vocab = (uint32_t)m->token_embd->ne[1];

    /* Position embedding (required). */
    if (require_named(loader, "position_embd.weight", &m->position_embd) != ANTS_OK) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (m->position_embd->ne[0] != (int64_t)n_embd || m->position_embd->ne[1] != (int64_t)n_ctx) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Token-type embedding (optional — XLM-R has trivial n_types=1,
     * bare BERT has n_types=2). We bind if present; forward pass
     * will degrade gracefully if NULL. */
    m->type_embd = embed_gguf_find_tensor(loader, "token_types.weight");
    if (m->type_embd != NULL && m->type_embd->ne[0] != (int64_t)n_embd) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Pre-encoder LN applied to the summed embedding. */
    if (require_named(loader, "token_embd_norm.weight", &m->token_embd_norm_w) != ANTS_OK ||
        require_named(loader, "token_embd_norm.bias", &m->token_embd_norm_b) != ANTS_OK) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (!tensor_is_1d(m->token_embd_norm_w, (int64_t)n_embd) ||
        !tensor_is_1d(m->token_embd_norm_b, (int64_t)n_embd)) {
        free(m);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Per-layer tensors. */
    m->layers = (bge_m3_layer_t *)calloc((size_t)n_layers, sizeof(bge_m3_layer_t));
    if (m->layers == NULL) {
        free(m);
        return ANTS_ERROR_MALFORMED;
    }

    for (uint32_t i = 0; i < n_layers; i++) {
        ants_error_t e = bind_layer(loader, i, n_embd, n_ffn, &m->layers[i]);
        if (e != ANTS_OK) {
            bge_m3_free(m);
            return e;
        }
    }

    *out_model = m;
    return ANTS_OK;
}

void bge_m3_free(bge_m3_model_t *model)
{
    if (model == NULL) {
        return;
    }
    free(model->layers);
    free(model);
}
