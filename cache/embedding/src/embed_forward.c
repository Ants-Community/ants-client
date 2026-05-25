/*
 * embed_forward.c — BGE-M3 / XLM-RoBERTa forward via ggml.
 *
 * Builds a ggml compute graph for one forward, runs it on the CPU
 * backend, then CLS-pools and L2-normalises the result.
 */

#include "embed_forward.h"

#include "embed_model.h"
#include "ggml-cpu.h"
#include "ggml.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Linear layer: y = W @ x + b, where ggml stores W as [in, out] so
 * ggml_mul_mat(W, x) returns [out, M] when x is [in, M]. */
static struct ggml_tensor *linear(struct ggml_context *ctx,
                                  struct ggml_tensor *x,
                                  struct ggml_tensor *W,
                                  struct ggml_tensor *b)
{
    struct ggml_tensor *y = ggml_mul_mat(ctx, W, x);
    y = ggml_add(ctx, y, b);
    return y;
}

/* LayerNorm with affine: gamma * normalize(x, eps) + beta.
 * ggml_norm only subtracts mean and divides by sqrt(var+eps); the
 * affine has to be expressed explicitly. */
static struct ggml_tensor *layer_norm(struct ggml_context *ctx,
                                      struct ggml_tensor *x,
                                      struct ggml_tensor *gamma,
                                      struct ggml_tensor *beta,
                                      float eps)
{
    struct ggml_tensor *y = ggml_norm(ctx, x, eps);
    y = ggml_mul(ctx, y, gamma);
    y = ggml_add(ctx, y, beta);
    return y;
}

/* Build the forward graph. Returns the pooled tensor (the output
 * of ggml_cont applied to the CLS view), or NULL on alloc failure. */
static struct ggml_tensor *build_graph(struct ggml_context *ctx,
                                       const bge_m3_model_t *model,
                                       struct ggml_tensor *ids_tensor,
                                       struct ggml_tensor *pos_tensor,
                                       struct ggml_tensor *type_tensor)
{
    const uint32_t n_layers = model->n_layers;
    const uint32_t n_heads = model->n_heads;
    const uint32_t n_embd = model->n_embd;
    const int64_t head_dim = (int64_t)(n_embd / n_heads);
    const float ln_eps = model->ln_eps;
    const int64_t n_tokens = ids_tensor->ne[0];

    /* Token embedding: ggml_get_rows(T[ne0=n_embd, ne1=n_vocab], ids[n_tokens])
     * returns [n_embd, n_tokens]. */
    struct ggml_tensor *x = ggml_get_rows(ctx, model->token_embd, ids_tensor);

    /* + position embedding. */
    struct ggml_tensor *pos_emb = ggml_get_rows(ctx, model->position_embd, pos_tensor);
    x = ggml_add(ctx, x, pos_emb);

    /* + token-type embedding when present. */
    if (model->type_embd != NULL && type_tensor != NULL) {
        struct ggml_tensor *type_emb = ggml_get_rows(ctx, model->type_embd, type_tensor);
        x = ggml_add(ctx, x, type_emb);
    }

    /* Pre-encoder LayerNorm on the summed embedding. */
    x = layer_norm(ctx, x, model->token_embd_norm_w, model->token_embd_norm_b, ln_eps);

    /* Transformer blocks (BERT post-norm). */
    for (uint32_t i = 0; i < n_layers; i++) {
        const bge_m3_layer_t *L = &model->layers[i];

        /* QKV projections, each [n_embd, n_tokens]. */
        struct ggml_tensor *q = linear(ctx, x, L->attn_q_w, L->attn_q_b);
        struct ggml_tensor *k = linear(ctx, x, L->attn_k_w, L->attn_k_b);
        struct ggml_tensor *v = linear(ctx, x, L->attn_v_w, L->attn_v_b);

        /* Reshape to multi-head: [head_dim, n_heads, n_tokens]. */
        q = ggml_reshape_3d(ctx, q, head_dim, (int64_t)n_heads, n_tokens);
        k = ggml_reshape_3d(ctx, k, head_dim, (int64_t)n_heads, n_tokens);
        v = ggml_reshape_3d(ctx, v, head_dim, (int64_t)n_heads, n_tokens);

        /* Permute heads onto the batch axis so each head's matmul is
         * independent. q,k become [head_dim, n_tokens, n_heads]; v
         * becomes [n_tokens, head_dim, n_heads] (transposed so v @ scores
         * works out as v.T @ scores in conceptual terms). */
        q = ggml_cont(ctx, ggml_permute(ctx, q, 0, 2, 1, 3));
        k = ggml_cont(ctx, ggml_permute(ctx, k, 0, 2, 1, 3));
        v = ggml_cont(ctx, ggml_permute(ctx, v, 1, 2, 0, 3));

        /* Scaled scores: ggml_mul_mat(K, Q) → [n_tokens, n_tokens, n_heads]. */
        struct ggml_tensor *scores = ggml_mul_mat(ctx, k, q);
        scores = ggml_scale(ctx, scores, 1.0f / sqrtf((float)head_dim));
        scores = ggml_soft_max(ctx, scores);

        /* attn = V @ scores → [head_dim, n_tokens, n_heads]. */
        struct ggml_tensor *attn = ggml_mul_mat(ctx, v, scores);

        /* Bring heads back next to head_dim, then collapse into n_embd. */
        attn = ggml_cont(ctx, ggml_permute(ctx, attn, 0, 2, 1, 3));
        attn = ggml_reshape_2d(ctx, attn, (int64_t)n_embd, n_tokens);

        /* Output projection. */
        attn = linear(ctx, attn, L->attn_out_w, L->attn_out_b);

        /* Residual + post-attn LN. */
        x = ggml_add(ctx, x, attn);
        x = layer_norm(ctx, x, L->attn_out_norm_w, L->attn_out_norm_b, ln_eps);

        /* FFN: up-project, GeLU, down-project. */
        struct ggml_tensor *h = linear(ctx, x, L->ffn_up_w, L->ffn_up_b);
        h = ggml_gelu(ctx, h);
        h = linear(ctx, h, L->ffn_down_w, L->ffn_down_b);

        /* Residual + post-FFN LN. */
        x = ggml_add(ctx, x, h);
        x = layer_norm(ctx, x, L->layer_out_norm_w, L->layer_out_norm_b, ln_eps);
    }

    /* CLS pooling: take column 0 of x [n_embd, n_tokens]. ggml_view_1d
     * at offset 0 with n_embd elements gives us that column; ggml_cont
     * forces the producer to materialise it so the output buffer is
     * contiguous and we can memcpy out of it. */
    struct ggml_tensor *pooled = ggml_view_1d(ctx, x, (int64_t)n_embd, 0);
    pooled = ggml_cont(ctx, pooled);
    return pooled;
}

ants_error_t bge_m3_forward(const bge_m3_model_t *model,
                            const int32_t *input_ids,
                            uint32_t n_tokens,
                            const int32_t *type_ids,
                            float *out)
{
    if (model == NULL || input_ids == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_tokens == 0 || n_tokens > model->n_ctx) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Memory budget. Each layer's intermediate activations are roughly
     * 20 [n_embd, n_tokens]-sized tensors plus 2 [n_ffn, n_tokens] plus
     * scores of size [n_tokens, n_tokens, n_heads]. Use a generous
     * heuristic: layer_cost = 30 × max(n_embd, n_ffn) × n_tokens × 4
     * plus the score buffer. Add 16 MB of fixed overhead for the graph
     * + headers + work buffer. */
    const uint64_t hidden_max = (model->n_embd > model->n_ffn) ? model->n_embd : model->n_ffn;
    const uint64_t per_layer = (uint64_t)n_tokens * hidden_max * sizeof(float) * 30u;
    const uint64_t scores = (uint64_t)n_tokens * n_tokens * model->n_heads * sizeof(float) * 4u;
    const uint64_t budget =
        ((uint64_t)model->n_layers) * (per_layer + scores) + (uint64_t)(16ULL * 1024ULL * 1024ULL);

    struct ggml_init_params gp = {
        /* clang-format off */
        .mem_size   = (size_t)budget,
        .mem_buffer = NULL,
        .no_alloc   = false,
        /* clang-format on */
    };
    struct ggml_context *ctx = ggml_init(gp);
    if (ctx == NULL) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Input tensors live in the compute context (no_alloc=false so
     * ->data is ready to write into). */
    struct ggml_tensor *ids_tensor = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, (int64_t)n_tokens);
    if (ids_tensor == NULL) {
        ggml_free(ctx);
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(ids_tensor->data, input_ids, (size_t)n_tokens * sizeof(int32_t));

    struct ggml_tensor *pos_tensor = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, (int64_t)n_tokens);
    if (pos_tensor == NULL) {
        ggml_free(ctx);
        return ANTS_ERROR_MALFORMED;
    }
    {
        int32_t *p = (int32_t *)pos_tensor->data;
        for (uint32_t i = 0; i < n_tokens; i++) {
            p[i] = (int32_t)i;
        }
    }

    struct ggml_tensor *type_tensor = NULL;
    if (model->type_embd != NULL) {
        type_tensor = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, (int64_t)n_tokens);
        if (type_tensor == NULL) {
            ggml_free(ctx);
            return ANTS_ERROR_MALFORMED;
        }
        int32_t *t = (int32_t *)type_tensor->data;
        if (type_ids != NULL) {
            memcpy(t, type_ids, (size_t)n_tokens * sizeof(int32_t));
        } else {
            memset(t, 0, (size_t)n_tokens * sizeof(int32_t));
        }
    }

    struct ggml_tensor *pooled = build_graph(ctx, model, ids_tensor, pos_tensor, type_tensor);
    if (pooled == NULL) {
        ggml_free(ctx);
        return ANTS_ERROR_MALFORMED;
    }

    struct ggml_cgraph *graph = ggml_new_graph(ctx);
    if (graph == NULL) {
        ggml_free(ctx);
        return ANTS_ERROR_MALFORMED;
    }
    ggml_build_forward_expand(graph, pooled);

    /* n_threads=1: required for bit-determinism across machines (cross-
     * platform float ordering is a separate problem, RFC-0009's
     * canonical numerics will pin it; this argument at least makes
     * a single host deterministic across runs). */
    enum ggml_status status = ggml_graph_compute_with_ctx(ctx, graph, 1);
    if (status != GGML_STATUS_SUCCESS) {
        ggml_free(ctx);
        return ANTS_ERROR_MALFORMED;
    }

    /* Copy pooled vector to caller buffer. */
    memcpy(out, pooled->data, (size_t)model->n_embd * sizeof(float));
    ggml_free(ctx);

    /* L2-normalise in-place. Doing this outside the graph keeps the
     * graph leaner and lets us catch the zero-norm pathological case
     * with a typed error. */
    double sumsq = 0.0;
    for (uint32_t i = 0; i < model->n_embd; i++) {
        double v = (double)out[i];
        sumsq += v * v;
    }
    double norm = sqrt(sumsq);
    if (norm < 1e-30) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    float inv_norm = (float)(1.0 / norm);
    for (uint32_t i = 0; i < model->n_embd; i++) {
        out[i] *= inv_norm;
    }
    return ANTS_OK;
}
