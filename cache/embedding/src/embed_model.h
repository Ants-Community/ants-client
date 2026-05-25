/*
 * embed_model.h — BGE-M3 / XLM-RoBERTa tensor binding for the
 * canonical embedding service.
 *
 * Private to cache/embedding. Sits on top of embed_gguf: takes a
 * GGUF loader, validates the file declares the BERT-family
 * architecture this service expects, mirrors the relevant metadata
 * KVs, and resolves every tensor a BGE-M3 forward pass will need
 * by name + shape. Does NOT execute forward inference (that's
 * step 5c).
 *
 * Naming convention assumed:
 *   - general.architecture            = "bert"
 *   - bert.block_count                (uint32_t)
 *   - bert.embedding_length           (uint32_t)
 *   - bert.feed_forward_length        (uint32_t)
 *   - bert.attention.head_count       (uint32_t)
 *   - bert.context_length             (uint32_t)
 *   - bert.attention.layer_norm_epsilon (float32)
 *
 *   Tensor naming follows llama.cpp's BERT mapping:
 *     token_embd.weight                 [n_embd, n_vocab]
 *     position_embd.weight              [n_embd, n_ctx]
 *     token_types.weight                [n_embd, n_types]  (optional)
 *     token_embd_norm.{weight,bias}     [n_embd]
 *     blk.{i}.attn_{q,k,v}.{weight,bias}
 *     blk.{i}.attn_output.{weight,bias}
 *     blk.{i}.attn_output_norm.{weight,bias}
 *     blk.{i}.ffn_up.{weight,bias}
 *     blk.{i}.ffn_down.{weight,bias}
 *     blk.{i}.layer_output_norm.{weight,bias}
 *
 * The canonical ANTS_EMBED_MODEL_ID = "ants-embed-v1" pins these
 * exact names at phase 5. Until then, the binder accepts any
 * BERT-family file whose dims are internally consistent so
 * cache/semantic and step 5c can be developed against synthetic
 * fixtures.
 */

#ifndef ANTS_EMBED_MODEL_H
#define ANTS_EMBED_MODEL_H

#include "ants_common.h"

#include <stdint.h>

struct ggml_tensor;
typedef struct embed_gguf_loader embed_gguf_loader_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Per-layer tensor handles for a BGE-M3 / BERT-style transformer
 * block. All pointers reference tensor storage inside the loader's
 * ggml_context; they MUST NOT outlive the loader. */
typedef struct {
    /* Self-attention QKV + output projection. */
    struct ggml_tensor *attn_q_w;
    struct ggml_tensor *attn_q_b;
    struct ggml_tensor *attn_k_w;
    struct ggml_tensor *attn_k_b;
    struct ggml_tensor *attn_v_w;
    struct ggml_tensor *attn_v_b;
    struct ggml_tensor *attn_out_w;
    struct ggml_tensor *attn_out_b;

    /* LN after attention output (post-norm BERT-style). */
    struct ggml_tensor *attn_out_norm_w;
    struct ggml_tensor *attn_out_norm_b;

    /* Position-wise FFN: up-projection (intermediate) + down-projection. */
    struct ggml_tensor *ffn_up_w;
    struct ggml_tensor *ffn_up_b;
    struct ggml_tensor *ffn_down_w;
    struct ggml_tensor *ffn_down_b;

    /* LN at end of layer block (post-FFN). */
    struct ggml_tensor *layer_out_norm_w;
    struct ggml_tensor *layer_out_norm_b;
} bge_m3_layer_t;

/* The BGE-M3 model handle. Tensor pointers reference the loader's
 * ggml_context. Lifetime is loader-bound: free the model BEFORE
 * the loader. */
typedef struct {
    /* Metadata mirrored from the GGUF KVs. */
    uint32_t n_layers;
    uint32_t n_heads;
    uint32_t n_embd;
    uint32_t n_ffn;
    uint32_t n_vocab; /* derived from token_embd shape, not from a KV */
    uint32_t n_ctx;
    float ln_eps;

    /* Token / position / type embeddings. */
    struct ggml_tensor *token_embd;        /* [n_embd, n_vocab] */
    struct ggml_tensor *position_embd;     /* [n_embd, n_ctx]   */
    struct ggml_tensor *type_embd;         /* [n_embd, n_types] — optional, may be NULL */
    struct ggml_tensor *token_embd_norm_w; /* [n_embd] */
    struct ggml_tensor *token_embd_norm_b; /* [n_embd] */

    /* Per-layer tensors. Heap-allocated array of n_layers entries. */
    bge_m3_layer_t *layers;
} bge_m3_model_t;

/*
 * Resolve all BGE-M3 tensors from a loaded GGUF, validating
 * architecture and shape consistency.
 *
 * Returns:
 *   ANTS_OK                 — *out_model populated.
 *   ANTS_ERROR_INVALID_ARG  — NULL args.
 *   ANTS_ERROR_MALFORMED    — required metadata KV missing or
 *                             architecture mismatch.
 *   ANTS_ERROR_NON_CANONICAL — a required tensor is missing or its
 *                              declared shape disagrees with the
 *                              metadata dims.
 *
 * The model is heap-allocated; free with bge_m3_free.
 */
ants_error_t bge_m3_load_from_gguf(const embed_gguf_loader_t *loader, bge_m3_model_t **out_model);

/* Tear down a model handle. Frees the layers[] array and the model
 * struct. Tensor pointers are not freed — they live in the loader's
 * ggml_context. Safe on NULL. */
void bge_m3_free(bge_m3_model_t *model);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_EMBED_MODEL_H */
