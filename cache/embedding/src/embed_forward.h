/*
 * embed_forward.h — BGE-M3 / XLM-RoBERTa-large forward pass.
 *
 * Private to cache/embedding. Sits on top of embed_model: takes a
 * bound bge_m3_model_t and a sequence of token ids, executes the
 * full transformer forward, applies CLS pooling, and L2-normalises
 * the result.
 *
 * Single entry point: bge_m3_forward(). Builds and tears down a
 * compute context per call. Step 5d will hoist the compute context
 * into ants_embed_t so successive calls reuse the buffer, but the
 * graph still rebuilds per-call (seq_len is dynamic).
 *
 * Numerical contract: deterministic on a single platform with a
 * given ggml version, n_threads=1. Bit-exactness across platforms
 * is NOT guaranteed at this layer — that's the canonical-numerics
 * problem RFC-0009 owns. Phase 5 will add a cross-platform vector
 * pack and pin the numerics path.
 */

#ifndef ANTS_EMBED_FORWARD_H
#define ANTS_EMBED_FORWARD_H

#include "ants_common.h"
#include "embed_model.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Execute the BGE-M3 forward pass on a sequence of token ids.
 *
 * Inputs:
 *   model       — bound model (see embed_model.h).
 *   input_ids   — token ids of length n_tokens. Caller's responsibility
 *                 to ensure each id is < model->n_vocab.
 *   n_tokens    — sequence length. Must be in [1, model->n_ctx].
 *   type_ids    — optional token-type ids of length n_tokens. If the
 *                 model has model->type_embd != NULL and type_ids is
 *                 NULL, all-zero type ids are assumed (XLM-R style).
 *                 If model->type_embd is NULL, this argument is
 *                 ignored.
 *   out         — caller-supplied float buffer of size model->n_embd.
 *                 Filled with the L2-normalised pooled embedding.
 *
 * Returns:
 *   ANTS_OK                  — out populated.
 *   ANTS_ERROR_INVALID_ARG   — NULL args, n_tokens out of range.
 *   ANTS_ERROR_MALFORMED     — internal allocation or compute failure.
 *   ANTS_ERROR_NON_CANONICAL — pooled vector had zero L2 norm
 *                              (cryptographically improbable with
 *                              real weights; defends against a
 *                              pathological all-zero model in tests).
 */
ants_error_t bge_m3_forward(const bge_m3_model_t *model,
                            const int32_t *input_ids,
                            uint32_t n_tokens,
                            const int32_t *type_ids,
                            float *out);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_EMBED_FORWARD_H */
