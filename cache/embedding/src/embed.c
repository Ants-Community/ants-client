/*
 * embed.c — Canonical embedding service stubs (Component #11).
 *
 * Phase 0 scaffolding. Public API declared in include/ants_embed.h;
 * everything here returns ANTS_ERROR_NOT_IMPLEMENTED until the per-PR
 * implementation lands:
 *
 *   - Phase 1: vendor ggml under deps/ggml/, wire as a static library.
 *   - Phase 2: vendor the BGE-M3 tokenizer + a loader for the JSON.
 *   - Phase 3: implement ants_embed_init's hash verification (the BLAKE3
 *     check is doable today, but useful only once the pinned hashes are
 *     real — see RFC-0008 §5).
 *   - Phase 4: implement ants_embed via ggml inference.
 *   - Phase 5: pin the actual v1 BGE-M3 weights+tokenizer hashes in
 *     constants below and ship the canonical bundle to ants-test-vectors.
 *
 * The public ANTS_EMBED_CTX_SIZE constant exists to let downstream
 * components (cache/semantic) compile against a stable opaque type
 * during phases 0-4 without having to wait for the inference work.
 */

#include "ants_embed.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Protocol-pinned constants                                                */
/*                                                                          */
/* All-zero placeholders for the hashes per RFC-0008 §5. The real values    */
/* land in phase 5 of this component, jointly with the test-vector pack    */
/* publication (ants-test-vectors/vectors/ants-embed-v1/).                  */
/* ------------------------------------------------------------------------ */

const char *const ANTS_EMBED_MODEL_ID = "ants-embed-v1";
const char *const ANTS_EMBED_MODEL_ARCH = "bge-m3";

const uint8_t ANTS_EMBED_WEIGHTS_HASH_PINNED[32] = {0};
const uint8_t ANTS_EMBED_TOKENIZER_HASH_PINNED[32] = {0};

/* ------------------------------------------------------------------------ */
/* Internal state layout                                                    */
/*                                                                          */
/* Even the stub keeps a struct definition so the compile-time-assertion   */
/* below catches an accidental ANTS_EMBED_CTX_SIZE shrink that would       */
/* break the real implementation later. The struct only carries the        */
/* config pointers + an initialised flag for now.                          */
/* ------------------------------------------------------------------------ */

struct ants_embed_state {
    bool initialised;
    uint8_t _pad[7];
    const uint8_t *weights;
    size_t weights_len;
    const uint8_t *tokenizer;
    size_t tokenizer_len;
    /* Phase 4 will append a ggml context handle + per-call scratch
     * pointer here. The 64 KiB budget should accommodate it; if not,
     * grow ANTS_EMBED_CTX_SIZE at the same time as the API consumers'
     * downstream rebuilds. */
};

typedef char ants_embed_state_size_check
    [(sizeof(struct ants_embed_state) <= sizeof(((ants_embed_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_embed_init(ants_embed_t *ctx, const ants_embed_config_t *config)
{
    if (ctx == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (config->weights == NULL || config->weights_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (config->tokenizer == NULL || config->tokenizer_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Scaffold: BLAKE3 hash verification + ggml load are deferred. We
     * still validate argument shape above so callers get a stable
     * contract during the scaffold phase. */
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_embed_destroy(ants_embed_t *ctx)
{
    if (ctx == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Safe on a zeroed ctx (the docstring guarantees it). The phase-4
     * ggml-backed implementation will tear down ggml state here; for
     * now there's nothing to release. */
    memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Inference                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_embed(ants_embed_t *ctx,
                        const uint8_t *input_bytes,
                        size_t input_len,
                        float out[ANTS_EMBED_DIM])
{
    if (ctx == NULL || input_bytes == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (input_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
