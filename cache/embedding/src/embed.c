/*
 * embed.c — Canonical embedding service (Component #11), phase 4-real
 * step 5d.
 *
 * The stub from step 5-stub is gone. ants_embed_init now drives the
 * full BGE-M3 pipeline:
 *
 *   1. Hash-verify both the weights and the tokenizer JSON against
 *      the pinned BLAKE3 (placeholders skip per RFC-0008 §5).
 *   2. Parse the weights as a GGUF (embed_gguf).
 *   3. Bind the BGE-M3 tensors (embed_model). Validates that the
 *      file declares ANTS_EMBED_DIM as its embedding_length —
 *      anything else fails ANTS_ERROR_NON_CANONICAL, even if the
 *      file is internally consistent.
 *   4. Parse the tokenizer.json into a vocab blob.
 *   5. Init the Unigram tokenizer (NFKC + byte-fallback NOT enabled
 *      at this step; caller-supplied vocab is expected to cover
 *      whitespace-separated UTF-8 input).
 *
 * ants_embed runs the BGE-M3 forward via embed_forward:
 *
 *   tokenize input bytes → wrap as <s> ... </s> (content capped to
 *   model->n_ctx - 2) → cast uint32 → int32 → bge_m3_forward → out
 *   (already L2-normalised inside forward). The <s>/</s> wrap is required:
 *   BGE-M3's dense vector is the <s> hidden state that CLS pooling reads.
 *
 * The opaque ctx still holds only the small state struct plus the
 * inline tokenizer; the gguf loader, model, and vocab blob live in
 * heap allocations referenced through state pointers.
 */

#include "ants_embed.h"

#include "ants_crypto.h"
#include "ants_tokenizer.h"
#include "embed_forward.h"
#include "embed_gguf.h"
#include "embed_model.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Protocol-pinned constants                                                */
/* ------------------------------------------------------------------------ */

const char *const ANTS_EMBED_MODEL_ID = "ants-embed-v1";
const char *const ANTS_EMBED_MODEL_ARCH = "bge-m3";

/* ants-embed-v1 pinned BLAKE3 hashes (RFC-0008 §5.1). No longer placeholders:
 *   weights   = BLAKE3 of the canonical BGE-M3 F32 GGUF (2 273 655 072 bytes)
 *   tokenizer = BLAKE3 of the canonical BAAI/bge-m3 tokenizer.json (17 098 108 B)
 * With these non-zero, ants_embed_init strictly verifies both buffers and
 * rejects (NON_CANONICAL) anything that does not hash to them — no "close
 * enough". See RFC-0008 §5 for provenance and how to obtain the exact files. */
const uint8_t ANTS_EMBED_WEIGHTS_HASH_PINNED[32] = {
    0x30, 0x55, 0xcf, 0x6c, 0x5e, 0xc0, 0xb4, 0x1d, 0xa5, 0xc8, 0x67, 0xcf, 0x0c, 0xa0, 0xb1, 0x83,
    0x1a, 0x98, 0x51, 0x68, 0xdf, 0x83, 0x52, 0x64, 0x5b, 0x04, 0xdc, 0xb8, 0x5b, 0x0d, 0x26, 0xe6};
const uint8_t ANTS_EMBED_TOKENIZER_HASH_PINNED[32] = {
    0xa0, 0x85, 0x38, 0x5b, 0x8b, 0x6f, 0x4a, 0x3f, 0x16, 0xa3, 0x49, 0x3c, 0x18, 0x0e, 0x69, 0x4f,
    0x92, 0x89, 0x7e, 0x91, 0x9d, 0x00, 0xaa, 0x9b, 0x3c, 0xd7, 0xfb, 0xff, 0xe1, 0x26, 0x9c, 0xee};

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* magic = "ANSE" identifies a fully-initialised state; embed_destroy on a  */
/* zeroed (never-initialised) ctx is a no-op because magic == 0 there.     */
/* Same discipline as ants_transport_state in network/transport/src.       */
/* ------------------------------------------------------------------------ */

#define ANTS_EMBED_STATE_MAGIC 0x414E5345u /* 'A','N','S','E' */

struct ants_embed_state {
    uint32_t magic;
    uint8_t _pad[4];

    /* Caller-owned buffers (kept for documentation; the heap resources
     * below reference into the weights blob for tensor data). */
    const uint8_t *weights;
    size_t weights_len;
    const uint8_t *tokenizer;
    size_t tokenizer_len;

    /* Heap-owned resources. Destroy order: tokenizer (uses vocab_blob)
     * → vocab_blob → model (uses loader's ggml_context) → loader. */
    embed_gguf_loader_t *gguf_loader;
    bge_m3_model_t *model;
    ants_tokenizer_vocab_blob_t *vocab_blob;

    /* Inline tokenizer ctx (1 KiB; ants_tokenizer_t is a union). */
    ants_tokenizer_t tok;
};

typedef char ants_embed_state_size_check
    [(sizeof(struct ants_embed_state) <= sizeof(((ants_embed_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Hash verification. ants_embed__test_verify is the shared check: an all-zero
 * (placeholder) pinned value skips — used only by unit tests passing explicit
 * zeros — while a real pinned value (the v1 constants above) BLAKE3-compares
 * bit-exactly. ants_embed_init runs it against the pinned constants before
 * touching ggml.                                                            */
/* ------------------------------------------------------------------------ */

static bool pinned_is_placeholder(const uint8_t pinned[32])
{
    for (size_t i = 0; i < 32; i++) {
        if (pinned[i] != 0) {
            return false;
        }
    }
    return true;
}

ants_error_t ants_embed__test_verify(const uint8_t *buf, size_t len, const uint8_t pinned[32]);
ants_error_t ants_embed__test_verify(const uint8_t *buf, size_t len, const uint8_t pinned[32])
{
    if (buf == NULL || len == 0 || pinned == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (pinned_is_placeholder(pinned)) {
        return ANTS_OK;
    }
    uint8_t actual[ANTS_BLAKE3_HASH_SIZE];
    ants_error_t err = ants_blake3_hash(buf, len, actual);
    if (err != ANTS_OK) {
        return err;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < ANTS_BLAKE3_HASH_SIZE; i++) {
        diff |= (uint8_t)(actual[i] ^ pinned[i]);
    }
    return diff == 0 ? ANTS_OK : ANTS_ERROR_NON_CANONICAL;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

static void tear_down(struct ants_embed_state *state)
{
    if (state == NULL) {
        return;
    }
    if (state->magic == ANTS_EMBED_STATE_MAGIC) {
        (void)ants_tokenizer_destroy(&state->tok);
    }
    if (state->vocab_blob != NULL) {
        ants_tokenizer_vocab_free(state->vocab_blob);
        state->vocab_blob = NULL;
    }
    if (state->model != NULL) {
        bge_m3_free(state->model);
        state->model = NULL;
    }
    if (state->gguf_loader != NULL) {
        embed_gguf_free(state->gguf_loader);
        state->gguf_loader = NULL;
    }
}

/* Argument validation shared by the checked and unchecked init paths. */
static ants_error_t embed_validate_config(const ants_embed_t *ctx,
                                          const ants_embed_config_t *config)
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
    return ANTS_OK;
}

/* Bring the model up: parse GGUF, bind tensors, dim-check, load + init the
 * tokenizer. Assumes config is already validated. Does NOT hash-verify — the
 * caller decides whether to gate on the pinned hashes. On any failure all
 * partial allocations are released and the ctx is left zeroed. */
static ants_error_t embed_bring_up(ants_embed_t *ctx, const ants_embed_config_t *config)
{
    memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    struct ants_embed_state *state = (struct ants_embed_state *)(void *)ctx->_opaque;
    state->weights = config->weights;
    state->weights_len = config->weights_len;
    state->tokenizer = config->tokenizer;
    state->tokenizer_len = config->tokenizer_len;

    /* Parse GGUF + bind the model. */
    ants_error_t err = embed_gguf_load(config->weights, config->weights_len, &state->gguf_loader);
    if (err != ANTS_OK) {
        tear_down(state);
        return err;
    }
    err = bge_m3_load_from_gguf(state->gguf_loader, &state->model);
    if (err != ANTS_OK) {
        tear_down(state);
        return err;
    }

    /* Protocol-pinned dim check: the canonical model is 1024-dim. A
     * GGUF that's internally consistent but with a different dim
     * (e.g. BGE-M3-small) is REJECTED here even though the binder
     * accepted it. */
    if (state->model->n_embd != ANTS_EMBED_DIM) {
        tear_down(state);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Parse tokenizer.json + bring up the Unigram tokenizer. */
    err = ants_tokenizer_load_huggingface_json(
        (const char *)config->tokenizer, config->tokenizer_len, &state->vocab_blob);
    if (err != ANTS_OK) {
        tear_down(state);
        return err;
    }
    const ants_tokenizer_vocab_entry_t *vocab = ants_tokenizer_vocab_entries(state->vocab_blob);
    size_t vocab_size = ants_tokenizer_vocab_size(state->vocab_blob);
    err = ants_tokenizer_init(&state->tok, vocab, vocab_size);
    if (err != ANTS_OK) {
        tear_down(state);
        return err;
    }

    state->magic = ANTS_EMBED_STATE_MAGIC;
    return ANTS_OK;
}

ants_error_t ants_embed_init(ants_embed_t *ctx, const ants_embed_config_t *config)
{
    ants_error_t err = embed_validate_config(ctx, config);
    if (err != ANTS_OK) {
        return err;
    }

    /* Hash-verify both buffers against the pinned v1 values before we touch
     * ggml. The pinned constants are non-zero, so a mismatch refuses init. */
    err = ants_embed__test_verify(
        config->weights, config->weights_len, ANTS_EMBED_WEIGHTS_HASH_PINNED);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_embed__test_verify(
        config->tokenizer, config->tokenizer_len, ANTS_EMBED_TOKENIZER_HASH_PINNED);
    if (err != ANTS_OK) {
        return err;
    }

    return embed_bring_up(ctx, config);
}

/* Test hook: bring the model up WITHOUT the pinned-hash gate. The unit tests
 * run against a tiny synthetic GGUF that cannot hash to the canonical v1 value,
 * so they need a way past the gate to exercise the forward path; production
 * code must always use ants_embed_init. Declared via extern in the test TU. */
ants_error_t ants_embed__test_init_unchecked(ants_embed_t *ctx, const ants_embed_config_t *config);
ants_error_t ants_embed__test_init_unchecked(ants_embed_t *ctx, const ants_embed_config_t *config)
{
    ants_error_t err = embed_validate_config(ctx, config);
    if (err != ANTS_OK) {
        return err;
    }
    return embed_bring_up(ctx, config);
}

ants_error_t ants_embed_destroy(ants_embed_t *ctx)
{
    if (ctx == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_embed_state *state = (struct ants_embed_state *)(void *)ctx->_opaque;
    tear_down(state);
    memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Inference                                                                */
/* ------------------------------------------------------------------------ */

/* Bound on token ids the forward pass accepts in a single call. BGE-M3
 * supports up to 8192 positions; we cap to the model's declared n_ctx
 * at runtime. The stack-allocated array below sizes for the worst
 * case so we don't malloc per call. */
#define ANTS_EMBED_MAX_TOKENS 8192

/* XLM-RoBERTa / BGE-M3 special-token ids. Fixed by the pinned tokenizer.json
 * (added_tokens: id 0 = "<s>", id 2 = "</s>"). The Unigram encoder emits
 * content pieces only (special tokens are the caller's job, per
 * ants_tokenizer.h); the model expects the input wrapped as <s> ... </s>.
 * BGE-M3's dense embedding is the hidden state of the <s> token at position 0
 * — precisely what bge_m3_forward's CLS pooling reads. Omit the wrap and the
 * pool returns the first *content* token's state, yielding a wrong vector. */
#define ANTS_EMBED_BOS_ID 0u
#define ANTS_EMBED_EOS_ID 2u

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
    struct ants_embed_state *state = (struct ants_embed_state *)(void *)ctx->_opaque;
    if (state->magic != ANTS_EMBED_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Tokenize content, then wrap as [<s>, content..., </s>]. Reserve two
     * slots of the model window for the special tokens; cap content to
     * min(model->n_ctx, ANTS_EMBED_MAX_TOKENS) - 2. ants_tokenizer_encode
     * emits uint32_t ids cast down to int32_t (vocab << 2^31, lossless). */
    const size_t window = (state->model->n_ctx < (uint32_t)ANTS_EMBED_MAX_TOKENS)
                              ? state->model->n_ctx
                              : (uint32_t)ANTS_EMBED_MAX_TOKENS;
    const size_t content_cap = window > 2 ? window - 2 : 0;
    uint32_t ids_u32[ANTS_EMBED_MAX_TOKENS];
    size_t n_content = 0;
    ants_error_t err = ants_tokenizer_encode(
        &state->tok, (const char *)input_bytes, input_len, ids_u32, content_cap, &n_content);
    /* BUFFER_TOO_SMALL is not a hard failure here: the input was longer
     * than what the model can attend to in one window. ants_tokenizer
     * leaves *out_count at the count it WOULD have written; we truncate
     * to content_cap. */
    if (err == ANTS_ERROR_BUFFER_TOO_SMALL) {
        n_content = content_cap;
    } else if (err != ANTS_OK) {
        return err;
    }

    int32_t ids_i32[ANTS_EMBED_MAX_TOKENS];
    size_t n_tokens = 0;
    ids_i32[n_tokens++] = (int32_t)ANTS_EMBED_BOS_ID;
    for (size_t i = 0; i < n_content; i++) {
        ids_i32[n_tokens++] = (int32_t)ids_u32[i];
    }
    ids_i32[n_tokens++] = (int32_t)ANTS_EMBED_EOS_ID;

    return bge_m3_forward(state->model, ids_i32, (uint32_t)n_tokens, NULL, out);
}
