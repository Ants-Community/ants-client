/*
 * embed.c — Canonical embedding service (Component #11).
 *
 * Phase 3 + Phase 4 (stub-inference variant). The hash-verification
 * path is implemented for real: when the protocol-pinned hash is
 * non-zero, the buffer is BLAKE3'd and constant-time-compared; a
 * mismatch refuses initialisation. When the pinned hash is all-zero
 * (the placeholder state per RFC-0008 §5: "the specific 32-byte
 * values for v1 will be set when the reference client is published"),
 * verification is skipped — this is the v0.x phase where the
 * canonical bundle has not yet been pinned. The non-zero path becomes
 * meaningful as soon as phase 5 lands the real BGE-M3 hashes.
 *
 * The inference path is a STUB. ants_embed currently derives a
 * deterministic 1024-dim L2-normalised float vector from the input
 * bytes via BLAKE3-keyed expansion. It is NOT a real BGE-M3
 * embedding; it has zero semantic meaning. It exists so:
 *
 *   - cache/semantic can be developed and tested against a stable
 *     ants_embed contract (same input → same output, every call,
 *     on the same platform),
 *   - the API surface and lifecycle ordering are exercised end-to-
 *     end (init → embed → destroy),
 *   - and a future PR can replace ONLY the inference implementation
 *     without touching the public API.
 *
 * Replacing the stub with real ggml-backed BGE-M3 inference is phase
 * 4-real (a follow-up PR that consumes the vendored deps/ggml). The
 * test vectors at ants-test-vectors/vectors/ants-embed-v1/ will be
 * populated jointly with that PR, against a fixed BGE-M3 checkpoint.
 */

#include "ants_embed.h"

#include "ants_crypto.h"

#include <math.h>
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
/* ------------------------------------------------------------------------ */

struct ants_embed_state {
    bool initialised;
    uint8_t _pad[7];
    const uint8_t *weights;
    size_t weights_len;
    const uint8_t *tokenizer;
    size_t tokenizer_len;
};

typedef char ants_embed_state_size_check
    [(sizeof(struct ants_embed_state) <= sizeof(((ants_embed_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Hash verification                                                        */
/*                                                                          */
/* Per RFC-0002: "no close enough, bit-exact match or rejection". The      */
/* check has two semantically distinct paths:                              */
/*                                                                          */
/*   - pinned == all-zero: v0.x placeholder phase. We have no real hash to */
/*     compare against, so verification is skipped (the caller is on their */
/*     own to ship the right weights). Returns ANTS_OK.                    */
/*   - pinned != all-zero: BLAKE3 the buffer, constant-time-compare to    */
/*     the pinned value. Mismatch → ANTS_ERROR_NON_CANONICAL.              */
/*                                                                          */
/* Exposed via a test hook (ants_embed__test_verify) so the verify path   */
/* can be exercised end-to-end even while the public pinned constants are */
/* still placeholder zeros.                                                */
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
    /* Constant-time compare via XOR-accumulate over all 32 bytes. */
    uint8_t diff = 0;
    for (size_t i = 0; i < ANTS_BLAKE3_HASH_SIZE; i++) {
        diff |= (uint8_t)(actual[i] ^ pinned[i]);
    }
    return diff == 0 ? ANTS_OK : ANTS_ERROR_NON_CANONICAL;
}

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
    ants_error_t err = ants_embed__test_verify(
        config->weights, config->weights_len, ANTS_EMBED_WEIGHTS_HASH_PINNED);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_embed__test_verify(
        config->tokenizer, config->tokenizer_len, ANTS_EMBED_TOKENIZER_HASH_PINNED);
    if (err != ANTS_OK) {
        return err;
    }
    memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    struct ants_embed_state *state = (struct ants_embed_state *)(void *)ctx->_opaque;
    state->initialised = true;
    state->weights = config->weights;
    state->weights_len = config->weights_len;
    state->tokenizer = config->tokenizer;
    state->tokenizer_len = config->tokenizer_len;
    return ANTS_OK;
}

ants_error_t ants_embed_destroy(ants_embed_t *ctx)
{
    if (ctx == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Stub inference                                                           */
/*                                                                          */
/* Deterministic 1024-dim float embedding derived from the input bytes via */
/* BLAKE3. Algorithm:                                                      */
/*                                                                          */
/*   seed = BLAKE3(input)                            (32 bytes)            */
/*   For chunk_idx in 0..127:                                              */
/*       chunk_input = seed || chunk_idx_LE32       (36 bytes)             */
/*       bytes[chunk_idx*32 .. +32] = BLAKE3(chunk_input)                  */
/*   For i in 0..1023:                                                     */
/*       bits = uint32_LE from bytes[i*4 .. +4]                            */
/*       out[i] = (bits/2^32)*2 - 1                  in [-1, 1)            */
/*   L2-normalise out to unit length.                                       */
/*                                                                          */
/* Properties:                                                              */
/*   - deterministic: same input → same output (same platform);            */
/*   - L2-normalised: ||out||_2 == 1.0 ± tiny FP rounding;                 */
/*   - distinct inputs → distinct outputs (BLAKE3 collision resistance);   */
/*   - NOT bit-exact across platforms (float multiplication ordering);    */
/*   - NOT a real BGE-M3 embedding — zero semantic meaning. The whole     */
/*     point is to be a stand-in until phase 4-real ggml inference lands. */
/* ------------------------------------------------------------------------ */

#define EMBED_STUB_CHUNK_COUNT (ANTS_EMBED_DIM / 8) /* 128 BLAKE3 calls × 32 B = 4096 B */

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
    if (!state->initialised) {
        return ANTS_ERROR_INVALID_ARG;
    }

    uint8_t seed[ANTS_BLAKE3_HASH_SIZE];
    ants_error_t err = ants_blake3_hash(input_bytes, input_len, seed);
    if (err != ANTS_OK) {
        return err;
    }

    /* 4096 bytes of derived material via 128 keyed BLAKE3 calls. */
    uint8_t bytes[ANTS_EMBED_DIM * 4];
    uint8_t chunk_input[ANTS_BLAKE3_HASH_SIZE + 4];
    memcpy(chunk_input, seed, ANTS_BLAKE3_HASH_SIZE);
    for (uint32_t chunk_idx = 0; chunk_idx < EMBED_STUB_CHUNK_COUNT; chunk_idx++) {
        chunk_input[ANTS_BLAKE3_HASH_SIZE + 0] = (uint8_t)(chunk_idx & 0xFFu);
        chunk_input[ANTS_BLAKE3_HASH_SIZE + 1] = (uint8_t)((chunk_idx >> 8) & 0xFFu);
        chunk_input[ANTS_BLAKE3_HASH_SIZE + 2] = (uint8_t)((chunk_idx >> 16) & 0xFFu);
        chunk_input[ANTS_BLAKE3_HASH_SIZE + 3] = (uint8_t)((chunk_idx >> 24) & 0xFFu);
        err = ants_blake3_hash(
            chunk_input, sizeof chunk_input, &bytes[chunk_idx * ANTS_BLAKE3_HASH_SIZE]);
        if (err != ANTS_OK) {
            return err;
        }
    }

    /* Map 4-byte LE chunks to floats in [-1, 1). */
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        uint32_t bits = (uint32_t)bytes[i * 4 + 0] | ((uint32_t)bytes[i * 4 + 1] << 8) |
                        ((uint32_t)bytes[i * 4 + 2] << 16) | ((uint32_t)bytes[i * 4 + 3] << 24);
        /* 2^32 = 4294967296.0. Mapping is exact for bits a multiple of 256,
         * close enough otherwise (FP rounding is the same on every IEEE 754
         * conformant target). */
        float u01 = (float)bits * (1.0f / 4294967296.0f);
        out[i] = u01 * 2.0f - 1.0f;
    }

    /* L2-normalise so ||out||_2 == 1. Accumulate in double to keep
     * rounding noise minimal across the 1024-term sum. */
    double sum_sq = 0.0;
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        double v = (double)out[i];
        sum_sq += v * v;
    }
    double norm = sqrt(sum_sq);
    if (norm < 1e-30) {
        /* Pathological all-zero output — would require a BLAKE3 preimage
         * that produces 1024 zero u32s, which is cryptographically
         * impossible. Defensive bail just to keep the divide safe. */
        return ANTS_ERROR_NON_CANONICAL;
    }
    float inv_norm = (float)(1.0 / norm);
    for (size_t i = 0; i < ANTS_EMBED_DIM; i++) {
        out[i] *= inv_norm;
    }
    return ANTS_OK;
}
