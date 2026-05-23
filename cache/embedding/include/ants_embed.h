/*
 * ants_embed.h — Canonical embedding service (Component #11).
 *
 * The cache layer's pinned-checkpoint embedding model: turns input bytes
 * into a deterministic 1024-dimensional dense vector that all conformant
 * peers compute identically for the same input. Used by cache/semantic
 * to LSH-route entries onto the DHT and by retrieval to compare similarity.
 *
 * Spec references:
 *   - RFC-0002 §The canonical embedding model — bit-exact requirement,
 *     version-transition discipline, governance.
 *   - RFC-0002 §Governance of the canonical embedding model — eight-week
 *     comment window, RFC process, TSC two-thirds vote post-v1.0.
 *   - RFC-0008 §5 Embedding model pinning — the exact metadata tuple
 *     (model_id, model_arch, weights_hash, tokenizer_hash) every peer
 *     must agree on bit-for-bit.
 *
 * Implementation strategy:
 *
 *   The canonical model at v0.1 launch is `ants-embed-v1`, derived from
 *   BAAI's BGE-M3 family (multilingual, 1024-dim dense output). Inference
 *   runs in C via `ggml`'s primitives — BGE-M3 is small enough to fit in
 *   ggml's transformer ops at acceptable latency (sub-200 ms on commodity
 *   CPU per the spec).
 *
 *   The weights and tokenizer JSON are loaded from caller-supplied
 *   buffers; the library does no I/O. The caller is responsible for
 *   producing these buffers (likely from a pinned download verified
 *   against the protocol-pinned BLAKE3 hashes). `ants_embed_init`
 *   re-verifies the hashes internally as a defence-in-depth check —
 *   a mismatch refuses to start (per the spec: "no close enough,
 *   bit-exact match or rejection").
 *
 *   Concrete hash values: the v1 pinned hashes are
 *   `ANTS_EMBED_WEIGHTS_HASH_PINNED` and `ANTS_EMBED_TOKENIZER_HASH_PINNED`,
 *   currently all-zero placeholders per RFC-0008 §5 (set when the
 *   reference client is published against the exact BGE-M3 checkpoint
 *   the reference client ships with). Until those are filled in, init
 *   accepts any weights+tokenizer that hash to the placeholder — which
 *   is impossible, so init returns ANTS_ERROR_NOT_IMPLEMENTED. The first
 *   real-hash PR will both populate the constants AND make init succeed
 *   on a matching buffer.
 *
 * API model: synchronous, single-shot. Caller-allocated context, no
 * threads, no logging, no malloc beyond what ggml itself allocates
 * inside the opaque buffer. Output is always exactly ANTS_EMBED_DIM
 * (= 1024) float32 values.
 */

#ifndef ANTS_EMBED_H
#define ANTS_EMBED_H

#include "ants_common.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Protocol-pinned metadata (RFC-0008 §5)                                   */
/*                                                                          */
/* These constants are the cross-peer agreement object. Every peer claiming */
/* support for `ANTS_EMBED_MODEL_ID` MUST be running a model whose          */
/* safetensors-encoded weights hash to ANTS_EMBED_WEIGHTS_HASH_PINNED and   */
/* whose tokenizer JSON hashes to ANTS_EMBED_TOKENIZER_HASH_PINNED.         */
/* ------------------------------------------------------------------------ */

/* Output dimension. The canonical model is 1024-dim dense. Changing this
 * is a protocol break (would require a new ANTS_EMBED_MODEL_ID and the
 * governance dance in RFC-0002 §Governance of the canonical embedding
 * model). */
#define ANTS_EMBED_DIM 1024

/* Protocol-version-pinned identifier. Set to "ants-embed-v1" for the v1
 * canonical model. A future "ants-embed-v2" introduction is a coordinated
 * RFC-process event per RFC-0002 §Governance. */
extern const char *const ANTS_EMBED_MODEL_ID;

/* Architecture family — informational, used for diagnostics and for
 * cross-peer compatibility chatter at handshake time. */
extern const char *const ANTS_EMBED_MODEL_ARCH;

/* Pinned hashes (32-byte BLAKE3) of the canonical-model artifacts.
 *
 * v0.x scaffold: both are 0x000...000 placeholders. They are populated
 * with the real BLAKE3 of the chosen BGE-M3 checkpoint + tokenizer when
 * the reference client publishes the v1 canonical bundle (per RFC-0008
 * §5: "the specific 32-byte values for v1 will be set when the reference
 * client is published").
 *
 * Treat any non-zero value here as the protocol-version-pinned canonical
 * hash. Treat all-zero as "v1 hash not yet pinned" — `ants_embed_init`
 * declines initialization in that state to prevent accidentally shipping
 * a peer with the wrong weights. */
extern const uint8_t ANTS_EMBED_WEIGHTS_HASH_PINNED[32];
extern const uint8_t ANTS_EMBED_TOKENIZER_HASH_PINNED[32];

/* ------------------------------------------------------------------------ */
/* Opaque context                                                           */
/*                                                                          */
/* Caller allocates. Sized for the ggml runtime state plus the loaded     */
/* model weights pointer table — the actual weights stay in caller-       */
/* supplied buffers (we never copy hundreds of MB), only the inference     */
/* scratch + index lives here. Conservative oversize so internal layout    */
/* changes don't break ABI for downstream consumers compiled against this */
/* header. The .c file enforces actual bounds via the compile-time-       */
/* assertion idiom.                                                         */
/* ------------------------------------------------------------------------ */

/* 64 KiB starting estimate. Will be tightened (or grown) once the ggml-
 * backed inference implementation lands and we measure its actual
 * footprint. */
#define ANTS_EMBED_CTX_SIZE 65536

typedef union {
    uint8_t _opaque[ANTS_EMBED_CTX_SIZE];
    uint64_t _align;
} ants_embed_t;

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/*                                                                          */
/* `weights` and `tokenizer` point at caller-owned memory that MUST remain  */
/* valid for the lifetime of the ants_embed_t — the library does not copy   */
/* them. The buffers are the *exact* safetensors and tokenizer-JSON bytes;  */
/* `ants_embed_init` BLAKE3-hashes each and compares against the pinned    */
/* values, refusing with ANTS_ERROR_NON_CANONICAL on mismatch (per          */
/* RFC-0002: "no close enough, bit-exact match or rejection").              */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* In-memory safetensors weights blob. Must hash to
     * ANTS_EMBED_WEIGHTS_HASH_PINNED under BLAKE3. Typically loaded from
     * a pinned file on disk (the caller owns the file I/O). */
    const uint8_t *weights;
    size_t weights_len;

    /* In-memory tokenizer JSON. Must hash to
     * ANTS_EMBED_TOKENIZER_HASH_PINNED under BLAKE3. */
    const uint8_t *tokenizer;
    size_t tokenizer_len;
} ants_embed_config_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Initialise an embedding context. Hashes both weights and tokenizer
 * with BLAKE3 and verifies against the protocol-pinned values.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL ctx/config or zero-length buffer;
 *   ANTS_ERROR_NON_CANONICAL — weights or tokenizer hash mismatch
 *     against the pinned value;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase (hashes are placeholders
 *     and/or ggml integration hasn't landed yet).
 *
 * On success the ctx is ready for ants_embed() calls. The weights and
 * tokenizer pointers must remain valid until ants_embed_destroy().
 */
ants_error_t ants_embed_init(ants_embed_t *ctx, const ants_embed_config_t *config);

/*
 * Tear down. Releases any internal ggml state. The caller's weights /
 * tokenizer buffers are NOT freed (library never owned them).
 *
 * Safe on a zeroed (never-initialised) ctx — returns ANTS_OK without
 * touching anything.
 */
ants_error_t ants_embed_destroy(ants_embed_t *ctx);

/* ------------------------------------------------------------------------ */
/* Inference                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Embed `input_bytes` (a UTF-8 encoded string or any byte sequence the
 * tokenizer accepts) into `out` — an array of ANTS_EMBED_DIM float32
 * values. The mapping is deterministic: the same input bytes on the
 * same canonical model produce identical output to the bit, on any
 * conformant peer.
 *
 * Output normalisation: the embedding is L2-normalised to unit length,
 * so cosine similarity reduces to a dot product (which is what
 * cache/semantic's lookup path computes).
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or zero-length input;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase, no inference yet.
 */
ants_error_t ants_embed(ants_embed_t *ctx,
                        const uint8_t *input_bytes,
                        size_t input_len,
                        float out[ANTS_EMBED_DIM]);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_EMBED_H */
