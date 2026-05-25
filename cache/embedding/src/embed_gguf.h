/*
 * embed_gguf.h — GGUF buffer loader for the canonical embedding service.
 *
 * Private to cache/embedding (NOT installed). Wraps ggml's gguf_init_*
 * with an in-memory-buffer entry point — our public ants_embed_config_t
 * takes a weights buffer, but upstream's loader only consumes a FILE *.
 * The wrapper bridges the two with fmemopen().
 *
 * Responsibilities of this layer:
 *   - Take a caller-owned weights buffer (typically the bytes of a
 *     pinned GGUF file on disk, already validated against the
 *     protocol-pinned BLAKE3) and parse it into a queryable structure.
 *   - Expose metadata (KV pairs) and tensor descriptors via thin
 *     accessors — no architecture knowledge here.
 *   - Own both the gguf_context (metadata index) and the ggml_context
 *     (tensor storage) for the lifetime of the loaded model.
 *
 * NOT responsible for:
 *   - Validating the model architecture or tensor shapes against a
 *     particular spec (BGE-M3 schema lives in the next layer up).
 *   - Verifying hashes against ANTS_EMBED_*_HASH_PINNED — that runs
 *     before we get the buffer (in ants_embed_init).
 *   - Forward inference — only the loader / index lives here.
 *
 * fmemopen(3) is POSIX 2008. The project's CI matrix is Ubuntu + macOS;
 * both expose it through glibc / Darwin libc respectively. Windows is
 * NOT a current target; if it ever becomes one, this module will need
 * a Windows-specific path (e.g. CreateFileMapping + tmpfile fallback).
 */

#ifndef ANTS_EMBED_GGUF_H
#define ANTS_EMBED_GGUF_H

#include "ants_common.h"

#include <stddef.h>
#include <stdint.h>

/* Forward-declare ggml types so consumers don't need ggml headers
 * unless they actually traverse tensors. */
struct ggml_tensor;

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque loader handle. Lifetime: heap-allocated by embed_gguf_load,
 * freed by embed_gguf_free. Owns the gguf_context + ggml_context. */
typedef struct embed_gguf_loader embed_gguf_loader_t;

/*
 * Parse a GGUF blob in `buf` (length `len`) and return a loader handle.
 *
 * `buf` MUST remain valid for the loader's lifetime — internally
 * the wrapper drives ggml's file-pointer loader via fmemopen, but
 * tensor data may be referenced into the buffer depending on ggml's
 * decisions; we hold the pointer in the loader to make the lifetime
 * coupling explicit.
 *
 * Returns:
 *   ANTS_OK          — loader populated in *out_loader.
 *   ANTS_ERROR_INVALID_ARG — NULL args or zero length.
 *   ANTS_ERROR_MALFORMED   — fmemopen failed or GGUF parse failed
 *                            (bad magic, truncated, unsupported
 *                            version, etc.).
 */
ants_error_t embed_gguf_load(const uint8_t *buf, size_t len, embed_gguf_loader_t **out_loader);

/*
 * Tear down a loader. Frees the gguf_context, the ggml_context, and
 * the loader struct itself. Safe on NULL.
 */
void embed_gguf_free(embed_gguf_loader_t *loader);

/* ------------------------------------------------------------------ */
/* Metadata accessors                                                 */
/*                                                                    */
/* Each accessor returns a defined sentinel (NULL / negative / error) */
/* when the key is missing or has the wrong type. None of them abort. */
/* ------------------------------------------------------------------ */

/* Returns total number of KV pairs in the file. */
int64_t embed_gguf_n_kv(const embed_gguf_loader_t *loader);

/* Returns total number of tensors declared in the file. */
int64_t embed_gguf_n_tensors(const embed_gguf_loader_t *loader);

/* Returns the GGUF wire version (1, 2, 3, ...). */
uint32_t embed_gguf_version(const embed_gguf_loader_t *loader);

/* String KV accessor. Returns NULL when key missing OR when the
 * value type is not GGUF_TYPE_STRING. The returned pointer lives
 * inside the gguf_context — valid until embed_gguf_free. */
const char *embed_gguf_get_str(const embed_gguf_loader_t *loader, const char *key);

/* Unsigned-integer KV accessors. Return ANTS_ERROR_INVALID_ARG when
 * key missing or type mismatched; ANTS_OK when *out populated. */
ants_error_t embed_gguf_get_u32(const embed_gguf_loader_t *loader, const char *key, uint32_t *out);
ants_error_t embed_gguf_get_u64(const embed_gguf_loader_t *loader, const char *key, uint64_t *out);
ants_error_t embed_gguf_get_f32(const embed_gguf_loader_t *loader, const char *key, float *out);

/* Tensor lookup by name. Returns NULL when not found. The returned
 * ggml_tensor lives inside the loader's ggml_context — valid until
 * embed_gguf_free. */
struct ggml_tensor *embed_gguf_find_tensor(const embed_gguf_loader_t *loader, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_EMBED_GGUF_H */
