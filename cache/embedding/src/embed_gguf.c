/*
 * embed_gguf.c — implementation of the buffer-input GGUF loader.
 *
 * Bridges our caller-supplies-a-buffer contract with ggml's
 * caller-supplies-a-FILE loader via fmemopen(3). See embed_gguf.h for
 * scope.
 */

/* fmemopen is POSIX 2008. On glibc, the prototype is hidden behind
 * _POSIX_C_SOURCE >= 200809L; macOS exposes it unconditionally but the
 * gate is harmless there. Must come before any system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "embed_gguf.h"

#include "ggml.h"
#include "gguf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct embed_gguf_loader {
    struct gguf_context *gguf;
    struct ggml_context *ggml;
    /* Kept for documentation / lifetime-coupling-tracking only; ggml
     * may or may not alias into it depending on no_alloc. */
    const uint8_t *src_buf;
    size_t src_len;
};

ants_error_t embed_gguf_load(const uint8_t *buf, size_t len, embed_gguf_loader_t **out_loader)
{
    if (buf == NULL || len == 0 || out_loader == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_loader = NULL;

    embed_gguf_loader_t *loader = (embed_gguf_loader_t *)calloc(1, sizeof(*loader));
    if (loader == NULL) {
        return ANTS_ERROR_MALFORMED;
    }

    /* fmemopen reads from a void*; the contents are not modified in
     * "rb" mode. The cast strips const at the API boundary only. */
    FILE *file = fmemopen((void *)(uintptr_t)buf, len, "rb");
    if (file == NULL) {
        free(loader);
        return ANTS_ERROR_MALFORMED;
    }

    struct ggml_context *ggml_ctx = NULL;
    struct gguf_init_params params = {
        /* no_alloc = false: allocate a ggml_context and load tensor
         * data into it. The tensor pointers stay valid until
         * embed_gguf_free. */
        /* clang-format off */
        .no_alloc = false,
        .ctx      = &ggml_ctx,
        /* clang-format on */
    };
    struct gguf_context *gguf_ctx = gguf_init_from_file_ptr(file, params);
    fclose(file);

    if (gguf_ctx == NULL) {
        /* gguf_init may have created ggml_ctx before failing — defensive
         * cleanup to avoid leaking it. */
        if (ggml_ctx != NULL) {
            ggml_free(ggml_ctx);
        }
        free(loader);
        return ANTS_ERROR_MALFORMED;
    }

    loader->gguf = gguf_ctx;
    loader->ggml = ggml_ctx;
    loader->src_buf = buf;
    loader->src_len = len;
    *out_loader = loader;
    return ANTS_OK;
}

void embed_gguf_free(embed_gguf_loader_t *loader)
{
    if (loader == NULL) {
        return;
    }
    if (loader->gguf != NULL) {
        gguf_free(loader->gguf);
    }
    if (loader->ggml != NULL) {
        ggml_free(loader->ggml);
    }
    free(loader);
}

/* ------------------------------------------------------------------ */
/* Metadata accessors                                                 */
/* ------------------------------------------------------------------ */

int64_t embed_gguf_n_kv(const embed_gguf_loader_t *loader)
{
    if (loader == NULL || loader->gguf == NULL) {
        return -1;
    }
    return gguf_get_n_kv(loader->gguf);
}

int64_t embed_gguf_n_tensors(const embed_gguf_loader_t *loader)
{
    if (loader == NULL || loader->gguf == NULL) {
        return -1;
    }
    return gguf_get_n_tensors(loader->gguf);
}

uint32_t embed_gguf_version(const embed_gguf_loader_t *loader)
{
    if (loader == NULL || loader->gguf == NULL) {
        return 0;
    }
    return gguf_get_version(loader->gguf);
}

const char *embed_gguf_get_str(const embed_gguf_loader_t *loader, const char *key)
{
    if (loader == NULL || loader->gguf == NULL || key == NULL) {
        return NULL;
    }
    int64_t id = gguf_find_key(loader->gguf, key);
    if (id < 0) {
        return NULL;
    }
    if (gguf_get_kv_type(loader->gguf, id) != GGUF_TYPE_STRING) {
        return NULL;
    }
    return gguf_get_val_str(loader->gguf, id);
}

ants_error_t embed_gguf_get_u32(const embed_gguf_loader_t *loader, const char *key, uint32_t *out)
{
    if (loader == NULL || loader->gguf == NULL || key == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    int64_t id = gguf_find_key(loader->gguf, key);
    if (id < 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (gguf_get_kv_type(loader->gguf, id) != GGUF_TYPE_UINT32) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out = gguf_get_val_u32(loader->gguf, id);
    return ANTS_OK;
}

ants_error_t embed_gguf_get_u64(const embed_gguf_loader_t *loader, const char *key, uint64_t *out)
{
    if (loader == NULL || loader->gguf == NULL || key == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    int64_t id = gguf_find_key(loader->gguf, key);
    if (id < 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (gguf_get_kv_type(loader->gguf, id) != GGUF_TYPE_UINT64) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out = gguf_get_val_u64(loader->gguf, id);
    return ANTS_OK;
}

ants_error_t embed_gguf_get_f32(const embed_gguf_loader_t *loader, const char *key, float *out)
{
    if (loader == NULL || loader->gguf == NULL || key == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    int64_t id = gguf_find_key(loader->gguf, key);
    if (id < 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (gguf_get_kv_type(loader->gguf, id) != GGUF_TYPE_FLOAT32) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out = gguf_get_val_f32(loader->gguf, id);
    return ANTS_OK;
}

struct ggml_tensor *embed_gguf_find_tensor(const embed_gguf_loader_t *loader, const char *name)
{
    if (loader == NULL || loader->ggml == NULL || name == NULL) {
        return NULL;
    }
    /* ggml_get_tensor requires non-const ctx; the call itself does not
     * mutate the context for a lookup. Cast at the boundary. */
    return ggml_get_tensor((struct ggml_context *)loader->ggml, name);
}
