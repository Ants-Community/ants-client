/*
 * test_embed_gguf.c — exercises the GGUF buffer loader.
 *
 * The fixtures are built in memory at test time via ggml + gguf upstream
 * APIs (gguf_init_empty + ggml_init + gguf_add_tensor + gguf_write_to_file_ptr
 * to a tmpfile, then read the bytes back into a buffer). This avoids
 * shipping a binary GGUF blob in the test tree and exercises the wrapper
 * against fresh, deterministic input on every run.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "embed_gguf.h"

#include "ggml.h"
#include "gguf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond)                                                                               \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define ASSERT_OK(expr)                                                                            \
    do {                                                                                           \
        ants_error_t _e = (expr);                                                                  \
        if (_e != ANTS_OK) {                                                                       \
            fprintf(stderr, "FAIL %s:%d: %s -> %d\n", __FILE__, __LINE__, #expr, (int)_e);         \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define ASSERT_ERR(expr, want)                                                                     \
    do {                                                                                           \
        ants_error_t _r = (expr);                                                                  \
        if (_r != (want)) {                                                                        \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d: %s -> %d (want %d)\n",                                            \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    #expr,                                                                         \
                    (int)_r,                                                                       \
                    (int)(want));                                                                  \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Drive ggml's GGUF writer onto a tmpfile, then read the bytes back
 * into a freshly-malloced buffer. Caller frees *out_buf. */
static int build_gguf_buffer(struct gguf_context *gguf, uint8_t **out_buf, size_t *out_len)
{
    FILE *f = tmpfile();
    if (f == NULL) {
        return -1;
    }
    if (!gguf_write_to_file_ptr(gguf, f, false)) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int test_loader_empty(void)
{
    struct gguf_context *gguf = gguf_init_empty();
    ASSERT(gguf != NULL);

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = build_gguf_buffer(gguf, &buf, &len);
    gguf_free(gguf);
    ASSERT(rc == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(buf, len, &loader));
    ASSERT(loader != NULL);
    ASSERT(embed_gguf_version(loader) == GGUF_VERSION);
    ASSERT(embed_gguf_n_kv(loader) == 0);
    ASSERT(embed_gguf_n_tensors(loader) == 0);
    ASSERT(embed_gguf_find_tensor(loader, "no.such.tensor") == NULL);
    ASSERT(embed_gguf_get_str(loader, "no.such.key") == NULL);

    embed_gguf_free(loader);
    free(buf);
    return 0;
}

static int test_loader_kv(void)
{
    struct gguf_context *gguf = gguf_init_empty();
    ASSERT(gguf != NULL);

    gguf_set_val_str(gguf, "general.architecture", "ants-test");
    gguf_set_val_u32(gguf, "test.dim", 1024U);
    gguf_set_val_u64(gguf, "test.count", (uint64_t)0xDEADBEEFCAFEBABEULL);
    gguf_set_val_f32(gguf, "test.alpha", 0.5f);

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = build_gguf_buffer(gguf, &buf, &len);
    gguf_free(gguf);
    ASSERT(rc == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(buf, len, &loader));
    ASSERT(embed_gguf_n_kv(loader) == 4);
    ASSERT(embed_gguf_n_tensors(loader) == 0);

    const char *arch = embed_gguf_get_str(loader, "general.architecture");
    ASSERT(arch != NULL);
    ASSERT(strcmp(arch, "ants-test") == 0);

    uint32_t dim = 0;
    ASSERT_OK(embed_gguf_get_u32(loader, "test.dim", &dim));
    ASSERT(dim == 1024U);

    uint64_t count = 0;
    ASSERT_OK(embed_gguf_get_u64(loader, "test.count", &count));
    ASSERT(count == (uint64_t)0xDEADBEEFCAFEBABEULL);

    float alpha = 0.0f;
    ASSERT_OK(embed_gguf_get_f32(loader, "test.alpha", &alpha));
    ASSERT(alpha == 0.5f);

    /* Wrong-type access on an existing key: u32 read of a string. */
    uint32_t bad_u32 = 0;
    ASSERT_ERR(embed_gguf_get_u32(loader, "general.architecture", &bad_u32),
               ANTS_ERROR_INVALID_ARG);

    /* Missing key. */
    uint32_t missing = 0;
    ASSERT_ERR(embed_gguf_get_u32(loader, "no.such.key", &missing), ANTS_ERROR_INVALID_ARG);
    ASSERT(embed_gguf_get_str(loader, "test.dim") == NULL); /* wrong type for str accessor */

    embed_gguf_free(loader);
    free(buf);
    return 0;
}

static int test_loader_tensor(void)
{
    struct ggml_init_params ggml_params = {
        /* clang-format off */
        .mem_size   = (size_t)1 << 18, /* 256 KiB scratch */
        .mem_buffer = NULL,
        .no_alloc   = false,
        /* clang-format on */
    };
    struct ggml_context *ggml_ctx = ggml_init(ggml_params);
    ASSERT(ggml_ctx != NULL);

    struct ggml_tensor *t = ggml_new_tensor_2d(ggml_ctx, GGML_TYPE_F32, 4, 4);
    ASSERT(t != NULL);
    ggml_set_name(t, "test.weight");

    /* Populate with a pattern of 0.25-multiples — exactly representable
     * in FP32 so cross-platform bit-equality is trivial. */
    float *data = (float *)t->data;
    ASSERT(data != NULL);
    for (int i = 0; i < 16; i++) {
        data[i] = (float)i * 0.25f;
    }

    struct gguf_context *gguf = gguf_init_empty();
    ASSERT(gguf != NULL);
    gguf_set_val_str(gguf, "general.architecture", "ants-test");
    gguf_add_tensor(gguf, t);

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = build_gguf_buffer(gguf, &buf, &len);
    gguf_free(gguf);
    ggml_free(ggml_ctx);
    ASSERT(rc == 0);

    embed_gguf_loader_t *loader = NULL;
    ASSERT_OK(embed_gguf_load(buf, len, &loader));
    ASSERT(embed_gguf_n_tensors(loader) == 1);

    struct ggml_tensor *got = embed_gguf_find_tensor(loader, "test.weight");
    ASSERT(got != NULL);
    ASSERT(got->ne[0] == 4 && got->ne[1] == 4);
    ASSERT(got->type == GGML_TYPE_F32);

    const float *got_data = (const float *)got->data;
    ASSERT(got_data != NULL);
    for (int i = 0; i < 16; i++) {
        float want = (float)i * 0.25f;
        ASSERT(got_data[i] == want);
    }

    ASSERT(embed_gguf_find_tensor(loader, "no.such.tensor") == NULL);

    embed_gguf_free(loader);
    free(buf);
    return 0;
}

static int test_loader_bad_args(void)
{
    embed_gguf_loader_t *loader = NULL;
    const uint8_t one_byte = 0;

    ASSERT_ERR(embed_gguf_load(NULL, 4, &loader), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(embed_gguf_load(&one_byte, 0, &loader), ANTS_ERROR_INVALID_ARG);
    ASSERT_ERR(embed_gguf_load(&one_byte, 1, NULL), ANTS_ERROR_INVALID_ARG);

    /* Garbage bytes — not GGUF magic. */
    uint8_t garbage[64];
    memset(garbage, 0xAB, sizeof garbage);
    ASSERT_ERR(embed_gguf_load(garbage, sizeof garbage, &loader), ANTS_ERROR_MALFORMED);
    ASSERT(loader == NULL);

    /* Wrong magic but plausible header — first 4 bytes != "GGUF". */
    uint8_t wrong_magic[24];
    memset(wrong_magic, 0, sizeof wrong_magic);
    memcpy(wrong_magic, "NOPE", 4);
    ASSERT_ERR(embed_gguf_load(wrong_magic, sizeof wrong_magic, &loader), ANTS_ERROR_MALFORMED);
    ASSERT(loader == NULL);

    return 0;
}

static int test_loader_truncated(void)
{
    struct gguf_context *gguf = gguf_init_empty();
    ASSERT(gguf != NULL);
    gguf_set_val_str(gguf, "general.architecture", "ants-test");
    gguf_set_val_u32(gguf, "test.dim", 1024U);

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = build_gguf_buffer(gguf, &buf, &len);
    gguf_free(gguf);
    ASSERT(rc == 0);
    ASSERT(len > 16);

    /* Truncate mid-stream. The exact failure mode (bad magic on a
     * mis-aligned read, short read, etc.) is ggml-internal — we only
     * require that the wrapper does NOT return ANTS_OK and does NOT
     * leak through a NULL loader. */
    embed_gguf_loader_t *loader = NULL;
    ants_error_t e = embed_gguf_load(buf, len / 2, &loader);
    ASSERT(e == ANTS_ERROR_MALFORMED);
    ASSERT(loader == NULL);

    free(buf);
    return 0;
}

static int test_free_null_safe(void)
{
    embed_gguf_free(NULL);
    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        {"loader_empty", test_loader_empty},
        {"loader_kv", test_loader_kv},
        {"loader_tensor", test_loader_tensor},
        {"loader_bad_args", test_loader_bad_args},
        {"loader_truncated", test_loader_truncated},
        {"free_null_safe", test_free_null_safe},
    };
    size_t n = sizeof(tests) / sizeof(tests[0]);
    int failed = 0;
    for (size_t i = 0; i < n; i++) {
        printf("[ RUN ] %s\n", tests[i].name);
        int rc = tests[i].fn();
        if (rc != 0) {
            printf("[FAIL ] %s\n", tests[i].name);
            failed++;
        } else {
            printf("[ OK  ] %s\n", tests[i].name);
        }
    }
    printf("\n%zu tests, %d failed\n", n, failed);
    return failed == 0 ? 0 : 1;
}
