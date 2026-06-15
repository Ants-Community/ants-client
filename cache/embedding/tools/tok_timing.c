/*
 * tok_timing.c — micro-benchmark the tokenizer bring-up on a real
 * tokenizer.json. Isolates load_huggingface_json vs tokenizer_init vs a
 * sample encode, so we can see which phase dominates at the full 250k-entry
 * XLM-R vocab (the test fixtures are tiny and never exercise scale).
 *
 * Gated behind ANTS_BUILD_EMBED_TOOLS; not protocol surface.
 *
 * Usage: tok_timing <tokenizer.json> [text-to-encode]
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_tokenizer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

static char *slurp(const char *path, size_t *out_len)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0) {
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    char *buf = (char *)malloc(len);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, len, fp);
    fclose(fp);
    if (got != len) {
        free(buf);
        return NULL;
    }
    *out_len = len;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <tokenizer.json> [text]\n", argv[0]);
        return 2;
    }
    size_t json_len = 0;
    char *json = slurp(argv[1], &json_len);
    if (!json) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    printf("tokenizer.json: %zu bytes\n", json_len);

    double t0 = now_ms();
    ants_tokenizer_vocab_blob_t *blob = NULL;
    ants_error_t e = ants_tokenizer_load_huggingface_json(json, json_len, &blob);
    double t1 = now_ms();
    if (e != ANTS_OK) {
        fprintf(stderr, "load_huggingface_json failed: %d\n", (int)e);
        return 1;
    }
    const ants_tokenizer_vocab_entry_t *vocab = ants_tokenizer_vocab_entries(blob);
    size_t n_vocab = ants_tokenizer_vocab_size(blob);
    printf("load_huggingface_json: %.1f ms  (n_vocab=%zu)\n", t1 - t0, n_vocab);

    double t2 = now_ms();
    ants_tokenizer_t tok;
    memset(&tok, 0, sizeof tok);
    e = ants_tokenizer_init(&tok, vocab, n_vocab);
    double t3 = now_ms();
    if (e != ANTS_OK) {
        fprintf(stderr, "tokenizer_init failed: %d\n", (int)e);
        return 1;
    }
    printf("tokenizer_init:        %.1f ms\n", t3 - t2);

    const char *text = argc >= 3 ? argv[2] : "Hello, world!";
    uint32_t ids[512];
    size_t n = 0;
    double t4 = now_ms();
    e = ants_tokenizer_encode(&tok, text, strlen(text), ids, 512, &n);
    double t5 = now_ms();
    printf("encode(%.40s): %.3f ms  rc=%d  n_tokens=%zu\n", text, t5 - t4, (int)e, n);
    if (e == ANTS_OK) {
        printf("  ids:");
        for (size_t i = 0; i < n && i < 32; i++) {
            printf(" %u", ids[i]);
        }
        printf("\n");
    }

    ants_tokenizer_destroy(&tok);
    ants_tokenizer_vocab_free(blob);
    free(json);
    return 0;
}
