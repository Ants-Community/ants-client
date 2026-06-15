/*
 * embed_vectors.c — drive the canonical embedding service over real inputs.
 *
 * Loads a GGUF weights file + a HuggingFace tokenizer.json from disk,
 * brings up ants_embed, and prints the L2-normalised float32[ANTS_EMBED_DIM]
 * vector for each input string.
 *
 * Dual use:
 *   1. Validation harness — diff the printed vectors against an independent
 *      reference embedder (e.g. llama.cpp's llama-embedding on the SAME
 *      GGUF) to confirm the ggml graph in embed_forward.c is wired right.
 *   2. Emitter — produce the ants-test-vectors embedding conformance pack
 *      once the canonical model is pinned.
 *
 * NOT built by default (gated behind ANTS_BUILD_EMBED_TOOLS) and NOT part
 * of the protocol surface — a developer/CI convenience that links the same
 * ants_embed library a peer would.
 *
 * Usage:
 *   embed_vectors <model.gguf> <tokenizer.json> [-p "text"]...
 *
 * With one or more -p arguments, each is embedded in order. With none,
 * one input per line is read from stdin (trailing newline stripped).
 *
 * Output: one line per input, ANTS_EMBED_DIM space-separated %.9g floats
 * (9 significant digits round-trips float32 exactly in decimal). A short
 * provenance + per-vector summary (L2 norm, which must be ~1.0) goes to
 * stderr so stdout stays a clean numeric matrix for diffing.
 */

/* getline(3) + ssize_t are POSIX 2008; glibc hides them without this. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_crypto.h"
#include "ants_embed.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Slurp an entire file into a malloc'd buffer. Returns NULL on failure;
 * *out_len holds the byte count on success. Handles multi-GB files
 * (stat's off_t is 64-bit on the Linux+macOS CI targets). */
static uint8_t *slurp(const char *path, size_t *out_len)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0) {
        fprintf(stderr, "embed_vectors: cannot stat '%s'\n", path);
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "embed_vectors: cannot open '%s'\n", path);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL) {
        fprintf(stderr, "embed_vectors: OOM allocating %zu bytes for '%s'\n", len, path);
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, len, fp);
    fclose(fp);
    if (got != len) {
        fprintf(stderr, "embed_vectors: short read on '%s' (%zu/%zu)\n", path, got, len);
        free(buf);
        return NULL;
    }
    *out_len = len;
    return buf;
}

static int embed_and_print(ants_embed_t *ctx, const char *text, size_t text_len)
{
    float vec[ANTS_EMBED_DIM];
    ants_error_t e = ants_embed(ctx, (const uint8_t *)text, text_len, vec);
    if (e != ANTS_OK) {
        fprintf(stderr, "embed_vectors: ants_embed failed (%d) on input of %zu bytes\n",
                (int)e, text_len);
        return -1;
    }
    double sumsq = 0.0;
    for (int i = 0; i < ANTS_EMBED_DIM; i++) {
        sumsq += (double)vec[i] * (double)vec[i];
    }
    fprintf(stderr, "  [ok] %zu bytes -> dim=%d L2=%.6f v0=%.6f\n",
            text_len, ANTS_EMBED_DIM, sumsq, vec[0]);
    for (int i = 0; i < ANTS_EMBED_DIM; i++) {
        if (i) {
            putchar(' ');
        }
        printf("%.9g", (double)vec[i]);
    }
    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <model.gguf> <tokenizer.json> [-p text]...\n", argv[0]);
        return 2;
    }
    const char *model_path = argv[1];
    const char *tok_path = argv[2];

    size_t weights_len = 0, tok_len = 0;
    uint8_t *weights = slurp(model_path, &weights_len);
    if (weights == NULL) {
        return 1;
    }
    uint8_t *tokenizer = slurp(tok_path, &tok_len);
    if (tokenizer == NULL) {
        free(weights);
        return 1;
    }
    fprintf(stderr, "embed_vectors: weights=%s (%zu B) tokenizer=%s (%zu B)\n",
            model_path, weights_len, tok_path, tok_len);

    /* --hashes: print the BLAKE3 of each buffer (the exact bytes and the
     * exact hash ants_embed_init checks against the pinned constants) and
     * exit, without bringing up ggml. These are the candidate
     * ANTS_EMBED_WEIGHTS_HASH_PINNED / ANTS_EMBED_TOKENIZER_HASH_PINNED. */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--hashes") == 0) {
            uint8_t wh[ANTS_BLAKE3_HASH_SIZE], th[ANTS_BLAKE3_HASH_SIZE];
            if (ants_blake3_hash(weights, weights_len, wh) != ANTS_OK ||
                ants_blake3_hash(tokenizer, tok_len, th) != ANTS_OK) {
                fprintf(stderr, "embed_vectors: blake3 failed\n");
                free(weights);
                free(tokenizer);
                return 1;
            }
            printf("weights_blake3   = ");
            for (int k = 0; k < ANTS_BLAKE3_HASH_SIZE; k++) {
                printf("%02x", wh[k]);
            }
            printf("\ntokenizer_blake3 = ");
            for (int k = 0; k < ANTS_BLAKE3_HASH_SIZE; k++) {
                printf("%02x", th[k]);
            }
            printf("\n");
            free(weights);
            free(tokenizer);
            return 0;
        }
    }

    ants_embed_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.weights = weights;
    cfg.weights_len = weights_len;
    cfg.tokenizer = tokenizer;
    cfg.tokenizer_len = tok_len;

    ants_embed_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ants_error_t e = ants_embed_init(&ctx, &cfg);
    if (e != ANTS_OK) {
        fprintf(stderr, "embed_vectors: ants_embed_init failed (%d)\n", (int)e);
        free(weights);
        free(tokenizer);
        return 1;
    }
    fprintf(stderr, "embed_vectors: init OK\n");

    int rc = 0;
    int did_any = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            const char *text = argv[++i];
            did_any = 1;
            if (embed_and_print(&ctx, text, strlen(text)) != 0) {
                rc = 1;
            }
        }
    }

    if (!did_any) {
        /* Read one input per line from stdin. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getline(&line, &cap, stdin)) != -1) {
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
                line[--n] = '\0';
            }
            if (n == 0) {
                continue;
            }
            if (embed_and_print(&ctx, line, (size_t)n) != 0) {
                rc = 1;
            }
        }
        free(line);
    }

    ants_embed_destroy(&ctx);
    free(weights);
    free(tokenizer);
    return rc;
}
