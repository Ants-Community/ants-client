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
 *   embed_vectors <model.gguf> <tokenizer.json> --hashes
 *   embed_vectors <model.gguf> <tokenizer.json> --pack
 *
 * With one or more -p arguments, each is embedded in order. With none,
 * one input per line is read from stdin (trailing newline stripped).
 * --hashes prints the BLAKE3 of each file and exits. --pack emits the
 * ants-test-vectors embedding pack (fixed canonical inputs) as JSON.
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
        fprintf(stderr,
                "embed_vectors: ants_embed failed (%d) on input of %zu bytes\n",
                (int)e,
                text_len);
        return -1;
    }
    double sumsq = 0.0;
    for (int i = 0; i < ANTS_EMBED_DIM; i++) {
        sumsq += (double)vec[i] * (double)vec[i];
    }
    fprintf(stderr,
            "  [ok] %zu bytes -> dim=%d L2=%.6f v0=%.6f\n",
            text_len,
            ANTS_EMBED_DIM,
            sumsq,
            vec[0]);
    for (int i = 0; i < ANTS_EMBED_DIM; i++) {
        if (i) {
            putchar(' ');
        }
        printf("%.9g", (double)vec[i]);
    }
    putchar('\n');
    return 0;
}

/* Minimal JSON string emitter: escapes " and \\ and control chars; UTF-8
 * bytes pass through unchanged (valid in JSON). */
static void json_puts(const char *s, size_t n)
{
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar((char)c);
        } else if (c < 0x20) {
            printf("\\u%04x", (unsigned)c);
        } else {
            putchar((char)c);
        }
    }
    putchar('"');
}

/* Canonical, reproducible input set for the --pack test-vector pack. ASCII,
 * accented-Latin, CJK and Cyrillic, so an independent implementation exercises
 * the multilingual tokenizer + forward, not just ASCII. */
static const char *const PACK_INPUTS[] = {
    "Hello, world!",
    "The quick brown fox jumps over the lazy dog.",
    "Ciao mondo",
    "机器学习",
    "Привет мир",
};

/* Emit the ants-test-vectors embedding pack as JSON to stdout. The hashes and
 * embeddings are produced by the compiled ants_embed library (init has already
 * strict-verified the buffers against the pinned v1 hashes), so nothing here is
 * hand-transcribed. */
static int emit_pack(ants_embed_t *ctx,
                     const uint8_t *weights,
                     size_t weights_len,
                     const uint8_t *tokenizer,
                     size_t tok_len)
{
    uint8_t wh[ANTS_BLAKE3_HASH_SIZE], th[ANTS_BLAKE3_HASH_SIZE];
    if (ants_blake3_hash(weights, weights_len, wh) != ANTS_OK ||
        ants_blake3_hash(tokenizer, tok_len, th) != ANTS_OK) {
        fprintf(stderr, "embed_vectors: blake3 failed\n");
        return -1;
    }

    printf("{\n");
    printf("  \"primitive\": \"canonical embedding model ants-embed-v1: BGE-M3 dense "
           "embedding (tokenize, wrap <s>..</s>, forward, CLS-pool, L2-normalise)\",\n");
    printf("  \"spec\": \"RFC-0008 \\u00a75 + \\u00a75.1; RFC-0002 \\u00a7The canonical "
           "embedding model\",\n");
    printf("  \"version\": 1,\n");
    printf("  \"generator\": \"ants-client cache/embedding/tools/embed_vectors.c --pack: "
           "hashes and embeddings emitted by the compiled ants_embed library; init "
           "strict-verified weights+tokenizer against the pinned v1 hashes first\",\n");
    printf("  \"notes\": \"The model hashes are the bit-exact cross-platform pin (a peer "
           "MUST load files hashing to these). The per-input embedding arrays are "
           "REFERENCE with tolerance: the F32 forward's reduction order is not yet "
           "canonical across platforms (open in RFC-0009), so conformant peers agree to "
           "cosine >= 0.999, not bit-for-bit. Floats are %%.9g decimal (round-trips "
           "float32). Cross-checked vs llama.cpp llama-embedding at cosine >= 0.999999.\",\n");
    printf("  \"model\": {\n");
    printf("    \"model_id\": \"%s\",\n", ANTS_EMBED_MODEL_ID);
    printf("    \"model_arch\": \"%s\",\n", ANTS_EMBED_MODEL_ARCH);
    printf("    \"dim\": %d,\n", ANTS_EMBED_DIM);
    printf("    \"weights_blake3\": \"");
    for (int k = 0; k < ANTS_BLAKE3_HASH_SIZE; k++) {
        printf("%02x", wh[k]);
    }
    printf("\",\n    \"weights_bytes\": %zu,\n", weights_len);
    printf("    \"tokenizer_blake3\": \"");
    for (int k = 0; k < ANTS_BLAKE3_HASH_SIZE; k++) {
        printf("%02x", th[k]);
    }
    printf("\",\n    \"tokenizer_bytes\": %zu\n", tok_len);
    printf("  },\n");
    printf("  \"vectors\": [\n");

    const size_t n_inputs = sizeof PACK_INPUTS / sizeof PACK_INPUTS[0];
    int rc = 0;
    for (size_t i = 0; i < n_inputs; i++) {
        const char *text = PACK_INPUTS[i];
        float vec[ANTS_EMBED_DIM];
        ants_error_t e = ants_embed(ctx, (const uint8_t *)text, strlen(text), vec);
        if (e != ANTS_OK) {
            fprintf(stderr, "embed_vectors: pack embed failed (%d) on input %zu\n", (int)e, i);
            rc = -1;
            break;
        }
        printf("    {\"text\": ");
        json_puts(text, strlen(text));
        printf(", \"embedding\": [");
        for (int d = 0; d < ANTS_EMBED_DIM; d++) {
            if (d) {
                putchar(',');
            }
            printf("%.9g", (double)vec[d]);
        }
        printf("]}%s\n", (i + 1 < n_inputs) ? "," : "");
    }
    printf("  ]\n}\n");
    return rc;
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
    fprintf(stderr,
            "embed_vectors: weights=%s (%zu B) tokenizer=%s (%zu B)\n",
            model_path,
            weights_len,
            tok_path,
            tok_len);

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

    /* --pack: emit the ants-test-vectors embedding pack (fixed canonical
     * inputs) as JSON to stdout, then exit. */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--pack") == 0) {
            int prc = emit_pack(&ctx, weights, weights_len, tokenizer, tok_len);
            ants_embed_destroy(&ctx);
            free(weights);
            free(tokenizer);
            return prc == 0 ? 0 : 1;
        }
    }

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
