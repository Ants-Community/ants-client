/*
 * tokenizer_json.c — HuggingFace tokenizer.json loader for the Unigram
 *                    tokenizer (Component #11, phase 4-real step 2).
 *
 * Parses the JSON config that ships with every HuggingFace Unigram
 * model (XLM-RoBERTa, BGE-M3, etc.) and extracts the
 * `model.vocab` = [[token, score], [token, score], ...] array into
 * an ants_tokenizer_vocab_blob_t suitable for ants_tokenizer_init.
 *
 * Uses jsmn (vendored under deps/jsmn/) for the JSON tokenization
 * pass. jsmn is a minimal tokenizer (returns a flat array of typed
 * spans into the source buffer); we walk those spans to locate the
 * vocab array and extract entries.
 *
 * Memory layout of the returned blob:
 *
 *   struct ants_tokenizer_vocab_blob {
 *       entries: ants_tokenizer_vocab_entry_t[n_vocab]
 *       text_pool: char[]   // all unescaped token text bytes packed
 *   }
 *
 * Each entry's `text` pointer aliases into text_pool. Single-pass
 * allocation: we first count vocab entries to size the entries array,
 * then unescape token strings into a sized text_pool. text_pool can
 * be smaller than the source JSON because escape sequences shrink
 * (e.g. \uXXXX → 1-3 UTF-8 bytes).
 *
 * What is parsed:
 *   - model.vocab array (top-level path: $.model.vocab)
 *
 * What is NOT parsed in step 2 (added in later step PRs):
 *   - normalizer / pre_tokenizer / post_processor / decoder configs
 *   - added_tokens / special_tokens (caller handles out-of-band)
 *   - model.unk_id (caller knows it from the vocab structure)
 *   - surrogate pairs in \uXXXX (codepoints above U+FFFF rare in vocab)
 */

#include "ants_tokenizer.h"

/* JSMN_PARENT_LINKS makes jsmn store each token's parent index and resolve
 * containers in O(1). Without it, jsmn closes every '}'/']' by scanning
 * backwards over all tokens emitted so far — O(n) per close, O(n^2) over
 * the whole file. On a real 250K-entry XLM-R/BGE-M3 vocab (~750K tokens)
 * that backward scan turns a sub-second parse into a multi-minute hang;
 * the tiny test fixtures never reach the scale that exposes it. */
#define JSMN_PARENT_LINKS
#define JSMN_STATIC
#include "jsmn.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Blob storage                                                             */
/* ------------------------------------------------------------------------ */

struct ants_tokenizer_vocab_blob {
    ants_tokenizer_vocab_entry_t *entries;
    size_t n_vocab;
    char *text_pool;
    size_t text_pool_size;
};

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/* Compare a jsmn string token to a literal. Returns true on match. */
static bool tok_eq(const char *json, const jsmntok_t *t, const char *lit)
{
    size_t lit_len = strlen(lit);
    size_t tlen = (size_t)(t->end - t->start);
    return t->type == JSMN_STRING && tlen == lit_len && memcmp(json + t->start, lit, lit_len) == 0;
}

/* Skip subtree starting at index i. Returns the index AFTER the
 * subtree. jsmn stores `size` as the number of direct children for
 * objects and arrays. We walk recursively. */
static int skip_subtree(const jsmntok_t *toks, int i, int n_tok)
{
    if (i >= n_tok) {
        return n_tok;
    }
    int children = toks[i].size;
    i++;
    if (toks[i - 1].type == JSMN_OBJECT) {
        /* For objects, size is the number of KEY-VALUE pairs; each pair
         * is one key string plus one value (which may itself be a
         * subtree). */
        for (int k = 0; k < children; k++) {
            i++; /* skip key */
            i = skip_subtree(toks, i, n_tok);
        }
    } else if (toks[i - 1].type == JSMN_ARRAY) {
        for (int k = 0; k < children; k++) {
            i = skip_subtree(toks, i, n_tok);
        }
    }
    return i;
}

/* Find the value-token index for a given key inside the object at
 * toks[obj_idx]. Returns -1 if not found. */
static int
find_object_key(const char *json, const jsmntok_t *toks, int obj_idx, int n_tok, const char *key)
{
    if (obj_idx >= n_tok || toks[obj_idx].type != JSMN_OBJECT) {
        return -1;
    }
    int n_pairs = toks[obj_idx].size;
    int cur = obj_idx + 1;
    for (int k = 0; k < n_pairs; k++) {
        if (cur >= n_tok) {
            return -1;
        }
        if (tok_eq(json, &toks[cur], key)) {
            return cur + 1;
        }
        cur++; /* skip key */
        cur = skip_subtree(toks, cur, n_tok);
    }
    return -1;
}

/* Parse a JSON number from json[start..end] into a float. The number
 * grammar is restrictive (digits, sign, decimal point, exponent), so
 * strtof handles it correctly. Returns true on success. */
static bool parse_number(const char *json, int start, int end, float *out)
{
    /* Copy into a NUL-terminated buffer because strtof wants one. */
    size_t len = (size_t)(end - start);
    if (len == 0 || len > 63) {
        return false;
    }
    char buf[64];
    memcpy(buf, json + start, len);
    buf[len] = '\0';
    char *endp = NULL;
    float v = strtof(buf, &endp);
    if (endp != buf + len) {
        return false;
    }
    *out = v;
    return true;
}

/* Encode codepoint cp as UTF-8 into out[]. Returns bytes written
 * (1..4) or 0 on invalid codepoint. */
static size_t emit_utf8(uint32_t cp, char *out)
{
    if (cp < 0x80u) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800u) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    if (cp < 0x110000u) {
        out[0] = (char)(0xF0u | (cp >> 18));
        out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[3] = (char)(0x80u | (cp & 0x3Fu));
        return 4;
    }
    return 0;
}

/* Unescape a JSON string token (jsmn types it as JSMN_STRING) into
 * out (caller-provided, sized at least src_len bytes since escapes
 * never grow). Returns the unescaped byte count, or SIZE_MAX on
 * malformed escape. */
#define UNESCAPE_FAIL SIZE_MAX

static size_t unescape_string(const char *src, size_t src_len, char *out)
{
    size_t op = 0;
    size_t i = 0;
    while (i < src_len) {
        char c = src[i];
        if (c != '\\') {
            out[op++] = c;
            i++;
            continue;
        }
        if (i + 1 >= src_len) {
            return UNESCAPE_FAIL;
        }
        char e = src[i + 1];
        switch (e) {
        case '"':
        case '\\':
        case '/':
            out[op++] = e;
            i += 2;
            break;
        case 'b':
            out[op++] = '\b';
            i += 2;
            break;
        case 'f':
            out[op++] = '\f';
            i += 2;
            break;
        case 'n':
            out[op++] = '\n';
            i += 2;
            break;
        case 'r':
            out[op++] = '\r';
            i += 2;
            break;
        case 't':
            out[op++] = '\t';
            i += 2;
            break;
        case 'u': {
            if (i + 5 >= src_len) {
                return UNESCAPE_FAIL;
            }
            uint32_t cp = 0;
            for (int k = 0; k < 4; k++) {
                char h = src[i + 2 + k];
                uint32_t d;
                if (h >= '0' && h <= '9') {
                    d = (uint32_t)(h - '0');
                } else if (h >= 'a' && h <= 'f') {
                    d = (uint32_t)(h - 'a' + 10);
                } else if (h >= 'A' && h <= 'F') {
                    d = (uint32_t)(h - 'A' + 10);
                } else {
                    return UNESCAPE_FAIL;
                }
                cp = (cp << 4) | d;
            }
            /* Surrogate pairs (D800-DFFF) deferred — would need to
             * combine with the next \uDXXX. Step 4+ handles this. */
            if (cp >= 0xD800u && cp <= 0xDFFFu) {
                return UNESCAPE_FAIL;
            }
            size_t w = emit_utf8(cp, out + op);
            if (w == 0) {
                return UNESCAPE_FAIL;
            }
            op += w;
            i += 6;
            break;
        }
        default:
            return UNESCAPE_FAIL;
        }
    }
    return op;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_tokenizer_load_huggingface_json(const char *json_bytes,
                                                  size_t json_len,
                                                  ants_tokenizer_vocab_blob_t **out_blob)
{
    if (json_bytes == NULL || json_len == 0 || out_blob == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_blob = NULL;

    /* Two-pass jsmn: first call returns the token count needed; second
     * call populates the token array. */
    jsmn_parser p;
    jsmn_init(&p);
    int n_tok_needed = jsmn_parse(&p, json_bytes, json_len, NULL, 0);
    if (n_tok_needed <= 0) {
        return ANTS_ERROR_NON_CANONICAL;
    }

    jsmntok_t *toks = (jsmntok_t *)malloc((size_t)n_tok_needed * sizeof(jsmntok_t));
    if (toks == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    jsmn_init(&p);
    int n_tok = jsmn_parse(&p, json_bytes, json_len, toks, (unsigned int)n_tok_needed);
    if (n_tok != n_tok_needed) {
        free(toks);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Walk: root must be object; find "model"; that must be object;
     * find "vocab"; that must be an array of [string, number] pairs. */
    if (n_tok < 1 || toks[0].type != JSMN_OBJECT) {
        free(toks);
        return ANTS_ERROR_NON_CANONICAL;
    }
    int model_idx = find_object_key(json_bytes, toks, 0, n_tok, "model");
    if (model_idx < 0 || toks[model_idx].type != JSMN_OBJECT) {
        free(toks);
        return ANTS_ERROR_NON_CANONICAL;
    }
    int vocab_idx = find_object_key(json_bytes, toks, model_idx, n_tok, "vocab");
    if (vocab_idx < 0 || toks[vocab_idx].type != JSMN_ARRAY) {
        free(toks);
        return ANTS_ERROR_NON_CANONICAL;
    }
    int n_vocab = toks[vocab_idx].size;
    if (n_vocab <= 0) {
        free(toks);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Allocate entries + a generous text_pool (sized at the worst-case
     * concatenation of all source vocab strings). Unescaped output is
     * always ≤ source length so this is a safe upper bound. */
    size_t entries_size = (size_t)n_vocab * sizeof(ants_tokenizer_vocab_entry_t);
    ants_tokenizer_vocab_entry_t *entries = (ants_tokenizer_vocab_entry_t *)malloc(entries_size);
    if (entries == NULL) {
        free(toks);
        return ANTS_ERROR_MALFORMED;
    }

    /* Compute the text-pool upper bound: sum of all string-token
     * lengths in the vocab array. We walk the vocab array's child
     * tokens to find the string tokens. Each child of the vocab array
     * is a 2-element sub-array [string, number]. */
    size_t pool_cap = 0;
    int cur = vocab_idx + 1;
    for (int i = 0; i < n_vocab; i++) {
        if (cur >= n_tok || toks[cur].type != JSMN_ARRAY || toks[cur].size != 2) {
            free(toks);
            free(entries);
            return ANTS_ERROR_NON_CANONICAL;
        }
        int sub_idx = cur + 1;
        if (toks[sub_idx].type != JSMN_STRING) {
            free(toks);
            free(entries);
            return ANTS_ERROR_NON_CANONICAL;
        }
        pool_cap += (size_t)(toks[sub_idx].end - toks[sub_idx].start);
        cur = skip_subtree(toks, cur, n_tok);
    }

    char *pool = (char *)malloc(pool_cap > 0 ? pool_cap : 1);
    if (pool == NULL) {
        free(toks);
        free(entries);
        return ANTS_ERROR_MALFORMED;
    }
    size_t pool_used = 0;

    /* Second pass: fill entries + pool. */
    cur = vocab_idx + 1;
    for (int i = 0; i < n_vocab; i++) {
        int sub_idx = cur + 1;
        const jsmntok_t *str_tok = &toks[sub_idx];
        const jsmntok_t *num_tok = &toks[sub_idx + 1];
        if (num_tok->type != JSMN_PRIMITIVE) {
            free(toks);
            free(entries);
            free(pool);
            return ANTS_ERROR_NON_CANONICAL;
        }
        /* Unescape the string into the pool. */
        size_t src_len = (size_t)(str_tok->end - str_tok->start);
        size_t written = unescape_string(json_bytes + str_tok->start, src_len, pool + pool_used);
        if (written == UNESCAPE_FAIL || written == 0) {
            free(toks);
            free(entries);
            free(pool);
            return ANTS_ERROR_NON_CANONICAL;
        }
        float score = 0.0f;
        if (!parse_number(json_bytes, num_tok->start, num_tok->end, &score)) {
            free(toks);
            free(entries);
            free(pool);
            return ANTS_ERROR_NON_CANONICAL;
        }
        entries[i].text = pool + pool_used;
        entries[i].text_len = written;
        entries[i].score = score;
        entries[i].token_id = (uint32_t)i;
        pool_used += written;
        cur = skip_subtree(toks, cur, n_tok);
    }

    free(toks);

    ants_tokenizer_vocab_blob_t *blob =
        (ants_tokenizer_vocab_blob_t *)malloc(sizeof(ants_tokenizer_vocab_blob_t));
    if (blob == NULL) {
        free(entries);
        free(pool);
        return ANTS_ERROR_MALFORMED;
    }
    blob->entries = entries;
    blob->n_vocab = (size_t)n_vocab;
    blob->text_pool = pool;
    blob->text_pool_size = pool_used;
    *out_blob = blob;
    return ANTS_OK;
}

const ants_tokenizer_vocab_entry_t *
ants_tokenizer_vocab_entries(const ants_tokenizer_vocab_blob_t *blob)
{
    return blob != NULL ? blob->entries : NULL;
}

size_t ants_tokenizer_vocab_size(const ants_tokenizer_vocab_blob_t *blob)
{
    return blob != NULL ? blob->n_vocab : 0;
}

void ants_tokenizer_vocab_free(ants_tokenizer_vocab_blob_t *blob)
{
    if (blob == NULL) {
        return;
    }
    free(blob->entries);
    free(blob->text_pool);
    free(blob);
}
