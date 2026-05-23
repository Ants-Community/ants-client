/*
 * tokenizer.c — SentencePiece Unigram tokenizer (Component #11,
 *               phase 4-real step 1).
 *
 * See include/ants_tokenizer.h for the public-API contract and
 * algorithm overview.
 *
 * Implementation notes:
 *
 *   - The Viterbi DP table is heap-allocated per encode call. For
 *     typical embedding inputs (a few hundred bytes) this is
 *     negligible. Hot-path callers can later batch encodes.
 *   - Vocab lookup is O(V) per position (linear scan). For 250K-entry
 *     vocabs that's slow; a trie / hash-prefix index lands in a
 *     follow-up PR. For step 1 the algorithm correctness comes first.
 *   - The pre-tokenization (whitespace → ▁) is done in-place on a
 *     working buffer also heap-allocated per call. Working buffer can
 *     grow input length by up to 3× (every ASCII space becomes 3 UTF-8
 *     bytes for ▁), so we allocate input_len*3 + 3 bytes (the +3 is for
 *     the always-prepended leading ▁ marker, see SentencePiece docs).
 */

#include "ants_tokenizer.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* SentencePiece word-boundary marker U+2581 ("LOWER ONE EIGHTH BLOCK"),
 * UTF-8 encoding. Used to mark "this token starts a new word". */
#define SP_UNDERSCORE_BYTE_0 0xE2u
#define SP_UNDERSCORE_BYTE_1 0x96u
#define SP_UNDERSCORE_BYTE_2 0x81u
#define SP_UNDERSCORE_LEN    3

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/* ------------------------------------------------------------------------ */

struct ants_tokenizer_state {
    bool initialised;
    uint8_t _pad[7];
    const ants_tokenizer_vocab_entry_t *vocab;
    size_t n_vocab;
    /* Cached: maximum text_len across the vocab. Lets the Viterbi inner
     * loop skip vocab entries whose text is longer than the remaining
     * suffix at position i. Cheap optimisation; trie wholesale lands
     * later. */
    size_t max_token_len;
};

typedef char ants_tokenizer_state_size_check
    [(sizeof(struct ants_tokenizer_state) <= sizeof(((ants_tokenizer_t *)0)->_opaque)) ? 1 : -1];

static struct ants_tokenizer_state *tok_state(ants_tokenizer_t *t)
{
    return (struct ants_tokenizer_state *)(void *)t->_opaque;
}

static const struct ants_tokenizer_state *tok_state_const(const ants_tokenizer_t *t)
{
    return (const struct ants_tokenizer_state *)(const void *)t->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_tokenizer_init(ants_tokenizer_t *tok,
                                 const ants_tokenizer_vocab_entry_t *vocab,
                                 size_t n_vocab)
{
    if (tok == NULL || vocab == NULL || n_vocab == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Validate vocab entry shape + compute max_token_len. */
    size_t max_len = 0;
    for (size_t i = 0; i < n_vocab; i++) {
        if (vocab[i].text == NULL || vocab[i].text_len == 0) {
            return ANTS_ERROR_INVALID_ARG;
        }
        if (vocab[i].text_len > max_len) {
            max_len = vocab[i].text_len;
        }
    }
    memset(tok->_opaque, 0, sizeof tok->_opaque);
    struct ants_tokenizer_state *state = tok_state(tok);
    state->initialised = true;
    state->vocab = vocab;
    state->n_vocab = n_vocab;
    state->max_token_len = max_len;
    return ANTS_OK;
}

ants_error_t ants_tokenizer_destroy(ants_tokenizer_t *tok)
{
    if (tok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(tok->_opaque, 0, sizeof tok->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Pre-tokenization                                                          */
/*                                                                          */
/* Always prepend ▁ to the input, then replace every ASCII whitespace      */
/* (space, tab, newline, CR) with ▁. Returns the byte length actually     */
/* written. Non-ASCII whitespace (U+00A0 NBSP, etc.) is intentionally     */
/* NOT special-cased — that's an NFKC-normaliser job and step-N           */
/* territory. Working buffer must hold up to input_len*3 + 3 bytes.       */
/* ------------------------------------------------------------------------ */

static size_t emit_underscore(uint8_t *out, size_t pos)
{
    out[pos + 0] = SP_UNDERSCORE_BYTE_0;
    out[pos + 1] = SP_UNDERSCORE_BYTE_1;
    out[pos + 2] = SP_UNDERSCORE_BYTE_2;
    return pos + SP_UNDERSCORE_LEN;
}

static bool is_ascii_ws(uint8_t b)
{
    return b == ' ' || b == '\t' || b == '\n' || b == '\r';
}

static size_t pretokenize(const uint8_t *in, size_t in_len, uint8_t *out)
{
    size_t pos = 0;
    pos = emit_underscore(out, pos);
    /* Skip leading ASCII whitespace — we already emitted the implicit
     * leading ▁, so consecutive leading spaces shouldn't double up. */
    size_t i = 0;
    while (i < in_len && is_ascii_ws(in[i])) {
        i++;
    }
    bool prev_was_ws = false;
    while (i < in_len) {
        uint8_t b = in[i];
        if (is_ascii_ws(b)) {
            /* Collapse runs of whitespace into a single ▁. */
            if (!prev_was_ws) {
                pos = emit_underscore(out, pos);
                prev_was_ws = true;
            }
        } else {
            out[pos++] = b;
            prev_was_ws = false;
        }
        i++;
    }
    return pos;
}

/* ------------------------------------------------------------------------ */
/* Viterbi                                                                  */
/*                                                                          */
/* dp[i] = highest score reachable at position i, where score = sum of    */
/* selected token scores. dp[0] = 0; dp[i] = -inf if unreachable.        */
/* back_pos[i] / back_id[i] hold the start position and token-id of the */
/* token whose end is i, on the best path.                                */
/* ------------------------------------------------------------------------ */

#define NEG_INF (-1.0e30f)

ants_error_t ants_tokenizer_encode(const ants_tokenizer_t *tok,
                                   const char *input,
                                   size_t input_len,
                                   uint32_t *out_token_ids,
                                   size_t out_cap,
                                   size_t *out_count)
{
    if (tok == NULL || input == NULL || input_len == 0 || out_count == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (out_token_ids == NULL && out_cap > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    const struct ants_tokenizer_state *state = tok_state_const(tok);
    if (!state->initialised) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Pre-tokenize. Worst case: every input byte is whitespace and
     * gets expanded to ▁ (3 bytes), plus the always-prepended ▁. */
    size_t work_cap = input_len * 3u + SP_UNDERSCORE_LEN;
    uint8_t *work = (uint8_t *)malloc(work_cap);
    if (work == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    size_t N = pretokenize((const uint8_t *)input, input_len, work);

    /* Allocate DP arrays. */
    float *dp = (float *)malloc((N + 1) * sizeof(float));
    size_t *back_pos = (size_t *)malloc((N + 1) * sizeof(size_t));
    uint32_t *back_id = (uint32_t *)malloc((N + 1) * sizeof(uint32_t));
    if (dp == NULL || back_pos == NULL || back_id == NULL) {
        free(work);
        free(dp);
        free(back_pos);
        free(back_id);
        return ANTS_ERROR_MALFORMED;
    }
    dp[0] = 0.0f;
    for (size_t i = 1; i <= N; i++) {
        dp[i] = NEG_INF;
        back_pos[i] = (size_t)-1;
        back_id[i] = UINT32_MAX;
    }

    /* Forward pass: for each end-position i, find the best (start, token)
     * pair that lands there. O(N × V) linear scan. */
    for (size_t i = 1; i <= N; i++) {
        for (size_t v = 0; v < state->n_vocab; v++) {
            const ants_tokenizer_vocab_entry_t *entry = &state->vocab[v];
            size_t L = entry->text_len;
            if (L == 0 || L > i || L > state->max_token_len) {
                continue;
            }
            size_t start = i - L;
            if (dp[start] == NEG_INF) {
                continue;
            }
            if (memcmp(work + start, entry->text, L) != 0) {
                continue;
            }
            float cand = dp[start] + entry->score;
            if (cand > dp[i]) {
                dp[i] = cand;
                back_pos[i] = start;
                back_id[i] = entry->token_id;
            }
        }
    }

    if (dp[N] == NEG_INF) {
        /* No covering segmentation. Phase-N adds byte-fallback that
         * makes this unreachable; for step 1, callers must ship a
         * vocab that covers their input alphabet. */
        free(work);
        free(dp);
        free(back_pos);
        free(back_id);
        return ANTS_ERROR_NON_CANONICAL;
    }

    /* Backtrace, filling a stack-of-IDs in reverse. */
    size_t out_n = 0;
    size_t cur = N;
    /* First pass: count tokens to size the reversed buffer. */
    while (cur > 0) {
        out_n++;
        cur = back_pos[cur];
    }
    *out_count = out_n;
    if (out_cap < out_n) {
        free(work);
        free(dp);
        free(back_pos);
        free(back_id);
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Second pass: fill out_token_ids in the correct left-to-right
     * order by walking back from N and writing into out_token_ids[k-1]. */
    cur = N;
    size_t k = out_n;
    while (cur > 0) {
        k--;
        out_token_ids[k] = back_id[cur];
        cur = back_pos[cur];
    }

    free(work);
    free(dp);
    free(back_pos);
    free(back_id);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Decode                                                                   */
/*                                                                          */
/* Look up each token_id in the vocab (linear scan; trie comes later),     */
/* concatenate the texts, then post-process ▁ → ' ' and strip the leading */
/* whitespace inserted by pretokenize's implicit leading ▁.                */
/* ------------------------------------------------------------------------ */

static const ants_tokenizer_vocab_entry_t *find_by_id(const struct ants_tokenizer_state *state,
                                                      uint32_t token_id)
{
    for (size_t i = 0; i < state->n_vocab; i++) {
        if (state->vocab[i].token_id == token_id) {
            return &state->vocab[i];
        }
    }
    return NULL;
}

ants_error_t ants_tokenizer_decode(const ants_tokenizer_t *tok,
                                   const uint32_t *token_ids,
                                   size_t n_tokens,
                                   char *out_text,
                                   size_t out_cap,
                                   size_t *out_len)
{
    if (tok == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_tokens > 0 && token_ids == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (out_text == NULL && out_cap > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    const struct ants_tokenizer_state *state = tok_state_const(tok);
    if (!state->initialised) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Two-pass: first compute required length (then fail fast if cap
     * insufficient), then write. */
    size_t need = 0;
    for (size_t i = 0; i < n_tokens; i++) {
        const ants_tokenizer_vocab_entry_t *e = find_by_id(state, token_ids[i]);
        if (e == NULL) {
            return ANTS_ERROR_INVALID_ARG;
        }
        /* Worst-case post-process: every ▁ (3 bytes) collapses to ' '
         * (1 byte). So written length ≤ concatenated length. We'll
         * compute the exact post-processed length in the second pass;
         * for the required-capacity hint use the pre-collapse length. */
        need += e->text_len;
    }
    /* Conservative pre-collapse estimate as the upper bound. The actual
     * written length is no greater. */
    *out_len = need;
    if (out_cap < need) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Second pass: write bytes, post-processing ▁ → ' ' and dropping
     * the leading ▁ inserted by pretokenize. */
    size_t pos = 0;
    bool first = true;
    for (size_t i = 0; i < n_tokens; i++) {
        const ants_tokenizer_vocab_entry_t *e = find_by_id(state, token_ids[i]);
        size_t j = 0;
        while (j + SP_UNDERSCORE_LEN <= e->text_len) {
            if ((uint8_t)e->text[j + 0] == SP_UNDERSCORE_BYTE_0 &&
                (uint8_t)e->text[j + 1] == SP_UNDERSCORE_BYTE_1 &&
                (uint8_t)e->text[j + 2] == SP_UNDERSCORE_BYTE_2) {
                if (first) {
                    /* Suppress the very first ▁ (matches encode's
                     * always-prepended marker). */
                    first = false;
                } else {
                    out_text[pos++] = ' ';
                }
                j += SP_UNDERSCORE_LEN;
            } else {
                out_text[pos++] = e->text[j++];
                first = false;
            }
        }
        while (j < e->text_len) {
            out_text[pos++] = e->text[j++];
            first = false;
        }
    }
    *out_len = pos;
    return ANTS_OK;
}
