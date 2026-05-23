/*
 * test_tokenizer.c — tests for the Unigram subword tokenizer
 *                    (Component #11, phase 4-real step 1).
 *
 * Covers:
 *   - init NULL/zero-shape arg validation
 *   - opaque ctx layout
 *   - encode rejects uninitialised tokenizer + bad args
 *   - encode produces the deterministic best-cost segmentation under
 *     a hand-crafted vocab where the optimal segmentation is known
 *   - encode handles whitespace (▁ pre-tokenization)
 *   - encode rejects when the vocab can't cover the input
 *   - decode round-trips through encode
 *   - decode rejects invalid token IDs
 *   - decode buffer-too-small contract
 *   - destroy safety on zeroed ctx
 */

#include "ants_common.h"
#include "ants_tokenizer.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                 \
    do {                                                                                           \
        ants_error_t _a = (actual);                                                                \
        ants_error_t _e = (expected);                                                              \
        if (_a != _e) {                                                                            \
            failures++;                                                                            \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

/* ▁ marker as 3 UTF-8 bytes. */
#define SP "\xE2\x96\x81"

/* ------------------------------------------------------------------------ */
/* Test vocabs                                                              */
/* ------------------------------------------------------------------------ */

/* Tiny vocab covering single ASCII letters + the ▁ marker + some
 * compound tokens. Designed so we can hand-compute the expected
 * Viterbi output. Token IDs are the array index. */
static const ants_tokenizer_vocab_entry_t kAsciiVocab[] = {
    /* Single-byte tokens for each lowercase letter we use (scores are
     * mild negatives so any single-letter path is feasible but
     * compound tokens win when applicable). */
    {"a", 1, -2.0f, 0},
    {"b", 1, -2.0f, 1},
    {"c", 1, -2.0f, 2},
    {"d", 1, -2.0f, 3},
    {"e", 1, -2.0f, 4},
    {"h", 1, -2.0f, 5},
    {"l", 1, -2.0f, 6},
    {"o", 1, -2.0f, 7},
    {"r", 1, -2.0f, 8},
    {"w", 1, -2.0f, 9},
    /* Word-boundary marker. */
    {SP, 3, -1.0f, 10},
    /* Compound tokens — high scores so Viterbi prefers them. */
    {SP "hello", 8, -0.5f, 11},
    {SP "world", 8, -0.5f, 12},
    /* Common bigram so we have a partial-cover case. */
    {"el", 2, -1.5f, 13},
};
#define kAsciiVocabLen (sizeof kAsciiVocab / sizeof kAsciiVocab[0])

/* ------------------------------------------------------------------------ */
/* Lifecycle / arg validation                                               */
/* ------------------------------------------------------------------------ */

static void test_opaque_ctx_layout(void)
{
    ants_tokenizer_t t;
    CHECK(((uintptr_t)&t & 7u) == 0);
    CHECK(sizeof t == ANTS_TOKENIZER_CTX_SIZE);
    CHECK(ANTS_TOKENIZER_CTX_SIZE == 1024);
}

static void test_init_rejects_invalid_args(void)
{
    ants_tokenizer_t t = {{0}};

    CHECK_EQ(ants_tokenizer_init(NULL, kAsciiVocab, kAsciiVocabLen), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_init(&t, NULL, kAsciiVocabLen), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, 0), ANTS_ERROR_INVALID_ARG);

    /* Bad vocab entry (NULL text). */
    ants_tokenizer_vocab_entry_t bad[2];
    bad[0] = kAsciiVocab[0];
    bad[1].text = NULL;
    bad[1].text_len = 1;
    bad[1].score = 0.0f;
    bad[1].token_id = 99;
    CHECK_EQ(ants_tokenizer_init(&t, bad, 2), ANTS_ERROR_INVALID_ARG);

    /* Bad vocab entry (zero text_len). */
    bad[1].text = "x";
    bad[1].text_len = 0;
    CHECK_EQ(ants_tokenizer_init(&t, bad, 2), ANTS_ERROR_INVALID_ARG);
}

static void test_destroy_rejects_null(void)
{
    CHECK_EQ(ants_tokenizer_destroy(NULL), ANTS_ERROR_INVALID_ARG);
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Encode                                                                   */
/* ------------------------------------------------------------------------ */

static void test_encode_rejects_invalid_args(void)
{
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(NULL, "hi", 2, out, 16, &out_n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_encode(&t, NULL, 2, out, 16, &out_n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_encode(&t, "hi", 0, out, 16, &out_n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_encode(&t, "hi", 2, out, 16, NULL), ANTS_ERROR_INVALID_ARG);
    /* NULL out with non-zero cap. */
    CHECK_EQ(ants_tokenizer_encode(&t, "hi", 2, NULL, 16, &out_n), ANTS_ERROR_INVALID_ARG);

    /* Uninitialised tokenizer. */
    ants_tokenizer_t uninit = {{0}};
    CHECK_EQ(ants_tokenizer_encode(&uninit, "hi", 2, out, 16, &out_n), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_picks_compound_tokens(void)
{
    /* "hello world" with the kAsciiVocab. The Viterbi-optimal
     * segmentation is the two compound tokens [▁hello, ▁world],
     * because (-0.5) + (-0.5) = -1.0 beats letter-by-letter
     * (5 chars × -2.0 = -10.0 for "hello"). */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "hello world", 11, out, 16, &out_n), ANTS_OK);
    CHECK(out_n == 2);
    if (out_n == 2) {
        CHECK(out[0] == 11); /* ▁hello */
        CHECK(out[1] == 12); /* ▁world */
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_falls_back_to_letters(void)
{
    /* "abc" — no compound tokens match; Viterbi falls back to
     * [▁, a, b, c] = 4 tokens. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "abc", 3, out, 16, &out_n), ANTS_OK);
    CHECK(out_n == 4);
    if (out_n == 4) {
        CHECK(out[0] == 10); /* ▁ */
        CHECK(out[1] == 0);  /* a */
        CHECK(out[2] == 1);  /* b */
        CHECK(out[3] == 2);  /* c */
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_handles_whitespace_collapse(void)
{
    /* Multiple consecutive spaces collapse to one ▁. "a  b" (two
     * spaces) → [▁, a, ▁, b]. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "a  b", 4, out, 16, &out_n), ANTS_OK);
    CHECK(out_n == 4);
    if (out_n == 4) {
        CHECK(out[0] == 10); /* ▁ */
        CHECK(out[1] == 0);  /* a */
        CHECK(out[2] == 10); /* ▁ */
        CHECK(out[3] == 1);  /* b */
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_rejects_uncovered_input(void)
{
    /* "xyz" — none of x/y/z in vocab → no covering segmentation. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "xyz", 3, out, 16, &out_n), ANTS_ERROR_NON_CANONICAL);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_buffer_too_small(void)
{
    /* Encode that needs 4 tokens into a 2-element buffer →
     * BUFFER_TOO_SMALL with *out_count = 4. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t out[2];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "abc", 3, out, 2, &out_n), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 4);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_encode_deterministic(void)
{
    /* Encode the same input twice; outputs must be bit-identical. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t a[16], b[16];
    size_t na = 0, nb = 0;
    const char *in = "hello world";
    CHECK_EQ(ants_tokenizer_encode(&t, in, strlen(in), a, 16, &na), ANTS_OK);
    CHECK_EQ(ants_tokenizer_encode(&t, in, strlen(in), b, 16, &nb), ANTS_OK);
    CHECK(na == nb);
    if (na == nb) {
        CHECK(memcmp(a, b, na * sizeof a[0]) == 0);
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Decode                                                                   */
/* ------------------------------------------------------------------------ */

static void test_decode_round_trip(void)
{
    /* encode → decode → original (modulo whitespace normalisation). */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t tokens[16];
    size_t n_tok = 0;
    const char *in = "hello world";
    CHECK_EQ(ants_tokenizer_encode(&t, in, strlen(in), tokens, 16, &n_tok), ANTS_OK);

    char decoded[64];
    size_t dec_len = 0;
    CHECK_EQ(ants_tokenizer_decode(&t, tokens, n_tok, decoded, sizeof decoded, &dec_len), ANTS_OK);
    /* Decoded length equals the original "hello world" (11 bytes). */
    CHECK(dec_len == 11);
    CHECK(memcmp(decoded, "hello world", 11) == 0);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_decode_rejects_invalid_id(void)
{
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    /* Token ID 9999 isn't in the vocab. */
    uint32_t bad[1] = {9999};
    char out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_decode(&t, bad, 1, out, sizeof out, &out_n), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_decode_rejects_invalid_args(void)
{
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t tokens[1] = {0};
    char out[16];
    size_t out_n = 0;

    CHECK_EQ(ants_tokenizer_decode(NULL, tokens, 1, out, sizeof out, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_decode(&t, tokens, 1, out, sizeof out, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_decode(&t, NULL, 1, out, sizeof out, &out_n), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_decode(&t, tokens, 1, NULL, sizeof out, &out_n),
             ANTS_ERROR_INVALID_ARG);

    /* Uninitialised. */
    ants_tokenizer_t uninit = {{0}};
    CHECK_EQ(ants_tokenizer_decode(&uninit, tokens, 1, out, sizeof out, &out_n),
             ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_decode_buffer_too_small(void)
{
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t tokens[16];
    size_t n_tok = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "hello world", 11, tokens, 16, &n_tok), ANTS_OK);

    char small[2];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_decode(&t, tokens, n_tok, small, sizeof small, &out_n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n > sizeof small);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* Byte fallback (phase 4-real step 4a)                                     */
/* ------------------------------------------------------------------------ */

static void test_byte_fallback_rejects_uninitialised(void)
{
    ants_tokenizer_t t = {{0}};
    uint32_t ids[256] = {0};
    CHECK_EQ(ants_tokenizer_set_byte_fallback(NULL, ids, -10.0f), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_set_byte_fallback(&t, ids, -10.0f), ANTS_ERROR_INVALID_ARG);
}

static void test_byte_fallback_covers_unknown_chars(void)
{
    /* Same kAsciiVocab from step 1. Without byte fallback, "xyz"
     * fails (no vocab covers x/y/z). With byte fallback enabled, the
     * Viterbi emits length-1 candidates with byte_fallback_ids[x/y/z]
     * → encode succeeds with 4 tokens [▁ fallback, x_fallback,
     * y_fallback, z_fallback]. The leading ▁ is provided by the
     * vocab (kAsciiVocab[10]) and outscores its byte-fallback
     * counterpart because the ▁ entry exists in the vocab. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    /* Build a byte-fallback ID array: ID = 1000 + byte value. */
    uint32_t ids[256];
    for (int i = 0; i < 256; i++) {
        ids[i] = (uint32_t)(1000 + i);
    }
    /* Score lower than any vocab score so trie-matched tokens always
     * win when available. */
    CHECK_EQ(ants_tokenizer_set_byte_fallback(&t, ids, -50.0f), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "xyz", 3, out, 16, &out_n), ANTS_OK);
    CHECK(out_n == 4);
    if (out_n == 4) {
        CHECK(out[0] == 10);                     /* ▁ from vocab */
        CHECK(out[1] == (uint32_t)(1000 + 'x')); /* byte fallback */
        CHECK(out[2] == (uint32_t)(1000 + 'y'));
        CHECK(out[3] == (uint32_t)(1000 + 'z'));
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_byte_fallback_preserves_compound_tokens(void)
{
    /* "hello world" still tokenises to [▁hello, ▁world] with byte
     * fallback enabled — fallback tokens have a much lower score so
     * Viterbi prefers the compound vocab entries. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t ids[256];
    for (int i = 0; i < 256; i++) {
        ids[i] = (uint32_t)(2000 + i);
    }
    CHECK_EQ(ants_tokenizer_set_byte_fallback(&t, ids, -50.0f), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "hello world", 11, out, 16, &out_n), ANTS_OK);
    CHECK(out_n == 2);
    if (out_n == 2) {
        CHECK(out[0] == 11); /* ▁hello */
        CHECK(out[1] == 12); /* ▁world */
    }

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

static void test_byte_fallback_can_be_disabled(void)
{
    /* Set fallback, then clear with NULL; "xyz" should once again
     * return NON_CANONICAL. */
    ants_tokenizer_t t = {{0}};
    CHECK_EQ(ants_tokenizer_init(&t, kAsciiVocab, kAsciiVocabLen), ANTS_OK);

    uint32_t ids[256];
    for (int i = 0; i < 256; i++) {
        ids[i] = (uint32_t)(3000 + i);
    }
    CHECK_EQ(ants_tokenizer_set_byte_fallback(&t, ids, -50.0f), ANTS_OK);
    CHECK_EQ(ants_tokenizer_set_byte_fallback(&t, NULL, 0.0f), ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&t, "xyz", 3, out, 16, &out_n), ANTS_ERROR_NON_CANONICAL);

    CHECK_EQ(ants_tokenizer_destroy(&t), ANTS_OK);
}

int main(void)
{
    test_opaque_ctx_layout();
    test_init_rejects_invalid_args();
    test_destroy_rejects_null();

    test_encode_rejects_invalid_args();
    test_encode_picks_compound_tokens();
    test_encode_falls_back_to_letters();
    test_encode_handles_whitespace_collapse();
    test_encode_rejects_uncovered_input();
    test_encode_buffer_too_small();
    test_encode_deterministic();

    test_decode_round_trip();
    test_decode_rejects_invalid_id();
    test_decode_rejects_invalid_args();
    test_decode_buffer_too_small();

    test_byte_fallback_rejects_uninitialised();
    test_byte_fallback_covers_unknown_chars();
    test_byte_fallback_preserves_compound_tokens();
    test_byte_fallback_can_be_disabled();

    if (failures > 0) {
        fprintf(stderr, "test_tokenizer: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_tokenizer: all checks passed\n");
    return 0;
}
