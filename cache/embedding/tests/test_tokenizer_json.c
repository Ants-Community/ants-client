/*
 * test_tokenizer_json.c — tests for the HuggingFace tokenizer.json
 *                        loader (Component #11, phase 4-real step 2).
 *
 * Covers:
 *   - load rejects NULL/zero args + malformed JSON
 *   - load rejects JSON missing $.model.vocab
 *   - load extracts the vocab array correctly (token text, score,
 *     token_id = index)
 *   - JSON string-escape handling: basic escapes (\\, \", \n, \t etc.)
 *     and \uXXXX (BMP codepoints)
 *   - end-to-end: load → init → encode produces expected token IDs
 *   - blob accessors return NULL/0 on NULL blob; free is safe on NULL
 */

#include "ants_common.h"
#include "ants_tokenizer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ------------------------------------------------------------------------ */
/* Sample tokenizer.json content                                            */
/*                                                                          */
/* A miniature HuggingFace-style config: top-level object with .model       */
/* containing .type and .vocab. The vocab is a small array of [string,     */
/* float] pairs that mirrors a real XLM-R shape (special tokens, ▁         */
/* marker, single letters, a compound).                                    */
/* ------------------------------------------------------------------------ */

static const char *kSampleJSON = "{"
                                 "  \"version\": \"1.0\","
                                 "  \"model\": {"
                                 "    \"type\": \"Unigram\","
                                 "    \"unk_id\": 3,"
                                 "    \"vocab\": ["
                                 "      [\"<s>\", 0.0],"
                                 "      [\"<pad>\", 0.0],"
                                 "      [\"</s>\", 0.0],"
                                 "      [\"<unk>\", 0.0],"
                                 "      [\"\\u2581\", -1.0],"
                                 "      [\"a\", -2.0],"
                                 "      [\"b\", -2.0],"
                                 "      [\"\\u2581hello\", -0.5],"
                                 "      [\"\\u2581world\", -0.5],"
                                 "      [\"escaped\\\"quote\", -3.5]"
                                 "    ]"
                                 "  }"
                                 "}";

/* ------------------------------------------------------------------------ */
/* Tests                                                                    */
/* ------------------------------------------------------------------------ */

static void test_load_rejects_invalid_args(void)
{
    ants_tokenizer_vocab_blob_t *blob = NULL;
    CHECK_EQ(ants_tokenizer_load_huggingface_json(NULL, 10, &blob), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_load_huggingface_json("{}", 0, &blob), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tokenizer_load_huggingface_json("{}", 2, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_load_rejects_malformed_json(void)
{
    ants_tokenizer_vocab_blob_t *blob = NULL;
    /* Truncated JSON. */
    CHECK_EQ(ants_tokenizer_load_huggingface_json("{\"model\":", 9, &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);
}

static void test_load_rejects_missing_vocab(void)
{
    ants_tokenizer_vocab_blob_t *blob = NULL;
    const char *no_model = "{\"version\":\"1.0\"}";
    CHECK_EQ(ants_tokenizer_load_huggingface_json(no_model, strlen(no_model), &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);

    const char *no_vocab = "{\"model\":{\"type\":\"Unigram\"}}";
    CHECK_EQ(ants_tokenizer_load_huggingface_json(no_vocab, strlen(no_vocab), &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);
}

static void test_load_rejects_malformed_vocab_entry(void)
{
    ants_tokenizer_vocab_blob_t *blob = NULL;
    /* Vocab entry must be a 2-element [string, number] array. */
    const char *bad_arity = "{\"model\":{\"vocab\":[[\"a\",-1.0,0]]}}";
    CHECK_EQ(ants_tokenizer_load_huggingface_json(bad_arity, strlen(bad_arity), &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);

    const char *bad_string = "{\"model\":{\"vocab\":[[123,-1.0]]}}";
    CHECK_EQ(ants_tokenizer_load_huggingface_json(bad_string, strlen(bad_string), &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);
}

static void test_load_parses_sample_vocab(void)
{
    ants_tokenizer_vocab_blob_t *blob = NULL;
    CHECK_EQ(ants_tokenizer_load_huggingface_json(kSampleJSON, strlen(kSampleJSON), &blob),
             ANTS_OK);
    CHECK(blob != NULL);
    if (blob == NULL) {
        return;
    }
    CHECK(ants_tokenizer_vocab_size(blob) == 10);

    const ants_tokenizer_vocab_entry_t *entries = ants_tokenizer_vocab_entries(blob);
    CHECK(entries != NULL);
    if (entries == NULL) {
        ants_tokenizer_vocab_free(blob);
        return;
    }

    /* Spot-check entries. */
    CHECK(entries[0].text_len == 3 && memcmp(entries[0].text, "<s>", 3) == 0);
    CHECK(entries[0].token_id == 0);
    CHECK(entries[0].score == 0.0f);

    CHECK(entries[3].text_len == 5 && memcmp(entries[3].text, "<unk>", 5) == 0);
    CHECK(entries[3].token_id == 3);

    /* ▁ = ▁ = 3 UTF-8 bytes E2 96 81. */
    CHECK(entries[4].text_len == 3);
    CHECK((unsigned char)entries[4].text[0] == 0xE2u);
    CHECK((unsigned char)entries[4].text[1] == 0x96u);
    CHECK((unsigned char)entries[4].text[2] == 0x81u);
    CHECK(entries[4].score == -1.0f);

    /* ▁hello = ▁hello (3 + 5 = 8 bytes). */
    CHECK(entries[7].text_len == 8);
    CHECK((unsigned char)entries[7].text[0] == 0xE2u);
    CHECK((unsigned char)entries[7].text[1] == 0x96u);
    CHECK((unsigned char)entries[7].text[2] == 0x81u);
    CHECK(memcmp(entries[7].text + 3, "hello", 5) == 0);
    CHECK(entries[7].score == -0.5f);

    /* Escape \" becomes a literal " in the text. */
    CHECK(entries[9].text_len == 13);
    CHECK(memcmp(entries[9].text, "escaped\"quote", 13) == 0);

    ants_tokenizer_vocab_free(blob);
}

static void test_load_then_encode_round_trip(void)
{
    /* Load the sample JSON, init a tokenizer against the parsed vocab,
     * encode "hello world" — Viterbi should pick [▁hello, ▁world]
     * exactly as in the hand-built test_tokenizer.c case. Confirms the
     * loader produces a vocab usable by the encoder end-to-end. */
    ants_tokenizer_vocab_blob_t *blob = NULL;
    CHECK_EQ(ants_tokenizer_load_huggingface_json(kSampleJSON, strlen(kSampleJSON), &blob),
             ANTS_OK);
    CHECK(blob != NULL);
    if (blob == NULL) {
        return;
    }

    ants_tokenizer_t tok = {{0}};
    CHECK_EQ(ants_tokenizer_init(
                 &tok, ants_tokenizer_vocab_entries(blob), ants_tokenizer_vocab_size(blob)),
             ANTS_OK);

    uint32_t out[16];
    size_t out_n = 0;
    CHECK_EQ(ants_tokenizer_encode(&tok, "hello world", 11, out, 16, &out_n), ANTS_OK);
    /* Vocab indices 7 = ▁hello, 8 = ▁world. */
    CHECK(out_n == 2);
    if (out_n == 2) {
        CHECK(out[0] == 7);
        CHECK(out[1] == 8);
    }

    CHECK_EQ(ants_tokenizer_destroy(&tok), ANTS_OK);
    ants_tokenizer_vocab_free(blob);
}

static void test_blob_accessors_null_safe(void)
{
    CHECK(ants_tokenizer_vocab_entries(NULL) == NULL);
    CHECK(ants_tokenizer_vocab_size(NULL) == 0);
    /* free(NULL) is a no-op. */
    ants_tokenizer_vocab_free(NULL);
}

static void test_load_rejects_invalid_escape(void)
{
    /* \z is not a valid JSON escape. */
    const char *bad_esc = "{\"model\":{\"vocab\":[[\"\\z\",-1.0]]}}";
    ants_tokenizer_vocab_blob_t *blob = NULL;
    /* Note: jsmn doesn't enforce escape validity at tokenize time; our
     * unescape_string catches the bad \z and returns NON_CANONICAL. */
    CHECK_EQ(ants_tokenizer_load_huggingface_json(bad_esc, strlen(bad_esc), &blob),
             ANTS_ERROR_NON_CANONICAL);
    CHECK(blob == NULL);
}

static void test_load_large_vocab_scale(void)
{
    /* Regression guard for the JSMN_PARENT_LINKS fix. Without parent links,
     * jsmn resolves every closing ']' / '}' by scanning all previously
     * emitted tokens — O(n) per close, O(n^2) over the file. A real
     * XLM-R/BGE-M3 tokenizer.json is 250002 vocab entries (~750K tokens),
     * where that quadratic scan turns a sub-second parse into a multi-minute
     * hang. This builds a 40000-entry vocab in memory: O(n) parses it in
     * tens of ms; an O(n^2) regression makes this test hang for tens of
     * seconds (and trips the CI timeout). */
    const size_t N = 40000;
    size_t cap = N * 24u + 64u;
    char *json = (char *)malloc(cap);
    CHECK(json != NULL);
    if (json == NULL) {
        return;
    }
    size_t p = 0;
    int w = snprintf(json + p, cap - p, "{\"model\":{\"vocab\":[");
    p += (size_t)w;
    for (size_t i = 0; i < N; i++) {
        w = snprintf(json + p, cap - p, "%s[\"t%zu\",-1.0]", i ? "," : "", i);
        p += (size_t)w;
    }
    w = snprintf(json + p, cap - p, "]}}");
    p += (size_t)w;

    ants_tokenizer_vocab_blob_t *blob = NULL;
    CHECK_EQ(ants_tokenizer_load_huggingface_json(json, p, &blob), ANTS_OK);
    CHECK(blob != NULL);
    if (blob != NULL) {
        CHECK(ants_tokenizer_vocab_size(blob) == N);
        const ants_tokenizer_vocab_entry_t *e = ants_tokenizer_vocab_entries(blob);
        if (e != NULL) {
            CHECK(e[0].token_id == 0 && e[0].text_len == 2 && memcmp(e[0].text, "t0", 2) == 0);
            CHECK(e[N - 1].token_id == (uint32_t)(N - 1));
        }
        ants_tokenizer_vocab_free(blob);
    }
    free(json);
}

int main(void)
{
    test_load_rejects_invalid_args();
    test_load_rejects_malformed_json();
    test_load_rejects_missing_vocab();
    test_load_rejects_malformed_vocab_entry();
    test_load_parses_sample_vocab();
    test_load_then_encode_round_trip();
    test_blob_accessors_null_safe();
    test_load_rejects_invalid_escape();
    test_load_large_vocab_scale();

    if (failures > 0) {
        fprintf(stderr, "test_tokenizer_json: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_tokenizer_json: all checks passed\n");
    return 0;
}
