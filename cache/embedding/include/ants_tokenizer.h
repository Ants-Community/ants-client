/*
 * ants_tokenizer.h — Unigram subword tokenizer (Component #11, phase 4-real
 *                    step 1).
 *
 * Implements the SentencePiece Unigram subword tokenization algorithm
 * over a caller-supplied vocab. Designed for use with `ants-embed-v1`
 * (BGE-M3 / XLM-RoBERTa family), but the algorithm itself is model-
 * agnostic: any Unigram-trained vocab works.
 *
 * Spec references:
 *   - RFC-0002 §The canonical embedding model — bit-exact tokenization
 *     is part of the cross-peer agreement that lets two peers compute
 *     identical embeddings for identical inputs.
 *   - SentencePiece paper (Kudo & Richardson, 2018): "SentencePiece: A
 *     simple and language independent subword tokenizer and detokenizer
 *     for Neural Text Processing".
 *
 * Algorithm:
 *
 *   1. Pre-tokenization: prepend the SentencePiece word-boundary marker
 *      ▁ (U+2581, 3 UTF-8 bytes 0xE2 0x96 0x81), and replace every
 *      whitespace character with ▁. So "hello world" becomes
 *      "▁hello▁world".
 *
 *   2. Viterbi forward: for each position i in the normalised input,
 *      compute dp[i] = max over all (token_text, token_score) such that
 *      input[i - len(token_text) .. i] == token_text of (dp[i - len] +
 *      score). Track backpointers.
 *
 *   3. Backtrace: from dp[N], walk back to dp[0] to recover the token
 *      ID sequence in left-to-right order.
 *
 * Cross-peer determinism: bit-exact across platforms because every step
 * is integer / byte-level (string comparison, sum of float scores; the
 * argmax is well-defined as long as no two paths tie exactly, and the
 * caller's vocab determines that).
 *
 * Out of scope for step 1 (lands in later phase-4-real PRs):
 *
 *   - Unicode NFKC normalisation. SentencePiece Unigram conventionally
 *     NFKC-normalises input first. For step 1 the caller is responsible
 *     for normalisation; raw UTF-8 bytes are tokenized as-is.
 *   - Byte fallback for genuinely unknown characters. Real XLM-R adds
 *     `<0xNN>` byte-fallback tokens that catch any byte the vocab can't
 *     express. Step 1 returns ANTS_ERROR_NON_CANONICAL if any input
 *     position has no covering vocab entry — caller is on the hook to
 *     ship a vocab that covers their input.
 *   - JSON loader for `tokenizer.json` files. Step 1 takes the vocab as
 *     an in-memory array; step 2 adds JSON parsing of HuggingFace
 *     tokenizer configs.
 *   - Trie-based lookup. Step 1 does O(N × V) Viterbi (linear scan over
 *     the vocab at each position). For BGE-M3's 250K-entry vocab and
 *     hundred-byte inputs this is ~25 million byte-comparisons per
 *     encode, which is still fast (~10 ms) but a trie reduces it
 *     to O(N × max_token_len).
 *   - Special tokens handling (CLS, SEP, PAD, MASK, UNK). The caller
 *     wraps the encoded sequence with these out-of-band.
 *
 * API model: caller-allocated context, no internal threads, no malloc
 * during init (vocab is supplied by pointer). Per-encode call mallocs
 * O(input_len) for the Viterbi DP table (released before return);
 * input sizes are typically a few hundred bytes for embedding tasks.
 */

#ifndef ANTS_TOKENIZER_H
#define ANTS_TOKENIZER_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Vocab entry                                                              */
/*                                                                          */
/* The caller assembles an array of these (one per vocab token) and        */
/* passes the array to ants_tokenizer_init. The tokenizer holds a pointer  */
/* to the array; the caller MUST keep the underlying memory (and the      */
/* `text` pointers inside each entry) valid for the tokenizer's lifetime. */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* UTF-8 bytes of the token. Not NUL-terminated (interpret with
     * text_len). Typical tokens are 1-8 bytes; ▁-prefixed wordpiece
     * tokens are longer. Caller-owned memory. */
    const char *text;
    size_t text_len;

    /* Log-probability or score. Higher = more likely. Viterbi picks the
     * segmentation that maximises the SUM of scores. SentencePiece
     * stores log-probs (negative floats); the algorithm works on any
     * additive score function. */
    float score;

    /* Numeric token ID the encoded output uses. Typically the entry's
     * index in the vocab array (so 0..n_vocab-1), but the caller may
     * assign any uint32_t — the tokenizer just passes it through. */
    uint32_t token_id;
} ants_tokenizer_vocab_entry_t;

/* ------------------------------------------------------------------------ */
/* Opaque context                                                           */
/* ------------------------------------------------------------------------ */

/* Sized for the small state struct plus headroom for future additions
 * (trie root, byte-fallback table, special-token IDs). 1 KiB is
 * generous given the actual state is currently ~32 bytes. */
#define ANTS_TOKENIZER_CTX_SIZE 1024

typedef union {
    uint8_t _opaque[ANTS_TOKENIZER_CTX_SIZE];
    uint64_t _align;
} ants_tokenizer_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Initialise the tokenizer against a caller-supplied vocab.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL tok / NULL vocab / n_vocab == 0, or
 *     if any vocab entry has NULL text or text_len == 0.
 *
 * The tokenizer holds a pointer to the vocab array; the caller MUST
 * keep the array (and the text pointers within each entry) valid until
 * ants_tokenizer_destroy returns.
 */
ants_error_t ants_tokenizer_init(ants_tokenizer_t *tok,
                                 const ants_tokenizer_vocab_entry_t *vocab,
                                 size_t n_vocab);

/*
 * Tear down. Safe on a zeroed (never-initialised) ctx.
 */
ants_error_t ants_tokenizer_destroy(ants_tokenizer_t *tok);

/* ------------------------------------------------------------------------ */
/* Byte fallback (phase 4-real step 4a)                                     */
/*                                                                          */
/* SentencePiece's mechanism for inputs the vocab can't cover: every byte  */
/* value (0..255) maps to a dedicated fallback token, and Viterbi can      */
/* always emit a length-1 candidate for whichever byte is at position s.   */
/* With fallback enabled, encode is guaranteed to find a covering          */
/* segmentation — ANTS_ERROR_NON_CANONICAL is never returned for an       */
/* unknown character.                                                      */
/*                                                                          */
/* Caller wiring (typical XLM-RoBERTa / BGE-M3 setup):                     */
/*   - The vocab contains 256 dedicated `<0x00>`...`<0xFF>` tokens with   */
/*     very low scores.                                                    */
/*   - Caller builds the byte-fallback ID array mapping byte value → that */
/*     token's ID, then passes it here.                                    */
/*   - The score is the per-byte fallback cost; SentencePiece typically   */
/*     uses something like the lowest score in the vocab.                  */
/*                                                                          */
/* Must be called AFTER ants_tokenizer_init (init builds the trie; this   */
/* just adds an extra always-available candidate to the Viterbi sweep).   */
/* Calling with byte_fallback_ids == NULL disables fallback (the default).*/
/* ------------------------------------------------------------------------ */

ants_error_t ants_tokenizer_set_byte_fallback(ants_tokenizer_t *tok,
                                              const uint32_t byte_fallback_ids[256],
                                              float byte_fallback_score);

/* ------------------------------------------------------------------------ */
/* NFKC normalisation (phase 4-real step 4b)                                */
/*                                                                          */
/* SentencePiece's standard normaliser canonicalises input to Unicode      */
/* NFKC (Normalization Form KC: compatibility-decompose, then canonical-  */
/* compose) before tokenisation. This handles compatibility forms (e.g.   */
/* "ﬁ" U+FB01 → "fi" two chars), full-width ↔ half-width (e.g.            */
/* "Ｈｅｌｌｏ" → "Hello"), and other equivalence-class collapses. Cross-     */
/* peer determinism requires either (a) the tokenizer normalises, or (b) */
/* the protocol mandates caller-side normalisation; option (a) is safer. */
/*                                                                          */
/* Set via `ants_tokenizer_set_nfkc_enabled(tok, true)` — defaults OFF    */
/* so existing call sites that pre-normalise (or don't need it for ASCII */
/* inputs) keep their current behaviour.                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_tokenizer_set_nfkc_enabled(ants_tokenizer_t *tok, bool enabled);

/* ------------------------------------------------------------------------ */
/* Encode                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Tokenize `input` (raw UTF-8 bytes; caller pre-normalises if needed).
 * Writes up to `out_cap` token IDs to `out_token_ids`; sets `*out_count`
 * to the number actually written, or to the required capacity if the
 * buffer is too small.
 *
 * Returns:
 *   ANTS_OK on success — *out_count tokens written to out_token_ids;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers, zero-length input, or
 *     uninitialised tokenizer;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — out_cap < required; *out_count holds
 *     the count that WOULD have been written;
 *   ANTS_ERROR_NON_CANONICAL — the vocab does not cover the input at
 *     some position (step-1 limitation; step-N adds byte fallback).
 */
ants_error_t ants_tokenizer_encode(const ants_tokenizer_t *tok,
                                   const char *input,
                                   size_t input_len,
                                   uint32_t *out_token_ids,
                                   size_t out_cap,
                                   size_t *out_count);

/* ------------------------------------------------------------------------ */
/* Decode                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Inverse of encode: given a sequence of token IDs, concatenate their
 * `text` bytes and convert the ▁ markers back to spaces. Writes up to
 * `out_cap` bytes to `out_text`; sets `*out_len` to the actual or
 * required byte count.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers / uninitialised tokenizer /
 *     a token_id not present in the vocab;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — out_cap < required; *out_len set.
 */
ants_error_t ants_tokenizer_decode(const ants_tokenizer_t *tok,
                                   const uint32_t *token_ids,
                                   size_t n_tokens,
                                   char *out_text,
                                   size_t out_cap,
                                   size_t *out_len);

/* ------------------------------------------------------------------------ */
/* HuggingFace tokenizer.json loader (phase 4-real step 2)                  */
/*                                                                          */
/* Parses the `model.vocab` array from a HuggingFace tokenizers JSON       */
/* config (the format that ships with XLM-RoBERTa, BGE-M3, and every       */
/* other Unigram-trained model on HuggingFace Hub). The model.vocab is an  */
/* array of `[token_string, score_float]` pairs; the entry index becomes   */
/* the token_id.                                                           */
/*                                                                          */
/* Caller owns the JSON buffer for the duration of the load call only;    */
/* the loader copies token text into its own storage so the JSON bytes    */
/* can be freed immediately after. The returned blob owns its internal    */
/* allocations and must outlive the tokenizer initialised against it.     */
/* ------------------------------------------------------------------------ */

typedef struct ants_tokenizer_vocab_blob ants_tokenizer_vocab_blob_t;

/*
 * Parse `json_bytes` (tokenizer.json content) and build a vocab blob.
 *
 * Returns:
 *   ANTS_OK on success; `*out_blob` points to a heap-allocated blob the
 *     caller must free via ants_tokenizer_vocab_free.
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or zero-length input.
 *   ANTS_ERROR_NON_CANONICAL — JSON parse error, missing model.vocab
 *     array, or vocab entry of the wrong shape (not a [string, number]
 *     pair).
 *   ANTS_ERROR_MALFORMED — malloc failure.
 *
 * The loader handles the basic JSON string escapes (\\, \", \/, \b, \f,
 * \n, \r, \t) and the \uXXXX form (4 hex digits → UTF-8). Surrogate
 * pairs for codepoints above U+FFFF are NOT handled in step 2.
 */
ants_error_t ants_tokenizer_load_huggingface_json(const char *json_bytes,
                                                  size_t json_len,
                                                  ants_tokenizer_vocab_blob_t **out_blob);

/*
 * Get the parsed vocab array. The returned pointer + the size below
 * are exactly what ants_tokenizer_init expects.
 */
const ants_tokenizer_vocab_entry_t *
ants_tokenizer_vocab_entries(const ants_tokenizer_vocab_blob_t *blob);
size_t ants_tokenizer_vocab_size(const ants_tokenizer_vocab_blob_t *blob);

/*
 * Free the blob's internal allocations. After this returns the blob
 * pointer is invalid; any tokenizer initialised against it must already
 * have been destroyed.
 */
void ants_tokenizer_vocab_free(ants_tokenizer_vocab_blob_t *blob);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_TOKENIZER_H */
