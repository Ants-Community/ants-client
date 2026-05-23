/*
 * tokenizer.c — SentencePiece Unigram tokenizer (Component #11).
 *
 * See include/ants_tokenizer.h for the public-API contract.
 *
 * Implementation notes (post phase 4-real step 3):
 *
 *   - Init builds a flat-packed trie over the vocab text. Each trie
 *     node carries an optional (token_id, score) terminator plus a
 *     sorted edge list. Lookup walks the trie from each Viterbi start
 *     position; every terminator hit during the walk yields a candidate
 *     for the corresponding end position. This replaces the step-1
 *     O(N × V) linear scan with O(N × max_token_len × log(branching))
 *     — for BGE-M3's 250K vocab that's ~10000× fewer comparisons.
 *
 *   - The trie is built once at init time and lives in two heap-
 *     allocated packed arrays (nodes + edges) referenced from the
 *     opaque ctx. Destroy frees them.
 *
 *   - Decode still uses linear scan (find_by_id). It's only invoked at
 *     test/debug time; a reverse-index lands later if we hit a hot
 *     decode path.
 *
 *   - The Viterbi DP table and pre-tokenize working buffer are still
 *     heap-allocated per encode call. Typical embedding inputs are
 *     hundreds of bytes — negligible.
 *
 *   - Pre-tokenize prepends ▁ (U+2581, 3 UTF-8 bytes E2 96 81), then
 *     collapses ASCII whitespace runs into single ▁. Non-ASCII
 *     whitespace is NFKC territory (step 4).
 */

#include "ants_tokenizer.h"

#include "utf8proc.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SP_UNDERSCORE_BYTE_0 0xE2u
#define SP_UNDERSCORE_BYTE_1 0x96u
#define SP_UNDERSCORE_BYTE_2 0x81u
#define SP_UNDERSCORE_LEN    3

/* ------------------------------------------------------------------------ */
/* Packed trie                                                              */
/*                                                                          */
/* Two flat heap arrays: nodes[] and edges[]. Each node's children live as */
/* a contiguous slice edges[child_start .. child_start + child_count],     */
/* sorted ascending by byte. Lookup is binary search within the slice.    */
/* token_id == -1 means "not a terminator"; otherwise the node ends a     */
/* vocab entry with the supplied score and token_id.                       */
/* ------------------------------------------------------------------------ */

struct trie_node {
    int32_t token_id;     /* -1 if not a terminator. */
    float score;          /* meaningful only if token_id != -1. */
    uint32_t child_start; /* index into edges[]. */
    uint32_t child_count;
};

struct trie_edge {
    uint8_t byte;
    uint8_t _pad[3];
    uint32_t node_idx; /* index into nodes[]. */
};

#define TRIE_ROOT_IDX 0u
#define TRIE_INVALID  UINT32_MAX

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/* ------------------------------------------------------------------------ */

struct ants_tokenizer_state {
    bool initialised;
    bool byte_fallback_enabled;
    bool nfkc_enabled;
    uint8_t _pad[5];
    const ants_tokenizer_vocab_entry_t *vocab;
    size_t n_vocab;
    size_t max_token_len;
    /* Trie data, heap-allocated by init, freed by destroy. */
    struct trie_node *trie_nodes;
    size_t trie_n_nodes;
    struct trie_edge *trie_edges;
    size_t trie_n_edges;
    /* Byte fallback: when set, every position in encode gets a length-1
     * candidate using byte_fallback_ids[work[s]] with score
     * byte_fallback_score. Set via ants_tokenizer_set_byte_fallback;
     * NULL = disabled. Heap-allocated 256 × uint32_t = 1 KiB; lives
     * here rather than in the opaque ctx because the ctx is itself
     * only 1 KiB. */
    uint32_t *byte_fallback_ids;
    float byte_fallback_score;
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
/* Trie build                                                               */
/*                                                                          */
/* Two-stage construction:                                                  */
/*   Stage A: build a tree of "build nodes" with dynamically-grown child   */
/*            arrays. Each insert walks the tree byte-by-byte from root,  */
/*            creating intermediate build nodes as needed; at the end of   */
/*            the byte sequence the terminator (token_id, score) is        */
/*            written into the build node.                                  */
/*   Stage B: pack the build tree into the flat nodes[] + edges[] arrays. */
/*            DFS the build tree assigning packed indices; for each node, */
/*            sort its children by byte (insertion sort; the per-node      */
/*            branching for natural-language vocabs is small) and write    */
/*            them into a contiguous slice of edges[].                     */
/*                                                                          */
/* The stage-A representation uses ~3× more memory than the stage-B        */
/* output (sparse vs. packed), but it's only alive during init. The       */
/* alternative — inserting directly into the packed format with sorted   */
/* shifts — would be quadratic per insert.                                 */
/* ------------------------------------------------------------------------ */

struct trie_build_child {
    uint8_t byte;
    uint8_t _pad[7];
    struct trie_build_node *child;
};

struct trie_build_node {
    int32_t token_id;
    float score;
    struct trie_build_child *children;
    uint32_t n_children;
    uint32_t cap_children;
};

static void trie_build_free(struct trie_build_node *n)
{
    if (n == NULL) {
        return;
    }
    for (uint32_t i = 0; i < n->n_children; i++) {
        trie_build_free(n->children[i].child);
    }
    free(n->children);
    free(n);
}

static struct trie_build_node *trie_build_new_node(void)
{
    struct trie_build_node *n = (struct trie_build_node *)malloc(sizeof(struct trie_build_node));
    if (n == NULL) {
        return NULL;
    }
    n->token_id = -1;
    n->score = 0.0f;
    n->children = NULL;
    n->n_children = 0;
    n->cap_children = 0;
    return n;
}

/* Linear-search child by byte (unsorted at build time). */
static struct trie_build_node *trie_build_find_child(struct trie_build_node *node, uint8_t byte)
{
    for (uint32_t i = 0; i < node->n_children; i++) {
        if (node->children[i].byte == byte) {
            return node->children[i].child;
        }
    }
    return NULL;
}

/* Append (byte, child) to node's children, growing the array as needed.
 * Returns false on alloc failure. */
static bool
trie_build_add_child(struct trie_build_node *node, uint8_t byte, struct trie_build_node *child)
{
    if (node->n_children == node->cap_children) {
        uint32_t new_cap = node->cap_children == 0 ? 4u : node->cap_children * 2u;
        struct trie_build_child *grown = (struct trie_build_child *)realloc(
            node->children, (size_t)new_cap * sizeof(struct trie_build_child));
        if (grown == NULL) {
            return false;
        }
        node->children = grown;
        node->cap_children = new_cap;
    }
    node->children[node->n_children].byte = byte;
    memset(node->children[node->n_children]._pad, 0, sizeof node->children[node->n_children]._pad);
    node->children[node->n_children].child = child;
    node->n_children++;
    return true;
}

/* Insert one vocab entry's text into the build tree. Returns false on
 * alloc failure. */
static bool trie_build_insert(struct trie_build_node *root,
                              const ants_tokenizer_vocab_entry_t *entry)
{
    struct trie_build_node *cur = root;
    for (size_t i = 0; i < entry->text_len; i++) {
        uint8_t b = (uint8_t)entry->text[i];
        struct trie_build_node *next = trie_build_find_child(cur, b);
        if (next == NULL) {
            next = trie_build_new_node();
            if (next == NULL) {
                return false;
            }
            if (!trie_build_add_child(cur, b, next)) {
                free(next);
                return false;
            }
        }
        cur = next;
    }
    /* Terminator: if the same text appears twice in the vocab, the
     * last-inserted score wins (deterministic per insert order). */
    cur->token_id = (int32_t)entry->token_id;
    cur->score = entry->score;
    return true;
}

/* Count nodes + edges in the build tree (DFS). */
static void
trie_build_count(const struct trie_build_node *node, size_t *out_nodes, size_t *out_edges)
{
    (*out_nodes)++;
    *out_edges += node->n_children;
    for (uint32_t i = 0; i < node->n_children; i++) {
        trie_build_count(node->children[i].child, out_nodes, out_edges);
    }
}

/* Insertion-sort the children array by byte (small N — typical
 * natural-language vocab branching is <16 at most non-root nodes). */
static void trie_build_sort_children(struct trie_build_child *children, uint32_t n)
{
    for (uint32_t i = 1; i < n; i++) {
        struct trie_build_child tmp = children[i];
        uint32_t j = i;
        while (j > 0 && children[j - 1].byte > tmp.byte) {
            children[j] = children[j - 1];
            j--;
        }
        children[j] = tmp;
    }
}

/* Pack `node` (and its subtree) into packed_nodes[*next_node_idx] and
 * its children's slice into packed_edges[*next_edge_idx]. Returns the
 * packed index assigned to this node. */
static uint32_t trie_build_pack(const struct trie_build_node *node,
                                struct trie_node *packed_nodes,
                                struct trie_edge *packed_edges,
                                size_t *next_node_idx,
                                size_t *next_edge_idx)
{
    uint32_t my_idx = (uint32_t)(*next_node_idx);
    (*next_node_idx)++;

    /* Reserve the edge slice for this node FIRST so children get
     * later edge ranges that don't overlap. */
    uint32_t my_edge_start = (uint32_t)(*next_edge_idx);
    uint32_t my_edge_count = node->n_children;
    (*next_edge_idx) += my_edge_count;

    packed_nodes[my_idx].token_id = node->token_id;
    packed_nodes[my_idx].score = node->score;
    packed_nodes[my_idx].child_start = my_edge_start;
    packed_nodes[my_idx].child_count = my_edge_count;

    /* Sort this node's children by byte, then recursively pack each
     * subtree, writing the child packed-index into the edge slot. */
    trie_build_sort_children(node->children, node->n_children);
    for (uint32_t i = 0; i < my_edge_count; i++) {
        packed_edges[my_edge_start + i].byte = node->children[i].byte;
        memset(
            packed_edges[my_edge_start + i]._pad, 0, sizeof packed_edges[my_edge_start + i]._pad);
        uint32_t child_idx = trie_build_pack(
            node->children[i].child, packed_nodes, packed_edges, next_node_idx, next_edge_idx);
        packed_edges[my_edge_start + i].node_idx = child_idx;
    }
    return my_idx;
}

/* Build the packed trie from `vocab[]`. On success, returns ANTS_OK and
 * sets state->trie_nodes / trie_edges + their counts. On failure all
 * allocations are released and state's trie pointers stay NULL. */
static ants_error_t trie_build(struct ants_tokenizer_state *state)
{
    struct trie_build_node *root = trie_build_new_node();
    if (root == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    for (size_t i = 0; i < state->n_vocab; i++) {
        if (!trie_build_insert(root, &state->vocab[i])) {
            trie_build_free(root);
            return ANTS_ERROR_MALFORMED;
        }
    }
    size_t n_nodes = 0, n_edges = 0;
    trie_build_count(root, &n_nodes, &n_edges);

    struct trie_node *packed_nodes = (struct trie_node *)malloc(n_nodes * sizeof(struct trie_node));
    struct trie_edge *packed_edges =
        (struct trie_edge *)malloc((n_edges > 0 ? n_edges : 1) * sizeof(struct trie_edge));
    if (packed_nodes == NULL || packed_edges == NULL) {
        free(packed_nodes);
        free(packed_edges);
        trie_build_free(root);
        return ANTS_ERROR_MALFORMED;
    }
    size_t ni = 0, ei = 0;
    (void)trie_build_pack(root, packed_nodes, packed_edges, &ni, &ei);
    trie_build_free(root);

    state->trie_nodes = packed_nodes;
    state->trie_n_nodes = n_nodes;
    state->trie_edges = packed_edges;
    state->trie_n_edges = n_edges;
    return ANTS_OK;
}

static void trie_destroy(struct ants_tokenizer_state *state)
{
    free(state->trie_nodes);
    free(state->trie_edges);
    state->trie_nodes = NULL;
    state->trie_edges = NULL;
    state->trie_n_nodes = 0;
    state->trie_n_edges = 0;
}

/* Binary search for byte b among a node's sorted children. Returns the
 * child's node_idx or TRIE_INVALID if no match. */
static uint32_t
trie_find_child(const struct ants_tokenizer_state *state, uint32_t parent_idx, uint8_t b)
{
    const struct trie_node *p = &state->trie_nodes[parent_idx];
    uint32_t lo = p->child_start;
    uint32_t hi = p->child_start + p->child_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        uint8_t mb = state->trie_edges[mid].byte;
        if (mb < b) {
            lo = mid + 1u;
        } else if (mb > b) {
            hi = mid;
        } else {
            return state->trie_edges[mid].node_idx;
        }
    }
    return TRIE_INVALID;
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
    state->vocab = vocab;
    state->n_vocab = n_vocab;
    state->max_token_len = max_len;
    ants_error_t err = trie_build(state);
    if (err != ANTS_OK) {
        /* trie_build cleaned up its own intermediate allocations. */
        memset(tok->_opaque, 0, sizeof tok->_opaque);
        return err;
    }
    state->initialised = true;
    return ANTS_OK;
}

ants_error_t ants_tokenizer_destroy(ants_tokenizer_t *tok)
{
    if (tok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_tokenizer_state *state = tok_state(tok);
    if (state->initialised) {
        trie_destroy(state);
        free(state->byte_fallback_ids);
        state->byte_fallback_ids = NULL;
    }
    memset(tok->_opaque, 0, sizeof tok->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Byte fallback                                                            */
/*                                                                          */
/* Heap-allocate the 256-entry byte→ID table; encode then has a length-1   */
/* candidate for every position. Passing NULL clears any previously-set    */
/* fallback (reverting to "uncovered → NON_CANONICAL" behaviour).          */
/* ------------------------------------------------------------------------ */

ants_error_t ants_tokenizer_set_byte_fallback(ants_tokenizer_t *tok,
                                              const uint32_t byte_fallback_ids[256],
                                              float byte_fallback_score)
{
    if (tok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_tokenizer_state *state = tok_state(tok);
    if (!state->initialised) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Clear path: caller passed NULL to disable. */
    if (byte_fallback_ids == NULL) {
        free(state->byte_fallback_ids);
        state->byte_fallback_ids = NULL;
        state->byte_fallback_enabled = false;
        state->byte_fallback_score = 0.0f;
        return ANTS_OK;
    }
    uint32_t *copy = (uint32_t *)malloc(256u * sizeof(uint32_t));
    if (copy == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(copy, byte_fallback_ids, 256u * sizeof(uint32_t));
    free(state->byte_fallback_ids);
    state->byte_fallback_ids = copy;
    state->byte_fallback_score = byte_fallback_score;
    state->byte_fallback_enabled = true;
    return ANTS_OK;
}

ants_error_t ants_tokenizer_set_nfkc_enabled(ants_tokenizer_t *tok, bool enabled)
{
    if (tok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_tokenizer_state *state = tok_state(tok);
    if (!state->initialised) {
        return ANTS_ERROR_INVALID_ARG;
    }
    state->nfkc_enabled = enabled;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Pre-tokenization                                                          */
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
    size_t i = 0;
    while (i < in_len && is_ascii_ws(in[i])) {
        i++;
    }
    bool prev_was_ws = false;
    while (i < in_len) {
        uint8_t b = in[i];
        if (is_ascii_ws(b)) {
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
/* Viterbi (trie-driven forward sweep)                                      */
/*                                                                          */
/* For each start position s with a reachable dp[s], walk the trie one    */
/* byte at a time over work[s..]. Every terminator node hit during the    */
/* walk yields a candidate update for dp[s + path_len]. We stop walking   */
/* either at the input end or when no child matches the next byte (no    */
/* longer prefix in the trie covers the suffix starting at s).            */
/*                                                                          */
/* Compared to step 1's O(N × V × max_len) "for each end, scan every     */
/* entry" pass, this is O(N × max_token_len × log(branching)).            */
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

    /* NFKC normalisation pass (optional). utf8proc_map allocates the
     * output buffer; we free it after pretokenize copies the bytes. */
    const uint8_t *src_bytes = (const uint8_t *)input;
    size_t src_len = input_len;
    utf8proc_uint8_t *nfkc_buf = NULL;
    if (state->nfkc_enabled) {
        utf8proc_ssize_t nfkc_len =
            utf8proc_map(src_bytes,
                         (utf8proc_ssize_t)input_len,
                         &nfkc_buf,
                         UTF8PROC_STABLE | UTF8PROC_COMPAT | UTF8PROC_COMPOSE);
        if (nfkc_len < 0 || nfkc_buf == NULL) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        src_bytes = (const uint8_t *)nfkc_buf;
        src_len = (size_t)nfkc_len;
    }

    /* Pre-tokenize. Worst case: every input byte is whitespace and
     * gets expanded to ▁ (3 bytes), plus the always-prepended ▁. */
    size_t work_cap = src_len * 3u + SP_UNDERSCORE_LEN;
    uint8_t *work = (uint8_t *)malloc(work_cap);
    if (work == NULL) {
        free(nfkc_buf);
        return ANTS_ERROR_MALFORMED;
    }
    size_t N = pretokenize(src_bytes, src_len, work);
    free(nfkc_buf);

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

    /* Forward sweep over starts, descending the trie per start. */
    for (size_t s = 0; s < N; s++) {
        if (dp[s] == NEG_INF) {
            continue;
        }
        uint32_t node = TRIE_ROOT_IDX;
        size_t k = 0;
        while (s + k < N && k < state->max_token_len) {
            uint8_t b = work[s + k];
            uint32_t child = trie_find_child(state, node, b);
            if (child == TRIE_INVALID) {
                break;
            }
            node = child;
            k++;
            int32_t tid = state->trie_nodes[node].token_id;
            if (tid >= 0) {
                size_t e = s + k;
                float cand = dp[s] + state->trie_nodes[node].score;
                if (cand > dp[e]) {
                    dp[e] = cand;
                    back_pos[e] = s;
                    back_id[e] = (uint32_t)tid;
                }
            }
        }
        /* Byte fallback: when enabled, every position also has a
         * length-1 candidate emitting byte_fallback_ids[work[s]] with
         * byte_fallback_score. Viterbi naturally picks whichever path
         * has the highest accumulated score — fallback tokens have low
         * scores by convention so they only "win" when no longer vocab
         * entry covers the position. */
        if (state->byte_fallback_enabled) {
            size_t e = s + 1;
            float cand = dp[s] + state->byte_fallback_score;
            if (cand > dp[e]) {
                dp[e] = cand;
                back_pos[e] = s;
                back_id[e] = state->byte_fallback_ids[work[s]];
            }
        }
    }

    if (dp[N] == NEG_INF) {
        free(work);
        free(dp);
        free(back_pos);
        free(back_id);
        return ANTS_ERROR_NON_CANONICAL;
    }

    size_t out_n = 0;
    size_t cur = N;
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

    size_t need = 0;
    for (size_t i = 0; i < n_tokens; i++) {
        const ants_tokenizer_vocab_entry_t *e = find_by_id(state, token_ids[i]);
        if (e == NULL) {
            return ANTS_ERROR_INVALID_ARG;
        }
        need += e->text_len;
    }
    *out_len = need;
    if (out_cap < need) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

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
