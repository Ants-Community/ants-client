/*
 * orchestration.c — Inference orchestration (Component #13).
 *
 * Per RFC-0003 v0.2 + RFC-0009 v0.5. Surfaces 1-3 are implemented; surface 4
 * (the serving runtime) is landing incrementally — init + the reference-model
 * forward pass are implemented here, with serve + the audit capstone still
 * stubs that validate arguments and return ANTS_ERROR_NOT_IMPLEMENTED until
 * their PRs:
 *
 *   1. Commit-at-send  — leaf hash, Merkle root/prove/verify, commit
 *                        encode/decode, Ed25519 sign/verify. IMPLEMENTED.
 *   2. Challenge       — the three beacon-bound PRF derivations. IMPLEMENTED.
 *   3. e-process       — init/update + discrepancy scoring. IMPLEMENTED.
 *   4. Serving runtime — init + the DRAFT reference model (a canonical forward
 *                        over the #12 kernels) + reference_distribution:
 *                        IMPLEMENTED. serve + the audit capstone: pending.
 *
 * Discipline: caller-owned state, no internal allocation, no threads, no
 * global mutable state, no logging — matching foundation/, network/,
 * cache/, and inference/kernels/. The commit-at-send path hashes with
 * ants_crypto (BLAKE3 + Ed25519) and serializes with ants_cbor, both
 * caller-buffer / no-malloc libraries, so the discipline holds end to end.
 */

#include "ants_inference.h"

#include "ants_cbor.h"
#include "ants_crypto.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* PRF domain-separation tags (RFC-0003 §Anti-grinding)                     */
/* ------------------------------------------------------------------------ */

const char *const ANTS_INFERENCE_PRF_CONTEXT_SEL = "sel";
const char *const ANTS_INFERENCE_PRF_CONTEXT_POS = "pos";
const char *const ANTS_INFERENCE_PRF_CONTEXT_AUD = "aud";

/* ------------------------------------------------------------------------ */
/* Opaque runtime state                                                     */
/*                                                                          */
/* Lives inside ants_inference_t::_opaque. Minimal in this scaffold; the    */
/* forward-looking fields are present so the compile-time size-check guards  */
/* a realistic footprint rather than a near-empty struct. Identified by a    */
/* magic word so destroy/serve can reject an uninitialized or wrong context.*/
/* ------------------------------------------------------------------------ */

#define ANTS_INFERENCE_STATE_MAGIC 0x494E4652u /* "INFR" */

struct ants_inference_state {
    uint32_t magic;

    /* Loaded reference-model dimensions (validated <= the REF_*_MAX caps at
     * init). vocab = V (logit-vector length); d_model = D (hidden size). */
    uint32_t vocab;
    uint32_t d_model;

    /* The loaded model's hash (bound into every commit) and the producer
     * public key derived from the configured private key. */
    uint8_t model_hash[ANTS_INFERENCE_HASH_SIZE];
    uint8_t producer_pub[ANTS_INFERENCE_PUBKEY_SIZE];

    /* FP32 tensor views into the caller-owned weight blob (never copied — the
     * blob must outlive the context). Row-major; shapes in brackets. */
    const float *embed;   /* E  [V x D] */
    const float *w_q;     /* Wq [D x D] */
    const float *w_k;     /* Wk [D x D] */
    const float *w_v;     /* Wv [D x D] */
    const float *w_o;     /* Wo [D x D] */
    const float *unembed; /* U  [D x V] */

    /* Per-request forward-pass scratch arena: the five [T x D] activation
     * buffers (X, Q, K, V, attn-out) plus the [T x T] attention scratch,
     * laid out contiguously and sized for the REF_*_MAX caps so a forward at
     * any admissible (prefix_len, dims) fits with no allocation. */
    float scratch[5u * ANTS_INFERENCE_REF_SEQLEN_MAX * ANTS_INFERENCE_REF_DMODEL_MAX +
                  ANTS_INFERENCE_REF_SEQLEN_MAX * ANTS_INFERENCE_REF_SEQLEN_MAX];
};

/* The opaque buffer must be able to hold the internal state. Conservative
 * oversize today (ANTS_INFERENCE_CTX_SIZE); tightened once `serve` is
 * implemented and the true footprint is measured. */
typedef char ants_inference_state_size_check
    [(sizeof(struct ants_inference_state) <= sizeof(((ants_inference_t *)0)->_opaque)) ? 1 : -1];

/* ======================================================================== */
/* 1. Commit-at-send                                                        */
/* ======================================================================== */

/* ---- internal helpers --------------------------------------------------- */

/* Little-endian 8-byte encode of a u64 (the position binding in a leaf). */
static void write_le64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

/* internal(L,R) = BLAKE3(0x01 ‖ L ‖ R). `out` may alias `left` or `right`:
 * each input is consumed into the hasher before `final` writes `out`. */
static ants_error_t node_hash(const uint8_t left[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                              const uint8_t right[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                              uint8_t out[ANTS_INFERENCE_MERKLE_ROOT_SIZE])
{
    const uint8_t prefix = ANTS_INFERENCE_MERKLE_NODE_PREFIX;
    ants_blake3_ctx_t h;
    ants_error_t rc;

    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, &prefix, 1);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, left, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, right, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out);
}

/* Merkle root over the contiguous leaf range [lo, hi) (requires hi > lo)
 * under the promote-lone-trailing-node level scheme, computed with an
 * O(log n) bounded stack and no allocation. Online MMR build: push each
 * leaf at height 0, eagerly merging the top two entries while they share a
 * height; then "bag" the leftover peaks right-to-left — each peak to the
 * left becomes the left child of the running accumulator, which reproduces
 * the level scheme's promotion of a lone trailing node. The stack holds at
 * most one peak per height (≤ MAX_DEPTH) plus the transient pre-merge push. */
static ants_error_t subtree_root_range(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                       size_t lo,
                                       size_t hi,
                                       uint8_t out[ANTS_INFERENCE_MERKLE_ROOT_SIZE])
{
    uint8_t stack[ANTS_INFERENCE_MERKLE_MAX_DEPTH + 2][ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    int height[ANTS_INFERENCE_MERKLE_MAX_DEPTH + 2];
    int top = 0;
    ants_error_t rc;
    size_t i;
    int k;

    for (i = lo; i < hi; i++) {
        memcpy(stack[top], leaves[i], ANTS_INFERENCE_MERKLE_ROOT_SIZE);
        height[top] = 0;
        top++;
        while (top >= 2 && height[top - 1] == height[top - 2]) {
            rc = node_hash(stack[top - 2], stack[top - 1], stack[top - 2]);
            if (rc != ANTS_OK) {
                return rc;
            }
            height[top - 2]++;
            top--;
        }
    }

    /* Bag the leftover peaks: accumulator is the rightmost (smallest) peak
     * at stack[top - 1]; fold each peak to its left in as the left child. */
    for (k = top - 2; k >= 0; k--) {
        rc = node_hash(stack[k], stack[top - 1], stack[top - 1]);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    memcpy(out, stack[top - 1], ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    return ANTS_OK;
}

/* Number of sibling hashes on the path from leaf `index` to the root in a
 * promote-lone-node tree of `n_leaves`. A promoted lone trailing node has
 * no sibling at its level and contributes no path entry. */
static size_t merkle_path_len(size_t index, size_t n_leaves)
{
    size_t len = 0;
    size_t idx = index;
    size_t count = n_leaves;

    while (count > 1) {
        if ((idx & 1u) == 1u) {
            len++; /* right child: always has a left sibling */
        } else if (idx + 1 < count) {
            len++; /* left child with a right sibling present */
        }
        idx /= 2;
        count = (count + 1) / 2;
    }
    return len;
}

/* ---- canonical CBOR commit scheme (DRAFT, defined by this PR) -----------
 *
 * A definite-length CBOR map of 10 pairs with ascending integer keys 1..10
 * in struct-field order, float-free (the audit probability rides as the
 * integer `audit_threshold`). Keys 1..10 each encode to a single byte
 * (0x01..0x0a) and so are already in canonical bytewise-ascending order.
 * Documented here for byte-for-byte agreement with any independent
 * implementation, pending RFC-0003 / RFC-0008 formalization.
 *
 *   1 root[32]   2 model_hash[32]   3 input_hash[32]   4 req_nonce[32]
 *   5 agent_meas[32]   6 round(u64)   7 audit_threshold(u64)
 *   8 m(u32)   9 length(u32)   10 tier(u8) */
#define COMMIT_CBOR_PAIRS 10

enum {
    COMMIT_KEY_ROOT = 1,
    COMMIT_KEY_MODEL = 2,
    COMMIT_KEY_INPUT = 3,
    COMMIT_KEY_NONCE = 4,
    COMMIT_KEY_AGENT = 5,
    COMMIT_KEY_ROUND = 6,
    COMMIT_KEY_AUDIT = 7,
    COMMIT_KEY_M = 8,
    COMMIT_KEY_LENGTH = 9,
    COMMIT_KEY_TIER = 10
};

static ants_error_t enc_kv_bytes(ants_cbor_enc_t *enc, uint64_t key, const uint8_t *b, size_t len)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bytes(enc, b, len);
}

static ants_error_t enc_kv_uint(ants_cbor_enc_t *enc, uint64_t key, uint64_t val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_uint(enc, val);
}

/* Collapse the decoder's full error vocabulary onto the commit_decode
 * contract. A §4.2.1 canonical violation (non-shortest integer, indefinite
 * length) keeps its NON_CANONICAL identity; everything else the decoder can
 * raise on malformed input — including UNSUPPORTED_TYPE for a wrong CBOR major
 * type where the schema demands a uint / byte-string / map — is structural
 * framing damage and folds into MALFORMED. INVALID_ARG cannot occur here: the
 * decoder only raises it for NULL arguments, which this path never passes. */
static ants_error_t norm_decode_err(ants_error_t rc)
{
    if (rc == ANTS_OK || rc == ANTS_ERROR_NON_CANONICAL) {
        return rc;
    }
    return ANTS_ERROR_MALFORMED;
}

/* Read the next map key and require it to equal `want` (the keys are fixed
 * and ascending, so a mismatch is a structural error). A canonical-order
 * violation surfaces as ANTS_ERROR_NON_CANONICAL straight from the decoder. */
static ants_error_t expect_key(ants_cbor_dec_t *dec, uint64_t want)
{
    uint64_t key;
    ants_error_t rc = norm_decode_err(ants_cbor_dec_uint(dec, &key));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (key != want) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

static ants_error_t
decode_bytes_field(ants_cbor_dec_t *dec, uint64_t key, uint8_t *dst, size_t want)
{
    const uint8_t *p;
    size_t len;
    ants_error_t rc;

    rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_bytes(dec, &p, &len));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (len != want) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(dst, p, want);
    return ANTS_OK;
}

static ants_error_t decode_uint_field(ants_cbor_dec_t *dec, uint64_t key, uint64_t *out)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_uint(dec, out));
}

/* ---- public API --------------------------------------------------------- */

ants_error_t ants_inference_leaf_hash(const uint8_t *dist_bytes,
                                      size_t dist_len,
                                      uint64_t position,
                                      uint8_t out_leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE])
{
    const uint8_t prefix = ANTS_INFERENCE_MERKLE_LEAF_PREFIX;
    uint8_t le[8];
    ants_blake3_ctx_t h;
    ants_error_t rc;

    if (dist_bytes == NULL || dist_len == 0 || out_leaf == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    write_le64(le, position);
    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, &prefix, 1);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, dist_bytes, dist_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, le, sizeof le);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out_leaf);
}

ants_error_t ants_inference_merkle_root(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                        size_t n_leaves,
                                        uint8_t out_root[ANTS_INFERENCE_MERKLE_ROOT_SIZE])
{
    if (leaves == NULL || n_leaves == 0 || out_root == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((uint64_t)n_leaves > ((uint64_t)1 << ANTS_INFERENCE_MERKLE_MAX_DEPTH)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return subtree_root_range(leaves, 0, n_leaves, out_root);
}

ants_error_t ants_inference_merkle_prove(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                         size_t n_leaves,
                                         size_t index,
                                         uint8_t *out_path,
                                         size_t out_path_cap,
                                         size_t *out_path_len)
{
    size_t need;
    size_t written = 0;
    size_t idx;
    size_t count;
    int level = 0;
    ants_error_t rc;

    if (leaves == NULL || n_leaves == 0 || index >= n_leaves || out_path == NULL ||
        out_path_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((uint64_t)n_leaves > ((uint64_t)1 << ANTS_INFERENCE_MERKLE_MAX_DEPTH)) {
        return ANTS_ERROR_INVALID_ARG;
    }

    need = merkle_path_len(index, n_leaves);
    if (need > out_path_cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    idx = index;
    count = n_leaves;
    while (count > 1) {
        bool has_sib = false;
        size_t sib = 0;

        if ((idx & 1u) == 1u) {
            has_sib = true;
            sib = idx - 1;
        } else if (idx + 1 < count) {
            has_sib = true;
            sib = idx + 1;
        }
        if (has_sib) {
            uint64_t lo64 = (uint64_t)sib << level;
            uint64_t hi64 = ((uint64_t)sib + 1) << level;
            if (hi64 > (uint64_t)n_leaves) {
                hi64 = (uint64_t)n_leaves;
            }
            rc = subtree_root_range(leaves,
                                    (size_t)lo64,
                                    (size_t)hi64,
                                    out_path + written * ANTS_INFERENCE_MERKLE_ROOT_SIZE);
            if (rc != ANTS_OK) {
                return rc;
            }
            written++;
        }
        idx /= 2;
        count = (count + 1) / 2;
        level++;
    }

    *out_path_len = written;
    return ANTS_OK;
}

ants_error_t ants_inference_merkle_verify(const uint8_t leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                          size_t index,
                                          size_t n_leaves,
                                          const uint8_t *path,
                                          size_t path_len,
                                          const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                          bool *out_ok)
{
    uint8_t cur[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    size_t consumed = 0;
    size_t idx;
    size_t count;
    ants_error_t rc;

    if (leaf == NULL || n_leaves == 0 || index >= n_leaves || path == NULL || root == NULL ||
        out_ok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((uint64_t)n_leaves > ((uint64_t)1 << ANTS_INFERENCE_MERKLE_MAX_DEPTH)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (path_len != merkle_path_len(index, n_leaves)) {
        return ANTS_ERROR_INVALID_ARG;
    }

    memcpy(cur, leaf, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    idx = index;
    count = n_leaves;
    while (count > 1) {
        bool has_sib = false;
        bool sib_on_left = false;

        if ((idx & 1u) == 1u) {
            has_sib = true;
            sib_on_left = true;
        } else if (idx + 1 < count) {
            has_sib = true;
            sib_on_left = false;
        }
        if (has_sib) {
            const uint8_t *sib = path + consumed * ANTS_INFERENCE_MERKLE_ROOT_SIZE;
            if (sib_on_left) {
                rc = node_hash(sib, cur, cur);
            } else {
                rc = node_hash(cur, sib, cur);
            }
            if (rc != ANTS_OK) {
                return rc;
            }
            consumed++;
        }
        idx /= 2;
        count = (count + 1) / 2;
    }

    *out_ok = (consumed == path_len) && (memcmp(cur, root, ANTS_INFERENCE_MERKLE_ROOT_SIZE) == 0);
    return ANTS_OK;
}

ants_error_t ants_inference_commit_encode(const ants_inference_commit_t *commit,
                                          uint8_t *out,
                                          size_t out_cap,
                                          size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (commit == NULL || out == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, out, out_cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, COMMIT_CBOR_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, COMMIT_KEY_ROOT, commit->root, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, COMMIT_KEY_MODEL, commit->model_hash, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, COMMIT_KEY_INPUT, commit->input_hash, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, COMMIT_KEY_NONCE, commit->req_nonce, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, COMMIT_KEY_AGENT, commit->agent_meas, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, COMMIT_KEY_ROUND, commit->round);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, COMMIT_KEY_AUDIT, commit->audit_threshold);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, COMMIT_KEY_M, commit->m);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, COMMIT_KEY_LENGTH, commit->length);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, COMMIT_KEY_TIER, commit->tier);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }

    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t
ants_inference_commit_decode(const uint8_t *in, size_t in_len, ants_inference_commit_t *out)
{
    ants_cbor_dec_t dec;
    size_t n_pairs;
    uint64_t u;
    ants_error_t rc;

    if (in == NULL || in_len == 0 || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_dec_init(&dec, in, in_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != COMMIT_CBOR_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }

    rc = decode_bytes_field(&dec, COMMIT_KEY_ROOT, out->root, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, COMMIT_KEY_MODEL, out->model_hash, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, COMMIT_KEY_INPUT, out->input_hash, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, COMMIT_KEY_NONCE, out->req_nonce, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, COMMIT_KEY_AGENT, out->agent_meas, ANTS_INFERENCE_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, COMMIT_KEY_ROUND, &out->round);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, COMMIT_KEY_AUDIT, &out->audit_threshold);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, COMMIT_KEY_M, &u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (u > UINT32_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    out->m = (uint32_t)u;
    rc = decode_uint_field(&dec, COMMIT_KEY_LENGTH, &u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (u > UINT32_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    out->length = (uint32_t)u;
    rc = decode_uint_field(&dec, COMMIT_KEY_TIER, &u);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (u > UINT8_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    out->tier = (uint8_t)u;

    /* A complete commit is exactly one map and nothing else; a trailing
     * byte or an unclosed container is malformed framing. */
    rc = ants_cbor_dec_finalise(&dec);
    if (rc != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

ants_error_t ants_inference_commit_sign(const ants_inference_commit_t *commit,
                                        const uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE],
                                        uint8_t out_sig[ANTS_INFERENCE_SIG_SIZE])
{
    uint8_t buf[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    size_t len;
    ants_error_t rc;

    if (commit == NULL || priv == NULL || out_sig == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_inference_commit_encode(commit, buf, sizeof buf, &len);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_ed25519_sign(priv, buf, len, out_sig);
}

ants_error_t ants_inference_commit_verify_sig(const ants_inference_commit_t *commit,
                                              const uint8_t pub[ANTS_INFERENCE_PUBKEY_SIZE],
                                              const uint8_t sig[ANTS_INFERENCE_SIG_SIZE],
                                              bool *out_ok)
{
    uint8_t buf[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    size_t len;
    ants_error_t rc;

    if (commit == NULL || pub == NULL || sig == NULL || out_ok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_inference_commit_encode(commit, buf, sizeof buf, &len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_ed25519_verify(pub, buf, len, sig);
    if (rc == ANTS_OK) {
        *out_ok = true;
        return ANTS_OK;
    }
    if (rc == ANTS_ERROR_MALFORMED) {
        *out_ok = false;
        return ANTS_OK;
    }
    return rc;
}

/* ======================================================================== */
/* 2. Anti-grinding challenge derivation                                    */
/* ======================================================================== */

/* ---- internal: the anti-grinding PRF keystream -------------------------- */

/* Read a 64-bit big-endian word. Big-endian matches the "interpret the PRF
 * output as a big-endian integer" convention the commit's audit_threshold
 * already uses. */
static uint64_t read_be64(const uint8_t b[8])
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

/* A counter-mode BLAKE3 keystream over seed = beacon ‖ root ‖ tag. BLAKE3 here
 * yields a 32-byte digest and no XOF, so an arbitrarily long stream is
 * block(i) = BLAKE3(seed ‖ LE64(i)), i = 0,1,2,…, read out as 64-bit
 * big-endian words. DRAFT scheme, pinned for byte-for-byte agreement with
 * independent implementations pending RFC-0003/RFC-0008 formalization. */
typedef struct {
    const uint8_t *beacon;
    const uint8_t *root;
    const uint8_t *tag;
    size_t tag_len;
    uint8_t block[ANTS_INFERENCE_HASH_SIZE]; /* most recently hashed block */
    uint64_t next_block;                     /* counter of the next block to hash */
    int words_left;                          /* unread words in `block` (0..4) */
} prf_keystream_t;

static void prf_keystream_init(prf_keystream_t *ks,
                               const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                               const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                               const char *tag)
{
    ks->beacon = beacon;
    ks->root = root;
    ks->tag = (const uint8_t *)tag;
    ks->tag_len = strlen(tag);
    ks->next_block = 0;
    ks->words_left = 0;
}

/* block = BLAKE3(beacon ‖ root ‖ tag ‖ LE64(counter)). */
static ants_error_t prf_compute_block(prf_keystream_t *ks, uint64_t counter)
{
    uint8_t ctr[8];
    ants_blake3_ctx_t h;
    ants_error_t rc;

    write_le64(ctr, counter);
    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, ks->beacon, ANTS_INFERENCE_BEACON_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, ks->root, ANTS_INFERENCE_MERKLE_ROOT_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, ks->tag, ks->tag_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, ctr, sizeof ctr);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, ks->block);
}

/* Next 64-bit big-endian keystream word. */
static ants_error_t prf_next_word(prf_keystream_t *ks, uint64_t *out)
{
    ants_error_t rc;
    int word_idx;

    if (ks->words_left == 0) {
        rc = prf_compute_block(ks, ks->next_block);
        if (rc != ANTS_OK) {
            return rc;
        }
        ks->next_block += 1;
        ks->words_left = 4;
    }
    word_idx = 4 - ks->words_left; /* 0..3 within the current block */
    *out = read_be64(ks->block + (size_t)word_idx * 8);
    ks->words_left -= 1;
    return ANTS_OK;
}

/* ---- public entry points ------------------------------------------------ */

ants_error_t
ants_inference_challenge_is_audited(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                    const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                    uint64_t audit_threshold,
                                    bool *out_audited)
{
    prf_keystream_t ks;
    uint64_t w0;
    ants_error_t rc;

    if (beacon == NULL || root == NULL || out_audited == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    prf_keystream_init(&ks, beacon, root, ANTS_INFERENCE_PRF_CONTEXT_SEL);
    rc = prf_next_word(&ks, &w0);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_audited = (w0 < audit_threshold);
    return ANTS_OK;
}

ants_error_t ants_inference_challenge_positions(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                                const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                                uint32_t m,
                                                uint32_t length,
                                                uint64_t *out_positions,
                                                size_t cap,
                                                size_t *out_count)
{
    prf_keystream_t ks;
    uint32_t count;
    uint32_t j;
    ants_error_t rc;

    if (beacon == NULL || root == NULL || m == 0 || length == 0 || out_positions == NULL ||
        out_count == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    count = (m < length) ? m : length; /* M = min(m, length) */
    if (cap < (size_t)count) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    if (m >= length) {
        /* The whole answer is opened: positions 0 .. length-1, no draw. */
        for (j = 0; j < length; j++) {
            out_positions[j] = j;
        }
        *out_count = (size_t)length;
        return ANTS_OK;
    }

    /* Stratified ("strided") sample: split [0, length) into m contiguous
     * buckets and draw one position per bucket. Disjoint buckets make the
     * result distinct and strictly ascending. m < length here, so every
     * bucket width is >= 1. */
    prf_keystream_init(&ks, beacon, root, ANTS_INFERENCE_PRF_CONTEXT_POS);
    for (j = 0; j < m; j++) {
        uint64_t lo = ((uint64_t)j * (uint64_t)length) / (uint64_t)m;
        uint64_t hi = (((uint64_t)j + 1u) * (uint64_t)length) / (uint64_t)m;
        uint64_t width = hi - lo;
        uint64_t w;
        rc = prf_next_word(&ks, &w);
        if (rc != ANTS_OK) {
            return rc;
        }
        out_positions[j] = lo + (w % width);
    }
    *out_count = (size_t)m;
    return ANTS_OK;
}

ants_error_t ants_inference_challenge_auditor(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                              const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                              uint64_t n_verifiers,
                                              uint64_t *out_index)
{
    prf_keystream_t ks;
    uint64_t reject_below;
    ants_error_t rc;

    if (beacon == NULL || root == NULL || n_verifiers == 0 || out_index == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Reject the low (2^64 mod n)-wide band so the accepted range is a whole
     * multiple of n; then w % n is unbiased. In u64 arithmetic (0 - n) is
     * 2^64 - n, and (2^64 - n) mod n == 2^64 mod n. */
    reject_below = ((uint64_t)0 - n_verifiers) % n_verifiers;

    prf_keystream_init(&ks, beacon, root, ANTS_INFERENCE_PRF_CONTEXT_AUD);
    for (;;) {
        uint64_t w;
        rc = prf_next_word(&ks, &w);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (w >= reject_below) {
            *out_index = w % n_verifiers;
            return ANTS_OK;
        }
    }
}

/* ======================================================================== */
/* 3. The betting e-process                                                 */
/* ======================================================================== */

ants_error_t ants_inference_eprocess_init(ants_inference_eprocess_t *ep,
                                          double alpha,
                                          double mu0,
                                          double lambda_cap)
{
    if (ep == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* The !(>=) form also rejects NaN parameters (every comparison is false). */
    if (!(alpha > 0.0 && alpha < 1.0) || !(mu0 >= 0.0 && mu0 < 1.0) || !(lambda_cap >= 0.0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ep->alpha = alpha;
    ep->mu0 = mu0;
    ep->lambda_cap = lambda_cap;
    ep->capital = 1.0;
    /* mu_hat / var_hat carry one pseudo-observation prior (mean 1/2, variance
     * 1/4) so the first bet is well-defined and var_hat stays > 0 thereafter. */
    ep->mu_hat = 0.5;
    ep->var_hat = 0.25;
    ep->n = 0;
    return ANTS_OK;
}

ants_error_t ants_inference_eprocess_update(ants_inference_eprocess_t *ep,
                                            double score,
                                            ants_inference_verdict_t *out_verdict)
{
    double lambda;
    double k, m2, knew, delta;

    if (ep == NULL || out_verdict == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!(score >= 0.0 && score <= 1.0)) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Predictable bet from the pre-score statistics, so lambda depends only on
     * X_1..X_n (never on this score): lambda = clip((mu_hat - mu0)/var_hat, 0,
     * lambda_cap). var_hat > 0 always (the prior), so the divide is safe. */
    lambda = (ep->mu_hat - ep->mu0) / ep->var_hat;
    if (lambda < 0.0) {
        lambda = 0.0;
    }
    if (lambda > ep->lambda_cap) {
        lambda = ep->lambda_cap;
    }

    /* Capital recursion M_n = prod_j (1 + lambda_j (X_j - mu0)). */
    ep->capital *= 1.0 + lambda * (score - ep->mu0);

    /* Fold the score into the prior-augmented running mean/variance: Welford,
     * treating the init prior as a pseudo-observation (pseudo-count). The
     * struct stores mu_hat and var_hat, so reconstruct the sum of squared
     * deviations m2 = var_hat * count, update it, and store the new variance. */
    k = (double)(ep->n + 1); /* prior obs + n scores seen so far */
    m2 = ep->var_hat * k;
    knew = k + 1.0;
    delta = score - ep->mu_hat;
    ep->mu_hat += delta / knew;
    m2 += delta * (score - ep->mu_hat);
    ep->var_hat = m2 / knew;
    ep->n += 1;

    *out_verdict = (ep->capital >= 1.0 / ep->alpha) ? ANTS_INFERENCE_VERDICT_FRAUD
                                                    : ANTS_INFERENCE_VERDICT_CONTINUE;
    return ANTS_OK;
}

ants_error_t ants_inference_discrepancy(const ants_canon_q24_t *p_ref,
                                        const ants_canon_q24_t *q_committed,
                                        size_t vocab,
                                        double *out_score)
{
    double max_p, max_q, sum_p, sum_q, tv;
    size_t i;

    if (p_ref == NULL || q_committed == NULL || vocab == 0 || out_score == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* DRAFT metric (pending RFC-0003/RFC-0009 ratification): total-variation
     * distance between the canonical softmaxes of the two q24 logit vectors,
     * TV = 1/2 * sum_i |P_i - Q_i|, which lies in [0, 1]. Computed streaming in
     * double (max pass, sum-of-exp pass, then the |.| accumulation) so no
     * vocab-sized buffer is needed; the canonical softmax kernel caps at 16384
     * < a real vocab, hence the local recomputation. exp() is libm; bit-exact
     * cross-verifier agreement of the transcendental step is the open item the
     * header documents. */
    max_p = (double)ants_canon_q24_to_f32(p_ref[0]);
    max_q = (double)ants_canon_q24_to_f32(q_committed[0]);
    for (i = 1; i < vocab; i++) {
        double lp = (double)ants_canon_q24_to_f32(p_ref[i]);
        double lq = (double)ants_canon_q24_to_f32(q_committed[i]);
        if (lp > max_p) {
            max_p = lp;
        }
        if (lq > max_q) {
            max_q = lq;
        }
    }

    sum_p = 0.0;
    sum_q = 0.0;
    for (i = 0; i < vocab; i++) {
        sum_p += exp((double)ants_canon_q24_to_f32(p_ref[i]) - max_p);
        sum_q += exp((double)ants_canon_q24_to_f32(q_committed[i]) - max_q);
    }
    /* The arg-max element contributes exp(0) = 1, so both sums are >= 1. */

    tv = 0.0;
    for (i = 0; i < vocab; i++) {
        double pi = exp((double)ants_canon_q24_to_f32(p_ref[i]) - max_p) / sum_p;
        double qi = exp((double)ants_canon_q24_to_f32(q_committed[i]) - max_q) / sum_q;
        double d = pi - qi;
        tv += (d < 0.0) ? -d : d;
    }
    tv *= 0.5;

    /* TV is in [0, 1] analytically; clamp away any floating-point spill. */
    if (tv < 0.0) {
        tv = 0.0;
    }
    if (tv > 1.0) {
        tv = 1.0;
    }
    *out_score = tv;
    return ANTS_OK;
}

/* ======================================================================== */
/* 4. The serving runtime                                                   */
/* ======================================================================== */

/* ---- the v0.x reference model (DRAFT weight-blob format) ---------------- */
/*
 * The reference model is the small canonical next-token predictor described
 * in ants_inference.h "The v0.x reference model". Its weight blob is, in
 * little-endian byte order:
 *
 *   [0  .. 8)   magic            "ANTSMOD1"
 *   [8  .. 12)  version          (= 1)
 *   [12 .. 16)  vocab V          (1 .. ANTS_INFERENCE_REF_VOCAB_MAX)
 *   [16 .. 20)  d_model D        (1 .. ANTS_INFERENCE_REF_DMODEL_MAX)
 *   [20 .. )    FP32 tensors, row-major, in this order:
 *                 E  [V x D]   token embedding
 *                 Wq [D x D]   query projection
 *                 Wk [D x D]   key projection
 *                 Wv [D x D]   value projection
 *                 Wo [D x D]   attention output projection
 *                 U  [D x V]   unembedding (hidden -> logits)
 *
 * Tensor floats are native little-endian FP32. The blob base must be 4-byte
 * aligned (init enforces it) so the kernels read well-aligned const float*
 * views; the 20-byte header keeps every tensor 4-aligned. DRAFT pending an
 * RFC-0009 reference-model appendix.
 */
#define ANTS_INFERENCE_MODEL_HEADER_LEN 20u
#define ANTS_INFERENCE_MODEL_VERSION    1u
static const uint8_t ANTS_INFERENCE_MODEL_MAGIC[8] = {'A', 'N', 'T', 'S', 'M', 'O', 'D', '1'};

/* Little-endian 4-byte read of a u32 from the blob header. */
static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Canonical forward pass over a token prefix, producing the FP32 logit vector
 * (length vocab) for the next position. Built entirely on the #12 kernels —
 * strict-left-to-right matmul, the pinned causal attention recipe — so two
 * honest peers compute byte-identical logits for the same prefix and weights.
 *
 *   X  = embed[token_i]                         (lookup, [T x D])
 *   Q  = X * Wq,  K = X * Wk,  V = X * Wv        (FP32 matmul, [T x D])
 *   A  = causal_attention(Q, K, V)              (single head, d_head = D)
 *   h  = A[T-1] * Wo + X[T-1]                    (last-position proj + residual)
 *   logits = h * U                               ([1 x D]*[D x V] -> [1 x V])
 *
 * T (= n_tokens) must be in [1, REF_SEQLEN_MAX]; `out_logits` holds vocab
 * floats. Writes the ctx scratch arena (caller guarantees it is the live ctx).
 */
static ants_error_t
forward_logits(struct ants_inference_state *st, const uint32_t *tokens, size_t T, float *out_logits)
{
    const size_t D = st->d_model;
    const size_t V = st->vocab;
    float *X = st->scratch;
    float *Q = X + T * D;
    float *K = Q + T * D;
    float *Vv = K + T * D;
    float *A = Vv + T * D;
    float *att = A + T * D; /* [T x T] attention-scores scratch */
    float hbuf[ANTS_INFERENCE_REF_DMODEL_MAX];
    ants_error_t rc;
    size_t i, d;

    /* 1. token-embedding lookup */
    for (i = 0; i < T; i++) {
        memcpy(X + i * D, st->embed + (size_t)tokens[i] * D, D * sizeof(float));
    }

    /* 2. Q, K, V projections (canonical FP32 matmul, strict left-to-right) */
    rc = ants_canon_matmul_fp32(X, st->w_q, Q, T, D, D);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_canon_matmul_fp32(X, st->w_k, K, T, D, D);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_canon_matmul_fp32(X, st->w_v, Vv, T, D, D);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* 3. single-head causal scaled-dot-product attention (d_head = D) */
    rc = ants_canon_attention_fp32(Q, K, Vv, A, T, D, true, att, T * T);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* 4. output projection of the last position + residual: h = A[T-1]*Wo + X[T-1] */
    rc = ants_canon_matmul_fp32(A + (T - 1) * D, st->w_o, hbuf, 1, D, D);
    if (rc != ANTS_OK) {
        return rc;
    }
    for (d = 0; d < D; d++) {
        hbuf[d] += X[(T - 1) * D + d];
    }

    /* 5. unembedding: logits = h * U */
    return ants_canon_matmul_fp32(hbuf, st->unembed, out_logits, 1, D, V);
}

ants_error_t ants_inference_init(ants_inference_t *ctx, const ants_inference_config_t *config)
{
    const uint8_t *blob;
    size_t len;
    uint32_t v_vocab;
    uint32_t v_dmodel;
    size_t n_floats;
    size_t expected;
    const float *t;
    struct ants_inference_state *st;
    ants_error_t rc;

    if (ctx == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (config->model_weights == NULL || config->model_weights_len == 0 ||
        config->producer_priv == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    blob = config->model_weights;
    len = config->model_weights_len;

    /* The blob base must be 4-byte aligned so the FP32 tensor views are
     * well-aligned for the canonical kernels (they index const float*). */
    if (((uintptr_t)blob & 3u) != 0u) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Parse + validate the DRAFT header. */
    if (len < ANTS_INFERENCE_MODEL_HEADER_LEN) {
        return ANTS_ERROR_MALFORMED;
    }
    if (memcmp(blob, ANTS_INFERENCE_MODEL_MAGIC, sizeof ANTS_INFERENCE_MODEL_MAGIC) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    if (read_le32(blob + 8) != ANTS_INFERENCE_MODEL_VERSION) {
        return ANTS_ERROR_MALFORMED;
    }
    v_vocab = read_le32(blob + 12);
    v_dmodel = read_le32(blob + 16);
    if (v_vocab == 0u || v_vocab > ANTS_INFERENCE_REF_VOCAB_MAX || v_dmodel == 0u ||
        v_dmodel > ANTS_INFERENCE_REF_DMODEL_MAX) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Exact blob length. V, D <= caps, so every product fits well within
     * size_t (max V*D = 512*64 = 32768; the largest term 4*D*D = 16384). */
    n_floats = (size_t)v_vocab * v_dmodel         /* E  */
               + 4u * (size_t)v_dmodel * v_dmodel /* Wq, Wk, Wv, Wo */
               + (size_t)v_dmodel * v_vocab;      /* U  */
    expected = ANTS_INFERENCE_MODEL_HEADER_LEN + n_floats * sizeof(float);
    if (len != expected) {
        return ANTS_ERROR_MALFORMED;
    }

    st = (struct ants_inference_state *)(void *)ctx->_opaque;
    memset(st, 0, sizeof *st);
    st->vocab = v_vocab;
    st->d_model = v_dmodel;

    /* Bind the FP32 tensor views (offsets are 4-aligned: header is 20 bytes,
     * blob base is 4-aligned). */
    t = (const float *)(const void *)(blob + ANTS_INFERENCE_MODEL_HEADER_LEN);
    st->embed = t;
    t += (size_t)v_vocab * v_dmodel;
    st->w_q = t;
    t += (size_t)v_dmodel * v_dmodel;
    st->w_k = t;
    t += (size_t)v_dmodel * v_dmodel;
    st->w_v = t;
    t += (size_t)v_dmodel * v_dmodel;
    st->w_o = t;
    t += (size_t)v_dmodel * v_dmodel;
    st->unembed = t;

    /* Bind H(M) and the producer public key. On any failure leave the ctx
     * uninitialized-looking (magic stays 0). */
    rc = ants_blake3_hash(blob, len, st->model_hash);
    if (rc != ANTS_OK) {
        memset(st, 0, sizeof *st);
        return rc;
    }
    rc = ants_ed25519_pubkey_from_priv(config->producer_priv, st->producer_pub);
    if (rc != ANTS_OK) {
        memset(st, 0, sizeof *st);
        return rc;
    }

    st->magic = ANTS_INFERENCE_STATE_MAGIC;
    return ANTS_OK;
}

ants_error_t ants_inference_destroy(ants_inference_t *ctx)
{
    if (ctx == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Safe on a zeroed (never-initialized) context: clear and return OK,
     * mirroring the embedding component. Once init populates real state
     * this releases it. */
    struct ants_inference_state *st = (struct ants_inference_state *)(void *)ctx->_opaque;
    if (st->magic == ANTS_INFERENCE_STATE_MAGIC) {
        memset(ctx->_opaque, 0, sizeof ctx->_opaque);
    }
    return ANTS_OK;
}

ants_error_t ants_inference_serve(ants_inference_t *ctx,
                                  const ants_inference_request_t *req,
                                  ants_inference_response_t *resp)
{
    if (ctx == NULL || req == NULL || resp == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (req->input == NULL || req->input_len == 0 || resp->answer_buf == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (req->tier != ANTS_INFERENCE_TIER_1 && req->tier != ANTS_INFERENCE_TIER_2 &&
        req->tier != ANTS_INFERENCE_TIER_3) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_inference_reference_distribution(ants_inference_t *ctx,
                                                   const uint8_t *prefix,
                                                   size_t prefix_len,
                                                   uint64_t position,
                                                   ants_canon_q24_t *out_dist,
                                                   size_t out_dist_cap,
                                                   size_t *out_vocab)
{
    struct ants_inference_state *st;
    uint32_t tokens[ANTS_INFERENCE_REF_SEQLEN_MAX];
    float logits[ANTS_INFERENCE_REF_VOCAB_MAX];
    ants_error_t rc;
    size_t i;

    (void)position; /* reference model is position-agnostic (see header) */

    if (ctx == NULL || prefix == NULL || out_dist == NULL || out_vocab == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    st = (struct ants_inference_state *)(void *)ctx->_opaque;
    if (st->magic != ANTS_INFERENCE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (prefix_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (prefix_len > ANTS_INFERENCE_REF_SEQLEN_MAX) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (out_dist_cap < st->vocab) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Byte vocabulary: token id = input byte mod vocab (deterministic for any
     * admissible vocab; bytes are 0..255). */
    for (i = 0; i < prefix_len; i++) {
        tokens[i] = (uint32_t)prefix[i] % st->vocab;
    }

    rc = forward_logits(st, tokens, prefix_len, logits);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* Quantize the FP32 logits to canonical q24 (the committed leaf form). */
    rc = ants_canon_q24_vec_from_f32(logits, out_dist, st->vocab);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_vocab = st->vocab;
    return ANTS_OK;
}

ants_error_t ants_inference_audit(const ants_inference_commit_t *commit,
                                  const uint8_t *answer_buf,
                                  size_t answer_len,
                                  const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                  ants_inference_reference_fn ref_fn,
                                  void *ref_user,
                                  const ants_inference_eprocess_t *eprocess_params,
                                  ants_inference_verdict_t *out_verdict)
{
    (void)ref_user;
    if (commit == NULL || answer_buf == NULL || answer_len == 0 || beacon == NULL ||
        ref_fn == NULL || eprocess_params == NULL || out_verdict == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ======================================================================== */
/* Test-only hooks                                                          */
/*                                                                          */
/* Non-static so the test binary can reach them; forward-declared just below */
/* to satisfy -Wmissing-prototypes (the convention reputation/crdt and       */
/* network/dht use for their __test_ hooks). Not part of the public API.     */
/* ======================================================================== */

ants_error_t ants_inference__test_get_identity(const ants_inference_t *ctx,
                                               uint8_t out_model_hash[ANTS_INFERENCE_HASH_SIZE],
                                               uint8_t out_pub[ANTS_INFERENCE_PUBKEY_SIZE]);

/* Copy out the bound model hash + producer public key so the test can
 * cross-check init against an independent BLAKE3 + Ed25519 derive. */
ants_error_t ants_inference__test_get_identity(const ants_inference_t *ctx,
                                               uint8_t out_model_hash[ANTS_INFERENCE_HASH_SIZE],
                                               uint8_t out_pub[ANTS_INFERENCE_PUBKEY_SIZE])
{
    const struct ants_inference_state *st;
    if (ctx == NULL || out_model_hash == NULL || out_pub == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    st = (const struct ants_inference_state *)(const void *)ctx->_opaque;
    if (st->magic != ANTS_INFERENCE_STATE_MAGIC) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memcpy(out_model_hash, st->model_hash, ANTS_INFERENCE_HASH_SIZE);
    memcpy(out_pub, st->producer_pub, ANTS_INFERENCE_PUBKEY_SIZE);
    return ANTS_OK;
}
