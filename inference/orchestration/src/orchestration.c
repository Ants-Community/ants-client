/*
 * orchestration.c — Inference orchestration (Component #13).
 *
 * Per RFC-0003 v0.2 + RFC-0009 v0.5. Surface 1 (commit-at-send) is
 * implemented here; surfaces 2–4 are still stubs that validate their
 * arguments and return ANTS_ERROR_NOT_IMPLEMENTED, replaced by their
 * implementation PRs in turn:
 *
 *   1. Commit-at-send  — leaf hash, Merkle root/prove/verify, commit
 *                        encode/decode, Ed25519 sign/verify. IMPLEMENTED.
 *   2. Challenge       — the three beacon-bound PRF derivations.
 *   3. e-process       — init/update + discrepancy scoring.
 *   4. Serving runtime — init/destroy/serve + the audit capstone, once
 *                        the kernels/embedding/identity composition and a
 *                        model loader exist.
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
    /* Populated when init/serve gain real logic: the loaded model's hash
     * (bound into every commit) and the producer public key derived from
     * the configured private key. */
    uint8_t model_hash[ANTS_INFERENCE_HASH_SIZE];
    uint8_t producer_pub[ANTS_INFERENCE_PUBKEY_SIZE];
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

ants_error_t
ants_inference_challenge_is_audited(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                    const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                    uint64_t audit_threshold,
                                    bool *out_audited)
{
    (void)audit_threshold;
    if (beacon == NULL || root == NULL || out_audited == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_inference_challenge_positions(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                                const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                                uint32_t m,
                                                uint32_t length,
                                                uint64_t *out_positions,
                                                size_t cap,
                                                size_t *out_count)
{
    (void)cap;
    if (beacon == NULL || root == NULL || m == 0 || length == 0 || out_positions == NULL ||
        out_count == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_inference_challenge_auditor(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                              const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                              uint64_t n_verifiers,
                                              uint64_t *out_index)
{
    if (beacon == NULL || root == NULL || n_verifiers == 0 || out_index == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
    if (!(alpha > 0.0 && alpha < 1.0) || !(mu0 >= 0.0 && mu0 < 1.0) || lambda_cap < 0.0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_inference_eprocess_update(ants_inference_eprocess_t *ep,
                                            double score,
                                            ants_inference_verdict_t *out_verdict)
{
    if (ep == NULL || out_verdict == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!(score >= 0.0 && score <= 1.0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_inference_discrepancy(const ants_canon_q24_t *p_ref,
                                        const ants_canon_q24_t *q_committed,
                                        size_t vocab,
                                        double *out_score)
{
    if (p_ref == NULL || q_committed == NULL || vocab == 0 || out_score == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ======================================================================== */
/* 4. The serving runtime                                                   */
/* ======================================================================== */

ants_error_t ants_inference_init(ants_inference_t *ctx, const ants_inference_config_t *config)
{
    if (ctx == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (config->model_weights == NULL || config->model_weights_len == 0 ||
        config->producer_priv == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
