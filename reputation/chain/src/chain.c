/*
 * chain.c — Layer 2: the PoUH chain as ordered witness (Component #8,
 * RFC-0004 v0.6 §"Layer 2 — the PoUH chain as ordered witness").
 *
 * Component #8 is feature-complete at the v0.x level:
 *   - the confirmed_proofs Merkle root + inclusion proof, and the
 *     EpochSummary + Block canonical-CBOR codecs;
 *   - the pattern-rule engine (L1 events -> severity findings per window);
 *   - VRF committee selection (deterministic, beacon-seeded, distinct);
 *   - block hashing + 2/3 finality over Ed25519 committee signatures;
 *   - Sigma T_eff fork choice + the social-Schelling fallback (partition
 *     recovery), reusing reputation/identity's saturating T_eff transform;
 *   - drand beacon verification + VRF seed derivation (live and degraded);
 *   - block proposal (the pure mempool->block step; the "mempool" IS the
 *     visible L1 CRDT at the cutoff) + round-robin proposer election.
 * Pure functions over bytes — no I/O, no malloc, no threads, and no floats
 * on any path a second peer must reproduce (determinism is load-bearing).
 *
 * The confirmed_proofs Merkle construction mirrors inference/orchestration's
 * commit Merkle exactly (domain-separated leaf/node, promote-lone-trailing,
 * online MMR build with an O(log n) bounded stack), so the two corpora share
 * one canonical scheme. The only chain-specific differences: leaves are the
 * 32-byte L1 proof content-ids (leaf = BLAKE3(0x00 ‖ content_id)), the
 * caller passes them STRICTLY ASCENDING (the canonical order that makes the
 * root reproducible across peers regardless of G-Set iteration order), and a
 * zero-proof epoch has a defined empty root BLAKE3(0x02).
 *
 * Spec: RFC-0004 v0.6 §"Layer 2"; RFC-0008 v0.5 §1.1 (canonical CBOR),
 * §2.1 (BLAKE3), §3.1/§3.3 (signatures), §4.2 (ECVRF).
 */

#include "ants_chain.h"

#include "ants_cbor.h"
#include "ants_crypto.h"
#include "ants_reputation.h"

#include <string.h>

/* ------------------------------------------------------------------------ */
/* confirmed_proofs Merkle: domain-separated hashing + bounded MMR build      */
/* ------------------------------------------------------------------------ */

/* Domain separation tags. leaf and node match inference/orchestration's
 * commit Merkle (0x00 / 0x01); 0x02 is the chain's empty-set root, a value
 * that can never collide with a leaf or node hash (different prefix). */
#define CHAIN_MERKLE_LEAF_PREFIX  0x00u
#define CHAIN_MERKLE_NODE_PREFIX  0x01u
#define CHAIN_MERKLE_EMPTY_PREFIX 0x02u

/* leaf(content_id) = BLAKE3(0x00 ‖ content_id). */
static ants_error_t leaf_hash(const uint8_t content_id[ANTS_CHAIN_HASH_SIZE],
                              uint8_t out[ANTS_CHAIN_HASH_SIZE])
{
    const uint8_t prefix = CHAIN_MERKLE_LEAF_PREFIX;
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
    rc = ants_blake3_update(&h, content_id, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out);
}

/* node(L,R) = BLAKE3(0x01 ‖ L ‖ R). `out` may alias `left` or `right`:
 * each input is consumed into the hasher before `final` writes `out`. */
static ants_error_t node_hash(const uint8_t left[ANTS_CHAIN_HASH_SIZE],
                              const uint8_t right[ANTS_CHAIN_HASH_SIZE],
                              uint8_t out[ANTS_CHAIN_HASH_SIZE])
{
    const uint8_t prefix = CHAIN_MERKLE_NODE_PREFIX;
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
    rc = ants_blake3_update(&h, left, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, right, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out);
}

/* The empty-set root, BLAKE3(0x02) — a legitimate zero-proof epoch. */
static ants_error_t empty_root(uint8_t out[ANTS_CHAIN_HASH_SIZE])
{
    const uint8_t prefix = CHAIN_MERKLE_EMPTY_PREFIX;
    return ants_blake3_hash(&prefix, 1, out);
}

/* Merkle root over the content-id range [lo, hi) (requires hi > lo) under
 * the promote-lone-trailing-node level scheme, computed with an O(log n)
 * bounded stack and no allocation (the same online MMR build as
 * inference/orchestration). Leaves are hashed on push: leaf_hash(ids[i]). */
static ants_error_t subtree_root_range(const uint8_t (*ids)[ANTS_CHAIN_HASH_SIZE],
                                       size_t lo,
                                       size_t hi,
                                       uint8_t out[ANTS_CHAIN_HASH_SIZE])
{
    uint8_t stack[ANTS_CHAIN_MERKLE_MAX_DEPTH + 2][ANTS_CHAIN_HASH_SIZE];
    int height[ANTS_CHAIN_MERKLE_MAX_DEPTH + 2];
    int top = 0;
    ants_error_t rc;
    size_t i;
    int k;

    for (i = lo; i < hi; i++) {
        rc = leaf_hash(ids[i], stack[top]);
        if (rc != ANTS_OK) {
            return rc;
        }
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

    /* Bag the leftover peaks right-to-left: the accumulator is the rightmost
     * (smallest) peak at stack[top - 1]; each peak to its left folds in as
     * the left child, reproducing the lone-trailing-node promotion. */
    for (k = top - 2; k >= 0; k--) {
        rc = node_hash(stack[k], stack[top - 1], stack[top - 1]);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    memcpy(out, stack[top - 1], ANTS_CHAIN_HASH_SIZE);
    return ANTS_OK;
}

/* Number of sibling hashes on the path from leaf `index` to the root in a
 * promote-lone-node tree of `n_leaves` (identical to the inference scheme). */
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

/* True iff the n content-ids are strictly ascending (the canonical order).
 * Strict ascent also rules out duplicates, which a set satisfies. */
static bool ids_strictly_ascending(const uint8_t (*ids)[ANTS_CHAIN_HASH_SIZE], size_t n)
{
    size_t i;
    for (i = 1; i < n; i++) {
        if (memcmp(ids[i - 1], ids[i], ANTS_CHAIN_HASH_SIZE) >= 0) {
            return false;
        }
    }
    return true;
}

/* n exceeding 2^MAX_DEPTH would overflow the bounded MMR stack. */
static bool n_leaves_in_range(size_t n)
{
#if SIZE_MAX > 0xFFFFFFFFu
    return (uint64_t)n <= ((uint64_t)1 << ANTS_CHAIN_MERKLE_MAX_DEPTH);
#else
    (void)n;
    return true; /* size_t can't exceed 2^32 == 2^MAX_DEPTH here */
#endif
}

ants_error_t ants_chain_confirmed_root(const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                       size_t n,
                                       uint8_t out_root[ANTS_CHAIN_HASH_SIZE])
{
    if (out_root == NULL || (content_ids == NULL && n != 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n == 0) {
        return empty_root(out_root);
    }
    if (!n_leaves_in_range(n)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!ids_strictly_ascending(content_ids, n)) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return subtree_root_range(content_ids, 0, n, out_root);
}

ants_error_t ants_chain_confirmed_prove(const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                        size_t n,
                                        size_t index,
                                        uint8_t *out_path,
                                        size_t path_cap,
                                        size_t *out_path_len)
{
    size_t need_bytes;
    size_t written = 0;
    size_t idx;
    size_t count;
    int level = 0;
    ants_error_t rc;

    if (content_ids == NULL || n == 0 || index >= n || out_path == NULL || out_path_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!n_leaves_in_range(n)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!ids_strictly_ascending(content_ids, n)) {
        return ANTS_ERROR_NON_CANONICAL;
    }

    need_bytes = merkle_path_len(index, n) * ANTS_CHAIN_HASH_SIZE;
    if (need_bytes > path_cap) {
        *out_path_len = need_bytes;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    idx = index;
    count = n;
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
            if (hi64 > (uint64_t)n) {
                hi64 = (uint64_t)n;
            }
            rc = subtree_root_range(
                content_ids, (size_t)lo64, (size_t)hi64, out_path + written * ANTS_CHAIN_HASH_SIZE);
            if (rc != ANTS_OK) {
                return rc;
            }
            written++;
        }
        idx /= 2;
        count = (count + 1) / 2;
        level++;
    }

    *out_path_len = written * ANTS_CHAIN_HASH_SIZE;
    return ANTS_OK;
}

ants_error_t ants_chain_confirmed_verify(const uint8_t leaf_content_id[ANTS_CHAIN_HASH_SIZE],
                                         size_t index,
                                         size_t n,
                                         const uint8_t *path,
                                         size_t path_len,
                                         const uint8_t root[ANTS_CHAIN_HASH_SIZE],
                                         bool *out_ok)
{
    uint8_t cur[ANTS_CHAIN_HASH_SIZE];
    size_t consumed = 0;
    size_t idx;
    size_t count;
    ants_error_t rc;

    if (leaf_content_id == NULL || n == 0 || index >= n || path == NULL || root == NULL ||
        out_ok == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!n_leaves_in_range(n)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (path_len != merkle_path_len(index, n) * ANTS_CHAIN_HASH_SIZE) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = leaf_hash(leaf_content_id, cur);
    if (rc != ANTS_OK) {
        return rc;
    }

    idx = index;
    count = n;
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
            const uint8_t *sib = path + consumed * ANTS_CHAIN_HASH_SIZE;
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

    *out_ok = (consumed * ANTS_CHAIN_HASH_SIZE == path_len) &&
              (memcmp(cur, root, ANTS_CHAIN_HASH_SIZE) == 0);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* EpochSummary canonical-CBOR codec                                          */
/*                                                                            */
/* A definite-length, float-free map(4) with ascending integer keys; the     */
/* findings ride in key 4 as an array of fixed-shape map(5)s. Formalised in   */
/* RFC-0008 v0.6 §11.6 "Layer-2 chain objects".                               */
/*                                                                            */
/*   summary  1:epoch(u) 2:cutoff_time(u) 3:confirmed_proofs(bytes32)         */
/*            4:findings(array of map(5))                                     */
/*   finding  1:subject(bytes32) 2:rule_id(u) 3:window_s(u) 4:count(u)        */
/*            5:severity(u)                                                    */
/* ------------------------------------------------------------------------ */

#define CHAIN_SUMMARY_PAIRS 4u
#define CHAIN_FINDING_PAIRS 5u

enum {
    SUMMARY_KEY_EPOCH = 1,
    SUMMARY_KEY_CUTOFF = 2,
    SUMMARY_KEY_CONFIRMED = 3,
    SUMMARY_KEY_FINDINGS = 4
};

enum {
    FINDING_KEY_SUBJECT = 1,
    FINDING_KEY_RULE = 2,
    FINDING_KEY_WINDOW = 3,
    FINDING_KEY_COUNT = 4,
    FINDING_KEY_SEVERITY = 5
};

static bool severity_valid(uint64_t s)
{
    return s >= ANTS_CHAIN_SEVERITY_SOFT && s < ANTS_CHAIN_SEVERITY__RESERVED_MIN;
}

static ants_error_t enc_kv_uint(ants_cbor_enc_t *enc, uint64_t key, uint64_t val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_uint(enc, val);
}

static ants_error_t enc_kv_bytes(ants_cbor_enc_t *enc, uint64_t key, const uint8_t *b, size_t len)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bytes(enc, b, len);
}

/* Collapse the decoder's full error vocabulary onto the codec contract: a
 * §4.2.1 canonical violation keeps NON_CANONICAL, everything else structural
 * folds to MALFORMED. INVALID_ARG can't occur (the decoder only raises it for
 * NULL, which these paths never pass). Mirrors inference/orchestration. */
static ants_error_t norm_decode_err(ants_error_t rc)
{
    if (rc == ANTS_OK || rc == ANTS_ERROR_NON_CANONICAL) {
        return rc;
    }
    return ANTS_ERROR_MALFORMED;
}

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

static ants_error_t decode_uint_field(ants_cbor_dec_t *dec, uint64_t key, uint64_t *out)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_uint(dec, out));
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

size_t ants_chain_epoch_summary_bound(const ants_chain_epoch_summary_t *s)
{
    if (s == NULL) {
        return 0;
    }
    /* map(4) + two u64 KVs + a 32-byte KV + the findings array header, then
     * each finding map(5) of one 32-byte KV and four u64 KVs. Each u64 KV is
     * <= 1 (key) + 9 (uint) bytes; a 32-byte KV <= 1 + 3 (bytes header) + 32.
     * Rounded up generously to stay a one-shot sizing. */
    return 80u + s->n_findings * 96u;
}

ants_error_t ants_chain_epoch_summary_encode(const ants_chain_epoch_summary_t *s,
                                             uint8_t *buf,
                                             size_t cap,
                                             size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;
    size_t i;

    if (s == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (s->n_findings > ANTS_CHAIN_MAX_PATTERN_FINDINGS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (s->n_findings > 0 && s->findings == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (i = 0; i < s->n_findings; i++) {
        if (!severity_valid(s->findings[i].severity)) {
            return ANTS_ERROR_INVALID_ARG;
        }
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, CHAIN_SUMMARY_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, SUMMARY_KEY_EPOCH, s->epoch);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, SUMMARY_KEY_CUTOFF, s->cutoff_time);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, SUMMARY_KEY_CONFIRMED, s->confirmed_proofs, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_uint(&enc, SUMMARY_KEY_FINDINGS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_array(&enc, s->n_findings);
    if (rc != ANTS_OK) {
        return rc;
    }
    for (i = 0; i < s->n_findings; i++) {
        const ants_chain_pattern_finding_t *f = &s->findings[i];
        rc = ants_cbor_enc_map(&enc, CHAIN_FINDING_PAIRS);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = enc_kv_bytes(&enc, FINDING_KEY_SUBJECT, f->subject, ANTS_CHAIN_PEER_ID_SIZE);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = enc_kv_uint(&enc, FINDING_KEY_RULE, f->rule_id);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = enc_kv_uint(&enc, FINDING_KEY_WINDOW, f->window_s);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = enc_kv_uint(&enc, FINDING_KEY_COUNT, f->count);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = enc_kv_uint(&enc, FINDING_KEY_SEVERITY, f->severity);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }

    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_chain_epoch_summary_decode(const uint8_t *buf,
                                             size_t len,
                                             ants_chain_epoch_summary_t *out_summary,
                                             ants_chain_pattern_finding_t *findings_buf,
                                             size_t findings_cap,
                                             size_t *out_n_findings)
{
    ants_cbor_dec_t dec;
    size_t n_pairs;
    size_t n_findings;
    uint64_t u;
    ants_error_t rc;
    size_t i;

    if (buf == NULL || len == 0 || out_summary == NULL || out_n_findings == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_dec_init(&dec, buf, len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != CHAIN_SUMMARY_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }

    rc = decode_uint_field(&dec, SUMMARY_KEY_EPOCH, &out_summary->epoch);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, SUMMARY_KEY_CUTOFF, &out_summary->cutoff_time);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(
        &dec, SUMMARY_KEY_CONFIRMED, out_summary->confirmed_proofs, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = expect_key(&dec, SUMMARY_KEY_FINDINGS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_array(&dec, &n_findings));
    if (rc != ANTS_OK) {
        return rc;
    }

    *out_n_findings = n_findings;
    if (n_findings > findings_cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < n_findings; i++) {
        ants_chain_pattern_finding_t *f = &findings_buf[i];
        rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
        if (rc != ANTS_OK) {
            return rc;
        }
        if (n_pairs != CHAIN_FINDING_PAIRS) {
            return ANTS_ERROR_MALFORMED;
        }
        rc = decode_bytes_field(&dec, FINDING_KEY_SUBJECT, f->subject, ANTS_CHAIN_PEER_ID_SIZE);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = decode_uint_field(&dec, FINDING_KEY_RULE, &f->rule_id);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = decode_uint_field(&dec, FINDING_KEY_WINDOW, &f->window_s);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = decode_uint_field(&dec, FINDING_KEY_COUNT, &f->count);
        if (rc != ANTS_OK) {
            return rc;
        }
        rc = decode_uint_field(&dec, FINDING_KEY_SEVERITY, &u);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (!severity_valid(u)) {
            return ANTS_ERROR_UNSUPPORTED_TYPE;
        }
        f->severity = (uint32_t)u;
    }

    rc = norm_decode_err(ants_cbor_dec_finalise(&dec));
    if (rc != ANTS_OK) {
        return rc;
    }

    out_summary->findings = findings_buf;
    out_summary->n_findings = n_findings;
    return ANTS_OK;
}

/* ======================================================================== */
/* PR3 — the pattern-rule engine                                             */
/* ======================================================================== */

/* The §Slash-mechanics escalation band for a within-window event count
 * (count >= 1 guaranteed by the caller). */
static uint32_t severity_for_count(uint64_t count)
{
    if (count >= ANTS_CHAIN_PATTERN_HARD_MIN_EVENTS) {
        return ANTS_CHAIN_SEVERITY_HARD;
    }
    if (count >= ANTS_CHAIN_PATTERN_MEDIUM_MIN_EVENTS) {
        return ANTS_CHAIN_SEVERITY_MEDIUM;
    }
    return ANTS_CHAIN_SEVERITY_SOFT;
}

/* An event falls in the (now - WINDOW, now] counting window. Future events
 * (timestamp > now) and events at or older than the window are excluded. */
static bool event_in_window(const ants_chain_event_t *e, uint64_t now)
{
    return e->timestamp <= now && (now - e->timestamp) < ANTS_CHAIN_PATTERN_WINDOW_S;
}

ants_error_t ants_chain_pattern_scan(const ants_chain_event_t *events,
                                     size_t n_events,
                                     uint64_t now,
                                     ants_chain_pattern_finding_t *out_findings,
                                     size_t cap,
                                     size_t *out_n)
{
    size_t total = 0;
    size_t i;
    size_t j;

    if (out_n == NULL || (events == NULL && n_events != 0) || (out_findings == NULL && cap != 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }

    for (i = 0; i < n_events; i++) {
        bool first = true;
        uint64_t count = 0;

        /* Act only on the first occurrence of each subject (one finding per
         * subject), so the result does not depend on duplicate listing. */
        for (j = 0; j < i; j++) {
            if (memcmp(events[j].subject, events[i].subject, ANTS_CHAIN_PEER_ID_SIZE) == 0) {
                first = false;
                break;
            }
        }
        if (!first) {
            continue;
        }

        for (j = 0; j < n_events; j++) {
            if (memcmp(events[j].subject, events[i].subject, ANTS_CHAIN_PEER_ID_SIZE) == 0 &&
                event_in_window(&events[j], now)) {
                count++;
            }
        }
        if (count < ANTS_CHAIN_PATTERN_SOFT_MIN_EVENTS) {
            continue; /* no in-window events for this subject */
        }

        if (total < cap) {
            ants_chain_pattern_finding_t *f = &out_findings[total];
            memcpy(f->subject, events[i].subject, ANTS_CHAIN_PEER_ID_SIZE);
            f->rule_id = ANTS_CHAIN_RULE_FAULT_COUNT_30D;
            f->window_s = ANTS_CHAIN_PATTERN_WINDOW_S;
            f->count = count;
            f->severity = severity_for_count(count);
        }
        total++;
    }

    *out_n = total;
    if (total > cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Canonicalise the emitted findings by subject ascending, so re-running
     * the rules over the same event SET yields byte-identical output
     * regardless of the order the events were listed in. Insertion sort over
     * the <= cap findings actually written (total <= cap here). */
    for (i = 1; i < total; i++) {
        ants_chain_pattern_finding_t key = out_findings[i];
        j = i;
        while (j > 0 &&
               memcmp(out_findings[j - 1].subject, key.subject, ANTS_CHAIN_PEER_ID_SIZE) > 0) {
            out_findings[j] = out_findings[j - 1];
            j--;
        }
        out_findings[j] = key;
    }

    return ANTS_OK;
}

/* ======================================================================== */
/* PR4 — VRF committee selection                                             */
/* ======================================================================== */

/* The committee for a block is a deterministic, publicly-recomputable
 * k-subset of the attested population, drawn from a beacon released AFTER
 * the previous block (so it is unpredictable and non-grindable at proposal
 * time) keyed together with the previous block hash. Every peer derives the
 * same committee, and selection uses unbiased rejection sampling (the
 * arc4random_uniform trick, as in inference/orchestration's auditor draw)
 * inside Floyd's algorithm for distinct sampling — O(k) space, no
 * population-sized array, no float, no malloc. (Per-peer ECVRF sortition
 * proof — a peer proving its own membership — is a later refinement; the
 * committee SET derived here is the canonical reference.) */

static void write_le64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static uint64_t read_be64(const uint8_t b[8])
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

/* The next 64-bit keystream word: BLAKE3(prev ‖ beacon ‖ "cmte" ‖ LE64(ctr))
 * read big-endian over the first 8 digest bytes; `ctr` increments per word. */
static ants_error_t committee_draw_word(const uint8_t prev[ANTS_CHAIN_HASH_SIZE],
                                        const uint8_t beacon[ANTS_CHAIN_HASH_SIZE],
                                        uint64_t *ctr,
                                        uint64_t *out_w)
{
    static const uint8_t tag[4] = {'c', 'm', 't', 'e'};
    uint8_t le[8];
    uint8_t digest[ANTS_CHAIN_HASH_SIZE];
    ants_blake3_ctx_t h;
    ants_error_t rc;

    write_le64(le, (*ctr)++);
    rc = ants_blake3_init(&h);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, prev, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, beacon, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, tag, sizeof tag);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, le, sizeof le);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_final(&h, digest);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_w = read_be64(digest);
    return ANTS_OK;
}

/* An unbiased uniform draw in [0, bound) (bound >= 1): reject the low
 * `2^64 mod bound` band, then take the remainder. */
static ants_error_t committee_uniform(const uint8_t prev[ANTS_CHAIN_HASH_SIZE],
                                      const uint8_t beacon[ANTS_CHAIN_HASH_SIZE],
                                      uint64_t *ctr,
                                      uint64_t bound,
                                      uint64_t *out)
{
    uint64_t min = ((uint64_t)0 - bound) % bound; /* == 2^64 mod bound */
    uint64_t w;
    ants_error_t rc;

    for (;;) {
        rc = committee_draw_word(prev, beacon, ctr, &w);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (w >= min) {
            *out = w % bound;
            return ANTS_OK;
        }
    }
}

ants_error_t ants_chain_committee_select(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                         const uint8_t beacon[ANTS_CHAIN_HASH_SIZE],
                                         size_t population_size,
                                         size_t k,
                                         size_t *out_indices,
                                         size_t cap,
                                         size_t *out_n)
{
    uint64_t ctr = 0;
    size_t s;
    size_t m;
    ants_error_t rc;

    if (prev_block_hash == NULL || beacon == NULL || out_indices == NULL || out_n == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (k == 0 || k > population_size) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (cap < k) {
        *out_n = k;
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Floyd's distinct-sampling: for j = N-k .. N-1, draw t in [0, j]; take t
     * if unused, else j (always fresh — j strictly grows past every earlier
     * candidate). Produces exactly k distinct indices in [0, N). */
    for (s = 0; s < k; s++) {
        size_t j = population_size - k + s;
        uint64_t t;
        bool found = false;

        rc = committee_uniform(prev_block_hash, beacon, &ctr, (uint64_t)j + 1, &t);
        if (rc != ANTS_OK) {
            return rc;
        }
        for (m = 0; m < s; m++) {
            if (out_indices[m] == (size_t)t) {
                found = true;
                break;
            }
        }
        out_indices[s] = found ? j : (size_t)t;
    }

    /* Canonicalise the committee as an ascending index list (insertion sort,
     * k <= K_MAX = 64), so the set has one byte representation. */
    for (s = 1; s < k; s++) {
        size_t key = out_indices[s];
        m = s;
        while (m > 0 && out_indices[m - 1] > key) {
            out_indices[m] = out_indices[m - 1];
            m--;
        }
        out_indices[m] = key;
    }

    *out_n = k;
    return ANTS_OK;
}

/* ======================================================================== */
/* PR5 — block hashing + encoding (finality_verify below remains a stub)     */
/* ======================================================================== */

/* A block is canonical CBOR map(4): {1: height, 2: prev_block_hash(32),
 * 3: degraded_seed(bool), 4: summary}. The epoch summary rides as a
 * byte-string holding its own complete canonical encoding — the same "embed
 * a sub-document as bytes" shape reputation/crdt uses for signed statement
 * bodies — so the block codec composes ants_chain_epoch_summary_{encode,
 * decode} without duplicating the summary wire format. degraded_seed sits
 * inside the signed bytes on purpose: the committee attests to the drand
 * outage claim, not just to the summary (RFC-0008 §4.3). */
#define CHAIN_BLOCK_PAIRS 4u

enum { BLOCK_KEY_HEIGHT = 1, BLOCK_KEY_PREV = 2, BLOCK_KEY_DEGRADED = 3, BLOCK_KEY_SUMMARY = 4 };

size_t ants_chain_block_bound(const ants_chain_block_t *b)
{
    if (b == NULL) {
        return 0;
    }
    /* map(3) + height KV + prev-hash KV + summary byte-string header, then
     * the embedded summary encoding. */
    return 64u + ants_chain_epoch_summary_bound(&b->summary);
}

ants_error_t
ants_chain_block_encode(const ants_chain_block_t *b, uint8_t *buf, size_t cap, size_t *out_len)
{
    uint8_t sbuf[ANTS_CHAIN_EPOCH_SUMMARY_ENCODED_MAX];
    ants_cbor_enc_t enc;
    size_t slen;
    ants_error_t rc;

    if (b == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Encode the summary to its own canonical doc first (this also validates
     * the summary — findings count + severities). */
    rc = ants_chain_epoch_summary_encode(&b->summary, sbuf, sizeof sbuf, &slen);
    if (rc != ANTS_OK) {
        return rc;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, CHAIN_BLOCK_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, BLOCK_KEY_HEIGHT, b->height);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, BLOCK_KEY_PREV, b->prev_block_hash, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_uint(&enc, BLOCK_KEY_DEGRADED);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_bool(&enc, b->degraded_seed);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_uint(&enc, BLOCK_KEY_SUMMARY);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_bytes(&enc, sbuf, slen);
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

ants_error_t ants_chain_block_hash(const ants_chain_block_t *b,
                                   uint8_t out_hash[ANTS_CHAIN_HASH_SIZE])
{
    uint8_t buf[ANTS_CHAIN_BLOCK_ENCODED_MAX];
    size_t len;
    ants_error_t rc;

    if (b == NULL || out_hash == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    rc = ants_chain_block_encode(b, buf, sizeof buf, &len);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_hash(buf, len, out_hash);
}

ants_error_t ants_chain_block_decode(const uint8_t *buf,
                                     size_t len,
                                     ants_chain_block_t *out_block,
                                     ants_chain_pattern_finding_t *findings_buf,
                                     size_t findings_cap,
                                     size_t *out_n_findings)
{
    ants_cbor_dec_t dec;
    const uint8_t *sp;
    size_t slen;
    size_t n_pairs;
    ants_error_t rc;

    if (buf == NULL || len == 0 || out_block == NULL || out_n_findings == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_dec_init(&dec, buf, len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != CHAIN_BLOCK_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    rc = decode_uint_field(&dec, BLOCK_KEY_HEIGHT, &out_block->height);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, BLOCK_KEY_PREV, out_block->prev_block_hash, ANTS_CHAIN_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = expect_key(&dec, BLOCK_KEY_DEGRADED);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_bool(&dec, &out_block->degraded_seed));
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = expect_key(&dec, BLOCK_KEY_SUMMARY);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_bytes(&dec, &sp, &slen));
    if (rc != ANTS_OK) {
        return rc;
    }

    /* Decode the embedded summary doc (validates it fully, including its own
     * no-trailing-bytes check). A probe (findings_cap 0) propagates
     * BUFFER_TOO_SMALL with *out_n_findings set. */
    rc = ants_chain_epoch_summary_decode(
        sp, slen, &out_block->summary, findings_buf, findings_cap, out_n_findings);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* No trailing bytes after the block map. */
    return norm_decode_err(ants_cbor_dec_finalise(&dec));
}

ants_error_t ants_chain_finality_verify(const uint8_t block_hash[ANTS_CHAIN_HASH_SIZE],
                                        const uint8_t (*committee_pubkeys)[ANTS_CHAIN_PEER_ID_SIZE],
                                        size_t k,
                                        const uint8_t *attestations,
                                        size_t attestations_len,
                                        const bool *signed_mask,
                                        bool *out_final)
{
    size_t n_signers = 0;
    size_t valid = 0;
    size_t threshold;
    size_t sig_idx = 0;
    size_t i;

    if (block_hash == NULL || committee_pubkeys == NULL || signed_mask == NULL ||
        out_final == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (k == 0 || k > ANTS_CHAIN_COMMITTEE_K_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* The attestation buffer is one Ed25519 signature per SIGNER (the
     * committee members with signed_mask set), packed in ascending member
     * order — so its length pins the signer count. */
    for (i = 0; i < k; i++) {
        if (signed_mask[i]) {
            n_signers++;
        }
    }
    if (attestations_len != n_signers * ANTS_CHAIN_SIG_SIZE) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_signers > 0 && attestations == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* 2/3 finality: at least ceil(FINALITY_NUM * k / FINALITY_DEN) valid. */
    threshold =
        (ANTS_CHAIN_FINALITY_NUM * k + (ANTS_CHAIN_FINALITY_DEN - 1)) / ANTS_CHAIN_FINALITY_DEN;

    for (i = 0; i < k; i++) {
        if (!signed_mask[i]) {
            continue;
        }
        if (ants_ed25519_verify(committee_pubkeys[i],
                                block_hash,
                                ANTS_CHAIN_HASH_SIZE,
                                attestations + sig_idx * ANTS_CHAIN_SIG_SIZE) == ANTS_OK) {
            valid++;
        }
        sig_idx++;
    }

    /* A signature shortfall or any invalid signature is a false verdict, not
     * an error. */
    *out_final = (valid >= threshold);
    return ANTS_OK;
}

/* ======================================================================== */
/* PR6 — partition recovery: Σ T_eff fork choice                             */
/* ======================================================================== */

ants_error_t ants_chain_fork_weight(const uint64_t *validator_tenures,
                                    size_t n,
                                    uint64_t t_cap,
                                    uint64_t *out_sum_t_eff)
{
    uint64_t sum = 0;
    size_t i;

    if (out_sum_t_eff == NULL || t_cap == 0 || (validator_tenures == NULL && n != 0)) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Σ T_eff over the fork's validators, with the saturating transform
     * applied by reputation/identity verbatim so the two components agree
     * bit-for-bit (the whole point of a shared, float-free t_eff). */
    for (i = 0; i < n; i++) {
        uint64_t te;
        ants_error_t rc = ants_reputation_t_eff(validator_tenures[i], t_cap, &te);
        if (rc != ANTS_OK) {
            return rc;
        }
        if (sum > UINT64_MAX - te) {
            return ANTS_ERROR_OVERFLOW;
        }
        sum += te;
    }

    *out_sum_t_eff = sum;
    return ANTS_OK;
}

ants_error_t ants_chain_fork_choice(uint64_t weight_a,
                                    uint64_t weight_b,
                                    uint64_t total_t_eff,
                                    uint64_t theta_num,
                                    uint64_t theta_den,
                                    int *out_winner)
{
    uint64_t q;
    uint64_t r;
    uint64_t thresh;
    bool a_clears;
    bool b_clears;

    if (out_winner == NULL || theta_den == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (weight_a > total_t_eff || weight_b > total_t_eff) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* thresh = floor(total * theta_num / theta_den), computed without
     * overflow: for a proper fraction theta_num < theta_den the result is
     * <= total <= UINT64_MAX, and q*theta_num <= total, so neither term
     * overflows. */
    q = total_t_eff / theta_den;
    r = total_t_eff % theta_den;
    thresh = q * theta_num + (r * theta_num) / theta_den;

    /* A fork is a legitimate-majority claimant iff its Σ T_eff exceeds θ of
     * the agreed total. If BOTH clear θ the partition is fundamentally
     * balanced → hand to the social layer; otherwise the heavier fork wins
     * (ties break to A, deterministically). */
    a_clears = weight_a > thresh;
    b_clears = weight_b > thresh;
    if (a_clears && b_clears) {
        *out_winner = ANTS_CHAIN_FORK_SOCIAL_SCHELLING;
    } else if (weight_a >= weight_b) {
        *out_winner = ANTS_CHAIN_FORK_A;
    } else {
        *out_winner = ANTS_CHAIN_FORK_B;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* PR7 — drand beacon verification + VRF seed derivation                    */
/* ------------------------------------------------------------------------ */

/* drand's chained payload uses big-endian rounds (read_be64 above reads
 * the same order off keystream digests; this is its write twin, kept
 * local to the beacon path). */
static void write_be64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

ants_error_t ants_chain_beacon_verify(const ants_chain_beacon_t *beacon,
                                      const uint8_t drand_pubkey[ANTS_CHAIN_DRAND_PUBKEY_SIZE],
                                      bool *out_ok)
{
    uint8_t payload[ANTS_CHAIN_DRAND_SIG_SIZE + 8];
    uint8_t digest[ANTS_SHA256_HASH_SIZE];
    ants_error_t err;

    if (beacon == NULL || drand_pubkey == NULL || out_ok == NULL || beacon->round < 2) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out_ok = false;

    /* The chained signing payload: SHA-256(previous_signature ||
     * round_be64). */
    memcpy(payload, beacon->previous_signature, ANTS_CHAIN_DRAND_SIG_SIZE);
    write_be64(payload + ANTS_CHAIN_DRAND_SIG_SIZE, beacon->round);
    err = ants_sha256(payload, sizeof payload, digest);
    if (err != ANTS_OK) {
        return err;
    }

    /* The beacon is untrusted input: a malformed point or a failed
     * pairing is a verdict, not an error. */
    err = ants_bls_verify(drand_pubkey, digest, sizeof digest, beacon->signature);
    if (err == ANTS_ERROR_MALFORMED) {
        return ANTS_OK;
    }
    if (err != ANTS_OK) {
        return err;
    }

    /* The published randomness must be SHA-256(signature). */
    err = ants_sha256(beacon->signature, ANTS_CHAIN_DRAND_SIG_SIZE, digest);
    if (err != ANTS_OK) {
        return err;
    }
    if (memcmp(digest, beacon->randomness, sizeof digest) != 0) {
        return ANTS_OK;
    }

    *out_ok = true;
    return ANTS_OK;
}

/* Shared derivation: key_material = prev_block_hash || height_be64
 * [|| randomness]; the context string separates the live and degraded
 * domains so the two can never collide. */
static ants_error_t vrf_seed_derive(const char *context,
                                    const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                    uint64_t height,
                                    const uint8_t *randomness,
                                    uint8_t out_seed[ANTS_CHAIN_HASH_SIZE])
{
    uint8_t km[ANTS_CHAIN_HASH_SIZE + 8 + ANTS_CHAIN_BEACON_RANDOMNESS_SIZE];
    size_t len = 0;

    memcpy(km + len, prev_block_hash, ANTS_CHAIN_HASH_SIZE);
    len += ANTS_CHAIN_HASH_SIZE;
    write_be64(km + len, height);
    len += 8;
    if (randomness != NULL) {
        memcpy(km + len, randomness, ANTS_CHAIN_BEACON_RANDOMNESS_SIZE);
        len += ANTS_CHAIN_BEACON_RANDOMNESS_SIZE;
    }
    return ants_blake3_derive_key(context, km, len, out_seed);
}

ants_error_t ants_chain_vrf_seed(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                 uint64_t height,
                                 const uint8_t randomness[ANTS_CHAIN_BEACON_RANDOMNESS_SIZE],
                                 uint8_t out_seed[ANTS_CHAIN_HASH_SIZE])
{
    if (prev_block_hash == NULL || randomness == NULL || out_seed == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return vrf_seed_derive("ants-v1-vrf-seed", prev_block_hash, height, randomness, out_seed);
}

ants_error_t ants_chain_vrf_seed_degraded(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                          uint64_t height,
                                          uint8_t out_seed[ANTS_CHAIN_HASH_SIZE])
{
    if (prev_block_hash == NULL || out_seed == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return vrf_seed_derive("ants-v1-vrf-seed-degraded", prev_block_hash, height, NULL, out_seed);
}

/* ======================================================================== */
/* PR8 — block proposal + proposer election                                  */
/* ======================================================================== */

ants_error_t ants_chain_proposer(uint64_t height, size_t k, size_t *out_member)
{
    if (out_member == NULL || k == 0 || k > ANTS_CHAIN_COMMITTEE_K_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* DRAFT round-robin (the header's rationale): the position height mod k
     * into the canonical ascending committee. k <= K_MAX = 64 so the result
     * always fits a size_t. */
    *out_member = (size_t)(height % (uint64_t)k);
    return ANTS_OK;
}

ants_error_t ants_chain_block_propose(uint64_t height,
                                      const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                      uint64_t epoch,
                                      uint64_t cutoff_time,
                                      bool degraded_seed,
                                      const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                      size_t n_ids,
                                      const ants_chain_event_t *events,
                                      size_t n_events,
                                      ants_chain_pattern_finding_t *findings_buf,
                                      size_t findings_cap,
                                      size_t *out_n_findings,
                                      ants_chain_block_t *out_block)
{
    uint8_t root[ANTS_CHAIN_HASH_SIZE];
    size_t n_findings = 0;
    ants_error_t rc;

    if (prev_block_hash == NULL || out_block == NULL || out_n_findings == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* NULL content_ids with n_ids != 0, NULL events with n_events != 0, and
     * NULL findings_buf with findings_cap != 0 are rejected by the two
     * composed functions below. */

    /* confirmed_proofs = MerkleRoot(visible proofs at the cutoff). Computed
     * into a local first so *out_block is only written from a view that
     * passed canonical-order validation. */
    rc = ants_chain_confirmed_root(content_ids, n_ids, root);
    if (rc != ANTS_OK) {
        return rc;
    }

    /* The pattern findings, with now ≡ cutoff_time — THE determinism pin:
     * every committee member recomputing from the same visible set windows
     * the events against the same instant and emits the byte-identical
     * findings, never its own wall clock. */
    rc = ants_chain_pattern_scan(
        events, n_events, cutoff_time, findings_buf, findings_cap, &n_findings);
    *out_n_findings = n_findings;
    if (rc != ANTS_OK) {
        return rc;
    }
    /* More findings than one summary can carry: a pathological epoch the
     * runtime must split (the same bound epoch_summary_encode enforces). */
    if (n_findings > ANTS_CHAIN_MAX_PATTERN_FINDINGS) {
        return ANTS_ERROR_INVALID_ARG;
    }

    out_block->height = height;
    memcpy(out_block->prev_block_hash, prev_block_hash, ANTS_CHAIN_HASH_SIZE);
    out_block->degraded_seed = degraded_seed;
    out_block->summary.epoch = epoch;
    out_block->summary.cutoff_time = cutoff_time;
    memcpy(out_block->summary.confirmed_proofs, root, ANTS_CHAIN_HASH_SIZE);
    out_block->summary.findings = n_findings > 0 ? findings_buf : NULL;
    out_block->summary.n_findings = n_findings;
    return ANTS_OK;
}
