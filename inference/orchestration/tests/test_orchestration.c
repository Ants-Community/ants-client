/*
 * test_orchestration.c — Tests for inference orchestration (Component #13).
 *
 * Surface 1 (commit-at-send) is implemented, so its eight entry points get
 * behavioral tests on top of the permanent argument-handling contract:
 *   - leaf hashing reproduces BLAKE3(0x00 ‖ dist ‖ LE64(pos)) and binds
 *     the position;
 *   - the Merkle root matches an independent level-by-level reduction of
 *     the promote-lone-trailing-node scheme (a different algorithm from the
 *     library's MMR build, so agreement is a genuine cross-check);
 *   - prove → verify round-trips for every index across several tree sizes,
 *     and any tamper (root / leaf / path) flips the verdict to false;
 *   - the commit codec round-trips every field, emits canonical CBOR, and
 *     rejects truncated / trailing / wrong-shape / non-canonical input with
 *     the documented MALFORMED / NON_CANONICAL split;
 *   - commit_sign signs exactly the canonical encoding (checked against a
 *     standalone encode-then-Ed25519-sign), and verify_sig rejects tampered
 *     commits, signatures, and wrong public keys.
 *
 * Surface 2 (anti-grinding challenge derivation) is implemented, so its three
 * entry points are cross-checked against an independent recompute of the
 * pinned PRF keystream (block(i) = BLAKE3(beacon ‖ root ‖ tag ‖ LE64(i)), read
 * as big-endian words): is_audited against the exact W_0 < threshold boundary;
 * positions against a stratified-stride reference (distinct, ascending,
 * in-range, whole-answer when m >= length); auditor against a replay of the
 * unbiased rejection sampling (in range, n == 1, deterministic, well-spread).
 *
 * Surfaces 3–4 (e-process, serving runtime) are still stubs: their tests pin
 * the API shape, argument validation, and the ANTS_ERROR_NOT_IMPLEMENTED
 * return until their implementing PRs land.
 *
 * The remaining checks pin protocol constants, distinct PRF tags, e-process
 * default ranges, and the opaque-context size.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_inference.h"

#include <stdbool.h>
#include <stddef.h>
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

/* -- constants -------------------------------------------------------- */

static void test_tier_constants(void)
{
    CHECK(ANTS_INFERENCE_TIER_1 == 1);
    CHECK(ANTS_INFERENCE_TIER_2 == 2);
    CHECK(ANTS_INFERENCE_TIER_3 == 3);
}

static void test_size_constants(void)
{
    CHECK(ANTS_INFERENCE_HASH_SIZE == 32);
    CHECK(ANTS_INFERENCE_MERKLE_LEAF_SIZE == 32);
    CHECK(ANTS_INFERENCE_MERKLE_ROOT_SIZE == 32);
    CHECK(ANTS_INFERENCE_BEACON_SIZE == 32);
    CHECK(ANTS_INFERENCE_PUBKEY_SIZE == 32);
    CHECK(ANTS_INFERENCE_PRIVKEY_SIZE == 32);
    CHECK(ANTS_INFERENCE_SIG_SIZE == 64);
    CHECK(ANTS_INFERENCE_MERKLE_MAX_DEPTH == 32);
}

static void test_merkle_prefixes_distinct(void)
{
    /* Domain separation requires leaf and internal-node prefixes differ. */
    CHECK(ANTS_INFERENCE_MERKLE_LEAF_PREFIX == 0x00);
    CHECK(ANTS_INFERENCE_MERKLE_NODE_PREFIX == 0x01);
    CHECK(ANTS_INFERENCE_MERKLE_LEAF_PREFIX != ANTS_INFERENCE_MERKLE_NODE_PREFIX);
}

static void test_verdict_enum_values(void)
{
    CHECK(ANTS_INFERENCE_VERDICT_CONTINUE == 0);
    CHECK(ANTS_INFERENCE_VERDICT_FRAUD == 1);
}

static void test_eprocess_defaults_in_range(void)
{
    CHECK(ANTS_INFERENCE_DEFAULT_ALPHA > 0.0 && ANTS_INFERENCE_DEFAULT_ALPHA < 1.0);
    CHECK(ANTS_INFERENCE_DEFAULT_MU0 >= 0.0 && ANTS_INFERENCE_DEFAULT_MU0 < 1.0);
    CHECK(ANTS_INFERENCE_DEFAULT_LAMBDA_CAP >= 0.0);
}

static void test_prf_contexts_present_and_distinct(void)
{
    CHECK(ANTS_INFERENCE_PRF_CONTEXT_SEL != NULL);
    CHECK(ANTS_INFERENCE_PRF_CONTEXT_POS != NULL);
    CHECK(ANTS_INFERENCE_PRF_CONTEXT_AUD != NULL);
    CHECK(strcmp(ANTS_INFERENCE_PRF_CONTEXT_SEL, ANTS_INFERENCE_PRF_CONTEXT_POS) != 0);
    CHECK(strcmp(ANTS_INFERENCE_PRF_CONTEXT_SEL, ANTS_INFERENCE_PRF_CONTEXT_AUD) != 0);
    CHECK(strcmp(ANTS_INFERENCE_PRF_CONTEXT_POS, ANTS_INFERENCE_PRF_CONTEXT_AUD) != 0);
}

static void test_ctx_size_as_advertised(void)
{
    CHECK(sizeof(ants_inference_t) == ANTS_INFERENCE_CTX_SIZE);
}

/* -- commit-at-send helpers (independent reimplementations) ----------- */

/* Recompute a leaf hash from the documented preimage, independent of the
 * library: BLAKE3(0x00 ‖ dist ‖ LE64(position)). */
static void tleaf(const uint8_t *dist, size_t dist_len, uint64_t pos, uint8_t out[32])
{
    const uint8_t prefix = 0x00;
    uint8_t le[8];
    ants_blake3_ctx_t h;
    int i;

    for (i = 0; i < 8; i++) {
        le[i] = (uint8_t)(pos >> (8 * i));
    }
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, dist, dist_len), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, le, sizeof le), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

/* Recompute an internal node hash: BLAKE3(0x01 ‖ L ‖ R). */
static void tnode(const uint8_t l[32], const uint8_t r[32], uint8_t out[32])
{
    const uint8_t prefix = 0x01;
    ants_blake3_ctx_t h;

    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, l, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, r, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

/* Build n distinct leaves the way a producer would, via the leaf preimage. */
static void make_leaves(uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE], size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t dist[3] = {(uint8_t)i, 0xAA, (uint8_t)(i * 7 + 1)};
        tleaf(dist, sizeof dist, i, leaves[i]);
    }
}

/* Independent reference root: reduce the leaves level by level, promoting a
 * lone trailing node unchanged. This is a different algorithm from the
 * library's online MMR build + peak bagging, so byte agreement cross-checks
 * the implementation rather than mirroring it. Capped at 64 leaves (tests
 * stay small). */
static void
expected_root(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE], size_t n, uint8_t out[32])
{
    uint8_t cur[64][32];
    size_t count = n;
    size_t i;

    CHECK(n >= 1 && n <= 64);
    for (i = 0; i < n; i++) {
        memcpy(cur[i], leaves[i], 32);
    }
    while (count > 1) {
        size_t w = 0;
        for (i = 0; i < count; i += 2) {
            if (i + 1 < count) {
                tnode(cur[i], cur[i + 1], cur[w]);
            } else {
                memcpy(cur[w], cur[i], 32); /* promote lone trailing node */
            }
            w++;
        }
        count = w;
    }
    memcpy(out, cur[0], 32);
}

/* A commit with distinct, recognizable bytes in every field — including a
 * max-value u64 to exercise the 9-byte integer encoding. */
static void fill_sample_commit(ants_inference_commit_t *c)
{
    int i;
    memset(c, 0, sizeof *c);
    for (i = 0; i < 32; i++) {
        c->root[i] = (uint8_t)i;
        c->model_hash[i] = (uint8_t)(0x40 + i);
        c->input_hash[i] = (uint8_t)(0x60 + i);
        c->req_nonce[i] = (uint8_t)(0x80 + i);
        c->agent_meas[i] = (uint8_t)(0xA0 + i);
    }
    c->round = 0x0102030405060708ULL;
    c->audit_threshold = 0xFFFFFFFFFFFFFFFFULL;
    c->m = 0x01020304u;
    c->length = 0x05060708u;
    c->tier = ANTS_INFERENCE_TIER_3;
}

static bool commit_eq(const ants_inference_commit_t *a, const ants_inference_commit_t *b)
{
    return memcmp(a->root, b->root, 32) == 0 && memcmp(a->model_hash, b->model_hash, 32) == 0 &&
           memcmp(a->input_hash, b->input_hash, 32) == 0 &&
           memcmp(a->req_nonce, b->req_nonce, 32) == 0 &&
           memcmp(a->agent_meas, b->agent_meas, 32) == 0 && a->round == b->round &&
           a->audit_threshold == b->audit_threshold && a->m == b->m && a->length == b->length &&
           a->tier == b->tier;
}

/* -- 1. commit-at-send ------------------------------------------------ */

static void test_leaf_hash_contract(void)
{
    uint8_t dist[16];
    uint8_t leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    uint8_t leaf2[ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    uint8_t expect[ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    int i;

    for (i = 0; i < 16; i++) {
        dist[i] = (uint8_t)(i + 1);
    }

    /* Argument validation (permanent contract). */
    CHECK_EQ(ants_inference_leaf_hash(NULL, sizeof dist, 0, leaf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_leaf_hash(dist, 0, 0, leaf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 0, NULL), ANTS_ERROR_INVALID_ARG);

    /* Known-answer: matches the documented leaf preimage. */
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 7, leaf), ANTS_OK);
    tleaf(dist, sizeof dist, 7, expect);
    CHECK(memcmp(leaf, expect, sizeof leaf) == 0);

    /* Deterministic. */
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 7, leaf2), ANTS_OK);
    CHECK(memcmp(leaf, leaf2, sizeof leaf) == 0);

    /* Position is bound: same bytes at a different index hash differently. */
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 8, leaf2), ANTS_OK);
    CHECK(memcmp(leaf, leaf2, sizeof leaf) != 0);

    /* Distribution bytes are bound: different content hashes differently. */
    dist[0] ^= 0xFF;
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 7, leaf2), ANTS_OK);
    CHECK(memcmp(leaf, leaf2, sizeof leaf) != 0);
}

static void test_merkle_root_contract(void)
{
    uint8_t leaves[8][ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    uint8_t expect[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    uint8_t dummy[1][ANTS_INFERENCE_MERKLE_LEAF_SIZE] = {{0}};
    const size_t sizes[] = {1, 2, 3, 4, 5, 8};
    size_t s;

    make_leaves(leaves, 8);

    /* Argument validation. */
    CHECK_EQ(ants_inference_merkle_root(NULL, 4, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_root(leaves, 0, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_root(leaves, 4, NULL), ANTS_ERROR_INVALID_ARG);
#if SIZE_MAX > 0xFFFFFFFFu
    /* n_leaves beyond 2^MERKLE_MAX_DEPTH is rejected before any deref. */
    CHECK_EQ(
        ants_inference_merkle_root(dummy, ((size_t)1 << ANTS_INFERENCE_MERKLE_MAX_DEPTH) + 1, root),
        ANTS_ERROR_INVALID_ARG);
#else
    (void)dummy;
#endif

    /* Single leaf: the root is the leaf itself. */
    CHECK_EQ(ants_inference_merkle_root(leaves, 1, root), ANTS_OK);
    CHECK(memcmp(root, leaves[0], sizeof root) == 0);

    /* Cross-check against the independent level-by-level reduction. */
    for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        CHECK_EQ(ants_inference_merkle_root(leaves, sizes[s], root), ANTS_OK);
        expected_root(leaves, sizes[s], expect);
        CHECK(memcmp(root, expect, sizeof root) == 0);
    }
}

static void test_merkle_prove_contract(void)
{
    uint8_t leaves[4][ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    uint8_t path[ANTS_INFERENCE_MERKLE_MAX_DEPTH * ANTS_INFERENCE_HASH_SIZE];
    size_t path_len = 0;

    make_leaves(leaves, 4);

    /* Argument validation. */
    CHECK_EQ(
        ants_inference_merkle_prove(NULL, 4, 0, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_inference_merkle_prove(leaves, 0, 0, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_inference_merkle_prove(leaves, 4, 4, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_ERROR_INVALID_ARG); /* index >= n_leaves */
    CHECK_EQ(
        ants_inference_merkle_prove(leaves, 4, 0, NULL, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_prove(leaves, 4, 0, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* A 4-leaf tree needs a 2-hash proof; capacity 1 is too small. */
    CHECK_EQ(ants_inference_merkle_prove(leaves, 4, 0, path, 1, &path_len),
             ANTS_ERROR_BUFFER_TOO_SMALL);

    /* Success: the proof for index 0 has the expected length. */
    path_len = 0;
    CHECK_EQ(
        ants_inference_merkle_prove(leaves, 4, 0, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_OK);
    CHECK(path_len == 2);
}

static void test_merkle_verify_contract(void)
{
    uint8_t leaves[8][ANTS_INFERENCE_MERKLE_LEAF_SIZE];
    uint8_t path[ANTS_INFERENCE_MERKLE_MAX_DEPTH * ANTS_INFERENCE_HASH_SIZE];
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    size_t path_len = 0;
    bool ok = false;
    const size_t sizes[] = {1, 2, 3, 4, 5, 8};
    size_t s;

    make_leaves(leaves, 8);

    /* Argument validation. A 4-leaf tree's index-0 proof length is 2, so the
     * path_len-shape guard can be exercised against that known-good value. */
    {
        uint8_t leaf0[ANTS_INFERENCE_MERKLE_LEAF_SIZE];
        memcpy(leaf0, leaves[0], sizeof leaf0);
        CHECK_EQ(ants_inference_merkle_verify(NULL, 0, 4, path, 2, root, &ok),
                 ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 0, path, 2, root, &ok),
                 ANTS_ERROR_INVALID_ARG); /* n_leaves == 0 */
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 4, 4, path, 2, root, &ok),
                 ANTS_ERROR_INVALID_ARG); /* index >= n_leaves */
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 4, NULL, 2, root, &ok),
                 ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 4, path, 2, NULL, &ok),
                 ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 4, path, 2, root, NULL),
                 ANTS_ERROR_INVALID_ARG);
        /* path_len inconsistent with the tree shape (correct is 2). */
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 4, path, 1, root, &ok),
                 ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_inference_merkle_verify(leaf0, 0, 4, path, 3, root, &ok),
                 ANTS_ERROR_INVALID_ARG);
    }

    /* Round-trip: for every tree size and index, prove then verify accepts,
     * and each single-byte tamper (root / leaf / path) flips it to false. */
    for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        size_t n = sizes[s];
        size_t idx;
        CHECK_EQ(ants_inference_merkle_root(leaves, n, root), ANTS_OK);
        for (idx = 0; idx < n; idx++) {
            uint8_t bad_root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
            uint8_t bad_leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE];

            CHECK_EQ(ants_inference_merkle_prove(
                         leaves, n, idx, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
                     ANTS_OK);

            ok = false;
            CHECK_EQ(ants_inference_merkle_verify(leaves[idx], idx, n, path, path_len, root, &ok),
                     ANTS_OK);
            CHECK(ok == true);

            /* Tampered root → reject. */
            memcpy(bad_root, root, sizeof bad_root);
            bad_root[0] ^= 0x01;
            ok = true;
            CHECK_EQ(
                ants_inference_merkle_verify(leaves[idx], idx, n, path, path_len, bad_root, &ok),
                ANTS_OK);
            CHECK(ok == false);

            /* Tampered leaf → reject. */
            memcpy(bad_leaf, leaves[idx], sizeof bad_leaf);
            bad_leaf[0] ^= 0x01;
            ok = true;
            CHECK_EQ(ants_inference_merkle_verify(bad_leaf, idx, n, path, path_len, root, &ok),
                     ANTS_OK);
            CHECK(ok == false);

            /* Tampered path (when the tree has one) → reject. */
            if (path_len > 0) {
                path[0] ^= 0x01;
                ok = true;
                CHECK_EQ(
                    ants_inference_merkle_verify(leaves[idx], idx, n, path, path_len, root, &ok),
                    ANTS_OK);
                CHECK(ok == false);
                path[0] ^= 0x01; /* restore */
            }
        }
    }
}

static void test_commit_encode_contract(void)
{
    ants_inference_commit_t commit;
    uint8_t out[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    size_t out_len = 0;

    fill_sample_commit(&commit);

    /* Argument validation. */
    CHECK_EQ(ants_inference_commit_encode(NULL, out, sizeof out, &out_len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_encode(&commit, NULL, sizeof out, &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_encode(&commit, out, sizeof out, NULL), ANTS_ERROR_INVALID_ARG);

    /* Success: fits the advertised bound and is canonical CBOR. */
    CHECK_EQ(ants_inference_commit_encode(&commit, out, sizeof out, &out_len), ANTS_OK);
    CHECK(out_len > 0 && out_len <= ANTS_INFERENCE_COMMIT_ENCODED_MAX);
    CHECK_EQ(ants_cbor_is_canonical(out, out_len), ANTS_OK);

    /* One byte short of the true length → BUFFER_TOO_SMALL. */
    {
        size_t shortlen = 0;
        CHECK_EQ(ants_inference_commit_encode(&commit, out, out_len - 1, &shortlen),
                 ANTS_ERROR_BUFFER_TOO_SMALL);
    }
}

static void test_commit_decode_contract(void)
{
    ants_inference_commit_t commit;
    ants_inference_commit_t got;
    uint8_t enc[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    uint8_t buf[ANTS_INFERENCE_COMMIT_ENCODED_MAX + 1];
    size_t enc_len = 0;
    uint8_t in[64] = {0};

    /* Argument validation. */
    CHECK_EQ(ants_inference_commit_decode(NULL, sizeof in, &commit), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_decode(in, 0, &commit), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_decode(in, sizeof in, NULL), ANTS_ERROR_INVALID_ARG);

    /* Round-trip: encode then decode reproduces every field. */
    fill_sample_commit(&commit);
    CHECK_EQ(ants_inference_commit_encode(&commit, enc, sizeof enc, &enc_len), ANTS_OK);
    memset(&got, 0, sizeof got);
    CHECK_EQ(ants_inference_commit_decode(enc, enc_len, &got), ANTS_OK);
    CHECK(commit_eq(&commit, &got));

    /* Truncated input → MALFORMED. */
    CHECK_EQ(ants_inference_commit_decode(enc, enc_len - 1, &got), ANTS_ERROR_MALFORMED);

    /* Trailing byte after a complete map → MALFORMED. */
    memcpy(buf, enc, enc_len);
    buf[enc_len] = 0x00;
    CHECK_EQ(ants_inference_commit_decode(buf, enc_len + 1, &got), ANTS_ERROR_MALFORMED);

    /* Well-formed CBOR but not a 10-pair commit map → MALFORMED. */
    {
        const uint8_t wrong_count[] = {0xA1, 0x01, 0x00}; /* map(1){1:0} */
        CHECK_EQ(ants_inference_commit_decode(wrong_count, sizeof wrong_count, &got),
                 ANTS_ERROR_MALFORMED);
    }

    /* Not a map at all (a bare integer) → MALFORMED. */
    {
        const uint8_t not_map[] = {0x00};
        CHECK_EQ(ants_inference_commit_decode(not_map, sizeof not_map, &got), ANTS_ERROR_MALFORMED);
    }

    /* Non-canonical framing: the 10-entry map header written in two bytes
     * (0xB8 0x0A) instead of the shortest form 0xAA → NON_CANONICAL. */
    {
        const uint8_t non_canon[] = {0xB8, 0x0A};
        CHECK_EQ(ants_inference_commit_decode(non_canon, sizeof non_canon, &got),
                 ANTS_ERROR_NON_CANONICAL);
    }
}

static void test_commit_sign_contract(void)
{
    ants_inference_commit_t commit;
    uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE];
    uint8_t pub[ANTS_INFERENCE_PUBKEY_SIZE];
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE];
    uint8_t sig_ref[ANTS_INFERENCE_SIG_SIZE];
    uint8_t enc[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    size_t enc_len = 0;
    bool ok = false;
    int i;

    fill_sample_commit(&commit);
    for (i = 0; i < ANTS_INFERENCE_PRIVKEY_SIZE; i++) {
        priv[i] = (uint8_t)(0x11 + i);
    }

    /* Argument validation. */
    CHECK_EQ(ants_inference_commit_sign(NULL, priv, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_sign(&commit, NULL, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_sign(&commit, priv, NULL), ANTS_ERROR_INVALID_ARG);

    /* Sign, then verify with the matching public key. */
    CHECK_EQ(ants_inference_commit_sign(&commit, priv, sig), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, sig, &ok), ANTS_OK);
    CHECK(ok == true);

    /* commit_sign signs exactly the canonical encoding — cross-check against
     * a standalone encode-then-Ed25519-sign over the same bytes. */
    CHECK_EQ(ants_inference_commit_encode(&commit, enc, sizeof enc, &enc_len), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(priv, enc, enc_len, sig_ref), ANTS_OK);
    CHECK(memcmp(sig, sig_ref, sizeof sig) == 0);
}

static void test_commit_verify_sig_contract(void)
{
    ants_inference_commit_t commit;
    ants_inference_commit_t tampered;
    uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE];
    uint8_t priv2[ANTS_INFERENCE_PRIVKEY_SIZE];
    uint8_t pub[ANTS_INFERENCE_PUBKEY_SIZE];
    uint8_t pub2[ANTS_INFERENCE_PUBKEY_SIZE];
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE];
    uint8_t bad_sig[ANTS_INFERENCE_SIG_SIZE];
    bool ok = false;
    int i;

    fill_sample_commit(&commit);
    for (i = 0; i < ANTS_INFERENCE_PRIVKEY_SIZE; i++) {
        priv[i] = (uint8_t)(0x11 + i);
        priv2[i] = (uint8_t)(0x55 + i);
    }
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv2, pub2), ANTS_OK);
    CHECK_EQ(ants_inference_commit_sign(&commit, priv, sig), ANTS_OK);

    /* Argument validation. */
    CHECK_EQ(ants_inference_commit_verify_sig(NULL, pub, sig, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, NULL, sig, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, NULL, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, sig, NULL), ANTS_ERROR_INVALID_ARG);

    /* Genuine signature verifies. */
    ok = false;
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, sig, &ok), ANTS_OK);
    CHECK(ok == true);

    /* Tampered commit → ran OK, verdict false. */
    tampered = commit;
    tampered.tier = (uint8_t)(tampered.tier ^ 0x01);
    ok = true;
    CHECK_EQ(ants_inference_commit_verify_sig(&tampered, pub, sig, &ok), ANTS_OK);
    CHECK(ok == false);

    /* Tampered signature → verdict false. */
    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[0] ^= 0x01;
    ok = true;
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, bad_sig, &ok), ANTS_OK);
    CHECK(ok == false);

    /* Genuine signature, wrong public key → verdict false. */
    ok = true;
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub2, sig, &ok), ANTS_OK);
    CHECK(ok == false);
}

/* -- 2. anti-grinding challenge derivation ---------------------------- */

/* Independent recompute of keystream word W_k, mirroring nothing in the
 * library's streaming reader: hash block(k/4) = BLAKE3(beacon ‖ root ‖ tag ‖
 * LE64(k/4)) one-shot via streaming, then read word (k%4) big-endian. */
static uint64_t t_prf_word(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                           const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                           const char *tag,
                           uint64_t k)
{
    uint64_t block_i = k / 4;
    int word_in = (int)(k % 4);
    uint8_t le[8];
    uint8_t block[32];
    ants_blake3_ctx_t h;
    uint64_t w = 0;
    int i;

    for (i = 0; i < 8; i++) {
        le[i] = (uint8_t)(block_i >> (8 * i));
    }
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, beacon, ANTS_INFERENCE_BEACON_SIZE), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, root, ANTS_INFERENCE_MERKLE_ROOT_SIZE), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, (const uint8_t *)tag, strlen(tag)), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, le, sizeof le), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, block), ANTS_OK);

    for (i = 0; i < 8; i++) {
        w = (w << 8) | block[word_in * 8 + i];
    }
    return w;
}

/* Replay the unbiased rejection sampling independently of the library. */
static uint64_t t_expected_auditor(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                   const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                   uint64_t n)
{
    uint64_t reject_below = ((uint64_t)0 - n) % n;
    uint64_t k;
    for (k = 0;; k++) {
        uint64_t w = t_prf_word(beacon, root, ANTS_INFERENCE_PRF_CONTEXT_AUD, k);
        if (w >= reject_below) {
            return w % n;
        }
    }
}

/* Run challenge_positions for one (m, length) and check it against the
 * independent stratified-stride reference: count, exact per-bucket value,
 * in-range, strictly ascending (hence distinct). */
static void check_positions_case(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                 const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                 uint32_t m,
                                 uint32_t length)
{
    uint64_t got[128];
    size_t count = 999;
    uint32_t M = (m < length) ? m : length;
    uint32_t j;

    CHECK(M <= 128);
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, m, length, got, 128, &count),
             ANTS_OK);
    CHECK(count == (size_t)M);

    for (j = 0; j < M; j++) {
        uint64_t lo = ((uint64_t)j * length) / M;
        uint64_t hi = (((uint64_t)j + 1u) * length) / M;
        uint64_t expect;
        if (m >= length) {
            expect = j; /* whole answer opened, no keystream draw */
        } else {
            uint64_t w = t_prf_word(beacon, root, ANTS_INFERENCE_PRF_CONTEXT_POS, j);
            expect = lo + (w % (hi - lo));
        }
        CHECK(got[j] == expect);
        CHECK(got[j] < length);
        if (j > 0) {
            CHECK(got[j] > got[j - 1]);
        }
    }
}

static void test_challenge_is_audited_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE];
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    bool a1 = false, a2 = false;
    uint64_t w0, w0b;
    int i;

    for (i = 0; i < 32; i++) {
        beacon[i] = (uint8_t)(0x10 + i);
        root[i] = (uint8_t)(0xC0 + i);
    }

    /* argument validation (permanent) */
    CHECK_EQ(ants_inference_challenge_is_audited(NULL, root, 0, &a1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, NULL, 0, &a1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, 0, NULL), ANTS_ERROR_INVALID_ARG);

    w0 = t_prf_word(beacon, root, ANTS_INFERENCE_PRF_CONTEXT_SEL, 0);
    CHECK(w0 != UINT64_MAX); /* keeps the boundary cases below well-defined */

    /* threshold 0 never audits */
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, 0, &a1), ANTS_OK);
    CHECK(!a1);

    /* exact "< threshold" semantics, against the independently recomputed W_0 */
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, w0, &a1), ANTS_OK);
    CHECK(!a1); /* W_0 < W_0 is false */
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, w0 + 1u, &a1), ANTS_OK);
    CHECK(a1); /* W_0 < W_0 + 1 is true */

    /* maximum threshold audits (W_0 < UINT64_MAX) */
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, UINT64_MAX, &a1), ANTS_OK);
    CHECK(a1);

    /* determinism */
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, w0 + 1u, &a2), ANTS_OK);
    CHECK(a2 == a1);

    /* root binding: a flipped root yields a different W_0 and the decision
     * tracks it at its own boundary */
    root[0] ^= 0x01;
    w0b = t_prf_word(beacon, root, ANTS_INFERENCE_PRF_CONTEXT_SEL, 0);
    CHECK(w0b != w0);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, w0b, &a1), ANTS_OK);
    CHECK(!a1);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, w0b + 1u, &a1), ANTS_OK);
    CHECK(a1);
}

static void test_challenge_positions_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE];
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    uint64_t positions[8] = {0};
    size_t count = 0;
    int i;

    for (i = 0; i < 32; i++) {
        beacon[i] = (uint8_t)(0x21 + i);
        root[i] = (uint8_t)(0x90 + i);
    }

    /* argument validation (permanent) */
    CHECK_EQ(ants_inference_challenge_positions(NULL, root, 4, 64, positions, 8, &count),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_positions(beacon, NULL, 4, 64, positions, 8, &count),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 0, 64, positions, 8, &count),
             ANTS_ERROR_INVALID_ARG); /* m == 0 */
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 0, positions, 8, &count),
             ANTS_ERROR_INVALID_ARG); /* length == 0 */
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 64, NULL, 8, &count),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 64, positions, 8, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* BUFFER_TOO_SMALL: cap < min(m, length) */
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 64, positions, 3, &count),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 100, 8, positions, 7, &count),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    /* cap exactly == min(m, length) succeeds */
    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 64, positions, 4, &count),
             ANTS_OK);
    CHECK(count == 4);

    /* behavioral + independent stratified cross-check over several shapes */
    check_positions_case(beacon, root, 4, 64);
    check_positions_case(beacon, root, 5, 64);
    check_positions_case(beacon, root, 1, 64);  /* single bucket = whole range */
    check_positions_case(beacon, root, 3, 5);   /* uneven bucket widths */
    check_positions_case(beacon, root, 8, 8);   /* m == length: whole answer */
    check_positions_case(beacon, root, 100, 8); /* m > length: whole answer */
    check_positions_case(beacon, root, 7, 7);
    check_positions_case(beacon, root, 64, 64);
}

static void test_challenge_auditor_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE];
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];
    uint64_t index = 0, index2 = 0;
    const uint64_t ns[] = {1, 2, 3, 7, 100, 1000, ((uint64_t)1 << 32) + 1, ((uint64_t)1 << 63) + 1};
    size_t t;
    int i;

    for (i = 0; i < 32; i++) {
        beacon[i] = (uint8_t)(0x33 + i);
        root[i] = (uint8_t)(0x77 + i);
    }

    /* argument validation (permanent) */
    CHECK_EQ(ants_inference_challenge_auditor(NULL, root, 10, &index), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_auditor(beacon, NULL, 10, &index), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 0, &index),
             ANTS_ERROR_INVALID_ARG); /* n_verifiers == 0 */
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 10, NULL), ANTS_ERROR_INVALID_ARG);

    /* n == 1 always yields 0 */
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 1, &index), ANTS_OK);
    CHECK(index == 0);

    /* in range + cross-check against an independent rejection-sampling replay */
    for (t = 0; t < sizeof ns / sizeof ns[0]; t++) {
        CHECK_EQ(ants_inference_challenge_auditor(beacon, root, ns[t], &index), ANTS_OK);
        CHECK(index < ns[t]);
        CHECK(index == t_expected_auditor(beacon, root, ns[t]));
    }

    /* determinism */
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 1000, &index), ANTS_OK);
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 1000, &index2), ANTS_OK);
    CHECK(index == index2);

    /* well-spread: varying the root over n == 2 produces both 0 and 1 (guards
     * against a stuck/degenerate draw the exact cross-check could share) */
    {
        int seen0 = 0, seen1 = 0;
        for (i = 0; i < 64; i++) {
            root[0] = (uint8_t)i;
            CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 2, &index), ANTS_OK);
            if (index == 0) {
                seen0 = 1;
            }
            if (index == 1) {
                seen1 = 1;
            }
        }
        CHECK(seen0 && seen1);
    }
}

/* -- 3. the betting e-process ----------------------------------------- */

static void test_eprocess_init_contract(void)
{
    ants_inference_eprocess_t ep;

    CHECK_EQ(ants_inference_eprocess_init(NULL,
                                          ANTS_INFERENCE_DEFAULT_ALPHA,
                                          ANTS_INFERENCE_DEFAULT_MU0,
                                          ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_INVALID_ARG);
    /* alpha must be in (0, 1). */
    CHECK_EQ(ants_inference_eprocess_init(
                 &ep, 0.0, ANTS_INFERENCE_DEFAULT_MU0, ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_eprocess_init(
                 &ep, 1.0, ANTS_INFERENCE_DEFAULT_MU0, ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_INVALID_ARG);
    /* mu0 must be in [0, 1). */
    CHECK_EQ(ants_inference_eprocess_init(
                 &ep, ANTS_INFERENCE_DEFAULT_ALPHA, -0.1, ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_eprocess_init(
                 &ep, ANTS_INFERENCE_DEFAULT_ALPHA, 1.0, ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_INVALID_ARG);
    /* lambda_cap must be >= 0. */
    CHECK_EQ(ants_inference_eprocess_init(
                 &ep, ANTS_INFERENCE_DEFAULT_ALPHA, ANTS_INFERENCE_DEFAULT_MU0, -1.0),
             ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_eprocess_init(&ep,
                                          ANTS_INFERENCE_DEFAULT_ALPHA,
                                          ANTS_INFERENCE_DEFAULT_MU0,
                                          ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_eprocess_update_contract(void)
{
    ants_inference_eprocess_t ep;
    ants_inference_verdict_t verdict = ANTS_INFERENCE_VERDICT_CONTINUE;
    memset(&ep, 0, sizeof ep);

    CHECK_EQ(ants_inference_eprocess_update(NULL, 0.5, &verdict), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_eprocess_update(&ep, 0.5, NULL), ANTS_ERROR_INVALID_ARG);
    /* score must be in [0, 1]. */
    CHECK_EQ(ants_inference_eprocess_update(&ep, -0.1, &verdict), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_eprocess_update(&ep, 1.1, &verdict), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_eprocess_update(&ep, 0.5, &verdict), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_discrepancy_contract(void)
{
    ants_canon_q24_t p[8] = {0};
    ants_canon_q24_t q[8] = {0};
    double score = -1.0;

    CHECK_EQ(ants_inference_discrepancy(NULL, q, 8, &score), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_discrepancy(p, NULL, 8, &score), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_discrepancy(p, q, 0, &score), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_discrepancy(p, q, 8, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_discrepancy(p, q, 8, &score), ANTS_ERROR_NOT_IMPLEMENTED);
}

/* -- 4. the serving runtime ------------------------------------------- */

static ants_error_t dummy_ref_fn(void *user,
                                 const uint8_t *prefix,
                                 size_t prefix_len,
                                 uint64_t position,
                                 ants_canon_q24_t *out_dist,
                                 size_t out_dist_cap,
                                 size_t *out_vocab)
{
    (void)user;
    (void)prefix;
    (void)prefix_len;
    (void)position;
    (void)out_dist;
    (void)out_dist_cap;
    (void)out_vocab;
    return ANTS_OK;
}

static void test_init_contract(void)
{
    ants_inference_t ctx;
    ants_inference_config_t config;
    uint8_t weights[16] = {0};
    uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE] = {0};

    memset(&config, 0, sizeof config);
    config.model_weights = weights;
    config.model_weights_len = sizeof weights;
    config.producer_priv = priv;

    CHECK_EQ(ants_inference_init(NULL, &config), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_init(&ctx, NULL), ANTS_ERROR_INVALID_ARG);

    /* Missing required config fields. */
    {
        ants_inference_config_t bad = config;
        bad.model_weights = NULL;
        CHECK_EQ(ants_inference_init(&ctx, &bad), ANTS_ERROR_INVALID_ARG);
    }
    {
        ants_inference_config_t bad = config;
        bad.model_weights_len = 0;
        CHECK_EQ(ants_inference_init(&ctx, &bad), ANTS_ERROR_INVALID_ARG);
    }
    {
        ants_inference_config_t bad = config;
        bad.producer_priv = NULL;
        CHECK_EQ(ants_inference_init(&ctx, &bad), ANTS_ERROR_INVALID_ARG);
    }

    CHECK_EQ(ants_inference_init(&ctx, &config), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_destroy_contract(void)
{
    ants_inference_t ctx;
    memset(&ctx, 0, sizeof ctx);

    CHECK_EQ(ants_inference_destroy(NULL), ANTS_ERROR_INVALID_ARG);
    /* Safe on a zeroed (never-initialized) context — returns OK. */
    CHECK_EQ(ants_inference_destroy(&ctx), ANTS_OK);
}

static void test_serve_contract(void)
{
    ants_inference_t ctx;
    ants_inference_request_t req;
    ants_inference_response_t resp;
    uint8_t input[8] = {0};
    uint8_t answer[256] = {0};

    memset(&ctx, 0, sizeof ctx);
    memset(&req, 0, sizeof req);
    memset(&resp, 0, sizeof resp);
    req.input = input;
    req.input_len = sizeof input;
    req.tier = ANTS_INFERENCE_TIER_2;
    req.round = 1;
    resp.answer_buf = answer;
    resp.answer_cap = sizeof answer;

    CHECK_EQ(ants_inference_serve(NULL, &req, &resp), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_serve(&ctx, NULL, &resp), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_serve(&ctx, &req, NULL), ANTS_ERROR_INVALID_ARG);

    {
        ants_inference_request_t bad = req;
        bad.input = NULL;
        CHECK_EQ(ants_inference_serve(&ctx, &bad, &resp), ANTS_ERROR_INVALID_ARG);
    }
    {
        ants_inference_request_t bad = req;
        bad.input_len = 0;
        CHECK_EQ(ants_inference_serve(&ctx, &bad, &resp), ANTS_ERROR_INVALID_ARG);
    }
    {
        ants_inference_request_t bad = req;
        bad.tier = 0; /* unknown tier */
        CHECK_EQ(ants_inference_serve(&ctx, &bad, &resp), ANTS_ERROR_INVALID_ARG);
    }
    {
        ants_inference_response_t bad = resp;
        bad.answer_buf = NULL;
        CHECK_EQ(ants_inference_serve(&ctx, &req, &bad), ANTS_ERROR_INVALID_ARG);
    }

    CHECK_EQ(ants_inference_serve(&ctx, &req, &resp), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_audit_contract(void)
{
    ants_inference_commit_t commit;
    ants_inference_eprocess_t params;
    uint8_t answer[16] = {0};
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE] = {0};
    ants_inference_verdict_t verdict = ANTS_INFERENCE_VERDICT_CONTINUE;

    memset(&commit, 0, sizeof commit);
    memset(&params, 0, sizeof params);

    CHECK_EQ(ants_inference_audit(
                 NULL, answer, sizeof answer, beacon, dummy_ref_fn, NULL, &params, &verdict),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_audit(
                 &commit, NULL, sizeof answer, beacon, dummy_ref_fn, NULL, &params, &verdict),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_inference_audit(&commit, answer, 0, beacon, dummy_ref_fn, NULL, &params, &verdict),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_audit(
                 &commit, answer, sizeof answer, NULL, dummy_ref_fn, NULL, &params, &verdict),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(
        ants_inference_audit(&commit, answer, sizeof answer, beacon, NULL, NULL, &params, &verdict),
        ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_audit(
                 &commit, answer, sizeof answer, beacon, dummy_ref_fn, NULL, NULL, &verdict),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_audit(
                 &commit, answer, sizeof answer, beacon, dummy_ref_fn, NULL, &params, NULL),
             ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_audit(
                 &commit, answer, sizeof answer, beacon, dummy_ref_fn, NULL, &params, &verdict),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_tier_constants();
    test_size_constants();
    test_merkle_prefixes_distinct();
    test_verdict_enum_values();
    test_eprocess_defaults_in_range();
    test_prf_contexts_present_and_distinct();
    test_ctx_size_as_advertised();

    test_leaf_hash_contract();
    test_merkle_root_contract();
    test_merkle_prove_contract();
    test_merkle_verify_contract();
    test_commit_encode_contract();
    test_commit_decode_contract();
    test_commit_sign_contract();
    test_commit_verify_sig_contract();

    test_challenge_is_audited_contract();
    test_challenge_positions_contract();
    test_challenge_auditor_contract();

    test_eprocess_init_contract();
    test_eprocess_update_contract();
    test_discrepancy_contract();

    test_init_contract();
    test_destroy_contract();
    test_serve_contract();
    test_audit_contract();

    if (failures > 0) {
        fprintf(stderr, "test_orchestration: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_orchestration: all checks passed\n");
    return 0;
}
