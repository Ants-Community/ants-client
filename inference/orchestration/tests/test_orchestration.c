/*
 * test_orchestration.c — Contract tests for inference orchestration
 * (Component #13), scaffold phase.
 *
 * Scope (this PR): pin the public API *shape* before any real logic
 * lands —
 *   - protocol constants (tiers, sizes, Merkle prefixes, enum values);
 *   - PRF domain-separation tags are present and distinct;
 *   - e-process default parameters are in their valid ranges;
 *   - argument validation: NULL / out-of-range inputs return
 *     ANTS_ERROR_INVALID_ARG on every entry point;
 *   - every stub returns ANTS_ERROR_NOT_IMPLEMENTED on valid input
 *     (except `destroy`, which is OK on a zeroed context);
 *   - the opaque context is sized as advertised.
 *
 * When the per-surface implementations land, these contract tests stay
 * (the argument-handling guarantees are permanent) and behavioral tests
 * are added alongside.
 */

#include "ants_common.h"
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

/* -- 1. commit-at-send ------------------------------------------------ */

static void test_leaf_hash_contract(void)
{
    uint8_t dist[16] = {0};
    uint8_t leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE] = {0};

    CHECK_EQ(ants_inference_leaf_hash(NULL, sizeof dist, 0, leaf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_leaf_hash(dist, 0, 0, leaf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 0, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_leaf_hash(dist, sizeof dist, 7, leaf), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_merkle_root_contract(void)
{
    uint8_t leaves[4][ANTS_INFERENCE_MERKLE_LEAF_SIZE] = {{0}};
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE] = {0};

    CHECK_EQ(ants_inference_merkle_root(NULL, 4, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_root(leaves, 0, root), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_root(leaves, 4, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_merkle_root(leaves, 4, root), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_merkle_prove_contract(void)
{
    uint8_t leaves[4][ANTS_INFERENCE_MERKLE_LEAF_SIZE] = {{0}};
    uint8_t path[ANTS_INFERENCE_MERKLE_MAX_DEPTH * ANTS_INFERENCE_HASH_SIZE] = {0};
    size_t path_len = 0;

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

    CHECK_EQ(
        ants_inference_merkle_prove(leaves, 4, 0, path, ANTS_INFERENCE_MERKLE_MAX_DEPTH, &path_len),
        ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_merkle_verify_contract(void)
{
    uint8_t leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE] = {0};
    uint8_t path[2 * ANTS_INFERENCE_HASH_SIZE] = {0};
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE] = {0};
    bool ok = false;

    CHECK_EQ(ants_inference_merkle_verify(NULL, 0, 4, path, 2, root, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_verify(leaf, 0, 0, path, 2, root, &ok),
             ANTS_ERROR_INVALID_ARG); /* n_leaves == 0 */
    CHECK_EQ(ants_inference_merkle_verify(leaf, 4, 4, path, 2, root, &ok),
             ANTS_ERROR_INVALID_ARG); /* index >= n_leaves */
    CHECK_EQ(ants_inference_merkle_verify(leaf, 0, 4, NULL, 2, root, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_verify(leaf, 0, 4, path, 2, NULL, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_merkle_verify(leaf, 0, 4, path, 2, root, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_merkle_verify(leaf, 0, 4, path, 2, root, &ok),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_commit_encode_contract(void)
{
    ants_inference_commit_t commit;
    uint8_t out[256] = {0};
    size_t out_len = 0;
    memset(&commit, 0, sizeof commit);

    CHECK_EQ(ants_inference_commit_encode(NULL, out, sizeof out, &out_len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_encode(&commit, NULL, sizeof out, &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_encode(&commit, out, sizeof out, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_commit_encode(&commit, out, sizeof out, &out_len),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_commit_decode_contract(void)
{
    uint8_t in[64] = {0};
    ants_inference_commit_t commit;
    memset(&commit, 0, sizeof commit);

    CHECK_EQ(ants_inference_commit_decode(NULL, sizeof in, &commit), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_decode(in, 0, &commit), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_decode(in, sizeof in, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_commit_decode(in, sizeof in, &commit), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_commit_sign_contract(void)
{
    ants_inference_commit_t commit;
    uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE] = {0};
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE] = {0};
    memset(&commit, 0, sizeof commit);

    CHECK_EQ(ants_inference_commit_sign(NULL, priv, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_sign(&commit, NULL, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_sign(&commit, priv, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_commit_sign(&commit, priv, sig), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_commit_verify_sig_contract(void)
{
    ants_inference_commit_t commit;
    uint8_t pub[ANTS_INFERENCE_PUBKEY_SIZE] = {0};
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE] = {0};
    bool ok = false;
    memset(&commit, 0, sizeof commit);

    CHECK_EQ(ants_inference_commit_verify_sig(NULL, pub, sig, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, NULL, sig, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, NULL, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, sig, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_commit_verify_sig(&commit, pub, sig, &ok), ANTS_ERROR_NOT_IMPLEMENTED);
}

/* -- 2. anti-grinding challenge derivation ---------------------------- */

static void test_challenge_is_audited_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE] = {0};
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE] = {0};
    bool audited = false;

    CHECK_EQ(ants_inference_challenge_is_audited(NULL, root, 0, &audited), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, NULL, 0, &audited),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, 0, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_challenge_is_audited(beacon, root, (uint64_t)1 << 63, &audited),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_challenge_positions_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE] = {0};
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE] = {0};
    uint64_t positions[8] = {0};
    size_t count = 0;

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

    CHECK_EQ(ants_inference_challenge_positions(beacon, root, 4, 64, positions, 8, &count),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_challenge_auditor_contract(void)
{
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE] = {0};
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE] = {0};
    uint64_t index = 0;

    CHECK_EQ(ants_inference_challenge_auditor(NULL, root, 10, &index), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_auditor(beacon, NULL, 10, &index), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 0, &index),
             ANTS_ERROR_INVALID_ARG); /* n_verifiers == 0 */
    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 10, NULL), ANTS_ERROR_INVALID_ARG);

    CHECK_EQ(ants_inference_challenge_auditor(beacon, root, 10, &index),
             ANTS_ERROR_NOT_IMPLEMENTED);
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
