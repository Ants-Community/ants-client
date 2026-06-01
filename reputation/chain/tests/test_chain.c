/*
 * test_chain.c — Tests for Layer 2, the PoUH chain as ordered witness
 * (Component #8 PR1: SCAFFOLD).
 *
 * The scaffold has no behaviour yet, so these are CONTRACT tests: every
 * public entry point links and returns ANTS_ERROR_NOT_IMPLEMENTED (the
 * documented scaffold state — distinct from INVALID_ARG, so the day a PR
 * lands real behaviour these flip and tell us), the bound helpers return
 * 0, and the protocol constants hold the invariants the design depends on
 * (severity ladder ordering, the K / BLS-transition relationship, the 2/3
 * finality fraction, sizes agreeing with foundation/crypto, distinct
 * fork-choice outcomes). This proves the surface compiles, links, and is
 * internally consistent before any of it is implemented.
 */

#include "ants_chain.h"
#include "ants_common.h"

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
                    "FAIL %s:%d  expected %d, got %d\n",                                           \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    (int)_e,                                                                       \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

/* The protocol invariants the rest of the design leans on. */
static void test_constants(void)
{
    /* Severity is a strictly-ascending, append-only ladder; the reserved
     * floor sits just above the last assigned level. */
    CHECK(ANTS_CHAIN_SEVERITY_SOFT < ANTS_CHAIN_SEVERITY_MEDIUM);
    CHECK(ANTS_CHAIN_SEVERITY_MEDIUM < ANTS_CHAIN_SEVERITY_HARD);
    CHECK(ANTS_CHAIN_SEVERITY_HARD < ANTS_CHAIN_SEVERITY_TERMINAL);
    CHECK(ANTS_CHAIN_SEVERITY_TERMINAL < ANTS_CHAIN_SEVERITY__RESERVED_MIN);

    /* The epoch-atomic signature scheme transitions strictly below the
     * mature committee size (so the K=64 mature committee is in the BLS
     * regime). */
    CHECK(ANTS_CHAIN_BLS_TRANSITION_K < ANTS_CHAIN_COMMITTEE_K_MAX);
    CHECK(ANTS_CHAIN_COMMITTEE_K_MAX == 64u);

    /* 2/3 finality, a proper fraction in (0,1). */
    CHECK(ANTS_CHAIN_FINALITY_NUM < ANTS_CHAIN_FINALITY_DEN);
    CHECK(ANTS_CHAIN_FINALITY_NUM > 0u);

    /* θ is a proper fraction in (0,1). */
    CHECK(ANTS_CHAIN_FORK_THETA_NUM < ANTS_CHAIN_FORK_THETA_DEN);
    CHECK(ANTS_CHAIN_FORK_THETA_NUM > 0u);

    /* Sizes agree with foundation/crypto and the sibling reputation
     * modules (peer-id = Ed25519 pubkey, sig = Ed25519, hash = BLAKE3). */
    CHECK(ANTS_CHAIN_PEER_ID_SIZE == 32u);
    CHECK(ANTS_CHAIN_SIG_SIZE == 64u);
    CHECK(ANTS_CHAIN_HASH_SIZE == 32u);
    CHECK(ANTS_CHAIN_BLS_PUBKEY_SIZE == 48u);
    CHECK(ANTS_CHAIN_BLS_SIG_SIZE == 96u);

    /* Timing: slow on purpose, and the finality timeout exceeds the block
     * time (a block gets more than one block-time to finalise). */
    CHECK(ANTS_CHAIN_FINALITY_TIMEOUT_S > ANTS_CHAIN_BLOCK_TIME_S);

    /* The three fork-choice outcomes are distinct. */
    CHECK(ANTS_CHAIN_FORK_A != ANTS_CHAIN_FORK_B);
    CHECK(ANTS_CHAIN_FORK_A != ANTS_CHAIN_FORK_SOCIAL_SCHELLING);
    CHECK(ANTS_CHAIN_FORK_B != ANTS_CHAIN_FORK_SOCIAL_SCHELLING);

    CHECK(ANTS_CHAIN_T_FORK_CHOICE_CAP > 0u);
    CHECK(ANTS_CHAIN_MERKLE_MAX_DEPTH > 0u);
    CHECK(ANTS_CHAIN_MAX_PATTERN_FINDINGS > 0u);
}

/* Every entry point links and reports the scaffold state. */
static void test_stubs_not_implemented(void)
{
    uint8_t ids[2][ANTS_CHAIN_HASH_SIZE] = {{0}};
    uint8_t pks[2][ANTS_CHAIN_PEER_ID_SIZE] = {{0}};
    uint8_t root[ANTS_CHAIN_HASH_SIZE] = {0};
    uint8_t hash[ANTS_CHAIN_HASH_SIZE] = {0};
    uint8_t buf[256] = {0};
    uint8_t path[128] = {0};
    uint8_t sigs[2 * ANTS_CHAIN_SIG_SIZE] = {0};
    bool mask[2] = {true, true};
    size_t out_len = 0;
    size_t out_n = 0;
    bool out_ok = true;
    int winner = -1;
    uint64_t out_u64 = 0;

    ants_chain_epoch_summary_t summary;
    ants_chain_block_t block;
    ants_chain_pattern_finding_t findings[4];
    ants_chain_event_t events[2];
    memset(&summary, 0, sizeof summary);
    memset(&block, 0, sizeof block);
    memset(findings, 0, sizeof findings);
    memset(events, 0, sizeof events);

    /* PR2 — Merkle */
    CHECK_EQ(ants_chain_confirmed_root(ids, 2, root), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_confirmed_prove(ids, 2, 0, path, sizeof path, &out_len),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_confirmed_verify(ids[0], 0, 2, path, sizeof path, root, &out_ok),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* PR2 — EpochSummary codec */
    CHECK(ants_chain_epoch_summary_bound(&summary) == 0);
    CHECK_EQ(ants_chain_epoch_summary_encode(&summary, buf, sizeof buf, &out_len),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_epoch_summary_decode(buf, sizeof buf, &summary, findings, 4, &out_n),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* PR3 — pattern engine */
    CHECK_EQ(ants_chain_pattern_scan(events, 2, 0, findings, 4, &out_n),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* PR4 — committee selection */
    CHECK_EQ(ants_chain_committee_select(hash, root, 100, 16, &out_n, 1, &out_n),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* PR5 — block + finality */
    CHECK_EQ(ants_chain_block_hash(&block, hash), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(ants_chain_block_bound(&block) == 0);
    CHECK_EQ(ants_chain_block_encode(&block, buf, sizeof buf, &out_len),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_block_decode(buf, sizeof buf, &block, findings, 4, &out_n),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_finality_verify(hash, pks, 2, sigs, sizeof sigs, mask, &out_ok),
             ANTS_ERROR_NOT_IMPLEMENTED);

    /* PR6 — fork choice */
    {
        uint64_t tenures[2] = {1000, 2000};
        CHECK_EQ(ants_chain_fork_weight(tenures, 2, ANTS_CHAIN_T_FORK_CHOICE_CAP, &out_u64),
                 ANTS_ERROR_NOT_IMPLEMENTED);
    }
    CHECK_EQ(ants_chain_fork_choice(
                 10, 20, 100, ANTS_CHAIN_FORK_THETA_NUM, ANTS_CHAIN_FORK_THETA_DEN, &winner),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_constants();
    test_stubs_not_implemented();

    if (failures == 0) {
        printf("test_chain: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_chain: %d check(s) failed\n", failures);
    return 1;
}
