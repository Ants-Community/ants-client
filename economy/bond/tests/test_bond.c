/*
 * test_bond.c — Tests for bond accounting (Component #15).
 *
 * PR1 behavioural tests over the local ledger: admission headroom
 * (`bondable_A = A − Σ locks`), the RFC-0004 §"Multi-act composition"
 * worked example (A=1000, two 300-locks → bondable 400, a third 500-act
 * refused), freeze (t_release = t_start + dispute window, slash_target
 * stored), release vs slash (the slashed amount is reported), the clamp when
 * `A` decays below the locked total, the full-ledger and overflow guards,
 * and the NULL guards. Expected values are computed by hand (independent of
 * the impl). PR2 entry points are contract-checked as NOT_IMPLEMENTED, and
 * the act-class + size constants hold their invariants.
 */

#include "ants_bond.h"
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

static void make_act(uint8_t act_id[ANTS_BOND_ACT_ID_SIZE], uint8_t byte)
{
    memset(act_id, 0, ANTS_BOND_ACT_ID_SIZE);
    act_id[0] = byte;
}

static void test_constants(void)
{
    CHECK(ANTS_BOND_ACT_TIER3_VERIFY < ANTS_BOND_ACT_L2_COMMITTEE);
    CHECK(ANTS_BOND_ACT_L2_COMMITTEE < ANTS_BOND_ACT_PERENNIAL_CACHE);
    CHECK(ANTS_BOND_ACT_PERENNIAL_CACHE < ANTS_BOND_ACT_FORK_RECOVERY);
    CHECK(ANTS_BOND_ACT_FORK_RECOVERY < ANTS_BOND_ACT_SETTLEMENT);
    CHECK(ANTS_BOND_ACT_SETTLEMENT < ANTS_BOND_ACT__RESERVED_MIN);

    CHECK(ANTS_BOND_PEER_ID_SIZE == 32u);
    CHECK(ANTS_BOND_ACT_ID_SIZE == 32u);
    CHECK(ANTS_BOND_SIG_SIZE == 64u);
    CHECK(ANTS_BOND_HASH_SIZE == 32u);
    CHECK(ANTS_BOND_MAX_LOCKED > 0u);
    CHECK(ANTS_BOND_DISPUTE_WINDOW_S > 0u);
    CHECK(ANTS_BOND_ADMISSION_DELAY_S > 0u);
}

static void test_accounting(void)
{
    ants_bond_ledger_t L;
    uint8_t st[ANTS_BOND_SIG_SIZE];
    uint8_t a1[32], a2[32], a3[32];
    bool ad = false;
    bool found = false;
    uint64_t bd = 0;
    uint64_t amt = 0;

    memset(st, 0xAA, sizeof st);
    make_act(a1, 1);
    make_act(a2, 2);
    make_act(a3, 3);

    ants_bond_ledger_init(&L);
    CHECK(ants_bond_count(&L) == 0);
    CHECK(ants_bond_locked_total(&L) == 0);
    CHECK_EQ(ants_bond_bondable_a(&L, 1000, &bd), ANTS_OK);
    CHECK(bd == 1000);

    /* Admit a1 = 300 against A = 1000. */
    CHECK_EQ(ants_bond_admit(&L, a1, 300, 1000, st, 1000, &ad), ANTS_OK);
    CHECK(ad);
    CHECK(ants_bond_count(&L) == 1);
    CHECK(ants_bond_locked_total(&L) == 300);
    CHECK_EQ(ants_bond_bondable_a(&L, 1000, &bd), ANTS_OK);
    CHECK(bd == 700);
    {
        const ants_bond_t *b = ants_bond_find(&L, a1);
        CHECK(b != NULL);
        CHECK(b->amount == 300);
        CHECK(b->t_start == 1000);
        CHECK(b->t_release == 1000 + ANTS_BOND_DISPUTE_WINDOW_S);
        CHECK(memcmp(b->slash_target, st, ANTS_BOND_SIG_SIZE) == 0);
    }

    /* Multi-act composition (RFC-0004 worked example): a second 300 lock
     * leaves bondable 400; a third act needing 500 is refused; an exact-fit
     * 400 act is admitted. */
    CHECK_EQ(ants_bond_admit(&L, a2, 300, 1000, st, 1000, &ad), ANTS_OK);
    CHECK(ad);
    CHECK(ants_bond_locked_total(&L) == 600);

    CHECK_EQ(ants_bond_admit(&L, a3, 500, 1000, st, 1000, &ad), ANTS_OK);
    CHECK(!ad); /* 400 headroom < 500 */
    CHECK(ants_bond_count(&L) == 2);

    CHECK_EQ(ants_bond_admit(&L, a3, 400, 1000, st, 1000, &ad), ANTS_OK);
    CHECK(ad);
    CHECK(ants_bond_locked_total(&L) == 1000);
    CHECK_EQ(ants_bond_bondable_a(&L, 1000, &bd), ANTS_OK);
    CHECK(bd == 0);

    /* A bonds once: re-admitting a locked act_id is a caller error. */
    CHECK_EQ(ants_bond_admit(&L, a1, 1, 1000, st, 100000, &ad), ANTS_ERROR_INVALID_ARG);

    /* bondable clamps to 0 when A decays below the frozen locked total. */
    CHECK_EQ(ants_bond_bondable_a(&L, 500, &bd), ANTS_OK);
    CHECK(bd == 0);

    /* Slash a1 → its frozen 300 is reported, lock removed. */
    CHECK_EQ(ants_bond_slash(&L, a1, &amt, &found), ANTS_OK);
    CHECK(found);
    CHECK(amt == 300);
    CHECK(ants_bond_count(&L) == 2);
    CHECK(ants_bond_find(&L, a1) == NULL);
    CHECK(ants_bond_locked_total(&L) == 700);

    /* Release a2 cleanly → lock removed, headroom restored. */
    CHECK_EQ(ants_bond_release(&L, a2, &found), ANTS_OK);
    CHECK(found);
    CHECK(ants_bond_count(&L) == 1);
    CHECK(ants_bond_locked_total(&L) == 400);

    /* Release / slash an absent act → not found, no change, amount 0. */
    CHECK_EQ(ants_bond_release(&L, a1, &found), ANTS_OK);
    CHECK(!found);
    CHECK_EQ(ants_bond_slash(&L, a1, &amt, &found), ANTS_OK);
    CHECK(!found);
    CHECK(amt == 0);
    CHECK(ants_bond_count(&L) == 1);
}

static void test_admit_edges(void)
{
    ants_bond_ledger_t L;
    uint8_t st[ANTS_BOND_SIG_SIZE];
    uint8_t act[32];
    bool ad = false;
    bool found = false;
    uint64_t bd = 0;
    uint64_t amt = 0;
    size_t i;

    memset(st, 0x11, sizeof st);

    /* Full ledger → BUFFER_TOO_SMALL on the next admit. */
    ants_bond_ledger_init(&L);
    for (i = 0; i < ANTS_BOND_MAX_LOCKED; i++) {
        make_act(act, (uint8_t)i);
        CHECK_EQ(ants_bond_admit(&L, act, 1, 1000, st, 1000, &ad), ANTS_OK);
        CHECK(ad);
    }
    CHECK(ants_bond_count(&L) == ANTS_BOND_MAX_LOCKED);
    make_act(act, 200);
    CHECK_EQ(ants_bond_admit(&L, act, 1, 1000, st, 1000, &ad), ANTS_ERROR_BUFFER_TOO_SMALL);

    /* t_start + window overflow → INVALID_ARG. */
    ants_bond_ledger_init(&L);
    make_act(act, 1);
    CHECK_EQ(ants_bond_admit(&L, act, 1, UINT64_MAX, st, 1000, &ad), ANTS_ERROR_INVALID_ARG);

    /* NULL guards. */
    CHECK_EQ(ants_bond_admit(NULL, act, 1, 1000, st, 1000, &ad), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_admit(&L, NULL, 1, 1000, st, 1000, &ad), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_admit(&L, act, 1, 1000, NULL, 1000, &ad), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_admit(&L, act, 1, 1000, st, 1000, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_bondable_a(NULL, 1000, &bd), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_bondable_a(&L, 1000, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_release(NULL, act, &found), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_release(&L, NULL, &found), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_slash(&L, act, NULL, &found), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_slash(NULL, act, &amt, &found), ANTS_ERROR_INVALID_ARG);
    CHECK(ants_bond_count(NULL) == 0);
    CHECK(ants_bond_locked_total(NULL) == 0);
    CHECK(ants_bond_find(NULL, act) == NULL);
    CHECK(ants_bond_find(&L, NULL) == NULL);
}

static void test_pr2_stubs(void)
{
    uint64_t out = 0;
    uint8_t buf[ANTS_BOND_ADMISSION_ENCODED_MAX];
    size_t olen = 0;
    ants_bond_admission_t adm;
    uint8_t key[ANTS_BOND_HASH_SIZE] = {0};
    uint8_t seed[ANTS_BOND_HASH_SIZE] = {0};
    uint8_t aid[ANTS_BOND_ACT_ID_SIZE] = {0};
    uint8_t vid[ANTS_BOND_PEER_ID_SIZE] = {0};

    memset(&adm, 0, sizeof adm);
    memset(buf, 0, sizeof buf);

    CHECK_EQ(ants_bond_required_tier3(1000, 4, &out), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bond_required_fork_recovery(1000, &out), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bond_required_value_scaled(1000, 1, 2, &out), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bond_admission_encode(&adm, buf, sizeof buf, &olen), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bond_admission_decode(buf, sizeof buf, &adm), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bond_tiebreak_key(seed, aid, vid, 0, key), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(ants_bond_admission_wins(key, key) == false); /* stub */
}

int main(void)
{
    test_constants();
    test_accounting();
    test_admit_edges();
    test_pr2_stubs();

    if (failures == 0) {
        printf("test_bond: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_bond: %d check(s) failed\n", failures);
    return 1;
}
