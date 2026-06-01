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
#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crypto.h"

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

/* Independent little-endian u64 writer for the tie-break cross-check. */
static void wr_le64(uint8_t out[8], uint64_t v)
{
    size_t i;
    for (i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (i * 8));
    }
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

/* ---- PR2: bond formulas, the bond_admission codec, the tie-break -------- */

static void test_formulas(void)
{
    uint64_t out = 0;

    /* Tier 3: query_stakes / N (floor). */
    CHECK_EQ(ants_bond_required_tier3(1000, 4, &out), ANTS_OK);
    CHECK(out == 250);
    CHECK_EQ(ants_bond_required_tier3(1000, 3, &out), ANTS_OK);
    CHECK(out == 333); /* floor(333.33) */
    CHECK_EQ(ants_bond_required_tier3(1000, 0, &out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_required_tier3(1000, 4, NULL), ANTS_ERROR_INVALID_ARG);

    /* Fork recovery: the whole T at stake. */
    CHECK_EQ(ants_bond_required_fork_recovery(123456789, &out), ANTS_OK);
    CHECK(out == 123456789);
    CHECK_EQ(ants_bond_required_fork_recovery(1, NULL), ANTS_ERROR_INVALID_ARG);

    /* Value-scaled: value * num / den (floor), overflow-safe. */
    CHECK_EQ(ants_bond_required_value_scaled(1000, 3, 2, &out), ANTS_OK);
    CHECK(out == 1500);
    CHECK_EQ(ants_bond_required_value_scaled(1000, 1, 1, &out), ANTS_OK);
    CHECK(out == 1000);
    CHECK_EQ(ants_bond_required_value_scaled(7, 1, 2, &out), ANTS_OK);
    CHECK(out == 3); /* floor(3.5) */
    CHECK_EQ(ants_bond_required_value_scaled(1000, 1, 0, &out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_required_value_scaled(1000, 1, 2, NULL), ANTS_ERROR_INVALID_ARG);
    /* x1 of UINT64_MAX fits; x2 overflows. */
    CHECK_EQ(ants_bond_required_value_scaled(UINT64_MAX, 1, 1, &out), ANTS_OK);
    CHECK(out == UINT64_MAX);
    CHECK_EQ(ants_bond_required_value_scaled(UINT64_MAX, 2, 1, &out), ANTS_ERROR_OVERFLOW);
}

static void test_admission_codec(void)
{
    ants_bond_admission_t in;
    ants_bond_admission_t out;
    uint8_t buf[ANTS_BOND_ADMISSION_ENCODED_MAX];
    uint8_t buf2[ANTS_BOND_ADMISSION_ENCODED_MAX + 1];
    size_t len = 0;
    size_t k;
    size_t i;

    memset(&in, 0, sizeof in);
    for (i = 0; i < 32; i++) {
        in.act_id[i] = (uint8_t)(i + 1);
        in.peer[i] = (uint8_t)(i + 40);
        in.v_id[i] = (uint8_t)(i + 80);
        in.l1_view_hash[i] = (uint8_t)(i * 3 + 1);
    }
    in.amount = 0xDEADBEEF12345678ull;

    CHECK_EQ(ants_bond_admission_encode(&in, buf, sizeof buf, &len), ANTS_OK);
    CHECK(len > 0 && len <= ANTS_BOND_ADMISSION_ENCODED_MAX);
    CHECK_EQ(ants_cbor_is_canonical(buf, len), ANTS_OK);

    memset(&out, 0, sizeof out);
    CHECK_EQ(ants_bond_admission_decode(buf, len, &out), ANTS_OK);
    CHECK(memcmp(out.act_id, in.act_id, 32) == 0);
    CHECK(memcmp(out.peer, in.peer, 32) == 0);
    CHECK(out.amount == in.amount);
    CHECK(memcmp(out.v_id, in.v_id, 32) == 0);
    CHECK(memcmp(out.l1_view_hash, in.l1_view_hash, 32) == 0);

    /* Truncation never yields OK. */
    for (k = 1; k < len; k++) {
        CHECK(ants_bond_admission_decode(buf, k, &out) != ANTS_OK);
    }
    /* Trailing byte → MALFORMED. */
    memcpy(buf2, buf, len);
    buf2[len] = 0x00;
    CHECK_EQ(ants_bond_admission_decode(buf2, len + 1, &out), ANTS_ERROR_MALFORMED);
    /* Wrong map size: map(5) 0xA5 → map(4) 0xA4. */
    memcpy(buf2, buf, len);
    CHECK(buf2[0] == 0xA5u);
    buf2[0] = 0xA4u;
    CHECK_EQ(ants_bond_admission_decode(buf2, len, &out), ANTS_ERROR_MALFORMED);
    /* NULL / empty. */
    CHECK_EQ(ants_bond_admission_encode(NULL, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_admission_decode(NULL, len, &out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_admission_decode(buf, 0, &out), ANTS_ERROR_INVALID_ARG);
}

static void test_tiebreak(void)
{
    uint8_t seed[32], act[32], vid[32];
    uint8_t k1[32], k2[32], ref[32];
    uint8_t le[8];
    ants_blake3_ctx_t h;
    size_t i;

    for (i = 0; i < 32; i++) {
        seed[i] = (uint8_t)(i + 1);
        act[i] = (uint8_t)(i + 50);
        vid[i] = (uint8_t)(i + 100);
    }

    /* Deterministic. */
    CHECK_EQ(ants_bond_tiebreak_key(seed, act, vid, 7, k1), ANTS_OK);
    CHECK_EQ(ants_bond_tiebreak_key(seed, act, vid, 7, k2), ANTS_OK);
    CHECK(memcmp(k1, k2, 32) == 0);

    /* Independent recompute via raw BLAKE3 derive_key. */
    CHECK_EQ(ants_blake3_init_derive(&h, "ants-v1-bond-tiebreak"), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, seed, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, act, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, vid, 32), ANTS_OK);
    wr_le64(le, 7);
    CHECK_EQ(ants_blake3_update(&h, le, 8), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, ref), ANTS_OK);
    CHECK(memcmp(k1, ref, 32) == 0);

    /* Round sensitivity. */
    CHECK_EQ(ants_bond_tiebreak_key(seed, act, vid, 8, k2), ANTS_OK);
    CHECK(memcmp(k1, k2, 32) != 0);

    /* NULL guards. */
    CHECK_EQ(ants_bond_tiebreak_key(NULL, act, vid, 7, k1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bond_tiebreak_key(seed, act, vid, 7, NULL), ANTS_ERROR_INVALID_ARG);

    /* admission_wins: the smaller key wins; equal does not; NULL loses. */
    {
        uint8_t a[32], b[32];
        memset(a, 0, 32);
        memset(b, 0, 32);
        a[0] = 1;
        b[0] = 2;
        CHECK(ants_bond_admission_wins(a, b) == true);
        CHECK(ants_bond_admission_wins(b, a) == false);
        CHECK(ants_bond_admission_wins(a, a) == false);
        CHECK(ants_bond_admission_wins(NULL, b) == false);
    }
}

int main(void)
{
    test_constants();
    test_accounting();
    test_admit_edges();
    test_formulas();
    test_admission_codec();
    test_tiebreak();

    if (failures == 0) {
        printf("test_bond: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_bond: %d check(s) failed\n", failures);
    return 1;
}
