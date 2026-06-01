/*
 * bond.c — Bond accounting for high-stakes acts (Component #15, RFC-0004
 * v0.6 §"Bonds for high-stakes acts" + §"Bond accounting model").
 *
 * PR1: the local bond ledger — init / count / locked_total / find /
 * bondable_a / admit / release / slash, and additive multi-act composition.
 * Pure functions over a caller-owned fixed-capacity ledger: no malloc, no
 * float, no threads, no hidden state. `A` is supplied by the caller
 * (computed via reputation/identity's ants_reputation_compute); this module
 * owns only the locked-bond set and the headroom arithmetic.
 *
 * The bond formulas, the canonical-CBOR bond_admission object, and the
 * race-safe tie-break are PR2 — present but returning
 * ANTS_ERROR_NOT_IMPLEMENTED.
 *
 * Spec: RFC-0004 v0.6 §"Bond accounting model"; RFC-0008 v0.5 §6 (u64 μNCS),
 * §7 (constants).
 */

#include "ants_bond.h"

#include <string.h>

/* ------------------------------------------------------------------------ */
/* PR1 — the local bond ledger                                               */
/* ------------------------------------------------------------------------ */

void ants_bond_ledger_init(ants_bond_ledger_t *ledger)
{
    if (ledger != NULL) {
        ledger->count = 0;
    }
}

size_t ants_bond_count(const ants_bond_ledger_t *ledger)
{
    return ledger != NULL ? ledger->count : 0;
}

uint64_t ants_bond_locked_total(const ants_bond_ledger_t *ledger)
{
    uint64_t total = 0;
    size_t i;

    if (ledger == NULL) {
        return 0;
    }
    for (i = 0; i < ledger->count; i++) {
        uint64_t a = ledger->locked[i].amount;
        if (a > UINT64_MAX - total) {
            return UINT64_MAX; /* defensive: admission keeps the true sum < 2^64 */
        }
        total += a;
    }
    return total;
}

/* Index of `act_id` in the ledger, or -1 if absent. */
static ptrdiff_t bond_index(const ants_bond_ledger_t *ledger, const uint8_t *act_id)
{
    size_t i;
    for (i = 0; i < ledger->count; i++) {
        if (memcmp(ledger->locked[i].act_id, act_id, ANTS_BOND_ACT_ID_SIZE) == 0) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

const ants_bond_t *ants_bond_find(const ants_bond_ledger_t *ledger,
                                  const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE])
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL) {
        return NULL;
    }
    idx = bond_index(ledger, act_id);
    return idx < 0 ? NULL : &ledger->locked[idx];
}

ants_error_t
ants_bond_bondable_a(const ants_bond_ledger_t *ledger, uint64_t total_a, uint64_t *out_bondable)
{
    uint64_t locked;
    if (ledger == NULL || out_bondable == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    locked = ants_bond_locked_total(ledger);
    *out_bondable = total_a > locked ? total_a - locked : 0;
    return ANTS_OK;
}

ants_error_t ants_bond_admit(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t amount,
                             uint64_t t_start,
                             const uint8_t slash_target[ANTS_BOND_SIG_SIZE],
                             uint64_t total_a,
                             bool *out_admitted)
{
    uint64_t bondable;
    ants_bond_t *slot;

    if (ledger == NULL || act_id == NULL || slash_target == NULL || out_admitted == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* A given act bonds once. */
    if (bond_index(ledger, act_id) >= 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* t_release must not wrap. */
    if (t_start > UINT64_MAX - ANTS_BOND_DISPUTE_WINDOW_S) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (ledger->count >= ANTS_BOND_MAX_LOCKED) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Headroom is an economic verdict, not an error. */
    {
        uint64_t locked = ants_bond_locked_total(ledger);
        bondable = total_a > locked ? total_a - locked : 0;
    }
    if (bondable < amount) {
        *out_admitted = false;
        return ANTS_OK;
    }

    slot = &ledger->locked[ledger->count];
    memcpy(slot->act_id, act_id, ANTS_BOND_ACT_ID_SIZE);
    slot->amount = amount;
    slot->t_start = t_start;
    slot->t_release = t_start + ANTS_BOND_DISPUTE_WINDOW_S;
    memcpy(slot->slash_target, slash_target, ANTS_BOND_SIG_SIZE);
    ledger->count++;

    *out_admitted = true;
    return ANTS_OK;
}

/* Remove the bond at index `idx` by swapping the last entry into its slot. */
static void bond_remove_at(ants_bond_ledger_t *ledger, ptrdiff_t idx)
{
    size_t last = ledger->count - 1;
    if ((size_t)idx != last) {
        ledger->locked[idx] = ledger->locked[last];
    }
    ledger->count--;
}

ants_error_t ants_bond_release(ants_bond_ledger_t *ledger,
                               const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                               bool *out_found)
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    idx = bond_index(ledger, act_id);
    if (idx >= 0) {
        bond_remove_at(ledger, idx);
    }
    if (out_found != NULL) {
        *out_found = (idx >= 0);
    }
    return ANTS_OK;
}

ants_error_t ants_bond_slash(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t *out_amount,
                             bool *out_found)
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL || out_amount == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    idx = bond_index(ledger, act_id);
    if (idx >= 0) {
        *out_amount = ledger->locked[idx].amount;
        bond_remove_at(ledger, idx);
    } else {
        *out_amount = 0;
    }
    if (out_found != NULL) {
        *out_found = (idx >= 0);
    }
    return ANTS_OK;
}

/* ======================================================================== */
/* PR2 — bond formulas (stub)                                                */
/* ======================================================================== */

ants_error_t ants_bond_required_tier3(uint64_t query_stakes, uint64_t n, uint64_t *out)
{
    (void)query_stakes;
    (void)n;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bond_required_fork_recovery(uint64_t total_t_at_stake, uint64_t *out)
{
    (void)total_t_at_stake;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t
ants_bond_required_value_scaled(uint64_t value, uint64_t mult_num, uint64_t mult_den, uint64_t *out)
{
    (void)value;
    (void)mult_num;
    (void)mult_den;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ======================================================================== */
/* PR2 — bond_admission object + race-safe tie-break (stub)                  */
/* ======================================================================== */

ants_error_t ants_bond_admission_encode(const ants_bond_admission_t *adm,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len)
{
    (void)adm;
    (void)buf;
    (void)cap;
    (void)out_len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bond_admission_decode(const uint8_t *buf, size_t len, ants_bond_admission_t *out)
{
    (void)buf;
    (void)len;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_bond_tiebreak_key(const uint8_t epoch_seed[ANTS_BOND_HASH_SIZE],
                                    const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                                    const uint8_t v_id[ANTS_BOND_PEER_ID_SIZE],
                                    uint64_t admission_round,
                                    uint8_t out_key[ANTS_BOND_HASH_SIZE])
{
    (void)epoch_seed;
    (void)act_id;
    (void)v_id;
    (void)admission_round;
    (void)out_key;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

bool ants_bond_admission_wins(const uint8_t my_key[ANTS_BOND_HASH_SIZE],
                              const uint8_t other_key[ANTS_BOND_HASH_SIZE])
{
    (void)my_key;
    (void)other_key;
    return false;
}
