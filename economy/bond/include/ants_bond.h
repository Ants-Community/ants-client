/*
 * ants_bond.h — Bond accounting for high-stakes acts (Component #15,
 * RFC-0004 v0.6 §"Bonds for high-stakes acts" + §"Bond accounting model").
 *
 * Some acts have a one-shot payoff that can dominate the standard slash
 * value `S_NCS` — a Tier-3 medical/legal/financial verification, an L2
 * committee suppressing a pattern finding, a perennial high-value cache
 * write, a fork-recovery vote, a cross-economy settlement. For these the
 * standard "lose your tenure if caught" deterrent is not enough: an
 * attacker who accepts the slash still comes out ahead. The protocol closes
 * this by requiring the actor to **lock a bond of `A`** (active reputation)
 * before the act is admitted; a fault against the act during the dispute
 * window adds the bonded `A` to the slash, otherwise it is released.
 *
 * Why this binds (RFC-0004 §"Why this works"): `A` decays fast (δ_A, on the
 * scale of minutes) and so **cannot be accumulated in advance** — a peer's
 * available `A` is, by construction, ~proportional to its recent honest
 * contribution. A defector with mature `T` but neglected `A` cannot post
 * the bond; assembling it requires sustained fresh participation, which is
 * exactly the contribution the network wanted. Time is the resource that
 * cannot be bought, and `A` is its fresh expression.
 *
 * THIS MODULE is the local bond ledger + the admission protocol. `A` itself
 * is **delegated to reputation/identity** (#9): the caller computes
 * `A(peer, t)` from the receipt bag via ants_reputation_compute and passes
 * it in; this module owns the set of currently-locked bonds, the headroom
 * check (`bondable_A = A − Σ locks`), freeze / release / slash, additive
 * multi-act composition, and (PR2) the per-class bond formulas + the
 * canonical-CBOR `bond_admission` object + the race-safe tie-break.
 *
 * Scope by PR:
 *   PR1  the local accounting — this file's ledger type + init / locked_total
 *        / bondable_a / admit / release / slash / find. Pure, no deps, no
 *        malloc, no float.
 *   PR2  bond formulas per act class; the `bond_admission` canonical-CBOR
 *        object (signed by the verifier, gossiped to L1); the race-safe
 *        admission tie-break (BLAKE3 derive_key, no clock-sync). Stubbed
 *        here, returning ANTS_ERROR_NOT_IMPLEMENTED.
 *
 * Numeric tunables (the dispute window, δ_admission, the formula risk
 * multipliers) are DRAFT b2-class — RFC-0008 §7; the recipes are the
 * deliverable, the values illustrative. The bond_admission wire format is
 * DRAFT pending RFC-0008.
 *
 * Spec: RFC-0004 v0.6 §"Bonds…" / §"Bond accounting model"; RFC-0008 v0.5
 * §6 (NCS as u64 μNCS), §1.1 (canonical CBOR), §2.1 (BLAKE3), §7 (constants).
 * Component README: ants-client/economy/bond/README.md.
 */

#ifndef ANTS_BOND_H
#define ANTS_BOND_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Sizes                                                                     */
/* ------------------------------------------------------------------------ */

/* A peer / verifier id is its 32-byte Ed25519 public key (matches
 * ANTS_REP_PEER_ID_SIZE). */
#define ANTS_BOND_PEER_ID_SIZE 32u

/* An act id — a 32-byte identifier of the specific high-stakes act being
 * bonded (e.g. BLAKE3 over the act's defining fields). A given act bonds
 * once; the ledger is keyed on it. */
#define ANTS_BOND_ACT_ID_SIZE 32u

/* The L1 fault-proof signature (Ed25519, 64 B) that would trigger this
 * bond's slash if filed — stored with the bond per the RFC-0004 tuple. */
#define ANTS_BOND_SIG_SIZE 64u

/* BLAKE3-256 digest: the L1-view hash carried in a bond_admission, and the
 * tie-break key (matches ANTS_BLAKE3_HASH_SIZE). */
#define ANTS_BOND_HASH_SIZE 32u

/* ------------------------------------------------------------------------ */
/* Tunables — DRAFT b2-class (RFC-0008 §7)                                   */
/* ------------------------------------------------------------------------ */

/* The dispute window a bond is held for after admission (RFC-0004
 * §"Freezing the bond", default 7 days). A fault for the act within
 * [t_start, t_start + window] slashes the bond; otherwise it releases. */
#define ANTS_BOND_DISPUTE_WINDOW_S 604800u /* 7 days */

/* The race-safe admission propagation delay δ_admission (RFC-0004
 * §"Atomicity", default 5 s for time-sensitive acts) — how long an
 * admitting verifier waits to observe a conflicting admission before
 * finalising. Used by the PR2 tie-break protocol. */
#define ANTS_BOND_ADMISSION_DELAY_S 5u

/* Max simultaneous locked bonds the caller-owned ledger holds. A peer with
 * more than this many high-stakes acts in flight is pathological. */
#define ANTS_BOND_MAX_LOCKED 32u

/* ------------------------------------------------------------------------ */
/* Act classes (the §"Bond formulas" ladder)                                 */
/* ------------------------------------------------------------------------ */

/*
 * The high-stakes act classes, each with its own bond formula (PR2).
 * Integer-stable and append-only like ants_error_t: a deployed value never
 * changes its number, so a peer meeting a future class it does not
 * implement treats it as unknown rather than mis-pricing the bond.
 */
#define ANTS_BOND_ACT_TIER3_VERIFY    1u /* bond = query_stakes / N per member */
#define ANTS_BOND_ACT_L2_COMMITTEE    2u /* bond = c_committee * pending_findings */
#define ANTS_BOND_ACT_PERENNIAL_CACHE 3u /* bond = lifetime royalty * risk mult  */
#define ANTS_BOND_ACT_FORK_RECOVERY   4u /* bond = total T at stake (pre-fault)  */
#define ANTS_BOND_ACT_SETTLEMENT      5u /* bond = settlement value * risk mult  */
#define ANTS_BOND_ACT__RESERVED_MIN   6u

/* ------------------------------------------------------------------------ */
/* The locked-bond record + ledger                                           */
/* ------------------------------------------------------------------------ */

/*
 * A single locked bond, the RFC-0004 §"Freezing the bond" tuple. `amount`
 * is frozen at its admitted value for the whole hold — it does NOT decay
 * (the locked portion is conceptually in escrow). `t_release = t_start +
 * ANTS_BOND_DISPUTE_WINDOW_S`.
 */
typedef struct {
    uint8_t act_id[ANTS_BOND_ACT_ID_SIZE];
    uint64_t amount;    /* μNCS, frozen at admission                         */
    uint64_t t_start;   /* unix seconds, admission time                      */
    uint64_t t_release; /* unix seconds, end of the dispute window           */
    uint8_t slash_target[ANTS_BOND_SIG_SIZE]; /* the fault sig that slashes */
} ants_bond_t;

/*
 * The caller-owned bond ledger: a peer's set of currently-locked bonds. A
 * fixed-capacity transparent struct (the locks are few and the values are
 * observable state), zero-initialised by ants_bond_ledger_init. No malloc.
 */
typedef struct {
    size_t count;
    ants_bond_t locked[ANTS_BOND_MAX_LOCKED];
} ants_bond_ledger_t;

/* Zero a ledger to the empty state. NULL is a no-op. */
void ants_bond_ledger_init(ants_bond_ledger_t *ledger);

/* Number of currently-locked bonds (0 if NULL). */
size_t ants_bond_count(const ants_bond_ledger_t *ledger);

/*
 * Σ of all currently-locked bond amounts (RFC-0004 §"Multi-act
 * composition": locks are additive). 0 if NULL; saturates at UINT64_MAX
 * (the admission check keeps the true sum ≤ A < 2^64, so saturation is a
 * defensive bound, not an expected path).
 */
uint64_t ants_bond_locked_total(const ants_bond_ledger_t *ledger);

/*
 * The bond record for `act_id`, or NULL if not locked. The pointer aliases
 * ledger storage and is invalidated by the next admit/release/slash.
 */
const ants_bond_t *ants_bond_find(const ants_bond_ledger_t *ledger,
                                  const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE]);

/*
 * Bondable `A` at the caller's supplied total `A(peer, t)`:
 * `bondable = max(0, total_a − locked_total)` (RFC-0004 §"Bondable A vs
 * total A"). Clamps at 0: `A` decays while locked amounts stay frozen, so
 * `A` can legitimately fall below `locked_total` mid-hold.
 *
 * @return ANTS_OK with *out_bondable set; INVALID_ARG on NULL.
 */
ants_error_t
ants_bond_bondable_a(const ants_bond_ledger_t *ledger, uint64_t total_a, uint64_t *out_bondable);

/*
 * Admit a bond of `amount` μNCS for `act_id` at `t_start`, given the peer's
 * current total `A` (`total_a`, computed by the caller via
 * ants_reputation_compute). The bond is admitted iff there is headroom:
 * `bondable_a(total_a) ≥ amount`. On admission the lock
 * `(act_id, amount, t_start, t_start + DISPUTE_WINDOW, slash_target)` enters
 * the ledger, frozen at `amount`.
 *
 * Insufficient headroom is a VERDICT, not an error: *out_admitted = false,
 * return ANTS_OK. The peer must wait for `A` to grow or a bond to release.
 *
 * @return ANTS_OK with *out_admitted set (true ⇒ lock added); INVALID_ARG on
 *         NULL, an already-locked act_id, or t_start + window overflowing;
 *         BUFFER_TOO_SMALL if the ledger is full (ANTS_BOND_MAX_LOCKED).
 */
ants_error_t ants_bond_admit(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t amount,
                             uint64_t t_start,
                             const uint8_t slash_target[ANTS_BOND_SIG_SIZE],
                             uint64_t total_a,
                             bool *out_admitted);

/*
 * Release the bond for `act_id` cleanly (no fault filed): remove the lock.
 * The released `A` is NOT a fresh contribution — it was a temporary
 * withdrawal from the decaying pool, so removing the lock simply restores
 * the headroom; the decay clock the caller's receipt bag already reflects
 * is unchanged (RFC-0004 §"Release and slash": holding gains no decay-clock
 * advantage).
 *
 * @return ANTS_OK with *out_found set (optional); INVALID_ARG on NULL.
 */
ants_error_t ants_bond_release(ants_bond_ledger_t *ledger,
                               const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                               bool *out_found);

/*
 * Slash the bond for `act_id` (a fault proof for it was propagated in L1
 * during the hold): remove the lock and report its frozen `amount` in
 * *out_amount — the value the caller adds to the standard reputation slash
 * (RFC-0004 §"Release and slash"). *out_amount is 0 if the act_id was not
 * locked.
 *
 * @return ANTS_OK with *out_amount set (and *out_found if non-NULL);
 *         INVALID_ARG on NULL ledger/act_id/out_amount.
 */
ants_error_t ants_bond_slash(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t *out_amount,
                             bool *out_found);

/* ======================================================================== */
/* PR2 — bond formulas per act class                                         */
/* ======================================================================== */

/*
 * Tier-3 verification committee member: bond = `query_stakes / N` per member
 * (if all N collude on an act worth query_stakes, the total bonded A slashed
 * equals the act's worth, so EV ≤ 0). N ≥ 1.
 *
 * @return ANTS_OK with *out set; INVALID_ARG on NULL or N 0.
 */
ants_error_t ants_bond_required_tier3(uint64_t query_stakes, uint64_t n, uint64_t *out);

/*
 * Fork-recovery vote: bond = the total `T` at stake as of the pre-fault
 * agreed state (the maximum case — the architecture's fixed point depends on
 * this vote not going rogue).
 *
 * @return ANTS_OK with *out set; INVALID_ARG on NULL.
 */
ants_error_t ants_bond_required_fork_recovery(uint64_t total_t_at_stake, uint64_t *out);

/*
 * Value-scaled classes (perennial cache write, settlement intermediation):
 * bond = `value · mult_num / mult_den` (lifetime royalty / settlement value
 * times a risk multiplier), computed overflow-safe.
 *
 * @return ANTS_OK with *out set; INVALID_ARG on NULL or mult_den 0;
 *         OVERFLOW if value · mult_num / mult_den exceeds UINT64_MAX.
 */
ants_error_t ants_bond_required_value_scaled(uint64_t value,
                                             uint64_t mult_num,
                                             uint64_t mult_den,
                                             uint64_t *out);

/* ======================================================================== */
/* PR2 — the bond_admission object + race-safe tie-break                     */
/* ======================================================================== */

/*
 * The verifier-signed admission record gossiped to L1 (RFC-0004
 * §"Atomicity"): which verifier admitted which peer's bond for which act,
 * against which L1 view. Other peers verify the signature and observe the
 * lock; a conflicting admission within δ_admission triggers the tie-break.
 */
typedef struct {
    uint8_t act_id[ANTS_BOND_ACT_ID_SIZE];
    uint8_t peer[ANTS_BOND_PEER_ID_SIZE];
    uint64_t amount;
    uint8_t v_id[ANTS_BOND_PEER_ID_SIZE];      /* the admitting verifier */
    uint8_t l1_view_hash[ANTS_BOND_HASH_SIZE]; /* current_L1_view_hash   */
} ants_bond_admission_t;

/* A safe upper bound for ants_bond_admission_encode. */
#define ANTS_BOND_ADMISSION_ENCODED_MAX 160u

/*
 * Encode / decode a bond_admission as canonical CBOR (RFC-0008 §1.1) — the
 * exact bytes the verifier's signature covers. map(5), integer keys
 * ascending, float-free.
 *
 * @return ANTS_OK with *out_len / *out set; INVALID_ARG on NULL;
 *         BUFFER_TOO_SMALL (encode) or MALFORMED / NON_CANONICAL (decode).
 */
ants_error_t ants_bond_admission_encode(const ants_bond_admission_t *adm,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len);
ants_error_t ants_bond_admission_decode(const uint8_t *buf, size_t len, ants_bond_admission_t *out);

/*
 * The race-safe admission tie-break key (RFC-0004 §"Atomicity"):
 * `BLAKE3.derive_key("ants-v1-bond-tiebreak", epoch_seed ‖ act_id ‖ v_id ‖
 * LE64(admission_round))`. When two verifiers admit conflicting bonds for
 * the same peer within δ_admission, the admission with the SMALLER key (by
 * bytewise compare) wins; the loser gossips a bond_admission_null. The
 * epoch_seed input (from the L2 chain) prevents a peer precomputing
 * favourable timings; the protocol needs only loose clock-sync (agreement
 * on the current epoch + seed), not wall-clock milliseconds.
 *
 * @return ANTS_OK with `out_key` set; INVALID_ARG on NULL.
 */
ants_error_t ants_bond_tiebreak_key(const uint8_t epoch_seed[ANTS_BOND_HASH_SIZE],
                                    const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                                    const uint8_t v_id[ANTS_BOND_PEER_ID_SIZE],
                                    uint64_t admission_round,
                                    uint8_t out_key[ANTS_BOND_HASH_SIZE]);

/*
 * True iff `my_key` wins the tie-break against `other_key` (strictly
 * smaller, bytewise). Equal keys (the same admission) do not "win" — false.
 */
bool ants_bond_admission_wins(const uint8_t my_key[ANTS_BOND_HASH_SIZE],
                              const uint8_t other_key[ANTS_BOND_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_BOND_H */
