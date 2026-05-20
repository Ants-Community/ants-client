# bond — Component #15

Bond accounting service. Economy & coordination layer.
**On the critical path (tail).**

**Status:** pending claim.
**Effort:** 2 EM.
**Spec:** [RFC-0004 v0.6 §Bond accounting model + §Atomicity](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md).
**Dependencies:** `reputation/identity`, `reputation/crdt`, `foundation/crypto`.

## Scope

The bond accounting and admission service for high-stakes acts.

- `A` computation (delegated to `reputation/identity`).
- Bond admission with **race-safe protocol** per RFC-0004 §Atomicity:
  per-epoch `δ_admission` window (default 5 s) + BLAKE3 tie-break
  on `(epoch_seed, act_id, V_id, admission_round)`, no NTP
  dependency.
- Freeze of bond value at admission, no decay during hold.
- Release-back-as-fresh-contribution semantics (preventing
  decay-clock laundering).
- Multi-act composition (additive bonds sum).
- Bond-formula application per act class per RFC-0004 §Bond formulas
  (Tier 3 verification: `query_stakes / N`; fork-recovery: total `T`
  at stake; perennial cache write / settlement intermediation:
  multiplier-based per RFC-0008 §7 constants).

## Good-first-contribution flag

**Yes.** Per IMPLEMENTATION.md §"Parallelisable vs critical-path
work", this is one of three "small, scope-clear, test-cleanly"
first-contribution candidates. Although on the critical path tail,
the actual work is small once `reputation/identity` is in place.
