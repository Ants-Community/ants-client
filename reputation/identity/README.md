# identity — Component #9

Identity & reputation service. Reputation & identity layer.

**Status:** pending claim.
**Effort:** 3 EM.
**Spec:** [RFC-0004 v0.6 §Tenure + §Bond accounting + §Selective disclosure](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md); [RFC-0005 §Multi-vendor reputation weighting](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md).
**Dependencies:** `foundation/crypto`, `foundation/cbor`, `foundation/tee`, `reputation/crdt`.

## Scope

The implementation of the (A, T, κ) spine and the bond-accounting
primitives the rest of the architecture depends on.

- **Receipt bag Merkle tree** for counterparty-countersigned receipts.
- **(A, T, κ) computation**: A (active, fast decay δ_A), T (tenure,
  slow decay δ_T), κ rate cap, all locally recomputable from receipts.
- **Bond accounting** per RFC-0004 v0.4+ §Bond accounting model:
  `bondable_A = total_A − Σ currently_locked_bonds`, freezing at
  admission value, no decay during hold, additive multi-act
  composition.
- **Race-safe bond admission** per RFC-0004 v0.5 §Atomicity:
  per-epoch `δ_admission` window + BLAKE3 tie-break on
  `(epoch_seed, act_id, V_id, admission_round)`, no clock-sync
  dependency.
- **Selective-disclosure protocol** per RFC-0004 v0.5 §Selective
  disclosure of receipts: Merkle inclusion proofs, lower-bound
  property, positive/negative asymmetry preserved.
- **Multi-vendor attestation lookups** via `foundation/tee`.

## Good-first-contribution flag

**No.** The (A, T, κ) computation is load-bearing for verifier
eligibility, bond capacity, and fork-choice. Claims from
contributors with prior reputation-system experience or
proof-system tooling.
