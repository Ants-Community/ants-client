# identity — Component #9

Identity & reputation service. Reputation & identity layer.

**Status:** the (A, T, κ) spine + saturating `T_eff` + the L1 slash gate + the full receipt-bag selective disclosure (Merkle commitment, inclusion proofs, and the `A ≥ b` subset recompute) implemented; compact summaries + bond-admission wiring pending.
**Effort:** 3 EM.
**Spec:** [RFC-0004 v0.6 §Tenure + §Bond accounting + §Selective disclosure](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md); [RFC-0005 §Multi-vendor reputation weighting](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md).
**Dependencies:** `foundation/crypto`, `foundation/cbor` — the library
links nothing else. The L1 slash gate takes its slash source as a
caller-supplied callback (canonically `reputation/crdt`'s
`ants_crdt_is_slashed`), so even `compute_checked` adds no link; the bag
Merkle uses only BLAKE3. Bond-admission and TEE attestation wiring will
involve `economy/bond` (#15) and `foundation/tee` at the call sites.

## Scope

The implementation of the (A, T, κ) spine and the bond-accounting
primitives the rest of the architecture depends on.

**Implemented (PR1 — the spine):**

- **The countersigned NCS receipt** (RFC-0004 §"The receipt that matters
  for tenure"): canonical-CBOR signed body (server, client, ncs_value,
  timestamp, nonce) + dual Ed25519 signatures; `verify` requires BOTH.
- **Deterministic fixed-point decay** — the spec-mandated alternative to
  non-deterministic float `exp()` (RFC-0004 §"A reference sketch": "the
  production code uses a fixed-point decay table — see RFC-0009"). Decay
  over k bins is `r^k` in q32 fixed-point, computed by **repeated
  multiplication** (the exact multiply sequence is the pinned recipe, since
  q32 multiply is not associative under truncation — binary exponentiation
  would give a different bit result and split tenure across peers).
  Bit-identical across platforms, so every honest peer computes the same
  `T_X`.
- **The (A, T) computation** (RFC-0004 §816 / §825): `A` = uncapped
  fast-decayed sum of verified receipts; `T` = per-bin, κ-clipped,
  slow-decayed sum. Invalid / wrong-server / future-dated receipts are
  skipped. No allocation; one stack bool array caches per-receipt
  validity so signatures are verified once.

> **Numeric constants are DRAFT placeholders, NOT calibrated.** RFC-0004
> §835 makes δ_A, δ_T, and κ b2-class testnet measurements. The
> fixed-point *recipe* is the deliverable; the ratio/κ/bin-width *values*
> are illustrative (so the code runs and tests). The recipe should be
> upstreamed to RFC-0004 (or an RFC-0009-style reputation-numerics
> section) and the values fixed by b2 before peers compute interoperable
> tenure.

**Implemented (PR2 — the saturating `T_eff` fork-choice transform,
RFC-0004 §"The saturating T → T_eff transform"):**

- **`ants_reputation_t_eff(t, t_cap)` = `t_cap · (1 − exp(−t/t_cap))`**,
  applied to tenure **for fork choice only** (raw `t` stays uncapped for
  verifier eligibility, bond capacity, persistence). Bounds the
  *relative* fork-choice weight of an arbitrarily old peer so the founder
  cohort cannot retain fork-choice dominance forever (long-tail
  centralisation). The caller sums `T_eff` over a fork's validators
  (`Σ T_eff`) to compare forks.
- **Deterministic, no float.** `exp(−t/t_cap)` is computed in pinned q32
  fixed-point by range reduction `t/t_cap = n + f`: `exp(−1)^n` via the
  PR1 repeated-multiplication `decay_factor` (base `exp(−1)` pinned in
  q32), `exp(−f)` for `f ∈ [0,1)` via a pinned 16-term Horner Taylor
  series; the fraction and final scaling use overflow-safe integer
  long-division / multiply-shift. The exact method is the canonical
  recipe — verified monotone (zero inversions over a 10·cap sweep),
  saturating to `t_cap` without exceeding it, linear for `t ≪ t_cap`, and
  bit-stable across calls. `T_CAP` (`T_FORK_CHOICE_CAP`, RFC-0008 §7) is
  a DRAFT placeholder, b2-class like δ/κ.

**Implemented — the L1 slash gate** (RFC-0004 §"How tenure interacts with
Layer 1"):

- **`ants_reputation_compute_checked`** zeroes a slashed peer's `A` AND `T`
  (a slashed identity is globally dead, §110) via a caller-supplied slash
  predicate — canonically `ants_crdt_is_slashed` over Component #7's live
  L1 G-Set, or the L2 chain index (default-to-slashed) for a late joiner.
  The library keeps no `crdt` dependency; the slash source is a callback.

**Implemented — receipt-bag Merkle commitment + inclusion proofs**
(RFC-0004 §"Selective disclosure of receipts"):

- **`ants_reputation_bag_root` / `_bag_prove` / `_bag_verify_inclusion`** —
  the receipt bag as a Merkle tree (the same domain-separated,
  promote-lone-trailing BLAKE3 scheme as `reputation/chain` and
  `inference/orchestration`). Each leaf commits a whole receipt (canonical
  body ‖ both signatures); canonical leaf order is (timestamp ASC, then
  leaf-hash ASC); `bag_root = derive_key("ants-v1-receipt-bag-root",
  peer_id ‖ merkle_root)` binds the tree to the committing peer. A peer
  proves a receipt is in its committed bag with an O(log n) inclusion path
  without revealing the rest of its history. Lower-bound soundness
  (revealing a subset understates, never overstates, `A`); fake receipts
  fail the separate countersignature check.
- **`ants_reputation_bag_select_for_bound` / `_bag_verify_bound`** — the
  `A ≥ b` proof (RFC-0004 §"Selective disclosure" steps 1-3): the prover
  selects a minimal most-recent-first subset reaching `b`; the verifier
  checks each revealed opening (countersignature + credits-this-peer +
  not-future-dated + distinct index + Merkle inclusion) and confirms the
  summed `A` contribution (the same decayed-value recipe as `compute`, so
  the two agree bit-for-bit) `≥ b`. A lower bound — a peer can understate
  but never overstate `A`.

**Pending (later PRs):**

- **Compact summaries** (RFC-0004 §"Selective disclosure of receipts"):
  signed `(time_bucket, Σ decayed_value)` hints for large bags, committed
  via the same Merkle root — an optimization (challengeable into individual
  receipts), not a security primitive.
- **Bond-admission wiring** into the real high-stakes-act call sites
  (Tier-3 committee per RFC-0003; L2 committee / fork-recovery vote per
  RFC-0004 §Layer 2) + the `bond_admission` L1 gossip. (Bond accounting
  itself is Component #15, `economy/bond`.)
- **Multi-vendor attestation lookups** via `foundation/tee` (RFC-0005).

## Good-first-contribution flag

**No.** The (A, T, κ) computation is load-bearing for verifier
eligibility, bond capacity, and fork-choice. Claims from
contributors with prior reputation-system experience or
proof-system tooling.
