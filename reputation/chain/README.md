# chain — Component #8

L2 PoUH chain. Reputation & identity layer.
**On the critical path. The single longest implementation deliverable in this layer.**

**Status:** PR1 — scaffold. The full public surface, the protocol structs
(`EpochSummary`, `PatternFinding`, `Block`) and tunable constants are in;
every entry point is present and returns `ANTS_ERROR_NOT_IMPLEMENTED` until
its PR lands (see the PR map in [`ants_chain.h`](include/ants_chain.h)).
Founder interim primary; CLAIM open.
**Effort:** 6 EM.
**Spec:** [RFC-0004 v0.6 §Layer 2](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md), §Partition recovery (incl. saturating Σ T_eff fork choice + equivocation slashing + social-Schelling fallback).
**Dependencies:** `foundation/crypto` (BLS, Ed25519, ECVRF-ELL2), `reputation/crdt`.

## Scope

The Proof-of-Unique-Hardware blockchain that acts as **ordered
witness** over the L1 CRDT.

- Block production with epoch-atomic signature scheme: Ed25519
  multi-sig (`K ≤ BLS_TRANSITION_K = 16`) or BLS12-381 aggregate
  (`K > 16`) per RFC-0008 §3.3 with the v0.4 disambiguation.
- VRF committee selection via **ECVRF-EDWARDS25519-SHA512-ELL2** (RFC
  9381) per RFC-0008 §4.2.
- Epoch summary generation with Merkle root over L1 fault proofs
  cut at epoch boundary.
- **drand integration with degraded-seed failover** per RFC-0008
  §4.3; `DRAND_OUTAGE_EMERGENCY_THRESHOLD` (6 hours) triggers
  emergency-response posture.
- **Equivocation slashing** as self-authenticating L1 fault per
  RFC-0004 §Partition recovery §Equivocation slashing.
- **Σ T_eff fork choice** with `T_FORK_CHOICE_CAP` saturating
  transform per RFC-0004 v0.6 §"The saturating T → T_eff transform".
- Social-Schelling fallback when both forks have
  `Σ T_eff > θ · Σ T_eff,total`.

## Good-first-contribution flag

**No.** Chain correctness is the most-audited surface in the corpus.
Claims from contributors with prior BFT-chain experience (Tendermint
Core, Cosmos SDK, Solana, Aptos, Sui, Polkadot, Lighthouse, Reth).
