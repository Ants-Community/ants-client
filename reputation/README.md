# reputation/

The architecture's load-bearing layer: the L1 consensus-free CRDT of
self-authenticating fault proofs, the L2 PoUH chain as ordered
witness, and the (A, T, κ) spine with bond accounting and selective
disclosure.

**Effort:** ~13 engineer-months total. Depends on `foundation/` +
`network/`.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`crdt/`](./crdt) — L1 CRDT (G-Set) (#7) | 4 EM | RFC-0004 v0.6 §Layer 1 + §G-Set pruning + §Archive nodes | pending claim |
| [`chain/`](./chain) — L2 PoUH chain (#8) | 6 EM | RFC-0004 v0.6 §Layer 2 + §Partition recovery (Σ T_eff fork choice) | pending claim |
| [`identity/`](./identity) — Identity & reputation service (#9) | 3 EM | RFC-0004 v0.6 §Tenure + §Bond accounting + §Selective disclosure; RFC-0005 | pending claim |

The L2 PoUH chain (#8) is the **single longest implementation
deliverable in this layer**. It covers block production, BLS
aggregation (K > 16) + Ed25519 multi-sig (K ≤ 16), VRF committee
selection (ECVRF-ELL2 per RFC-0008 §4.2), epoch summary generation,
drand integration with degraded-seed failover, equivocation
slashing, and Σ T_eff fork choice with the saturating cap per
RFC-0004 §"The saturating T → T_eff transform".

This layer is **on the critical path** (per IMPLEMENTATION.md
§"Critical path"): the unbreakable chain is `#3 TEE harness → #7 L1
CRDT → #8 L2 chain → #13 inference orchestration → #15 bond
accounting`, totalling ~22 EM minimum wall-clock.
