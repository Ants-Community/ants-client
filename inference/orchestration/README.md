# orchestration — Component #13

Inference orchestration. Inference layer.
**On the critical path.**

**Status:** **feature-complete at v0.x** (BDFL interim primary; claim still open). Full API surface + opaque ctx + protocol constants in `include/ants_inference.h`. All four surfaces are implemented and tested (KAT + independent cross-checks under ASan/UBSan): surface 1 (commit-at-send) — per-position leaf hashing, the promote-lone-node Merkle root/prove/verify, canonical-CBOR commit encode/decode, and Ed25519 sign/verify; surface 2 (anti-grinding challenge derivation) — the three beacon-bound PRF derivations over a counter-mode BLAKE3 keystream; surface 3 (the betting e-process) — the anytime-valid capital recursion with a predictable plug-in bet and Ville-bounded slash, plus a total-variation discrepancy score over canonical q24 logits; surface 4 (the serving runtime) — a small DRAFT reference model built on the #12 kernels (a byte-vocabulary causal-attention next-token predictor), `init` / `serve` / `audit`, the shared `reference_distribution` seam, and the DRAFT answer-envelope codec. The producer commits, the verifier reruns and slashes: an honest answer passes, a tampered envelope is caught by the Merkle gate, and a disagreeing reference drives the e-process to FRAUD. The reference model's weight VALUES are illustrative (the canonical RECIPE is the deliverable); the answer-envelope and weight-blob wire formats are DRAFT pending RFC formalization.
**Effort:** 4 EM.
**Spec:** [RFC-0003 v0.2](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0003-verification.md), [RFC-0009 v0.5](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0009-canonical-numerics.md).
**Dependencies:** `inference/kernels`, `cache/embedding`, `cache/semantic`, `reputation/crdt`, `reputation/identity`.

## Scope

The runtime that does inference, commits to it, and dispatches audits.

- Model loading and request routing.
- **Fast-path serving** (the producer's chosen kernel for the user's experience).
- **Audited-path commit** — `Y_canon` per RFC-0009; commit-at-send object with Merkle root over per-position logit-distribution leaves per RFC-0003 §commit-at-send (Tier 2).
- **e-process audit verifier role** — the anytime-valid betting e-process per RFC-0003 §Tier 2 with beacon-bound challenge sub-protocol.
- **Tier 1 / Tier 2 / Tier 3 dispatch** per the requester's declared assurance level.

## Good-first-contribution flag

**No.** Orchestration glues the architecture's load-bearing layers.
Claims from contributors comfortable with at least four of the
upstream components or with comparable ML-serving experience.
