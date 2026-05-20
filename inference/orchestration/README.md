# orchestration — Component #13

Inference orchestration. Inference layer.
**On the critical path.**

**Status:** pending claim.
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
