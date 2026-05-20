# cache/

The distributed memory of the network. Semantic cache routed by
LSH-derived shard keys, with the BGE-M3 canonical embedding model
pinned by hash.

**Effort:** ~6 engineer-months total. Depends on `network/` (DHT) +
`reputation/` (identity for write attestation).

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`semantic/`](./semantic) — Semantic cache, DHT-routed (#10) | 5 EM | RFC-0002 v0.4 | pending claim |
| [`embedding/`](./embedding) — Canonical embedding service (#11) | 1 EM | RFC-0002 v0.4 §The canonical embedding model + RFC-0008 §5 | pending claim |

The embedding service (#11) is one of the three "good first
contribution" components per IMPLEMENTATION.md §"Parallelisable vs
critical-path work" — it is mostly packaging an existing model
(BGE-M3) with the hash-verification check at startup.

The semantic cache (#10) is on the critical path *indirectly*: it
depends on `reputation/identity` (component #9) and on `network/`.
Cache itself does not block downstream components in the same way
the chain does.
