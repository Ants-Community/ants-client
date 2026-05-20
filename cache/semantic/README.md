# semantic — Component #10

Semantic cache (DHT-routed). Cache layer.

**Status:** pending claim.
**Effort:** 5 EM.
**Spec:** [RFC-0002 v0.4](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-semantic-cache.md).
**Dependencies:** `network/dht`, `reputation/identity`, `cache/embedding`.

## Scope

The distributed content-addressable cache layer.

- LSH shard-key routing via `network/dht`.
- Local shard storage with FAISS-style cosine-similarity lookup
  (or hand-rolled equivalent if linking FAISS proves heavy for the
  embedded/mobile build targets).
- Replication factor `CACHE_REPLICATION_FACTOR` (default 3).
- Write protocol with producer attestation per RFC-0002 §The write protocol.
- Lookup protocol with similarity-threshold + multi-shard aggregation
  per RFC-0002 §The lookup protocol.
- Eviction policy + decay by validity class.
- Quality signal aggregation (positive/negative signed events).
- **Cross-economy royalty accounting** with `PRODUCER_ROYALTY_FRACTION`
  (default 65%, 60–70% band, Round 3) — note: this is the per-retrieval
  fee split, *not* the verifiability tax (which is one-time at
  fresh-inference time; see RFC-0002 v0.4 §"The verifiability tax and
  the royalty split do not compound at the producer's detriment").

## Good-first-contribution flag

**No** (medium-large scope), but lower barrier than #7/#8. Suitable
for contributors comfortable with distributed storage and
content-addressing.
