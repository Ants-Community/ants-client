# embedding — Component #11

Canonical embedding service. Cache layer.

**Status:** pending claim.
**Effort:** 1 EM.
**Spec:** [RFC-0002 §The canonical embedding model](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-semantic-cache.md), [RFC-0008 §5](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md).
**Dependencies:** `foundation/crypto` (BLAKE3 for hash verification).

## Scope

Inference of the canonical embedding model with bit-exact
hash-verification at startup.

- BGE-M3 (or whichever model is pinned as `ants-embed-v1` at v0.1
  launch) loaded from a pinned checkpoint.
- `embedding_model_weights_hash` verified against the pinned BLAKE3
  hash per RFC-0008 §5. Mismatch → refuse to start.
- `embedding_model_tokenizer_hash` likewise verified.
- API: `ants_embed(input_bytes, len) → float32[1024]`.

The component is mostly *packaging* an existing model — BGE-M3
inference in C via `ggml` (since the canonical embedding model is
small enough to fit in `ggml`'s primitives) or via a focused
embedded inference loop.

## Good-first-contribution flag

**Yes.** Per IMPLEMENTATION.md §"Parallelisable vs critical-path
work", this is one of three "small, scope-clear, test-cleanly"
first-contribution candidates. Suitable for contributors familiar
with embedding models and willing to learn `ggml`'s API.
