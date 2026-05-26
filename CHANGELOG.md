# ants-client CHANGELOG

A record of substantive changes to the reference client. Per the spec
repo's CHANGELOG discipline, this records *what changed*, *what is
now*, and *why* — not just commit summaries.

This CHANGELOG covers **implementation** changes only. **Protocol**
changes (RFC amendments, manifesto edits, governance updates) live in
the spec repo's
[`spec/CHANGELOG.md`](https://github.com/Ants-Community/ants/blob/main/spec/CHANGELOG.md).

---

## Unreleased

### cache: Component #10 (semantic cache) — Ed25519 producer-signature verify · 2026-05-26

**The cache no longer admits unsigned (or tampered) entries.** The
long-standing TODO in `handle_inbound_entry` is closed: every inbound
cache-entry record is now verified against the producer's Ed25519
public key before the record touches the local shard, per RFC-0002
§The cache entry. An invalid or missing signature returns
`MALFORMED`; the entry is never `put_record`'d.

**PR #67 — Ed25519 producer-signature verify** (+223/-18):

- `entry_emit` in `cache_wire.c` gains an `include_signature` flag.
  Public `entry_encode` and `lookup_response_encode` continue to emit
  the canonical `map(10)` (the on-wire record); the new signing path
  emits `map(9)` over fields 1..9 only — the exact byte sequence the
  producer signs.
- New module-private helper `cache_entry_emit_signing_payload(entry,
  buf, cap, *out_len)` — not in the public header; forward-declared
  via `extern` in `cache.c`. Caller passes a buffer at least as large
  as the full record's CBOR (the signing payload is always smaller —
  it drops the 67-byte signature field), so `cbor_len` is a safe
  upper bound for the allocation in `handle_inbound_entry`. The
  helper is also re-used by the test fixture to construct properly-
  signed records.
- `handle_inbound_entry` malloc's a `cbor_len`-byte scratch, emits
  the signing payload, runs `ants_ed25519_verify(producer, payload,
  signature)`, frees the scratch. On verify failure the
  `MALFORMED` (or other) error from the crypto routine is returned
  verbatim and the record is never admitted.

**Test fixtures**:
- New `fill_signed_test_entry(e, emb, response, resp_model, priv)` —
  builds a record whose `producer` matches `pub(priv)` and whose
  `signature` is the actual Ed25519 signature over the canonical
  signing payload. Used by every test that drives
  `handle_inbound_entry`.
- New `make_test_priv(priv, seed_byte)` — deterministic 32-byte
  private keys for reproducible tests.

**3 tests** (1 updated, 2 new):
- `test_handle_inbound_entry_round_trip` updated to use the signed
  fixture (would otherwise fail under the new gate because the
  pre-existing `fill_test_entry` produces a stub `0xD0..0xDF`
  signature).
- `test_handle_inbound_entry_rejects_tampered_signature` — flip one
  bit of `entry.signature` → `MALFORMED`, no entry persisted.
- `test_handle_inbound_entry_rejects_wrong_producer_pubkey` — sign
  with private key A but set `producer = pub(B)` → `MALFORMED`.
  Defends against a relayer who tries to attribute someone else's
  signed payload to themselves by substituting the `producer` field
  alone.
- `test_handle_inbound_entry_malformed` unchanged: garbage bytes
  fail the CBOR decode before reaching the verify path, the
  pre-existing assertion still holds.

**Component #10 status**: server-side admission is now signature-
gated. The remaining cache work is the cross-peer client side —
DHT-routed publish (step 7b) and DHT-routed query (step 7c) — plus
quality signals + decay (step 9). Step 8 (Hamming-neighbour
expansion) and Ed25519 verify together close every server-side gap
that doesn't depend on the DHT and transport.

CI matrix (7 jobs): first-push green.

### cache: Component #10 (semantic cache) step 8 — Hamming-neighbour expansion · 2026-05-26

**The lookup envelope widens past the exact shard.** `get_topk` and
the lookup request wire format gain a `hamming_radius` parameter
(0..3); the candidate set is now every entry whose `shard_key` is
within `radius` bit-flips of the query embedding's `shard_key`, per
RFC-0002 §The lookup protocol's near-neighbour widening. `radius = 0`
preserves step 7a's exact-shard semantics bit-for-bit.

**PR #65 — step 8: Hamming-neighbour expansion** (+649/-69):

- Filter is `popcount(entry.shard_key ^ query_key) ≤ radius`.
  Implemented as a Brian Kernighan iteration in `shard_key_popcount`
  to avoid relying on a compiler builtin and stay bit-exact across
  hosts; the typical XOR has at most 3 set bits, so the cost in the
  inner scan loop is negligible.
- New protocol-pinned constant
  `ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS = 3`: three flips give
  `C(64,0)+C(64,1)+C(64,2)+C(64,3) ≈ 43k` addressable shards, an
  envelope wide enough for high-recall semantic search and tight
  enough that the upper-bound DHT fan-out stays bounded.
  Out-of-range values are rejected `INVALID_ARG` on the API entry
  points (`get_topk`, `lookup_request_encode`) and `NON_CANONICAL`
  on the wire (`lookup_request_decode`).
- **Wire format** grows CBOR key `4: hamming_radius uint` in
  canonical ascending order. `handle_inbound_lookup` decodes the
  new field and threads it through to `get_topk`. The server-side
  `HANDLE_LOOKUP_SERVER_CAP = 15` still bounds the response size;
  the radius widens the candidate pool, not the emitted match
  count.
- **7 new tests**:
  - `test_get_topk_hamming_zero_matches_exact_shard_only` —
    `radius = 0` preserves step-7a exact-shard semantics.
  - `test_get_topk_hamming_radius_widens_envelope` — for
    `radius ∈ 0..MAX`, the returned tag-set is exactly the
    expected pool subset (brute-force ground truth from a
    near-embedding pool, classified by actual Hamming distance).
  - `test_get_topk_hamming_excludes_entries_beyond_radius` —
    a Hamming-~32 entry stays invisible at every allowed
    radius.
  - `test_get_topk_hamming_ranks_by_similarity_across_shards`
    — ranking is by cosine similarity, not by Hamming
    distance: a high-cos neighbour-shard entry can outrank a
    lower-cos exact-shard entry.
  - `test_lookup_request_round_trip_with_hamming_radius` —
    every legal radius round-trips through the wire format.
  - `test_lookup_request_rejects_wire_radius_above_max` — a
    hand-crafted CBOR payload with `radius = MAX + 1` is
    rejected `NON_CANONICAL` (the public encoder rejects
    earlier so the wire receiver path is exercised
    independently).
  - `test_handle_inbound_lookup_propagates_hamming_radius` —
    end-to-end: a request with `radius = N` admits a
    neighbour at Hamming distance `N` on the server's local
    scan.

**Convention worth preserving**: brute-forcing a Hamming-1/2/3
neighbour by enumerating small-noise variants is the natural test
fixture pattern in this regime — two independent random unit
vectors land at Hamming distance ≈ 32 with overwhelming
probability, so directly synthesising a near-shard entry is
impractical. The pool builder + brute-force-find pattern
(`build_hamming_pool` and the inline loops in
`*_ranks_by_similarity_across_shards` /
`*_propagates_hamming_radius`) should be reused for future
shard-locality tests.

**Component #10 status after step 8**: server-side and local
top-K both honour the near-neighbour widening; the cache is
ready for the cross-peer DHT publish (step 7b) and query
(step 7c). The single remaining server-side gap is the Ed25519
signature-verify TODO in `handle_inbound_entry` (any well-formed
record currently admits) — independent of step 8.

CI matrix (7 jobs): first-push green.

### cache: Component #10 (semantic cache) step 7a — top-K + storage refactor + inbound handlers · 2026-05-25

**Server-side end-to-end ready.** Two consecutive PRs close the
local half of the DHT-routed write + lookup protocols. After this,
the cache can fully receive a producer-signed entry off the wire
(`handle_inbound_entry`), persist it with every field intact, and
serve canonical-CBOR responses to inbound lookup requests
(`handle_inbound_lookup`). The remaining Component #10 work is
the **client side** — DHT-routed publish (step 7b) and DHT-routed
query (step 7c) — plus Hamming neighbour expansion (step 8) and
the quality-signal layer (step 9).

**PR #62 — step 7a: top-K lookup** (+344):

- `ants_semantic_cache_get_topk(cache, embedding, threshold, top_k,
  out_matches, out_embeddings, cap_matches, *out_n)`: linear scan
  filtered by shard_key, collect every entry above threshold into
  a 256-slot stack-resident candidate array, insertion-sort desc
  by similarity, emit `min(top_k, cap_matches, n_eligible)` matches
  into caller buffers. `*out_n` is always `min(top_k, n_eligible)`
  — the count the caller needs to allocate to receive every
  eligible match — so `BUFFER_TOO_SMALL` can drive a retry with
  a bigger buffer.
- `last_access` bumped on every match emitted (LRU semantics:
  retrieval refreshes recency, consistent with the existing get
  path).
- Storage limitation flagged in the header: at step 7a the local
  store still persists only `(embedding, value-as-response)`, so
  every other entry field comes back zero/empty in the match
  views.
- 7 new tests: NULL args, uninit ctx, empty cache, sorted-desc
  with LSH-cell-boundary tolerance, top_k cap, top_k=0 unbounded,
  buffer-too-small with `out_n=full_count`.

**PR #63 — step 7a.2: full-record storage + inbound handlers** (+568/-45):

- **Storage refactor**: `cache_entry_t` now carries the full
  producer-signed record. Heap-allocated copies of `embedding_model`,
  `response`, `response_model`, `attestation`; inlined fixed-length
  `prompt_hash`, `producer`, `signature`; scalars `created`,
  `validity_class`. `free_entry()` helper releases every owned
  allocation (called by `free_all_entries`, `evict_at`, `destroy`,
  `clear`).
- `get_topk` now populates the full `match.entry` view: pointer
  fields alias the cache's internal heap copies, fixed-length
  fields are `memcpy`'d, scalars copied.
- **New public API**:
  - `ants_semantic_cache_put_record(cache, *entry)`: all-or-nothing
    copy of every field. Pre-validates exactly as the encoder does;
    rolls back any partial mallocs on failure.
  - `ants_semantic_cache_handle_inbound_entry(cache, cbor, len)`:
    decode the step-4 wire bytes + `put_record`. Signature
    verification is a documented TODO for step 7b+ (Ed25519 over
    canonical fields 1..9 vs `producer` pubkey).
  - `ants_semantic_cache_handle_inbound_lookup(cache, req, req_len,
    resp_buf, resp_cap, *out_len)`: decode the step-5 request →
    `get_topk` with server-side cap of 15 (defensive against
    greedy clients) → encode the step-6 response. Heap-allocates
    the 60 KB match-embedding scratch so the stack stays clean
    even on platforms with tight defaults.
- `ants_semantic_cache_put(emb, value)` is now a thin convenience
  wrapper that builds a placeholder record (model = `"ants-embed-v1"`,
  everything else zero / EPHEMERAL) and calls `put_record`. All
  pre-existing put / get / get_topk / eviction tests pass
  unchanged.
- 8 new tests including the round-trip end-to-end check:
  `put_record` → `entry_encode` → `handle_inbound_entry` ↔
  `lookup_request_encode` → `handle_inbound_lookup` →
  `lookup_response_decode`, verifying every entry field
  byte-for-byte through the whole pipeline.

**Component #10 status after PR #63**: every byte of the local
server side is exercised — wire formats, LSH routing, full-record
storage, LRU eviction, top-K cosine ranking, inbound write +
lookup handlers. Two peers running this cache can already exchange
records if you hand-wire the bytes between them. Steps 7b/7c put
the DHT + transport in the middle so peers discover each other
without a side-channel.

CI matrix (7 jobs): both PRs first-push green; #62 absorbed one
unrelated DHT-flake re-run.

### cache: Component #10 (semantic cache) steps 0-6 — scaffold through wire formats · 2026-05-25

**Local cache layer + wire formats complete.** Seven consecutive PRs
take `cache/semantic` from "pending claim" to "fully functional in-
memory cache with LSH shard-key + LRU eviction + both wire formats
ready for DHT integration". After this, the only Component #10 work
remaining is **step 7** (DHT-routed publish + lookup networking),
**step 8** (Hamming-1/2/3 neighbour expansion + multi-shard
aggregation), and **step 9** (quality-signal aggregation + challenge
invalidation + decay by validity class).

**PR #54 — step 0: scaffold** (+636):

- New `cache/semantic/{include,src,tests}/` directory tree.
- Public `ants_semantic_cache.h` declares the API surface:
  `ants_semantic_cache_t` opaque ctx (4 KiB), config (per_shard_max,
  total_max), lifecycle (init/destroy), put/get with similarity
  threshold + BUFFER_TOO_SMALL contract, `shard_key` derivation,
  `entries`/`clear` diagnostics.
- Protocol-pinned constants (RFC-0002): `SHARD_KEY_BITS=64`,
  `DEFAULT_THRESHOLD=0.92f`, `DEFAULT_REPLICATION=3`,
  `shard_key_t = uint64_t` (matches `ants_dht_shard_key_t`).
- Every implementation path returns `NOT_IMPLEMENTED`; `destroy` is
  a safe no-op on zeroed ctxs (matches the pattern in `ants_embed`
  and `ants_transport`).
- 13 contract tests (constants, alignment, NULL-arg validation,
  scaffold-NOT_IMPLEMENTED-everywhere, safe-on-zero behaviours).
- CMake: `cache/CMakeLists.txt` enables `semantic` after
  `embedding` (depends on `ANTS_EMBED_DIM`).

**PR #55 — step 1: LSH shard-key** (+317/-21):

- `ants_semantic_cache_shard_key(embedding, *out_key)` implements
  the RFC-0002 §DHT routing scheme: 64 pseudorandom hyperplanes,
  sign of each projection → bit of the 64-bit key.
- **The projection matrix is part of the protocol-pinned bundle**,
  derived deterministically from a fixed BLAKE3 seed label
  (`"ants-semantic-cache/v1/projection-matrix"`). Generation:
  16K BLAKE3 calls × 4 Box-Muller Gaussians per 32-byte chunk
  = 65536 Gaussian floats = 64 × 1024 matrix. <5 ms total even
  under ASan+UBSan.
- Lazy init via `atomic_int` (stdatomic) double-checked-locking;
  fast path is one acquire-load. Process-global (NOT per-cache).
- Shard-key path: 64 double-precision dot products in fixed order;
  cross-host bit-exactness depends on RFC-0009 canonical numerics,
  single-host determinism is solid.
- 5 new behavioural tests including the locality property: base +
  2 % noise → Hamming ≤ 8 vs base; unrelated random → Hamming
  20–44 (~32 expected for orthogonal). Confirms RFC-0002's
  "similar embeddings share most bits" claim end-to-end.

**PR #56 — step 2: local-shard storage + cosine lookup** (+450/-46):

- `init`/`destroy`/`put`/`get`/`clear`/`entries` now do real work
  against an in-memory bucket store. Magic-tagged state ("CNCS")
  for uninit-vs-init detection.
- Flat heap array of `cache_entry_t`, grown geometrically (16 → 32
  → ...). Each entry: precomputed shard_key + L2-normalised
  embedding (4 KB inline) + heap-allocated value copy + LRU
  counter.
- `put`: shard_key, grow if full, malloc+memcpy value, inline
  embedding + key + lru++. `get`: shard_key, linear scan filtered
  by matching shard_key, cosine via double-precision dot product,
  rank by similarity; `NOT_FOUND` if no match above threshold,
  `BUFFER_TOO_SMALL` with `*out_len = required` if value bigger
  than caller buffer.
- **Cross-module**: new `ANTS_ERROR_NOT_FOUND` (code 12) in
  `include/ants_common.h` for "lookup completed, no result above
  threshold". Wired into `ants_strerror` + the iterate-all-codes
  test (foundation/cbor). Reusable by future components (DHT
  lookup with no peer, etc.).
- 7 new behavioural tests: round-trip, threshold miss, buffer-
  too-small, ranking, entries grow, clear-and-reuse.

**PR #57 — step 3: LRU eviction** (+251/-14):

- Enforces `per_shard_max` + `total_max` from the config (advisory
  in step 2). Pre-insert: total_max check first (may incidentally
  free a slot in this shard), then per_shard_max.
- `find_lru(filter_by_shard, key)` picks smallest `last_access`.
  `evict_at(idx)` frees value, swap-with-last, `n_entries--`. O(1)
  once the LRU is identified; the array order is internal.
- `last_access` is bumped on every get hit (step 2) so the
  eviction picks the genuine LRU rather than oldest insert.
- 4 new tests: total cap, total cap with get-bumps-recency,
  per-shard cap, shard-isolation (per-shard eviction does NOT
  touch other shards).

**PR #58 — step 4: cache-entry wire format** (+880/-1):

- CBOR encode/decode for the producer-signed cache-entry record
  per RFC-0002 §The cache entry + RFC-0008 §3 deterministic
  encoding.
- Public `ants_semantic_cache_entry_t` struct + `_validity_t` enum
  (ephemeral/weeks/months/years/perennial).
- Wire format: CBOR map with ascending integer keys 1..10:
  `embedding` (bytes 4096, raw LE float32), `embedding_model`
  (text), `prompt_hash` (bytes 32), `response` (bytes),
  `response_model` (text), `producer` (bytes 32, Ed25519 pubkey),
  `created` (uint), `validity_class` (uint), `attestation`
  (bytes), `signature` (bytes 64).
- Embedding + similarity raw-bytes, NOT CBOR float native:
  canonical-numerics rationale (CBOR's half/single/double
  "shortest form" is ambiguous; protocol pins the binary footprint).
- Decoder zero-copy on text/bytes (aliases into source buffer);
  embedding unpacked into caller-supplied float buffer.
- 6 wire-format tests: round-trip, empty attestation, buffer-too-
  small, NULL args, truncated, patched invalid validity_class.

**PR #59 — step 5: lookup-request wire format** (+356):

- CBOR encode/decode for the cache lookup request:
  `_lookup_request_encode(embedding, threshold, top_k, ...)`
  + matching `_decode`.
- Wire format: map { 1: embedding bytes(4096), 2: threshold
  bytes(4), 3: top_k uint }. `top_k = 0` means "unbounded
  (responder picks)".
- New `float_to_le_bytes` / `le_bytes_to_float` helpers (single-
  float variant of the embedding pack/unpack).
- 5 tests: round-trip, top_k=0, buffer-too-small, NULL args,
  truncated.

**PR #60 — step 6: lookup-response wire format** (+506/-61):

- CBOR encode/decode for the cache lookup response: a list of
  `{similarity, entry}` matches the responder returns for each
  lookup request from step 5.
- **Refactor**: extracted static `entry_validate` / `entry_emit` /
  `entry_consume` helpers from the existing entry codec; the
  public entry encode/decode are now thin wrappers around them.
  `entry_emit` is reused mid-stream by the response encoder to
  inline a full entry map under match key 2; `entry_consume`
  likewise on the decode side.
- Wire format: map { 1: matches[] }, each match = map { 1:
  similarity bytes(4), 2: nested entry-map(10) }.
- Decoder semantics for `cap_matches < n_matches`: `*out_n`
  always set to actual wire count; up to `cap_matches` entries
  filled; returns `BUFFER_TOO_SMALL` so caller can re-call with
  bigger buffer.
- 5 tests: empty matches, 3-match round-trip, partial-cap
  partial-fill, NULL args, truncated.

**Component #10 status after PR #60**: `cache/semantic` is fully
functional as an in-memory cache (init, put, get with cosine
ranking, LRU eviction, shard-key derivation), and both wire
formats (cache-entry + lookup-request + lookup-response) are
defined + round-trip-tested. The library has no network code
yet; **step 7** plugs `ants_dht` + `ants_transport` into the
publish + lookup paths so peers actually exchange these messages.

CI matrix (7 jobs): all 7 PRs first-push green except PR #54
(two re-runs absorbed unrelated `dht_basic` + `transport_basic`
macOS Release flakes — both spawned as chip-tasks for separate
poll-loop iter-cap bumps).

### cache: Component #11 (canonical embedding) phase 4-real step 5 — BGE-M3 forward pass · 2026-05-25

**Inference live.** Four consecutive PRs land the remaining phase-4-real
layer: GGUF buffer loader, BGE-M3 model binding, forward pass, and
`embed.c` integration. After this, `ants_embed` is end-to-end functional
against any caller-supplied BGE-M3 GGUF + HuggingFace tokenizer.json
that satisfies the protocol-pinned 1024-dim constraint. **Phase 5**
(pinning real hashes + publishing reference vectors against the
official BGE-M3 checkpoint) is the only remaining work before
Component #11 is production-ready.

**PR #49 — step 5a: GGUF buffer loader** (+636):

- New private module `cache/embedding/src/embed_gguf.{h,c}`. Bridges
  the caller-supplies-a-buffer contract with ggml's caller-supplies-a-
  `FILE *` loader via `fmemopen(3)`.
- Opaque `embed_gguf_loader_t`. Thin metadata accessors
  (`n_kv`/`n_tensors`/`version`, `get_str`/`get_u32`/`get_u64`/`get_f32`,
  `find_tensor`) each define a sentinel (NULL / negative / `INVALID_ARG`)
  for the missing-key or wrong-type case so callers don't trip ggml's
  abort-on-mismatch.
- `ggml` linked PRIVATE into `ants_embed` — first consumer of the
  dep vendored back in PR #39.
- 6 tests build GGUF fixtures in-memory via upstream `gguf_init_empty`
  + `ggml_init` + `gguf_add_tensor` + `gguf_write_to_file_ptr(tmpfile)`,
  then read back: empty file, KV round-trip with type-mismatch rejection,
  FP32 tensor round-trip, bad-args, mid-stream truncation, `free(NULL)`.
- POSIX-2008 `_POSIX_C_SOURCE 200809L` discipline for `fmemopen` —
  same pattern as `dht_now_us` in `network/dht/src/dht.c` and the
  `_GNU_SOURCE` guard in `deps/ggml/CMakeLists.txt`.

**PR #50 — step 5b: BGE-M3 tensor binding** (+881):

- New private module `cache/embedding/src/embed_model.{h,c}`.
  `bge_m3_model_t` mirrors GGUF metadata (`n_layers`, `n_heads`,
  `n_embd`, `n_ffn`, `n_vocab` derived from `token_embd` shape,
  `n_ctx`, `ln_eps`) and holds tensor pointers for the three
  embeddings + the pre-encoder LN.
- `bge_m3_layer_t` holds 16 tensor pointers per transformer block
  (attn QKV + output projection, post-attn LN, FFN up/down, post-FFN
  LN). Heap-allocated array of `n_layers` entries.
- `bge_m3_load_from_gguf` gates on `general.architecture == "bert"`,
  reads six metadata KVs, derives `n_vocab` from `token_embd.weight`,
  resolves each tensor by name, shape-checks. Typed errors:
  `MALFORMED` for missing/wrong metadata, `NON_CANONICAL` for missing
  or wrong-shape tensors.
- Naming convention follows llama.cpp's BERT mapping
  (`token_embd.weight`, `blk.{i}.attn_q.weight`,
  `blk.{i}.attn_output_norm.weight`, `blk.{i}.ffn_up.weight`, etc.) —
  exactly what `convert_hf_to_gguf.py` emits for a `BertModel` /
  `XLMRobertaModel` checkpoint. Phase 5 pins them against the actual
  BGE-M3 GGUF the protocol ships.
- 10 tests on a 2-layer × 32-embd × 64-ffn × 4-heads fixture cover
  valid happy-path (with + without optional `token_types.weight`),
  wrong arch, missing arch KV, missing block_count, n_embd not
  divisible by n_heads, missing token_embd, missing layer-0
  `attn_q.weight`, wrong-shape layer-0 `attn_q.weight`, plus
  NULL-arg defences and `bge_m3_free(NULL)` no-crash.

**PR #51 — step 5c: forward pass** (+793):

- New private module `cache/embedding/src/embed_forward.{h,c}`.
  `bge_m3_forward(model, ids, n_tokens, type_ids, out)` builds a
  ggml compute graph per call, executes it via
  `ggml_graph_compute_with_ctx(..., n_threads=1)` for run-to-run
  determinism, CLS-pools (column 0 of the final hidden state),
  L2-normalises in-place.
- Graph (BERT post-norm): token + position (+type, optional)
  embedding → pre-encoder LN → N × {QKV linear → reshape +
  permute to multi-head → scaled scores → softmax → V matmul →
  permute + reshape back → output projection → residual + LN →
  up-FFN + GeLU + down-FFN → residual + LN} → CLS pool → L2 norm.
- Memory budget heuristic scales with `n_layers · n_tokens ·
  max(n_embd, n_ffn)` plus the score buffer + 16 MB fixed overhead.
  Phase 5 tightens this once the real BGE-M3 latency is measured.
- Per-call `ggml_init` / `ggml_free`. Step 5d does NOT hoist the
  compute context into `ants_embed_t` — buffer reuse across calls
  is a future-PR optimisation when latency matters.
- 5 tests on an FNV-1a-keyed pattern-weight fixture (2 layers ×
  16 embd × 32 ffn × 2 heads × 8 ctx × 50 vocab, weights in
  [-0.1, +0.1) so FFN doesn't blow up): basic forward, type_embd
  path, determinism across two independent ggml_init/forward/free
  cycles, distinct-input distinctness, bad-args (NULL + range).

**PR #52 — step 5d: integrate into ants_embed** (+443 / -185):

- `embed.c` rewritten. The stub from the v0.x scaffold is gone.
  State struct is now magic-tagged (`"ANSE"`) and holds three
  heap-owned resources (`gguf_loader`, `model`, `vocab_blob`) plus
  an inline `ants_tokenizer_t` (1 KiB). Tear-down runs in
  reverse-dep order: tokenizer → vocab_blob → model → loader.
- `ants_embed_init` drives the full pipeline: hash-verify weights
  + tokenizer.json (placeholder pinned hashes still skip per
  RFC-0008 §5) → `embed_gguf_load` → `bge_m3_load_from_gguf` →
  protocol-pinned dim check (`model->n_embd == ANTS_EMBED_DIM`,
  i.e. 1024) → `ants_tokenizer_load_huggingface_json` →
  `ants_tokenizer_init`.
- `ants_embed` tokenises input bytes via the loaded tokenizer,
  caps to `min(model->n_ctx, ANTS_EMBED_MAX_TOKENS = 8192)`,
  casts uint32→int32, runs `bge_m3_forward`. `BUFFER_TOO_SMALL`
  from the tokenizer (input longer than `model->n_ctx`) is
  treated as a graceful truncate-to-cap, not an error.
- `test_embed.c` adds an in-memory fixture builder (1024-embd × 1
  layer × 64-ffn × 8-heads × 8-ctx × 50-vocab GGUF with FNV-1a-keyed
  pattern weights + matching tokenizer.json with 10 ▁-prefixed
  test tokens). The three "real embed" cases now exercise the full
  forward against this fixture (deterministic-same-input,
  distinct-input-distinct-output, L2-normalised output). All
  pre-existing constants / layout / arg / verify / destroy tests
  unchanged.
- Behaviour change: weights MUST be a valid GGUF with
  `embedding_length = 1024`; tokenizer MUST parse as HuggingFace
  tokenizer.json. Buffer ownership: both caller buffers MUST
  outlive the `ants_embed_t` (the gguf loader's `ggml_context`
  may alias the weights buffer).

**Roadmap remaining for Component #11**:

- **Phase 5**: pin real `ANTS_EMBED_WEIGHTS_HASH_PINNED` +
  `ANTS_EMBED_TOKENIZER_HASH_PINNED` against the exact BGE-M3
  checkpoint the reference client ships. Publish reference inputs
  + 1024-dim outputs to `ants-test-vectors/vectors/ants-embed-v1/`.
  After phase 5, RFC-0008 §5 placeholder note can be removed.

CI matrix (7 jobs): all 4 PRs first-push green.

### cache: Component #11 (canonical embedding) phase 4-real steps 1-4 — full Unigram tokenizer · 2026-05-23

**Tokenizer infrastructure complete.** Five consecutive PRs land
every piece needed for cross-peer-deterministic Unigram tokenisation
against any HuggingFace tokenizer.json (XLM-RoBERTa / BGE-M3 / etc.):
algorithm, JSON loader, trie acceleration, byte fallback, and NFKC
normalisation. After this, the only Component #11 work remaining is
**phase 4-real step 5 (GGUF + BGE-M3 forward pass via ggml)** and
**phase 5 (pin real hashes + reference vectors)**.

**PR #42 — step 1: Unigram tokenizer + API** (+619):

- New `cache/embedding/include/ants_tokenizer.h` with
  `ants_tokenizer_t` (1 KiB opaque ctx), `_vocab_entry_t`, init /
  destroy / encode / decode.
- Algorithm: pre-tokenize (prepend ▁ U+2581, collapse ASCII-whitespace
  runs into single ▁) → Viterbi forward over caller-supplied vocab
  (O(N × V) linear scan; trie comes in step 3) → backtrace.
- Bit-exact deterministic across platforms.
- 13 test functions: Viterbi correctness on hand-crafted vocab,
  letter fallback, whitespace collapse, NON_CANONICAL on uncovered
  input, BUFFER_TOO_SMALL contract, encode determinism, decode
  round-trip.
- **Why hand-rolled instead of vendoring SentencePiece**: upstream
  is ~60 MB / 151K LoC C++ with protobuf + abseil + darts-clone
  cascade; algorithm is ~150 LoC. Focused-subset discipline matches
  ed25519 ref10 + ggml CPU subset.

**PR #43 — step 2: tokenizer.json loader (jsmn vendored)** (+1267):

- New `deps/jsmn/` — single-header minimal JSON tokenizer (~470
  LoC, MIT). INTERFACE library, `JSMN_STATIC` include in the
  single consuming TU.
- New API: opaque `ants_tokenizer_vocab_blob_t` +
  `ants_tokenizer_load_huggingface_json` + `_vocab_entries` /
  `_vocab_size` / `_vocab_free` accessors. Heap-allocated blob owns
  both entries array and packed text_pool.
- Parses `$.model.vocab` from HuggingFace tokenizer.json. JSON
  unescape handles `\\`, `\"`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`,
  `\uXXXX` (BMP only — surrogate pairs deferred).
- End-to-end load → init → encode produces same Viterbi result as
  the hand-built vocab in step 1.
- 8 test functions.

**PR #44 — step 3: trie-based Viterbi lookup** (+355/-84):

- Replaces step 1's O(N × V) linear-scan inner loop with a packed
  flat trie. For BGE-M3's 250K-entry vocab and ~100-byte inputs
  that's ~10000× fewer byte-comparisons per encode.
- Two flat heap arrays in state: `trie_nodes` (terminator + score +
  child slice ref) + `trie_edges` (sorted byte → child node_idx).
  Allocated by init, freed by destroy.
- Two-stage build: stage A builds a sparse tree with dynamic child
  arrays; stage B DFS-packs into the flat arrays with insertion-
  sorted children. Build tree freed after packing.
- Encode now sweeps FORWARD from each start position (Viterbi
  forward variant): walk the trie one byte at a time over
  `work[s..]`; every terminator yields a candidate for
  `dp[s + path_len]`.
- Test-observable behaviour unchanged — existing tests still pass.

**PR #45 — step 4a: byte fallback** (+192):

- New API: `ants_tokenizer_set_byte_fallback(tok, ids[256], score)`.
  256-entry byte → token-ID array is copy-stored in heap (1 KiB).
- Viterbi forward sweep gains a length-1 candidate per position when
  fallback enabled. Score is additive; fallback only "wins" when no
  longer vocab entry covers — exactly SentencePiece's semantic.
- With fallback enabled, encode is guaranteed to find a covering
  segmentation. `ANTS_ERROR_NON_CANONICAL` never fires for unknown
  characters.
- 4 new tests: NULL/uninitialised rejection, "xyz" covered, compound
  tokens still preferred, NULL clears fallback.

**PR #46 — step 4b: NFKC normalisation via utf8proc** (+~17.7K mostly tables):

- New `deps/utf8proc/` — utf8proc v2.10.0, ~18.7K LoC (mostly the
  17K-line generated Unicode-tables file). MIT license preserved.
  Single static library.
- New API: `ants_tokenizer_set_nfkc_enabled(tok, bool)` — defaults
  OFF.
- Encode runs `utf8proc_map(in, ..., UTF8PROC_STABLE | UTF8PROC_COMPAT
  | UTF8PROC_COMPOSE)` before the ▁-pretokenize pass when enabled.
- Pipeline order: NFKC → pretokenize → trie-Viterbi → byte fallback.
  Compatibility forms / ligatures / full-width chars fold into vocab's
  canonical forms before byte fallback fires.
- 4 new tests: NULL/uninitialised rejection, default-OFF behaviour,
  compat-form collapse (full-width `Ｈｅｌｌｏ` → `[▁Hello]`),
  ligature decomposition (`ﬁne` U+FB01 → `[▁fine]`).

**PR #47 — test/dht: bump poll-loop iter caps 200 → 500** (+13/-13):

- 13 `for (int i = 0; i < 200; i++)` poll loops in `test_dht.c`
  bumped to 500. Same pattern that newer phase-6.1 tests already
  use. PR #46's first CI run hit the macOS-Release flake we'd
  spawned a chip-task for earlier; this fix lands inline now
  rather than recurring.
- All affected loops are wait-on-condition with early `break`;
  fast runners unaffected, slow runners get longer safety margin.

**Tokenizer pipeline status after these 5 PRs**:

```
caller input bytes
  │
  ├─ NFKC normalise (utf8proc; opt-in via set_nfkc_enabled)
  │
  ├─ Pre-tokenize (prepend ▁ + collapse whitespace → ▁)
  │
  ├─ Trie-Viterbi (O(N × max_token_len × log(branching)))
  │   ├─ Vocab-trie candidates per position
  │   └─ Byte fallback length-1 candidates per position
  │      (opt-in via set_byte_fallback)
  │
  └─ Backtrace → uint32_t token IDs
```

Cross-peer determinism property holds end-to-end: any two
conformant peers running the same canonical model produce
identical token sequences for identical input bytes (modulo the
caller-chosen on/off settings, which are part of the protocol spec).

**Roadmap remaining for Component #11**:
- **Phase 4-real step 5**: GGUF model loader (consume vendored
  ggml) + BGE-M3 architecture struct + forward pass + mean-pool +
  L2-norm. The pezzo grosso restante.
- **Phase 5**: pin real `ANTS_EMBED_WEIGHTS_HASH_PINNED` +
  `ANTS_EMBED_TOKENIZER_HASH_PINNED` against the exact BGE-M3
  checkpoint the reference client ships. Publish reference
  inputs+outputs to `ants-test-vectors/vectors/ants-embed-v1/`.

CI matrix (7 jobs): all 5 substantive PRs first-push green except
PR #46 (one re-run for the macOS DHT flake, fix landed in #47).

### cache: Component #11 (canonical embedding) — scaffold → verify + stub inference → ggml vendored · 2026-05-23

**Cache layer begins.** Component #11 (canonical embedding service)
goes from "pending claim" to "API stable + hash verification + stub
inference + ggml ready for real-inference wiring" in three
consecutive PRs. After this, `cache/semantic` (Component #10) can be
developed against a stable `ants_embed` contract while phase 4-real
(BGE-M3 inference via ggml) lands separately.

**PR #38 — Scaffold + API design** (+561):

- New `cache/embedding/include/ants_embed.h` declares the public API:
  - `ANTS_EMBED_DIM = 1024` (output dimension; protocol-pinned per
    RFC-0002 §The canonical embedding model)
  - `ANTS_EMBED_MODEL_ID = "ants-embed-v1"`,
    `ANTS_EMBED_MODEL_ARCH = "bge-m3"`
  - `ANTS_EMBED_WEIGHTS_HASH_PINNED[32]` +
    `ANTS_EMBED_TOKENIZER_HASH_PINNED[32]` — all-zero placeholders
    per RFC-0008 §5 ("the specific 32-byte values for v1 will be set
    when the reference client is published")
  - Opaque `ants_embed_t` (64 KiB; conservative oversize for ggml
    state), `ants_embed_init`, `ants_embed_destroy`,
    `ants_embed(ctx, in, in_len, out[1024])`
- Caller-supplied weights+tokenizer buffers — library never copies
  hundreds of MB.
- Stubbed initially (returns `ANTS_ERROR_NOT_IMPLEMENTED`); 7 tests
  pin the contract.

**PR #39 — Vendor ggml v0.12.0 (portable CPU subset)** (+58991):

- New `deps/ggml/` with ~57K LoC vendored from
  [ggml-org/ggml @ v0.12.0](https://github.com/ggml-org/ggml/tree/v0.12.0).
  License: MIT (preserved).
- Top-level `project()` language list bumped from `C` to `C CXX`
  (ggml is C++17 since its v0.10 rewrite; our own code stays strict
  C99 — CXX requirement is contained to `deps/ggml`).
- All GPU backends OFF (CUDA, Metal, Vulkan, OpenCL, ROCm/HIP, SYCL,
  MUSA, etc.). Per-arch SIMD kernels OFF via `GGML_CPU_GENERIC`.
  Niche extensions OFF (HBM, KleidiAI, AMX, llamafile, spacemit).
- Single static library `ggml` built with `-w` so vendored warnings
  don't surface in our consumer compilation units. Includes marked
  SYSTEM — same pattern as `deps/picoquic`.
- `_GNU_SOURCE` defined on Linux (fixes glibc-only need for
  `clock_gettime`, `CPU_ZERO`, `pthread_setaffinity_np`, `M_PI`,
  etc.). First push to PR #39 hit the same glibc-gating that PR #34
  did with `dht_now_us`.
- `ggml` library is built but NOT yet linked from `ants_embed`.
  Phase 4-real wires it in.

**PR #40 — Phase 3 hash verify + phase 4-stub deterministic inference** (+319/-91):

- `ants_embed_init` is real: BLAKE3 the weights+tokenizer buffers,
  constant-time-compare to the pinned constants. Mismatch →
  `NON_CANONICAL` (RFC-0002: "no close enough, bit-exact match or
  rejection"). All-zero pinned hash → skip verification (placeholder
  semantics per RFC-0008 §5; phase 5 lands the real hashes).
- Verify helper exposed as `ants_embed__test_verify` test hook so the
  strict path is tested against synthetic pinned hashes even while
  the public constants stay zero — covers the path before phase 5
  makes the real-hash path observable.
- `ants_embed` is a deterministic STUB:
  - `seed = BLAKE3(input)`
  - 128 keyed-chunk BLAKE3 calls produce 4096 bytes
  - 4-byte LE chunks → floats in `[-1, 1)`
  - L2-normalise to unit length
- Properties: same input → same output (same platform), L2-unit-norm,
  distinct inputs → distinct outputs. NOT bit-exact across platforms
  (float multiplication ordering). NOT a real BGE-M3 embedding.
  Purpose: stand-in until phase 4-real wires ggml.
- `embed` requires `init` first — calling on a zeroed ctx →
  `INVALID_ARG`.
- 12 test functions (up from 7 in scaffold): pinned constants +
  opaque ctx + arg validation + verify path (placeholder + real-hash)
  + determinism + distinctness + L2-norm + uninitialised-ctx
  rejection.
- `libm` linked on non-macOS / non-MSVC for sqrt in the L2
  normalisation.

**Quirks worth preserving** for future sessions:

- **Never pass `CMakeLists.txt` through `clang-format -i`** — it
  mangles the CMake syntax catastrophically (CMake parse errors,
  six-job CI failure). The `clang-format` workflow correctly limits
  itself to `*.c`/`*.h` files; the human-run `clang-format -i` glob
  must too. PR #40's first push hit this; force-push + amend fixed
  it.
- The C++ requirement is bounded to `deps/ggml`. Our own code
  remains strict C99. The discipline is enforced by per-target
  `target_compile_features`.

**Roadmap remaining** (separate PRs, not in this batch):

- **Phase 4-real**: replace the stub with real BGE-M3 inference via
  the vendored ggml. Requires: BGE-M3 model conversion to GGUF,
  XLM-Roberta SentencePiece tokenizer integration (likely a
  tokenizers-cpp or hand-rolled WordPiece loader), forward-pass
  glue, mean-pool over hidden states, L2-normalise.
- **Phase 5**: populate `ANTS_EMBED_WEIGHTS_HASH_PINNED` +
  `ANTS_EMBED_TOKENIZER_HASH_PINNED` against the exact BGE-M3
  checkpoint the reference client ships with. Publish reference
  inputs+outputs to `ants-test-vectors/vectors/ants-embed-v1/`.
  Also the trigger for RFC-0008 §5 to lose its `0x000…000`
  placeholder note.

CI matrix (7 jobs): PR #38 first-push green; PR #39 needed the
`_GNU_SOURCE` follow-up; PR #40 first-push hit the CMakeLists.txt
clang-format mangling, fixed via amend + force-push.

### network: Component #5 (DHT) phase 6.1 — maintenance loop · 2026-05-23

**Production steady-state behaviour.** Three consecutive PRs land the
deferred phase 6.1 maintenance pieces. After this, the DHT survives
long-running operation: dead peers get pinged and evicted, announces
propagate to the K-closest storers, and lookups can dial peers they
know about but haven't reached yet. The 6.1 work was sliced into three
PRs (one per sub-piece) to match the established 1-PR-per-phase
cadence of Component #5.

**Phase 6.1.a — refresh PING + dead_strikes eviction** (PR #34, +651):

- Internal `dht_now_us()` wraps `clock_gettime(CLOCK_MONOTONIC)` with
  a paranoid `CLOCK_REALTIME` fallback. Decouples the DHT from
  picoquic. Gated on `_POSIX_C_SOURCE 200809L` (added in a follow-up
  push to the same PR after Linux CI flagged `struct timespec` as
  incomplete on glibc).
- `ants_dht_bucket_entry` gains `dead_strikes` + `ping_in_flight` +
  6-byte alignment pad. `kbucket_insert` memsets new entries to
  avoid uninitialised padding bytes.
- `refresh_tick` walks all 256 buckets on every `dht_tick`; entries
  with a live conn that haven't been seen in `refresh_interval_ms`
  get PINGed. `ping_in_flight` prevents double-issuing within the
  same RTT. An earlier draft throttled the sweep to
  `refresh_interval_ms/4`, but on a tight test loop the wall clock
  doesn't advance fast enough between ticks and the throttle
  starved eviction — removed; the bucket walk is cheap.
- PING success resets `dead_strikes` + bumps `last_seen_us`; PING
  failure increments `dead_strikes`; reaching
  `ANTS_DHT_DEAD_STRIKE_THRESHOLD` (3) evicts the entry and fires
  `PEER_EVICTED`. `TABLE_REFRESHED` fires after each sweep.
- New public constant `ANTS_DHT_DEAD_STRIKE_THRESHOLD = 3`
  (BitTorrent mainline convention).
- `ants_dht_tick` now returns `refresh_interval_ms/4` (a wake-delay
  hint) when refresh is enabled, instead of `UINT32_MAX`.
- Two existing call sites that hardcoded `now_us = 0` now use
  `dht_now_us()`: `handle_bootstrap_conn_ready` and the self-upsert
  branch in `ants_dht_announce`.
- Test hooks: `__test_get_entry_state`, `__test_now_us`. Test plumbing:
  `test_dht_endpoint_t` gains `stream_opened`; new
  `test_dht_event_recorder_t` for observing `PEER_EVICTED` /
  `TABLE_REFRESHED`.

**Phase 6.1.b — announce republish chain** (PR #35, +467):

- `ants_dht_announce(key)` now actually propagates. Every
  `announce_republish_ms` (or immediately on first announce), the
  DHT walks the K closest live-conn peers (by XOR distance from
  `BLAKE3(shard_key_le)`) and chains `GET_PEERS → ANNOUNCE_PEER`
  per target. The first `ANNOUNCE_PEER_RESP` of the cycle fires
  `ANNOUNCE_CONFIRMED`. Pre-6.1.b the announce was only recorded
  locally + self-server-set, so a lookup from a third party
  couldn't find us — the gap the phase-6 announce comment named.
- `dht_now_us` un-static + declared in `dht_internal.h` so
  `dht_server.c` stamps inbound ANNOUNCE_PEER timestamps for real
  (closed the `0 /* now_us, TODO */` from phase 6).
- New `struct republish_chain_ctx` (heap-allocated per
  `(shard, target_peer)`) threads state across the
  `GET_PEERS → ANNOUNCE_PEER` completions; reuses the same ctx for
  both hops, freed in the final completion or on RPC-send failure.
- `find_kclosest_conn_entries` mirrors `dht_server.c`'s
  `find_kclosest_peers` insertion-sort but filters on `conn != NULL`
  (6.1.c lifts that restriction by lazily dialing NULL-conn
  candidates).
- `ants_dht_announce` memsets a reused slot to avoid inheriting
  stale `last_republished_at_us` from a previous
  `unannounce → reannounce`.
- `ants_dht_tick` wake-delay is now
  `min(refresh_interval_ms/4, announce_republish_ms/4)`.
- Test hook: `__test_server_announce_count`. Tests share a
  `test_republish_fixture_t` (init/teardown helpers).

**Phase 6.1.c — dial-promote during lookup** (PR #36, +437):

- New candidate state `ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL = 4`.
  Convergence waits for it alongside `UNQUERIED` / `INFLIGHT`.
- New `struct ants_dht_pending_dial` array on the DHT state (cap
  16). Same lazy-free model as `bootstrap_entries[]`: heap conns
  survive `CONN_CLOSED`, freed in `ants_dht_destroy` AFTER
  `ants_transport_destroy`.
- `try_dial_promote` in `dht_lookup.c`: NULL-conn candidate with
  multiaddr → heap-alloc conn → `ants_transport_dial` → flip
  candidate to `INFLIGHT_DIAL`. `inflight_count` is NOT
  incremented (it tracks GET_PEERS RPCs, not dials). Empty
  multiaddr or no free slot → candidate FAILED.
- `handle_pending_dial_conn_ready` in `dht.c`: match conn pointer,
  verify expected `peer_id`, `kbucket_insert` (promote the conn
  into the routing table so future lookups benefit too), then
  `ants_dht_lookup_promote_dialed_peer` flips every waiting
  candidate back to `UNQUERIED` with the live conn.
- `handle_pending_dial_conn_closed` calls
  `ants_dht_lookup_fail_dialing_candidates` for dials that closed
  before READY.
- `seed_candidates_from_routing` now includes NULL-conn entries.
  Pre-6.1.c they were filtered out (lookup would have immediately
  marked them FAILED); with dial-promote they're a live discovery
  channel.
- Test plumbing fix: synthetic GET_PEERS_RESP peer in
  `test_rpc_build_response` now uses an empty multiaddr (was
  `/ip4/127.0.0.1/udp/12345/quic-v1`). Pre-6.1.c the NULL-conn
  peer was harmlessly FAILED at query; with dial-promote it would
  try to dial a port with no listener and hang the lookup forever.
  Empty multiaddr preserves test semantics (LOOKUP_COMPLETE with B
  as sole ANSWERED peer).

**Notes for future sessions** worth preserving:

- The DHT shares the bootstrap discipline that
  `ants_transport_destroy` MUST precede `ants_dht_destroy`
  whenever the DHT may hold heap conns (`bootstrap_entries[]` or
  `pending_dials[]`). Lookup-only tests that previously didn't
  follow this convention can now hit the same picoquic UAF if
  dial-promote runs.
- `dht_now_us` lives in `dht.c` but is declared in
  `dht_internal.h` so any DHT translation unit can use it. This
  is the only declared cross-TU function in the internal header.

**Component totals after phase 6.1**: 35 test functions in
`test_dht.c` (up from 30); `dht_basic` ctest target runs in ~3.5 s
under AppleClang Debug + ASan + UBSan (8 real-QUIC round-trip
scenarios plus the K-bucket / wire-codec / RPC-dispatch unit tests).

CI matrix (7 jobs, all green every PR): Linux gcc/clang
Debug+Release, macOS clang Debug+Release, TSan Linux clang,
clang-format.

### network: Component #5 (DHT) feature-complete · 2026-05-22

**ANTS DHT live.** Four consecutive PRs close out Component #5 by
landing RPC dispatch, the iterative-lookup state machine, bootstrap
plus server-side request handling, and the end-to-end two-node
integration test. The DHT now performs full Kademlia
bootstrap → announce → iterative lookup over the QUIC transport.

**Phase 4 — RPC dispatch over transport bidi streams** (PR #29,
+1320):

- New module `src/dht_rpc.{h,c}` owns the pending-RPC registry
  (`struct ants_dht_state.pending[]`, 64 slots). Each `send_*` call
  heap-allocates an `ants_transport_stream_t *`, opens a bidi
  stream, sends the canonical CBOR-encoded request with FIN, and
  arms a completion handler.
- New public API `ants_dht_handle_transport_event(dht, ev)` so the
  caller can delegate transport events from their own `event_fn`
  (transport accepts a single registered callback, so the DHT
  cannot register its own).
- Dispatch: `STREAM_READABLE` accumulates into a lazy-alloc
  `recv_buf` (4 KB cap), `STREAM_FIN` peeks the response type +
  decodes + fires the completion, `STREAM_RESET` fails the slot,
  `CONN_CLOSED` sweeps every slot on the conn.
- Storage layout moved to private `src/dht_internal.h` shared
  between `dht.c` and `dht_rpc.c`.
- Tests: NULL-arg guards, non-DHT-event no-op path, two-endpoint
  integration with real Ed25519 + real QUIC for PING and
  FIND_NODE round-trips.

**Phase 5 — iterative-lookup state machine** (PR #30, +949):

- New module `src/dht_lookup.{h,c}` (441 LoC impl) implements the
  standard Kademlia GET_PEERS loop: seed candidates from
  routing-table conn-bearing entries → issue α=3 RPCs at a time
  toward the closest UNQUERIED → fold each response back into the
  sorted candidate set → converge when inflight=0 and no UNQUERIED
  → fire LOOKUP_COMPLETE with up to K closest ANSWERED.
- `struct ants_dht_bucket_entry` extended with an optional
  `ants_transport_conn_t *conn` (NULL = known peer, not dialed
  yet). Phase 6 lazily promotes those.
- Candidate set sorted ascending by XOR distance from
  `BLAKE3(target_key_le)`; cap 40 (each entry ~336 B due to full
  `ants_dht_peer_t` with multiaddr).
- `ANTS_DHT_LOOKUP_CTX_SIZE` bumped 8 KB → 16 KB.
- Cancellation invalidates per-RPC completion records so late-
  firing RPCs no-op safely.

**Phase 6 — bootstrap + server-side dispatch + announces** (PR #31,
+1259):

- New module `src/dht_server.{h,c}` (514 LoC) decodes inbound DHT
  requests on peer-initiated bidi streams and produces responses.
  Inbound stream registry (32 slots) accumulates the request until
  STREAM_FIN; then peek + decode + dispatch to one of four
  handlers (PING / FIND_NODE / GET_PEERS / ANNOUNCE_PEER); encode
  the response, send back on the same stream with FIN, release
  the slot.
- **Token discipline (BitTorrent style):** GET_PEERS_RESP carries
  a 16-byte token = `BLAKE3(server_secret || peer_id)[0..16]`.
  ANNOUNCE_PEER_REQ must echo a valid token or the announce is
  rejected. `server_secret = BLAKE3(local_peer_id)` (phase 6 uses
  a fixed value; rotation is deferred).
- `ants_dht_bootstrap` real impl: heap-allocates the conn, dials
  via transport, registers in `bootstrap_entries[8]`. On
  CONN_READY (delegated via `handle_transport_event`), the peer
  gets promoted into the routing table with its live conn pointer,
  and a self-FIND_NODE round-trip seeds nearby buckets.
- `ants_dht_announce` / `_unannounce` real impl: maintains a
  local-host announce list AND inserts self into the server-side
  announce set, so a GET_PEERS query from a peer routing us finds
  a real announcer entry.
- **Bootstrap conn lifetime quirk worth recording**: picoquic's
  disconnect path keeps using the conn state for a few lines
  after firing CONN_CLOSED (it sets `cs->cnx = NULL` afterward).
  Freeing the heap conn inside the CONN_CLOSED callback therefore
  produced an ASan UAF on first attempt. Fixed by deferring the
  free to `ants_dht_destroy`'s sweep — the leak window closes at
  destroy. **Teardown order matters**: `ants_transport_destroy`
  MUST precede `ants_dht_destroy` when bootstrap conns are open.
- Tests: announce/unannounce local; A-pings-B with no manual
  server stub on B; A-get-peers-B with a real announce; A
  bootstraps B and B's peer-id ends up in A's routing table.

**Phase 7 — end-to-end two-node integration** (PR #32, +173):

- Single test `test_two_node_end_to_end`. A and B both run full
  DHTs over listener+dialer transports. Mutual bootstrap (each
  dials the other, two independent QUIC sessions). Each announces
  a distinct shard. Each looks up the OTHER's shard. Both observe
  a LOOKUP_COMPLETE event containing the expected announcer.
- Exercises every prior phase end-to-end: k-buckets via bootstrap
  promotion → CBOR wire codec → outbound RPC dispatch → lookup
  state machine → server-side dispatch with token + announce set.

**Component totals**: ~4250 LoC implementation + ~1900 LoC tests
across `src/{dht,dht_internal,dht_lookup,dht_rpc,dht_server,dht_wire}.{c,h}`
plus `include/ants_dht.h`. `dht_basic` test suite runs in ~1.4 s
under AppleClang Debug + ASan + UBSan (5 QUIC round-trip scenarios
plus the K-bucket / wire-codec / RPC-dispatch unit tests).

**Phase 6.1 deferred (not on critical path):** periodic bucket
refresh via PING (evict on dead_strikes), announce republish every
`announce_republish_ms`, dial-promote for candidates discovered with
NULL conn during a lookup. Required for production network steady-
state; not for "the DHT works at all" demonstration.

CI matrix (7 jobs, all green every PR): Linux gcc/clang
Debug+Release, macOS clang Debug+Release, TSan Linux clang,
clang-format.

### network: Component #4 (transport) feature-complete + Component #5 (DHT) phase 0-3 · 2026-05-21

**ANTS network live at the transport layer.** Ten consecutive PRs land
the full P2P transport plus the first three phases of the DHT.

**Transport (Component #4) phases 1 → 3d-2** (PRs #18 - #24):

- Vendored picoquic (BSD-3, single-TU port) + picotls (BSD-3, minicrypto
  backend with cifra + micro-ecc) under `deps/`. Both marked `SYSTEM`
  include in CMake so their C11-extension warnings don't surface in
  our compilation units under `-Wpedantic`.
- Caller-driven async API: opaque `ants_transport_t` (16 KB), tick +
  registered event callback, no internal threads, no logging.
- Stream API: bidi + uni open, send (with FIN flag), recv from an
  internal linear buffer, close, reset. Per-stream state in 1024-byte
  opaque buffer.
- **RFC 7250 raw-pubkey TLS 1.3 with mutual auth.** Custom
  `ptls_sign_certificate_t` delegates to caller-supplied `sign_fn`
  (TEE-safe). Custom `ptls_verify_certificate_t` parses SPKI-wrapped
  peer pubkey and verifies `CertificateVerify` via
  `ants_ed25519_verify`. `expected_peer_id` enforcement on dialer side
  (anti-MITM for RFC-0010 bootstrap seeds).
- Inbound (peer-initiated) connections AND streams bootstrap heap-
  allocated state on demand via the `verify_certificate` and stream-
  data callback paths respectively, tracked through linked lists in
  parent state so `destroy()` can sweep orphans.
- Test milestone (PR #24): two transports with real Ed25519 keypairs,
  dialer sends `"ping\0"` + FIN on a bidi stream, listener's
  `event_fn` observes `STREAM_OPENED` and `STREAM_READABLE` with the
  exact bytes. Clean teardown under ASan + UBSan + TSan.

**DHT (Component #5) phases 0 → 3** (PRs #25 - #27):

- API design (PR #25): `ants_dht.h` pins Kademlia parameters (K=20,
  α=3, 256 buckets), opaque ctx sizes (32 KB top-level, 8 KB per
  lookup), event kinds. `ants_dht_shard_key_t` = `uint64_t` per
  RFC-0002 §DHT LSH. Caller-driven async mirroring transport.
- k-buckets (PR #26): heap-allocated bucket entries (linked-list MRU
  at head, K cap, full bucket rejects until phase 6 LRU-eviction-on-
  PING lands). XOR-distance math: 32-byte XOR, find MSB → bucket
  index 0..255. `routing_table_size` and `_enumerate` now return real
  data. `destroy()` sweeps heap entries.
- CBOR wire codec (PR #27): envelope `{0: type, 1: txid, 2: body}`
  with integer keys for compactness + natural canonical ordering. 8
  message types (PING / FIND_NODE / GET_PEERS / ANNOUNCE_PEER plus
  their responses) with bodies per type. Peer descriptor `{id:
  bytes(32), addr: text}` — "id" sorts before "addr" canonically
  because length-tag bytes differ (text(2)=0x62 < text(4)=0x64).
  **Wire format is DRAFT pending RFC-0008 §DHT formalization.**

**Remaining DHT phases (4-7) for next session:** RPC dispatch over
transport streams, iterative-lookup state machine, bootstrap +
maintenance, two-node integration test. Phase 4 is the natural
next step — uses the wire codec from PR #27 with the stream API
from PR #21.

CI matrix (7 jobs, all green every PR): Linux gcc/clang Debug+Release,
macOS clang Debug+Release, TSan Linux clang, clang-format.

### foundation/crypto: implement Ed25519 (vendored libsodium 1.0.22 ref10) · 2026-05-20

Second crypto primitive landed. Ed25519 sign / verify / pubkey-derive
wired against a vendored subset of libsodium's `ref10` implementation.

Vendoring (`deps/ed25519/`):

- Pinned snapshot of [jedisct1/libsodium 1.0.22](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE)
  ref10 subset. Upstream LICENSE (ISC) preserved.
- Source files: `sign_ed25519.c`, `ref10_keypair.c`, `ref10_sign.c`,
  `ref10_open.c`, `ed25519_ref10_core.c` (fe25519/ge25519/sc25519 ops),
  `hash_sha512.c` (SHA-512 portable), `verify.c` (constant-time
  compare), `utils.c` (libsodium plumbing). Plus a small
  `sodium_stub.c` that provides abort-stubs for `sodium_misuse()` and
  `randombytes_buf()` (the deterministic Ed25519 ref10 path does not
  call randomness).
- Headers: all relevant libsodium public + private headers flattened
  under `include/` and `include/private/` with the upstream
  hierarchy mostly preserved (only `crypto_sign/ed25519/ref10/sign_ed25519_ref10.h`
  is renamed to flat `include/sign_ed25519_ref10.h` to match the
  layout).
- CMake forces the portable C path everywhere: `HAVE_AMD64_ASM` and
  `HAVE_*MMINTRIN_H` deliberately *not* defined (libsodium uses
  `#ifdef`, so defining to 0 still triggers true; the only correct
  way is to not define them at all).

Wrapper (`foundation/crypto/src/crypto.c`):

- `ants_ed25519_pubkey_from_priv` — derives the 32-byte public key
  from a 32-byte seed via `crypto_sign_ed25519_seed_keypair`. The
  intermediate 64-byte libsodium secret-key buffer is zeroed before
  return.
- `ants_ed25519_sign` — derives the libsodium sk on the fly and
  signs via `crypto_sign_ed25519_detached`.
- `ants_ed25519_verify` — calls `crypto_sign_ed25519_verify_detached`;
  maps libsodium's non-zero return to `ANTS_ERROR_MALFORMED`.

Tests (4 new functions):

- `test_ed25519_rejects_invalid_args` — NULL pointers.
- `test_ed25519_rfc8032_test1_empty` — RFC 8032 §7.1 TEST 1 (empty
  message). Derived pubkey matches expected; signature matches
  expected; verify accepts both fresh and expected signatures.
- `test_ed25519_rfc8032_test2_single_byte` — RFC 8032 §7.1 TEST 2
  (single-byte message `0x72`). Same checks.
- `test_ed25519_verify_rejects_tampered` — tamper-bit-flip on
  signature / message / pubkey each cause `MALFORMED`.

Local build clean (Debug, AppleClang 21 on arm64), 2/2 ctest passing.
Format clean (clang-format-22 dry-run --Werror).

The ANTS protocol's identity layer now has a working peer-identity
signature primitive end-to-end against the RFC 8032 reference
vectors.

Next: vendor `supranational/blst` and wire `ants_bls_*` (sign/verify
+ aggregate for L2 PoUH committee signatures).

### foundation/crypto: implement BLAKE3 (vendored 1.8.5) · 2026-05-20

First crypto primitive implemented. BLAKE3 (hash + `derive_key` +
incremental streaming) wired against a vendored snapshot of the
upstream C reference implementation.

Vendoring:

- `deps/blake3/` — pinned snapshot of [BLAKE3-team/BLAKE3 v1.8.5](https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.5)
  with all three upstream LICENSE files (`LICENSE_A2`,
  `LICENSE_A2LLVM`, `LICENSE_CC0`) preserved.
- Portable C only at this stage; SIMD acceleration sources
  (`blake3_avx2.c`, `_sse41.c`, `_avx512.c`, `_neon.c` + asm) are
  deliberately not vendored yet. The CMake build sets `BLAKE3_NO_*`
  and `BLAKE3_USE_NEON=0` to force the dispatch to the portable
  path on every architecture.
- `deps/blake3/CMakeLists.txt` builds a static `blake3` library
  with relaxed warning flags (the upstream code is high-quality but
  triggers the project's strict `-Wshadow`/`-Wconversion` set).
- Root `CMakeLists.txt` adds `deps/blake3` as a subdirectory before
  `foundation/`.

Wrapper:

- `foundation/crypto/src/crypto.c` wires `ants_blake3_hash`,
  `ants_blake3_derive_key`, and the incremental
  `init`/`init_derive`/`update`/`final` family to the upstream
  `blake3_hasher_*` functions.
- Portable C99 compile-time `_Static_assert` analogue verifies
  `sizeof(blake3_hasher) ≤ sizeof(ants_blake3_ctx_t._opaque)`.
- All memory caller-provided; the wrapper never calls malloc.

Tests:

- `test_blake3_rejects_invalid_args` — NULL pointers, zero
  capacity.
- `test_blake3_empty` — BLAKE3 of empty input matches the
  well-known constant `af1349b9...`.
- `test_blake3_known_inputs` — three short inputs (`"IETF"`,
  single `0x00`, 64-byte mod-251 pattern) pinned against vendored
  BLAKE3 v1.8.5 output.
- `test_blake3_derive_key` — `derive_key` returns OK and produces
  non-zero output (full known-answer pinning awaits the
  ants-test-vectors BLAKE3 regen).
- `test_blake3_streaming_matches_one_shot` — feeds 100 bytes one
  at a time through the incremental API; verifies the final hash
  matches the one-shot call.

Ed25519, BLS12-381, ECVRF-ELL2 stubs unchanged; next PR vendors
`ed25519-donna` (or a verified C impl) and wires `ants_ed25519_*`.

### foundation/crypto: scaffolding + public API header · 2026-05-20

First foundation-layer code for Component #1 (Crypto primitives,
RFC-0008 §§ 2–4). Establishes the public API surface of the wrapper
library as a stubbed library: every primitive returns
`ANTS_ERROR_NOT_IMPLEMENTED`, but the API contract is now reviewable
and the static library + ctest harness compile.

Public API declared in `foundation/crypto/include/ants_crypto.h`:

- **BLAKE3**: `ants_blake3_hash`, `ants_blake3_derive_key`, plus the
  incremental `init` / `update` / `final` family. Reserved
  domain-separation context strings from RFC-0008 §4.1 will be honoured
  by the implementation when it lands.
- **Ed25519**: `ants_ed25519_pubkey_from_priv`, `_sign`, `_verify`. Per
  RFC 8032.
- **BLS12-381**: `ants_bls_pubkey_from_priv`, `_sign`, `_verify`,
  `_aggregate`, `_verify_aggregate`. Per the IETF BLS signature draft
  with the ciphersuite RFC-0008 §3.3 names.
- **ECVRF-EDWARDS25519-SHA512-ELL2**: `ants_vrf_prove`, `_verify`. Per
  RFC 9381 with the Elligator 2 hash-to-curve.

The PR-by-primitive plan in `foundation/crypto/README.md` calls for
vendoring upstream reference implementations under `deps/<lib>/`
followed by a thin wrapper layer in `src/crypto.c`. Each vendoring
will preserve the upstream LICENSE notice and pin a specific
commit/version.

A placeholder test binary `crypto_basic` validates that every stub
returns `ANTS_ERROR_NOT_IMPLEMENTED` rather than crashing or returning
a misleading success.

Local: 2/2 ctest targets passing (`crypto_basic` + `cbor_basic`).
Format clean.

Next per-primitive PRs land in order: BLAKE3, Ed25519, BLS, ECVRF.

### foundation/cbor: implement ants_cbor_is_canonical (codec feature-complete) · 2026-05-20

The CBOR codec is now **feature-complete**. `ants_cbor_is_canonical`
walks every item in the input by calling each decode function (which
already enforces shortest-form, canonical-key-order, reserved-info
rejection, no-floats, no-indefinite-length), then requires:

- exactly `len` bytes consumed (no trailing data), AND
- depth back to -1 (every container properly closed).

A small static `walk_one_item` helper dispatches on
`ants_cbor_dec_peek_type` to the appropriate decode function and
recurses into arrays / maps / tagged items. Recursion depth is
bounded by `ANTS_CBOR_MAX_DEPTH` because the underlying decoder
rejects deeper nesting.

Test additions (9 new functions):

- `test_is_canonical_accepts_valid` — uint, array, map, tagged, mixed
  nesting `[tag 0 + uint 1, {1: true}]`
- `test_is_canonical_rejects_empty` — both `NULL` pointer and length 0
- `test_is_canonical_rejects_trailing` — bytes after the top-level item
- `test_is_canonical_rejects_non_shortest` — `0x18 0x00` (uint 0 in
  2-byte form)
- `test_is_canonical_rejects_indefinite` — indefinite-length array
  `0x9f 0x01 0xff`
- `test_is_canonical_rejects_unsorted_map` — keys out of order
- `test_is_canonical_rejects_underfill_array` — array(3) with 2 items
- `test_is_canonical_rejects_unreserved_tag` — tag 1
- `test_is_canonical_rejects_float` — float16 0xf9 0x3c 0x00

Local: `1/1 tests passed`, **52 internal test functions** now.
Format clean.

The CBOR codec is the first ants-client component to reach
feature-complete. Next session moves on to component #1 (crypto
primitives) — wrappers for BLAKE3, Ed25519, BLS12-381, ECVRF-ELL2,
with test-vector conformance against pinned implementations.

### foundation/cbor: implement major type 6 (tag) + bool + null · 2026-05-20

`ants_cbor` codec now implements every encode/decode primitive except
the top-level `ants_cbor_is_canonical` validator.

- **Tag** (major type 6): restricted to the RFC-0008 §1.1 reserved set
  {0, 32, 42}. Any other tag is rejected with
  `ANTS_ERROR_UNSUPPORTED_TYPE`. Tag opens a `ANTS_CBOR_CTX_TAG`
  context expecting exactly one tagged item; the tracker closes the
  TAG and registers the combined (tag header + tagged item) byte
  range as a single item in the parent. Symmetric on the decoder.
- **Bool**: encoded as 1-byte simple value 0xf4 (false) / 0xf5 (true).
  Decoder rejects 0xf6 (null) as `UNSUPPORTED_TYPE`.
- **Null**: encoded as 1-byte simple value 0xf6. Decoder rejects 0xf4
  / 0xf5 as `UNSUPPORTED_TYPE`.

The ctx-kind enum gained `ANTS_CBOR_CTX_TAG` and both track-item
helpers gained a TAG case. The single-decrement → close pattern is
identical to the array case at remaining=1.

Test additions (12 new functions):

- `test_encode_bool` / `test_decode_bool` /
  `test_decode_bool_rejects_non_bool`.
- `test_encode_null` / `test_decode_null` /
  `test_decode_null_rejects_non_null`.
- `test_encode_tag_reserved` covers all three reserved tags with the
  expected hex byte sequences (0xc0 0x05, 0xd8 0x20 0x05,
  0xd8 0x2a 0x62 0x68 0x69).
- `test_encode_tag_rejects_non_reserved` rejects tags 1, 31, 100.
- `test_decode_tag_reserved` round-trips all three.
- `test_decode_tag_rejects_non_reserved` rejects tag 1 on input.
- `test_encode_tag_in_array` exercises array-of-tagged-items nesting.
- `test_encode_map_with_simple_values` exercises `{1: true, 2: null}`
  to verify the canonical-key-order tracker works across simple-value
  values.

Local build clean, ctest 1/1 passing, format clean.

Only `ants_cbor_is_canonical` (the top-level validator that walks
every item and ensures exactly `len` bytes are consumed) remains
stubbed. Next PR closes CBOR.

### foundation/cbor: implement major types 4 (array) + 5 (map) · 2026-05-20

`ants_cbor` library now implements arrays and maps with
canonical-key-order enforcement on both encode and decode paths.

Mechanism:

- `ants_cbor_ctx_t` extended with `container_begin` so the tracker can
  register a closed container as a single item in its parent.
- `ants_cbor_dec_t` extended with `stack[]` + `depth` symmetric to the
  encoder, so canonical-key-order is enforced on decode too.
- Two static helpers `enc_track_item` and `dec_track_item` walk the
  context stack after each item is written/consumed, decrementing
  remaining counts, switching MAP_KEY ↔ MAP_VALUE state, and
  recursively closing full containers by registering them as items in
  their parents. Both helpers are *transactional*: any failure path
  restores the depth/stack to pre-call state via a snapshot at entry.
- `compare_keys` implements bytewise lexicographic comparison with
  length tiebreak per RFC 8949 §4.2.1, used by both encoder and
  decoder for map key ordering.

Canonical-encoding rules now enforced for maps:

- Keys must be **strictly monotonically increasing** in bytewise
  lexicographic order of their canonical CBOR encoding. The encoder
  rejects an out-of-order or duplicate key with
  `ANTS_ERROR_NON_CANONICAL`. The decoder symmetrically rejects an
  input that presents keys out of order.
- The encoder validates each new key against the byte range of the
  previously-added key (stored in the context stack).
- The decoder does the same against the input buffer.

Tests added (14 new test functions):

- `test_encode_array_empty / _flat / _nested / _underfill` — array
  round-trip including nested `[[1,2],[3]]`, plus underfill detection
  via `ants_cbor_enc_finalise` returning `ANTS_ERROR_MALFORMED`.
- `test_encode_map_empty / _canonical_order` — round-trip
  `{1:"one", 2:"two"}` to the expected byte string.
- `test_encode_map_rejects_unsorted_keys / _duplicate_keys` —
  encoder rejects key 1 after key 2, and key 1 after key 1.
- `test_encode_map_in_array` — mixed nesting
  `[{1:10}, {2:20}]`.
- `test_decode_array_round_trip / _empty` — symmetric decode.
- `test_decode_map_round_trip / _rejects_unsorted_keys /
  _rejects_duplicate_keys` — decoder enforces the same canonical-key
  order on input.

Still stubbed: major type 6 (tag), bool, null, `ants_cbor_is_canonical`.

Bug found and fixed during this iteration: `enc_track_item` /
`dec_track_item` were missing an `else { return ANTS_OK; }` after the
non-closing path, causing the loop to keep decrementing remaining
until the container was forced shut on the first item write. Caught
by `test_encode_array_underfill` (which expected MALFORMED on
finalise but got OK). The fix is two lines.

### foundation/cbor: implement major types 0–3 · 2026-05-20

`ants_cbor` library now implements:

- **Major type 0** — unsigned integer encode/decode with shortest-form
  enforcement (1/2/3/5/9-byte representations chosen by value range).
- **Major type 1** — signed integer encode/decode covering the full
  int64_t range, including the `-1 - n` convention for negatives.
- **Major type 2** — byte string encode/decode with length-prefixed
  shortest-form headers; decoder rejects truncated input as malformed.
- **Major type 3** — UTF-8 text string encode/decode; the codec does
  not validate UTF-8 well-formedness (caller's responsibility).
- **`ants_cbor_dec_peek_type`** for type dispatch.

Canonical-encoding discipline is enforced by `cbor_read_head` (a
static helper inside `cbor.c`):

- Reject non-shortest-form encodings (e.g., `0x18 0x00` is rejected
  because the value 0 must use the 1-byte form `0x00`).
- Reject indefinite-length items (additional info 31).
- Reject reserved additional-info values 28, 29, 30.

Tests cover round-trip for all listed major types, canonical
rejection vectors (non-shortest, indefinite, reserved), and overflow
when decoding a uint into `int64_t`. ~17 test functions in
`test_cbor.c`, single `cbor_basic` ctest target.

Still stubbed: major types 4 (array), 5 (map), 6 (tag), simple
values (bool, null), and `ants_cbor_is_canonical`. Next PR adds
arrays and maps with the canonical-key-order discipline (RFC 8949
§4.2.1 most important rule).

### CI workflow + clang-format · 2026-05-20

GitHub Actions workflow added (`.github/workflows/ci.yml`) with build
matrix across Linux GCC/Clang and macOS arm64 Clang, in Debug
(AddressSanitizer + UndefinedBehaviorSanitizer) and Release. A
separate ThreadSanitizer job runs on Ubuntu Clang. A
`clang-format`-check job validates formatting against the new
`.clang-format` config — currently a no-op trivially-passing since no
C source files exist yet, but in place for the first PRs landing
component code.

This is infrastructure-only: no component code, no behavioural
change. Establishes the review surface so subsequent PRs (CBOR
scaffolding, then CBOR implementation) have a working CI signal from
the first line of C.

---

## v0.0.1 — Scaffolding · 2026-05-20

Initial repository creation. No component code yet.

**Why:** the spec corpus closed both multi-persona review rounds
(see spec repo CHANGELOG Round 1 through Round 5) and the project
pivoted from "design" to "code preparation." The Round 5 decision
fixed the implementation language as **C (C99/C11)** with `ggml`
as the foundation for canonical kernels.

This scaffolding commit establishes:

- The 15-component / 6-layer directory structure per
  IMPLEMENTATION.md.
- CMake superbuild with strict portability discipline (C99 no
  extensions), sanitizers in Debug builds, optional ThreadSanitizer
  via `-DANTS_TSAN=ON`.
- Apache-2.0 OR MIT dual-license.
- Contributing process pointing back to the spec repo's `[CLAIM]
  Component #N` issue flow per IMPLEMENTATION.md §"How to claim a
  sub-component".
- One `README.md` per component subdirectory with spec reference,
  claim status (currently all "pending claim"), and intended
  interface.

No protocol behaviour is defined here. The bytes on the wire remain
specified by the spec repo's RFCs; this client will implement them
as components are claimed and code lands.
