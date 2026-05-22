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
