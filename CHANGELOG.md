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
