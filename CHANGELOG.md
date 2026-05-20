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
