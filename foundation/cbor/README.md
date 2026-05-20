# cbor — Component #2

CBOR canonical codec. Foundation layer.

**Status:** **feature-complete** (BDFL interim primary; claim still open for review/co-maintenance). All major types 0-6 implemented with full RFC 8949 §4.2.1 canonical-encoding discipline, bool/null subset of type 7 implemented, top-level `ants_cbor_is_canonical` validator implemented. ~52 internal test functions in `tests/test_cbor.c`; CI verde on every push.
**Effort:** 1 EM.
**Spec:** [RFC-0008 §1.1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md) (deterministic CBOR per RFC 8949 §4.2.1).
**Dependencies:** none internal. Candidate baselines: [`tinycbor`](https://github.com/intel/tinycbor) (Intel) or [`nanocbor`](https://github.com/bergzand/NanoCBOR).

## Scope

Encode and decode CBOR objects following RFC 8949 with the
**deterministic encoding** discipline of §4.2.1:

- Shortest-form integer encoding.
- Definite-length encoding for arrays, maps, and byte strings.
- Map keys sorted by bytewise lexicographic order of their canonical
  CBOR encoding.
- No indefinite-length items.
- No tags except those explicitly listed in RFC-0008 §1.1
  (currently: tag 0, tag 32, tag 42).

Per RFC-0008 §10 "What we have not figured out yet", most existing
CBOR libraries are **non-conformant** on the deterministic encoding
rules. Expect to fork `tinycbor` or `nanocbor` and add the
discipline; alternatively, write from scratch (small surface: ~500
lines of audited C).

## Intended public API

```c
// cbor_encode.h
typedef struct ants_cbor_enc ants_cbor_enc_t;
ants_error_t ants_cbor_enc_init(ants_cbor_enc_t *enc, uint8_t *buf, size_t cap);
ants_error_t ants_cbor_enc_uint(ants_cbor_enc_t *enc, uint64_t v);
ants_error_t ants_cbor_enc_int(ants_cbor_enc_t *enc, int64_t v);
ants_error_t ants_cbor_enc_bytes(ants_cbor_enc_t *enc, const uint8_t *b, size_t len);
ants_error_t ants_cbor_enc_text(ants_cbor_enc_t *enc, const char *s, size_t len);
ants_error_t ants_cbor_enc_array(ants_cbor_enc_t *enc, size_t n);
ants_error_t ants_cbor_enc_map(ants_cbor_enc_t *enc, size_t n);  // keys must be added in canonical order
ants_error_t ants_cbor_enc_bool(ants_cbor_enc_t *enc, bool v);
ants_error_t ants_cbor_enc_tag(ants_cbor_enc_t *enc, uint64_t tag);
size_t       ants_cbor_enc_size(const ants_cbor_enc_t *enc);

// cbor_decode.h
typedef struct ants_cbor_dec ants_cbor_dec_t;
ants_error_t ants_cbor_dec_init(ants_cbor_dec_t *dec, const uint8_t *buf, size_t len);
ants_error_t ants_cbor_dec_uint(ants_cbor_dec_t *dec, uint64_t *out);
ants_error_t ants_cbor_dec_int(ants_cbor_dec_t *dec, int64_t *out);
ants_error_t ants_cbor_dec_bytes(ants_cbor_dec_t *dec, const uint8_t **out, size_t *out_len);
// ...

// cbor_validate.h
//
// Decoder MUST reject inputs that violate §4.2.1 determinism rules,
// not just parse them leniently. Validation is part of the canonical
// contract — a non-deterministic input is a protocol-level error.
bool ants_cbor_is_canonical(const uint8_t *buf, size_t len);
```

The strict-validation rejection of non-canonical inputs is the
component's most-important security property: a peer that accepts
non-canonical CBOR opens itself to hash-malleability attacks across
the whole stack (commit objects, fault proofs, attestations).

## Test vectors

Per RFC-0008 §8, every CBOR-encoded protocol object type has
fixed-input/fixed-output vectors in
[`ants-test-vectors`](https://github.com/Ants-Community/ants-test-vectors).
The codec passes iff every vector round-trips byte-identically and
every adversarial non-canonical input is rejected.

## Good-first-contribution flag

**Yes.** Per IMPLEMENTATION.md §"Parallelisable vs critical-path
work", this is one of three "small, scope-clear, test-cleanly"
first-contribution candidates. Suitable for any C programmer
comfortable with byte-level discipline and willing to read RFC
8949 carefully.
