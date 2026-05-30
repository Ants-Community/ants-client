# identity — Component #9

Identity & reputation service. Reputation & identity layer.

**Status:** PR1 (the (A, T, κ) spine) implemented; bonds + selective disclosure pending.
**Effort:** 3 EM.
**Spec:** [RFC-0004 v0.6 §Tenure + §Bond accounting + §Selective disclosure](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md); [RFC-0005 §Multi-vendor reputation weighting](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md).
**Dependencies:** `foundation/crypto`, `foundation/cbor`. (Bonds + slash
integration will additionally use `foundation/tee` + `reputation/crdt`
once those are built; PR1 does not — it computes A/T from a verified
receipt bag with nothing but crypto + cbor.)

## Scope

The implementation of the (A, T, κ) spine and the bond-accounting
primitives the rest of the architecture depends on.

**Implemented (PR1 — the spine):**

- **The countersigned NCS receipt** (RFC-0004 §"The receipt that matters
  for tenure"): canonical-CBOR signed body (server, client, ncs_value,
  timestamp, nonce) + dual Ed25519 signatures; `verify` requires BOTH.
- **Deterministic fixed-point decay** — the spec-mandated alternative to
  non-deterministic float `exp()` (RFC-0004 §"A reference sketch": "the
  production code uses a fixed-point decay table — see RFC-0009"). Decay
  over k bins is `r^k` in q32 fixed-point, computed by binary
  exponentiation (the exact multiply sequence is the pinned recipe, since
  q32 multiply is not associative under truncation). Bit-identical across
  platforms, so every honest peer computes the same `T_X`.
- **The (A, T) computation** (RFC-0004 §816 / §825): `A` = uncapped
  fast-decayed sum of verified receipts; `T` = per-bin, κ-clipped,
  slow-decayed sum. Invalid / wrong-server / future-dated receipts are
  skipped. No allocation; one stack bool array caches per-receipt
  validity so signatures are verified once.

> **Numeric constants are DRAFT placeholders, NOT calibrated.** RFC-0004
> §835 makes δ_A, δ_T, and κ b2-class testnet measurements. The
> fixed-point *recipe* is the deliverable; the ratio/κ/bin-width *values*
> are illustrative (so the code runs and tests). The recipe should be
> upstreamed to RFC-0004 (or an RFC-0009-style reputation-numerics
> section) and the values fixed by b2 before peers compute interoperable
> tenure.

**Pending (later PRs):**

- **Saturating `T_eff` fork-choice transform** (RFC-0004 §"The saturating
  T → T_eff transform").
- **Receipt-bag Merkle tree** + **selective disclosure** (RFC-0004
  §"Selective disclosure of receipts"): inclusion proofs, lower-bound
  property, positive/negative asymmetry.
- **Bond accounting** + **race-safe admission** (RFC-0004 §"Bond
  accounting model" / §Atomicity) — needs `reputation/crdt` for slash
  integration.
- **Multi-vendor attestation lookups** via `foundation/tee` (RFC-0005).

## Good-first-contribution flag

**No.** The (A, T, κ) computation is load-bearing for verifier
eligibility, bond capacity, and fork-choice. Claims from
contributors with prior reputation-system experience or
proof-system tooling.
