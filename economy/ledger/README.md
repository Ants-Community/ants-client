# ledger — Component #14

Local economic ledger. Economy & coordination layer.

**Status:** PR1 (accounting core) + PR2 (choke/unchoke loop) + PR3 (payment-terms object) implemented — Component #14 feature-complete at the v0.x level.
**Effort:** 2 EM.
**Spec:** [RFC-0001 v0.3](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0001-community-economy.md), [RFC-0006 v0.1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0006-payment-terms.md).
**Dependencies:** `foundation/cbor` (canonical record serialisation). None
of the code so far depends on `reputation/identity` (the ledger keys peers
by their raw 32-byte Ed25519 id, the generosity score is purely local
recent-receipts, and payment terms are a self-describing advertisement).

## Scope

The per-pair NCS accounting and the choke/unchoke scheduler that the
community economy runs on.

**Implemented (PR1 — the accounting core):**

- **Per-pair `served_to` / `served_by` running totals** in **u64 μNCS**
  per RFC-0008 §6. No floats anywhere; credits are overflow-checked and
  a credit that would exceed `UINT64_MAX` is rejected with the total
  left unchanged (RFC-0008 §6: "overflow … causes the transaction to be
  rejected").
- **Signed net balance computed on demand** from the two unsigned
  totals (never stored), with an `int64` range guard. Negative balances
  are impossible to store by construction.
- **Canonical-CBOR record (de)serialisation** for the local on-disk log
  (RFC-0008 §1.1): an integer-keyed map; the decoder is strict
  (non-canonical → `NON_CANONICAL`, structural damage → `MALFORMED`).

**Implemented (PR2 — the choke / unchoke loop):**

- **Windowed generosity score** over a per-peer recent-receipts ring
  buffer (`ants_ledger_record_recv` records a receipt + credits the
  total; `ants_ledger_generosity` sums receipts inside `CHOKE_WINDOW`).
  Reputation is *recent behaviour*, not accumulated wealth (RFC-0001).
- **`ants_ledger_unchoke_round`**: ranks peers by `generosity × quality`
  (quality is a multiplier, not a replacement), unchokes the earned
  slots, and reserves a 1/8 **optimistic-unchoke** slot for a not-
  recently-served peer (network porosity for newcomers). RNG-free: the
  optimistic pick rotates deterministically via a caller-advanced
  counter. Caller-owned score scratch, no internal allocation.
- The recent-receipts ring is persisted in the CBOR record (key 8), so a
  restart does not wipe every peer's generosity window.

> **Spec note:** RFC-0001's pseudocode shows `slots // 4` for the
> optimistic reservation, but its prose ("12.5% of capacity") and the
> RFC-0008 §7 constants table (`OPTIMISTIC_UNCHOKE_RATIO = 12.5% = 1/8`)
> say 1/8. We follow 1/8 (authoritative) and flag the pseudocode/table
> mismatch for an upstream clarification.

**Implemented (PR3 — the payment-terms object, RFC-0006):**

- **`payment_terms` advertisement object** (`ants_payment.h` /
  `payment.c`): the structured metadata by which a peer declares the
  economic terms it transacts under. An ordered list of `PaymentScheme`s
  (most-preferred first), a `validity` deadline, a `scope`, and free-form
  `notes`. The six schemes of RFC-0006 §"Standard schemes" are modelled:
  `none`, `ncs`, `fiat_stripe`, `fiat_lightning`, `subscription`,
  `custom`; each carries only its kind's fields (no floats — Stripe rate
  and Lightning sats are u64).
- **Canonical-CBOR codec** (RFC-0008 §1.1) + structural validation +
  `ants_payment_terms_intersects` (the RFC-0006 match test: do two
  parties share at least one scheme kind). The decoder is strict — a
  scheme whose key set does not match its kind, an over-long text field,
  too many schemes, or any non-canonical framing is rejected.
- **Deliberately out of scope** (RFC-0006 is v0.1 early): the requester's
  candidate-ranking / price-matching *policy* (described in prose, not
  pinned), cross-economy cache settlement, and the fiat-NCS gateway. This
  PR ships the stable object + codec, not the volatile policy.

Payment terms are a separate module (`payment.c`) inside this component,
linked into `ants_ledger`; they are conceptually distinct from the
per-pair NCS ledger but share the economy layer and the CBOR discipline.

## Good-first-contribution flag

**Moderate.** Smaller scope than the critical-path components but
still touches the per-pair economic primitive. Suitable for
contributors comfortable with state machines and rate-limited
gossip discipline.
