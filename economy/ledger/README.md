# ledger — Component #14

Local economic ledger. Economy & coordination layer.

**Status:** PR1 (accounting core) + PR2 (choke/unchoke loop) implemented; payment-terms pending.
**Effort:** 2 EM.
**Spec:** [RFC-0001 v0.3](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0001-community-economy.md), [RFC-0006 v0.1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0006-payment-terms.md).
**Dependencies:** `foundation/cbor` (canonical record serialisation). The
payment-terms work will additionally use `reputation/identity` once that
component lands; the code so far does not depend on it (the ledger keys
peers by their raw 32-byte Ed25519 id, and the generosity score is purely
local recent-receipts).

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

**Pending (later PRs):**

- **Payment-terms negotiation** per RFC-0006 (the metadata field by which any peer declares its economic terms).

## Good-first-contribution flag

**Moderate.** Smaller scope than the critical-path components but
still touches the per-pair economic primitive. Suitable for
contributors comfortable with state machines and rate-limited
gossip discipline.
