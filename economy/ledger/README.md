# ledger — Component #14

Local economic ledger. Economy & coordination layer.

**Status:** PR1 (accounting core) implemented; choke/unchoke + payment-terms pending.
**Effort:** 2 EM.
**Spec:** [RFC-0001 v0.3](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0001-community-economy.md), [RFC-0006 v0.1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0006-payment-terms.md).
**Dependencies:** `foundation/cbor` (canonical record serialisation). The
choke/unchoke and payment-terms work will additionally use
`reputation/identity` once that component lands; PR1 does not depend on
it (the ledger keys peers by their raw 32-byte Ed25519 id).

## Scope

The per-pair NCS accounting that the community economy runs on.

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
  (RFC-0008 §1.1): a 7-pair integer-keyed map; the decoder is strict
  (non-canonical → `NON_CANONICAL`, structural damage → `MALFORMED`).

**Pending (later PRs):**

- **Choke / unchoke loop** per RFC-0001 with `CHOKE_WINDOW` (default 20 min) and `CHOKE_LOOP_INTERVAL` (default 10 s).
- **Optimistic unchoke slot** per `OPTIMISTIC_UNCHOKE_RATIO` (default 12.5%).
- **Payment-terms negotiation** per RFC-0006 (the metadata field by which any peer declares its economic terms).

The record already carries the `quality_q14k`, `choked`, and timestamp
fields the choke loop will drive, so the on-disk format will not change
when that work lands.

## Good-first-contribution flag

**Moderate.** Smaller scope than the critical-path components but
still touches the per-pair economic primitive. Suitable for
contributors comfortable with state machines and rate-limited
gossip discipline.
