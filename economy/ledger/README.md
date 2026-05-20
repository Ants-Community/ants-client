# ledger — Component #14

Local economic ledger. Economy & coordination layer.

**Status:** pending claim.
**Effort:** 2 EM.
**Spec:** [RFC-0001 v0.3](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0001-community-economy.md), [RFC-0006 v0.1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0006-payment-terms.md).
**Dependencies:** `reputation/identity`, `foundation/cbor`.

## Scope

The per-pair NCS accounting that the community economy runs on.

- **Per-pair `served_to` / `served_by` running totals** in **u64 μNCS** per RFC-0008 §6. Floats forbidden in protocol-level objects.
- **Choke / unchoke loop** per RFC-0001 with `CHOKE_WINDOW` (default 20 min) and `CHOKE_LOOP_INTERVAL` (default 10 s).
- **Optimistic unchoke slot** per `OPTIMISTIC_UNCHOKE_RATIO` (default 12.5%).
- **Payment-terms negotiation** per RFC-0006 (the metadata field by which any peer declares its economic terms).

## Good-first-contribution flag

**Moderate.** Smaller scope than the critical-path components but
still touches the per-pair economic primitive. Suitable for
contributors comfortable with state machines and rate-limited
gossip discipline.
