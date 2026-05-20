# economy/

The user-visible economic surface: local per-pair NCS accounting and
bond accounting for high-stakes acts.

**Effort:** ~4 engineer-months total. Depends on `reputation/identity`
(component #9) for receipts and (A, T, κ) computation.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`ledger/`](./ledger) — Local economic ledger (#14) | 2 EM | RFC-0001 v0.3 | pending claim |
| [`bond/`](./bond) — Bond accounting service (#15) | 2 EM | RFC-0004 v0.6 §Bond accounting model + §Atomicity | pending claim |

Both components are relatively small in scope and well-defined by
their spec sections. The bond accounting service (#15) is one of the
three "good first contribution" components per IMPLEMENTATION.md
§"Parallelisable vs critical-path work" — although it is technically
on the critical path tail (`#13 → #15`), the actual work is small
once the (A, T, κ) primitives in `reputation/identity` are in place.

The local ledger (#14) implements the choke/unchoke loop, optimistic
unchoke slot, and the per-pair u64 μNCS accounting per RFC-0008 §6.
Payment-terms negotiation per RFC-0006 lives here too — though
RFC-0006 itself is still v0.1 (early) and may evolve.
