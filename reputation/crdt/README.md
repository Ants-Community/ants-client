# crdt — Component #7

L1 CRDT (G-Set) implementation. Reputation & identity layer.
**On the critical path.**

**Status:** pending claim.
**Effort:** 4 EM.
**Spec:** [RFC-0004 v0.6 §Layer 1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md), §G-Set pruning + late-joiner protocol, §Archive nodes and the pruning-DoS defence.
**Dependencies:** `foundation/crypto`, `foundation/cbor`, `network/gossip`.

## Scope

The consensus-free grow-only set of self-authenticating fault proofs.

- `VERIFY(π)` deterministic context-free pure function for every
  proof type (verification fault, equivocation, bond misadmission,
  selective-disclosure forgery, vendor revocation, key-rotation
  equivocation).
- Gossip integration (via `network/gossip`) for propagation.
- **G-Set pruning** post-epoch-confirmation per RFC-0004 v0.5+ §G-Set
  pruning + late-joiner protocol.
- **Archive-node interface** with rarity flag + inverse-redundancy
  reward scaling per RFC-0004 v0.6 §Archive nodes and the pruning-DoS
  defence. Constant `R_ARCHIVE_MIN` (default 8).
- **Late-joiner protocol** with safe-direction-of-error default-slash
  on retrieval failure.

## Good-first-contribution flag

**No.** L1 CRDT is the architecture's load-bearing layer. Claims
from contributors with prior CRDT or self-authenticating-fact
experience (Automerge, Yjs, Riak, Roughtime).
