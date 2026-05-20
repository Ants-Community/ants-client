# gossip — Component #6

Gossip overlay (L1 CRDT propagation). Network layer.

**Status:** pending claim.
**Effort:** 3 EM.
**Spec:** [RFC-0004 §Layer 1](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md), §G-Set pruning, §Archive nodes; anti-eclipse from [RFC-0005](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md).
**Dependencies:** `network/transport`, `foundation/crypto`, `foundation/cbor`.

## Scope

The gossip discipline that propagates L1 CRDT fault proofs, bond
admissions, key-rotation announcements, and (after Round 4 HARD)
archive-redundancy reports.

The component must enforce:

- **Anti-eclipse peer selection** — the standing assumption that
  every honest peer has at least one honest path of length
  `≤ T_prop/Δ` to every other honest peer.
- **`T_prop < T_beacon`** — the binding cross-layer constraint per
  RFC-0004 §"The binding cross-layer constraint" between gossip
  latency and verifier-rotation cadence.
- **Rate limits** per RFC-0004 §DoS, with attributable-fault penalty
  for relaying invalid proofs.

## Good-first-contribution flag

**No.** Gossip correctness underpins the L1 CRDT's one-honest-path
property. Claims from contributors with prior gossip-protocol
experience (Cosmos Tendermint, Hyperledger, libp2p gossipsub,
Solana Turbine).
