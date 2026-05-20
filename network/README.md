# network/

The peer-to-peer transport, DHT, and gossip overlay. Depends on
`foundation/` (crypto, CBOR).

**Effort:** ~9–12 engineer-months total.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`transport/`](./transport) — P2P transport (#4) | 3–6 EM | RFC-0002 §DHT routing, RFC-0010 §First peer's flow | pending claim |
| [`dht/`](./dht) — Kademlia DHT, shard-key variant (#5) | 3 EM | RFC-0002 §DHT routing | pending claim |
| [`gossip/`](./gossip) — Gossip overlay for L1 CRDT (#6) | 3 EM | RFC-0004 §Layer 1 + §G-Set pruning | pending claim |

**Open architectural choice on transport.** The P2P transport
component has three plausible implementation paths (named in
IMPLEMENTATION.md §"Language and stack"):

1. **Custom minimal C transport** (UDP + TLS + Kademlia) — most
   portable, smallest dependency surface, longest to write.
2. **`libp2p-c`** (libp2p C bindings, less mature than `rust-libp2p`
   or `go-libp2p`) — moderate dependency surface, library is still
   evolving.
3. **External daemon via IPC** — embed `go-libp2p` as a sidecar
   daemon, communicate via local IPC. Largest dependency surface,
   fastest to implement.

The decision is deferred to the component's primary contributor;
the claim issue should propose the path with rationale.
