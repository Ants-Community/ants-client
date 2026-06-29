# network/

The peer-to-peer transport, DHT, and gossip overlay. Depends on
`foundation/` (crypto, CBOR).

**Effort:** ~11 engineer-months total.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`transport/`](./transport) — P2P transport (#4) | 5 EM | RFC-0002 §DHT routing, RFC-0010 §First peer's flow | feature-complete (picoquic) |
| [`dht/`](./dht) — Kademlia DHT, shard-key variant (#5) | 3 EM | RFC-0002 §DHT routing | feature-complete |
| [`gossip/`](./gossip) — Gossip overlay for L1 CRDT (#6) | 3 EM | RFC-0004 §Layer 1 + §G-Set pruning | feature-complete |

## Transport: picoquic + ANTS-native protocol (decided 2026-05-21)

The earlier framing of the transport as "libp2p-c or external daemon
via IPC or custom" turned out to be impractical for a C99-pure
reference client. The decision landed in
[IMPLEMENTATION.md component #4](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)
and the [CHANGELOG entry](https://github.com/Ants-Community/ants/blob/main/spec/CHANGELOG.md)
on 2026-05-21:

- **Vendor [`picoquic`](https://github.com/private-octopus/picoquic)**
  (IETF QUIC reference implementation, pure C99, BSD-3-licensed,
  ~50k LOC). Snapshot-vendorable like `deps/blst`/`deps/blake3`/
  `deps/ed25519`. Gives us TLS 1.3 + multiplexed streams +
  congestion + NAT-friendly UDP transport without writing any of
  it ourselves.
- **ANTS-native application protocol on top of QUIC streams**:
  peer identity binding via Ed25519 + RFC 7250 raw-public-key
  (skipping X.509+CA), DHT query framing (RFC-0002 §DHT routing),
  gossip discipline (RFC-0004 §Layer 1), anti-eclipse peer
  selection (RFC-0005).

The libp2p path was dropped because the canonical implementations
are Go and Rust (both pull non-C runtimes), the C++ binding is
half-maintained, and the external-daemon-via-IPC approach carries
the same runtime dependency wrapped in process boundaries. None
fit the project's day-zero portability target.

## Build status

All three components are feature-complete at v0.x and are built + tested in
`network/CMakeLists.txt`. The original scaffold sequence was: API design →
scaffolding PR (all stubbed) → vendor picoquic under `deps/picoquic/` → wire the
transport wrapper → build DHT + gossip on top.
