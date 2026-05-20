# transport — Component #4

P2P transport. Network layer.

**Status:** pending claim.
**Effort:** 3 EM (via libp2p), 6 EM (custom).
**Spec:** [RFC-0002 §DHT routing](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-semantic-cache.md), [RFC-0010 §First peer's flow](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0010-bootstrap.md).
**Dependencies:** `foundation/crypto`, `foundation/cbor`.

## Scope

The base P2P transport: peer dialing, TLS-equivalent encrypted
channels, multiaddr support, NAT traversal, basic peer lifecycle.
Sits below the DHT (#5) and the gossip overlay (#6).

## Open architectural choice

Three plausible paths, per IMPLEMENTATION.md §"Language and stack"
and `network/README.md`:

1. **Custom minimal C transport** (UDP + TLS + Kademlia) — most
   portable, smallest dependency surface, ~6 EM.
2. **`libp2p-c`** (libp2p C bindings) — ~3 EM but library is still
   evolving.
3. **External daemon via IPC** (embed `go-libp2p` or `rust-libp2p`
   as a sidecar) — ~3 EM, fastest to ship, largest runtime dep.

The claim issue must propose a path with rationale.

## Good-first-contribution flag

**No.** Touches peer-lifecycle and the network's anti-eclipse
posture (RFC-0005). Claims from contributors with prior P2P
networking experience (libp2p, Tor, IPFS, BitTorrent, BGP).
