# dht — Component #5

Kademlia DHT (shard-key variant). Network layer.

**Status:** pending claim.
**Effort:** 3 EM.
**Spec:** [RFC-0002 §DHT routing](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-semantic-cache.md).
**Dependencies:** `network/transport`.

## Scope

A Kademlia variant adapted to use **LSH-derived shard keys** as node
identifiers, per RFC-0002 §DHT routing. Each embedding is reduced to
a 64-bit shard key by projecting onto 64 pseudorandom hyperplanes
(the projection matrix is part of the protocol spec, fixed once per
embedding model version) and taking the sign of each projection.

A lookup query computes its own shard key, then queries the DHT for
peers responsible for that key plus near-neighbour shards (Hamming
distance 1, 2, sometimes 3).

## Good-first-contribution flag

**No.** Touches routing correctness which is load-bearing for the
cache layer. Claims from contributors with prior DHT experience
(libp2p Kademlia, BitTorrent DHT, IPFS DHT).
