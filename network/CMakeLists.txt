# network/ layer
#
# P2P transport, DHT, gossip overlay.
# ~11 engineer-months total per IMPLEMENTATION.md.
# Depends on foundation/ (crypto, CBOR).

# Component #4 — P2P transport  (5 EM: ~3 picoquic wrap + ~2 app protocol)
#
# v1.0 ships the API surface as a NOT_IMPLEMENTED stub so upstream
# components (DHT, gossip, reputation) can integrate against
# ants_transport.h now. The real implementation against vendored
# picoquic + picotls lands in subsequent PRs. See
# network/transport/README.md.
add_subdirectory(transport)

# Component #5 — Kademlia DHT (shard-key variant)  (3 EM)
#
# v1.0 ships the API surface as a NOT_IMPLEMENTED stub so upstream
# components (cache/semantic, reputation, anti-eclipse) can integrate
# against ants_dht.h now. Phases 2+ wire k-buckets, XOR-distance
# routing, CBOR-encoded RPCs, and the iterative-lookup state machine.
add_subdirectory(dht)

# Component #6 — Gossip overlay (L1 CRDT propagation)  (3 EM)
#
# PR1 ships the transport-agnostic dissemination engine + eager-push wire
# frame over the real L1 G-Set (reputation/crdt); byte delivery is behind a
# send callback. Wiring to real ants_transport streams + the inbound demux,
# lazy-pull anti-entropy, and anti-eclipse DHT peer sampling land later.
add_subdirectory(gossip)
