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
# add_subdirectory(dht)

# Component #6 — Gossip overlay (L1 CRDT propagation)  (3 EM)
# add_subdirectory(gossip)
