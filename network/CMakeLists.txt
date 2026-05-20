# network/ layer
#
# P2P transport, DHT, gossip overlay.
# ~9–12 engineer-months total per IMPLEMENTATION.md.
# Depends on foundation/ (crypto, CBOR).

# Component #4 — P2P transport  (3 EM via libp2p, 6 EM custom)
# add_subdirectory(transport)

# Component #5 — Kademlia DHT (shard-key variant)  (3 EM)
# add_subdirectory(dht)

# Component #6 — Gossip overlay (L1 CRDT propagation)  (3 EM)
# add_subdirectory(gossip)
