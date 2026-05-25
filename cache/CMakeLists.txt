# cache/ layer
#
# Semantic cache (DHT-routed) and canonical embedding service.
# ~6 engineer-months total per IMPLEMENTATION.md.
# Depends on network/ + reputation/.

# Component #11 — Canonical embedding service  (1 EM)
add_subdirectory(embedding)

# Component #10 — Semantic cache (DHT-routed)  (5 EM)
# Depends on cache/embedding (ANTS_EMBED_DIM); must be enabled AFTER
# the embedding subdirectory above so ants_embed is a known target.
add_subdirectory(semantic)
