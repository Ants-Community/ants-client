# network/gossip — Component #6 (gossip overlay, L1 CRDT propagation).
#
# Spec: RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set".
#
# Status: PR1 — the transport-agnostic dissemination engine + the
# eager-push wire frame. The reference-sketch path (receive → VERIFY-and-
# apply → dedup → forward to fanout) runs over the caller's real L1 G-Set
# (reputation/crdt), with byte delivery behind a send callback. Wiring the
# callback to real ants_transport bidi streams + the inbound demux, lazy-
# pull (IHAVE/IWANT) anti-entropy, and anti-eclipse DHT peer sampling land
# in later PRs.

add_library(ants_gossip STATIC
    src/gossip.c
    src/gossip_transport.c
)

target_include_directories(ants_gossip
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_crdt (#7) — the L1 G-Set used as the VERIFY-and-dedup oracle — is a
# PUBLIC dep: ants_gossip.h includes ants_crdt.h (the engine takes an
# ants_crdt_t*). ants_transport (#4) is PUBLIC too as of PR2: ants_gossip.h
# includes ants_transport.h for the transport binding (gossip_transport.c
# opens uni streams and demuxes inbound frames). ants_cbor (#2) — the
# push-frame codec — is PRIVATE: gossip.c calls it but the header does not
# expose it. ants_cbor also hosts ants_strerror during the transitional
# period.
target_link_libraries(ants_gossip
    PUBLIC
        ants_crdt
        ants_transport
    PRIVATE
        ants_cbor
)

target_compile_features(ants_gossip PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_gossip tests/test_gossip.c)
    # Link ONLY the top lib: ants_gossip's static archive transitively pulls
    # ants_crdt + ants_transport (PUBLIC) and ants_cbor + ants_crypto (one
    # level down), so every symbol the test calls resolves. Linking just the
    # top lib avoids the macOS 'ld: ignoring duplicate libraries' warning.
    # The test references headers of those lower-level libs directly (real
    # Ed25519 proofs via ants_crypto, frame encode via ants_cbor, the G-Set
    # via ants_crdt) — PRIVATE deps don't re-export include dirs, so add them
    # explicitly. ants_transport's headers come through the PUBLIC link.
    target_link_libraries(test_gossip PRIVATE ants_gossip)
    target_include_directories(test_gossip PRIVATE
        ${CMAKE_SOURCE_DIR}/reputation/crdt/include
        ${CMAKE_SOURCE_DIR}/foundation/crypto/include
        ${CMAKE_SOURCE_DIR}/foundation/cbor/include
    )
    add_test(NAME gossip_basic COMMAND test_gossip)
endif()
