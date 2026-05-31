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
)

target_include_directories(ants_gossip
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_crdt (#7) — the L1 G-Set used as the VERIFY-and-dedup oracle — is a
# PUBLIC dep: ants_gossip.h includes ants_crdt.h (the engine takes an
# ants_crdt_t*). ants_cbor (#2) — the push-frame codec — is PRIVATE:
# gossip.c calls it but the header does not expose it. ants_cbor also hosts
# ants_strerror during the transitional period. The transport layer is
# deliberately NOT a dependency in PR1 (delivery is behind a callback).
target_link_libraries(ants_gossip
    PUBLIC
        ants_crdt
    PRIVATE
        ants_cbor
)

target_compile_features(ants_gossip PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_gossip tests/test_gossip.c)
    # The test builds real equivocation proofs (ants_crdt_* + ants_crypto +
    # ants_cbor) and exercises two in-process gossip instances exchanging
    # frames, so it links crdt, crypto, and cbor explicitly (PRIVATE deps
    # of the lib are not re-exported).
    target_link_libraries(test_gossip PRIVATE ants_gossip ants_crdt ants_crypto ants_cbor)
    add_test(NAME gossip_basic COMMAND test_gossip)
endif()
