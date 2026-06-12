# reputation/crdt — Component #7 (the L1 consensus-free fault G-Set).
#
# Spec: RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set".
#
# Status: the self-authenticating fault proof (canonical-CBOR envelope +
# per-class evidence), VERIFY(π) for the equivocation and
# invalid-transition fault classes, the BLAKE3 content-address the G-Set
# dedupes on, and the G-Set container with pruning + the late-joiner
# snapshot. Gossip propagation is Component #6; the remaining fault
# classes land as the layers they depend on come online.

add_library(ants_crdt STATIC
    src/crdt.c
)

target_include_directories(ants_crdt
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_crypto (#1) — Ed25519 signature verification + the BLAKE3 content
# address — and ants_cbor (#2) — the canonical fault-proof codec — are
# PRIVATE deps: crdt.c calls their symbols directly. ants_cbor also hosts
# ants_strerror during the transitional period.
target_link_libraries(ants_crdt
    PRIVATE
        ants_crypto
        ants_cbor
)

target_compile_features(ants_crdt PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_crdt tests/test_crdt.c)
    # The test signs real statements (ants_ed25519_*), probes canonical
    # CBOR, needs ants_strerror, and cross-checks the invalid-transition
    # Merkle/block mirror against the REAL reputation/chain encoders
    # (ants_chain_confirmed_{root,prove}, the block codec) — the test is
    # what pins the two restated constructions bit-for-bit. crypto/cbor
    # symbols resolve transitively through the static libs' PRIVATE deps,
    # so we link only ants_crdt + ants_chain and add the include dirs the
    # test references directly (PRIVATE deps don't export include dirs;
    # linking them explicitly too would double them on the link line — the
    # macOS ld "ignoring duplicate libraries" warning).
    target_link_libraries(test_crdt PRIVATE ants_crdt ants_chain)
    target_include_directories(test_crdt PRIVATE
        ${CMAKE_SOURCE_DIR}/foundation/crypto/include
        ${CMAKE_SOURCE_DIR}/foundation/cbor/include)
    add_test(NAME crdt_basic COMMAND test_crdt)
endif()
