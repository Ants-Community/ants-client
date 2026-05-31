# reputation/crdt — Component #7 (the L1 consensus-free fault G-Set).
#
# Spec: RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set".
#
# Status: PR1 — the self-authenticating fault proof. The canonical-CBOR
# fault-proof wire format (envelope + equivocation evidence), VERIFY(π)
# for the equivocation fault class (two Ed25519 checks + an inequality),
# and the BLAKE3 content-address the G-Set dedupes on. The G-Set
# container, the pruning + late-joiner protocol, gossip propagation, and
# the other fault classes land in later PRs.

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
    # CBOR, and needs ants_strerror, so it links crypto and cbor
    # explicitly (PRIVATE deps of the lib are not re-exported).
    target_link_libraries(test_crdt PRIVATE ants_crdt ants_crypto ants_cbor)
    add_test(NAME crdt_basic COMMAND test_crdt)
endif()
