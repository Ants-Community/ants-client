# reputation/chain — Component #8 (the L2 PoUH chain as ordered witness).
#
# Spec: RFC-0004 v0.6 §"Layer 2 — the PoUH chain as ordered witness",
# §"Partition recovery" (Σ T_eff fork choice + equivocation slashing +
# social-Schelling fallback).
#
# Status: PR1 — SCAFFOLD. The full public surface, the protocol structs
# (EpochSummary, PatternFinding, Block) and tunable constants, with every
# entry point present but returning ANTS_ERROR_NOT_IMPLEMENTED. Behaviour
# lands per the PR map in ants_chain.h: PR2 confirmed_proofs Merkle +
# EpochSummary codec, PR3 the pattern engine, PR4 VRF committee selection,
# PR5 block hashing + epoch-atomic signatures + 2/3 finality, PR6 Σ T_eff
# fork choice + partition recovery.
#
# Dependencies (wired as each PR first uses them, per "link what you use"):
# foundation/crypto (Ed25519, BLS aggregate, ECVRF), foundation/cbor (the
# canonical codec), reputation/crdt (#7 — VERIFY + content-id of the L1
# proofs the chain witnesses), reputation/identity (#9 — the saturating
# T_eff transform reused by Σ T_eff fork choice). The scaffold calls none
# of them yet, so PR1 links nothing.

add_library(ants_chain STATIC
    src/chain.c
)

target_include_directories(ants_chain
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

target_compile_features(ants_chain PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_chain tests/test_chain.c)
    target_link_libraries(test_chain PRIVATE ants_chain)
    add_test(NAME chain_basic COMMAND test_chain)
endif()
