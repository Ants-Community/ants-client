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
# T_eff transform reused by Σ T_eff fork choice). PR2 wires crypto + cbor (the
# Merkle + codec use them); crdt + identity wire in with their PRs.

add_library(ants_chain STATIC
    src/chain.c
)

target_include_directories(ants_chain
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_crypto (#1) — BLAKE3 for the confirmed_proofs Merkle — and ants_cbor
# (#2) — the canonical EpochSummary codec — are PRIVATE deps: chain.c calls
# their symbols directly (since PR2). ants_cbor also hosts ants_strerror
# during the transitional period. reputation/crdt (#7) + reputation/identity
# (#9) wire in with their PRs (VRF/finality/fork-choice).
target_link_libraries(ants_chain
    PRIVATE
        ants_crypto
        ants_cbor
)

target_compile_features(ants_chain PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_chain tests/test_chain.c)
    # The test recomputes BLAKE3 leaf/node hashes independently and probes
    # canonical CBOR (ants_cbor_is_canonical), so it links crypto + cbor
    # explicitly (PRIVATE deps of the lib are not re-exported).
    target_link_libraries(test_chain PRIVATE ants_chain ants_crypto ants_cbor)
    add_test(NAME chain_basic COMMAND test_chain)
endif()
