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

# PRIVATE deps (chain.c calls their symbols directly): ants_crypto (#1) —
# BLAKE3 for the confirmed_proofs Merkle + Ed25519 for finality; ants_cbor
# (#2) — the canonical EpochSummary / block codec (also hosts ants_strerror);
# ants_reputation (#9) — the saturating T_eff transform reused by the Σ T_eff
# fork choice, so the two components agree bit-for-bit. (CMake resolves the
# ants_reputation target even though identity/ is configured after chain/.)
target_link_libraries(ants_chain
    PRIVATE
        ants_crypto
        ants_cbor
        ants_reputation
)

target_compile_features(ants_chain PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_chain tests/test_chain.c)
    # The test recomputes BLAKE3 leaf/node hashes, signs real Ed25519
    # committee attestations, probes canonical CBOR, and cross-checks Σ T_eff
    # against ants_reputation_t_eff. All those symbols resolve transitively
    # through ants_chain's (static) PRIVATE deps, so we link ONLY ants_chain
    # and add the include directories for the headers the test references
    # directly (PRIVATE deps don't export their include dirs). Linking those
    # libs explicitly too would list them twice on the link line — the macOS
    # ld "ignoring duplicate libraries" warning.
    target_link_libraries(test_chain PRIVATE ants_chain)
    target_include_directories(test_chain PRIVATE
        ${CMAKE_SOURCE_DIR}/foundation/crypto/include
        ${CMAKE_SOURCE_DIR}/foundation/cbor/include
        ${CMAKE_SOURCE_DIR}/reputation/identity/include)
    add_test(NAME chain_basic COMMAND test_chain)
endif()
