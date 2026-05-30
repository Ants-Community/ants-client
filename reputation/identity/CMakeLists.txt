# reputation/identity — Component #9 (the (A, T, κ) reputation spine).
#
# Spec: RFC-0004 v0.6 §"Tenure: the (A, T, κ) spine" + §"Computing A".
#
# Status: PR1 — the spine. The countersigned NCS receipt (canonical-CBOR
# body + dual Ed25519 verification), the deterministic fixed-point decay
# primitive (the spec-mandated alternative to non-deterministic float
# exp(), RFC-0004 §"A reference sketch"), and the A / T computation from a
# receipt bag. The saturating T_eff fork-choice transform, bond
# accounting + race-safe admission, selective disclosure, the receipt-bag
# Merkle tree, and L1/L2 slash integration land in later PRs.

add_library(ants_reputation STATIC
    src/reputation.c
)

target_include_directories(ants_reputation
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_crypto (#1) — Ed25519 dual-signature verification — and ants_cbor
# (#2) — the canonical receipt-body encoding — are PRIVATE deps:
# reputation.c calls their symbols directly. ants_cbor also hosts
# ants_strerror during the transitional period.
target_link_libraries(ants_reputation
    PRIVATE
        ants_crypto
        ants_cbor
)

target_compile_features(ants_reputation PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_reputation tests/test_reputation.c)
    # The test signs real receipts (ants_ed25519_*) and probes canonical
    # CBOR + needs ants_strerror, so it links both crypto and cbor
    # explicitly (PRIVATE deps of the lib are not re-exported).
    target_link_libraries(test_reputation PRIVATE ants_reputation ants_crypto ants_cbor)
    add_test(NAME reputation_basic COMMAND test_reputation)
endif()
