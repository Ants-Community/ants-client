# reputation/identity — Component #9 (the (A, T, κ) reputation spine).
#
# Spec: RFC-0004 v0.7 §"Tenure: the (A, T, κ) spine" + §"Computing A".
#
# Status: the (A, T, κ) spine + the saturating T_eff fork-choice transform
# + the L1 slash gate. The countersigned NCS receipt (canonical-CBOR body +
# dual Ed25519 verification), the deterministic fixed-point decay primitive
# (the spec-mandated alternative to non-deterministic float exp(), RFC-0004
# §"A reference sketch"), the A / T computation from a receipt bag,
# ants_reputation_compute_checked which zeroes a slashed peer's A and T via
# a caller-supplied L1 slash predicate (canonically ants_crdt_is_slashed
# over Component #7's G-Set), the full receipt-bag selective disclosure of
# receipts (the Merkle commitment + inclusion proofs + the A >= b subset
# recompute), and the signed compact summary (RFC-0008 §11.9 codec + the
# per-bucket audit check). The component's lib surface is complete; what
# remains is wiring bond admission / the slash predicate into the real
# high-stakes-act call sites — daemon-side composition, in later PRs.
# (Bond accounting itself is Component #15, economy/bond.)

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
    # explicitly (PRIVATE deps of the lib are not re-exported). It also
    # binds the REAL L1 slash predicate (ants_crdt_is_slashed over a live
    # G-Set built from a real equivocation proof) to exercise
    # ants_reputation_compute_checked end-to-end, so it links ants_crdt
    # (Component #7) — a test-only dep; the library itself takes no crdt
    # dependency (the slash source is a caller-supplied callback).
    target_link_libraries(test_reputation PRIVATE ants_reputation ants_crdt ants_crypto ants_cbor)
    add_test(NAME reputation_basic COMMAND test_reputation)
endif()
