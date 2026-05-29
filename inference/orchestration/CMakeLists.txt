# inference/orchestration — Component #13 (inference orchestration, ants-inference)
#
# Spec: RFC-0003 v0.2 + RFC-0009 v0.5.
# Effort: 4 EM.
#
# Status: surfaces 1-2 implemented. The full public API surface
# (ants_inference.h) is laid down; the commit-at-send and challenge-derivation
# surfaces have real implementations, the other two still validate arguments
# and return ANTS_ERROR_NOT_IMPLEMENTED until their PRs land:
#   1. commit-at-send       (leaf/Merkle hashing, commit encode/decode/sign) — DONE
#   2. challenge derivation (the three beacon-bound PRF derivations) — DONE
#   3. betting e-process    (init/update + discrepancy scoring)
#   4. serving runtime      (init/destroy/serve + the audit capstone)

add_library(ants_inference STATIC
    src/orchestration.c
)

target_include_directories(ants_inference
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_canon (#12) is a PUBLIC dependency: the public header ants_inference.h
# includes ants_canon.h (the audited path operates on canonical q24 logit
# vectors). ants_canon in turn brings ants_cbor PUBLIC, which hosts
# ants_strerror during the transitional period — so the test binary resolves
# it transitively without an explicit link here.
target_link_libraries(ants_inference
    PUBLIC
        ants_canon
    PRIVATE
        ants_crypto
        ants_cbor
)

# ants_crypto (#1) — BLAKE3 leaf/Merkle hashing and Ed25519 commit signing —
# and ants_cbor (#2) — the canonical commit encode/decode — are PRIVATE
# dependencies of the commit-at-send surface: orchestration.c calls their
# symbols directly, so they are linked explicitly rather than leaned on
# transitively (ants_canon already brings ants_cbor PUBLIC, but we link what
# we use). libm still follows the don't-link-what-you-don't-use rule — it
# joins with the e-process / discrepancy softmax implementation, guarded the
# usual NOT MSVC AND NOT APPLE.

target_compile_features(ants_inference PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_orchestration tests/test_orchestration.c)
    # ants_crypto is a PRIVATE dep of ants_inference, so it is NOT re-exported
    # to the test; the commit-at-send tests recompute BLAKE3 leaf/node hashes
    # and Ed25519 signatures independently, so the test links it directly.
    # ants_cbor (for ants_cbor_is_canonical) arrives transitively through
    # ants_canon's PUBLIC link — the same path that already supplies
    # ants_strerror and the q24 types — so linking it again here is redundant.
    target_link_libraries(test_orchestration PRIVATE ants_inference ants_crypto)
    add_test(NAME orchestration_basic COMMAND test_orchestration)
endif()
