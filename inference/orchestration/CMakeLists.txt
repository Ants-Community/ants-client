# inference/orchestration — Component #13 (inference orchestration, ants-inference)
#
# Spec: RFC-0003 v0.2 + RFC-0009 v0.5.
# Effort: 4 EM.
#
# Status: scaffold. The full public API surface (ants_inference.h) is laid
# down with every entry point stubbed — argument validation runs, then the
# function returns ANTS_ERROR_NOT_IMPLEMENTED. Per-surface implementation
# PRs replace the stub bodies in turn:
#   1. commit-at-send       (leaf/Merkle hashing, commit encode/decode/sign)
#   2. challenge derivation (the three beacon-bound PRF derivations)
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
)

# ants_crypto (#1) — BLAKE3 leaf/Merkle hashing and Ed25519 commit signing —
# becomes a PRIVATE dependency once the commit-at-send implementation PR
# lands. Not linked yet: the scaffold stubs reference no crypto symbols, and
# (per the kernels component's precedent with ggml) we don't link what we
# don't yet use. libm follows the same rule — added with the e-process /
# discrepancy softmax implementation, guarded the usual NOT MSVC AND NOT APPLE.

target_compile_features(ants_inference PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_orchestration tests/test_orchestration.c)
    target_link_libraries(test_orchestration PRIVATE ants_inference)
    add_test(NAME orchestration_basic COMMAND test_orchestration)
endif()
