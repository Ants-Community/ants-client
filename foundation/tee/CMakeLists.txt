# foundation/tee — TEE attestation harness (Component #3).
#
# v1.0: stub only — every function in ants_tee.h returns
# ANTS_ERROR_NOT_IMPLEMENTED. The API surface is pinned so upstream
# components (network, reputation, identity) can integrate against it
# without waiting for the real implementation.
#
# Real implementation: targeted v2.x per RFC-0005's hardware-trust
# timeline (2030-2032 silicon-vulnerability-window closure). See the
# component README and the open [CLAIM] issue at
# Ants-Community/ants#6.

add_library(ants_tee STATIC
    src/tee.c
)

target_include_directories(ants_tee
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (a transitional placement
# until we extract a shared common.c). Link against it so the tee
# tests can call ants_strerror without redefining the symbol.
target_link_libraries(ants_tee PUBLIC ants_cbor)

target_compile_features(ants_tee PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_tee tests/test_tee.c)
    target_link_libraries(test_tee PRIVATE ants_tee)
    add_test(NAME tee_basic COMMAND test_tee)
endif()
