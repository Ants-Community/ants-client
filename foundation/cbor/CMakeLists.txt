# foundation/cbor — Deterministic CBOR codec.
#
# Spec: RFC-0008 §1.1. Implements RFC 8949 §4.2.1 strict deterministic
# encoding. Decoder rejects non-canonical inputs.
#
# Status: API surface declared; implementation is stubbed (returns
# ANTS_ERROR_NOT_IMPLEMENTED). Implementation lands in subsequent PRs.

add_library(ants_cbor STATIC
    src/cbor.c
)

target_include_directories(ants_cbor
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

target_compile_features(ants_cbor PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_cbor tests/test_cbor.c)
    target_link_libraries(test_cbor PRIVATE ants_cbor)
    add_test(NAME cbor_basic COMMAND test_cbor)
endif()
