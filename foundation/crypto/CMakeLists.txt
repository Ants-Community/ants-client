# foundation/crypto — Crypto primitives library.
#
# Spec: RFC-0008 §§ 2–4 (BLAKE3, Ed25519, BLS12-381, ECVRF-ELL2).
#
# Status: API surface declared; implementation is stubbed (returns
# ANTS_ERROR_NOT_IMPLEMENTED). Per-primitive implementations land in
# subsequent PRs by vendoring mature C reference implementations under
# deps/.

add_library(ants_crypto STATIC
    src/crypto.c
)

target_include_directories(ants_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (a transitional placement
# until we extract a shared common.c). Link against it so the crypto
# tests can call ants_strerror without redefining the symbol.
target_link_libraries(ants_crypto PUBLIC ants_cbor)

# Vendored BLAKE3 (deps/blake3, pinned to 1.8.5).
target_link_libraries(ants_crypto PRIVATE blake3)

# Vendored Ed25519 from libsodium ref10 (deps/ed25519, pinned to 1.0.22).
target_link_libraries(ants_crypto PRIVATE ed25519_sodium)

# Vendored BLS12-381 from supranational/blst (deps/blst, pinned to 0.3.15,
# portable C path via __BLST_NO_ASM__).
target_link_libraries(ants_crypto PRIVATE blst)

target_compile_features(ants_crypto PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto PRIVATE ants_crypto)
    add_test(NAME crypto_basic COMMAND test_crypto)
endif()
