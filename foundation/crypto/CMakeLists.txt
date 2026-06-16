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

# Vendored p256-m (deps/p256-m, upstream 44af59e) — ECDSA P-256 verify only,
# for TEE attestation signature chains (RFC-0005). crypto.c supplies the
# p256_generate_random fail-stub since we never sign/keygen with P-256.
target_link_libraries(ants_crypto PRIVATE p256m)

# Vendored BearSSL EC subset (deps/bearssl, upstream 7bea48e) — ECDSA verify on
# the NIST prime curves. ANTS uses P-384 (AMD SEV-SNP's attestation curve);
# p256-m is P-256-only. Verify-only, RNG-free, no local patches.
target_link_libraries(ants_crypto PRIVATE bearssl_ec)

target_compile_features(ants_crypto PUBLIC c_std_99)

# ECVRF-ELL2 needs direct access to libsodium's ref10 fe/ge/sc
# primitives; pulling in `private/ed25519_ref10.h` transitively
# instantiates a header full of static-inline implementations that
# trigger our pedantic warning set. The warnings are vendor-code
# noise (unused-static-inline, signed/unsigned narrowing inside
# 25.5/51-radix field arithmetic) — apply targeted suppressions
# rather than weakening the project-wide flags. Wrapper logic in
# crypto.c is still covered by the full warning set everywhere
# *except* through these specific suppressions.
if(NOT MSVC)
    target_compile_options(ants_crypto PRIVATE
        -Wno-unused-function
        -Wno-sign-conversion
    )
endif()

# libsodium's private/common.h emits `#warning` diagnostics unless the
# CONFIGURED and DEV_MODE build-tier macros are defined; they are
# defined inside deps/ed25519's own build, but PRIVATE there so they
# don't reach foundation/crypto when we include the same header.
target_compile_definitions(ants_crypto PRIVATE
    CONFIGURED=1
    DEV_MODE=1
    SODIUM_STATIC=1
)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(ants_crypto PRIVATE HAVE_TI_MODE=1)
endif()

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto PRIVATE ants_crypto)
    add_test(NAME crypto_basic COMMAND test_crypto)
endif()

# ecdsa_p256_vectors — emits the ecdsa-p256.verify test-vector pack (JSON on
# stdout, the ants-test-vectors house format). Vectors are sourced from
# Project Wycheproof; every verdict is confirmed against the compiled
# ants_ecdsa_p256_verify before emission.
#   ./build/foundation/crypto/ecdsa_p256_vectors > .../vectors/ecdsa-p256/ecdsa-p256.json
add_executable(ecdsa_p256_vectors tools/ecdsa_p256_vectors.c)
target_link_libraries(ecdsa_p256_vectors PRIVATE ants_crypto)

# ecdsa_p384_vectors — emits the ecdsa-p384.verify test-vector pack (JSON on
# stdout, the ants-test-vectors house format). Vectors are sourced from Project
# Wycheproof (ecdsa_secp384r1_sha512_p1363); every verdict is confirmed against
# the compiled ants_ecdsa_p384_verify and each digest computed by ants_sha512.
#   ./build/foundation/crypto/ecdsa_p384_vectors > .../vectors/ecdsa-p384/ecdsa-p384.json
add_executable(ecdsa_p384_vectors tools/ecdsa_p384_vectors.c)
target_link_libraries(ecdsa_p384_vectors PRIVATE ants_crypto)
