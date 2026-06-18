# foundation/tee — TEE attestation harness (Component #3).
#
# A v1 deliverable, in progress (un-deferred from v2.x on 2026-06-15).
# The uniform ants_attestation_* surface is still a stub; the per-vendor
# structure parsers + report-signature verifiers land incrementally on
# top of foundation/crypto. AMD SEV-SNP report parse + signature verify
# is the first (ECDSA P-384 over SHA-384). See the component README and
# the open [CLAIM] issue at Ants-Community/ants#6.

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

# SNP report-signature verification uses SHA-384 + ECDSA P-384 from
# foundation/crypto. Private: crypto is an implementation detail, not
# part of the ants_tee.h surface.
target_link_libraries(ants_tee PRIVATE ants_crypto)

target_compile_features(ants_tee PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_tee tests/test_tee.c)
    target_link_libraries(test_tee PRIVATE ants_tee)
    add_test(NAME tee_basic COMMAND test_tee)
endif()
