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
    src/der.c
    src/x509.c
    src/x509_chain.c
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

    # The strict DER reader is internal (src/der.h, compiled into ants_tee);
    # the test includes the header directly and links the library.
    add_executable(test_der tests/test_der.c)
    target_link_libraries(test_der PRIVATE ants_tee)
    target_include_directories(test_der PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME der_basic COMMAND test_der)

    # The X.509 certificate parser is internal (src/x509.h, compiled into
    # ants_tee); the test includes the header directly. It also links
    # ants_crypto so the parsed leaf keys can be driven through the real
    # SNP/TDX/RSA verifiers end to end (parse -> hand the verifier the leaf).
    add_executable(test_x509 tests/test_x509.c)
    target_link_libraries(test_x509 PRIVATE ants_tee ants_crypto)
    target_include_directories(test_x509 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME x509_basic COMMAND test_x509)

    # The certificate-chain validator is internal (src/x509_chain.h, compiled
    # into ants_tee); the test includes the header directly. It links
    # ants_crypto so the full path validation runs against the real RSA-PSS +
    # ECDSA verifiers over genuine AMD + Intel vendor chains.
    add_executable(test_x509_chain tests/test_x509_chain.c)
    target_link_libraries(test_x509_chain PRIVATE ants_tee ants_crypto)
    target_include_directories(test_x509_chain PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME x509_chain_basic COMMAND test_x509_chain)
endif()

# ---- Vector emitter ------------------------------------------------------

# snp_vectors — emits the snp-report.verify test-vector pack (JSON on stdout,
# the ants-test-vectors house format) from the genuine Milan KAT report. Every
# verdict is confirmed against the compiled ants_snp_report_verify_signature
# before emission. Shares the report bytes with the tests via tests/.
#   ./build/foundation/tee/snp_vectors > .../vectors/snp-report/snp-report.json
add_executable(snp_vectors tools/snp_vectors.c)
target_link_libraries(snp_vectors PRIVATE ants_tee)
target_include_directories(snp_vectors PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# tdx_vectors — emits the tdx-quote.verify test-vector pack (JSON on stdout,
# the ants-test-vectors house format) from the genuine Sapphire Rapids KAT
# quote. Every verdict is confirmed against the compiled
# ants_tdx_quote_verify_signature before emission. Shares the quote bytes with
# the tests via tests/.
#   ./build/foundation/tee/tdx_vectors > .../vectors/tdx-quote/tdx-quote.json
add_executable(tdx_vectors tools/tdx_vectors.c)
target_link_libraries(tdx_vectors PRIVATE ants_tee)
target_include_directories(tdx_vectors PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
