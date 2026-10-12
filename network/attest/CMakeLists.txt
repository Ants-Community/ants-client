# network/attest — attestation presentation + the v1 handshake gate.
#
# Spec: RFC-0008 v0.9 §11.12 (ATTEST_REQ/ATTEST_RESP on the bidi-RPC
# envelope, presentation encoding, report_data binding, verification) and
# RFC-0005 v0.3 §"v1 admission posture: verify-and-tag".
#
# A sibling dispatcher of the DHT server on the same transport: it claims
# envelope types 9/10 and leaves 1-8 to the DHT. Verification is
# foundation/tee's ants_attestation_verify + ants_attestation_is_fresh
# against the peer-id the transport authenticated.

add_library(ants_attest STATIC
    src/attest.c
    src/attest_wire.c
)

target_include_directories(ants_attest
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_tee (#3) and ants_transport (#4) are PUBLIC: ants_attest.h uses
# ants_tee_vendor_t and the transport's conn/event types. ants_cbor (#2),
# the codec, is PRIVATE.
target_link_libraries(ants_attest
    PUBLIC
        ants_tee
        ants_transport
    PRIVATE
        ants_cbor
)

target_compile_features(ants_attest PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    # Codec + engine over real loopback QUIC (two transports), including
    # genuine vendor evidence from foundation/tee's KATs.
    add_executable(test_attest tests/test_attest.c)
    # Link only the top lib: ants_crypto (the test's real Ed25519 keys)
    # arrives transitively through ants_tee's static archive; linking it
    # again trips macOS 'ld: ignoring duplicate libraries'. Its headers
    # are not re-exported (PRIVATE dep of ants_tee), so add them.
    target_link_libraries(test_attest PRIVATE ants_attest)
    target_include_directories(test_attest PRIVATE
        ${CMAKE_SOURCE_DIR}/foundation/tee/tests
        ${CMAKE_SOURCE_DIR}/foundation/crypto/include
    )
    add_test(NAME attest_basic COMMAND test_attest)
endif()
