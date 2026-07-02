# network/transport — P2P transport (Component #4).
#
# Implemented: encrypted, authenticated, multiplexed QUIC streams over
# vendored picoquic + picotls, with RFC 7250 raw-pubkey TLS identity
# binding (the Ed25519 peer pubkey IS the TLS auth key). A few
# peer-introspection accessors remain NOT_IMPLEMENTED in v1.0 — see the
# status note in ants_transport.h.
#
# See:
#   - network/transport/README.md for the picoquic decision rationale
#   - Ants-Community/ants IMPLEMENTATION.md component #4 row
#   - Ants-Community/ants/spec/CHANGELOG.md "P2P transport: picoquic,
#     not libp2p" entry (2026-05-21)

add_library(ants_transport STATIC
    src/transport.c
)

target_include_directories(ants_transport
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (transitional placement
# until we extract a shared common.c). ants_crypto provides Ed25519
# types/constants referenced by the transport header.
target_link_libraries(ants_transport PUBLIC ants_cbor ants_crypto)

# Phase 1: link picoquic for the real init/destroy lifecycle.
# Subsequent phases use the same dep for tick / dial / streams.
target_link_libraries(ants_transport PRIVATE picoquic_core)

target_compile_features(ants_transport PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_transport tests/test_transport.c)
    target_link_libraries(test_transport PRIVATE ants_transport)
    add_test(NAME transport_basic COMMAND test_transport)
endif()
