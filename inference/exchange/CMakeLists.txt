# inference/exchange — the inference exchange (RFC-0008 §11.14).
#
# INFER_REQ / INFER_RESP on the bidi-RPC envelope: a sibling dispatcher of
# the DHT server and network/attest on the same transport, claiming envelope
# types 11/12. The producer side is a callback; the requester side checks
# every answer with ants_inference_answer_check against the peer-id the
# transport authenticated.

add_library(ants_infer STATIC
    src/infer.c
    src/infer_wire.c
)

target_include_directories(ants_infer
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_inference (#13) and ants_transport (#4) are PUBLIC: ants_infer.h uses
# the commit type and the transport's conn/event types. ants_cbor (#2), the
# codec, is PRIVATE.
target_link_libraries(ants_infer
    PUBLIC
        ants_inference
        ants_transport
    PRIVATE
        ants_cbor
)

target_compile_features(ants_infer PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    # Codec + engine over real loopback QUIC (two transports), serving the
    # pinned v1 reference model.
    add_executable(test_infer tests/test_infer.c)
    target_link_libraries(test_infer PRIVATE ants_infer)
    target_include_directories(test_infer PRIVATE
        ${CMAKE_SOURCE_DIR}/foundation/crypto/include
    )
    add_test(NAME infer_basic COMMAND test_infer)
endif()
