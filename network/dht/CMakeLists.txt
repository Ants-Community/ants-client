# network/dht — Component #5
#
# v1.0 scaffold: API surface + stubs returning NOT_IMPLEMENTED.
# Subsequent PRs land the k-bucket data structure, XOR-distance
# routing, wire-message encoding (CBOR), and lookup state machine.
#
# Spec: RFC-0002 §DHT routing.
# Dependencies (link-time): network/transport, foundation/cbor,
# foundation/crypto.

add_library(ants_dht STATIC
    src/dht.c
    src/dht_lookup.c
    src/dht_rpc.c
    src/dht_server.c
    src/dht_wire.c
)

target_include_directories(ants_dht
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (transitional placement
# until we extract a shared common.c). ants_crypto provides Ed25519
# types referenced by the DHT header. ants_transport gives us peer
# connections and streams to drive RPCs over.
target_link_libraries(ants_dht
    PUBLIC
        ants_cbor
        ants_crypto
        ants_transport
)

target_compile_features(ants_dht PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_dht tests/test_dht.c)
    target_link_libraries(test_dht PRIVATE ants_dht)
    # Tests need access to the private src/ header for the wire codec
    # round-trip tests. Not exposed via target_include_directories on
    # the library — only the test target sees it.
    target_include_directories(test_dht PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    add_test(NAME dht_basic COMMAND test_dht)
endif()
