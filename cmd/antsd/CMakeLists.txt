# cmd/antsd — the ANTS node daemon (the composing process).
#
# The daemon owns all node state (the libraries are caller-owns-memory
# and never malloc) and drives a single-threaded event loop over the
# QUIC transport, the Kademlia DHT and the gossip engine:
#   antsd init <config>  — generate an Ed25519 identity + write a config
#   antsd show <config>  — decode + print a config
#   antsd run  <config>  — stand up transport + DHT (bootstrapped from
#                          the config seeds) + gossip (view fed from DHT
#                          discovery, refreshed on the anti-eclipse
#                          epoch cadence) and drive the tick loop until
#                          SIGINT/SIGTERM
# The chain loop lands next.

add_library(antsd_config STATIC config.c)
target_include_directories(antsd_config
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)
# ants_cbor: the canonical codec. ants_crypto: Ed25519 size constants used
# by the config struct.
target_link_libraries(antsd_config PUBLIC ants_cbor ants_crypto)
target_compile_features(antsd_config PUBLIC c_std_99)

add_executable(antsd antsd.c run.c util.c)
target_link_libraries(antsd PRIVATE antsd_config ants_gossip ants_dht ants_crdt ants_transport
                                    ants_crypto)
target_compile_features(antsd PRIVATE c_std_99)

if(BUILD_TESTING)
    add_executable(test_antsd_config tests/test_antsd_config.c)
    target_link_libraries(test_antsd_config PRIVATE antsd_config)
    add_test(NAME antsd_config_basic COMMAND test_antsd_config)

    # Integration test: spawns the real antsd binary (its path arrives
    # as argv[1]), dials it over loopback QUIC, runs an in-process seed
    # node the daemon bootstraps its DHT against, then SIGTERMs it and
    # requires a clean exit.
    add_executable(test_antsd_run tests/test_antsd_run.c)
    target_link_libraries(test_antsd_run PRIVATE antsd_config ants_dht ants_transport)
    add_test(NAME antsd_run_basic COMMAND test_antsd_run $<TARGET_FILE:antsd>)
endif()
