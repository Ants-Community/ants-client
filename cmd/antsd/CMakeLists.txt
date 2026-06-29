# cmd/antsd — the ANTS node daemon (the composing process).
#
# PR 1: the skeleton — a CBOR config codec (antsd_config) + the `antsd`
# CLI with `init` (generate an Ed25519 identity + write a config) and
# `show` (decode + print a config). The live transport event loop, and
# the `run` command that drives it, land next.

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

add_executable(antsd antsd.c)
target_link_libraries(antsd PRIVATE antsd_config ants_crypto)
target_compile_features(antsd PRIVATE c_std_99)

if(BUILD_TESTING)
    add_executable(test_antsd_config tests/test_antsd_config.c)
    target_link_libraries(test_antsd_config PRIVATE antsd_config)
    add_test(NAME antsd_config_basic COMMAND test_antsd_config)
endif()
