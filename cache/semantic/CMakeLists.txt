# cache/semantic — Component #10
#
# Spec: RFC-0002 v0.4 (Semantic cache).
# Effort: 5 EM.
#
# Status: scaffold. API surface declared; every entry point returns
# ANTS_ERROR_NOT_IMPLEMENTED. Subsequent steps land the LSH
# function, local-shard storage, eviction, DHT-routed write/lookup,
# and quality-signal aggregation.

add_library(ants_semantic_cache STATIC
    src/cache.c
    src/cache_wire.c
)

target_include_directories(ants_semantic_cache
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (same transitional placement
# the other components use). ants_embed for ANTS_EMBED_DIM. ants_crypto
# (BLAKE3) is PRIVATE — used internally to derive the LSH projection
# matrix from a fixed seed label; not exposed in our public API.
target_link_libraries(ants_semantic_cache
    PUBLIC
        ants_cbor
        ants_embed
    PRIVATE
        ants_crypto
)

# libm for sqrt/log/cos used by the LSH Box-Muller transform. On
# macOS clang links libm implicitly; glibc requires it explicit. Same
# guard cache/embedding uses for its stub L2-normalisation.
if(NOT MSVC AND NOT APPLE)
    target_link_libraries(ants_semantic_cache PUBLIC m)
endif()

target_compile_features(ants_semantic_cache PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_cache tests/test_cache.c)
    target_link_libraries(test_cache PRIVATE ants_semantic_cache)
    add_test(NAME cache_basic COMMAND test_cache)
endif()
