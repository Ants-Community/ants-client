# inference/kernels — Component #12 (canonical kernels, ants-canonical-kernels)
#
# Spec: RFC-0009 v0.5.
# Effort: 6–12 EM (CPU baseline) + 6–18 EM per GPU platform (v0.2+).
#
# Status: scaffold + first two kernels (q24 + per-token scale). Other
# entry points are stubs returning ANTS_ERROR_NOT_IMPLEMENTED.
#
# Implementation discipline per RFC-0009 §"The reference kernel library":
# `cpu_scalar.c` is the bit-exact reference. Future SIMD paths
# (avx2.c, avx512.c, neon.c, sve.c) link alongside and must produce
# byte-identical output against this reference for every test vector
# on every supported architecture.

add_library(ants_canon STATIC
    src/cpu_scalar.c
)

target_include_directories(ants_canon
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_cbor hosts ants_strerror for the transitional period (same
# placement as the other components). No runtime dependency on cbor
# in this PR — once Component #12 grows beyond pure-scalar kernels,
# ggml (already vendored under deps/) becomes a private dependency
# per RFC-0009.
target_link_libraries(ants_canon
    PUBLIC
        ants_cbor
)

# libm for fabsf / fmaxf / rintf / isnan / isinf. macOS clang links
# libm implicitly; glibc requires it explicit. Same guard the cache
# and embed components use.
if(NOT MSVC AND NOT APPLE)
    target_link_libraries(ants_canon PUBLIC m)
endif()

target_compile_features(ants_canon PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_canon tests/test_canon.c)
    target_link_libraries(test_canon PRIVATE ants_canon)
    add_test(NAME canon_basic COMMAND test_canon)
endif()
