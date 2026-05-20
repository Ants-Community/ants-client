# deps/blake3 — vendored BLAKE3 v1.8.5
#
# Portable C only. SIMD acceleration sources are not vendored yet (see
# README.md). The compile definitions below force the dispatch to the
# portable path on every architecture.

add_library(blake3 STATIC
    blake3.c
    blake3_dispatch.c
    blake3_portable.c
)

target_include_directories(blake3 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
    BLAKE3_USE_NEON=0
)

# Upstream BLAKE3 is high-quality C but it does not target the
# pedantic warning set we use project-wide. Relax warnings for these
# vendored sources only.
if(NOT MSVC)
    target_compile_options(blake3 PRIVATE
        -Wno-shadow
        -Wno-conversion
        -Wno-cast-qual
        -Wno-cast-align
        -Wno-undef
        -Wno-strict-prototypes
        -Wno-missing-prototypes
        -Wno-format
        -Wno-pedantic
    )
endif()

# Help foundation/crypto link against this target by name.
add_library(ants::blake3 ALIAS blake3)
