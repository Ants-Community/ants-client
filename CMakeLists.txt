# ants-client / root CMakeLists.txt
#
# The all-in-one reference client for the ANTS protocol.
# Decomposed into 15 sub-components across 6 layers, per
# IMPLEMENTATION.md in the spec repo (Ants-Community/ants).
#
# This is scaffolding: layer subdirectories are present but
# their component CMakeLists are minimal until claims arrive.
# Each layer enables its components by uncommenting their
# add_subdirectory() lines as code lands.

cmake_minimum_required(VERSION 3.20)
project(ants_client
        VERSION 0.0.1
        DESCRIPTION "Reference client for the ANTS protocol"
        HOMEPAGE_URL "https://github.com/Ants-Community/ants-client"
        LANGUAGES C CXX)
# C++ is required only for the vendored ggml (Component #11 canonical
# embedding service). Our own code remains strict C99 — only deps/ggml
# uses C++ (its ggml-cpu/ ops are .cpp since the v0.10 rewrite).

# ---- Language and portability discipline ---------------------------------
#
# C99 with no compiler extensions. Strict portability is a hard
# constraint of the project (per IMPLEMENTATION.md §Language and
# stack: "total cross-platform reach").

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release when not specified; Debug enables sanitizers.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

# ---- Warnings and static-analysis discipline ------------------------------
#
# These apply to every component target. Components may opt out for
# specific files only with explicit justification (vendored deps, etc.).

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion
        -Wstrict-prototypes -Wmissing-prototypes
        -Wcast-qual -Wcast-align
        -Wundef -Wpointer-arith
        -Wformat=2 -Wno-unused-parameter)
endif()

# ---- Sanitizers (Debug builds) -------------------------------------------
#
# AddressSanitizer + UndefinedBehaviorSanitizer on by default in
# Debug. ThreadSanitizer is mutually exclusive with ASan and is
# enabled via -DANTS_TSAN=ON.

option(ANTS_TSAN "Enable ThreadSanitizer (replaces ASan/UBSan)" OFF)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT MSVC)
    add_compile_options(-fno-omit-frame-pointer -g3)
    if(ANTS_TSAN)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    else()
        add_compile_options(-fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# ---- Release: optimisation + LTO ------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NOT MSVC)
        add_compile_options(-O3)
    endif()
    include(CheckIPOSupported)
    check_ipo_supported(RESULT lto_supported OUTPUT lto_error)
    if(lto_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# ---- Testing --------------------------------------------------------------

include(CTest)
enable_testing()

# ---- Layer subdirectories -------------------------------------------------
#
# Each layer maintains its own CMakeLists.txt with add_subdirectory()
# for the components within it. Components are uncommented in the
# layer's CMakeLists.txt as their code lands.

# Vendored dependencies (added as they arrive per-component).
add_subdirectory(deps/blake3)
add_subdirectory(deps/ed25519)
add_subdirectory(deps/blst)
add_subdirectory(deps/picotls)
add_subdirectory(deps/picoquic)
add_subdirectory(deps/ggml)
add_subdirectory(deps/jsmn)
add_subdirectory(deps/utf8proc)

add_subdirectory(foundation)
add_subdirectory(network)
add_subdirectory(reputation)
add_subdirectory(cache)
add_subdirectory(inference)
add_subdirectory(economy)

# ---- Status banner --------------------------------------------------------

message(STATUS "")
message(STATUS "ants-client ${PROJECT_VERSION}")
message(STATUS "  Build type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:    ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  System:      ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  Status:      scaffolding (no component code yet)")
message(STATUS "")
