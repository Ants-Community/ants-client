# deps/ggml — vendored ggml v0.12.0 portable CPU subset
#
# ANTS reference client's vendored snapshot of ggml. Used by the
# canonical embedding service (Component #11) for BGE-M3 inference.
#
# Source: https://github.com/ggml-org/ggml @ v0.12.0 (tag).
# License: MIT (see LICENSE in this directory, preserved from upstream).
#
# What is vendored:
#   - Core: ggml.{c,cpp}, ggml-alloc.c, ggml-quants.c
#   - Backend abstraction: ggml-backend*.cpp, gguf.cpp, ggml-opt.cpp,
#     ggml-threading.{h,cpp}
#   - CPU backend: src/ggml-cpu/ (ggml-cpu.{c,cpp}, ops.cpp,
#     binary-ops.cpp, unary-ops.cpp, vec.cpp, quants.c, repack.cpp,
#     traits.cpp) — generic-C path only
#
# What is NOT vendored:
#   - GPU backends (CUDA, Metal, Vulkan, OpenCL, ROCm/HIP, SYCL,
#     MUSA, Hexagon, CANN, OpenVino, WebGPU, ZDNN, Zen DNN, virtGPU,
#     RPC) — protocol does not require GPU inference; the canonical
#     embedding is small enough for CPU. Future PRs may add backends
#     once we measure portable-CPU latency against the spec's
#     "sub-200 ms on commodity CPU" target.
#   - Per-arch optimised quant kernels (src/ggml-cpu/arch/) — we set
#     GGML_CPU_GENERIC which routes through the portable C
#     implementations in the parent dir. The arch-optimised paths
#     can be re-vendored if/when CPU inference latency becomes a
#     real bottleneck.
#   - HBM, KleidiAI, AMX, llamafile, spacemit extensions — irrelevant
#     for the canonical inference path.
#
# Compile discipline:
#   - C99 + C++17 (ggml uses structured bindings, lambdas, deduction).
#   - All upstream warnings relaxed via -w (the upstream code is
#     high-quality but triggers our project's strict -Wshadow /
#     -Wconversion / -Wpedantic set).
#   - SYSTEM include directives so vendored warnings don't surface in
#     downstream compilation units.

if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

set(_GGML_SOURCES
    # Core
    src/ggml.c
    src/ggml.cpp
    src/ggml-alloc.c
    src/ggml-quants.c
    # Backend abstraction
    src/ggml-backend.cpp
    src/ggml-backend-reg.cpp
    src/ggml-backend-dl.cpp
    src/ggml-backend-meta.cpp
    src/ggml-opt.cpp
    src/ggml-threading.cpp
    src/gguf.cpp
    # CPU backend (generic-C path only)
    src/ggml-cpu/ggml-cpu.c
    src/ggml-cpu/ggml-cpu.cpp
    src/ggml-cpu/ops.cpp
    src/ggml-cpu/binary-ops.cpp
    src/ggml-cpu/unary-ops.cpp
    src/ggml-cpu/vec.cpp
    src/ggml-cpu/quants.c
    src/ggml-cpu/repack.cpp
    src/ggml-cpu/traits.cpp
)

add_library(ggml STATIC ${_GGML_SOURCES})

# Public include paths are SYSTEM so consumers don't get pedantic
# warnings from ggml's headers in their own compilation units.
target_include_directories(ggml SYSTEM PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Private include paths for ggml's own .c/.cpp files.
target_include_directories(ggml PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ggml-cpu
)

target_compile_definitions(ggml PRIVATE
    # Force generic portable-C path (no per-arch SIMD intrinsics).
    GGML_CPU_GENERIC
    # CPU backend is the only one compiled in; this is the flag
    # ggml-backend-reg.cpp uses to register it.
    GGML_USE_CPU
    # Upstream ggml expects these to be set by its CMake (version
    # banner + build commit). We pin the version we vendored and use
    # a fixed string for the commit so reproducible builds get the
    # same banner without us tracking the upstream HEAD.
    GGML_VERSION="0.12.0"
    GGML_COMMIT="vendored-ants-client"
)

# ggml's source triggers our project's strict warning set in places
# (e.g. -Wshadow on long inline expressions, -Wcast-qual on
# `void *` shuffles in backend dispatch). Silence them for the
# vendored sources only — our own code retains the strict set.
target_compile_options(ggml PRIVATE -w)

# C++17 for the .cpp sources; C11 for the .c sources to match ggml's
# upstream language requirement.
target_compile_features(ggml PUBLIC c_std_11 cxx_std_17)

# pthreads on POSIX (ggml-threading uses pthread for the work
# distribution). On Windows ggml uses native threads.
find_package(Threads REQUIRED)
target_link_libraries(ggml PUBLIC Threads::Threads)
