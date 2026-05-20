# deps/blst — vendored supranational/blst v0.3.15
#
# Single-TU compilation: src/server.c #include-s every other .c file in
# src/. Building blst means compiling exactly server.c. The
# __BLST_NO_ASM__ define forces the portable C path; the asm files in
# build/{elf,coff,mach-o,cheri}/ are deliberately not vendored.
#
# Note on __BLST_NO_CPUID__: cpuid.c references x86 cpuid intrinsics
# that don't compile under arm64 even with __BLST_NO_ASM__. Defining
# __BLST_NO_CPUID__ tells server.c to skip cpuid.c entirely; the
# portable code does not need it.

add_library(blst STATIC
    src/server.c
)

target_include_directories(blst PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(blst PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(blst PRIVATE
    __BLST_NO_ASM__
    __BLST_NO_CPUID__
    __BLST_PORTABLE__
)

target_compile_features(blst PUBLIC c_std_99)

# Upstream blst is built strict; we relax the project's pedantic flags
# that blst does not target.
if(NOT MSVC)
    target_compile_options(blst PRIVATE
        -Wno-shadow
        -Wno-conversion
        -Wno-cast-qual
        -Wno-cast-align
        -Wno-undef
        -Wno-strict-prototypes
        -Wno-missing-prototypes
        -Wno-pedantic
        -Wno-sign-compare
        -Wno-unused-function
        -Wno-unused-variable
        -Wno-unused-parameter
    )
endif()

add_library(ants::blst ALIAS blst)
