# deps/ed25519 — vendored libsodium 1.0.22 Ed25519 ref10 subset.
#
# Portable C only; SIMD paths disabled. Symbol scope is reduced to the
# Ed25519 keypair/sign/verify primitives + the SHA-512 portable path
# they require + the constant-time compare functions + minimal utility
# (memzero, misuse handler).

add_library(ed25519_sodium STATIC
    src/sign_ed25519.c
    src/ref10_keypair.c
    src/ref10_sign.c
    src/ref10_open.c
    src/ed25519_ref10_core.c
    src/hash_sha512.c
    src/verify.c
    src/utils.c
    src/sodium_stub.c
)

target_include_directories(ed25519_sodium PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(ed25519_sodium PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/private
)

# Force the portable C path everywhere. The libsodium code uses
# `#ifdef HAVE_X` to gate platform-specific code; we therefore must NOT
# define those macros at all (defining them to 0 still triggers
# #ifdef true). The only HAVE_* we positively define is HAVE_TI_MODE
# for 64-bit ti-mode field arithmetic on 64-bit hosts.
target_compile_definitions(ed25519_sodium PRIVATE
    CONFIGURED=1          # libsodium private/common.h gate
    DEV_MODE=1
    SODIUM_STATIC=1
)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(ed25519_sodium PRIVATE HAVE_TI_MODE=1)
endif()

# Upstream code uses many constructs that trigger the project's strict
# warning set; relax for these vendored sources only.
if(NOT MSVC)
    target_compile_options(ed25519_sodium PRIVATE
        -Wno-shadow
        -Wno-conversion
        -Wno-cast-qual
        -Wno-cast-align
        -Wno-undef
        -Wno-strict-prototypes
        -Wno-missing-prototypes
        -Wno-format
        -Wno-pedantic
        -Wno-sign-compare
        -Wno-pointer-arith
        -Wno-unused-but-set-variable
        -Wno-unused-function
        -Wno-unused-variable
        -Wno-unused-parameter
        -Wno-implicit-function-declaration
    )
endif()

add_library(ants::ed25519 ALIAS ed25519_sodium)
