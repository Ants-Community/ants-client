# deps/p256-m — vendored p256-m (NIST P-256 ECDSA + ECDH), Apache-2.0.
#
# Upstream: github.com/mpg/p256-m @ 44af59e (2022-06-15). A single-file,
# constant-time, dependency-free C implementation (~700 LOC of code, more
# comments than code), by the mbed TLS crypto maintainer, written to be
# auditable.
#
# ANTS uses it for ECDSA P-256 *verification only* — checking the vendor
# signature chains in TEE attestation quotes (RFC-0005; Intel TDX is P-256,
# AMD SEV-SNP is P-384, a later sibling). We never sign or generate keys with
# P-256 (peer identity is Ed25519). The externally-supplied RNG hook
# `p256_generate_random` (declared by p256-m.h, referenced only on the
# sign/keygen paths) is provided as a fail-stub by foundation/crypto — see
# crypto.c. Verification pulls in no RNG and no external library.

add_library(p256m STATIC
    p256-m.c
)

target_include_directories(p256m PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Upstream p256-m is high-quality, constant-time C, but it does not target
# the project-wide pedantic warning set. Relax warnings for the vendored
# source only; the wrapper in foundation/crypto keeps the full set.
if(NOT MSVC)
    target_compile_options(p256m PRIVATE
        -Wno-shadow
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-cast-qual
        -Wno-cast-align
        -Wno-undef
        -Wno-strict-prototypes
        -Wno-missing-prototypes
        -Wno-unused-function
        -Wno-pedantic
    )
endif()

# Help foundation/crypto link against this target by name.
add_library(ants::p256m ALIAS p256m)
