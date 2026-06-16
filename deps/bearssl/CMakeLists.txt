# deps/bearssl — vendored subset of BearSSL (MIT): ECDSA signature
# verification on the NIST prime curves (constant-time "i31" backend) plus the
# SHA-384/512 hash.
#
# Upstream: bearssl.org (Thomas Pornin) @ 7bea48e (2026-04-06). BearSSL is a
# portable, clean-room C90 TLS/crypto library. We vendor ONLY the dependency
# closure of (1) br_ecdsa_i31_vrfy_raw over br_ec_prime_i31 — the generic-prime
# ECDSA *verifier* (P-256 / P-384 / P-521) consuming raw IEEE-P1363 (r||s)
# signatures — and (2) br_sha384 / br_sha512 (sha2big). ANTS uses both for AMD
# SEV-SNP attestation: the report is signed ECDSA P-384 over a SHA-384 digest
# (RFC-0005). Intel TDX is P-256 / SHA-256 (P-256 via deps/p256-m, SHA-256 via
# blst). The sources are byte-for-byte upstream — no local patches.
#
# Closure (empirically reduced: each file was removed until the verifier
# stopped linking, then restored — see README.md):
#   - i31_*.c              the i31 (31-bit-limb) big-integer backend
#   - i32_div32.c          br_divrem, called by br_i31_muladd_small
#   - ec_prime_i31.c       generic-prime curve point arithmetic
#   - ec_secp{256,384,521}r1.c  curve parameters. ec_prime_i31.c's dispatch
#                          table names all three; the two ANTS does not verify
#                          with are unreferenced and dropped by the linker —
#                          kept so ec_prime_i31.c stays unmodified upstream.
#   - ecdsa_i31_vrfy_raw.c + ecdsa_i31_bits.c   the P1363 verifier
#   - ccopy.c              br_ccopy, constant-time conditional copy
#   - sha2big.c            br_sha384 + br_sha512 (the SHA-2 512-family)
#   - dec64be.c, enc64be.c br_range_{dec,enc}64be, sha2big's block codec
#
# Verify-only and RNG-free: no sign/keygen path is compiled, and neither the
# verify nor the hash closure pulls in a DRBG (no RNG symbol is referenced).
# The wrappers (ants_ecdsa_p384_verify, ants_sha384) live in
# foundation/crypto/src/crypto.c.

add_library(bearssl_ec STATIC
    src/ccopy.c
    src/ec_prime_i31.c
    src/ec_secp256r1.c
    src/ec_secp384r1.c
    src/ec_secp521r1.c
    src/ecdsa_i31_bits.c
    src/ecdsa_i31_vrfy_raw.c
    src/i31_add.c
    src/i31_bitlen.c
    src/i31_decmod.c
    src/i31_decode.c
    src/i31_decred.c
    src/i31_encode.c
    src/i31_fmont.c
    src/i31_iszero.c
    src/i31_moddiv.c
    src/i31_modpow.c
    src/i31_modpow2.c
    src/i31_montmul.c
    src/i31_mulacc.c
    src/i31_muladd.c
    src/i31_ninv31.c
    src/i31_reduce.c
    src/i31_rshift.c
    src/i31_sub.c
    src/i31_tmont.c
    src/i32_div32.c
    src/sha2big.c
    src/dec64be.c
    src/enc64be.c
)

# Public: the BearSSL API headers (br_ecdsa_i31_vrfy_raw, br_ec_prime_i31,
# br_ec_public_key) for the wrapper in foundation/crypto.
target_include_directories(bearssl_ec PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)
# Private: inner.h / config.h live alongside the sources.
target_include_directories(bearssl_ec PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Upstream BearSSL is high-quality, constant-time C, but it does not target
# the project-wide pedantic warning set (chiefly -Wundef on its feature-probe
# #if ladders). Relax warnings for the vendored source only; the wrapper in
# foundation/crypto keeps the full set.
if(NOT MSVC)
    target_compile_options(bearssl_ec PRIVATE
        -Wno-undef
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-shadow
        -Wno-cast-qual
        -Wno-cast-align
        -Wno-strict-prototypes
        -Wno-missing-prototypes
        -Wno-unused-function
        -Wno-pedantic
    )
endif()

# Help foundation/crypto link against this target by name.
add_library(ants::bearssl_ec ALIAS bearssl_ec)
