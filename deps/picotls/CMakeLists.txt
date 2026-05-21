# deps/picotls — vendored h2o/picotls (TLS 1.3 backend for picoquic)
#
# Status: picotls-minicrypto target only. The OpenSSL, fusion (AES-NI),
# mbedTLS, and AEGIS backends are NOT vendored; we want a single C99
# build with no optional accel paths. cifra (CC0) provides the symmetric
# primitives; micro-ecc (2-clause BSD) provides secp256r1.
#
# Upstream pinned at commit 7c32032 (head of master, 2026-05-21).
# See README.md for the update procedure.

# ---- Core (TLS state machine) ---------------------------------------------

add_library(picotls_core STATIC
    lib/picotls.c
    lib/hpke.c
    lib/pembase64.c
)

target_include_directories(picotls_core SYSTEM PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(picotls_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/cifra/src
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/cifra/src/ext
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/micro-ecc
)

target_compile_features(picotls_core PUBLIC c_std_99)

# _GNU_SOURCE exposes Linux glibc functions that picotls relies on
# (posix_memalign, strdup, syscall) without making them visible
# under a strict C99 feature-test set. Same generator-expression
# guard as deps/picoquic — no-op on Windows and macOS (where these
# are unconditionally exposed).
target_compile_definitions(picotls_core PRIVATE
    $<$<NOT:$<PLATFORM_ID:Windows>>:_GNU_SOURCE=1>
)

# Upstream is built with looser warning flags; the project's pedantic
# set treats picotls as vendored code (same approach as deps/blst).
if(NOT MSVC)
    target_compile_options(picotls_core PRIVATE
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
        -Wno-implicit-fallthrough
    )
endif()

# ---- Minicrypto (cifra + micro-ecc) ---------------------------------------

add_library(picotls_minicrypto STATIC
    # cifra symmetric primitives
    deps/cifra/src/aes.c
    deps/cifra/src/blockwise.c
    deps/cifra/src/chacha20.c
    deps/cifra/src/chash.c
    deps/cifra/src/curve25519.c
    deps/cifra/src/drbg.c
    deps/cifra/src/hmac.c
    deps/cifra/src/gcm.c
    deps/cifra/src/gf128.c
    deps/cifra/src/modes.c
    deps/cifra/src/poly1305.c
    deps/cifra/src/sha256.c
    deps/cifra/src/sha512.c
    # micro-ecc (secp256r1)
    deps/micro-ecc/uECC.c
    # picotls minicrypto adapter
    lib/cifra.c
    lib/cifra/x25519.c
    lib/cifra/chacha20.c
    lib/cifra/aes128.c
    lib/cifra/aes256.c
    lib/cifra/random.c
    lib/minicrypto-pem.c
    lib/uecc.c
    lib/asn1.c
    lib/ffx.c
)

target_include_directories(picotls_minicrypto SYSTEM PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(picotls_minicrypto PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/cifra/src
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/cifra/src/ext
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/micro-ecc
)

target_link_libraries(picotls_minicrypto PUBLIC picotls_core)
target_compile_features(picotls_minicrypto PUBLIC c_std_99)

# Same _GNU_SOURCE rationale as picotls_core (cifra adapter + uecc
# also pull glibc functions on Linux). No-op on macOS/Windows.
target_compile_definitions(picotls_minicrypto PRIVATE
    $<$<NOT:$<PLATFORM_ID:Windows>>:_GNU_SOURCE=1>
)

if(NOT MSVC)
    target_compile_options(picotls_minicrypto PRIVATE
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
        -Wno-implicit-fallthrough
    )
endif()

add_library(ants::picotls ALIAS picotls_minicrypto)
