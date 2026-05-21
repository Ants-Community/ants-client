# deps/picoquic — vendored private-octopus/picoquic (IETF QUIC reference)
#
# Status: picoquic-core static library. The OpenSSL, fusion (AES-NI),
# and mbedtls backends are NOT vendored (the three picoquic_ptls_*.c
# files plus mbedtls_sign.inc are excluded). We use the minicrypto
# backend exclusively — which is what picoquic_ptls_minicrypto.c
# provides — linking against deps/picotls/picotls_minicrypto.
#
# Upstream pinned at commit d9c705a (master HEAD, 2026-05-21).
# See README.md for the update procedure.

# Glob-style explicit list. We do NOT include:
#   picoquic_ptls_openssl.c  — OpenSSL backend, not vendored
#   picoquic_ptls_fusion.c   — AES-NI fusion backend, not vendored
#   picoquic_mbedtls.c       — mbedTLS backend, not vendored
add_library(picoquic_core STATIC
    picoquic/bbr.c
    picoquic/bbr1.c
    picoquic/bytestream.c
    picoquic/c4.c
    picoquic/cc_common.c
    picoquic/config.c
    picoquic/cubic.c
    picoquic/dualq_aqm.c
    picoquic/ech.c
    picoquic/error_names.c
    picoquic/fastcc.c
    picoquic/frames.c
    picoquic/frame_names.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/logwriter.c
    picoquic/loss_recovery.c
    picoquic/newreno.c
    picoquic/pacing.c
    picoquic/packet.c
    picoquic/packet_names.c
    picoquic/paths.c
    picoquic/performance_log.c
    picoquic/picohash.c
    picoquic/picoquic_lb.c
    picoquic/picoquic_ptls_minicrypto.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/port_blocking.c
    picoquic/prague.c
    picoquic/qmux.c
    picoquic/quicctx.c
    picoquic/register_all_cc_algorithms.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/sim_link.c
    picoquic/siphash.c
    picoquic/sockloop.c
    picoquic/spinbit.c
    picoquic/ticket_store.c
    picoquic/timing.c
    picoquic/token_store.c
    picoquic/tls_api.c
    picoquic/tp_names.c
    picoquic/transport.c
    picoquic/unified_log.c
    picoquic/util.c
)

target_include_directories(picoquic_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/picoquic
)

# Link picotls (TLS 1.3 backend). PUBLIC because picoquic exposes
# ptls_context_t in some public APIs.
target_link_libraries(picoquic_core PUBLIC picotls_minicrypto)

# Force minicrypto as the only crypto provider. The header
# picoquic_crypto_provider_api.h exposes per-backend init functions;
# we register only minicrypto.
target_compile_definitions(picoquic_core PRIVATE
    PICOQUIC_WITHOUT_OPENSSL=1
    PTLS_WITHOUT_OPENSSL=1
)

target_compile_features(picoquic_core PUBLIC c_std_99)

# Upstream is built with looser warning flags. Project pedantic set
# treats picoquic as vendored code (same approach as deps/blst).
if(NOT MSVC)
    target_compile_options(picoquic_core PRIVATE
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
        -Wno-unused-but-set-variable
        -Wno-implicit-fallthrough
        -Wno-format
    )
endif()

add_library(ants::picoquic ALIAS picoquic_core)
