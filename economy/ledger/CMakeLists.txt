# economy/ledger — Component #14 (local economic ledger).
#
# Spec: RFC-0001 v0.3 §"The local ledger" + §"The choke / unchoke
# algorithm"; RFC-0006 v0.1 (payment terms); RFC-0008 v0.5 §6 (NCS as u64
# micro-NCS) + §1.1 (canonical CBOR) + §7 (choke constants).
#
# Status: PR1 accounting core + PR2 choke/unchoke loop + PR3 payment-terms
# object. ledger.c = the per-pair NCS accounting and the choke/unchoke
# scheduler; payment.c = the RFC-0006 payment_terms advertisement object
# and its canonical-CBOR codec.

add_library(ants_ledger STATIC
    src/ledger.c
    src/payment.c
)

target_include_directories(ants_ledger
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_cbor (#2) is a PRIVATE dependency: the public header ants_ledger.h
# includes only ants_common.h; ledger.c calls the canonical CBOR codec
# directly for record (de)serialisation. ants_cbor also hosts
# ants_strerror during the transitional period.
target_link_libraries(ants_ledger
    PRIVATE
        ants_cbor
)

target_compile_features(ants_ledger PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_ledger tests/test_ledger.c)
    # ants_cbor is a PRIVATE dep of ants_ledger, so it is NOT re-exported to
    # the test; the test calls ants_cbor directly (the non-canonical-int
    # probe) and needs ants_strerror, so it links ants_cbor explicitly.
    target_link_libraries(test_ledger PRIVATE ants_ledger ants_cbor)
    add_test(NAME ledger_basic COMMAND test_ledger)

    add_executable(test_payment tests/test_payment.c)
    # Same rationale: the payment-terms tests probe ants_cbor canonicity
    # directly and need ants_strerror.
    target_link_libraries(test_payment PRIVATE ants_ledger ants_cbor)
    add_test(NAME payment_basic COMMAND test_payment)
endif()
