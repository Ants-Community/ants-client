# economy/bond — Component #15 (bond accounting for high-stakes acts).
#
# Spec: RFC-0004 v0.6 §"Bonds for high-stakes acts" + §"Bond accounting
# model"; RFC-0008 v0.5 §6 (u64 μNCS), §1.1 (canonical CBOR), §2.1 (BLAKE3),
# §7 (constants).
#
# Status: PR1 — the local bond ledger (init / locked_total / bondable_a /
# admit / release / slash + multi-act composition). `A` is delegated to
# reputation/identity (the caller passes it in), so the accounting is pure
# and links nothing. PR2 adds the per-class bond formulas, the canonical-CBOR
# bond_admission object (→ ants_cbor), and the race-safe tie-break (→
# ants_crypto BLAKE3 derive_key); deps wire in then, per "link what you use".

add_library(ants_bond STATIC
    src/bond.c
)

target_include_directories(ants_bond
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

target_compile_features(ants_bond PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_bond tests/test_bond.c)
    target_link_libraries(test_bond PRIVATE ants_bond)
    add_test(NAME bond_basic COMMAND test_bond)
endif()
