# cache/embedding — Component #11
#
# Spec: RFC-0002 §The canonical embedding model, RFC-0008 §5.
# Effort: 1 EM, good-first-contribution.
#
# Status: API surface declared, implementation stubbed
# (ANTS_ERROR_NOT_IMPLEMENTED). Implementation lands per-phase in
# subsequent PRs: vendor ggml → vendor tokenizer → hash verification
# → ggml inference → pin v1 BGE-M3 hashes.

add_library(ants_embed STATIC
    src/embed.c
    src/tokenizer.c
    src/tokenizer_json.c
)

target_include_directories(ants_embed
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
)

# ants_strerror lives in ants_cbor for now (transitional placement
# until we extract a shared common.c). The embedding service itself
# will depend on foundation/crypto for BLAKE3 hash verification once
# phase 3 lands; we link it now so the dependency chain is wired.
target_link_libraries(ants_embed
    PUBLIC
        ants_cbor
        ants_crypto
    PRIVATE
        jsmn
        utf8proc
)

# libm for sqrt (used in the stub-inference L2 normalisation). On
# macOS clang links libm implicitly; glibc requires it explicit.
if(NOT MSVC AND NOT APPLE)
    target_link_libraries(ants_embed PUBLIC m)
endif()

target_compile_features(ants_embed PUBLIC c_std_99)

# ---- Tests ---------------------------------------------------------------

if(BUILD_TESTING)
    add_executable(test_embed tests/test_embed.c)
    target_link_libraries(test_embed PRIVATE ants_embed)
    add_test(NAME embed_basic COMMAND test_embed)

    add_executable(test_tokenizer tests/test_tokenizer.c)
    target_link_libraries(test_tokenizer PRIVATE ants_embed)
    add_test(NAME tokenizer_basic COMMAND test_tokenizer)

    add_executable(test_tokenizer_json tests/test_tokenizer_json.c)
    target_link_libraries(test_tokenizer_json PRIVATE ants_embed)
    add_test(NAME tokenizer_json COMMAND test_tokenizer_json)
endif()
