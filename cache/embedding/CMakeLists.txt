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
    src/embed_forward.c
    src/embed_gguf.c
    src/embed_model.c
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
        ggml
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

    # The GGUF loader test calls ggml + gguf APIs directly to build
    # a fixture in-memory; it therefore needs both ants_embed (for
    # embed_gguf_*) and ggml (for the gguf_init_*/ggml_init_* helpers).
    # tests/ also needs access to the src/ private header.
    add_executable(test_embed_gguf tests/test_embed_gguf.c)
    target_include_directories(test_embed_gguf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(test_embed_gguf PRIVATE ants_embed ggml)
    add_test(NAME embed_gguf COMMAND test_embed_gguf)

    # Same access pattern as test_embed_gguf — the model binder needs
    # the GGUF wrapper + ggml for fixture construction.
    add_executable(test_embed_model tests/test_embed_model.c)
    target_include_directories(test_embed_model PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(test_embed_model PRIVATE ants_embed ggml)
    add_test(NAME embed_model COMMAND test_embed_model)

    # Forward-pass test runs the BGE-M3 graph end-to-end on a tiny
    # FNV-1a-keyed pattern-weight fixture.
    add_executable(test_embed_forward tests/test_embed_forward.c)
    target_include_directories(test_embed_forward PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(test_embed_forward PRIVATE ants_embed ggml)
    add_test(NAME embed_forward COMMAND test_embed_forward)
endif()
