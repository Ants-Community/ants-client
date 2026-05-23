# deps/utf8proc — vendored utf8proc v2.10.0 (Unicode normalisation)
#
# Source: github.com/JuliaStrings/utf8proc @ v2.10.0 tag.
# License: MIT (deps/utf8proc/LICENSE preserved from upstream).
#
# Used by cache/embedding/src/tokenizer.c for NFKC normalisation of
# input before SentencePiece pre-tokenization (phase 4-real step 4b).
#
# What's vendored: utf8proc.h, utf8proc.c, utf8proc_data.c.
# Total ~18.7K LoC (mostly the 17K-line generated Unicode tables in
# utf8proc_data.c). Single static library, no other deps.
#
# Compile discipline:
#   - Strict C99 (utf8proc is portable C with no extensions).
#   - Upstream warnings relaxed via -w; SYSTEM include directive so
#     warnings don't surface in our consumer compilation units. Same
#     pattern as deps/ggml and deps/picoquic.

add_library(utf8proc STATIC
    utf8proc.c
)

target_include_directories(utf8proc SYSTEM PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Don't build as a shared library / DLL. UTF8PROC_STATIC tells
# utf8proc.h to skip __declspec(dllimport) attributes.
target_compile_definitions(utf8proc PUBLIC UTF8PROC_STATIC)

# utf8proc_data.c is the generated Unicode-table file; it's #include'd
# from utf8proc.c at build time, NOT compiled as a separate TU.

target_compile_options(utf8proc PRIVATE -w)
target_compile_features(utf8proc PUBLIC c_std_99)
