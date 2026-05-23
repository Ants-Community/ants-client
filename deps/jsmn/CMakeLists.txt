# deps/jsmn — vendored jsmn JSON parser
#
# Header-only minimal JSON tokenizer. Exposed as an INTERFACE library:
# downstream consumers get the include path; the actual parser code
# lives in jsmn.h and is included (with #define JSMN_STATIC) by the
# single TU that consumes it.
#
# Source: https://github.com/zserge/jsmn (unversioned upstream; we
# pinned the snapshot dated 2026-05-23 — file SHA tracked in CHANGELOG).
# License: MIT (see deps/jsmn/LICENSE preserved from upstream).
#
# Used by cache/embedding/src/tokenizer_json.c to parse HuggingFace
# tokenizer.json files (phase 4-real step 2).

add_library(jsmn INTERFACE)
target_include_directories(jsmn SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
