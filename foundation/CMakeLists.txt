# foundation/ layer
#
# The three components with no internal dependencies; can be built in
# parallel from day one. ~9 engineer-months total per IMPLEMENTATION.md.

# Component #1 — Crypto primitives library  (2 EM)
# add_subdirectory(crypto)

# Component #2 — CBOR canonical codec  (1 EM)
# add_subdirectory(cbor)

# Component #3 — TEE attestation harness  (6 EM)
# add_subdirectory(tee)
