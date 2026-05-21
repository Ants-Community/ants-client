# foundation/ layer
#
# The three components with no internal dependencies; can be built in
# parallel from day one. ~9 engineer-months total per IMPLEMENTATION.md.

# Component #1 — Crypto primitives library  (2 EM)
add_subdirectory(crypto)

# Component #2 — CBOR canonical codec  (1 EM)
add_subdirectory(cbor)

# Component #3 — TEE attestation harness  (6 EM)
#
# v1.0 ships the API surface as a NOT_IMPLEMENTED stub so upstream
# components (network, reputation, identity) can integrate against it
# now. The real per-vendor implementation is targeted v2.x per
# RFC-0005's hardware-trust timeline (2030-2032 silicon-vulnerability
# window closure). See foundation/tee/README.md.
add_subdirectory(tee)
