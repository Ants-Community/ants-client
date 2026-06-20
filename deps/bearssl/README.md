# BearSSL — vendored subset (ECDSA + RSA-PSS verify on the i31 backend + SHA-384/512)

Upstream: [BearSSL](https://bearssl.org/) by Thomas Pornin, commit `7bea48e`
(2026-04-06). License: **MIT** (`LICENSE.txt`, copied verbatim).

BearSSL is a portable, clean-room C90 implementation of TLS and its
supporting cryptography. ANTS does **not** use BearSSL's TLS stack — only the
**signature verifiers** (generic-prime ECDSA and RSA RSASSA-PSS) and the
**SHA-384/512 hash**, for checking the vendor signature chains in TEE
attestation (RFC-0005):

- **AMD SEV-SNP** signs its attestation report with **ECDSA P-384 over a
  SHA-384 digest**, and its **ASK/ARK certificate chain with RSA-4096
  RSASSA-PSS** (SHA-384, MGF1-SHA-384, salt 48). Neither the P-384 verifier
  nor the RSA-PSS verifier is provided by the other vendored crypto — hence
  this dependency. (libsodium exposes SHA-512 but not SHA-384, a distinct IV +
  truncation.)
- **Intel TDX** signs with ECDSA P-256 (handled by `deps/p256-m`) over an
  all-ECDSA PKI, so it needs no RSA.

## What is vendored

The dependency closures of `br_ecdsa_i31_vrfy_raw` (the generic-prime ECDSA
verifier over `br_ec_prime_i31` — the constant-time "i31", 31-bit-limb,
big-integer backend), `br_rsa_i31_pss_vrfy` (the RSASSA-PSS verifier over the
same i31 backend), and `br_sha384` / `br_sha512`. The sources are
**byte-for-byte upstream — no local patches**:

| Files | Role |
|---|---|
| `src/i31_*.c` (19) | the i31 big-integer backend |
| `src/i32_div32.c` | `br_divrem`, called by `br_i31_muladd_small` |
| `src/ec_prime_i31.c` | generic-prime curve point arithmetic |
| `src/ec_secp256r1.c`, `ec_secp384r1.c`, `ec_secp521r1.c` | curve parameters |
| `src/ecdsa_i31_vrfy_raw.c`, `ecdsa_i31_bits.c` | the IEEE-P1363 ECDSA verifier |
| `src/rsa/rsa_i31_pss_vrfy.c` → `src/rsa_i31_pss_vrfy.c` | RSASSA-PSS verifier entry |
| `src/rsa/rsa_pss_sig_unpad.c` → `src/rsa_pss_sig_unpad.c` | PSS EMSA decode + salt/hash recompute |
| `src/rsa/rsa_i31_pub.c` → `src/rsa_i31_pub.c` | `br_rsa_i31_public`, the `m^e mod n` op |
| `src/hash/mgf1.c` → `src/mgf1.c` | `br_mgf1_xor` (MGF1 over a hash vtable) |
| `src/codec/ccopy.c` → `src/ccopy.c` | `br_ccopy`, constant-time conditional copy |
| `src/hash/sha2big.c` → `src/sha2big.c` | `br_sha384` + `br_sha512` (+ their `br_*_vtable`) |
| `src/codec/{dec64be,enc64be}.c` | `br_range_{dec,enc}64be`, sha2big's block codec |
| `src/inner.h`, `src/config.h`, `inc/*.h` | headers (declarations only) |

`ec_prime_i31.c`'s curve-dispatch table names all three NIST primes, so all
three parameter files are present; the curves ANTS does not verify with
(P-256, P-521) are unreferenced and dropped by the linker. Keeping them avoids
editing the upstream source.

The RSA-PSS leg reuses the same i31 backend — `br_rsa_i31_public` calls only
`br_i31_decode{,_mod}`, `br_i31_encode`, `br_i31_modpow_opt`, `br_i31_ninv31`
(all already present for ECDSA), and the PSS data/MGF1 hash is
`br_sha384_vtable` from the already-vendored `sha2big.c`. The only new sources
are the four RSA-PSS files: `mgf1.c`, `rsa_i31_pss_vrfy.c`, `rsa_i31_pub.c`,
`rsa_pss_sig_unpad.c`.

## How the closure was determined

Empirically, against the artifact rather than by reading call graphs: each
file was removed until `br_ecdsa_i31_vrfy_raw` / `br_rsa_i31_pss_vrfy` failed
to link, then restored. The ECDSA verifier links and checks all 14 curated
P-384 vectors from Project Wycheproof (`ecdsa_secp384r1_sha512_p1363`) — 4
valid + 10 adversarial. The RSA-PSS verifier links and checks the real AMD
SEV-Milan ASK/ARK chain (RSA-4096 PSS / SHA-384, openssl-confirmed; see
`foundation/crypto/tests/rsa_kat_vectors.h`).

## Properties relied on

- **Verify-only.** No sign or key-generation path is compiled or reachable
  (PSS *signing* pad, OAEP, and keygen are not vendored).
- **RNG-free.** The verify closure references no DRBG symbol; verification
  needs no randomness. RSASSA-PSS verification is deterministic — the salt is
  recovered from the signature, not generated.
- **Constant-time.** The i31 backend is BearSSL's constant-time implementation.

The ANTS wrappers (`ants_ecdsa_p384_verify`, `ants_rsa_pss_verify`) are in
`foundation/crypto/src/crypto.c`; each takes the raw fixed-width encodings the
verifier holds after stripping container framing and a pre-computed digest.
