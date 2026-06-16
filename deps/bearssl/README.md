# BearSSL — vendored subset (ECDSA verify on NIST prime curves)

Upstream: [BearSSL](https://bearssl.org/) by Thomas Pornin, commit `7bea48e`
(2026-04-06). License: **MIT** (`LICENSE.txt`, copied verbatim).

BearSSL is a portable, clean-room C90 implementation of TLS and its
supporting cryptography. ANTS does **not** use BearSSL's TLS stack — only the
generic-prime **ECDSA signature verifier**, for checking the vendor signature
chains in TEE attestation quotes (RFC-0005). Intel TDX signs with ECDSA P-256
(handled by `deps/p256-m`); **AMD SEV-SNP signs its attestation report with
ECDSA P-384**, which p256-m cannot do — hence this dependency.

## What is vendored

Only the dependency closure of `br_ecdsa_i31_vrfy_raw` over the generic-prime
curve implementation `br_ec_prime_i31` (the constant-time "i31", 31-bit-limb,
big-integer backend). The sources are **byte-for-byte upstream — no local
patches**:

| Files | Role |
|---|---|
| `src/i31_*.c` (19) | the i31 big-integer backend |
| `src/i32_div32.c` | `br_divrem`, called by `br_i31_muladd_small` |
| `src/ec_prime_i31.c` | generic-prime curve point arithmetic |
| `src/ec_secp256r1.c`, `ec_secp384r1.c`, `ec_secp521r1.c` | curve parameters |
| `src/ecdsa_i31_vrfy_raw.c`, `ecdsa_i31_bits.c` | the IEEE-P1363 verifier |
| `src/codec/ccopy.c` → `src/ccopy.c` | `br_ccopy`, constant-time conditional copy |
| `src/inner.h`, `src/config.h`, `inc/*.h` | headers (declarations only) |

`ec_prime_i31.c`'s curve-dispatch table names all three NIST primes, so all
three parameter files are present; the curves ANTS does not verify with
(P-256, P-521) are unreferenced and dropped by the linker. Keeping them avoids
editing the upstream source.

## How the closure was determined

Empirically, against the artifact rather than by reading call graphs: starting
from the full `src/int/` + EC + codec set, each file was removed until
`br_ecdsa_i31_vrfy_raw` failed to link, then restored. The result is the
minimal set above (27 `.c`). It links and verifies all 14 curated P-384
vectors from Project Wycheproof (`ecdsa_secp384r1_sha512_p1363`) — 4 valid + 10
adversarial special-value cases.

## Properties relied on

- **Verify-only.** No sign or key-generation path is compiled or reachable.
- **RNG-free.** The verify closure references no hash, HMAC, or DRBG symbol
  (verification needs no randomness).
- **Constant-time.** The i31 backend is BearSSL's constant-time implementation.

The ANTS wrapper (`ants_ecdsa_p384_verify`) is in
`foundation/crypto/src/crypto.c`; it takes the raw fixed-width encodings the
verifier holds after stripping container framing (96-byte uncompressed public
key `X||Y`, 96-byte signature `r||s`) and a pre-computed digest.
