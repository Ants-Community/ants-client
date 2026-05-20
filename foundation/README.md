# foundation/

The three components with no internal dependencies. Can be built in
parallel from day one.

**Effort:** ~9 engineer-months total.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`crypto/`](./crypto) — Crypto primitives library (#1) | 2 EM | RFC-0008 §2–4 | pending claim |
| [`cbor/`](./cbor) — CBOR canonical codec (#2) | 1 EM | RFC-0008 §1.1 | pending claim |
| [`tee/`](./tee) — TEE attestation harness (#3) | 6 EM | RFC-0005 | pending claim |

The TEE harness is the **single longest foundation component** because
it spans five vendor families (Intel TDX, AMD SEV-SNP, ARM CCA, Apple
Secure Enclave, Qualcomm QSEE), each with its own attestation format,
signing chain, and revocation flow. All five vendor SDKs are native
C/C++, so there is no binding work — but there is a lot of vendor-side
glue.

Per IMPLEMENTATION.md §"Parallelisable vs critical-path work", the
TEE harness is **on the critical path**; the crypto primitives and
CBOR codec are not. Either of the latter two is a good "first
contribution" component (small scope, clear spec, clean test vector
conformance).
