# tee — Component #3

TEE attestation harness. Foundation layer.

**Status:** **a v1 deliverable, largely landed** — un-deferred from v2.x on
2026-06-15 (see the spec [CHANGELOG](https://github.com/Ants-Community/ants/blob/main/spec/CHANGELOG.md)
and [IMPLEMENTATION.md](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)
row #3). `ants_attestation_verify` is wired end to end for both launch vendors,
**Intel TDX** and **AMD SEV-SNP**: each composes its structure parser, the
in-tree X.509 certificate-chain validator, and a pinned vendor root (Intel SGX
Root CA / AMD ARK-Milan), built on the ECDSA P-256/P-384, SHA-256/384/512 and
RSA-PSS primitives in [`foundation/crypto`](../crypto/).
`ants_attestation_is_fresh` enforces the recency + vendor-expiry window. What
remains: `ants_attestation_generate` (gated on real confidential-compute
hardware), the ARM CCA / Apple SE / Qualcomm vendor paths (v1.x), and
`ants_attestation_is_revoked` (a v1 stub until the vendor revocation-list API
lands). The [CLAIM](https://github.com/Ants-Community/ants/issues/6) remains
open sine die; the BDFL is interim primary.

**Why the surface compiled ahead of the vendors:** upstream components
(network, reputation, identity) reference attestations in their data
structures — peer handshake bindings, trustee key rotation, bond admission,
and committee role assumption all carry attestation metadata. Compiling
against the header early meant those components never had to mock or `#ifdef`
around a future shape; when each vendor's verify landed, the integration
sites needed no changes.

**Why v1, not v2.x — the earlier deferral conflated two jobs.** The TEE does
two things. As the *fourth verifiability leg* ([RFC-0002](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-verifiability.md)
— alongside re-execution, scheme (C) probabilistic, and reputation) it is
genuinely optional: the other three legs suffice for soundness. But as the
**identity root** it is not. RFC-0005's "one attested CPU, one peer identity"
Sybil resistance and RFC-0004's "one CPU, one voice" validator pool both
reduce to *the attested population*. Until the node daemon wires attestation
into handshake admission and validator-pool membership, that population is
every freely-generated Ed25519 keypair — so the L2 committee selection, the
per-attested-identity rate limits, and the Sybil-cost table are not yet
enforced ("one keypair, one voice"); the verification machinery they need now
exists. The 2030-2032 horizon in RFC-0005 is
the *open-hardware* migration (Keystone / OpenTitan), **not** a reason to
defer closed-vendor attestation, which RFC-0005 assumes runs throughout the
v1 era. The residual closed-silicon trust window is addressed by the security
audit and the freshness / revocation bounds below — not by waiting.

**Effort (v1):** 6 EM total — Intel TDX + AMD SEV-SNP launch vendors ~2.4 EM,
the rest v1.x — plus full security audit.
**Spec:** [RFC-0005](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md) (all sections).
**Dependencies:** `crypto/` (BLAKE3, Ed25519, SHA-256/384/512, ECDSA
P-256/P-384, RSA-PSS) plus the in-tree strict DER reader + X.509 certificate
parser and chain validator (`foundation/tee/src/{der,x509,x509_chain}.c`). The
quote/report *verification* path is offline- and vector-testable on commodity
hardware; only quote *generation* and end-to-end need confidential-compute
hardware (a Confidential VM, or local attestation-capable silicon).

## Scope

A uniform wrapper around five vendor TEE families. For each, the
component must implement: attestation generation (binding the peer's
Ed25519 public key to attested hardware), attestation verification
(checking the vendor's signature chain), freshness check, and
revocation propagation.

| Vendor family | SDK | Attestation chain root |
|---|---|---|
| Intel SGX / TDX | Intel SGX SDK + DCAP | Intel Attestation Service |
| AMD SEV-SNP | AMD SEV-SNP firmware + KVM | AMD Vendor Certificate Authority |
| ARM CCA | ARM CCA reference implementation | ARM Realm Management Monitor + vendor |
| Apple Secure Enclave | Apple Security Framework (Obj-C bridge) | Apple Inc. attestation root |
| Qualcomm QSEE / Hexagon | QSEE SDK | Qualcomm vendor root |

## Constants this component enforces

Per RFC-0005 + RFC-0008 §7, the harness must enforce:

- **`ATTESTATION_FRESHNESS_WINDOW`** — default 30 days, applied uniformly to peer handshake, trustee key rotation, bond admission, and committee role assumption per RFC-0005 §Attestation freshness window.
- **`VENDOR_REVOCATION_PROPAGATION_BOUND`** — default 72 hours, after which revoked attestations are rejected network-wide per RFC-0005 §Vendor revocation propagation timing.
- **`MULTI_VENDOR_WEIGHT_{SINGLE,DUAL,TRIPLE}`** — 1.0 / 1.2 / 1.4, the reputation-weight multiplier per RFC-0005 §Multi-vendor reputation weighting.

## Intended public API

```c
// attestation.h
typedef enum {
    ANTS_TEE_INTEL_TDX = 1,
    ANTS_TEE_AMD_SEV_SNP,
    ANTS_TEE_ARM_CCA,
    ANTS_TEE_APPLE_SE,
    ANTS_TEE_QUALCOMM_QSEE,
} ants_tee_vendor_t;

typedef struct {
    ants_tee_vendor_t vendor;
    uint8_t           peer_pubkey[32];       // Ed25519, bound by this attestation
    uint8_t           tcb_identifier[64];    // vendor-specific TCB id (firmware ver, etc.)
    int64_t           issued_at_unix;        // seconds since epoch
    int64_t           expires_at_unix;
    const uint8_t    *vendor_blob;           // opaque vendor signature chain
    size_t            vendor_blob_len;
} ants_attestation_t;

ants_error_t ants_attestation_generate(ants_tee_vendor_t vendor,
                                       const uint8_t peer_pubkey[32],
                                       ants_attestation_t *out);

ants_error_t ants_attestation_verify(const ants_attestation_t *att);

bool ants_attestation_is_fresh(const ants_attestation_t *att, int64_t now,
                               int64_t freshness_window_seconds);

bool ants_attestation_is_revoked(const ants_attestation_t *att);
```

## A v1 deliverable, but parallelisable

Per [IMPLEMENTATION.md](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)
§"Critical path", the v1 critical *chain* is `#7 → #8 → #13 → #15` (16 EM) and
this component is not on it — but it is a **v1 deliverable** (no longer v2.x):
a foundation component with no upstream dependency, so it builds in parallel
and gates integration / first testnet (it is the attested population the L2
enforces).

Start order: **Intel TDX + AMD SEV-SNP first** — the two x86 server vendors,
mature DCAP/KDS endpoints, ~2.4 of the 6 EM, and quote *verification* is
offline/vector-testable — then ARM CCA, Apple SE, Qualcomm QSEE as the device
population broadens (v1.x). Each later vendor adds ~1.2 EM.

## Good-first-contribution flag

**No.** TEE attestation is the protocol's identity root and the
hardest-to-debug component. Claims encouraged from contributors with
prior confidential-compute experience (Intel SGX, Microsoft Azure
Confidential, AWS Nitro Enclaves, GCP Confidential VMs, Hyperledger
Fabric private channels, Phala Network, Oasis Labs).
