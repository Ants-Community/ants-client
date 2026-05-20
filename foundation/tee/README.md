# tee — Component #3

TEE attestation harness. Foundation layer.

**Status:** pending claim.
**Effort:** 6 EM. **The single longest foundation component**;
also on the critical path.
**Spec:** [RFC-0005](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md) (all sections).
**Dependencies:** `crypto/` (BLAKE3, Ed25519). External: each vendor's TEE SDK (all C/C++ native, no binding work).

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

bool ants_attestation_is_fresh(const ants_attestation_t *att, int64_t now);

bool ants_attestation_is_revoked(const ants_attestation_t *att);
```

## Critical path

Per IMPLEMENTATION.md §"Critical path", this component is the **first
link** of the critical chain `#3 → #7 → #8 → #13 → #15`. Without a
working TEE harness, no peer can attest its identity, so no other
component can be tested end-to-end. The claiming contributor
materially affects the project's wall-clock timeline.

Recommended start order: Intel TDX + AMD SEV-SNP first (the two
x86 server vendors, mature DCAP/KDS endpoints), then ARM CCA, then
Apple SE, then Qualcomm QSEE. Each vendor adds ~1.2 EM.

## Good-first-contribution flag

**No.** TEE attestation is the protocol's identity root and the
hardest-to-debug component. Claims encouraged from contributors with
prior confidential-compute experience (Intel SGX, Microsoft Azure
Confidential, AWS Nitro Enclaves, GCP Confidential VMs, Hyperledger
Fabric private channels, Phala Network, Oasis Labs).
