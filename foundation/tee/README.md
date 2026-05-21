# tee — Component #3

TEE attestation harness. Foundation layer.

**Status (v1.0):** **API-surface stub only.** Every function returns
`ANTS_ERROR_NOT_IMPLEMENTED` or the documented safe default. Targeted
**v2.x** per [RFC-0005](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md)'s
hardware-trust timeline (2030-2032 silicon-vulnerability-window closure).
The [CLAIM](https://github.com/Ants-Community/ants/issues/6) remains
open sine die — no nomination-window deadline.

**Why v1.0 ships the stub:** upstream components (network, reputation,
identity) reference attestations in their data structures — peer
handshake bindings, trustee key rotation, bond admission, and committee
role assumption all carry attestation metadata. Compiling against the
header now means those components don't need to mock or `#ifdef`
around a future shape; when the real implementation lands in v2.x,
integration sites need no changes.

**Why v1.0 doesn't ship the real impl:** TEE attestation is one of the
four legs of [RFC-0002](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-verifiability.md)
verifiability — re-execution, scheme (C) probabilistic, reputation,
and TEE attestation. The other three legs are sufficient for protocol
soundness; TEE adds a fourth participation path for operators who
can't run full verification. Per RFC-0005 Round 1, the current
generation of TEE silicon has a 5-7 year vulnerability window before
trust assurance is operationally meaningful. Shipping it earlier
would mean either (a) accepting that window inside the protocol's
identity root, or (b) wrapping it in caveats that defeat its purpose.
Better to wait.

**Effort (v2.x):** 6 EM, plus full security audit.
**Spec:** [RFC-0005](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md) (all sections).
**Dependencies:** `crypto/` (BLAKE3, Ed25519). External (v2.x): each
vendor's TEE SDK (all C/C++ native, no binding work).

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

## Not on the v1.0 critical path

Per the updated [IMPLEMENTATION.md](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)
§"Critical path", this component is **no longer on the v1.0 critical
chain**. v1.0 chain is `#7 → #8 → #13 → #15` (16 EM total). The TEE
harness is a v2.x deliverable.

When the real implementation lands (v2.x), the recommended start
order is: Intel TDX + AMD SEV-SNP first (the two x86 server vendors,
mature DCAP/KDS endpoints), then ARM CCA, then Apple SE, then
Qualcomm QSEE. Each vendor adds ~1.2 EM.

## Good-first-contribution flag

**No.** TEE attestation is the protocol's identity root and the
hardest-to-debug component. Claims encouraged from contributors with
prior confidential-compute experience (Intel SGX, Microsoft Azure
Confidential, AWS Nitro Enclaves, GCP Confidential VMs, Hyperledger
Fabric private channels, Phala Network, Oasis Labs).
