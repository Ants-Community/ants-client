/*
 * ants_tee.h — TEE attestation harness (Component #3).
 *
 * Spec reference: RFC-0005 (Identity & TEE attestation, all sections).
 *
 * Status: **API surface only — v1.0 ships with every function
 * returning `ANTS_ERROR_NOT_IMPLEMENTED`.** Real implementation is
 * targeted v2.x per RFC-0005's hardware-trust timeline (2030-2032
 * silicon-vulnerability-window closure). See `foundation/tee/README.md`
 * for the scope sketch and the open `[CLAIM]` issue at
 * Ants-Community/ants#6.
 *
 * Why the stub exists in v1.0: upstream components (network,
 * reputation, identity) reference attestations in their data structures
 * — peer-handshake bindings, trustee key rotation, bond admission, and
 * committee role assumption all carry attestation metadata. Having the
 * API compiled means those components can integrate against it now
 * without having to mock or `#ifdef` a future shape. When the harness
 * lands in v2.x the integration sites need no changes.
 *
 * v1.0 verifiability without TEE: RFC-0002 lists four legs (re-
 * execution, scheme (C) probabilistic, reputation, TEE attestation).
 * Without leg 4, the protocol still composes the other three. The
 * absence reduces participation-path diversity for low-resource
 * operators — not soundness, safety, or correctness.
 */

#ifndef ANTS_TEE_H
#define ANTS_TEE_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Vendor families                                                          */
/*                                                                          */
/* Per RFC-0005 §Multi-vendor TEE families. The five vendor IDs are pinned  */
/* here so consumers can encode/decode them in CBOR without depending on    */
/* a separate enum table. Adding a vendor is a v-bump for this header.      */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_tee_vendor_t;

#define ANTS_TEE_VENDOR_UNKNOWN       ((ants_tee_vendor_t)0)
#define ANTS_TEE_VENDOR_INTEL_TDX     ((ants_tee_vendor_t)1)
#define ANTS_TEE_VENDOR_AMD_SEV_SNP   ((ants_tee_vendor_t)2)
#define ANTS_TEE_VENDOR_ARM_CCA       ((ants_tee_vendor_t)3)
#define ANTS_TEE_VENDOR_APPLE_SE      ((ants_tee_vendor_t)4)
#define ANTS_TEE_VENDOR_QUALCOMM_QSEE ((ants_tee_vendor_t)5)

/* ------------------------------------------------------------------------ */
/* Constants enforced uniformly across vendors                              */
/*                                                                          */
/* Per RFC-0005 §Attestation freshness window + §Vendor revocation          */
/* propagation timing + §Multi-vendor reputation weighting.                 */
/* ------------------------------------------------------------------------ */

/* Default attestation freshness: 30 days. Configurable via the protocol
 * params struct at higher layers; the harness must honour the supplied
 * value, not a baked-in literal. */
#define ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS ((int64_t)(30 * 24 * 3600))

/* Default vendor revocation propagation bound: 72 hours. After this
 * window, revoked attestations are network-wide rejected. */
#define ANTS_TEE_DEFAULT_REVOCATION_BOUND_SECONDS ((int64_t)(72 * 3600))

/* Multi-vendor reputation weights per RFC-0005 §Multi-vendor reputation
 * weighting. The harness exposes the lookup; reputation layer uses it
 * when computing a peer's effective reputation. */
#define ANTS_TEE_WEIGHT_SINGLE_NUM 10 /* multiplier 1.0 */
#define ANTS_TEE_WEIGHT_SINGLE_DEN 10
#define ANTS_TEE_WEIGHT_DUAL_NUM   12 /* multiplier 1.2 */
#define ANTS_TEE_WEIGHT_DUAL_DEN   10
#define ANTS_TEE_WEIGHT_TRIPLE_NUM 14 /* multiplier 1.4 */
#define ANTS_TEE_WEIGHT_TRIPLE_DEN 10

/* ------------------------------------------------------------------------ */
/* Attestation record                                                       */
/*                                                                          */
/* The opaque vendor blob is the only field whose internal layout differs   */
/* per-vendor; the surrounding metadata (peer_pubkey, tcb_identifier,       */
/* issued_at_unix, expires_at_unix) is uniform.                             */
/*                                                                          */
/* `vendor_blob` is borrowed: the caller retains ownership and must keep    */
/* it alive for the lifetime of the ants_attestation_t. The library never   */
/* malloc()s on behalf of the caller (see foundation/ memory discipline).   */
/* ------------------------------------------------------------------------ */

#define ANTS_TEE_TCB_IDENTIFIER_SIZE 64

typedef struct {
    ants_tee_vendor_t vendor;
    /* The Ed25519 public key (32 bytes) that THIS attestation binds to
     * attested hardware. Comparison with peer-handshake pubkeys is the
     * way the protocol verifies that the same physical TEE produced
     * both this attestation and the peer's session signatures. */
    uint8_t peer_pubkey[32];
    /* Vendor-specific TCB identifier (firmware/microcode version
     * fingerprint). Format is vendor-defined; opaque to consumers
     * except for equality comparison against vendor revocation lists. */
    uint8_t tcb_identifier[ANTS_TEE_TCB_IDENTIFIER_SIZE];
    /* Issuance time (seconds since Unix epoch). Used by the freshness
     * window check; the harness does NOT consult a system clock —
     * callers supply the reference `now`. */
    int64_t issued_at_unix;
    /* Vendor-supplied expiry (seconds since Unix epoch). May be 0 if
     * the vendor doesn't carry a hard expiry; in that case the freshness
     * window alone enforces an upper bound. */
    int64_t expires_at_unix;
    /* Vendor-signed attestation blob (DCAP quote, SEV-SNP report, etc).
     * Borrowed pointer — caller owns the memory. */
    const uint8_t *vendor_blob;
    size_t vendor_blob_len;
} ants_attestation_t;

/* ------------------------------------------------------------------------ */
/* API surface                                                              */
/*                                                                          */
/* All functions return `ANTS_ERROR_NOT_IMPLEMENTED` in v1.0. The shape is  */
/* pinned so v1.0 consumers can integrate and v2.x can drop the real       */
/* implementation in without API churn.                                     */
/* ------------------------------------------------------------------------ */

/*
 * Generate a fresh attestation binding `peer_pubkey` to the local
 * vendor TEE. Output is written to `*out`; the caller does not need to
 * preallocate the `vendor_blob` — `ants_attestation_generate` may set
 * it to a library-owned static buffer that is overwritten on the next
 * call (the v2.x signature will document this precisely).
 */
ants_error_t ants_attestation_generate(ants_tee_vendor_t vendor,
                                       const uint8_t peer_pubkey[32],
                                       ants_attestation_t *out);

/*
 * Verify the attestation's vendor signature chain. Does NOT consult the
 * freshness window or revocation state — those are separate, composable
 * checks. Returns ANTS_OK on a valid signature chain;
 * ANTS_ERROR_MALFORMED on invalid blob, wrong vendor root, or bound
 * pubkey mismatch.
 */
ants_error_t ants_attestation_verify(const ants_attestation_t *att);

/*
 * Returns true iff `now - issued_at_unix < freshness_window_seconds`
 * AND `now < expires_at_unix` (when expires_at_unix != 0). Caller
 * supplies both `now` (UTC seconds) and the freshness window (typically
 * `ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS` but configurable per
 * RFC-0005 §Attestation freshness window).
 *
 * Returns false on a null pointer (safe default — treat unknown as
 * stale).
 */
bool ants_attestation_is_fresh(const ants_attestation_t *att,
                               int64_t now,
                               int64_t freshness_window_seconds);

/*
 * Returns true iff the attestation's `tcb_identifier` appears on the
 * currently-loaded vendor revocation list for `att->vendor`. The
 * revocation list management API is intentionally not exposed in v1.0
 * — it will land alongside the real attestation_verify implementation
 * in v2.x.
 *
 * Until then, this function returns false (no attestation is considered
 * revoked because no list is loaded). Callers MUST treat
 * `ants_attestation_is_revoked() == false` as inconclusive when running
 * against the v1.0 stub; the harness will start surfacing true
 * positives only when v2.x ships.
 */
bool ants_attestation_is_revoked(const ants_attestation_t *att);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_TEE_H */
