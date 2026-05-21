/*
 * tee.c — Stub implementation of the TEE attestation harness.
 *
 * v1.0 ships every function returning `ANTS_ERROR_NOT_IMPLEMENTED` or
 * the documented safe-default. See `ants_tee.h` for the rationale: the
 * harness's real implementation is deferred to v2.x per RFC-0005's
 * hardware-trust timeline.
 */

#include "ants_tee.h"

ants_error_t ants_attestation_generate(ants_tee_vendor_t vendor,
                                       const uint8_t peer_pubkey[32],
                                       ants_attestation_t *out)
{
    (void)vendor;
    (void)peer_pubkey;
    (void)out;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_attestation_verify(const ants_attestation_t *att)
{
    (void)att;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

bool ants_attestation_is_fresh(const ants_attestation_t *att,
                               int64_t now,
                               int64_t freshness_window_seconds)
{
    /* Documented contract: returns false on a null attestation
     * pointer (treat unknown as stale). Returning false until the
     * real implementation lands is the safe default: callers
     * checking freshness will treat the attestation as expired and
     * fall back to non-TEE participation paths. */
    (void)att;
    (void)now;
    (void)freshness_window_seconds;
    return false;
}

bool ants_attestation_is_revoked(const ants_attestation_t *att)
{
    /* Documented contract: false in v1.0 because no revocation list
     * is loaded. Callers MUST treat the false-return as inconclusive
     * until v2.x ships the real revocation lookup. */
    (void)att;
    return false;
}
