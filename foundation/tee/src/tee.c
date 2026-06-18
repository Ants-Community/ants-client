/*
 * tee.c — TEE attestation harness.
 *
 * The uniform `ants_attestation_*` surface is still a stub (it needs the
 * vendor certificate chains). The per-vendor structure parsers + report-
 * signature verifiers land incrementally on top of foundation/crypto;
 * AMD SEV-SNP is the first (see the SNP section below). See `ants_tee.h`
 * for the rationale.
 */

#include "ants_tee.h"

#include "ants_crypto.h"

#include <string.h>

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

/* ------------------------------------------------------------------------ */
/* AMD SEV-SNP attestation report                                           */
/*                                                                          */
/* Field offsets into the 0x4A0-byte ATTESTATION_REPORT structure (AMD      */
/* SEV-SNP ABI spec). Only the fields whose offsets are stable across       */
/* report VERSION 2 and 3 are decoded — the version-specific reserved       */
/* regions between them are left untouched.                                 */
/* ------------------------------------------------------------------------ */

#define SNP_OFF_VERSION        0x000
#define SNP_OFF_GUEST_SVN      0x004
#define SNP_OFF_POLICY         0x008
#define SNP_OFF_FAMILY_ID      0x010
#define SNP_OFF_IMAGE_ID       0x020
#define SNP_OFF_VMPL           0x030
#define SNP_OFF_SIGNATURE_ALGO 0x034
#define SNP_OFF_CURRENT_TCB    0x038
#define SNP_OFF_PLATFORM_INFO  0x040
#define SNP_OFF_REPORT_DATA    0x050
#define SNP_OFF_MEASUREMENT    0x090
#define SNP_OFF_HOST_DATA      0x0C0
#define SNP_OFF_REPORT_ID      0x140
#define SNP_OFF_REPORTED_TCB   0x180
#define SNP_OFF_CHIP_ID        0x1A0
#define SNP_OFF_SIGNATURE      0x2A0

/* Within the 512-byte SIGNATURE field, R then S each occupy a 72-byte
 * little-endian slot; only the low 48 bytes are significant for P-384,
 * the high 24 are zero padding. */
#define SNP_RS_SLOT_SIZE  72
#define SNP_RS_VALUE_SIZE 48

static uint32_t snp_rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t snp_rd_u64le(const uint8_t *p)
{
    return (uint64_t)snp_rd_u32le(p) | ((uint64_t)snp_rd_u32le(p + 4) << 32);
}

/* OR-accumulate so the result depends on every byte (no early exit). */
static bool snp_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

/* Write the 48-byte big-endian form of a little-endian P-384 scalar. */
static void snp_be_from_le48(uint8_t out[SNP_RS_VALUE_SIZE], const uint8_t *le)
{
    for (size_t i = 0; i < SNP_RS_VALUE_SIZE; i++) {
        out[i] = le[SNP_RS_VALUE_SIZE - 1 - i];
    }
}

ants_error_t ants_snp_report_parse(const uint8_t *report, size_t report_len, ants_snp_report_t *out)
{
    if (report == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (report_len != ANTS_SNP_REPORT_SIZE) {
        return ANTS_ERROR_MALFORMED;
    }

    memset(out, 0, sizeof *out);
    out->version = snp_rd_u32le(report + SNP_OFF_VERSION);
    out->guest_svn = snp_rd_u32le(report + SNP_OFF_GUEST_SVN);
    out->policy = snp_rd_u64le(report + SNP_OFF_POLICY);
    memcpy(out->family_id, report + SNP_OFF_FAMILY_ID, ANTS_SNP_FAMILY_ID_SIZE);
    memcpy(out->image_id, report + SNP_OFF_IMAGE_ID, ANTS_SNP_IMAGE_ID_SIZE);
    out->vmpl = snp_rd_u32le(report + SNP_OFF_VMPL);
    out->signature_algo = snp_rd_u32le(report + SNP_OFF_SIGNATURE_ALGO);
    out->current_tcb = snp_rd_u64le(report + SNP_OFF_CURRENT_TCB);
    out->platform_info = snp_rd_u64le(report + SNP_OFF_PLATFORM_INFO);
    memcpy(out->report_data, report + SNP_OFF_REPORT_DATA, ANTS_SNP_REPORT_DATA_SIZE);
    memcpy(out->measurement, report + SNP_OFF_MEASUREMENT, ANTS_SNP_MEASUREMENT_SIZE);
    memcpy(out->host_data, report + SNP_OFF_HOST_DATA, ANTS_SNP_HOST_DATA_SIZE);
    memcpy(out->report_id, report + SNP_OFF_REPORT_ID, ANTS_SNP_REPORT_ID_SIZE);
    out->reported_tcb = snp_rd_u64le(report + SNP_OFF_REPORTED_TCB);
    memcpy(out->chip_id, report + SNP_OFF_CHIP_ID, ANTS_SNP_CHIP_ID_SIZE);
    return ANTS_OK;
}

ants_error_t ants_snp_report_verify_signature(const uint8_t *report,
                                              size_t report_len,
                                              const uint8_t vcek_pubkey[ANTS_SNP_VCEK_PUBKEY_SIZE])
{
    if (report == NULL || vcek_pubkey == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (report_len != ANTS_SNP_REPORT_SIZE) {
        return ANTS_ERROR_MALFORMED;
    }
    if (snp_rd_u32le(report + SNP_OFF_SIGNATURE_ALGO) != ANTS_SNP_SIG_ALGO_ECDSA_P384_SHA384) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Digest the signed prefix: report bytes [0, 0x2A0). */
    uint8_t digest[ANTS_SHA384_HASH_SIZE];
    ants_error_t err = ants_sha384(report, ANTS_SNP_SIGNED_PREFIX_LEN, digest);
    if (err != ANTS_OK) {
        return err;
    }

    const uint8_t *r_le = report + SNP_OFF_SIGNATURE;
    const uint8_t *s_le = report + SNP_OFF_SIGNATURE + SNP_RS_SLOT_SIZE;

    /* The high 24 bytes of each 72-byte slot must be zero: a non-zero
     * value there is an out-of-range scalar, i.e. a malformed report. */
    if (!snp_all_zero(r_le + SNP_RS_VALUE_SIZE, SNP_RS_SLOT_SIZE - SNP_RS_VALUE_SIZE) ||
        !snp_all_zero(s_le + SNP_RS_VALUE_SIZE, SNP_RS_SLOT_SIZE - SNP_RS_VALUE_SIZE)) {
        return ANTS_ERROR_MALFORMED;
    }

    /* AMD stores R and S little-endian; the curve primitive wants r || s
     * big-endian (ANTS_ECDSA_P384_SIG_SIZE == 2 * 48). */
    uint8_t sig_be[ANTS_ECDSA_P384_SIG_SIZE];
    snp_be_from_le48(sig_be, r_le);
    snp_be_from_le48(sig_be + SNP_RS_VALUE_SIZE, s_le);

    return ants_ecdsa_p384_verify(vcek_pubkey, digest, ANTS_SHA384_HASH_SIZE, sig_be);
}
