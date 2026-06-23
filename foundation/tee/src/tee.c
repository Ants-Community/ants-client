/*
 * tee.c — TEE attestation harness.
 *
 * ants_attestation_verify is wired for Intel TDX: it composes the quote parser,
 * the X.509 certificate-chain validator (x509_chain.h) and the pinned Intel SGX
 * Root CA (tee_roots.h) — see the composition section at the foot of this file.
 * AMD SEV-SNP verify and ants_attestation_generate are still pending (generate
 * needs real confidential-compute hardware). The per-vendor structure parsers +
 * report-signature verifiers (AMD SEV-SNP, then Intel TDX) are below. See
 * `ants_tee.h` for the rationale.
 */

#include "ants_tee.h"

#include "ants_crypto.h"

#include "tee_roots.h"
#include "x509.h"
#include "x509_chain.h"

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

/* Per-vendor composition, defined at the foot of this file (it depends on the
 * TDX layout constants below). */
static ants_error_t tdx_attestation_verify(const ants_attestation_t *att);

ants_error_t ants_attestation_verify(const ants_attestation_t *att)
{
    if (att == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    switch (att->vendor) {
    case ANTS_TEE_VENDOR_INTEL_TDX:
        return tdx_attestation_verify(att);
    default:
        /* AMD SEV-SNP wiring lands next; ARM CCA / Apple SE / Qualcomm are
         * v1.x. */
        return ANTS_ERROR_NOT_IMPLEMENTED;
    }
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

/* ------------------------------------------------------------------------ */
/* Intel TDX DCAP attestation quote (v4, ECDSA-P256)                        */
/*                                                                          */
/* Absolute byte offsets into a v4 quote. The header (0x30) and TD report   */
/* body (0x248) are fixed; the signature section that follows is variable    */
/* and is walked with bounds checks. Offsets cross-checked against           */
/* google/go-tdx-guest abi/abi.go and a real Sapphire Rapids quote (see      */
/* tests/tdx_kat_vectors.h).                                                 */
/* ------------------------------------------------------------------------ */

/* Header. */
#define TDX_OFF_VERSION      0x000 /* u16 LE */
#define TDX_OFF_ATT_KEY_TYPE 0x002 /* u16 LE */
#define TDX_OFF_TEE_TYPE     0x004 /* u32 LE */
#define TDX_OFF_QE_VENDOR_ID 0x00C /* 16 */

/* TD report body (starts at 0x30). */
#define TDX_OFF_TEE_TCB_SVN     0x030 /* 16 */
#define TDX_OFF_MR_SEAM         0x040 /* 48 */
#define TDX_OFF_MR_SIGNER_SEAM  0x070 /* 48 */
#define TDX_OFF_SEAM_ATTRIBUTES 0x0A0 /* u64 LE */
#define TDX_OFF_TD_ATTRIBUTES   0x0A8 /* u64 LE */
#define TDX_OFF_XFAM            0x0B0 /* u64 LE */
#define TDX_OFF_MR_TD           0x0B8 /* 48 */
#define TDX_OFF_MR_CONFIG_ID    0x0E8 /* 48 */
#define TDX_OFF_MR_OWNER        0x118 /* 48 */
#define TDX_OFF_MR_OWNER_CONFIG 0x148 /* 48 */
#define TDX_OFF_RTMR0           0x178 /* 4 x 48 */
#define TDX_OFF_REPORT_DATA     0x238 /* 64 */

/* End of header+body == the message the attestation key signs, and the
 * offset of the u32 LE signature-data length. */
#define TDX_OFF_SIG_DATA_LEN 0x278 /* == HEADER_SIZE + BODY_SIZE */
#define TDX_OFF_SIG_DATA     0x27C /* signature data begins here */

/* Signature-data field offsets, relative to TDX_OFF_SIG_DATA. */
#define TDX_SD_SIGNATURE 0   /* att-key signature, 64 (r||s BE) */
#define TDX_SD_ATT_KEY   64  /* att public key, 64 (X||Y BE) */
#define TDX_SD_CERT_TYPE 128 /* u16 LE */
#define TDX_SD_CERT_SIZE 130 /* u32 LE */
#define TDX_SD_CERT_BODY 134 /* certification data body */

/* QE-report-certification-data (type 6) offsets, relative to the cert body
 * (TDX_OFF_SIG_DATA + TDX_SD_CERT_BODY). */
#define TDX_CD_QE_REPORT     0   /* 384-byte SGX report body */
#define TDX_CD_QE_REPORT_SIG 384 /* 64 (r||s BE) */
#define TDX_CD_QE_AUTH_SIZE  448 /* u16 LE */
#define TDX_CD_QE_AUTH       450 /* qe_auth_data */

/* report_data within the 384-byte QE (SGX) report body. */
#define TDX_QE_REPORT_DATA_OFF 0x140 /* 320; 64 bytes */

static uint16_t tdx_rd_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t tdx_rd_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t tdx_rd_u64le(const uint8_t *p)
{
    return (uint64_t)tdx_rd_u32le(p) | ((uint64_t)tdx_rd_u32le(p + 4) << 32);
}

/* OR-accumulate so the result depends on every byte (no early exit). */
static bool tdx_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

ants_error_t ants_tdx_quote_parse(const uint8_t *quote, size_t quote_len, ants_tdx_quote_t *out)
{
    if (quote == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (quote_len < ANTS_TDX_QUOTE_HEADER_SIZE + ANTS_TDX_QUOTE_BODY_SIZE) {
        return ANTS_ERROR_MALFORMED;
    }
    /* The body layout is version/tee-type specific; only decode a v4 TDX
     * quote (the TDX-1.0 584-byte body). */
    if (tdx_rd_u16le(quote + TDX_OFF_VERSION) != ANTS_TDX_QUOTE_VERSION ||
        tdx_rd_u32le(quote + TDX_OFF_TEE_TYPE) != ANTS_TDX_TEE_TYPE) {
        return ANTS_ERROR_MALFORMED;
    }

    memset(out, 0, sizeof *out);
    out->version = tdx_rd_u16le(quote + TDX_OFF_VERSION);
    out->att_key_type = tdx_rd_u16le(quote + TDX_OFF_ATT_KEY_TYPE);
    out->tee_type = tdx_rd_u32le(quote + TDX_OFF_TEE_TYPE);
    memcpy(out->qe_vendor_id, quote + TDX_OFF_QE_VENDOR_ID, ANTS_TDX_QE_VENDOR_ID_SIZE);
    memcpy(out->tee_tcb_svn, quote + TDX_OFF_TEE_TCB_SVN, ANTS_TDX_TCB_SVN_SIZE);
    memcpy(out->mr_seam, quote + TDX_OFF_MR_SEAM, ANTS_TDX_MEASUREMENT_SIZE);
    memcpy(out->mr_signer_seam, quote + TDX_OFF_MR_SIGNER_SEAM, ANTS_TDX_MEASUREMENT_SIZE);
    out->seam_attributes = tdx_rd_u64le(quote + TDX_OFF_SEAM_ATTRIBUTES);
    out->td_attributes = tdx_rd_u64le(quote + TDX_OFF_TD_ATTRIBUTES);
    out->xfam = tdx_rd_u64le(quote + TDX_OFF_XFAM);
    memcpy(out->mr_td, quote + TDX_OFF_MR_TD, ANTS_TDX_MEASUREMENT_SIZE);
    memcpy(out->mr_config_id, quote + TDX_OFF_MR_CONFIG_ID, ANTS_TDX_MEASUREMENT_SIZE);
    memcpy(out->mr_owner, quote + TDX_OFF_MR_OWNER, ANTS_TDX_MEASUREMENT_SIZE);
    memcpy(out->mr_owner_config, quote + TDX_OFF_MR_OWNER_CONFIG, ANTS_TDX_MEASUREMENT_SIZE);
    for (size_t i = 0; i < ANTS_TDX_RTMR_COUNT; i++) {
        memcpy(out->rtmr[i],
               quote + TDX_OFF_RTMR0 + i * ANTS_TDX_MEASUREMENT_SIZE,
               ANTS_TDX_MEASUREMENT_SIZE);
    }
    memcpy(out->report_data, quote + TDX_OFF_REPORT_DATA, ANTS_TDX_REPORT_DATA_SIZE);
    return ANTS_OK;
}

ants_error_t
ants_tdx_quote_verify_signature(const uint8_t *quote,
                                size_t quote_len,
                                const uint8_t pck_leaf_pubkey[ANTS_TDX_PCK_PUBKEY_SIZE])
{
    if (quote == NULL || pck_leaf_pubkey == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Need header + body + the 4-byte signature-data length. */
    if (quote_len < TDX_OFF_SIG_DATA) {
        return ANTS_ERROR_MALFORMED;
    }
    /* Header invariants: a v4 ECDSA-P256 TDX quote. */
    if (tdx_rd_u16le(quote + TDX_OFF_VERSION) != ANTS_TDX_QUOTE_VERSION ||
        tdx_rd_u16le(quote + TDX_OFF_ATT_KEY_TYPE) != ANTS_TDX_ATT_KEY_TYPE_ECDSA_P256 ||
        tdx_rd_u32le(quote + TDX_OFF_TEE_TYPE) != ANTS_TDX_TEE_TYPE) {
        return ANTS_ERROR_MALFORMED;
    }

    /* The signature data must fit within the quote (sig_data_len is
     * authoritative; any trailing bytes are not part of the quote). */
    uint32_t sig_data_len = tdx_rd_u32le(quote + TDX_OFF_SIG_DATA_LEN);
    if ((uint64_t)TDX_OFF_SIG_DATA + sig_data_len > quote_len) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *sd = quote + TDX_OFF_SIG_DATA;

    /* att signature (64) + att key (64) + 6-byte certification header. */
    if (sig_data_len < TDX_SD_CERT_BODY) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *att_sig = sd + TDX_SD_SIGNATURE;
    const uint8_t *att_key = sd + TDX_SD_ATT_KEY;
    if (tdx_rd_u16le(sd + TDX_SD_CERT_TYPE) != ANTS_TDX_CERT_TYPE_QE_REPORT) {
        return ANTS_ERROR_MALFORMED;
    }
    uint32_t cert_size = tdx_rd_u32le(sd + TDX_SD_CERT_SIZE);
    if ((uint64_t)TDX_SD_CERT_BODY + cert_size > sig_data_len) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *cd = sd + TDX_SD_CERT_BODY;

    /* QE report (384) + its signature (64) + 2-byte auth length. */
    if (cert_size < TDX_CD_QE_AUTH) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *qe_report = cd + TDX_CD_QE_REPORT;
    const uint8_t *qe_report_sig = cd + TDX_CD_QE_REPORT_SIG;
    uint16_t qe_auth_size = tdx_rd_u16le(cd + TDX_CD_QE_AUTH_SIZE);
    if ((uint64_t)TDX_CD_QE_AUTH + qe_auth_size > cert_size) {
        return ANTS_ERROR_MALFORMED;
    }
    if (qe_auth_size > ANTS_TDX_QE_AUTH_DATA_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *qe_auth = cd + TDX_CD_QE_AUTH;

    ants_error_t err;
    uint8_t digest[ANTS_SHA256_HASH_SIZE];

    /* Link 1: the platform PCK leaf signs SHA-256(the QE report). */
    err = ants_sha256(qe_report, ANTS_TDX_QE_REPORT_SIZE, digest);
    if (err != ANTS_OK) {
        return err;
    }
    if (ants_ecdsa_p256_verify(pck_leaf_pubkey, digest, ANTS_SHA256_HASH_SIZE, qe_report_sig) !=
        ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Link 2: the QE report binds the attestation key. The binding is
     * SHA-256(att_key(64) || qe_auth_data) in the low 32 bytes of the QE
     * report's report_data; the high 32 bytes are zero. */
    {
        uint8_t bind_in[ANTS_ECDSA_P256_PUBKEY_SIZE + ANTS_TDX_QE_AUTH_DATA_MAX];
        memcpy(bind_in, att_key, ANTS_ECDSA_P256_PUBKEY_SIZE);
        memcpy(bind_in + ANTS_ECDSA_P256_PUBKEY_SIZE, qe_auth, qe_auth_size);
        err = ants_sha256(bind_in, (size_t)ANTS_ECDSA_P256_PUBKEY_SIZE + qe_auth_size, digest);
        if (err != ANTS_OK) {
            return err;
        }
        const uint8_t *rd = qe_report + TDX_QE_REPORT_DATA_OFF;
        if (memcmp(rd, digest, ANTS_SHA256_HASH_SIZE) != 0 ||
            !tdx_all_zero(rd + ANTS_SHA256_HASH_SIZE,
                          ANTS_TDX_REPORT_DATA_SIZE - ANTS_SHA256_HASH_SIZE)) {
            return ANTS_ERROR_MALFORMED;
        }
    }

    /* Link 3: the attestation key signs SHA-256(header || TD body). */
    err = ants_sha256(quote, TDX_OFF_SIG_DATA_LEN, digest);
    if (err != ANTS_OK) {
        return err;
    }
    if (ants_ecdsa_p256_verify(att_key, digest, ANTS_SHA256_HASH_SIZE, att_sig) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Attestation verification (composition over the per-vendor pieces)        */
/*                                                                          */
/* ants_attestation_verify ties the structure parser + the certificate-     */
/* chain validator (x509_chain.h) together: extract the embedded vendor cert */
/* chain from the blob, validate it to a PINNED vendor root (tee_roots.h),   */
/* take the proven leaf key, verify the report/quote signature under it, and */
/* bind the attestation to the peer's Ed25519 identity key.                  */
/*                                                                          */
/* Peer binding (v1): the low 32 bytes of the 64-byte report_data carry the  */
/* Ed25519 peer public key; the upper 32 bytes are reserved (the generate    */
/* side zero-fills them; verify does not constrain them in v1). This is the  */
/* byte-level binding RFC-0005 leaves to the implementation — pin it in the  */
/* spec when ants_attestation_generate lands.                               */
/*                                                                          */
/* No dynamic allocation: embedded certificates decode into fixed stack      */
/* buffers; an over-large embedded cert is rejected, not truncated.          */
/* ------------------------------------------------------------------------ */

/* Upper bound on one embedded DER certificate (Intel PCK leaf / Platform CA
 * are ~0.7-1.1 KB). */
#define ANTS_TEE_MAX_CERT_DER 2048

/* Ed25519 peer key carried in the low half of the 64-byte report_data. */
#define ANTS_TEE_PEER_BINDING_LEN 32

static int b64_val(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* Decode base64 [in, in+in_len) into out (cap out_cap), skipping whitespace.
 * ANTS_ERROR_MALFORMED on overflow or base64 data after '=' padding. */
static ants_error_t
b64_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t o = 0;
    uint32_t acc = 0;
    int nbits = 0;
    bool pad = false;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = in[i];
        if (c == '=') {
            pad = true;
            continue;
        }
        int v = b64_val(c);
        if (v < 0) {
            continue; /* whitespace / newline */
        }
        if (pad) {
            return ANTS_ERROR_MALFORMED; /* base64 data after padding */
        }
        acc = (acc << 6) | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o >= out_cap) {
                return ANTS_ERROR_MALFORMED;
            }
            out[o++] = (uint8_t)((acc >> nbits) & 0xFFu);
        }
    }
    *out_len = o;
    return ANTS_OK;
}

/* First occurrence of needle in [hay, hay+hay_len), or NULL. */
static const uint8_t *
find_bytes(const uint8_t *hay, size_t hay_len, const char *needle, size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len) {
        return NULL;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* Decode the next PEM CERTIFICATE block in [*cur, end) to DER, advancing *cur
 * past its END line. ANTS_ERROR_MALFORMED if none / malformed / oversize. */
static ants_error_t pem_next_cert(const uint8_t **cur,
                                  const uint8_t *end,
                                  uint8_t *out,
                                  size_t out_cap,
                                  size_t *out_len)
{
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    static const char END[] = "-----END CERTIFICATE-----";
    const uint8_t *b = find_bytes(*cur, (size_t)(end - *cur), BEGIN, sizeof BEGIN - 1);
    if (b == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *body = b + (sizeof BEGIN - 1);
    const uint8_t *e = find_bytes(body, (size_t)(end - body), END, sizeof END - 1);
    if (e == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    ants_error_t err = b64_decode(body, (size_t)(e - body), out, out_cap, out_len);
    if (err != ANTS_OK) {
        return err;
    }
    *cur = e + (sizeof END - 1);
    return ANTS_OK;
}

/* Locate the PCK certificate PEM chain embedded in a TDX v4 quote: it follows
 * the QE auth data as a type-5 (PCK_CHAIN) certification-data blob. Mirrors the
 * bounds checks of ants_tdx_quote_verify_signature up to qe_auth. */
static ants_error_t
tdx_locate_pck_pem(const uint8_t *quote, size_t quote_len, const uint8_t **pem, size_t *pem_len)
{
    if (quote_len < TDX_OFF_SIG_DATA) {
        return ANTS_ERROR_MALFORMED;
    }
    uint32_t sig_data_len = tdx_rd_u32le(quote + TDX_OFF_SIG_DATA_LEN);
    if ((uint64_t)TDX_OFF_SIG_DATA + sig_data_len > quote_len) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *sd = quote + TDX_OFF_SIG_DATA;
    if (sig_data_len < TDX_SD_CERT_BODY) {
        return ANTS_ERROR_MALFORMED;
    }
    if (tdx_rd_u16le(sd + TDX_SD_CERT_TYPE) != ANTS_TDX_CERT_TYPE_QE_REPORT) {
        return ANTS_ERROR_MALFORMED;
    }
    uint32_t cert_size = tdx_rd_u32le(sd + TDX_SD_CERT_SIZE);
    if ((uint64_t)TDX_SD_CERT_BODY + cert_size > sig_data_len) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *cd = sd + TDX_SD_CERT_BODY;
    if (cert_size < TDX_CD_QE_AUTH) {
        return ANTS_ERROR_MALFORMED;
    }
    uint16_t qe_auth_size = tdx_rd_u16le(cd + TDX_CD_QE_AUTH_SIZE);
    if ((uint64_t)TDX_CD_QE_AUTH + qe_auth_size > cert_size) {
        return ANTS_ERROR_MALFORMED;
    }
    /* The PCK certification data follows qe_auth: type(u16) + size(u32) + body. */
    uint64_t off = (uint64_t)TDX_CD_QE_AUTH + qe_auth_size;
    if (off + 6 > cert_size) {
        return ANTS_ERROR_MALFORMED;
    }
    const uint8_t *inner = cd + off;
    if (tdx_rd_u16le(inner) != ANTS_TDX_CERT_TYPE_PCK_CHAIN) {
        return ANTS_ERROR_MALFORMED;
    }
    uint32_t inner_size = tdx_rd_u32le(inner + 2);
    if (off + 6 + (uint64_t)inner_size > cert_size) {
        return ANTS_ERROR_MALFORMED;
    }
    *pem = inner + 6;
    *pem_len = inner_size;
    return ANTS_OK;
}

static ants_error_t tdx_attestation_verify(const ants_attestation_t *att)
{
    const uint8_t *quote = att->vendor_blob;
    size_t quote_len = att->vendor_blob_len;
    if (quote == NULL) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Extract the embedded PCK PEM chain (leaf + Platform CA; the root is
     * pinned, never taken from the quote). */
    const uint8_t *pem;
    size_t pem_len;
    ants_error_t err = tdx_locate_pck_pem(quote, quote_len, &pem, &pem_len);
    if (err != ANTS_OK) {
        return err;
    }
    uint8_t pck_der[ANTS_TEE_MAX_CERT_DER];
    uint8_t plat_der[ANTS_TEE_MAX_CERT_DER];
    size_t pck_len, plat_len;
    const uint8_t *cur = pem;
    const uint8_t *pend = pem + pem_len;
    err = pem_next_cert(&cur, pend, pck_der, sizeof pck_der, &pck_len);
    if (err != ANTS_OK) {
        return err;
    }
    err = pem_next_cert(&cur, pend, plat_der, sizeof plat_der, &plat_len);
    if (err != ANTS_OK) {
        return err;
    }

    /* Validate PCK -> Platform CA -> pinned Intel SGX Root CA, as of the
     * attestation's issuance time (recency is the separate is_fresh check). */
    const uint8_t *chain[] = {pck_der, plat_der};
    size_t lens[] = {pck_len, plat_len};
    ants_x509_cert leaf;
    err = ants_x509_chain_verify(chain,
                                 lens,
                                 2,
                                 ANTS_TEE_INTEL_SGX_ROOT_CA_DER,
                                 ANTS_TEE_INTEL_SGX_ROOT_CA_DER_LEN,
                                 att->issued_at_unix,
                                 &leaf);
    if (err != ANTS_OK) {
        return err;
    }
    if (leaf.key_kind != ANTS_X509_KEY_EC || leaf.curve != ANTS_X509_CURVE_P256 ||
        leaf.ec_point_len != ANTS_TDX_PCK_PUBKEY_SIZE) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Verify the quote's internal 3-link signature chain under the now-trusted
     * PCK leaf key. */
    err = ants_tdx_quote_verify_signature(quote, quote_len, leaf.ec_point);
    if (err != ANTS_OK) {
        return err;
    }

    /* Bind to the peer identity: report_data[0:32] == the peer's Ed25519 key. */
    ants_tdx_quote_t q;
    err = ants_tdx_quote_parse(quote, quote_len, &q);
    if (err != ANTS_OK) {
        return err;
    }
    if (memcmp(q.report_data, att->peer_pubkey, ANTS_TEE_PEER_BINDING_LEN) != 0) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
