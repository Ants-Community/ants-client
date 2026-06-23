/*
 * test_tee.c — placeholder tests for the TEE attestation harness.
 *
 * These tests pin the harness contract so it can't silently change:
 *
 *   - public-API symbols link;
 *   - ants_attestation_generate is still a stub (NOT_IMPLEMENTED); verify
 *     dispatches per vendor (INVALID_ARG on NULL, NOT_IMPLEMENTED for a
 *     vendor whose wiring is pending; the real Intel TDX verification is
 *     covered end to end in test_attestation.c); is_fresh / is_revoked
 *     return their documented false default;
 *   - constant values (vendor IDs, default windows, weight ratios)
 *     match the spec.
 */

#include "ants_common.h"
#include "ants_tee.h"

#include "snp_kat_vectors.h"
#include "tdx_kat_vectors.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                 \
    do {                                                                                           \
        ants_error_t _a = (actual);                                                                \
        ants_error_t _e = (expected);                                                              \
        if (_a != _e) {                                                                            \
            failures++;                                                                            \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

static void test_vendor_ids_pinned(void)
{
    /* Vendor IDs MUST NOT change across releases — they appear in CBOR
     * encodings of peer-handshake attestations. Pin them explicitly. */
    CHECK(ANTS_TEE_VENDOR_UNKNOWN == 0);
    CHECK(ANTS_TEE_VENDOR_INTEL_TDX == 1);
    CHECK(ANTS_TEE_VENDOR_AMD_SEV_SNP == 2);
    CHECK(ANTS_TEE_VENDOR_ARM_CCA == 3);
    CHECK(ANTS_TEE_VENDOR_APPLE_SE == 4);
    CHECK(ANTS_TEE_VENDOR_QUALCOMM_QSEE == 5);
}

static void test_default_windows_match_rfc0005(void)
{
    /* 30 days × 24 h × 3600 s = 2592000 s, per RFC-0005 §Attestation
     * freshness window. */
    CHECK(ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS == 2592000LL);
    /* 72 h × 3600 s = 259200 s, per RFC-0005 §Vendor revocation
     * propagation timing. */
    CHECK(ANTS_TEE_DEFAULT_REVOCATION_BOUND_SECONDS == 259200LL);
}

static void test_multivendor_weight_ratios(void)
{
    /* Per RFC-0005 §Multi-vendor reputation weighting:
     * single=1.0, dual=1.2, triple=1.4. Stored as num/den so callers
     * can avoid float arithmetic in reputation accumulators. */
    CHECK(ANTS_TEE_WEIGHT_SINGLE_NUM * 10 == ANTS_TEE_WEIGHT_SINGLE_DEN * 10); /* 1.0 */
    CHECK(ANTS_TEE_WEIGHT_DUAL_NUM * 10 == ANTS_TEE_WEIGHT_DUAL_DEN * 12);     /* 1.2 */
    CHECK(ANTS_TEE_WEIGHT_TRIPLE_NUM * 10 == ANTS_TEE_WEIGHT_TRIPLE_DEN * 14); /* 1.4 */
}

static void test_generate_returns_not_implemented(void)
{
    uint8_t pk[32] = {0};
    ants_attestation_t att;
    memset(&att, 0, sizeof att);
    CHECK_EQ(ants_attestation_generate(ANTS_TEE_VENDOR_INTEL_TDX, pk, &att),
             ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_verify_dispatch_contract(void)
{
    /* NULL is an argument error. */
    CHECK_EQ(ants_attestation_verify(NULL), ANTS_ERROR_INVALID_ARG);
    /* A vendor whose wiring has not landed returns NOT_IMPLEMENTED: a zeroed
     * att is ANTS_TEE_VENDOR_UNKNOWN, and AMD SEV-SNP is likewise pending. The
     * real Intel TDX path is covered end to end in test_attestation.c. */
    ants_attestation_t att;
    memset(&att, 0, sizeof att);
    CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_NOT_IMPLEMENTED);
    att.vendor = ANTS_TEE_VENDOR_AMD_SEV_SNP;
    CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_is_fresh_returns_false(void)
{
    /* Documented contract: false until v2.x ships the real impl. */
    ants_attestation_t att;
    memset(&att, 0, sizeof att);
    att.issued_at_unix = 0;
    att.expires_at_unix = 0;
    CHECK(ants_attestation_is_fresh(&att, 1000, 100) == false);
    CHECK(ants_attestation_is_fresh(NULL, 1000, 100) == false);
}

static void test_is_revoked_returns_false(void)
{
    /* Documented contract: false in v1.0 (no revocation list loaded).
     * Callers MUST treat this as inconclusive. */
    ants_attestation_t att;
    memset(&att, 0, sizeof att);
    CHECK(ants_attestation_is_revoked(&att) == false);
    CHECK(ants_attestation_is_revoked(NULL) == false);
}

/* ---- AMD SEV-SNP report parse + signature verify ---------------------- */
/*                                                                         */
/* KAT vector: a genuine attestation report from real AMD Milan silicon,   */
/* its VCEK signature independently confirmed with OpenSSL before pinning  */
/* (see snp_kat_vectors.h for provenance + the verification transcript).   */

static void test_snp_report_parse_fields(void)
{
    ants_snp_report_t r;
    CHECK_EQ(ants_snp_report_parse(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE, &r), ANTS_OK);

    /* Scalar fields, independently decoded from the report. */
    CHECK(r.version == 2);
    CHECK(r.guest_svn == 0);
    CHECK(r.policy == 0x00000000000b0000ULL);
    CHECK(r.vmpl == 0);
    CHECK(r.signature_algo == ANTS_SNP_SIG_ALGO_ECDSA_P384_SHA384);
    CHECK(r.current_tcb == 0x4405000000000002ULL);
    CHECK(r.reported_tcb == 0x4405000000000002ULL);

    /* Byte-array fields: anchor both ends so a wrong offset is caught
     * (REPORT_DATA carries the 01 02 03 04 05 nonce, then zeros). */
    CHECK(r.report_data[0] == 0x01 && r.report_data[4] == 0x05 && r.report_data[5] == 0x00);
    CHECK(r.measurement[0] == 0xb0 && r.measurement[ANTS_SNP_MEASUREMENT_SIZE - 1] == 0x01);
    CHECK(r.chip_id[0] == 0x3a && r.chip_id[ANTS_SNP_CHIP_ID_SIZE - 1] == 0x5d);

    /* Guards. */
    CHECK_EQ(ants_snp_report_parse(NULL, ANTS_SNP_REPORT_SIZE, &r), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_snp_report_parse(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_snp_report_parse(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE - 1, &r),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_real_report(void)
{
    /* Positive KAT: the real Milan VCEK signature must verify. */
    CHECK_EQ(
        ants_snp_report_verify_signature(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE, SNP_KAT_VCEK_PUBKEY),
        ANTS_OK);
}

static void test_snp_verify_rejects_tampered_body(void)
{
    /* Flip a measurement bit (inside the signed [0, 0x2A0) prefix). */
    uint8_t buf[ANTS_SNP_REPORT_SIZE];
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x90] ^= 0x01;
    CHECK_EQ(ants_snp_report_verify_signature(buf, sizeof buf, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_rejects_tampered_signature(void)
{
    /* Flip a low byte of R. */
    uint8_t buf[ANTS_SNP_REPORT_SIZE];
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x2A0] ^= 0x01;
    CHECK_EQ(ants_snp_report_verify_signature(buf, sizeof buf, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_rejects_wrong_key(void)
{
    /* Corrupt one byte of the VCEK X coordinate. */
    uint8_t key[ANTS_SNP_VCEK_PUBKEY_SIZE];
    memcpy(key, SNP_KAT_VCEK_PUBKEY, sizeof key);
    key[0] ^= 0x01;
    CHECK_EQ(ants_snp_report_verify_signature(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE, key),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_rejects_bad_algo(void)
{
    /* SIGNATURE_ALGO != ECDSA-P384-SHA384 is rejected before any crypto. */
    uint8_t buf[ANTS_SNP_REPORT_SIZE];
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x34] = 2;
    CHECK_EQ(ants_snp_report_verify_signature(buf, sizeof buf, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_rejects_nonzero_rs_padding(void)
{
    /* The high 24 bytes of each 72-byte R/S slot must be zero. */
    uint8_t buf[ANTS_SNP_REPORT_SIZE];
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x2A0 + 48] = 0x01; /* first padding byte of R */
    CHECK_EQ(ants_snp_report_verify_signature(buf, sizeof buf, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_snp_verify_guards(void)
{
    CHECK_EQ(ants_snp_report_verify_signature(NULL, ANTS_SNP_REPORT_SIZE, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_snp_report_verify_signature(SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_snp_report_verify_signature(
                 SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE - 1, SNP_KAT_VCEK_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

/* ---- Intel TDX DCAP quote parse + signature verify ------------------- */
/*                                                                        */
/* KAT vector: a genuine production Sapphire Rapids TDX quote (v4,         */
/* ECDSA-P256). Its three signature links (PCK->QE report, QE->att key     */
/* binding, att key->TD body) were independently confirmed with Python     */
/* cryptography + OpenSSL before pinning (see tdx_kat_vectors.h).          */

/* Absolute tamper offsets into the structured quote (see tee.c). */
#define TDX_T_VERSION       0x000
#define TDX_T_ATT_KEY_TYPE  0x002
#define TDX_T_TEE_TYPE      0x004
#define TDX_T_MR_TD         0x0B8 /* inside the att-key-signed [0, 0x278) */
#define TDX_T_ATT_SIG       0x27C
#define TDX_T_ATT_KEY       0x2BC
#define TDX_T_CERT_TYPE     0x2FC
#define TDX_T_QE_REPORT     0x302
#define TDX_T_QE_REPORT_SIG 0x482
#define TDX_T_QE_AUTH       0x4C4

static void test_tdx_quote_parse_fields(void)
{
    ants_tdx_quote_t q;
    CHECK_EQ(ants_tdx_quote_parse(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, &q), ANTS_OK);

    /* Header. */
    CHECK(q.version == ANTS_TDX_QUOTE_VERSION);
    CHECK(q.att_key_type == ANTS_TDX_ATT_KEY_TYPE_ECDSA_P256);
    CHECK(q.tee_type == ANTS_TDX_TEE_TYPE);
    CHECK(q.qe_vendor_id[0] == 0x93 && q.qe_vendor_id[ANTS_TDX_QE_VENDOR_ID_SIZE - 1] == 0x07);

    /* Scalar TD-body bitfields, independently decoded from the quote. */
    CHECK(q.seam_attributes == 0);
    CHECK(q.td_attributes == 0x0000000040000000ULL);
    CHECK(q.xfam == 0x0000000000061ae7ULL);

    /* Byte-array fields: anchor both ends so a wrong offset is caught. */
    CHECK(q.tee_tcb_svn[0] == 0x03);
    CHECK(q.mr_seam[0] == 0x2f && q.mr_seam[ANTS_TDX_MEASUREMENT_SIZE - 1] == 0x56);
    CHECK(q.mr_td[0] == 0x63 && q.mr_td[ANTS_TDX_MEASUREMENT_SIZE - 1] == 0xbb);
    CHECK(q.rtmr[0][0] == 0x29 && q.rtmr[0][ANTS_TDX_MEASUREMENT_SIZE - 1] == 0x2a);
    CHECK(q.report_data[0] == 0x6c && q.report_data[ANTS_TDX_REPORT_DATA_SIZE - 1] == 0x13);

    /* Guards. */
    CHECK_EQ(ants_tdx_quote_parse(NULL, sizeof TDX_KAT_QUOTE, &q), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tdx_quote_parse(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tdx_quote_parse(
                 TDX_KAT_QUOTE, ANTS_TDX_QUOTE_HEADER_SIZE + ANTS_TDX_QUOTE_BODY_SIZE - 1, &q),
             ANTS_ERROR_MALFORMED);
}

static void test_tdx_verify_real_quote(void)
{
    /* Positive KAT: the full three-link chain must verify. */
    CHECK_EQ(ants_tdx_quote_verify_signature(
                 TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_OK);
}

/* Helper: copy the KAT, flip one byte, expect MALFORMED. */
static void tdx_expect_malformed_with_flip(size_t off)
{
    uint8_t buf[sizeof TDX_KAT_QUOTE];
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[off] ^= 0x01;
    CHECK_EQ(ants_tdx_quote_verify_signature(buf, sizeof buf, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_tdx_verify_rejects_tampering(void)
{
    /* TD body (breaks link 3: att key over header||body). */
    tdx_expect_malformed_with_flip(TDX_T_MR_TD);
    /* Attestation signature (link 3). */
    tdx_expect_malformed_with_flip(TDX_T_ATT_SIG);
    /* Attestation key (breaks the link-2 binding hash). */
    tdx_expect_malformed_with_flip(TDX_T_ATT_KEY);
    /* QE report (breaks link 1: PCK over the QE report). */
    tdx_expect_malformed_with_flip(TDX_T_QE_REPORT);
    /* QE report signature (link 1). */
    tdx_expect_malformed_with_flip(TDX_T_QE_REPORT_SIG);
    /* QE auth data (breaks link 2 binding in isolation — it is signed by
     * nothing else, only bound through report_data). */
    tdx_expect_malformed_with_flip(TDX_T_QE_AUTH);
}

static void test_tdx_verify_rejects_wrong_pck_key(void)
{
    uint8_t key[ANTS_TDX_PCK_PUBKEY_SIZE];
    memcpy(key, TDX_KAT_PCK_LEAF_PUBKEY, sizeof key);
    key[0] ^= 0x01;
    CHECK_EQ(ants_tdx_quote_verify_signature(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, key),
             ANTS_ERROR_MALFORMED);
}

static void test_tdx_verify_rejects_header_invariants(void)
{
    uint8_t buf[sizeof TDX_KAT_QUOTE];

    /* version != 4. */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[TDX_T_VERSION] = 5;
    CHECK_EQ(ants_tdx_quote_verify_signature(buf, sizeof buf, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);

    /* att_key_type != 2 (ECDSA-P256). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[TDX_T_ATT_KEY_TYPE] = 3;
    CHECK_EQ(ants_tdx_quote_verify_signature(buf, sizeof buf, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);

    /* tee_type != TDX. */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[TDX_T_TEE_TYPE] = 0x00;
    CHECK_EQ(ants_tdx_quote_verify_signature(buf, sizeof buf, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);

    /* certification data type != 6 (QE report). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[TDX_T_CERT_TYPE] ^= 0x01;
    CHECK_EQ(ants_tdx_quote_verify_signature(buf, sizeof buf, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

static void test_tdx_verify_guards(void)
{
    CHECK_EQ(ants_tdx_quote_verify_signature(NULL, sizeof TDX_KAT_QUOTE, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_tdx_quote_verify_signature(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, NULL),
             ANTS_ERROR_INVALID_ARG);
    /* Too short to even hold header + body + the sig-data length word. */
    CHECK_EQ(ants_tdx_quote_verify_signature(TDX_KAT_QUOTE, 0x27B, TDX_KAT_PCK_LEAF_PUBKEY),
             ANTS_ERROR_MALFORMED);
}

int main(void)
{
    test_vendor_ids_pinned();
    test_default_windows_match_rfc0005();
    test_multivendor_weight_ratios();
    test_generate_returns_not_implemented();
    test_verify_dispatch_contract();
    test_is_fresh_returns_false();
    test_is_revoked_returns_false();

    test_snp_report_parse_fields();
    test_snp_verify_real_report();
    test_snp_verify_rejects_tampered_body();
    test_snp_verify_rejects_tampered_signature();
    test_snp_verify_rejects_wrong_key();
    test_snp_verify_rejects_bad_algo();
    test_snp_verify_rejects_nonzero_rs_padding();
    test_snp_verify_guards();

    test_tdx_quote_parse_fields();
    test_tdx_verify_real_quote();
    test_tdx_verify_rejects_tampering();
    test_tdx_verify_rejects_wrong_pck_key();
    test_tdx_verify_rejects_header_invariants();
    test_tdx_verify_guards();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
