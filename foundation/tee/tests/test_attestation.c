/*
 * test_attestation.c — end-to-end KAT for ants_attestation_verify.
 *
 * Drives the full per-vendor composition over GENUINE attestations, through the
 * public ants_tee.h surface only (the composition is the whole point — parse +
 * chain-validate to a pinned root + verify + bind, no caller-supplied leaf key):
 *
 *   - Intel TDX (tdx_kat_vectors.h): a real Sapphire Rapids quote with its PCK
 *     PEM chain embedded; verify extracts it, validates to the pinned Intel SGX
 *     Root CA, checks the quote's 3-link signature, and binds report_data[0:32].
 *   - AMD SEV-SNP (snp_kat_vectors.h + cert_kat_vectors.h): a real Milan report
 *     followed by a GHCB certificate table assembled here from the genuine
 *     VCEK/ASK/ARK DER. verify extracts VCEK + ASK, validates VCEK -> ASK -> the
 *     pinned ARK-Milan, checks the report signature under the proven VCEK leaf,
 *     and binds report_data[0:32]. (go-sev-guest ships the report and certs
 *     separately — no combined fixture exists — so the blob is assembled here in
 *     the canonical AMD layout, byte-faithful to what hardware emits.)
 *
 * verify = EVIDENCE (chain to the pinned root + report/quote signature) + the
 * RFC-0008 §11.12 BINDING (report_data == peer-id ‖ LE64(issued_at) ‖ 0×24).
 * A genuine vendor attestation carries third-party report_data, never an ANTS
 * binding, so no real KAT can pass the full verify — that positive needs
 * ants_attestation_generate on real confidential-compute hardware. The halves
 * are therefore tested separately: the evidence half over the genuine
 * attestations through an internal hook (every tamper case below goes through
 * it, so each failure is caused by the tamper, not by the binding), and the
 * binding half through ants_attestation_report_data plus verify's rejection of
 * the genuine-but-unbound evidence.
 */

#include "ants_common.h"
#include "ants_tee.h"

#include "cert_kat_vectors.h"
#include "snp_kat_vectors.h"
#include "tdx_kat_vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

/* Internal test hook (tee.c): verify's evidence half; returns the signed
 * report_data. */
extern ants_error_t ants_attestation__test_verify_evidence(const ants_attestation_t *att,
                                                           uint8_t out_report_data[64]);

static ants_error_t evidence(const ants_attestation_t *att)
{
    uint8_t rd[ANTS_TEE_REPORT_DATA_SIZE];
    return ants_attestation__test_verify_evidence(att, rd);
}

/* Upper bound on the assembled SNP blob (report 1184 + 96-byte table header +
 * VCEK 1360 + ASK 1677 + ARK 1639 ~= 5956). */
#define SNP_BLOB_CAP 8192

static int failures = 0;

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

/* 2025-01-01T00:00:00Z — inside every vendor cert window: Intel (PCK 2022-2029,
 * Platform 2018-2033, Root 2018-2049) and AMD (VCEK 2022-2029, ASK/ARK
 * 2020-2045). */
#define NOW_VALID ((int64_t)1735689600)
/* 2010-01-01 — before the Intel or AMD chains existed. */
#define NOW_TOO_EARLY ((int64_t)1262304000)

/* Build a TDX attestation over `blob`, binding the supplied 32-byte peer key. */
static void make_att(ants_attestation_t *att,
                     const uint8_t *blob,
                     size_t blob_len,
                     const uint8_t peer[32],
                     int64_t issued)
{
    memset(att, 0, sizeof *att);
    att->vendor = ANTS_TEE_VENDOR_INTEL_TDX;
    att->vendor_blob = blob;
    att->vendor_blob_len = blob_len;
    att->issued_at_unix = issued;
    memcpy(att->peer_pubkey, peer, 32);
}

/* As make_att, but for the AMD SEV-SNP vendor. */
static void make_att_snp(ants_attestation_t *att,
                         const uint8_t *blob,
                         size_t blob_len,
                         const uint8_t peer[32],
                         int64_t issued)
{
    make_att(att, blob, blob_len, peer, issued);
    att->vendor = ANTS_TEE_VENDOR_AMD_SEV_SNP;
}

/* AMD certificate-table GUIDs, on-wire RFC-4122 big-endian bytes — encoded here
 * directly from the go-sev-guest strings, independent of the implementation's
 * own constants, so the assembled blob is a faithful copy of the real GHCB
 * layout (a parser-side GUID/format bug then fails the positive KAT below
 * rather than passing it). */
static const uint8_t SNP_T_GUID_VCEK[16] = {0x63,
                                            0xda,
                                            0x75,
                                            0x8d,
                                            0xe6,
                                            0x64,
                                            0x45,
                                            0x64,
                                            0xad,
                                            0xc5,
                                            0xf4,
                                            0xb9,
                                            0x3b,
                                            0xe8,
                                            0xac,
                                            0xcd};
static const uint8_t SNP_T_GUID_ASK[16] = {0x4a,
                                           0xb7,
                                           0xb3,
                                           0x79,
                                           0xbb,
                                           0xac,
                                           0x4f,
                                           0xe4,
                                           0xa0,
                                           0x2f,
                                           0x05,
                                           0xae,
                                           0xf3,
                                           0x27,
                                           0xc7,
                                           0x82};
static const uint8_t SNP_T_GUID_ARK[16] = {0xc0,
                                           0xb4,
                                           0x06,
                                           0xa4,
                                           0xa8,
                                           0x03,
                                           0x49,
                                           0x52,
                                           0x97,
                                           0x43,
                                           0x3f,
                                           0xb6,
                                           0x01,
                                           0x4c,
                                           0xd0,
                                           0xae};

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Write a 24-byte cert-table entry { guid || offset:u32 LE || length:u32 LE }. */
static void put_entry(uint8_t *e, const uint8_t guid[16], uint32_t off, uint32_t len)
{
    memcpy(e, guid, 16);
    put_u32le(e + 16, off);
    put_u32le(e + 20, len);
}

/* Assemble report || GHCB cert table { VCEK, ASK, ARK } into `out`. The table is
 * 3 entries + an all-zero terminator (96 B), then the DER certs; each entry's
 * offset is measured from the table start. Returns the total length, or 0 on
 * overflow. */
static size_t build_snp_blob(uint8_t *out,
                             size_t out_cap,
                             const uint8_t *vcek,
                             size_t vcek_len,
                             const uint8_t *ask,
                             size_t ask_len,
                             const uint8_t *ark,
                             size_t ark_len)
{
    const size_t hdr = 4 * 24; /* 3 real entries + 1 zero terminator */
    const size_t voff = hdr;
    const size_t aoff = voff + vcek_len;
    const size_t koff = aoff + ask_len;
    const size_t table_len = koff + ark_len;
    const size_t total = sizeof SNP_KAT_REPORT + table_len;
    if (total > out_cap) {
        return 0;
    }
    memcpy(out, SNP_KAT_REPORT, sizeof SNP_KAT_REPORT);
    uint8_t *table = out + sizeof SNP_KAT_REPORT;
    memset(table, 0, table_len);
    put_entry(table + 0, SNP_T_GUID_VCEK, (uint32_t)voff, (uint32_t)vcek_len);
    put_entry(table + 24, SNP_T_GUID_ASK, (uint32_t)aoff, (uint32_t)ask_len);
    put_entry(table + 48, SNP_T_GUID_ARK, (uint32_t)koff, (uint32_t)ark_len);
    /* table + 72 .. +96 stays zero: the terminator entry. */
    memcpy(table + voff, vcek, vcek_len);
    memcpy(table + aoff, ask, ask_len);
    memcpy(table + koff, ark, ark_len);
    return total;
}

int main(void)
{
    /* The peer key the genuine quote is bound to: its report_data low 32 bytes. */
    ants_tdx_quote_t q;
    CHECK_EQ(ants_tdx_quote_parse(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, &q), ANTS_OK);
    uint8_t peer[32];
    memcpy(peer, q.report_data, 32);

    /* Evidence positive: the full chain validates to the pinned Intel root, the
     * quote verifies under the extracted PCK leaf, and the hook returns the
     * signed report_data byte-for-byte. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_VALID);
        uint8_t rd[ANTS_TEE_REPORT_DATA_SIZE];
        CHECK_EQ(ants_attestation__test_verify_evidence(&att, rd), ANTS_OK);
        CHECK(memcmp(rd, q.report_data, sizeof rd) == 0);
        /* ...but the full verify rejects it: the genuine quote's report_data
         * [32:64] is third-party bytes, not LE64(issued_at) ‖ 0×24. With the
         * evidence proven good above, the binding is the rejecting step. */
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
    }

    /* Corrupted quote body: the attestation-key signature over header||body
     * fails (the embedded chain and PEM location are untouched, so the failure
     * is the quote-signature step). */
    {
        static uint8_t buf[sizeof TDX_KAT_QUOTE];
        memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
        buf[0x100] ^= 0xFF; /* inside the signed TD body [0, 0x278) */
        ants_attestation_t att;
        make_att(&att, buf, sizeof buf, peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Issued before the certificate chain was valid: chain validity rejects. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_TOO_EARLY);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Truncated blob: bounds checks reject before any crypto. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, 100, peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* ---- AMD SEV-SNP ------------------------------------------------------ */

    /* Assemble the vendor blob: the genuine Milan report || a GHCB cert table
     * built from the genuine VCEK/ASK/ARK DER. The VCEK leaf, proven to chain to
     * the pinned ARK-Milan, is what verifies the report. */
    static uint8_t snp_blob[SNP_BLOB_CAP];
    size_t snp_len = build_snp_blob(snp_blob,
                                    sizeof snp_blob,
                                    CERT_KAT_VCEK_DER,
                                    sizeof CERT_KAT_VCEK_DER,
                                    CERT_KAT_ASK_DER,
                                    sizeof CERT_KAT_ASK_DER,
                                    CERT_KAT_ARK_DER,
                                    sizeof CERT_KAT_ARK_DER);
    if (snp_len == 0) {
        failures++;
        fprintf(stderr, "FAIL %s:%d  SNP blob assembly overflowed\n", __FILE__, __LINE__);
    }

    /* The peer key the genuine report is bound to: its report_data low 32 bytes. */
    ants_snp_report_t sr;
    CHECK_EQ(ants_snp_report_parse(SNP_KAT_REPORT, sizeof SNP_KAT_REPORT, &sr), ANTS_OK);
    uint8_t snp_peer[32];
    memcpy(snp_peer, sr.report_data, 32);

    /* Evidence positive: VCEK -> ASK -> pinned ARK-Milan validates, the report
     * verifies under the proven VCEK leaf, and the signed report_data comes
     * back byte-for-byte. */
    {
        ants_attestation_t att;
        make_att_snp(&att, snp_blob, snp_len, snp_peer, NOW_VALID);
        uint8_t rd[ANTS_TEE_REPORT_DATA_SIZE];
        CHECK_EQ(ants_attestation__test_verify_evidence(&att, rd), ANTS_OK);
        CHECK(memcmp(rd, sr.report_data, sizeof rd) == 0);
        /* The full verify rejects it: report_data[32:40] is zero, i.e. it
         * would bind issued_at = 0, but this presentation claims NOW_VALID. */
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
        /* Claiming issued_at = 0 satisfies the binding — and then the chain
         * check rejects it, since the VCEK was not valid in 1970. Rewriting
         * issued_at cannot get past both. */
        make_att_snp(&att, snp_blob, snp_len, snp_peer, 0);
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
    }

    /* Corrupted report body: the report-to-VCEK signature over report[0, 0x2A0)
     * fails (the cert table is left intact). */
    {
        static uint8_t buf[SNP_BLOB_CAP];
        memcpy(buf, snp_blob, snp_len);
        buf[0x100] ^= 0xFF; /* inside the signed report prefix [0, 0x2A0) */
        ants_attestation_t att;
        make_att_snp(&att, buf, snp_len, snp_peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Issued before the VCEK was valid (2010 < 2022): chain validity rejects. */
    {
        ants_attestation_t att;
        make_att_snp(&att, snp_blob, snp_len, snp_peer, NOW_TOO_EARLY);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Truncated blob (shorter than the report): rejected before any crypto. */
    {
        ants_attestation_t att;
        make_att_snp(&att, snp_blob, 100, snp_peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Cert table with the VCEK GUID corrupted: the leaf cannot be located. */
    {
        static uint8_t buf[SNP_BLOB_CAP];
        memcpy(buf, snp_blob, snp_len);
        buf[sizeof SNP_KAT_REPORT] ^= 0xFF; /* first byte of the VCEK GUID */
        ants_attestation_t att;
        make_att_snp(&att, buf, snp_len, snp_peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* Cert-table entry with an out-of-bounds length: the bounds check rejects
     * (no read past the table — exercised under ASan/UBSan). */
    {
        static uint8_t buf[SNP_BLOB_CAP];
        memcpy(buf, snp_blob, snp_len);
        size_t lf = sizeof SNP_KAT_REPORT + 20; /* VCEK entry's length:u32 LE */
        buf[lf] = 0xFF;
        buf[lf + 1] = 0xFF;
        buf[lf + 2] = 0xFF;
        buf[lf + 3] = 0xFF;
        ants_attestation_t att;
        make_att_snp(&att, buf, snp_len, snp_peer, NOW_VALID);
        CHECK_EQ(evidence(&att), ANTS_ERROR_MALFORMED);
    }

    /* ---- RFC-0008 §11.12 binding ----------------------------------------- */

    /* Known answer: peer-id ‖ LE64(issued_at) ‖ 0x00 × 24. Expected bytes are
     * written out by hand, independently of the implementation. */
    {
        uint8_t pk[32];
        for (size_t i = 0; i < sizeof pk; i++) {
            pk[i] = (uint8_t)i;
        }
        uint8_t rd[ANTS_TEE_REPORT_DATA_SIZE];
        memset(rd, 0xAA, sizeof rd);
        CHECK_EQ(ants_attestation_report_data(pk, (int64_t)0x0102030405060708LL, rd), ANTS_OK);
        static const uint8_t want_time[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
        static const uint8_t zeros[24] = {0};
        CHECK(memcmp(rd, pk, 32) == 0);
        CHECK(memcmp(rd + 32, want_time, 8) == 0);
        CHECK(memcmp(rd + 40, zeros, 24) == 0);

        /* 2025-01-01T00:00:00Z = 0x67748580. */
        CHECK_EQ(ants_attestation_report_data(pk, NOW_VALID, rd), ANTS_OK);
        static const uint8_t want_now[8] = {0x80, 0x85, 0x74, 0x67, 0x00, 0x00, 0x00, 0x00};
        CHECK(memcmp(rd + 32, want_now, 8) == 0);

        /* issued_at = 0 is the SNP KAT's own report_data: the builder
         * reproduces a real vendor-signed report_data exactly. */
        CHECK_EQ(ants_attestation_report_data(snp_peer, 0, rd), ANTS_OK);
        CHECK(memcmp(rd, sr.report_data, sizeof rd) == 0);

        /* Argument guards: NULLs, and a negative time (the wire field is
         * unsigned — it has no LE64 encoding). */
        CHECK_EQ(ants_attestation_report_data(NULL, 0, rd), ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_attestation_report_data(pk, 0, NULL), ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_attestation_report_data(pk, -1, rd), ANTS_ERROR_INVALID_ARG);
    }

    /* Evidence-hook argument guards. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_VALID);
        uint8_t rd[ANTS_TEE_REPORT_DATA_SIZE];
        CHECK_EQ(ants_attestation__test_verify_evidence(NULL, rd), ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_attestation__test_verify_evidence(&att, NULL), ANTS_ERROR_INVALID_ARG);
    }

    /* Vendor whose wiring has not landed yet (ARM CCA is v1.x). */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_VALID);
        att.vendor = ANTS_TEE_VENDOR_ARM_CCA;
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_NOT_IMPLEMENTED);
    }

    /* Argument guard. */
    CHECK_EQ(ants_attestation_verify(NULL), ANTS_ERROR_INVALID_ARG);

    if (failures == 0) {
        printf("test_attestation: all KATs passed\n");
        return 0;
    }
    fprintf(stderr, "test_attestation: %d check(s) FAILED\n", failures);
    return 1;
}
