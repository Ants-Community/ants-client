/*
 * snp_vectors.c -- emit the snp-report.verify test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout.
 * The base vector is a genuine AMD SEV-SNP attestation report from real
 * Milan silicon (see foundation/tee/tests/snp_kat_vectors.h for provenance:
 * google/go-sev-guest verify/testdata, VCEK CN=SEV-VCEK / issuer SEV-Milan,
 * signature independently confirmed with OpenSSL). The negative cases are
 * single-byte mutations of that report -- the standard guards a verifier
 * must enforce.
 *
 * Every verdict is CONFIRMED against the compiled ants_snp_report_verify_
 * signature before emission: a vector this tool prints is one our own
 * implementation already agrees with.
 *
 * Deterministic: fixed inputs, no clock, no randomness. Run it twice and
 * the bytes match.
 *
 * Usage:  snp_vectors > snp-report.json
 *
 * Spec: RFC-0005 (TEE attestation -- AMD SEV-SNP report signatures).
 */

#include "ants_tee.h"

#include "snp_kat_vectors.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what)
{
    fprintf(stderr, "snp_vectors: %s\n", what);
    exit(1);
}

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

static int g_first = 1;

/* From-artifact gate + emit. `result` is "valid" or "invalid"; we refuse to
 * print a case our own verifier does not reproduce. */
static void
emit_case(int tc_id, const char *comment, const uint8_t *report, size_t len, const char *result)
{
    ants_error_t e = ants_snp_report_verify_signature(report, len, SNP_KAT_VCEK_PUBKEY);
    bool want_valid = (strcmp(result, "valid") == 0);
    if (want_valid ? (e != ANTS_OK) : (e == ANTS_OK)) {
        die("verdict does not match the compiled verifier");
    }

    if (!g_first) {
        printf(",\n");
    }
    g_first = 0;
    printf("    {\"tc_id\": %d, \"comment\": \"%s\", \"report_hex\": \"", tc_id, comment);
    print_hex(report, len);
    printf("\", \"result\": \"%s\"}", result);
}

int main(void)
{
    uint8_t buf[ANTS_SNP_REPORT_SIZE];

    printf("{\n");
    printf("  \"primitive\": \"snp-report.verify (AMD SEV-SNP attestation report; ECDSA P-384 "
           "over SHA-384)\",\n");
    printf("  \"spec\":      \"RFC-0005 (TEE attestation: AMD SEV-SNP report signatures)\",\n");
    printf("  \"version\":   1,\n");
    printf("  \"vendor\":    \"verdicts confirmed through ants_snp_report_verify_signature\",\n");
    printf("  \"source\":    \"google/go-sev-guest verify/testdata @33e009a4 (attestation.bin "
           "sha256 377e6241d3b373ab1df80c0f96978594e7e21f4797dd6ea95e2957e1c1e26060; VCEK "
           "vcek.testcer CN=SEV-VCEK / issuer SEV-Milan); signature independently confirmed with "
           "OpenSSL\",\n");
    printf("  \"notes\":     \"The report is the 0x4A0-byte ATTESTATION_REPORT structure. The "
           "signature covers report[0, 0x2A0) and is ECDSA P-384 over its SHA-384 digest; R and S "
           "are stored little-endian in 72-byte slots (low 48 significant). vcek_pubkey_hex is the "
           "VCEK leaf point X||Y (96 bytes, big-endian, no 0x04 prefix). This pack covers ONLY the "
           "report-to-VCEK signature, not the VCEK certificate chain, freshness, or revocation. "
           "result 'valid' MUST verify (ANTS_OK); 'invalid' MUST be rejected. Negative cases are "
           "single-byte mutations of the genuine report. Every verdict was confirmed against the "
           "compiled ants_snp_report_verify_signature before emission.\",\n");
    printf("  \"vcek_pubkey_hex\": \"");
    print_hex(SNP_KAT_VCEK_PUBKEY, sizeof SNP_KAT_VCEK_PUBKEY);
    printf("\",\n");
    printf("  \"vectors\": [\n");

    /* 1: the genuine report verifies. */
    emit_case(1,
              "genuine AMD Milan report, valid VCEK signature",
              SNP_KAT_REPORT,
              ANTS_SNP_REPORT_SIZE,
              "valid");

    /* 2: a flipped byte inside the signed prefix breaks the signature. */
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x90] ^= 0x01;
    emit_case(2,
              "tampered report body (measurement byte) in the signed prefix",
              buf,
              sizeof buf,
              "invalid");

    /* 3, 4: a flipped byte in R or S breaks the signature. */
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x2A0] ^= 0x01;
    emit_case(3, "tampered signature R", buf, sizeof buf, "invalid");

    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x2E8] ^= 0x01;
    emit_case(4, "tampered signature S", buf, sizeof buf, "invalid");

    /* 5: an unsupported SIGNATURE_ALGO is rejected before any crypto. */
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x34] = 0x02;
    emit_case(5, "unsupported SIGNATURE_ALGO (2)", buf, sizeof buf, "invalid");

    /* 6: a non-zero high byte in R's 72-byte slot is an out-of-range scalar. */
    memcpy(buf, SNP_KAT_REPORT, sizeof buf);
    buf[0x2A0 + 48] = 0x01;
    emit_case(
        6, "non-canonical R padding (high 24 bytes must be zero)", buf, sizeof buf, "invalid");

    /* 7: a wrong-length report is rejected by the length guard. */
    emit_case(
        7, "truncated report (wrong length)", SNP_KAT_REPORT, ANTS_SNP_REPORT_SIZE - 1, "invalid");

    printf("\n  ]\n");
    printf("}\n");
    return 0;
}
