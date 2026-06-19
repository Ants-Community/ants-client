/*
 * tdx_vectors.c -- emit the tdx-quote.verify test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout.
 * The base vector is a genuine production Sapphire Rapids Intel TDX DCAP v4
 * quote (see foundation/tee/tests/tdx_kat_vectors.h for provenance:
 * google/go-tdx-guest testing/testdata; its three signature links --
 * PCK->QE report, QE->att-key binding, att-key->TD body -- independently
 * confirmed with Python cryptography + OpenSSL). The negative cases are
 * single-byte mutations of that quote (plus a truncation) -- the standard
 * guards a verifier must enforce.
 *
 * Every verdict is CONFIRMED against the compiled ants_tdx_quote_verify_
 * signature before emission: a vector this tool prints is one our own
 * implementation already agrees with.
 *
 * Deterministic: fixed inputs, no clock, no randomness. Run it twice and
 * the bytes match.
 *
 * Usage:  tdx_vectors > tdx-quote.json
 *
 * Spec: RFC-0005 (TEE attestation -- Intel TDX DCAP quote signatures).
 */

#include "ants_tee.h"

#include "tdx_kat_vectors.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what)
{
    fprintf(stderr, "tdx_vectors: %s\n", what);
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
emit_case(int tc_id, const char *comment, const uint8_t *quote, size_t len, const char *result)
{
    ants_error_t e = ants_tdx_quote_verify_signature(quote, len, TDX_KAT_PCK_LEAF_PUBKEY);
    bool want_valid = (strcmp(result, "valid") == 0);
    if (want_valid ? (e != ANTS_OK) : (e == ANTS_OK)) {
        die("verdict does not match the compiled verifier");
    }

    if (!g_first) {
        printf(",\n");
    }
    g_first = 0;
    printf("    {\"tc_id\": %d, \"comment\": \"%s\", \"quote_hex\": \"", tc_id, comment);
    print_hex(quote, len);
    printf("\", \"result\": \"%s\"}", result);
}

int main(void)
{
    uint8_t buf[sizeof TDX_KAT_QUOTE];

    printf("{\n");
    printf("  \"primitive\": \"tdx-quote.verify (Intel TDX DCAP v4 attestation quote; ECDSA P-256 "
           "over SHA-256, three-link chain)\",\n");
    printf("  \"spec\":      \"RFC-0005 (TEE attestation: Intel TDX DCAP quote signatures)\",\n");
    printf("  \"version\":   1,\n");
    printf("  \"vendor\":    \"verdicts confirmed through ants_tdx_quote_verify_signature\",\n");
    printf("  \"source\":    \"google/go-tdx-guest testing/testdata @4612d58 "
           "(tdx_prod_quote_SPR_E4.dat sha256 "
           "6dde5548bec99147fef832643301f113df99931547be26df8ac376c4eaa5b5a7; structured quote "
           "sha256 3507b5f7e6124e17210ffb4d5caf25a5d289a64fb19068ae90cd4cb25828db9f); the three "
           "signature links independently confirmed with Python cryptography + OpenSSL\",\n");
    printf("  \"notes\":     \"quote_hex is the STRUCTURED quote (header 0x30 + TD body 0x248 + "
           "signature data; the upstream .dat's 39-byte test-only trailer beyond sig_data_len is "
           "stripped). Verification is a three-link chain over a CALLER-SUPPLIED PCK leaf key: (1) "
           "PCK leaf signs SHA-256(QE report); (2) the QE report's report_data binds the "
           "attestation key (== SHA-256(att_key || qe_auth_data)); (3) the attestation key signs "
           "SHA-256(header || TD body). All ECDSA P-256 over SHA-256, r||s and X||Y big-endian. "
           "pck_leaf_pubkey_hex is the PCK leaf point X||Y (64 bytes, big-endian, no 0x04 prefix). "
           "This pack covers ONLY the quote's internal signatures, not the PCK certificate chain, "
           "freshness, or revocation. result 'valid' MUST verify (ANTS_OK); 'invalid' MUST be "
           "rejected. Negative cases are single-byte mutations of the genuine quote (and one "
           "truncation). Every verdict was confirmed against the compiled "
           "ants_tdx_quote_verify_signature before emission.\",\n");
    printf("  \"pck_leaf_pubkey_hex\": \"");
    print_hex(TDX_KAT_PCK_LEAF_PUBKEY, sizeof TDX_KAT_PCK_LEAF_PUBKEY);
    printf("\",\n");
    printf("  \"vectors\": [\n");

    /* 1: the genuine quote verifies end to end. */
    emit_case(1,
              "genuine production Sapphire Rapids TDX quote, full chain valid",
              TDX_KAT_QUOTE,
              sizeof TDX_KAT_QUOTE,
              "valid");

    /* 2: a flipped byte in the TD body breaks link 3 (att key over body). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x0B8] ^= 0x01;
    emit_case(2,
              "tampered TD body (MRTD) -- breaks the attestation signature",
              buf,
              sizeof buf,
              "invalid");

    /* 3: a flipped byte in the attestation signature (link 3). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x27C] ^= 0x01;
    emit_case(3, "tampered attestation signature", buf, sizeof buf, "invalid");

    /* 4: a flipped byte in the attestation key breaks the link-2 binding. */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x2BC] ^= 0x01;
    emit_case(4,
              "tampered attestation key -- breaks the report_data binding",
              buf,
              sizeof buf,
              "invalid");

    /* 5: a flipped byte in the QE report breaks link 1 (PCK over QE report). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x302] ^= 0x01;
    emit_case(5, "tampered QE report -- breaks the PCK signature", buf, sizeof buf, "invalid");

    /* 6: a flipped byte in the QE report signature (link 1). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x482] ^= 0x01;
    emit_case(6, "tampered QE report signature", buf, sizeof buf, "invalid");

    /* 7: a flipped byte in the QE auth data breaks link 2 in isolation. */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x4C4] ^= 0x01;
    emit_case(
        7, "tampered QE auth data -- breaks the report_data binding", buf, sizeof buf, "invalid");

    /* 8: a wrong quote version is rejected before any crypto. */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x000] = 0x05;
    emit_case(8, "unsupported quote version (5)", buf, sizeof buf, "invalid");

    /* 9: a wrong certification-data type (not 6 = QE report). */
    memcpy(buf, TDX_KAT_QUOTE, sizeof buf);
    buf[0x2FC] ^= 0x01;
    emit_case(9, "unsupported certification-data type (not QE report)", buf, sizeof buf, "invalid");

    /* 10: a quote too short to hold header + body + the sig-data length. */
    emit_case(10, "truncated quote (wrong length)", TDX_KAT_QUOTE, 0x27B, "invalid");

    printf("\n  ]\n");
    printf("}\n");
    return 0;
}
