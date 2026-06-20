/*
 * rsa_pss_vectors.c -- emit the rsa-pss.verify test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout. The
 * base vectors are two genuine RSA-4096 RSASSA-PSS signatures from the real
 * AMD SEV-Milan certificate chain (see foundation/crypto/tests/rsa_kat_vectors.h
 * for provenance: AMD KDS Milan/cert_chain, both signatures independently
 * confirmed with OpenSSL). The negative cases are single-byte mutations of the
 * genuine message or signature, a cross-signer, and a truncation -- the
 * standard guards a verifier must enforce.
 *
 * Every verdict is CONFIRMED against the compiled ants_rsa_pss_verify before
 * emission: a vector this tool prints is one our own implementation already
 * agrees with. The per-vector msg_sha384 is computed by the reference
 * ants_sha384 (the digest our verify consumes), not transcribed.
 *
 * Deterministic: fixed inputs, no clock, no randomness. Run it twice and the
 * bytes match.
 *
 * Usage:  rsa_pss_vectors > rsa-pss.json
 *
 * Spec: RFC-0005 (TEE attestation -- AMD SEV-SNP's ASK/ARK certificate chain is
 * RSA-4096 RSASSA-PSS over SHA-384). RFC-0008 (signatures).
 */

#include "ants_crypto.h"

#include "rsa_kat_vectors.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what)
{
    fprintf(stderr, "rsa_pss_vectors: %s\n", what);
    exit(1);
}

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

static int g_first = 1;

/* From-artifact gate + emit. Computes SHA-384(msg) with the reference
 * ants_sha384, verifies it against the ARK key with the compiled
 * ants_rsa_pss_verify, and refuses to print a case whose verdict our own
 * implementation does not reproduce. */
static void emit_case(int tc_id,
                      const char *comment,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t *sig,
                      size_t sig_len,
                      const char *result)
{
    uint8_t digest[ANTS_SHA384_HASH_SIZE];
    if (ants_sha384(msg, msg_len, digest) != ANTS_OK) {
        die("sha384");
    }
    ants_error_t e = ants_rsa_pss_verify(RSA_KAT_ARK_N,
                                         sizeof RSA_KAT_ARK_N,
                                         RSA_KAT_ARK_E,
                                         sizeof RSA_KAT_ARK_E,
                                         digest,
                                         sizeof digest,
                                         sig,
                                         sig_len);
    bool want_valid = (strcmp(result, "valid") == 0);
    if (want_valid ? (e != ANTS_OK) : (e == ANTS_OK)) {
        die("verdict does not match the compiled verifier");
    }

    if (!g_first) {
        printf(",\n");
    }
    g_first = 0;
    printf("    {\"tc_id\": %d, \"comment\": \"%s\", \"msg_sha384_hex\": \"", tc_id, comment);
    print_hex(digest, sizeof digest);
    printf("\", \"sig_hex\": \"");
    print_hex(sig, sig_len);
    printf("\", \"result\": \"%s\"}", result);
}

int main(void)
{
    uint8_t msg[2048]; /* >= ASK / ARK TBSCertificate length */
    uint8_t sig[ANTS_RSA_MAX_MODULUS_SIZE];

    if (sizeof RSA_KAT_ASK_TBS > sizeof msg || sizeof RSA_KAT_ARK_TBS > sizeof msg) {
        die("message buffer too small");
    }

    printf("{\n");
    printf("  \"primitive\": \"rsa-pss.verify (RSA-4096 RSASSA-PSS; SHA-384, MGF1-SHA-384, "
           "salt 48)\",\n");
    printf("  \"spec\":      \"RFC-0005 (TEE attestation: AMD SEV-SNP ASK/ARK certificate "
           "chain); RFC-0008 \\u00a73 (signatures)\",\n");
    printf("  \"version\":   1,\n");
    printf("  \"vendor\":    \"BearSSL @7bea48e (MIT); verdicts confirmed through "
           "ants_rsa_pss_verify\",\n");
    printf("  \"source\":    \"AMD KDS https://kdsintf.amd.com/vcek/v1/Milan/cert_chain "
           "(cert_chain sha256 "
           "22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6; ASK CN=SEV-Milan, "
           "ARK CN=ARK-Milan); both signatures independently confirmed with OpenSSL\",\n");
    printf("  \"notes\":     \"AMD signs the SEV certificate chain with RSA-4096 RSASSA-PSS "
           "(SHA-384, MGF1-SHA-384, salt length 48). Each vector is verified by the ARK public "
           "key (modulus_hex, exponent_hex, big-endian); msg_sha384_hex is the SHA-384 digest "
           "the verifier consumes (computed by the reference ants_sha384 over a DER "
           "TBSCertificate) and sig_hex is the raw signature, the same byte-length as the "
           "modulus (512). This pack covers ONLY the RSA-PSS signature, not X.509 chain "
           "validation, freshness, or revocation. result 'valid' MUST verify (ANTS_OK); "
           "'invalid' MUST be rejected. Negative cases mutate the genuine message or signature, "
           "cross signers, or truncate. Every verdict was confirmed against the compiled "
           "ants_rsa_pss_verify before emission.\",\n");
    printf("  \"modulus_hex\":  \"");
    print_hex(RSA_KAT_ARK_N, sizeof RSA_KAT_ARK_N);
    printf("\",\n");
    printf("  \"exponent_hex\": \"");
    print_hex(RSA_KAT_ARK_E, sizeof RSA_KAT_ARK_E);
    printf("\",\n");
    printf("  \"vectors\": [\n");

    /* 1: ASK signed by ARK -- intermediate by root, genuine. */
    emit_case(1,
              "genuine ASK certificate signed by ARK (RSA-4096 PSS / SHA-384)",
              RSA_KAT_ASK_TBS,
              sizeof RSA_KAT_ASK_TBS,
              RSA_KAT_ASK_SIG,
              sizeof RSA_KAT_ASK_SIG,
              "valid");

    /* 2: ARK self-signed root, genuine. */
    emit_case(2,
              "genuine ARK self-signed root (RSA-4096 PSS / SHA-384)",
              RSA_KAT_ARK_TBS,
              sizeof RSA_KAT_ARK_TBS,
              RSA_KAT_ARK_SIG,
              sizeof RSA_KAT_ARK_SIG,
              "valid");

    /* 3: a flipped message byte changes the digest, so the signature no longer matches. */
    memcpy(msg, RSA_KAT_ASK_TBS, sizeof RSA_KAT_ASK_TBS);
    msg[100] ^= 0x01;
    emit_case(3,
              "tampered message (one TBSCertificate byte flipped)",
              msg,
              sizeof RSA_KAT_ASK_TBS,
              RSA_KAT_ASK_SIG,
              sizeof RSA_KAT_ASK_SIG,
              "invalid");

    /* 4: a flipped signature byte breaks the PSS encoding. */
    memcpy(sig, RSA_KAT_ASK_SIG, sizeof RSA_KAT_ASK_SIG);
    sig[100] ^= 0x01;
    emit_case(4,
              "tampered signature (one byte flipped)",
              RSA_KAT_ASK_TBS,
              sizeof RSA_KAT_ASK_TBS,
              sig,
              sizeof RSA_KAT_ASK_SIG,
              "invalid");

    /* 5: the ARK self-signature does not verify the ASK message (wrong signer/message). */
    emit_case(5,
              "mismatched signature (ARK self-signature against the ASK message)",
              RSA_KAT_ASK_TBS,
              sizeof RSA_KAT_ASK_TBS,
              RSA_KAT_ARK_SIG,
              sizeof RSA_KAT_ARK_SIG,
              "invalid");

    /* 6: a signature shorter than the modulus is rejected by the length guard. */
    emit_case(6,
              "truncated signature (one byte short of the modulus length)",
              RSA_KAT_ASK_TBS,
              sizeof RSA_KAT_ASK_TBS,
              RSA_KAT_ASK_SIG,
              sizeof RSA_KAT_ASK_SIG - 1,
              "invalid");

    printf("\n  ]\n");
    printf("}\n");
    return 0;
}
