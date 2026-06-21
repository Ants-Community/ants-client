/*
 * test_x509.c — KAT for the X.509 certificate field extractor (x509.h).
 *
 * Parses four GENUINE vendor certificates and checks the parser against
 * independently-extracted ground truth:
 *
 *   ARK  — AMD SEV Milan root, RSA-4096, self-signed
 *   ASK  — AMD SEV Milan intermediate, RSA-4096, signed by ARK
 *   VCEK — AMD SEV leaf, EC P-384, signed by ASK
 *   PCK  — Intel SGX PCK leaf, EC P-256
 *
 * Provenance + the cross-checks that anchor authenticity are in
 * cert_kat_vectors.h. The strongest gate here is end-to-end: the leaf key the
 * parser pulls out of a cert is fed straight into the REAL attestation
 * verifier (the parser's entire reason to exist — "parse -> hand the verifier
 * the leaf"). The extracted public keys are independently cross-checked
 * against the same keys other KAT packs pinned (SNP_KAT_VCEK_PUBKEY /
 * TDX_KAT_PCK_LEAF_PUBKEY), and the RSA chain is exercised by verifying ARK's
 * self-signature and the ASK-by-ARK link with the parser's own outputs.
 */

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_tee.h"

#include "der.h" /* ANTS_DER_TAG_UTC_TIME */
#include "x509.h"

#include "cert_kat_vectors.h"
#include "snp_kat_vectors.h"
#include "tdx_kat_vectors.h"

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

/* RSA-4096: 512-byte modulus and signature. */
#define RSA4096_BYTES 512

static bool names_equal(const ants_x509_cert *a, const ants_x509_cert *b)
{
    return a->subject_len == b->issuer_len && memcmp(a->subject, b->issuer, a->subject_len) == 0;
}

static void test_ark_rsa_self_signed_root(void)
{
    ants_x509_cert ark;
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, &ark), ANTS_OK);

    CHECK(ark.key_kind == ANTS_X509_KEY_RSA);
    CHECK(ark.curve == ANTS_X509_CURVE_NONE);
    CHECK(ark.rsa_modulus_len == RSA4096_BYTES);
    /* publicExponent 65537 = 0x010001. */
    const uint8_t e_65537[] = {0x01, 0x00, 0x01};
    CHECK(ark.rsa_exponent_len == sizeof e_65537);
    CHECK(memcmp(ark.rsa_exponent, e_65537, sizeof e_65537) == 0);

    /* Self-signed: issuer Name == subject Name, byte-for-byte. */
    CHECK(ark.issuer_len == ark.subject_len &&
          memcmp(ark.issuer, ark.subject, ark.issuer_len) == 0);

    /* Validity, raw ASN.1 UTCTime (YYMMDDHHMMSSZ). */
    CHECK(ark.not_before_tag == ANTS_DER_TAG_UTC_TIME);
    CHECK(ark.not_before_len == 13 && memcmp(ark.not_before, "201022172305Z", 13) == 0);
    CHECK(ark.not_after_tag == ANTS_DER_TAG_UTC_TIME);
    CHECK(ark.not_after_len == 13 && memcmp(ark.not_after, "451022172305Z", 13) == 0);

    CHECK(ark.tbs_len > 0);
    CHECK(ark.sig_alg_oid_len > 0);
    CHECK(ark.signature_len == RSA4096_BYTES);

    /* End to end: ARK's self-signature verifies under the very key the parser
     * extracted from ARK, over the TBS the parser delimited. AMD signs with
     * RSASSA-PSS (SHA-384) — the digest the verifier consumes is SHA-384(TBS). */
    uint8_t digest[ANTS_SHA384_HASH_SIZE];
    CHECK_EQ(ants_sha384(ark.tbs, ark.tbs_len, digest), ANTS_OK);
    CHECK_EQ(ants_rsa_pss_verify(ark.rsa_modulus,
                                 ark.rsa_modulus_len,
                                 ark.rsa_exponent,
                                 ark.rsa_exponent_len,
                                 digest,
                                 ANTS_SHA384_HASH_SIZE,
                                 ark.signature,
                                 ark.signature_len),
             ANTS_OK);
}

static void test_ask_rsa_intermediate_and_chain_link(void)
{
    ants_x509_cert ark, ask;
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, &ark), ANTS_OK);
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ASK_DER, sizeof CERT_KAT_ASK_DER, &ask), ANTS_OK);

    CHECK(ask.key_kind == ANTS_X509_KEY_RSA);
    CHECK(ask.rsa_modulus_len == RSA4096_BYTES);
    CHECK(ask.signature_len == RSA4096_BYTES);

    /* Not self-signed; the issuer is ARK. */
    CHECK(!(ask.issuer_len == ask.subject_len &&
            memcmp(ask.issuer, ask.subject, ask.issuer_len) == 0));
    /* Chain link at the name level: ASK.issuer == ARK.subject, byte-for-byte —
     * exactly the equality the path validator relies on. */
    CHECK(names_equal(&ark, &ask));

    /* Chain link at the signature level: ARK's key verifies ASK's signature
     * over ASK's TBS. This is one real step of the forthcoming path walk,
     * driven entirely by parser output. */
    uint8_t digest[ANTS_SHA384_HASH_SIZE];
    CHECK_EQ(ants_sha384(ask.tbs, ask.tbs_len, digest), ANTS_OK);
    CHECK_EQ(ants_rsa_pss_verify(ark.rsa_modulus,
                                 ark.rsa_modulus_len,
                                 ark.rsa_exponent,
                                 ark.rsa_exponent_len,
                                 digest,
                                 ANTS_SHA384_HASH_SIZE,
                                 ask.signature,
                                 ask.signature_len),
             ANTS_OK);
}

static void test_vcek_ec_p384_leaf(void)
{
    ants_x509_cert ask, vcek;
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ASK_DER, sizeof CERT_KAT_ASK_DER, &ask), ANTS_OK);
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_VCEK_DER, sizeof CERT_KAT_VCEK_DER, &vcek), ANTS_OK);

    CHECK(vcek.key_kind == ANTS_X509_KEY_EC);
    CHECK(vcek.curve == ANTS_X509_CURVE_P384);
    CHECK(vcek.ec_point_len == ANTS_SNP_VCEK_PUBKEY_SIZE);
    /* The extracted point matches the VCEK key the snp-report KAT pinned. */
    CHECK(memcmp(vcek.ec_point, SNP_KAT_VCEK_PUBKEY, ANTS_SNP_VCEK_PUBKEY_SIZE) == 0);

    /* Validity is UTCTime here too. */
    CHECK(vcek.not_before_tag == ANTS_DER_TAG_UTC_TIME);
    CHECK(vcek.not_before_len == 13 && memcmp(vcek.not_before, "220924005528Z", 13) == 0);

    /* Chain link (name level): VCEK.issuer == ASK.subject. */
    CHECK(names_equal(&ask, &vcek));

    /* End to end: the leaf key the parser extracted verifies the REAL SNP
     * attestation report — the exact handoff the chain validator exists for. */
    CHECK_EQ(ants_snp_report_verify_signature(SNP_KAT_REPORT, sizeof SNP_KAT_REPORT, vcek.ec_point),
             ANTS_OK);
}

static void test_pck_ec_p256_leaf(void)
{
    ants_x509_cert pck;
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_PCK_DER, sizeof CERT_KAT_PCK_DER, &pck), ANTS_OK);

    CHECK(pck.key_kind == ANTS_X509_KEY_EC);
    CHECK(pck.curve == ANTS_X509_CURVE_P256);
    CHECK(pck.ec_point_len == ANTS_TDX_PCK_PUBKEY_SIZE);
    /* The extracted point matches the PCK leaf key the tdx-quote KAT pinned. */
    CHECK(memcmp(pck.ec_point, TDX_KAT_PCK_LEAF_PUBKEY, ANTS_TDX_PCK_PUBKEY_SIZE) == 0);

    /* Leaf, not self-signed: issuer (Platform CA) != subject (PCK cert). */
    CHECK(!(pck.issuer_len == pck.subject_len &&
            memcmp(pck.issuer, pck.subject, pck.issuer_len) == 0));

    /* End to end: the parsed PCK leaf key verifies the REAL TDX quote chain. */
    CHECK_EQ(ants_tdx_quote_verify_signature(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, pck.ec_point),
             ANTS_OK);
}

static void test_guards(void)
{
    ants_x509_cert c;
    CHECK_EQ(ants_x509_cert_parse(NULL, sizeof CERT_KAT_ARK_DER, &c), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* Empty and too-short inputs cannot hold a certificate. */
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, 0, &c), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, 1, &c), ANTS_ERROR_MALFORMED);
    /* Truncated: the outer SEQUENCE length runs past the buffer. */
    CHECK_EQ(ants_x509_cert_parse(CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER - 1, &c),
             ANTS_ERROR_MALFORMED);
}

static void test_rejects_corruption(void)
{
    ants_x509_cert c;

    /* Corrupt the outer SEQUENCE identifier (0x30 -> 0x31): not a certificate. */
    uint8_t buf[sizeof CERT_KAT_PCK_DER];
    memcpy(buf, CERT_KAT_PCK_DER, sizeof buf);
    buf[0] ^= 0x01;
    CHECK_EQ(ants_x509_cert_parse(buf, sizeof buf, &c), ANTS_ERROR_MALFORMED);

    /* A trailing byte after a complete certificate is rejected (no slack). */
    uint8_t buf2[sizeof CERT_KAT_PCK_DER + 1];
    memcpy(buf2, CERT_KAT_PCK_DER, sizeof CERT_KAT_PCK_DER);
    buf2[sizeof CERT_KAT_PCK_DER] = 0x00;
    CHECK_EQ(ants_x509_cert_parse(buf2, sizeof buf2, &c), ANTS_ERROR_MALFORMED);
}

int main(void)
{
    test_ark_rsa_self_signed_root();
    test_ask_rsa_intermediate_and_chain_link();
    test_vcek_ec_p384_leaf();
    test_pck_ec_p256_leaf();
    test_guards();
    test_rejects_corruption();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
