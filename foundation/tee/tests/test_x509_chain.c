/*
 * test_x509_chain.c — KAT for the X.509 certificate-chain path validator
 * (x509_chain.h).
 *
 * Validates two GENUINE vendor chains to their pinned self-signed roots, and —
 * the strongest gate — feeds the validated leaf key straight into the REAL
 * attestation verifier, the walk's whole reason to exist ("chain-validate ->
 * hand the verifier the leaf"):
 *
 *   AMD SEV-SNP:  VCEK (EC P-384) -> ASK -> ARK (RSA-4096 RSASSA-PSS),
 *                 pinned root ARK-Milan; the leaf then verifies the real SNP
 *                 report (SNP_KAT_REPORT).
 *   Intel TDX:    PCK (EC P-256) -> Platform CA -> Root CA (ECDSA P-256),
 *                 pinned root Intel SGX Root CA; the leaf then verifies the
 *                 real TDX quote (TDX_KAT_QUOTE).
 *
 * The AMD chain exercises the RSA-PSS link path, the Intel chain the ECDSA
 * link path. Cert provenance + cross-checks live in cert_kat_vectors.h. Beyond
 * the positives, a tamper matrix drives every rejection branch: out-of-window
 * `now`, the wrong root, a non-self-signed root, broken name chaining, a
 * corrupted signature at each link, and the argument guards.
 */

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_tee.h"

#include "der.h"
#include "x509.h"
#include "x509_chain.h"

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

/* 2025-01-01T00:00:00Z — inside every cert window on both chains (AMD: VCEK
 * 2022-09-24..2029-09-24, ASK/ARK 2020..2045; Intel: PCK 2022-09-20..
 * 2029-09-20, Platform 2018..2033, Root 2018..2049). */
#define NOW_VALID ((int64_t)1735689600)
/* 2021-01-01: before the 2022 leaf certs were issued. */
#define NOW_TOO_EARLY ((int64_t)1609459200)
/* 2030-06-01: after the 2029 leaf certs expire. */
#define NOW_TOO_LATE ((int64_t)1906502400)

/* Run the AMD chain (VCEK leaf -> ASK -> pinned ARK root). */
static ants_error_t amd_verify(const uint8_t *vcek,
                               size_t vcek_len,
                               const uint8_t *ask,
                               size_t ask_len,
                               const uint8_t *ark,
                               size_t ark_len,
                               int64_t now,
                               ants_x509_cert *leaf)
{
    const uint8_t *certs[] = {vcek, ask};
    size_t lens[] = {vcek_len, ask_len};
    return ants_x509_chain_verify(certs, lens, 2, ark, ark_len, now, leaf);
}

/* Run the Intel chain (PCK leaf -> Platform CA -> pinned Root CA). */
static ants_error_t intel_verify(const uint8_t *pck,
                                 size_t pck_len,
                                 const uint8_t *plat,
                                 size_t plat_len,
                                 const uint8_t *root,
                                 size_t root_len,
                                 int64_t now,
                                 ants_x509_cert *leaf)
{
    const uint8_t *certs[] = {pck, plat};
    size_t lens[] = {pck_len, plat_len};
    return ants_x509_chain_verify(certs, lens, 2, root, root_len, now, leaf);
}

static void test_amd_chain_valid_to_report(void)
{
    ants_x509_cert leaf;
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_ARK_DER,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_VALID,
                        &leaf),
             ANTS_OK);

    /* The validated leaf is the VCEK: EC P-384, and its key matches the one the
     * SNP KAT pinned independently. */
    CHECK(leaf.key_kind == ANTS_X509_KEY_EC && leaf.curve == ANTS_X509_CURVE_P384);
    CHECK(leaf.ec_point_len == ANTS_SNP_VCEK_PUBKEY_SIZE);
    CHECK(memcmp(leaf.ec_point, SNP_KAT_VCEK_PUBKEY, ANTS_SNP_VCEK_PUBKEY_SIZE) == 0);

    /* End to end: the key the chain just proved trusted verifies the real SNP
     * report. This is what ants_attestation_verify will compose. */
    CHECK_EQ(ants_snp_report_verify_signature(SNP_KAT_REPORT, sizeof SNP_KAT_REPORT, leaf.ec_point),
             ANTS_OK);
}

static void test_intel_chain_valid_to_quote(void)
{
    ants_x509_cert leaf;
    CHECK_EQ(intel_verify(CERT_KAT_PCK_DER,
                          sizeof CERT_KAT_PCK_DER,
                          CERT_KAT_INTEL_PLATFORM_DER,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          CERT_KAT_INTEL_ROOT_DER,
                          sizeof CERT_KAT_INTEL_ROOT_DER,
                          NOW_VALID,
                          &leaf),
             ANTS_OK);

    CHECK(leaf.key_kind == ANTS_X509_KEY_EC && leaf.curve == ANTS_X509_CURVE_P256);
    CHECK(leaf.ec_point_len == ANTS_TDX_PCK_PUBKEY_SIZE);
    CHECK(memcmp(leaf.ec_point, TDX_KAT_PCK_LEAF_PUBKEY, ANTS_TDX_PCK_PUBKEY_SIZE) == 0);

    CHECK_EQ(ants_tdx_quote_verify_signature(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, leaf.ec_point),
             ANTS_OK);
}

static void test_validity_window(void)
{
    /* Both chains' leaves are 2022..2029; before and after that window the walk
     * must reject (notBefore/notAfter enforced against the supplied `now`). */
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_ARK_DER,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_TOO_EARLY,
                        NULL),
             ANTS_ERROR_MALFORMED);
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_ARK_DER,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_TOO_LATE,
                        NULL),
             ANTS_ERROR_MALFORMED);
    CHECK_EQ(intel_verify(CERT_KAT_PCK_DER,
                          sizeof CERT_KAT_PCK_DER,
                          CERT_KAT_INTEL_PLATFORM_DER,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          CERT_KAT_INTEL_ROOT_DER,
                          sizeof CERT_KAT_INTEL_ROOT_DER,
                          NOW_TOO_LATE,
                          NULL),
             ANTS_ERROR_MALFORMED);
}

static void test_wrong_root(void)
{
    /* A real chain against the OTHER vendor's pinned root: the top
     * intermediate's issuer no longer names the root. */
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_INTEL_ROOT_DER,
                        sizeof CERT_KAT_INTEL_ROOT_DER,
                        NOW_VALID,
                        NULL),
             ANTS_ERROR_MALFORMED);
    CHECK_EQ(intel_verify(CERT_KAT_PCK_DER,
                          sizeof CERT_KAT_PCK_DER,
                          CERT_KAT_INTEL_PLATFORM_DER,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          CERT_KAT_ARK_DER,
                          sizeof CERT_KAT_ARK_DER,
                          NOW_VALID,
                          NULL),
             ANTS_ERROR_MALFORMED);
}

static void test_root_must_be_self_signed(void)
{
    /* Pin the ASK (intermediate, issuer ARK != subject SEV-Milan) as the root.
     * The leaf VCEK still name-chains to it (VCEK.issuer == ASK.subject), so
     * only the self-signed-root requirement can reject this. */
    const uint8_t *certs[] = {CERT_KAT_VCEK_DER};
    size_t lens[] = {sizeof CERT_KAT_VCEK_DER};
    CHECK_EQ(ants_x509_chain_verify(
                 certs, lens, 1, CERT_KAT_ASK_DER, sizeof CERT_KAT_ASK_DER, NOW_VALID, NULL),
             ANTS_ERROR_MALFORMED);
}

static void test_broken_name_chain(void)
{
    /* Swap leaf and intermediate: now the leaf's issuer no longer matches the
     * cert presented as its issuer. */
    const uint8_t *amd[] = {CERT_KAT_ASK_DER, CERT_KAT_VCEK_DER};
    size_t amd_lens[] = {sizeof CERT_KAT_ASK_DER, sizeof CERT_KAT_VCEK_DER};
    CHECK_EQ(ants_x509_chain_verify(
                 amd, amd_lens, 2, CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
             ANTS_ERROR_MALFORMED);

    const uint8_t *intel[] = {CERT_KAT_INTEL_PLATFORM_DER, CERT_KAT_PCK_DER};
    size_t intel_lens[] = {sizeof CERT_KAT_INTEL_PLATFORM_DER, sizeof CERT_KAT_PCK_DER};
    CHECK_EQ(ants_x509_chain_verify(intel,
                                    intel_lens,
                                    2,
                                    CERT_KAT_INTEL_ROOT_DER,
                                    sizeof CERT_KAT_INTEL_ROOT_DER,
                                    NOW_VALID,
                                    NULL),
             ANTS_ERROR_MALFORMED);
}

/* Copy `src` and flip one byte deep in its signatureValue (offset from the
 * end), so the link signature fails rather than the structure parse. */
static void corrupt_tail(const uint8_t *src, size_t n, uint8_t *dst)
{
    memcpy(dst, src, n);
    dst[n - 10] ^= 0xFF;
}

static void test_tampered_links(void)
{
    static uint8_t buf[4096];

    /* AMD: corrupt each cert in turn; every link must fail closed. */
    corrupt_tail(CERT_KAT_VCEK_DER, sizeof CERT_KAT_VCEK_DER, buf);
    CHECK_EQ(amd_verify(buf,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_ARK_DER,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_VALID,
                        NULL),
             ANTS_ERROR_MALFORMED);
    corrupt_tail(CERT_KAT_ASK_DER, sizeof CERT_KAT_ASK_DER, buf);
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        buf,
                        sizeof CERT_KAT_ASK_DER,
                        CERT_KAT_ARK_DER,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_VALID,
                        NULL),
             ANTS_ERROR_MALFORMED);
    corrupt_tail(CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, buf);
    CHECK_EQ(amd_verify(CERT_KAT_VCEK_DER,
                        sizeof CERT_KAT_VCEK_DER,
                        CERT_KAT_ASK_DER,
                        sizeof CERT_KAT_ASK_DER,
                        buf,
                        sizeof CERT_KAT_ARK_DER,
                        NOW_VALID,
                        NULL),
             ANTS_ERROR_MALFORMED);

    /* Intel: same, exercising the ECDSA link path's failure branch. */
    corrupt_tail(CERT_KAT_PCK_DER, sizeof CERT_KAT_PCK_DER, buf);
    CHECK_EQ(intel_verify(buf,
                          sizeof CERT_KAT_PCK_DER,
                          CERT_KAT_INTEL_PLATFORM_DER,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          CERT_KAT_INTEL_ROOT_DER,
                          sizeof CERT_KAT_INTEL_ROOT_DER,
                          NOW_VALID,
                          NULL),
             ANTS_ERROR_MALFORMED);
    corrupt_tail(CERT_KAT_INTEL_PLATFORM_DER, sizeof CERT_KAT_INTEL_PLATFORM_DER, buf);
    CHECK_EQ(intel_verify(CERT_KAT_PCK_DER,
                          sizeof CERT_KAT_PCK_DER,
                          buf,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          CERT_KAT_INTEL_ROOT_DER,
                          sizeof CERT_KAT_INTEL_ROOT_DER,
                          NOW_VALID,
                          NULL),
             ANTS_ERROR_MALFORMED);
    corrupt_tail(CERT_KAT_INTEL_ROOT_DER, sizeof CERT_KAT_INTEL_ROOT_DER, buf);
    CHECK_EQ(intel_verify(CERT_KAT_PCK_DER,
                          sizeof CERT_KAT_PCK_DER,
                          CERT_KAT_INTEL_PLATFORM_DER,
                          sizeof CERT_KAT_INTEL_PLATFORM_DER,
                          buf,
                          sizeof CERT_KAT_INTEL_ROOT_DER,
                          NOW_VALID,
                          NULL),
             ANTS_ERROR_MALFORMED);
}

static void test_arg_guards(void)
{
    const uint8_t *certs[] = {CERT_KAT_VCEK_DER, CERT_KAT_ASK_DER};
    size_t lens[] = {sizeof CERT_KAT_VCEK_DER, sizeof CERT_KAT_ASK_DER};

    CHECK_EQ(ants_x509_chain_verify(
                 certs, lens, 0, CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_x509_chain_verify(
                 NULL, lens, 2, CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_x509_chain_verify(
                 certs, NULL, 2, CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_x509_chain_verify(certs, lens, 2, NULL, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
             ANTS_ERROR_INVALID_ARG);

    /* A NULL entry inside the chain. */
    const uint8_t *with_null[] = {NULL, CERT_KAT_ASK_DER};
    size_t null_lens[] = {16, sizeof CERT_KAT_ASK_DER};
    CHECK_EQ(
        ants_x509_chain_verify(
            with_null, null_lens, 2, CERT_KAT_ARK_DER, sizeof CERT_KAT_ARK_DER, NOW_VALID, NULL),
        ANTS_ERROR_INVALID_ARG);

    /* Over the chain-length cap. */
    const uint8_t *many[ANTS_X509_CHAIN_MAX + 1];
    size_t many_lens[ANTS_X509_CHAIN_MAX + 1];
    for (size_t i = 0; i < ANTS_X509_CHAIN_MAX + 1; i++) {
        many[i] = CERT_KAT_VCEK_DER;
        many_lens[i] = sizeof CERT_KAT_VCEK_DER;
    }
    CHECK_EQ(ants_x509_chain_verify(many,
                                    many_lens,
                                    ANTS_X509_CHAIN_MAX + 1,
                                    CERT_KAT_ARK_DER,
                                    sizeof CERT_KAT_ARK_DER,
                                    NOW_VALID,
                                    NULL),
             ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_amd_chain_valid_to_report();
    test_intel_chain_valid_to_quote();
    test_validity_window();
    test_wrong_root();
    test_root_must_be_self_signed();
    test_broken_name_chain();
    test_tampered_links();
    test_arg_guards();

    if (failures == 0) {
        printf("test_x509_chain: all KATs passed\n");
        return 0;
    }
    fprintf(stderr, "test_x509_chain: %d check(s) FAILED\n", failures);
    return 1;
}
