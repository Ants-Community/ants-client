/*
 * test_attestation.c — end-to-end KAT for ants_attestation_verify.
 *
 * Drives the full Intel TDX composition over a GENUINE quote
 * (tdx_kat_vectors.h): ants_attestation_verify extracts the embedded PCK PEM
 * chain from the quote, validates it to the PINNED Intel SGX Root CA, verifies
 * the quote's 3-link signature chain under the proven PCK leaf key, and binds
 * report_data[0:32] to the peer key. Exercises only the public ants_tee.h
 * surface (the composition is the whole point — parse + chain-validate + verify
 * + bind, no caller-supplied leaf key).
 *
 * The quote's report_data is third-party test data, so the peer key under test
 * is its low 32 bytes — what an ANTS generate side would have placed there.
 * The binding check is then a real equality test, and a mismatch is rejected.
 */

#include "ants_common.h"
#include "ants_tee.h"

#include "tdx_kat_vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

/* 2025-01-01T00:00:00Z — inside every Intel cert window (PCK 2022-2029,
 * Platform 2018-2033, Root 2018-2049). */
#define NOW_VALID ((int64_t)1735689600)
/* 2010-01-01 — before the whole Intel chain existed. */
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

int main(void)
{
    /* The peer key the genuine quote is bound to: its report_data low 32 bytes. */
    ants_tdx_quote_t q;
    CHECK_EQ(ants_tdx_quote_parse(TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, &q), ANTS_OK);
    uint8_t peer[32];
    memcpy(peer, q.report_data, 32);

    /* Positive: the full chain validates to the pinned Intel root and the quote
     * verifies under the extracted PCK leaf. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_VALID);
        CHECK_EQ(ants_attestation_verify(&att), ANTS_OK);
    }

    /* Wrong peer key: signature chain is fine, but the identity binding fails. */
    {
        uint8_t bad_peer[32];
        memcpy(bad_peer, peer, 32);
        bad_peer[0] ^= 0xFF;
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, bad_peer, NOW_VALID);
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
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
    }

    /* Issued before the certificate chain was valid: chain validity rejects. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_TOO_EARLY);
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
    }

    /* Truncated blob: bounds checks reject before any crypto. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, 100, peer, NOW_VALID);
        CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_MALFORMED);
    }

    /* Vendor whose wiring has not landed yet. */
    {
        ants_attestation_t att;
        make_att(&att, TDX_KAT_QUOTE, sizeof TDX_KAT_QUOTE, peer, NOW_VALID);
        att.vendor = ANTS_TEE_VENDOR_AMD_SEV_SNP;
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
