/*
 * test_tee.c — placeholder tests for the TEE attestation harness.
 *
 * v1.0 stub: every function returns NOT_IMPLEMENTED or the documented
 * safe default. These tests pin the contract so a future v2.x
 * implementation can't silently change it without us noticing:
 *
 *   - public-API symbols link;
 *   - stubs return the documented codes (NOT_IMPLEMENTED for generate
 *     and verify; false for is_fresh and is_revoked);
 *   - constant values (vendor IDs, default windows, weight ratios)
 *     match the spec.
 */

#include "ants_common.h"
#include "ants_tee.h"

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

static void test_verify_returns_not_implemented(void)
{
    ants_attestation_t att;
    memset(&att, 0, sizeof att);
    CHECK_EQ(ants_attestation_verify(&att), ANTS_ERROR_NOT_IMPLEMENTED);
    /* NULL also returns NOT_IMPLEMENTED (or could return INVALID_ARG;
     * but in v1.0 we don't expose an error code other than the stub
     * sentinel — that's the documented behaviour). */
    CHECK_EQ(ants_attestation_verify(NULL), ANTS_ERROR_NOT_IMPLEMENTED);
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

int main(void)
{
    test_vendor_ids_pinned();
    test_default_windows_match_rfc0005();
    test_multivendor_weight_ratios();
    test_generate_returns_not_implemented();
    test_verify_returns_not_implemented();
    test_is_fresh_returns_false();
    test_is_revoked_returns_false();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
