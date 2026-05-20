/*
 * test_crypto.c — placeholder tests for the crypto primitives library.
 *
 * The implementation is stubbed (every primitive returns
 * ANTS_ERROR_NOT_IMPLEMENTED). These tests validate:
 *
 *   - that the public-API symbols link;
 *   - that every stub returns NOT_IMPLEMENTED rather than crashing or
 *     returning a misleading success.
 *
 * Each primitive PR (BLAKE3 implementation, Ed25519, BLS, ECVRF) will
 * replace its corresponding placeholder with vector-driven tests against
 * the ants-test-vectors pack.
 */

#include "ants_common.h"
#include "ants_crypto.h"

#include <stdbool.h>
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

static void test_blake3_stubs(void)
{
    uint8_t data[1] = {0};
    uint8_t out[ANTS_BLAKE3_HASH_SIZE];
    ants_blake3_ctx_t ctx;

    CHECK_EQ(ants_blake3_hash(data, sizeof data, out), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_blake3_derive_key("ants-v1-test", data, sizeof data, out),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_blake3_init(&ctx), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_blake3_init_derive(&ctx, "ants-v1-test"), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_blake3_update(&ctx, data, sizeof data), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_blake3_final(&ctx, out), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_ed25519_stubs(void)
{
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE] = {0};
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE] = {0};
    uint8_t sig[ANTS_ED25519_SIG_SIZE] = {0};
    uint8_t msg[1] = {0};

    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_ed25519_sign(priv, msg, sizeof msg, sig), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_ed25519_verify(pub, msg, sizeof msg, sig), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_bls_stubs(void)
{
    uint8_t priv[ANTS_BLS_PRIVKEY_SIZE] = {0};
    uint8_t pub[ANTS_BLS_PUBKEY_SIZE] = {0};
    uint8_t sig[ANTS_BLS_SIG_SIZE] = {0};
    uint8_t msg[1] = {0};
    uint8_t sigs[2][ANTS_BLS_SIG_SIZE] = {{0}};
    uint8_t pubs[2][ANTS_BLS_PUBKEY_SIZE] = {{0}};

    CHECK_EQ(ants_bls_pubkey_from_priv(priv, pub), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bls_sign(priv, msg, sizeof msg, sig), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bls_verify(pub, msg, sizeof msg, sig), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bls_aggregate(sigs, 2, sig), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 2, msg, sizeof msg, sig), ANTS_ERROR_NOT_IMPLEMENTED);
}

static void test_vrf_stubs(void)
{
    uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE] = {0};
    uint8_t pk[ANTS_ED25519_PUBKEY_SIZE] = {0};
    uint8_t alpha[1] = {0};
    uint8_t proof[ANTS_VRF_PROOF_SIZE] = {0};
    uint8_t beta[ANTS_VRF_OUTPUT_SIZE] = {0};

    CHECK_EQ(ants_vrf_prove(sk, alpha, sizeof alpha, proof), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_vrf_verify(pk, alpha, sizeof alpha, proof, beta), ANTS_ERROR_NOT_IMPLEMENTED);
}

int main(void)
{
    test_blake3_stubs();
    test_ed25519_stubs();
    test_bls_stubs();
    test_vrf_stubs();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
