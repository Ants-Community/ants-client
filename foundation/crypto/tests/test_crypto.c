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

/* Helper: convert a hex string to bytes. Returns the number of bytes
 * written. */
static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_cap) {
        return 0;
    }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (uint8_t)byte;
    }
    return n / 2;
}

/* Helper: check that `actual` (32 bytes) matches `expected_hex`. */
static void check_hash(const char *what, const uint8_t actual[32], const char *expected_hex)
{
    uint8_t expected[32];
    size_t n = hex_to_bytes(expected_hex, expected, sizeof expected);
    if (n != 32) {
        failures++;
        fprintf(stderr, "FAIL %s: bad expected hex\n", what);
        return;
    }
    if (memcmp(actual, expected, 32) != 0) {
        failures++;
        fprintf(stderr, "FAIL %s\n  expected: %s\n  got:     ", what, expected_hex);
        for (size_t i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", actual[i]);
        }
        fprintf(stderr, "\n");
    }
}

/* ------------------------------------------------------------------------ */
/* BLAKE3 — known-answer tests against upstream test_vectors.json subset.   */
/* ------------------------------------------------------------------------ */

static void test_blake3_rejects_invalid_args(void)
{
    uint8_t out[ANTS_BLAKE3_HASH_SIZE];
    ants_blake3_ctx_t ctx;
    CHECK_EQ(ants_blake3_hash(NULL, 1, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_hash((const uint8_t *)"x", 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_derive_key(NULL, NULL, 0, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_derive_key("ctx", NULL, 1, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_init(NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_init_derive(&ctx, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_update(NULL, (const uint8_t *)"x", 1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_blake3_final(&ctx, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_blake3_empty(void)
{
    uint8_t out[ANTS_BLAKE3_HASH_SIZE];
    CHECK_EQ(ants_blake3_hash(NULL, 0, out), ANTS_OK);
    /* BLAKE3 of empty input. From upstream test_vectors.json. */
    check_hash(
        "blake3('')", out, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

static void test_blake3_known_inputs(void)
{
    uint8_t out[ANTS_BLAKE3_HASH_SIZE];

    /* "IETF" — 4 bytes (0x49 0x45 0x54 0x46). Value pinned against
     * vendored BLAKE3 v1.8.5 output; cross-verify against upstream
     * test_vectors.json when the ants-test-vectors BLAKE3 pack is
     * regenerated. */
    CHECK_EQ(ants_blake3_hash((const uint8_t *)"IETF", 4, out), ANTS_OK);
    check_hash(
        "blake3('IETF')", out, "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2");

    /* 1-byte input 0x00 — boundary case (block-aligned, single byte).
     * Value pinned against vendored BLAKE3 v1.8.5 output (self-
     * consistency check; cross-verify against upstream
     * test_vectors.json when ants-test-vectors gets the BLAKE3 pack
     * regenerated from upstream). */
    const uint8_t one_zero[1] = {0x00};
    CHECK_EQ(ants_blake3_hash(one_zero, 1, out), ANTS_OK);
    check_hash(
        "blake3(0x00)", out, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");

    /* 64-byte input pattern 0,1,2,...,63 (mod 251) — exactly one BLAKE3
     * block. The 0..63 mod 251 pattern is the upstream test vector
     * input convention. Value pinned against vendored BLAKE3 v1.8.5
     * output. */
    uint8_t pattern64[64];
    for (size_t i = 0; i < 64; i++) {
        pattern64[i] = (uint8_t)(i % 251);
    }
    CHECK_EQ(ants_blake3_hash(pattern64, sizeof pattern64, out), ANTS_OK);
    check_hash("blake3(0..63 mod 251)",
               out,
               "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98");
}

static void test_blake3_derive_key(void)
{
    uint8_t out[ANTS_BLAKE3_HASH_SIZE];
    /* Empty key_material with a small context string. The output is
     * deterministic but we don't pin a known answer here — we just
     * verify the call returns OK and produces a non-zero output. The
     * known-answer pinning happens once the ants-test-vectors pack is
     * regenerated from the upstream BLAKE3 vectors. */
    CHECK_EQ(ants_blake3_derive_key("ants-v1-test", NULL, 0, out), ANTS_OK);
    /* Output should not be all zeros. */
    bool all_zero = true;
    for (size_t i = 0; i < sizeof out; i++) {
        if (out[i] != 0) {
            all_zero = false;
            break;
        }
    }
    CHECK(!all_zero);
}

static void test_blake3_streaming_matches_one_shot(void)
{
    /* Feed 100 bytes via update() one byte at a time; verify the
     * final matches the one-shot hash. */
    uint8_t input[100];
    for (size_t i = 0; i < sizeof input; i++) {
        input[i] = (uint8_t)i;
    }
    uint8_t one_shot[ANTS_BLAKE3_HASH_SIZE];
    uint8_t streamed[ANTS_BLAKE3_HASH_SIZE];

    CHECK_EQ(ants_blake3_hash(input, sizeof input, one_shot), ANTS_OK);

    ants_blake3_ctx_t ctx;
    CHECK_EQ(ants_blake3_init(&ctx), ANTS_OK);
    for (size_t i = 0; i < sizeof input; i++) {
        CHECK_EQ(ants_blake3_update(&ctx, &input[i], 1), ANTS_OK);
    }
    CHECK_EQ(ants_blake3_final(&ctx, streamed), ANTS_OK);

    CHECK(memcmp(one_shot, streamed, ANTS_BLAKE3_HASH_SIZE) == 0);
}

/* RFC 8032 §7.1 TEST 1: empty message */
static const char *RFC8032_T1_SEED =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static const char *RFC8032_T1_PUB =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char *RFC8032_T1_SIG =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
    "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

/* RFC 8032 §7.1 TEST 2: single-byte message 0x72 */
static const char *RFC8032_T2_SEED =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
static const char *RFC8032_T2_PUB =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
static const char *RFC8032_T2_MSG = "72";
static const char *RFC8032_T2_SIG =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

static void test_ed25519_rejects_invalid_args(void)
{
    uint8_t buf[64];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(NULL, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(buf, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_sign(NULL, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_sign(buf, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_sign(buf, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_verify(NULL, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_verify(buf, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ed25519_verify(buf, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_ed25519_rfc8032_test1_empty(void)
{
    uint8_t seed[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t expected_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t expected_sig[ANTS_ED25519_SIG_SIZE];
    CHECK(hex_to_bytes(RFC8032_T1_SEED, seed, sizeof seed) == 32);
    CHECK(hex_to_bytes(RFC8032_T1_PUB, expected_pub, sizeof expected_pub) == 32);
    CHECK(hex_to_bytes(RFC8032_T1_SIG, expected_sig, sizeof expected_sig) == 64);

    /* Derive pubkey from seed; must match expected. */
    uint8_t derived_pub[ANTS_ED25519_PUBKEY_SIZE];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(seed, derived_pub), ANTS_OK);
    CHECK(memcmp(derived_pub, expected_pub, ANTS_ED25519_PUBKEY_SIZE) == 0);

    /* Sign empty message; must produce expected signature. */
    uint8_t sig[ANTS_ED25519_SIG_SIZE];
    CHECK_EQ(ants_ed25519_sign(seed, NULL, 0, sig), ANTS_OK);
    CHECK(memcmp(sig, expected_sig, ANTS_ED25519_SIG_SIZE) == 0);

    /* Verify both expected and freshly-signed signatures against the
     * expected pubkey. */
    CHECK_EQ(ants_ed25519_verify(expected_pub, NULL, 0, expected_sig), ANTS_OK);
    CHECK_EQ(ants_ed25519_verify(expected_pub, NULL, 0, sig), ANTS_OK);
}

static void test_ed25519_rfc8032_test2_single_byte(void)
{
    uint8_t seed[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t expected_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t expected_sig[ANTS_ED25519_SIG_SIZE];
    uint8_t msg[1];
    CHECK(hex_to_bytes(RFC8032_T2_SEED, seed, sizeof seed) == 32);
    CHECK(hex_to_bytes(RFC8032_T2_PUB, expected_pub, sizeof expected_pub) == 32);
    CHECK(hex_to_bytes(RFC8032_T2_SIG, expected_sig, sizeof expected_sig) == 64);
    CHECK(hex_to_bytes(RFC8032_T2_MSG, msg, sizeof msg) == 1);

    uint8_t derived_pub[ANTS_ED25519_PUBKEY_SIZE];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(seed, derived_pub), ANTS_OK);
    CHECK(memcmp(derived_pub, expected_pub, ANTS_ED25519_PUBKEY_SIZE) == 0);

    uint8_t sig[ANTS_ED25519_SIG_SIZE];
    CHECK_EQ(ants_ed25519_sign(seed, msg, sizeof msg, sig), ANTS_OK);
    CHECK(memcmp(sig, expected_sig, ANTS_ED25519_SIG_SIZE) == 0);

    CHECK_EQ(ants_ed25519_verify(expected_pub, msg, sizeof msg, expected_sig), ANTS_OK);
}

static void test_ed25519_verify_rejects_tampered(void)
{
    uint8_t seed[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t sig[ANTS_ED25519_SIG_SIZE];
    const uint8_t msg[] = "ANTS test message";
    CHECK(hex_to_bytes(RFC8032_T1_SEED, seed, sizeof seed) == 32);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(seed, pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(seed, msg, sizeof msg - 1, sig), ANTS_OK);

    /* Untampered: verify OK. */
    CHECK_EQ(ants_ed25519_verify(pub, msg, sizeof msg - 1, sig), ANTS_OK);

    /* Tamper the signature: verify must fail with MALFORMED. */
    uint8_t bad_sig[ANTS_ED25519_SIG_SIZE];
    memcpy(bad_sig, sig, sizeof bad_sig);
    bad_sig[0] ^= 0x01;
    CHECK_EQ(ants_ed25519_verify(pub, msg, sizeof msg - 1, bad_sig), ANTS_ERROR_MALFORMED);

    /* Tamper the message: verify must fail. */
    uint8_t bad_msg[sizeof msg - 1];
    memcpy(bad_msg, msg, sizeof bad_msg);
    bad_msg[0] ^= 0x01;
    CHECK_EQ(ants_ed25519_verify(pub, bad_msg, sizeof bad_msg, sig), ANTS_ERROR_MALFORMED);

    /* Tamper the public key: verify must fail. */
    uint8_t bad_pub[ANTS_ED25519_PUBKEY_SIZE];
    memcpy(bad_pub, pub, sizeof bad_pub);
    bad_pub[0] ^= 0x01;
    CHECK_EQ(ants_ed25519_verify(bad_pub, msg, sizeof msg - 1, sig), ANTS_ERROR_MALFORMED);
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
    test_blake3_rejects_invalid_args();
    test_blake3_empty();
    test_blake3_known_inputs();
    test_blake3_derive_key();
    test_blake3_streaming_matches_one_shot();

    test_ed25519_rejects_invalid_args();
    test_ed25519_rfc8032_test1_empty();
    test_ed25519_rfc8032_test2_single_byte();
    test_ed25519_verify_rejects_tampered();

    test_bls_stubs();
    test_vrf_stubs();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
