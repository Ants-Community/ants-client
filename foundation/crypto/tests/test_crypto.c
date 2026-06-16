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

/* Helper: check that `actual` (`len` bytes, len <= 64) matches `expected_hex`. */
static void
check_hash_n(const char *what, const uint8_t *actual, size_t len, const char *expected_hex)
{
    uint8_t expected[64];
    if (len > sizeof expected) {
        failures++;
        fprintf(stderr, "FAIL %s: digest too large\n", what);
        return;
    }
    size_t n = hex_to_bytes(expected_hex, expected, sizeof expected);
    if (n != len) {
        failures++;
        fprintf(stderr, "FAIL %s: bad expected hex\n", what);
        return;
    }
    if (memcmp(actual, expected, len) != 0) {
        failures++;
        fprintf(stderr, "FAIL %s\n  expected: %s\n  got:     ", what, expected_hex);
        for (size_t i = 0; i < len; i++) {
            fprintf(stderr, "%02x", actual[i]);
        }
        fprintf(stderr, "\n");
    }
}

/* Helper: check that `actual` (32 bytes) matches `expected_hex`. */
static void check_hash(const char *what, const uint8_t actual[32], const char *expected_hex)
{
    check_hash_n(what, actual, 32, expected_hex);
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

static void test_sha256_rejects_invalid_args(void)
{
    uint8_t out[ANTS_SHA256_HASH_SIZE];
    CHECK_EQ(ants_sha256(NULL, 1, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_sha256((const uint8_t *)"x", 1, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_sha256_known_inputs(void)
{
    uint8_t out[ANTS_SHA256_HASH_SIZE];

    /* FIPS 180 known answers; every value below cross-checked against
     * two independent implementations (macOS shasum -a 256 and Python
     * hashlib, 2026-06-11) rather than copied from one source. */
    CHECK_EQ(ants_sha256(NULL, 0, out), ANTS_OK);
    check_hash(
        "sha256('')", out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    CHECK_EQ(ants_sha256((const uint8_t *)"abc", 3, out), ANTS_OK);
    check_hash(
        "sha256('abc')", out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /* 104-byte pattern byte[i] = (i*7 + 3) mod 256 — crosses one
     * 64-byte SHA-256 block boundary. Same two references. */
    uint8_t pattern[104];
    for (size_t i = 0; i < sizeof pattern; i++) {
        pattern[i] = (uint8_t)(i * 7 + 3);
    }
    CHECK_EQ(ants_sha256(pattern, sizeof pattern, out), ANTS_OK);
    check_hash("sha256(pattern 104B)",
               out,
               "5af877de0ea99d70bd0a547c967dbecd4525d6bba9ab2917d54d6aa742874687");
}

static void test_sha512_rejects_invalid_args(void)
{
    uint8_t out[ANTS_SHA512_HASH_SIZE];
    CHECK_EQ(ants_sha512(NULL, 1, out), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_sha512((const uint8_t *)"x", 1, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_sha512_known_inputs(void)
{
    uint8_t out[ANTS_SHA512_HASH_SIZE];

    /* FIPS 180-4 known answers; every value below cross-checked against
     * two independent implementations (macOS shasum -a 512 and Python
     * hashlib, 2026-06-16) rather than copied from one source. */
    CHECK_EQ(ants_sha512(NULL, 0, out), ANTS_OK);
    check_hash_n("sha512('')",
                 out,
                 ANTS_SHA512_HASH_SIZE,
                 "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                 "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    CHECK_EQ(ants_sha512((const uint8_t *)"abc", 3, out), ANTS_OK);
    check_hash_n("sha512('abc')",
                 out,
                 ANTS_SHA512_HASH_SIZE,
                 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    /* 200-byte pattern byte[i] = (i*7 + 3) mod 256 — crosses one
     * 128-byte SHA-512 block boundary. Same two references. */
    uint8_t pattern[200];
    for (size_t i = 0; i < sizeof pattern; i++) {
        pattern[i] = (uint8_t)(i * 7 + 3);
    }
    CHECK_EQ(ants_sha512(pattern, sizeof pattern, out), ANTS_OK);
    check_hash_n("sha512(pattern 200B)",
                 out,
                 ANTS_SHA512_HASH_SIZE,
                 "cca3c0276046ef9f2897bdfc3ec330f77f4959914b1462bd581b232ddb3e9aa9"
                 "8acf5f5a2b21c7f49d2e43721daa61a2b5cee6af6052dfeb766e66ddb0d1719c");
}

/* drand default chain (scheme pedersen-bls-chained, chain hash
 * 8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce),
 * round 1000, fetched from api.drand.sh on 2026-06-11. */
static const char *DRAND_R1000_SIG =
    "99bf96de133c3d3937293cfca10c8152b18ab2d034ccecf115658db324d2edc0"
    "0a16a2044cd04a8a38e2a307e5ecff3511315be8d282079faf24098f283e0ed2"
    "c199663b334d2e84c55c032fe469b212c5c2087ebb83a5b25155c3283f5b79ac";
static const char *DRAND_R1000_RANDOMNESS =
    "a40d3e0e7e3c71f28b7da2fd339f47f0bcf10910309f5253d7c323ec8cea3212";

static void test_sha256_drand_randomness(void)
{
    /* Real-world vector: a drand round's published randomness is
     * defined as SHA-256(signature) — the relation Component #8's
     * beacon verification (RFC-0008 §4.2) relies on. The signature is
     * a 96-byte BLS G2 point. */
    uint8_t sig[96];
    CHECK(hex_to_bytes(DRAND_R1000_SIG, sig, sizeof sig) == 96);
    uint8_t out[ANTS_SHA256_HASH_SIZE];
    CHECK_EQ(ants_sha256(sig, sizeof sig, out), ANTS_OK);
    check_hash("sha256(drand round-1000 sig)", out, DRAND_R1000_RANDOMNESS);
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

/* ------------------------------------------------------------------------ */
/* BLS12-381 — vector-driven tests against IETF BLS signature draft v5 and  */
/* round-trip self-consistency.                                             */
/* ------------------------------------------------------------------------ */

/*
 * Helper SK = scalar 1, encoded big-endian. Per BLS draft §2.3 the
 * scalar 1 is a valid secret key (in [1, r-1]). Its public key is the
 * G1 generator, which has a well-known compressed encoding.
 */
static const char *BLS_SK_ONE_HEX =
    "0000000000000000000000000000000000000000000000000000000000000001";

/* G1 generator compressed (Zcash serialization). The leading 0x97
 * encodes: bit 7 = compressed flag (1), bit 6 = infinity flag (0),
 * bit 5 = y-sign (1 here for the generator with positive-y choice as
 * defined in draft-irtf-cfrg-pairing-friendly-curves §4.2.1). The
 * remaining bytes are the x-coordinate of the G1 generator. */
static const char *BLS_PK_G1_GENERATOR_HEX =
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c5"
    "5e83ff97a1aeffb3af00adb22c6bb";

static void test_bls_rejects_invalid_args(void)
{
    uint8_t buf[ANTS_BLS_SIG_SIZE];
    /* Single-element arrays whose addresses match the
     * pointer-to-array parameter types of aggregate / verify_aggregate.
     * We don't care what they contain — only the n=0 and NULL-msg
     * cases reach the body; any non-NULL pointer is accepted by the
     * argument checks. */
    uint8_t sigs[1][ANTS_BLS_SIG_SIZE] = {{0}};
    uint8_t pubs[1][ANTS_BLS_PUBKEY_SIZE] = {{0}};

    CHECK_EQ(ants_bls_pubkey_from_priv(NULL, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_pubkey_from_priv(buf, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_sign(NULL, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_sign(buf, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_sign(buf, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify(NULL, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify(buf, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify(buf, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_aggregate(NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_aggregate(sigs, 0, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_aggregate(sigs, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify_aggregate(NULL, 1, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 0, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 1, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 1, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
}

/* SK = 1 derives PK = G1 generator. This is a fixed point of the
 * BLS12-381 curve definition and a universal cross-implementation
 * check: every spec-conformant implementation MUST produce the same
 * bytes for the G1 generator's compressed encoding. */
static void test_bls_g1_generator(void)
{
    uint8_t sk[ANTS_BLS_PRIVKEY_SIZE];
    uint8_t expected_pk[ANTS_BLS_PUBKEY_SIZE];
    uint8_t pk[ANTS_BLS_PUBKEY_SIZE];
    CHECK(hex_to_bytes(BLS_SK_ONE_HEX, sk, sizeof sk) == ANTS_BLS_PRIVKEY_SIZE);
    CHECK(hex_to_bytes(BLS_PK_G1_GENERATOR_HEX, expected_pk, sizeof expected_pk) ==
          ANTS_BLS_PUBKEY_SIZE);
    CHECK_EQ(ants_bls_pubkey_from_priv(sk, pk), ANTS_OK);
    CHECK(memcmp(pk, expected_pk, ANTS_BLS_PUBKEY_SIZE) == 0);
}

/* Scalar 0 is NOT a valid secret key (blst_sk_check rejects it; the
 * BLS spec requires SK in [1, r-1]). The wrapper must surface this as
 * MALFORMED rather than computing the identity point. */
static void test_bls_rejects_zero_sk(void)
{
    uint8_t sk[ANTS_BLS_PRIVKEY_SIZE] = {0};
    uint8_t pk[ANTS_BLS_PUBKEY_SIZE];
    uint8_t sig[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_pubkey_from_priv(sk, pk), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_bls_sign(sk, (const uint8_t *)"x", 1, sig), ANTS_ERROR_MALFORMED);
}

static void test_bls_sign_verify_roundtrip(void)
{
    /* Three distinct secret keys (SK=1, SK=2, SK=3). */
    uint8_t sk1[ANTS_BLS_PRIVKEY_SIZE] = {0};
    uint8_t sk2[ANTS_BLS_PRIVKEY_SIZE] = {0};
    uint8_t sk3[ANTS_BLS_PRIVKEY_SIZE] = {0};
    sk1[31] = 1;
    sk2[31] = 2;
    sk3[31] = 3;

    uint8_t pk1[ANTS_BLS_PUBKEY_SIZE];
    uint8_t pk2[ANTS_BLS_PUBKEY_SIZE];
    uint8_t pk3[ANTS_BLS_PUBKEY_SIZE];
    CHECK_EQ(ants_bls_pubkey_from_priv(sk1, pk1), ANTS_OK);
    CHECK_EQ(ants_bls_pubkey_from_priv(sk2, pk2), ANTS_OK);
    CHECK_EQ(ants_bls_pubkey_from_priv(sk3, pk3), ANTS_OK);

    /* Distinct SK ⇒ distinct PK. */
    CHECK(memcmp(pk1, pk2, ANTS_BLS_PUBKEY_SIZE) != 0);
    CHECK(memcmp(pk1, pk3, ANTS_BLS_PUBKEY_SIZE) != 0);
    CHECK(memcmp(pk2, pk3, ANTS_BLS_PUBKEY_SIZE) != 0);

    const uint8_t msg[] = "ants L2 block hash";
    uint8_t sig1[ANTS_BLS_SIG_SIZE];
    uint8_t sig2[ANTS_BLS_SIG_SIZE];
    uint8_t sig3[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_sign(sk1, msg, sizeof msg - 1, sig1), ANTS_OK);
    CHECK_EQ(ants_bls_sign(sk2, msg, sizeof msg - 1, sig2), ANTS_OK);
    CHECK_EQ(ants_bls_sign(sk3, msg, sizeof msg - 1, sig3), ANTS_OK);

    /* Each sig verifies against its own pk. */
    CHECK_EQ(ants_bls_verify(pk1, msg, sizeof msg - 1, sig1), ANTS_OK);
    CHECK_EQ(ants_bls_verify(pk2, msg, sizeof msg - 1, sig2), ANTS_OK);
    CHECK_EQ(ants_bls_verify(pk3, msg, sizeof msg - 1, sig3), ANTS_OK);

    /* Cross-verification fails: sig1 against pk2, etc. */
    CHECK_EQ(ants_bls_verify(pk2, msg, sizeof msg - 1, sig1), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_bls_verify(pk1, msg, sizeof msg - 1, sig2), ANTS_ERROR_MALFORMED);

    /* Verify rejects tampered signature. */
    uint8_t bad_sig[ANTS_BLS_SIG_SIZE];
    memcpy(bad_sig, sig1, sizeof bad_sig);
    bad_sig[ANTS_BLS_SIG_SIZE - 1] ^= 0x01;
    CHECK_EQ(ants_bls_verify(pk1, msg, sizeof msg - 1, bad_sig), ANTS_ERROR_MALFORMED);

    /* Verify rejects tampered message. */
    uint8_t bad_msg[sizeof msg - 1];
    memcpy(bad_msg, msg, sizeof bad_msg);
    bad_msg[0] ^= 0x01;
    CHECK_EQ(ants_bls_verify(pk1, bad_msg, sizeof bad_msg, sig1), ANTS_ERROR_MALFORMED);

    /* Aggregate the three signatures (all over the same message), then
     * FastAggregateVerify against the three public keys. This is the
     * L2 PoUH committee-signature path of RFC-0008 §3.3. */
    uint8_t sigs[3][ANTS_BLS_SIG_SIZE];
    memcpy(sigs[0], sig1, ANTS_BLS_SIG_SIZE);
    memcpy(sigs[1], sig2, ANTS_BLS_SIG_SIZE);
    memcpy(sigs[2], sig3, ANTS_BLS_SIG_SIZE);
    uint8_t agg[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_aggregate(sigs, 3, agg), ANTS_OK);

    uint8_t pubs[3][ANTS_BLS_PUBKEY_SIZE];
    memcpy(pubs[0], pk1, ANTS_BLS_PUBKEY_SIZE);
    memcpy(pubs[1], pk2, ANTS_BLS_PUBKEY_SIZE);
    memcpy(pubs[2], pk3, ANTS_BLS_PUBKEY_SIZE);
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 3, msg, sizeof msg - 1, agg), ANTS_OK);

    /* Aggregate of just sig1 must equal sig1 itself (since the
     * accumulator is initialised by decompressing sig1 alone). The
     * compressed encoding is unique for points in G2, so the bytes
     * match. */
    uint8_t agg_single[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_aggregate(sigs, 1, agg_single), ANTS_OK);
    CHECK(memcmp(agg_single, sig1, ANTS_BLS_SIG_SIZE) == 0);

    /* Tamper one of the pubkeys: aggregate-verify must fail. */
    uint8_t bad_pubs[3][ANTS_BLS_PUBKEY_SIZE];
    memcpy(bad_pubs, pubs, sizeof bad_pubs);
    /* Flipping a coordinate bit yields an off-curve point ⇒
     * uncompress fails ⇒ MALFORMED. */
    bad_pubs[0][1] ^= 0x01;
    CHECK_EQ(ants_bls_verify_aggregate(bad_pubs, 3, msg, sizeof msg - 1, agg),
             ANTS_ERROR_MALFORMED);
}

/* Aggregate verification with the WRONG message must fail. */
static void test_bls_aggregate_wrong_message_fails(void)
{
    uint8_t sk[ANTS_BLS_PRIVKEY_SIZE] = {0};
    sk[31] = 7;
    uint8_t pk[ANTS_BLS_PUBKEY_SIZE];
    uint8_t sig[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_pubkey_from_priv(sk, pk), ANTS_OK);
    CHECK_EQ(ants_bls_sign(sk, (const uint8_t *)"msg-A", 5, sig), ANTS_OK);

    uint8_t pubs[1][ANTS_BLS_PUBKEY_SIZE];
    memcpy(pubs[0], pk, ANTS_BLS_PUBKEY_SIZE);
    uint8_t sigs[1][ANTS_BLS_SIG_SIZE];
    memcpy(sigs[0], sig, ANTS_BLS_SIG_SIZE);
    uint8_t agg[ANTS_BLS_SIG_SIZE];
    CHECK_EQ(ants_bls_aggregate(sigs, 1, agg), ANTS_OK);

    /* Right message: OK. */
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 1, (const uint8_t *)"msg-A", 5, agg), ANTS_OK);
    /* Wrong message: MALFORMED. */
    CHECK_EQ(ants_bls_verify_aggregate(pubs, 1, (const uint8_t *)"msg-B", 5, agg),
             ANTS_ERROR_MALFORMED);
}

/* ------------------------------------------------------------------------ */
/* ECVRF-EDWARDS25519-SHA512-ELL2 — RFC 9381 §B.4 reference vectors +       */
/* round-trip + tamper-detection. SK/PK pairs are inherited from RFC 8032   */
/* §7.1 (TEST 1/2/3); pi and beta are the Examples 19/20/21 outputs of     */
/* RFC 9381 §B.4 (also reproducing H, x, k, U, V intermediates which we    */
/* don't expose, but the published pi/beta pin the whole construction).    */
/* ------------------------------------------------------------------------ */

/* RFC 9381 §B.4 Example 19 — alpha = "". */
static const char *VRF_T1_SK = "9d61b19deffd5a60ba844af492ec2cc4"
                               "4449c5697b326919703bac031cae7f60";
static const char *VRF_T1_PK = "d75a980182b10ab7d54bfed3c964073a"
                               "0ee172f3daa62325af021a68f707511a";
static const char *VRF_T1_PI = "7d9c633ffeee27349264cf5c667579fc"
                               "583b4bda63ab71d001f89c10003ab46f"
                               "14adf9a3cd8b8412d9038531e865c341"
                               "cafa73589b023d14311c331a9ad15ff2"
                               "fb37831e00f0acaa6d73bc9997b06501";
static const char *VRF_T1_BETA = "9d574bf9b8302ec0fc1e21c3ec536826"
                                 "9527b87b462ce36dab2d14ccf80c53cc"
                                 "cf6758f058c5b1c856b116388152bbe5"
                                 "09ee3b9ecfe63d93c3b4346c1fbc6c54";

/* RFC 9381 §B.4 Example 20 — alpha = 0x72. */
static const char *VRF_T2_SK = "4ccd089b28ff96da9db6c346ec114e0f"
                               "5b8a319f35aba624da8cf6ed4fb8a6fb";
static const char *VRF_T2_PK = "3d4017c3e843895a92b70aa74d1b7ebc"
                               "9c982ccf2ec4968cc0cd55f12af4660c";
static const char *VRF_T2_ALPHA_HEX = "72";
static const char *VRF_T2_PI = "47b327393ff2dd81336f8a2ef1033911"
                               "2401253b3c714eeda879f12c509072ef"
                               "055b48372bb82efbdce8e10c8cb9a2f9"
                               "d60e93908f93df1623ad78a86a028d6b"
                               "c064dbfc75a6a57379ef855dc6733801";
static const char *VRF_T2_BETA = "38561d6b77b71d30eb97a062168ae12b"
                                 "667ce5c28caccdf76bc88e093e463598"
                                 "7cd96814ce55b4689b3dd2947f80e59a"
                                 "ac7b7675f8083865b46c89b2ce9cc735";

/* RFC 9381 §B.4 Example 21 — alpha = 0xaf82. */
static const char *VRF_T3_SK = "c5aa8df43f9f837bedb7442f31dcb7b1"
                               "66d38535076f094b85ce3a2e0b4458f7";
static const char *VRF_T3_PK = "fc51cd8e6218a1a38da47ed00230f058"
                               "0816ed13ba3303ac5deb911548908025";
static const char *VRF_T3_ALPHA_HEX = "af82";
static const char *VRF_T3_PI = "926e895d308f5e328e7aa159c06eddbe"
                               "56d06846abf5d98c2512235eaa57fdce"
                               "35b46edfc655bc828d44ad09d1150f31"
                               "374e7ef73027e14760d42e77341fe054"
                               "67bb286cc2c9d7fde29120a0b2320d04";
static const char *VRF_T3_BETA = "121b7f9b9aaaa29099fc04a94ba52784"
                                 "d44eac976dd1a3cca458733be5cd090a"
                                 "7b5fbd148444f17f8daf1fb55cb04b1a"
                                 "e85a626e30a54b4b0f8abf4a43314a58";

static void check_vrf_vector(const char *what,
                             const char *sk_hex,
                             const char *pk_hex,
                             const uint8_t *alpha,
                             size_t alpha_len,
                             const char *pi_hex,
                             const char *beta_hex)
{
    uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pk[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t expected_pi[ANTS_VRF_PROOF_SIZE];
    uint8_t expected_beta[ANTS_VRF_OUTPUT_SIZE];

    CHECK(hex_to_bytes(sk_hex, sk, sizeof sk) == ANTS_ED25519_PRIVKEY_SIZE);
    CHECK(hex_to_bytes(pk_hex, pk, sizeof pk) == ANTS_ED25519_PUBKEY_SIZE);
    CHECK(hex_to_bytes(pi_hex, expected_pi, sizeof expected_pi) == ANTS_VRF_PROOF_SIZE);
    CHECK(hex_to_bytes(beta_hex, expected_beta, sizeof expected_beta) == ANTS_VRF_OUTPUT_SIZE);

    /* PK consistency: derived from SK must match the vector's PK. */
    uint8_t derived_pk[ANTS_ED25519_PUBKEY_SIZE];
    CHECK_EQ(ants_ed25519_pubkey_from_priv(sk, derived_pk), ANTS_OK);
    if (memcmp(derived_pk, pk, ANTS_ED25519_PUBKEY_SIZE) != 0) {
        failures++;
        fprintf(stderr, "FAIL %s: derived PK mismatch\n", what);
    }

    /* Prove. */
    uint8_t pi[ANTS_VRF_PROOF_SIZE];
    CHECK_EQ(ants_vrf_prove(sk, alpha, alpha_len, pi), ANTS_OK);
    if (memcmp(pi, expected_pi, ANTS_VRF_PROOF_SIZE) != 0) {
        failures++;
        fprintf(stderr, "FAIL %s pi mismatch\n  expected: %s\n  got:      ", what, pi_hex);
        for (size_t i = 0; i < ANTS_VRF_PROOF_SIZE; i++) {
            fprintf(stderr, "%02x", pi[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Verify expected_pi against expected_pk; beta must match. */
    uint8_t beta[ANTS_VRF_OUTPUT_SIZE];
    CHECK_EQ(ants_vrf_verify(pk, alpha, alpha_len, expected_pi, beta), ANTS_OK);
    if (memcmp(beta, expected_beta, ANTS_VRF_OUTPUT_SIZE) != 0) {
        failures++;
        fprintf(stderr, "FAIL %s beta mismatch\n  expected: %s\n  got:      ", what, beta_hex);
        for (size_t i = 0; i < ANTS_VRF_OUTPUT_SIZE; i++) {
            fprintf(stderr, "%02x", beta[i]);
        }
        fprintf(stderr, "\n");
    }
}

static void test_vrf_rfc9381_vectors(void)
{
    check_vrf_vector("RFC 9381 §B.4 ex19", VRF_T1_SK, VRF_T1_PK, NULL, 0, VRF_T1_PI, VRF_T1_BETA);

    uint8_t alpha2[1];
    CHECK(hex_to_bytes(VRF_T2_ALPHA_HEX, alpha2, sizeof alpha2) == 1);
    check_vrf_vector(
        "RFC 9381 §B.4 ex20", VRF_T2_SK, VRF_T2_PK, alpha2, sizeof alpha2, VRF_T2_PI, VRF_T2_BETA);

    uint8_t alpha3[2];
    CHECK(hex_to_bytes(VRF_T3_ALPHA_HEX, alpha3, sizeof alpha3) == 2);
    check_vrf_vector(
        "RFC 9381 §B.4 ex21", VRF_T3_SK, VRF_T3_PK, alpha3, sizeof alpha3, VRF_T3_PI, VRF_T3_BETA);
}

static void test_vrf_rejects_invalid_args(void)
{
    uint8_t buf[ANTS_VRF_PROOF_SIZE];
    CHECK_EQ(ants_vrf_prove(NULL, buf, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_prove(buf, NULL, 1, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_prove(buf, buf, 1, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_verify(NULL, buf, 1, buf, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_verify(buf, NULL, 1, buf, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_verify(buf, buf, 1, NULL, buf), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_vrf_verify(buf, buf, 1, buf, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_vrf_roundtrip(void)
{
    /* Use the RFC 8032 §7.1 TEST 1 seed (well-known fixed key). */
    uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pk[ANTS_ED25519_PUBKEY_SIZE];
    CHECK(hex_to_bytes(RFC8032_T1_SEED, sk, sizeof sk) == ANTS_ED25519_PRIVKEY_SIZE);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(sk, pk), ANTS_OK);

    /* Round-trip over three alpha sizes: empty, 1 byte, 17 bytes. */
    const struct {
        const char *desc;
        const uint8_t *alpha;
        size_t alpha_len;
    } cases[] = {
        {"empty", NULL, 0},
        {"1B", (const uint8_t *)"\x72", 1},
        {"17B", (const uint8_t *)"ANTS VRF round-tr", 17},
    };

    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        uint8_t pi[ANTS_VRF_PROOF_SIZE];
        uint8_t beta1[ANTS_VRF_OUTPUT_SIZE];
        uint8_t beta2[ANTS_VRF_OUTPUT_SIZE];
        CHECK_EQ(ants_vrf_prove(sk, cases[i].alpha, cases[i].alpha_len, pi), ANTS_OK);
        CHECK_EQ(ants_vrf_verify(pk, cases[i].alpha, cases[i].alpha_len, pi, beta1), ANTS_OK);

        /* Determinism: prove again, same proof bytes; verify again,
         * same beta bytes. ECVRF is fully deterministic in SK and
         * alpha (nonce k is hash-derived, not random). */
        uint8_t pi2[ANTS_VRF_PROOF_SIZE];
        CHECK_EQ(ants_vrf_prove(sk, cases[i].alpha, cases[i].alpha_len, pi2), ANTS_OK);
        CHECK(memcmp(pi, pi2, ANTS_VRF_PROOF_SIZE) == 0);
        CHECK_EQ(ants_vrf_verify(pk, cases[i].alpha, cases[i].alpha_len, pi, beta2), ANTS_OK);
        CHECK(memcmp(beta1, beta2, ANTS_VRF_OUTPUT_SIZE) == 0);
        (void)cases[i].desc;
    }
}

static void test_vrf_distinct_alpha_distinct_beta(void)
{
    /* Same key, different alpha ⇒ distinct beta values. Beta is the
     * VRF's pseudorandom output; if the same key produced the same
     * beta for distinct inputs, the construction would be broken. */
    uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pk[ANTS_ED25519_PUBKEY_SIZE];
    CHECK(hex_to_bytes(RFC8032_T1_SEED, sk, sizeof sk) == ANTS_ED25519_PRIVKEY_SIZE);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(sk, pk), ANTS_OK);

    uint8_t pi_a[ANTS_VRF_PROOF_SIZE];
    uint8_t pi_b[ANTS_VRF_PROOF_SIZE];
    uint8_t beta_a[ANTS_VRF_OUTPUT_SIZE];
    uint8_t beta_b[ANTS_VRF_OUTPUT_SIZE];
    CHECK_EQ(ants_vrf_prove(sk, (const uint8_t *)"A", 1, pi_a), ANTS_OK);
    CHECK_EQ(ants_vrf_prove(sk, (const uint8_t *)"B", 1, pi_b), ANTS_OK);
    CHECK(memcmp(pi_a, pi_b, ANTS_VRF_PROOF_SIZE) != 0);
    CHECK_EQ(ants_vrf_verify(pk, (const uint8_t *)"A", 1, pi_a, beta_a), ANTS_OK);
    CHECK_EQ(ants_vrf_verify(pk, (const uint8_t *)"B", 1, pi_b, beta_b), ANTS_OK);
    CHECK(memcmp(beta_a, beta_b, ANTS_VRF_OUTPUT_SIZE) != 0);
}

static void test_vrf_verify_rejects_tampered(void)
{
    uint8_t sk[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pk[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t pi[ANTS_VRF_PROOF_SIZE];
    uint8_t beta[ANTS_VRF_OUTPUT_SIZE];
    const uint8_t alpha[] = "ANTS VRF test input";
    const size_t alpha_len = sizeof alpha - 1;

    CHECK(hex_to_bytes(RFC8032_T1_SEED, sk, sizeof sk) == ANTS_ED25519_PRIVKEY_SIZE);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(sk, pk), ANTS_OK);
    CHECK_EQ(ants_vrf_prove(sk, alpha, alpha_len, pi), ANTS_OK);
    CHECK_EQ(ants_vrf_verify(pk, alpha, alpha_len, pi, beta), ANTS_OK);

    /* Tamper Gamma (proof byte 0). */
    uint8_t bad_pi[ANTS_VRF_PROOF_SIZE];
    memcpy(bad_pi, pi, sizeof bad_pi);
    bad_pi[0] ^= 0x01;
    CHECK(ants_vrf_verify(pk, alpha, alpha_len, bad_pi, beta) != ANTS_OK);

    /* Tamper c (proof byte 32). */
    memcpy(bad_pi, pi, sizeof bad_pi);
    bad_pi[32] ^= 0x01;
    CHECK_EQ(ants_vrf_verify(pk, alpha, alpha_len, bad_pi, beta), ANTS_ERROR_MALFORMED);

    /* Tamper s (proof byte 48). */
    memcpy(bad_pi, pi, sizeof bad_pi);
    bad_pi[48] ^= 0x01;
    CHECK_EQ(ants_vrf_verify(pk, alpha, alpha_len, bad_pi, beta), ANTS_ERROR_MALFORMED);

    /* Tamper alpha. */
    uint8_t bad_alpha[sizeof alpha - 1];
    memcpy(bad_alpha, alpha, sizeof bad_alpha);
    bad_alpha[0] ^= 0x01;
    CHECK_EQ(ants_vrf_verify(pk, bad_alpha, sizeof bad_alpha, pi, beta), ANTS_ERROR_MALFORMED);

    /* Tamper PK. byte 0 flip may produce a non-canonical encoding
     * (which we reject with MALFORMED). Either way the call must
     * not succeed. */
    uint8_t bad_pk[ANTS_ED25519_PUBKEY_SIZE];
    memcpy(bad_pk, pk, sizeof bad_pk);
    bad_pk[0] ^= 0x01;
    CHECK(ants_vrf_verify(bad_pk, alpha, alpha_len, pi, beta) != ANTS_OK);
}

/* ------------------------------------------------------------------------ */
/* ECDSA P-256 — known-answer + adversarial tests.                          */
/*                                                                          */
/* Vectors from Project Wycheproof ecdsa_secp256r1_sha256_p1363 (group 0,   */
/* testvectors_v1): the IEEE P1363 raw r||s encoding, matching our wrapper's */
/* 64-byte signature. Wycheproof is an independent, adversarial vector set — */
/* the cross-check that catches a verifier which is self-consistent but      */
/* wrong (the ECVRF lesson). Each signature is verified over SHA-256(msg),   */
/* exercising ants_sha256 in the chain. The 64-byte public key is            */
/* testGroups[0].publicKey.uncompressed with the leading 0x04 stripped       */
/* (X || Y). result "valid" -> ANTS_OK; "invalid" -> ANTS_ERROR_MALFORMED.   */
/* Only 64-byte signatures are taken here — over/under-length P1363/DER      */
/* encodings are the TEE layer's parsing concern, not this fixed-width       */
/* primitive's.                                                              */
/* ------------------------------------------------------------------------ */

static void test_ecdsa_p256_rejects_invalid_args(void)
{
    uint8_t pub[ANTS_ECDSA_P256_PUBKEY_SIZE] = {0};
    uint8_t sig[ANTS_ECDSA_P256_SIG_SIZE] = {0};
    uint8_t hash[ANTS_SHA256_HASH_SIZE] = {0};
    CHECK_EQ(ants_ecdsa_p256_verify(NULL, hash, sizeof hash, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ecdsa_p256_verify(pub, NULL, 1, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ecdsa_p256_verify(pub, hash, sizeof hash, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_ecdsa_p256_wycheproof(void)
{
    /* testGroups[0].publicKey.uncompressed, 0x04 prefix stripped (X || Y). */
    static const char pub_hex[] =
        "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838"
        "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e";

    struct kat {
        int tc_id;
        const char *msg_hex;
        const char *sig_hex;
        ants_error_t expect;
    };
    static const struct kat kats[] = {
        /* valid signatures */
        {1,
         "313233343030",
         "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184"
         "cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
         ANTS_OK},
        {60,
         "3639383139",
         "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6"
         "af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
         ANTS_OK},
        {61,
         "343236343739373234",
         "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf2662"
         "52cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
         ANTS_OK},
        /* invalid signatures — adversarial edge cases */
        {4,
         "313233343030", /* r replaced by n - r */
         "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739"
         "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
         ANTS_ERROR_MALFORMED},
        {11,
         "313233343030", /* r = 0, s = 0 */
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000000",
         ANTS_ERROR_MALFORMED},
        {12,
         "313233343030", /* r = 0, s = 1 */
         "0000000000000000000000000000000000000000000000000000000000000000"
         "0000000000000000000000000000000000000000000000000000000000000001",
         ANTS_ERROR_MALFORMED},
        {13,
         "313233343030", /* r = 0, s = n */
         "0000000000000000000000000000000000000000000000000000000000000000"
         "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
         ANTS_ERROR_MALFORMED},
        {14,
         "313233343030", /* r = 0, s = n - 1 */
         "0000000000000000000000000000000000000000000000000000000000000000"
         "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
         ANTS_ERROR_MALFORMED},
        {16,
         "313233343030", /* r = 0, s = p */
         "0000000000000000000000000000000000000000000000000000000000000000"
         "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
         ANTS_ERROR_MALFORMED},
    };

    uint8_t pub[ANTS_ECDSA_P256_PUBKEY_SIZE];
    CHECK(hex_to_bytes(pub_hex, pub, sizeof pub) == sizeof pub);

    for (size_t i = 0; i < sizeof kats / sizeof kats[0]; i++) {
        const struct kat *k = &kats[i];
        uint8_t msg[64];
        uint8_t sig[ANTS_ECDSA_P256_SIG_SIZE];
        uint8_t hash[ANTS_SHA256_HASH_SIZE];
        size_t msg_len = hex_to_bytes(k->msg_hex, msg, sizeof msg);
        CHECK(hex_to_bytes(k->sig_hex, sig, sizeof sig) == sizeof sig);
        CHECK_EQ(ants_sha256(msg, msg_len, hash), ANTS_OK);
        ants_error_t got = ants_ecdsa_p256_verify(pub, hash, sizeof hash, sig);
        if (got != k->expect) {
            failures++;
            fprintf(stderr,
                    "FAIL ecdsa-p256 wycheproof tcId=%d: expected %s, got %s\n",
                    k->tc_id,
                    ants_strerror(k->expect),
                    ants_strerror(got));
        }
    }
}


/* ------------------------------------------------------------------------ */
/* ECDSA P-384 verify — KAT + adversarial vectors from Project Wycheproof.   */
/*                                                                          */
/* ecdsa_secp384r1_sha512_p1363_test.json testGroups[0]: AMD SEV-SNP signs  */
/* its attestation report with ECDSA P-384 (RFC-0005). Wycheproof is an     */
/* independent, adversarial set — the cross-check that catches a verifier   */
/* that is self-consistent but wrong (the ECVRF lesson). Each signature is  */
/* verified over SHA-512(msg), exercising ants_sha512 in the chain. The     */
/* 96-byte public key is testGroups[0].publicKey.uncompressed with the      */
/* leading 0x04 stripped (X || Y). result "valid" -> ANTS_OK; "invalid" ->  */
/* ANTS_ERROR_MALFORMED. Only 96-byte signatures are taken here.            */
/* ------------------------------------------------------------------------ */

static void test_ecdsa_p384_rejects_invalid_args(void)
{
    uint8_t pub[ANTS_ECDSA_P384_PUBKEY_SIZE] = {0};
    uint8_t sig[ANTS_ECDSA_P384_SIG_SIZE] = {0};
    uint8_t hash[ANTS_SHA512_HASH_SIZE] = {0};
    CHECK_EQ(ants_ecdsa_p384_verify(NULL, hash, sizeof hash, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ecdsa_p384_verify(pub, NULL, 1, sig), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_ecdsa_p384_verify(pub, hash, sizeof hash, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_ecdsa_p384_wycheproof(void)
{
    /* testGroups[0].publicKey.uncompressed, 0x04 prefix stripped (X || Y). */
    static const char pub_hex[] = "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f2"
                                  "0f47ff888274389772d98cc5752138aa"
                                  "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc"
                                  "7407b0d6091f9e4d88f014274406174f";

    struct kat {
        int tc_id;
        const char *msg_hex;
        const char *sig_hex;
        ants_error_t expect;
    };
    static const struct kat kats[] = {
        {1,
         "313233343030", /* signature malleability */
         "814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d297ea9"
         "44a15e2"
         "7b0a10ee2dd0dd2fab75095af240d095e446faba7a50a19fbb197e4c4250926e30c5303a2c2d34250f17fcf5a"
         "b3181a6",
         ANTS_OK},
        {60,
         "3637323636", /* Edge case for Shamir multiplication */
         "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335de0cd"
         "f565684"
         "8f8a277dde5282671af958e3315e795a20e2885157b77663a67a77ef2379020c5d12be6c732fd725402cb9ee8"
         "c345284",
         ANTS_OK},
        {61,
         "33393439313934313732", /* special case hash */
         "d51c53fa3e201c440a4e33ea0bbc1d3f3fe18b0cc2a4d6812dd217a9b426e54eb4024113b354441272174549c"
         "979857c"
         "0992c5442dc6d5d6095a45720f5c5344acb78bc18817ef32c1334e6eba7726246577d4257942bdefe994c1575"
         "ed15a6e",
         ANTS_OK},
        {62,
         "35333637363431383737", /* special case hash */
         "c8d44c8b70abed9e6ae6bbb9f4b72ed6e8b50a52a8e6e1bd3447c0828dad26fc6f395ba09069b307f040d1e86"
         "a42c022"
         "01e0af500505bb88b3a2b0f132acb4da64adddc0598318cb7612b5812d29c2d0dde1413d0ce40044b44590e91"
         "b97bacd",
         ANTS_OK},
        {11,
         "313233343030", /* Signature with special case values r=0 and s=0 */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000",
         ANTS_ERROR_MALFORMED},
        {12,
         "313233343030", /* Signature with special case values r=0 and s=1 */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000001",
         ANTS_ERROR_MALFORMED},
        {13,
         "313233343030", /* Signature with special case values r=0 and s=n */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000"
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52973",
         ANTS_ERROR_MALFORMED},
        {14,
         "313233343030", /* Signature with special case values r=0 and s=n - 1 */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000"
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52972",
         ANTS_ERROR_MALFORMED},
        {16,
         "313233343030", /* Signature with special case values r=0 and s=p */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000"
         "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000f"
         "fffffff",
         ANTS_ERROR_MALFORMED},
        {18,
         "313233343030", /* Signature with special case values r=1 and s=0 */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000001"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000",
         ANTS_ERROR_MALFORMED},
        {20,
         "313233343030", /* Signature with special case values r=1 and s=n */
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000001"
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52973",
         ANTS_ERROR_MALFORMED},
        {25,
         "313233343030", /* Signature with special case values r=n and s=0 */
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52973"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000",
         ANTS_ERROR_MALFORMED},
        {39,
         "313233343030", /* Signature with special case values r=n + 1 and s=0 */
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52974"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000000",
         ANTS_ERROR_MALFORMED},
        {40,
         "313233343030", /* Signature with special case values r=n + 1 and s=1 */
         "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196ac"
         "cc52974"
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "0000001",
         ANTS_ERROR_MALFORMED}};

    uint8_t pub[ANTS_ECDSA_P384_PUBKEY_SIZE];
    CHECK(hex_to_bytes(pub_hex, pub, sizeof pub) == sizeof pub);

    for (size_t i = 0; i < sizeof kats / sizeof kats[0]; i++) {
        const struct kat *k = &kats[i];
        uint8_t msg[64];
        uint8_t sig[ANTS_ECDSA_P384_SIG_SIZE];
        uint8_t hash[ANTS_SHA512_HASH_SIZE];
        size_t msg_len = hex_to_bytes(k->msg_hex, msg, sizeof msg);
        CHECK(hex_to_bytes(k->sig_hex, sig, sizeof sig) == sizeof sig);
        CHECK_EQ(ants_sha512(msg, msg_len, hash), ANTS_OK);
        ants_error_t got = ants_ecdsa_p384_verify(pub, hash, sizeof hash, sig);
        if (got != k->expect) {
            failures++;
            fprintf(stderr,
                    "FAIL ecdsa-p384 wycheproof tcId=%d: expected %s, got %s\n",
                    k->tc_id,
                    ants_strerror(k->expect),
                    ants_strerror(got));
        }
    }
}

int main(void)
{
    test_blake3_rejects_invalid_args();
    test_blake3_empty();
    test_blake3_known_inputs();
    test_blake3_derive_key();
    test_blake3_streaming_matches_one_shot();

    test_sha256_rejects_invalid_args();
    test_sha256_known_inputs();
    test_sha256_drand_randomness();

    test_sha512_rejects_invalid_args();
    test_sha512_known_inputs();

    test_ed25519_rejects_invalid_args();
    test_ed25519_rfc8032_test1_empty();
    test_ed25519_rfc8032_test2_single_byte();
    test_ed25519_verify_rejects_tampered();

    test_bls_rejects_invalid_args();
    test_bls_g1_generator();
    test_bls_rejects_zero_sk();
    test_bls_sign_verify_roundtrip();
    test_bls_aggregate_wrong_message_fails();

    test_vrf_rejects_invalid_args();
    test_vrf_rfc9381_vectors();
    test_vrf_roundtrip();
    test_vrf_distinct_alpha_distinct_beta();
    test_vrf_verify_rejects_tampered();

    test_ecdsa_p256_rejects_invalid_args();
    test_ecdsa_p256_wycheproof();

    test_ecdsa_p384_rejects_invalid_args();
    test_ecdsa_p384_wycheproof();

    if (failures > 0) {
        fprintf(stderr, "%d test check(s) failed\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
