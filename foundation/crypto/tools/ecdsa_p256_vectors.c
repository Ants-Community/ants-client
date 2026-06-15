/*
 * ecdsa_p256_vectors.c — emit the ecdsa-p256.verify test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout.
 * The vectors are sourced from Project Wycheproof
 * (ecdsa_secp256r1_sha256_p1363_test.json, testGroups[0]) — an independent,
 * adversarial set: the cross-check that catches a verifier which is
 * self-consistent but wrong. Every verdict is CONFIRMED against the
 * compiled ants_ecdsa_p256_verify before being printed — a vector this tool
 * emits is one our own implementation already agrees with.
 *
 * Deterministic: fixed inputs, no clock, no randomness. Run it twice and the
 * bytes match. The per-vector msg_sha256 is computed by the reference
 * ants_sha256 (the digest our verify consumes), not transcribed.
 *
 * Usage:  ecdsa_p256_vectors > ecdsa-p256.json
 *
 * Spec: RFC-0005 (TEE attestation — vendor signature chains; Intel TDX signs
 * ECDSA P-256). FIPS 186-4 / SEC1. RFC-0008 (signatures).
 */

#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what)
{
    fprintf(stderr, "ecdsa_p256_vectors: %s\n", what);
    exit(1);
}

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

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

/* Public key shared by every vector: Wycheproof group-0
 * publicKey.uncompressed with the leading 0x04 stripped (X || Y). */
static const char PUB_HEX[] = "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838"
                              "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e";

static const struct {
    int tc_id;
    const char *comment;
    const char *msg_hex;
    const char *sig_hex;
    bool valid;
} CASES[] = {
    /* valid signatures */
    {1,
     "signature malleability",
     "313233343030",
     "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184"
     "cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
     true},
    {60,
     "edge case for Shamir multiplication",
     "3639383139",
     "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6"
     "af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
     true},
    {61,
     "special case hash",
     "343236343739373234",
     "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf2662"
     "52cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
     true},
    {62,
     "special case hash",
     "37313338363834383931",
     "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882"
     "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
     true},
    /* invalid signatures — special-value / out-of-range r,s */
    {4,
     "r replaced by n - r",
     "313233343030",
     "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739"
     "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
     false},
    {11,
     "r=0 and s=0",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000000",
     false},
    {12,
     "r=0 and s=1",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000001",
     false},
    {13,
     "r=0 and s=n",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     false},
    {14,
     "r=0 and s=n-1",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
     false},
    {16,
     "r=0 and s=p",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000"
     "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
     false},
    {18,
     "r=1 and s=0",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000001"
     "0000000000000000000000000000000000000000000000000000000000000000",
     false},
    {20,
     "r=1 and s=n",
     "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000001"
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     false},
    {39,
     "r=n+1 and s=0",
     "313233343030",
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"
     "0000000000000000000000000000000000000000000000000000000000000000",
     false},
    {40,
     "r=n+1 and s=1",
     "313233343030",
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"
     "0000000000000000000000000000000000000000000000000000000000000001",
     false},
};

int main(void)
{
    uint8_t pub[ANTS_ECDSA_P256_PUBKEY_SIZE];
    if (hex_to_bytes(PUB_HEX, pub, sizeof pub) != sizeof pub) {
        die("bad public key hex");
    }

    printf("{\n");
    printf(
        "  \"primitive\": \"ecdsa-p256.verify (NIST P-256 / secp256r1, ECDSA with SHA-256)\",\n");
    printf("  \"spec\":      \"RFC-0005 (TEE attestation: vendor signature chains; Intel TDX signs "
           "ECDSA P-256); FIPS 186-4; SEC1; RFC-0008 \\u00a73 (signatures)\",\n");
    printf("  \"version\":   1,\n");
    printf("  \"vendor\":    \"mpg/p256-m @44af59e (Apache-2.0); verdicts confirmed through "
           "ants_ecdsa_p256_verify\",\n");
    printf("  \"source\":    \"Project Wycheproof ecdsa_secp256r1_sha256_p1363_test.json, "
           "testGroups[0] (https://github.com/google/wycheproof)\",\n");
    printf(
        "  \"notes\":     \"Verify-only (ANTS never signs with P-256; peer identity is Ed25519). "
        "Signatures are IEEE-P1363 raw r||s (64 bytes); the public key is uncompressed X||Y "
        "(64 bytes, no 0x04 prefix). The signature is over SHA-256(msg); msg_sha256_hex is that "
        "digest, computed by the reference ants_sha256. result 'valid' MUST verify (ANTS_OK), "
        "'invalid' MUST be rejected. Only 64-byte signatures are included (this primitive is "
        "fixed-width; over/under-length DER/SEC1 encodings are the TEE layer's parsing concern). "
        "Every verdict was confirmed against the compiled ants_ecdsa_p256_verify before "
        "emission; tc_id is the Wycheproof test id.\",\n");
    printf("  \"public_key_hex\": \"");
    print_hex(pub, sizeof pub);
    printf("\",\n");
    printf("  \"vectors\": [\n");

    const size_t n = sizeof CASES / sizeof CASES[0];
    for (size_t i = 0; i < n; i++) {
        uint8_t msg[64];
        uint8_t sig[ANTS_ECDSA_P256_SIG_SIZE];
        uint8_t hash[ANTS_SHA256_HASH_SIZE];
        size_t msg_len = hex_to_bytes(CASES[i].msg_hex, msg, sizeof msg);
        if (hex_to_bytes(CASES[i].sig_hex, sig, sizeof sig) != sizeof sig) {
            die("signature hex is not 64 bytes");
        }
        if (ants_sha256(msg, msg_len, hash) != ANTS_OK) {
            die("sha256");
        }
        /* From-artifact gate: our verify MUST agree with the expected
         * Wycheproof verdict, or we do not emit. */
        bool got_valid = (ants_ecdsa_p256_verify(pub, hash, sizeof hash, sig) == ANTS_OK);
        if (got_valid != CASES[i].valid) {
            fprintf(stderr,
                    "ecdsa_p256_vectors: tc %d verdict mismatch (expected %s, lib says %s)\n",
                    CASES[i].tc_id,
                    CASES[i].valid ? "valid" : "invalid",
                    got_valid ? "valid" : "invalid");
            exit(1);
        }

        printf(
            "    {\"tc_id\": %d, \"comment\": \"%s\", \"msg_hex\": \"%s\", \"msg_sha256_hex\": \"",
            CASES[i].tc_id,
            CASES[i].comment,
            CASES[i].msg_hex);
        print_hex(hash, sizeof hash);
        printf("\", \"sig_hex\": \"%s\", \"result\": \"%s\"}%s\n",
               CASES[i].sig_hex,
               CASES[i].valid ? "valid" : "invalid",
               (i + 1 < n) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
    return 0;
}
