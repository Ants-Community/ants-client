/*
 * ecdsa_p384_vectors.c -- emit the ecdsa-p384.verify test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout.
 * The vectors are sourced from Project Wycheproof
 * (ecdsa_secp384r1_sha512_p1363_test.json, testGroups[0]) -- an independent,
 * adversarial set: the cross-check that catches a verifier which is
 * self-consistent but wrong. Every verdict is CONFIRMED against the compiled
 * ants_ecdsa_p384_verify before being printed -- a vector this tool emits is
 * one our own implementation already agrees with.
 *
 * Deterministic: fixed inputs, no clock, no randomness. Run it twice and the
 * bytes match. The per-vector msg_sha512 is computed by the reference
 * ants_sha512 (the digest our verify consumes), not transcribed.
 *
 * Usage:  ecdsa_p384_vectors > ecdsa-p384.json
 *
 * Spec: RFC-0005 (TEE attestation -- vendor signature chains; AMD SEV-SNP
 * signs ECDSA P-384). FIPS 186-4 / SEC1. RFC-0008 (signatures).
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
    fprintf(stderr, "ecdsa_p384_vectors: %s\n", what);
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
static const char PUB_HEX[] = "2da57dda1089276a543f9ffdac0bff0d976cad71eb7280e7d9bfd9fee4bdb2f20f47"
                              "ff888274389772d98cc5752138aa"
                              "4b6d054d69dcf3e25ec49df870715e34883b1836197d76f8ad962e78f6571bbc7407"
                              "b0d6091f9e4d88f014274406174f";

static const struct {
    int tc_id;
    const char *comment;
    const char *msg_hex;
    const char *sig_hex;
    bool valid;
} CASES[] = {{1,
              "signature malleability",
              "313233343030",
              "814cc9a70febda342d4ada87fc39426f403d5e89808428460c1eca60c897bfd6728da14673854673d7d2"
              "97ea944a15e2"
              "7b0a10ee2dd0dd2fab75095af240d095e446faba7a50a19fbb197e4c4250926e30c5303a2c2d34250f17"
              "fcf5ab3181a6",
              true},
             {60,
              "Edge case for Shamir multiplication",
              "3637323636",
              "ac042e13ab83394692019170707bc21dd3d7b8d233d11b651757085bdd5767eabbb85322984f14437335"
              "de0cdf565684"
              "8f8a277dde5282671af958e3315e795a20e2885157b77663a67a77ef2379020c5d12be6c732fd725402c"
              "b9ee8c345284",
              true},
             {61,
              "special case hash",
              "33393439313934313732",
              "d51c53fa3e201c440a4e33ea0bbc1d3f3fe18b0cc2a4d6812dd217a9b426e54eb4024113b35444127217"
              "4549c979857c"
              "0992c5442dc6d5d6095a45720f5c5344acb78bc18817ef32c1334e6eba7726246577d4257942bdefe994"
              "c1575ed15a6e",
              true},
             {62,
              "special case hash",
              "35333637363431383737",
              "c8d44c8b70abed9e6ae6bbb9f4b72ed6e8b50a52a8e6e1bd3447c0828dad26fc6f395ba09069b307f040"
              "d1e86a42c022"
              "01e0af500505bb88b3a2b0f132acb4da64adddc0598318cb7612b5812d29c2d0dde1413d0ce40044b445"
              "90e91b97bacd",
              true},
             {11,
              "Signature with special case values r=0 and s=0",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000",
              false},
             {12,
              "Signature with special case values r=0 and s=1",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000001",
              false},
             {13,
              "Signature with special case values r=0 and s=n",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000"
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52973",
              false},
             {14,
              "Signature with special case values r=0 and s=n - 1",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000"
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52972",
              false},
             {16,
              "Signature with special case values r=0 and s=p",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000"
              "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000"
              "0000ffffffff",
              false},
             {18,
              "Signature with special case values r=1 and s=0",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000001"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000",
              false},
             {20,
              "Signature with special case values r=1 and s=n",
              "313233343030",
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000001"
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52973",
              false},
             {25,
              "Signature with special case values r=n and s=0",
              "313233343030",
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52973"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000",
              false},
             {39,
              "Signature with special case values r=n + 1 and s=0",
              "313233343030",
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52974"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000",
              false},
             {40,
              "Signature with special case values r=n + 1 and s=1",
              "313233343030",
              "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec"
              "196accc52974"
              "000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000001",
              false}};

int main(void)
{
    uint8_t pub[ANTS_ECDSA_P384_PUBKEY_SIZE];
    if (hex_to_bytes(PUB_HEX, pub, sizeof pub) != sizeof pub) {
        die("bad public key hex");
    }

    printf("{\n");
    printf(
        "  \"primitive\": \"ecdsa-p384.verify (NIST P-384 / secp384r1, ECDSA with SHA-512)\",\n");
    printf("  \"spec\":      \"RFC-0005 (TEE attestation: vendor signature chains; AMD SEV-SNP "
           "signs ECDSA P-384); FIPS 186-4; SEC1; RFC-0008 \\u00a73 (signatures)\",\n");
    printf("  \"version\":   1,\n");
    printf("  \"vendor\":    \"BearSSL @7bea48e (MIT); verdicts confirmed through "
           "ants_ecdsa_p384_verify\",\n");
    printf("  \"source\":    \"Project Wycheproof ecdsa_secp384r1_sha512_p1363_test.json, "
           "testGroups[0] (https://github.com/google/wycheproof)\",\n");
    printf(
        "  \"notes\":     \"Verify-only (ANTS never signs with P-384; peer identity is Ed25519). "
        "Signatures are IEEE-P1363 raw r||s (96 bytes); the public key is uncompressed X||Y "
        "(96 bytes, no 0x04 prefix). The signature is over SHA-512(msg); msg_sha512_hex is that "
        "digest, computed by the reference ants_sha512. result 'valid' MUST verify (ANTS_OK), "
        "'invalid' MUST be rejected. Only 96-byte signatures are included (this primitive is "
        "fixed-width; over/under-length DER/SEC1 encodings are the TEE layer's parsing concern). "
        "Every verdict was confirmed against the compiled ants_ecdsa_p384_verify before "
        "emission; tc_id is the Wycheproof test id.\",\n");
    printf("  \"public_key_hex\": \"");
    print_hex(pub, sizeof pub);
    printf("\",\n");
    printf("  \"vectors\": [\n");

    const size_t n = sizeof CASES / sizeof CASES[0];
    for (size_t i = 0; i < n; i++) {
        uint8_t msg[64];
        uint8_t sig[ANTS_ECDSA_P384_SIG_SIZE];
        uint8_t hash[ANTS_SHA512_HASH_SIZE];
        size_t msg_len = hex_to_bytes(CASES[i].msg_hex, msg, sizeof msg);
        if (hex_to_bytes(CASES[i].sig_hex, sig, sizeof sig) != sizeof sig) {
            die("signature hex is not 96 bytes");
        }
        if (ants_sha512(msg, msg_len, hash) != ANTS_OK) {
            die("sha512");
        }
        /* From-artifact gate: our verify MUST agree with the expected
         * Wycheproof verdict, or we do not emit. */
        bool got_valid = (ants_ecdsa_p384_verify(pub, hash, sizeof hash, sig) == ANTS_OK);
        if (got_valid != CASES[i].valid) {
            fprintf(stderr,
                    "ecdsa_p384_vectors: tc %d verdict mismatch (expected %s, lib says %s)\n",
                    CASES[i].tc_id,
                    CASES[i].valid ? "valid" : "invalid",
                    got_valid ? "valid" : "invalid");
            exit(1);
        }

        printf(
            "    {\"tc_id\": %d, \"comment\": \"%s\", \"msg_hex\": \"%s\", \"msg_sha512_hex\": \"",
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
