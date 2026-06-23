/*
 * x509.h — minimal X.509 v3 certificate field extractor.
 *
 * Walks a single DER-encoded certificate with the strict reader in der.h and
 * surfaces the fields the TEE certificate-chain validator (RFC-0005) needs to
 * walk a vendor chain: the signed tbsCertificate byte range, the issuer and
 * subject Names (for chaining), the validity window, the SubjectPublicKeyInfo
 * public key (RSA or EC), and the outer signatureAlgorithm + signatureValue.
 *
 * This is the "parse" half of the forthcoming chain validator: parse a cert ->
 * (later) verify its signature with the issuer's key + chain to a pinned root.
 * The public keys are surfaced in exactly the form the verifiers consume:
 *   - EC: the uncompressed point X || Y, big-endian, no 0x04 prefix — what
 *     ants_ecdsa_p256_verify / ants_ecdsa_p384_verify and the SNP/TDX leaf-key
 *     contracts (ANTS_SNP_VCEK_PUBKEY_SIZE / ANTS_TDX_PCK_PUBKEY_SIZE) take;
 *   - RSA: modulus + public exponent, big-endian, leading sign octet stripped —
 *     what ants_rsa_pss_verify takes (AMD's ASK/ARK are RSA-4096 RSASSA-PSS).
 *
 * Allocation-free: every output slice points into the caller's `der` buffer,
 * which must outlive the ants_x509_cert. v3 extensions are tolerated but not
 * decoded here (BasicConstraints / KeyUsage / vendor TCB OIDs are the chain
 * validator's concern). Internal to foundation/tee; exposed via this header
 * (not ants_tee.h) so it can be unit-tested in isolation against real
 * vendor certificates — see tests/test_x509.c + tests/cert_kat_vectors.h.
 */

#ifndef ANTS_TEE_X509_H
#define ANTS_TEE_X509_H

#include "ants_common.h"

#include <stddef.h>
#include <stdint.h>

/* SubjectPublicKeyInfo key family. */
typedef enum {
    ANTS_X509_KEY_UNKNOWN = 0,
    ANTS_X509_KEY_RSA, /* rsaEncryption (1.2.840.113549.1.1.1) */
    ANTS_X509_KEY_EC,  /* id-ecPublicKey (1.2.840.10045.2.1) */
} ants_x509_key_kind;

/* Named curve, EC keys only. */
typedef enum {
    ANTS_X509_CURVE_NONE = 0,
    ANTS_X509_CURVE_P256, /* prime256v1 / secp256r1 (1.2.840.10045.3.1.7) */
    ANTS_X509_CURVE_P384, /* secp384r1 (1.3.132.0.34) */
} ants_x509_curve;

/*
 * Decoded view of one X.509 certificate. All pointers are slices into the
 * `der` buffer passed to ants_x509_cert_parse (no copy); they are valid only
 * as long as that buffer is.
 */
typedef struct {
    /* The raw tbsCertificate element INCLUDING its SEQUENCE tag + length
     * octets: the exact bytes the certificate signature is computed over. */
    const uint8_t *tbs;
    size_t tbs_len;

    /* The outer signatureAlgorithm's algorithm OBJECT IDENTIFIER value octets
     * (without the 0x06 tag/length) — enough to route a chain link to the
     * right verifier (ecdsa-with-SHA* vs RSASSA-PSS). */
    const uint8_t *sig_alg_oid;
    size_t sig_alg_oid_len;

    /* signatureValue: the BIT STRING payload with the leading unused-bits
     * octet removed. RSA: the raw signature. ECDSA: DER SEQUENCE { r, s }. */
    const uint8_t *signature;
    size_t signature_len;

    /* issuer / subject Name: the full DER element (tag + length + value) so a
     * chain walk can match child.issuer to parent.subject byte-for-byte
     * without canonicalisation. */
    const uint8_t *issuer;
    size_t issuer_len;
    const uint8_t *subject;
    size_t subject_len;

    /* Validity, as the raw time value octets (no tag/length). The tag field
     * distinguishes UTCTime (ANTS_DER_TAG_UTC_TIME, YYMMDDHHMMSSZ) from
     * GeneralizedTime (ANTS_DER_TAG_GENERALIZED_TIME, YYYYMMDDHHMMSSZ); the
     * chain validator converts + compares against `now`. */
    uint8_t not_before_tag;
    const uint8_t *not_before;
    size_t not_before_len;
    uint8_t not_after_tag;
    const uint8_t *not_after;
    size_t not_after_len;

    /* SubjectPublicKeyInfo, decoded into verifier-ready form. */
    ants_x509_key_kind key_kind;
    ants_x509_curve curve; /* EC only; ANTS_X509_CURVE_NONE for RSA */

    /* EC: uncompressed point X || Y big-endian, no 0x04 prefix (64 bytes for
     * P-256, 96 for P-384). NULL for RSA. */
    const uint8_t *ec_point;
    size_t ec_point_len;

    /* RSA: modulus and public exponent, big-endian, leading 0x00 sign octet
     * stripped. NULL for EC. */
    const uint8_t *rsa_modulus;
    size_t rsa_modulus_len;
    const uint8_t *rsa_exponent;
    size_t rsa_exponent_len;

    /* The DER content of the v3 extensions SEQUENCE — the bytes of the
     * SEQUENCE OF Extension carried inside the [3] EXPLICIT wrapper — or NULL
     * if the certificate has no extensions. Not decoded here; the chain
     * validator iterates it (e.g. for the BasicConstraints CA flag). */
    const uint8_t *extensions;
    size_t extensions_len;
} ants_x509_cert;

/*
 * Parse a single DER-encoded X.509 certificate from [der, der+der_len).
 *
 * On success fills `*out` with slices into `der` and returns ANTS_OK. The
 * input must be exactly one certificate (trailing bytes are rejected). Only
 * RSA and EC (P-256 / P-384) SubjectPublicKeyInfo are understood; any other
 * key algorithm or curve is ANTS_ERROR_MALFORMED.
 *
 * Returns ANTS_ERROR_INVALID_ARG on a NULL argument, ANTS_ERROR_MALFORMED on
 * any strict-DER violation, an unexpected structure, or an unsupported key.
 */
ants_error_t ants_x509_cert_parse(const uint8_t *der, size_t der_len, ants_x509_cert *out);

#endif /* ANTS_TEE_X509_H */
