/*
 * x509.c — minimal X.509 v3 certificate field extractor (see x509.h).
 *
 * Structure walked (RFC 5280):
 *
 *   Certificate ::= SEQUENCE {
 *       tbsCertificate       TBSCertificate,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING }
 *
 *   TBSCertificate ::= SEQUENCE {
 *       version         [0] EXPLICIT INTEGER DEFAULT v1,
 *       serialNumber         INTEGER,
 *       signature            AlgorithmIdentifier,
 *       issuer               Name,
 *       validity             SEQUENCE { notBefore Time, notAfter Time },
 *       subject              Name,
 *       subjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING },
 *       ... [1] [2] [3] optional ... }
 *
 * The strict reader in der.h enforces definite, minimal-length DER and rejects
 * anything outside the X.509 subset, so this file only has to follow the shape
 * and pull out the pieces the chain validator needs.
 */

#include "x509.h"

#include "der.h"

#include <string.h>

/* OBJECT IDENTIFIER value octets (the bytes after the 0x06 tag/length). */
static const uint8_t OID_RSA_ENCRYPTION[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t OID_CURVE_P256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static const uint8_t OID_CURVE_P384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};

#define ANTS_X509_EC_POINT_P256 64
#define ANTS_X509_EC_POINT_P384 96

static bool oid_eq(const ants_der_tlv *t, const uint8_t *oid, size_t n)
{
    return t->len == n && memcmp(t->val, oid, n) == 0;
}

/* der's value slice drops the tag+length header, but the signed tbsCertificate
 * and the issuer/subject Names (compared byte-for-byte during chain building)
 * need their full on-wire bytes. The reader's cursor marks where the next
 * element begins; capture it before a read and the element spans [start,
 * cursor-after-read). der.h documents the reader as the cert-chain validator's
 * tool, so reaching for the element boundary here is intended use. */
static const uint8_t *cursor(const ants_der *r)
{
    return r->buf + r->pos;
}

/* Strip a single leading 0x00 DER sign octet from a positive INTEGER, leaving
 * the big-endian magnitude (modulus / exponent). */
static void trim_sign_octet(const uint8_t **p, size_t *n)
{
    if (*n > 1 && (*p)[0] == 0x00) {
        (*p)++;
        (*n)--;
    }
}

/* Read a BIT STRING and return its payload past the leading unused-bits octet,
 * which must be 0 (whole octets) for every BIT STRING X.509 uses here. */
static ants_error_t read_bit_string_body(ants_der *r, const uint8_t **body, size_t *body_len)
{
    ants_der_tlv bits;
    ants_error_t e = ants_der_read(r, ANTS_DER_TAG_BIT_STRING, &bits);
    if (e != ANTS_OK) {
        return e;
    }
    if (bits.len < 1 || bits.val[0] != 0x00) {
        return ANTS_ERROR_MALFORMED;
    }
    *body = bits.val + 1;
    *body_len = bits.len - 1;
    return ANTS_OK;
}

/* Decode SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }. */
static ants_error_t parse_spki(ants_der *tbs, ants_x509_cert *out)
{
    ants_der spki;
    ants_error_t e = ants_der_enter(tbs, ANTS_DER_TAG_SEQUENCE, &spki);
    if (e != ANTS_OK) {
        return e;
    }

    ants_der alg;
    e = ants_der_enter(&spki, ANTS_DER_TAG_SEQUENCE, &alg);
    if (e != ANTS_OK) {
        return e;
    }
    ants_der_tlv algoid;
    e = ants_der_read(&alg, ANTS_DER_TAG_OID, &algoid);
    if (e != ANTS_OK) {
        return e;
    }

    if (oid_eq(&algoid, OID_RSA_ENCRYPTION, sizeof OID_RSA_ENCRYPTION)) {
        out->key_kind = ANTS_X509_KEY_RSA;
        out->curve = ANTS_X509_CURVE_NONE;

        /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER },
         * wrapped in the SPKI BIT STRING. */
        const uint8_t *body;
        size_t body_len;
        e = read_bit_string_body(&spki, &body, &body_len);
        if (e != ANTS_OK) {
            return e;
        }
        ants_der rsa;
        ants_der_init(&rsa, body, body_len);
        ants_der inner;
        e = ants_der_enter(&rsa, ANTS_DER_TAG_SEQUENCE, &inner);
        if (e != ANTS_OK) {
            return e;
        }
        ants_der_tlv mod, exp;
        e = ants_der_read(&inner, ANTS_DER_TAG_INTEGER, &mod);
        if (e != ANTS_OK) {
            return e;
        }
        e = ants_der_read(&inner, ANTS_DER_TAG_INTEGER, &exp);
        if (e != ANTS_OK) {
            return e;
        }
        out->rsa_modulus = mod.val;
        out->rsa_modulus_len = mod.len;
        out->rsa_exponent = exp.val;
        out->rsa_exponent_len = exp.len;
        trim_sign_octet(&out->rsa_modulus, &out->rsa_modulus_len);
        trim_sign_octet(&out->rsa_exponent, &out->rsa_exponent_len);
        return ANTS_OK;
    }

    if (oid_eq(&algoid, OID_EC_PUBLIC_KEY, sizeof OID_EC_PUBLIC_KEY)) {
        out->key_kind = ANTS_X509_KEY_EC;

        /* The AlgorithmIdentifier parameters carry the named curve OID. */
        ants_der_tlv curveoid;
        e = ants_der_read(&alg, ANTS_DER_TAG_OID, &curveoid);
        if (e != ANTS_OK) {
            return e;
        }
        size_t point_len;
        if (oid_eq(&curveoid, OID_CURVE_P256, sizeof OID_CURVE_P256)) {
            out->curve = ANTS_X509_CURVE_P256;
            point_len = ANTS_X509_EC_POINT_P256;
        } else if (oid_eq(&curveoid, OID_CURVE_P384, sizeof OID_CURVE_P384)) {
            out->curve = ANTS_X509_CURVE_P384;
            point_len = ANTS_X509_EC_POINT_P384;
        } else {
            return ANTS_ERROR_MALFORMED;
        }

        /* subjectPublicKey BIT STRING = uncompressed point 0x04 || X || Y. */
        const uint8_t *body;
        size_t body_len;
        e = read_bit_string_body(&spki, &body, &body_len);
        if (e != ANTS_OK) {
            return e;
        }
        if (body_len != (size_t)1 + point_len || body[0] != 0x04) {
            return ANTS_ERROR_MALFORMED;
        }
        out->ec_point = body + 1;
        out->ec_point_len = point_len;
        return ANTS_OK;
    }

    return ANTS_ERROR_MALFORMED; /* unsupported SubjectPublicKeyInfo algorithm */
}

/* Decode the TBSCertificate contents (reader positioned over them). */
static ants_error_t parse_tbs_body(ants_der *tbs, ants_x509_cert *out)
{
    ants_error_t e;
    uint8_t tag;
    /* der rejects a NULL out slice, so fields we only need to consume (and
     * tag-check) past are read into this throwaway. */
    ants_der_tlv tmp;

    /* version [0] EXPLICIT — optional (absent means v1). */
    e = ants_der_peek_tag(tbs, &tag);
    if (e != ANTS_OK) {
        return e;
    }
    if (tag == ANTS_DER_TAG_CONTEXT(0)) {
        e = ants_der_skip(tbs);
        if (e != ANTS_OK) {
            return e;
        }
    }

    /* serialNumber INTEGER, signature AlgorithmIdentifier — not surfaced. */
    e = ants_der_read(tbs, ANTS_DER_TAG_INTEGER, &tmp);
    if (e != ANTS_OK) {
        return e;
    }
    e = ants_der_read(tbs, ANTS_DER_TAG_SEQUENCE, &tmp);
    if (e != ANTS_OK) {
        return e;
    }

    /* issuer Name — capture the full element for chain matching. */
    {
        const uint8_t *start = cursor(tbs);
        e = ants_der_read(tbs, ANTS_DER_TAG_SEQUENCE, &tmp);
        if (e != ANTS_OK) {
            return e;
        }
        out->issuer = start;
        out->issuer_len = (size_t)(cursor(tbs) - start);
    }

    /* validity SEQUENCE { notBefore Time, notAfter Time }. */
    {
        ants_der validity;
        e = ants_der_enter(tbs, ANTS_DER_TAG_SEQUENCE, &validity);
        if (e != ANTS_OK) {
            return e;
        }
        ants_der_tlv t;
        e = ants_der_read(&validity, 0, &t);
        if (e != ANTS_OK) {
            return e;
        }
        if (t.tag != ANTS_DER_TAG_UTC_TIME && t.tag != ANTS_DER_TAG_GENERALIZED_TIME) {
            return ANTS_ERROR_MALFORMED;
        }
        out->not_before_tag = t.tag;
        out->not_before = t.val;
        out->not_before_len = t.len;
        e = ants_der_read(&validity, 0, &t);
        if (e != ANTS_OK) {
            return e;
        }
        if (t.tag != ANTS_DER_TAG_UTC_TIME && t.tag != ANTS_DER_TAG_GENERALIZED_TIME) {
            return ANTS_ERROR_MALFORMED;
        }
        out->not_after_tag = t.tag;
        out->not_after = t.val;
        out->not_after_len = t.len;
    }

    /* subject Name — full element, like issuer. */
    {
        const uint8_t *start = cursor(tbs);
        e = ants_der_read(tbs, ANTS_DER_TAG_SEQUENCE, &tmp);
        if (e != ANTS_OK) {
            return e;
        }
        out->subject = start;
        out->subject_len = (size_t)(cursor(tbs) - start);
    }

    /* subjectPublicKeyInfo. */
    e = parse_spki(tbs, out);
    if (e != ANTS_OK) {
        return e;
    }

    /* Optional trailing fields: issuerUniqueID [1], subjectUniqueID [2] and
     * extensions [3] EXPLICIT. Only the extensions are surfaced (the chain
     * validator reads BasicConstraints from them); the unique IDs are skipped.
     * Walk whatever remains so an unexpected element is still rejected. */
    while (!ants_der_eof(tbs)) {
        e = ants_der_peek_tag(tbs, &tag);
        if (e != ANTS_OK) {
            return e;
        }
        if (tag == ANTS_DER_TAG_CONTEXT(3)) {
            ants_der ext_wrap;
            e = ants_der_enter(tbs, ANTS_DER_TAG_CONTEXT(3), &ext_wrap);
            if (e != ANTS_OK) {
                return e;
            }
            ants_der_tlv exts;
            e = ants_der_read(&ext_wrap, ANTS_DER_TAG_SEQUENCE, &exts);
            if (e != ANTS_OK) {
                return e;
            }
            out->extensions = exts.val;
            out->extensions_len = exts.len;
        } else {
            e = ants_der_skip(tbs);
            if (e != ANTS_OK) {
                return e;
            }
        }
    }
    return ANTS_OK;
}

ants_error_t ants_x509_cert_parse(const uint8_t *der, size_t der_len, ants_x509_cert *out)
{
    if (der == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);

    ants_der top;
    ants_der_init(&top, der, der_len);

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     * signatureValue }. Read the outer element, then walk its contents; the
     * tbsCertificate is the first element so it begins at the contents start. */
    ants_der_tlv cert;
    ants_error_t e = ants_der_read(&top, ANTS_DER_TAG_SEQUENCE, &cert);
    if (e != ANTS_OK) {
        return e;
    }
    if (!ants_der_eof(&top)) {
        return ANTS_ERROR_MALFORMED; /* trailing bytes after the certificate */
    }

    ants_der body;
    ants_der_init(&body, cert.val, cert.len);

    /* tbsCertificate: capture its full bytes (the signed range), then descend. */
    const uint8_t *tbs_start = cursor(&body);
    ants_der tbs;
    e = ants_der_enter(&body, ANTS_DER_TAG_SEQUENCE, &tbs);
    if (e != ANTS_OK) {
        return e;
    }
    out->tbs = tbs_start;
    out->tbs_len = (size_t)(cursor(&body) - tbs_start);

    e = parse_tbs_body(&tbs, out);
    if (e != ANTS_OK) {
        return e;
    }

    /* signatureAlgorithm AlgorithmIdentifier — surface its OID. */
    ants_der sig_alg;
    e = ants_der_enter(&body, ANTS_DER_TAG_SEQUENCE, &sig_alg);
    if (e != ANTS_OK) {
        return e;
    }
    ants_der_tlv sigoid;
    e = ants_der_read(&sig_alg, ANTS_DER_TAG_OID, &sigoid);
    if (e != ANTS_OK) {
        return e;
    }
    out->sig_alg_oid = sigoid.val;
    out->sig_alg_oid_len = sigoid.len;

    /* signatureValue BIT STRING. */
    e = read_bit_string_body(&body, &out->signature, &out->signature_len);
    if (e != ANTS_OK) {
        return e;
    }
    if (!ants_der_eof(&body)) {
        return ANTS_ERROR_MALFORMED; /* unexpected trailing element in Certificate */
    }
    return ANTS_OK;
}
