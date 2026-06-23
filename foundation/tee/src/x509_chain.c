/*
 * x509_chain.c — X.509 certificate-chain path validation (see x509_chain.h).
 *
 * Walks a leaf-first chain to a pinned self-signed root, checking, for every
 * (child, issuer) link:
 *   - name chaining: child.issuer == issuer.subject, byte-for-byte;
 *   - signature: child.tbs verifies under issuer's key, routed by child's
 *     signatureAlgorithm OID to the foundation/crypto verifier;
 *   - validity: child is within [notBefore, notAfter] at the caller's `now`;
 *   - issuer is a CA (BasicConstraints cA = TRUE).
 * The pinned root is additionally required to be self-signed.
 *
 * Only the signature algorithms the AMD and Intel vendor chains actually use
 * are accepted: RSASSA-PSS/SHA-384 (AMD ASK/ARK, RSA-4096) and
 * ecdsa-with-SHA256 (Intel PCK/Platform/Root, P-256). ECDSA signatures are
 * carried as a DER SEQUENCE { r, s } in the certificate and converted to the
 * fixed-width r||s the curve primitive consumes.
 */

#include "x509_chain.h"

#include "ants_crypto.h"
#include "der.h"
#include "x509.h"

#include <string.h>

/* signatureAlgorithm OBJECT IDENTIFIER value octets (after the 0x06 tag/len). */
static const uint8_t OID_RSASSA_PSS[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a};
static const uint8_t OID_ECDSA_SHA256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
/* id-ce-basicConstraints (2.5.29.19). */
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55, 0x1d, 0x13};

static bool oid_eq(const uint8_t *oid, size_t oid_len, const uint8_t *want, size_t want_len)
{
    return oid != NULL && oid_len == want_len && memcmp(oid, want, want_len) == 0;
}

/* A Name (issuer/subject) is matched as raw DER, no canonicalisation: the
 * vendor chains issue with byte-identical encodings, which is what RFC 5280
 * permits a relying party to require. */
static bool name_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    return a != NULL && b != NULL && a_len == b_len && memcmp(a, b, a_len) == 0;
}

/* Strip leading 0x00 sign octets from a DER INTEGER magnitude (DER permits at
 * most one, before a high-bit-set value). */
static void trim_leading_zeros(const uint8_t **p, size_t *n)
{
    while (*n > 1 && (*p)[0] == 0x00) {
        (*p)++;
        (*n)--;
    }
}

/*
 * Convert an ECDSA signature DER SEQUENCE { r INTEGER, s INTEGER } into the
 * fixed-width big-endian r||s (each component `half` bytes) the curve verifier
 * takes. `out` must hold 2*half bytes.
 */
static ants_error_t ecdsa_sig_to_rs(const uint8_t *sig, size_t sig_len, size_t half, uint8_t *out)
{
    memset(out, 0, 2 * half);

    ants_der r;
    ants_der_init(&r, sig, sig_len);
    ants_der seq;
    ants_error_t e = ants_der_enter(&r, ANTS_DER_TAG_SEQUENCE, &seq);
    if (e != ANTS_OK) {
        return e;
    }
    if (!ants_der_eof(&r)) {
        return ANTS_ERROR_MALFORMED; /* trailing bytes after the signature */
    }

    ants_der_tlv ri, si;
    e = ants_der_read(&seq, ANTS_DER_TAG_INTEGER, &ri);
    if (e != ANTS_OK) {
        return e;
    }
    e = ants_der_read(&seq, ANTS_DER_TAG_INTEGER, &si);
    if (e != ANTS_OK) {
        return e;
    }
    if (!ants_der_eof(&seq)) {
        return ANTS_ERROR_MALFORMED;
    }

    const uint8_t *rp = ri.val;
    size_t rn = ri.len;
    const uint8_t *sp = si.val;
    size_t sn = si.len;
    trim_leading_zeros(&rp, &rn);
    trim_leading_zeros(&sp, &sn);
    if (rn == 0 || sn == 0 || rn > half || sn > half) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(out + (half - rn), rp, rn);
    memcpy(out + half + (half - sn), sp, sn);
    return ANTS_OK;
}

/* Verify that `child`'s tbsCertificate was signed by `issuer`'s key, dispatched
 * on child's signatureAlgorithm OID. */
static ants_error_t verify_link_sig(const ants_x509_cert *child, const ants_x509_cert *issuer)
{
    if (oid_eq(child->sig_alg_oid, child->sig_alg_oid_len, OID_RSASSA_PSS, sizeof OID_RSASSA_PSS)) {
        if (issuer->key_kind != ANTS_X509_KEY_RSA) {
            return ANTS_ERROR_MALFORMED;
        }
        uint8_t digest[ANTS_SHA384_HASH_SIZE];
        ants_error_t e = ants_sha384(child->tbs, child->tbs_len, digest);
        if (e != ANTS_OK) {
            return e;
        }
        /* RSASSA-PSS with SHA-384/MGF1-SHA-384/salt-48 is the only RSA-PSS
         * profile in the protocol (AMD ASK/ARK); the digest length selects it
         * inside ants_rsa_pss_verify. */
        return ants_rsa_pss_verify(issuer->rsa_modulus,
                                   issuer->rsa_modulus_len,
                                   issuer->rsa_exponent,
                                   issuer->rsa_exponent_len,
                                   digest,
                                   sizeof digest,
                                   child->signature,
                                   child->signature_len);
    }

    if (oid_eq(child->sig_alg_oid,
               child->sig_alg_oid_len,
               OID_ECDSA_SHA256,
               sizeof OID_ECDSA_SHA256)) {
        if (issuer->key_kind != ANTS_X509_KEY_EC || issuer->curve != ANTS_X509_CURVE_P256) {
            return ANTS_ERROR_MALFORMED;
        }
        uint8_t digest[ANTS_SHA256_HASH_SIZE];
        ants_error_t e = ants_sha256(child->tbs, child->tbs_len, digest);
        if (e != ANTS_OK) {
            return e;
        }
        uint8_t rs[ANTS_ECDSA_P256_SIG_SIZE];
        e = ecdsa_sig_to_rs(
            child->signature, child->signature_len, ANTS_ECDSA_P256_SIG_SIZE / 2, rs);
        if (e != ANTS_OK) {
            return e;
        }
        return ants_ecdsa_p256_verify(issuer->ec_point, digest, sizeof digest, rs);
    }

    /* Anything else — incl. ecdsa-with-SHA384: no vendor chain signs a
     * certificate with a P-384 key (VCEK is a P-384 leaf, it signs the SNP
     * report, not a cert), so it is not a chain-link algorithm here. */
    return ANTS_ERROR_MALFORMED;
}

/* Parse two ASCII decimal digits at p into 0..99. */
static ants_error_t two_digits(const uint8_t *p, int *out)
{
    if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') {
        return ANTS_ERROR_MALFORMED;
    }
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return ANTS_OK;
}

/* Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
 * algorithm). Valid for any y; m in [1,12], d in [1,31]. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/*
 * Convert a DER X.509 Time (UTCTime "YYMMDDHHMMSSZ" or GeneralizedTime
 * "YYYYMMDDHHMMSSZ", both Zulu) to seconds since the Unix epoch.
 */
static ants_error_t time_to_epoch(uint8_t tag, const uint8_t *v, size_t n, int64_t *out)
{
    int year, mon, day, hh, mm, ss;
    if (tag == ANTS_DER_TAG_UTC_TIME) {
        int yy, cc;
        if (n != 13 || v[12] != 'Z') {
            return ANTS_ERROR_MALFORMED;
        }
        if (two_digits(v, &yy) != ANTS_OK) {
            return ANTS_ERROR_MALFORMED;
        }
        /* RFC 5280: YY < 50 => 20YY, else 19YY. */
        cc = (yy < 50) ? 2000 : 1900;
        year = cc + yy;
        v += 2;
    } else if (tag == ANTS_DER_TAG_GENERALIZED_TIME) {
        int hi, lo;
        if (n != 15 || v[14] != 'Z') {
            return ANTS_ERROR_MALFORMED;
        }
        if (two_digits(v, &hi) != ANTS_OK || two_digits(v + 2, &lo) != ANTS_OK) {
            return ANTS_ERROR_MALFORMED;
        }
        year = hi * 100 + lo;
        v += 4;
    } else {
        return ANTS_ERROR_MALFORMED;
    }

    if (two_digits(v, &mon) != ANTS_OK || two_digits(v + 2, &day) != ANTS_OK ||
        two_digits(v + 4, &hh) != ANTS_OK || two_digits(v + 6, &mm) != ANTS_OK ||
        two_digits(v + 8, &ss) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60) {
        return ANTS_ERROR_MALFORMED;
    }

    int64_t days = days_from_civil(year, mon, day);
    *out = days * 86400 + (int64_t)hh * 3600 + (int64_t)mm * 60 + ss;
    return ANTS_OK;
}

/* notBefore <= now <= notAfter. */
static ants_error_t within_validity(const ants_x509_cert *c, int64_t now)
{
    int64_t nb, na;
    ants_error_t e = time_to_epoch(c->not_before_tag, c->not_before, c->not_before_len, &nb);
    if (e != ANTS_OK) {
        return e;
    }
    e = time_to_epoch(c->not_after_tag, c->not_after, c->not_after_len, &na);
    if (e != ANTS_OK) {
        return e;
    }
    if (now < nb || now > na) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/*
 * True iff the certificate carries a BasicConstraints extension asserting
 * cA = TRUE. Walks Extensions ::= SEQUENCE OF Extension, each
 *   Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
 *                            extnValue OCTET STRING }
 * and, for BasicConstraints, decodes
 *   BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
 * from the extnValue OCTET STRING. Absent extension or absent/false cA => not
 * a CA.
 */
static bool is_ca(const ants_x509_cert *c)
{
    if (c->extensions == NULL || c->extensions_len == 0) {
        return false;
    }
    ants_der r;
    ants_der_init(&r, c->extensions, c->extensions_len);
    while (!ants_der_eof(&r)) {
        ants_der ext;
        if (ants_der_enter(&r, ANTS_DER_TAG_SEQUENCE, &ext) != ANTS_OK) {
            return false;
        }
        ants_der_tlv id;
        if (ants_der_read(&ext, ANTS_DER_TAG_OID, &id) != ANTS_OK) {
            return false;
        }
        uint8_t t;
        if (ants_der_peek_tag(&ext, &t) != ANTS_OK) {
            return false;
        }
        if (t == ANTS_DER_TAG_BOOLEAN) { /* optional `critical` flag — consume */
            ants_der_tlv crit;
            if (ants_der_read(&ext, ANTS_DER_TAG_BOOLEAN, &crit) != ANTS_OK) {
                return false;
            }
        }
        ants_der_tlv val;
        if (ants_der_read(&ext, ANTS_DER_TAG_OCTET_STRING, &val) != ANTS_OK) {
            return false;
        }
        if (!oid_eq(id.val, id.len, OID_BASIC_CONSTRAINTS, sizeof OID_BASIC_CONSTRAINTS)) {
            continue;
        }
        ants_der bc;
        ants_der_init(&bc, val.val, val.len);
        ants_der seq;
        if (ants_der_enter(&bc, ANTS_DER_TAG_SEQUENCE, &seq) != ANTS_OK) {
            return false;
        }
        uint8_t bt;
        if (ants_der_peek_tag(&seq, &bt) != ANTS_OK || bt != ANTS_DER_TAG_BOOLEAN) {
            return false; /* empty SEQUENCE or cA absent => default FALSE */
        }
        ants_der_tlv ca;
        if (ants_der_read(&seq, ANTS_DER_TAG_BOOLEAN, &ca) != ANTS_OK) {
            return false;
        }
        return ca.len == 1 && ca.val[0] == 0xFF; /* DER BOOLEAN TRUE */
    }
    return false;
}

ants_error_t ants_x509_chain_verify(const uint8_t *const certs_der[],
                                    const size_t certs_len[],
                                    size_t n_certs,
                                    const uint8_t *root_der,
                                    size_t root_len,
                                    int64_t now_unix,
                                    ants_x509_cert *out_leaf)
{
    if (certs_der == NULL || certs_len == NULL || root_der == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (n_certs == 0 || n_certs > ANTS_X509_CHAIN_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }

    ants_x509_cert chain[ANTS_X509_CHAIN_MAX];
    for (size_t i = 0; i < n_certs; i++) {
        if (certs_der[i] == NULL) {
            return ANTS_ERROR_INVALID_ARG;
        }
        ants_error_t e = ants_x509_cert_parse(certs_der[i], certs_len[i], &chain[i]);
        if (e != ANTS_OK) {
            return e;
        }
    }

    ants_x509_cert root;
    ants_error_t e = ants_x509_cert_parse(root_der, root_len, &root);
    if (e != ANTS_OK) {
        return e;
    }

    /* The pinned trust anchor must be a self-signed CA, currently valid, whose
     * signature verifies under its own key. */
    if (!name_eq(root.subject, root.subject_len, root.issuer, root.issuer_len)) {
        return ANTS_ERROR_MALFORMED;
    }
    if (!is_ca(&root)) {
        return ANTS_ERROR_MALFORMED;
    }
    e = within_validity(&root, now_unix);
    if (e != ANTS_OK) {
        return e;
    }
    e = verify_link_sig(&root, &root);
    if (e != ANTS_OK) {
        return e;
    }

    /* Walk leaf -> top: each child is name-chained to and signed by its issuer
     * (the next cert up, or the pinned root for the top intermediate), is
     * currently valid, and is issued by a CA. The leaf itself is CA-exempt. */
    for (size_t i = 0; i < n_certs; i++) {
        const ants_x509_cert *child = &chain[i];
        const ants_x509_cert *issuer = (i + 1 < n_certs) ? &chain[i + 1] : &root;

        if (!name_eq(child->issuer, child->issuer_len, issuer->subject, issuer->subject_len)) {
            return ANTS_ERROR_MALFORMED;
        }
        e = within_validity(child, now_unix);
        if (e != ANTS_OK) {
            return e;
        }
        if (!is_ca(issuer)) {
            return ANTS_ERROR_MALFORMED;
        }
        e = verify_link_sig(child, issuer);
        if (e != ANTS_OK) {
            return e;
        }
    }

    if (out_leaf != NULL) {
        *out_leaf = chain[0];
    }
    return ANTS_OK;
}
