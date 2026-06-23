/*
 * x509_chain.h — X.509 certificate-chain path validation for TEE attestation.
 *
 * The closing half of the foundation/tee certificate-chain validator
 * (RFC-0005). The parser in x509.h turns one DER certificate into fields; this
 * walks a leaf-first chain of them up to a PINNED, self-signed trust-anchor
 * root and decides whether the leaf is genuinely descended from that root —
 * name chaining, per-link signature verification, validity windows, and the
 * BasicConstraints CA flag on issuers. On success it hands back the validated
 * leaf so its public key can be fed to the SNP/TDX report verifiers.
 *
 * This is what lets ants_attestation_verify replace "caller-supplied leaf key"
 * with "leaf key proven to chain to the vendor root":
 *   - AMD SEV-SNP: VCEK (EC P-384 leaf) -> ASK -> ARK, every link signed
 *     RSA-4096 RSASSA-PSS/SHA-384; pinned root = ARK-Milan (self-signed);
 *   - Intel TDX:   PCK (EC P-256 leaf) -> Platform CA -> Root CA, every link
 *     ECDSA P-256/SHA-256; pinned root = Intel SGX Root CA (self-signed).
 *
 * Trust comes from the root being PINNED in the binary by the caller, never
 * from the (attacker-controlled) chain: the supplied chain runs leaf ->
 * last-intermediate, and the top intermediate must be issued by — and verify
 * under — the separately-supplied pinned root. Per-link signatures are routed
 * by the child's signatureAlgorithm OID to the matching foundation/crypto
 * verifier; only the two algorithms these vendor chains use are accepted
 * (RSASSA-PSS/SHA-384 and ecdsa-with-SHA256). EC P-384 never signs a
 * certificate in either chain (VCEK is a leaf key, it signs the SNP report,
 * not a cert), so ecdsa-with-SHA384 is intentionally not accepted here.
 *
 * Allocation-free and clock-free: the caller supplies the reference time, as
 * everywhere else in the harness. Out of scope here, by design (separate,
 * composable checks per ants_tee.h): attestation freshness/expiry
 * (ants_attestation_is_fresh), TCB-level / revocation policy
 * (ants_attestation_is_revoked), and KeyUsage beyond the CA basic constraint.
 *
 * Internal to foundation/tee; exposed via this header (not ants_tee.h) so the
 * walk can be unit-tested in isolation against real vendor chains — see
 * tests/test_x509_chain.c + tests/cert_kat_vectors.h.
 */

#ifndef ANTS_TEE_X509_CHAIN_H
#define ANTS_TEE_X509_CHAIN_H

#include "ants_common.h"
#include "x509.h"

#include <stddef.h>
#include <stdint.h>

/* Upper bound on certificates in the supplied chain (leaf + intermediates,
 * excluding the pinned root). Both real chains need 2 (leaf + one
 * intermediate); the cap bounds the on-stack parse array since foundation does
 * no dynamic allocation. */
#define ANTS_X509_CHAIN_MAX 8

/*
 * Validate a leaf-first DER certificate chain up to a pinned self-signed root.
 *
 *   certs_der / certs_len / n_certs
 *       The chain as parallel arrays: certs_der[0] = leaf, certs_der[n_certs-1]
 *       = the intermediate whose issuer is the pinned root. n_certs must be in
 *       [1, ANTS_X509_CHAIN_MAX]. These bytes are attacker-controlled.
 *   root_der / root_len
 *       The pinned trust anchor: a self-signed root certificate the caller
 *       hardcodes in the binary (ARK-Milan / Intel SGX Root CA). Trust derives
 *       from this pin, not from the chain.
 *   now_unix
 *       Reference time (UTC seconds since epoch). Every certificate, including
 *       the root, must satisfy notBefore <= now_unix <= notAfter.
 *   out_leaf
 *       On ANTS_OK, the parsed and validated leaf certificate (its public key
 *       is now trusted — hand it to the SNP/TDX verifier). May be NULL.
 *
 * Walking each adjacent (child, issuer) pair from leaf towards the root, with
 * the pinned root as the final issuer, it requires:
 *   - child.issuer == issuer.subject, byte-for-byte (no canonicalisation);
 *   - child's signature verifies under issuer's public key, routed by child's
 *     signatureAlgorithm OID;
 *   - child is within its validity window at now_unix;
 *   - issuer asserts BasicConstraints cA = TRUE (the leaf itself is exempt);
 * and, for the pinned root: it is self-signed (subject == issuer), its
 * signature verifies under its own key, it is a CA, and it is within validity.
 *
 * Returns ANTS_OK if the whole path validates; ANTS_ERROR_MALFORMED on any
 * parse failure, name-chain break, signature failure, expired/not-yet-valid
 * certificate, missing CA constraint, or unsupported signature algorithm;
 * ANTS_ERROR_INVALID_ARG on a NULL pointer or out-of-range n_certs.
 */
ants_error_t ants_x509_chain_verify(const uint8_t *const certs_der[],
                                    const size_t certs_len[],
                                    size_t n_certs,
                                    const uint8_t *root_der,
                                    size_t root_len,
                                    int64_t now_unix,
                                    ants_x509_cert *out_leaf);

#endif /* ANTS_TEE_X509_CHAIN_H */
