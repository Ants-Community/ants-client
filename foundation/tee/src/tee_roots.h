/*
 * tee_roots.h — pinned vendor TEE attestation root certificates (trust anchors).
 *
 * RFC-0005 attestation chains terminate at a vendor root that is PINNED in the
 * binary: trust comes from this pin, never from the (attacker-controlled)
 * certificate chain carried inside a quote/report. ants_attestation_verify
 * hands these to ants_x509_chain_verify as the trust anchor.
 *
 * v1 pins the production x86-server roots:
 *   - Intel SGX Root CA — anchors every Intel DCAP chain (SGX + TDX): the
 *     PCK -> Platform CA -> Root CA chain embedded in a TDX quote.
 *   - AMD ARK-Milan — anchors the AMD SEV-SNP chain on Zen3 (Milan): the
 *     VCEK -> ASK -> ARK chain carried in the report's GHCB cert table. AMD's
 *     ARK is per-CPU-family, so each family is its own distinct pin (Genoa and
 *     later add their own ARK as those vendors are brought up).
 *
 * Internal to foundation/tee.
 */

#ifndef ANTS_TEE_ROOTS_H
#define ANTS_TEE_ROOTS_H

#include <stddef.h>
#include <stdint.h>

/* Intel SGX Root CA, self-signed (CN=Intel SGX Root CA), ECDSA P-256. */
extern const uint8_t ANTS_TEE_INTEL_SGX_ROOT_CA_DER[];
extern const size_t ANTS_TEE_INTEL_SGX_ROOT_CA_DER_LEN;

/* AMD ARK-Milan, self-signed (CN=ARK-Milan), RSA-4096 RSASSA-PSS/SHA-384. */
extern const uint8_t ANTS_TEE_AMD_ARK_MILAN_DER[];
extern const size_t ANTS_TEE_AMD_ARK_MILAN_DER_LEN;

#endif /* ANTS_TEE_ROOTS_H */
