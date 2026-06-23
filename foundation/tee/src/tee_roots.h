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
 * (AMD's ARK is per-CPU-family; ARK-Milan lands with the SNP wiring.)
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

#endif /* ANTS_TEE_ROOTS_H */
