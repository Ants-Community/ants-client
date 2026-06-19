/*
 * ants_tee.h — TEE attestation harness (Component #3).
 *
 * Spec reference: RFC-0005 (Identity & TEE attestation, all sections).
 *
 * Status: **a v1 deliverable, in progress** (un-deferred from v2.x on
 * 2026-06-15). The functions below still return
 * `ANTS_ERROR_NOT_IMPLEMENTED` — the per-vendor attestation_verify lands
 * incrementally (Intel TDX + AMD SEV-SNP first), built on the ECDSA
 * P-256/P-384 + SHA-256/512 primitives now in foundation/crypto. See
 * `foundation/tee/README.md` for scope + the open `[CLAIM]` issue at
 * Ants-Community/ants#6.
 *
 * Why the stub exists in v1.0: upstream components (network,
 * reputation, identity) reference attestations in their data structures
 * — peer-handshake bindings, trustee key rotation, bond admission, and
 * committee role assumption all carry attestation metadata. Having the
 * API compiled means those components can integrate against it now
 * without having to mock or `#ifdef` a future shape. When each vendor's
 * verify lands the integration sites need no changes.
 *
 * The TEE does two jobs. As RFC-0002's fourth verifiability leg (re-
 * execution, scheme (C) probabilistic, reputation, TEE) it is optional —
 * the other three legs compose without it. But as the identity root it
 * is not: RFC-0005 "one attested CPU, one peer identity" and RFC-0004
 * "one CPU, one voice" both reduce to the attested population, which is
 * why this is a v1 deliverable, not v2.x.
 */

#ifndef ANTS_TEE_H
#define ANTS_TEE_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Vendor families                                                          */
/*                                                                          */
/* Per RFC-0005 §Multi-vendor TEE families. The five vendor IDs are pinned  */
/* here so consumers can encode/decode them in CBOR without depending on    */
/* a separate enum table. Adding a vendor is a v-bump for this header.      */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_tee_vendor_t;

#define ANTS_TEE_VENDOR_UNKNOWN       ((ants_tee_vendor_t)0)
#define ANTS_TEE_VENDOR_INTEL_TDX     ((ants_tee_vendor_t)1)
#define ANTS_TEE_VENDOR_AMD_SEV_SNP   ((ants_tee_vendor_t)2)
#define ANTS_TEE_VENDOR_ARM_CCA       ((ants_tee_vendor_t)3)
#define ANTS_TEE_VENDOR_APPLE_SE      ((ants_tee_vendor_t)4)
#define ANTS_TEE_VENDOR_QUALCOMM_QSEE ((ants_tee_vendor_t)5)

/* ------------------------------------------------------------------------ */
/* Constants enforced uniformly across vendors                              */
/*                                                                          */
/* Per RFC-0005 §Attestation freshness window + §Vendor revocation          */
/* propagation timing + §Multi-vendor reputation weighting.                 */
/* ------------------------------------------------------------------------ */

/* Default attestation freshness: 30 days. Configurable via the protocol
 * params struct at higher layers; the harness must honour the supplied
 * value, not a baked-in literal. */
#define ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS ((int64_t)(30 * 24 * 3600))

/* Default vendor revocation propagation bound: 72 hours. After this
 * window, revoked attestations are network-wide rejected. */
#define ANTS_TEE_DEFAULT_REVOCATION_BOUND_SECONDS ((int64_t)(72 * 3600))

/* Multi-vendor reputation weights per RFC-0005 §Multi-vendor reputation
 * weighting. The harness exposes the lookup; reputation layer uses it
 * when computing a peer's effective reputation. */
#define ANTS_TEE_WEIGHT_SINGLE_NUM 10 /* multiplier 1.0 */
#define ANTS_TEE_WEIGHT_SINGLE_DEN 10
#define ANTS_TEE_WEIGHT_DUAL_NUM   12 /* multiplier 1.2 */
#define ANTS_TEE_WEIGHT_DUAL_DEN   10
#define ANTS_TEE_WEIGHT_TRIPLE_NUM 14 /* multiplier 1.4 */
#define ANTS_TEE_WEIGHT_TRIPLE_DEN 10

/* ------------------------------------------------------------------------ */
/* Attestation record                                                       */
/*                                                                          */
/* The opaque vendor blob is the only field whose internal layout differs   */
/* per-vendor; the surrounding metadata (peer_pubkey, tcb_identifier,       */
/* issued_at_unix, expires_at_unix) is uniform.                             */
/*                                                                          */
/* `vendor_blob` is borrowed: the caller retains ownership and must keep    */
/* it alive for the lifetime of the ants_attestation_t. The library never   */
/* malloc()s on behalf of the caller (see foundation/ memory discipline).   */
/* ------------------------------------------------------------------------ */

#define ANTS_TEE_TCB_IDENTIFIER_SIZE 64

typedef struct {
    ants_tee_vendor_t vendor;
    /* The Ed25519 public key (32 bytes) that THIS attestation binds to
     * attested hardware. Comparison with peer-handshake pubkeys is the
     * way the protocol verifies that the same physical TEE produced
     * both this attestation and the peer's session signatures. */
    uint8_t peer_pubkey[32];
    /* Vendor-specific TCB identifier (firmware/microcode version
     * fingerprint). Format is vendor-defined; opaque to consumers
     * except for equality comparison against vendor revocation lists. */
    uint8_t tcb_identifier[ANTS_TEE_TCB_IDENTIFIER_SIZE];
    /* Issuance time (seconds since Unix epoch). Used by the freshness
     * window check; the harness does NOT consult a system clock —
     * callers supply the reference `now`. */
    int64_t issued_at_unix;
    /* Vendor-supplied expiry (seconds since Unix epoch). May be 0 if
     * the vendor doesn't carry a hard expiry; in that case the freshness
     * window alone enforces an upper bound. */
    int64_t expires_at_unix;
    /* Vendor-signed attestation blob (DCAP quote, SEV-SNP report, etc).
     * Borrowed pointer — caller owns the memory. */
    const uint8_t *vendor_blob;
    size_t vendor_blob_len;
} ants_attestation_t;

/* ------------------------------------------------------------------------ */
/* API surface                                                              */
/*                                                                          */
/* All functions return `ANTS_ERROR_NOT_IMPLEMENTED` in v1.0. The shape is  */
/* pinned so v1.0 consumers can integrate and v2.x can drop the real       */
/* implementation in without API churn.                                     */
/* ------------------------------------------------------------------------ */

/*
 * Generate a fresh attestation binding `peer_pubkey` to the local
 * vendor TEE. Output is written to `*out`; the caller does not need to
 * preallocate the `vendor_blob` — `ants_attestation_generate` may set
 * it to a library-owned static buffer that is overwritten on the next
 * call (the v2.x signature will document this precisely).
 */
ants_error_t ants_attestation_generate(ants_tee_vendor_t vendor,
                                       const uint8_t peer_pubkey[32],
                                       ants_attestation_t *out);

/*
 * Verify the attestation's vendor signature chain. Does NOT consult the
 * freshness window or revocation state — those are separate, composable
 * checks. Returns ANTS_OK on a valid signature chain;
 * ANTS_ERROR_MALFORMED on invalid blob, wrong vendor root, or bound
 * pubkey mismatch.
 */
ants_error_t ants_attestation_verify(const ants_attestation_t *att);

/*
 * Returns true iff `now - issued_at_unix < freshness_window_seconds`
 * AND `now < expires_at_unix` (when expires_at_unix != 0). Caller
 * supplies both `now` (UTC seconds) and the freshness window (typically
 * `ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS` but configurable per
 * RFC-0005 §Attestation freshness window).
 *
 * Returns false on a null pointer (safe default — treat unknown as
 * stale).
 */
bool ants_attestation_is_fresh(const ants_attestation_t *att,
                               int64_t now,
                               int64_t freshness_window_seconds);

/*
 * Returns true iff the attestation's `tcb_identifier` appears on the
 * currently-loaded vendor revocation list for `att->vendor`. The
 * revocation list management API is intentionally not exposed in v1.0
 * — it will land alongside the real attestation_verify implementation
 * in v2.x.
 *
 * Until then, this function returns false (no attestation is considered
 * revoked because no list is loaded). Callers MUST treat
 * `ants_attestation_is_revoked() == false` as inconclusive when running
 * against the v1.0 stub; the harness will start surfacing true
 * positives only when v2.x ships.
 */
bool ants_attestation_is_revoked(const ants_attestation_t *att);

/* ------------------------------------------------------------------------ */
/* AMD SEV-SNP attestation report                                           */
/*                                                                          */
/* The first per-vendor structure parser + report-signature verifier. The  */
/* SNP `vendor_blob` (above) is, at its head, a 0x4A0-byte ATTESTATION_     */
/* REPORT structure (AMD SEV-SNP ABI spec, "ATTESTATION_REPORT Structure"); */
/* the trailing bytes carry the VCEK/ASK/ARK certificate table. This        */
/* section parses the fixed-layout report and verifies its signature        */
/* against a CALLER-SUPPLIED VCEK public key.                               */
/*                                                                          */
/* The VCEK is the leaf of the AMD certificate chain (VCEK -> ASK -> ARK).  */
/* Extracting the VCEK key from that X.509 chain — and validating the chain */
/* to the AMD root — is a separate, forthcoming step (it needs ASN.1/X.509  */
/* + RSA-4096 verification). Until that lands, this verifier takes the      */
/* leaf key as an input, which is exactly the contract a chain validator    */
/* will satisfy once it does: parse + chain-validate -> hand us the leaf.   */
/*                                                                          */
/* The report is signed with ECDSA P-384 over a SHA-384 digest of its       */
/* first 0x2A0 bytes (RFC-0005; the only SIGNATURE_ALGO SNP defines). The   */
/* digest + curve primitives live in foundation/crypto.                     */
/* ------------------------------------------------------------------------ */

/* Wire size of the fixed ATTESTATION_REPORT structure. */
#define ANTS_SNP_REPORT_SIZE 0x4A0 /* 1184 bytes */

/* Length of the prefix the signature covers: report bytes [0, 0x2A0). */
#define ANTS_SNP_SIGNED_PREFIX_LEN 0x2A0 /* 672 bytes */

/* Fixed field sizes (bytes), per the ABI structure. */
#define ANTS_SNP_FAMILY_ID_SIZE   16
#define ANTS_SNP_IMAGE_ID_SIZE    16
#define ANTS_SNP_REPORT_DATA_SIZE 64
#define ANTS_SNP_MEASUREMENT_SIZE 48
#define ANTS_SNP_HOST_DATA_SIZE   32
#define ANTS_SNP_REPORT_ID_SIZE   32
#define ANTS_SNP_CHIP_ID_SIZE     64

/* The only signature algorithm SNP defines: ECDSA P-384 with SHA-384. */
#define ANTS_SNP_SIG_ALGO_ECDSA_P384_SHA384 1

/* VCEK public key as the verifier consumes it: the raw 96-byte
 * uncompressed P-384 point X || Y, big-endian, no 0x04 prefix — exactly
 * what `ants_ecdsa_p384_verify` expects (== ANTS_ECDSA_P384_PUBKEY_SIZE).
 * An X.509 SubjectPublicKeyInfo stores X and Y big-endian already, so a
 * future chain validator can hand these 96 bytes straight through. */
#define ANTS_SNP_VCEK_PUBKEY_SIZE 96

/*
 * Decoded view of the stable, version-independent fields of an SNP
 * attestation report. Only fields whose offsets are identical across
 * report VERSION 2 and 3 are surfaced; the version-specific reserved
 * regions are not. Integers are host-order (decoded from the on-wire
 * little-endian); byte arrays are copied verbatim.
 */
typedef struct {
    uint32_t version;   /* report format version (2 or 3) */
    uint32_t guest_svn; /* guest security version number */
    uint64_t policy;    /* guest policy bitfield */
    uint8_t family_id[ANTS_SNP_FAMILY_ID_SIZE];
    uint8_t image_id[ANTS_SNP_IMAGE_ID_SIZE];
    uint32_t vmpl;                                  /* VMPL the report was requested at */
    uint32_t signature_algo;                        /* SIGNATURE_ALGO (see ANTS_SNP_SIG_ALGO_*) */
    uint64_t current_tcb;                           /* CurrentTcb */
    uint64_t platform_info;                         /* PLATFORM_INFO bitfield */
    uint8_t report_data[ANTS_SNP_REPORT_DATA_SIZE]; /* guest-supplied nonce; binds the peer key */
    uint8_t measurement[ANTS_SNP_MEASUREMENT_SIZE]; /* launch measurement */
    uint8_t host_data[ANTS_SNP_HOST_DATA_SIZE];     /* hypervisor-supplied data */
    uint8_t report_id[ANTS_SNP_REPORT_ID_SIZE];
    uint64_t reported_tcb;                  /* TCB the VCEK was derived at */
    uint8_t chip_id[ANTS_SNP_CHIP_ID_SIZE]; /* unique chip identifier */
} ants_snp_report_t;

/*
 * Parse the fixed-layout fields of an SNP attestation report.
 *
 * `report` must point to at least `report_len` bytes; `report_len` must
 * equal ANTS_SNP_REPORT_SIZE. On success the decoded fields are written
 * to `*out`. Parsing does NOT verify the signature (see
 * ants_snp_report_verify_signature) and does not gate on VERSION — it
 * only decodes; callers branch on `out->version` / `out->signature_algo`.
 *
 * Returns ANTS_OK on success, ANTS_ERROR_INVALID_ARG on a null pointer,
 * ANTS_ERROR_MALFORMED if `report_len != ANTS_SNP_REPORT_SIZE`.
 */
ants_error_t
ants_snp_report_parse(const uint8_t *report, size_t report_len, ants_snp_report_t *out);

/*
 * Verify the ECDSA P-384 / SHA-384 signature of an SNP attestation report
 * against the supplied VCEK public key.
 *
 * Recomputes SHA-384 over the signed prefix (report[0, 0x2A0)), converts
 * the report's little-endian R and S components to the big-endian form the
 * curve primitive expects, and checks them against `vcek_pubkey`
 * (ANTS_SNP_VCEK_PUBKEY_SIZE bytes, X || Y big-endian).
 *
 * This checks ONLY the report-to-VCEK signature. It does NOT validate the
 * VCEK certificate chain to the AMD root, nor freshness/revocation — those
 * are separate, composable checks. A caller that has not yet validated the
 * chain must not treat a pass here as a full attestation.
 *
 * Returns ANTS_OK if the signature is valid; ANTS_ERROR_MALFORMED on a
 * wrong-size report, an unsupported SIGNATURE_ALGO, non-canonical R/S
 * padding, or an invalid signature/key; ANTS_ERROR_INVALID_ARG on a null
 * pointer.
 */
ants_error_t ants_snp_report_verify_signature(const uint8_t *report,
                                              size_t report_len,
                                              const uint8_t vcek_pubkey[ANTS_SNP_VCEK_PUBKEY_SIZE]);

/* ------------------------------------------------------------------------ */
/* Intel TDX DCAP attestation quote (v4, ECDSA-P256)                        */
/*                                                                          */
/* The second per-vendor structure parser + signature verifier (after AMD   */
/* SEV-SNP above). An Intel TDX `vendor_blob` is a DCAP "quote": a 48-byte   */
/* header, a 584-byte TD report body (the trust domain's measurements),     */
/* then a variable-length signature section. Where SNP carries a single      */
/* report-to-VCEK signature, a TDX quote is a three-link chain, and this     */
/* verifier checks all three against a CALLER-SUPPLIED PCK leaf key:         */
/*                                                                          */
/*   1. the platform PCK leaf key signs SHA-256(the QE report);             */
/*   2. the Quoting Enclave (QE) report's report_data binds the per-quote   */
/*      attestation key (== SHA-256(att_key || qe_auth_data));              */
/*   3. that attestation key signs SHA-256(header || TD body).             */
/*                                                                          */
/* Together: PCK -> QE -> attestation key -> TD body. The PCK leaf is the    */
/* leaf of the Intel certificate chain (PCK -> Platform CA -> Root CA),      */
/* carried as a PEM chain inside the quote. Extracting that leaf from the    */
/* embedded X.509 chain — and validating the chain to the Intel root — is a  */
/* separate, forthcoming step (it needs ASN.1/X.509). Until it lands this    */
/* verifier takes the leaf key as input, exactly the contract that chain     */
/* validator will satisfy: parse + chain-validate -> hand us the leaf.       */
/*                                                                          */
/* All signatures are ECDSA P-256 over SHA-256, with r||s and the public     */
/* point X||Y stored big-endian — the form ants_ecdsa_p256_verify consumes   */
/* directly (no byte-order conversion, unlike SNP's little-endian R/S).      */
/* The curve + digest primitives live in foundation/crypto.                 */
/* ------------------------------------------------------------------------ */

/* Fixed sizes of the quote's leading, version-determined region. */
#define ANTS_TDX_QUOTE_HEADER_SIZE 48  /* 0x30 */
#define ANTS_TDX_QUOTE_BODY_SIZE   584 /* 0x248: the TDX-1.0 TD report body */

/* Header invariants this verifier requires (a v4 ECDSA-P256 TDX quote). */
#define ANTS_TDX_QUOTE_VERSION           4
#define ANTS_TDX_TEE_TYPE                0x00000081u /* TDX (SGX is 0x0) */
#define ANTS_TDX_ATT_KEY_TYPE_ECDSA_P256 2

/* Certification-data types (Intel DCAP). */
#define ANTS_TDX_CERT_TYPE_QE_REPORT 6 /* QE report + PCK chain */
#define ANTS_TDX_CERT_TYPE_PCK_CHAIN 5 /* PEM cert chain */

/* The QE report is a 384-byte SGX report body; its trailing 64-byte
 * report_data field carries the attestation-key binding. */
#define ANTS_TDX_QE_REPORT_SIZE 384 /* 0x180 */

/* Fixed TD-body field sizes (bytes). */
#define ANTS_TDX_QE_VENDOR_ID_SIZE 16
#define ANTS_TDX_TCB_SVN_SIZE      16
#define ANTS_TDX_MEASUREMENT_SIZE  48 /* mr_seam, mr_td, rtmr*, ... */
#define ANTS_TDX_REPORT_DATA_SIZE  64
#define ANTS_TDX_RTMR_COUNT        4

/* PCK leaf public key as the verifier consumes it: the raw 64-byte
 * uncompressed P-256 point X || Y, big-endian, no 0x04 prefix — exactly
 * what ants_ecdsa_p256_verify expects (== ANTS_ECDSA_P256_PUBKEY_SIZE). An
 * X.509 SubjectPublicKeyInfo stores X and Y big-endian already, so a future
 * chain validator can hand these 64 bytes straight through. */
#define ANTS_TDX_PCK_PUBKEY_SIZE 64

/* Upper bound on the QE authentication data length the binding hash will
 * accept. The Intel QE emits 32 bytes; this cap (foundation does no dynamic
 * allocation) is generous headroom. A larger value is rejected as malformed
 * rather than truncated. */
#define ANTS_TDX_QE_AUTH_DATA_MAX 1024

/*
 * Decoded view of the stable header + TD-body fields of a TDX v4 quote.
 * Integers are host-order (decoded from on-wire little-endian); byte arrays
 * are copied verbatim. The variable-length signature section is not
 * surfaced here (see ants_tdx_quote_verify_signature).
 */
typedef struct {
    uint16_t version;      /* quote format version (== 4) */
    uint16_t att_key_type; /* attestation key type (== 2, ECDSA P-256) */
    uint32_t tee_type;     /* == ANTS_TDX_TEE_TYPE */
    uint8_t qe_vendor_id[ANTS_TDX_QE_VENDOR_ID_SIZE];
    uint8_t tee_tcb_svn[ANTS_TDX_TCB_SVN_SIZE];
    uint8_t mr_seam[ANTS_TDX_MEASUREMENT_SIZE];        /* SEAM module measurement */
    uint8_t mr_signer_seam[ANTS_TDX_MEASUREMENT_SIZE]; /* SEAM signer */
    uint64_t seam_attributes;
    uint64_t td_attributes;                   /* TD attributes bitfield */
    uint64_t xfam;                            /* extended-features-allowed mask */
    uint8_t mr_td[ANTS_TDX_MEASUREMENT_SIZE]; /* TD measurement (the "what ran") */
    uint8_t mr_config_id[ANTS_TDX_MEASUREMENT_SIZE];
    uint8_t mr_owner[ANTS_TDX_MEASUREMENT_SIZE];
    uint8_t mr_owner_config[ANTS_TDX_MEASUREMENT_SIZE];
    uint8_t rtmr[ANTS_TDX_RTMR_COUNT][ANTS_TDX_MEASUREMENT_SIZE]; /* runtime-extendable */
    uint8_t report_data[ANTS_TDX_REPORT_DATA_SIZE]; /* guest-supplied; binds the peer key */
} ants_tdx_quote_t;

/*
 * Parse the fixed header + TD-body fields of a TDX v4 quote.
 *
 * `quote` must point to at least `quote_len` bytes; `quote_len` must be at
 * least ANTS_TDX_QUOTE_HEADER_SIZE + ANTS_TDX_QUOTE_BODY_SIZE (the variable
 * signature section may follow and is ignored here). Decoding the body
 * presupposes the v4 / TDX-1.0 layout, so unlike the SNP parser this one
 * gates on version and tee_type. Parsing does NOT verify any signature (see
 * ants_tdx_quote_verify_signature).
 *
 * Returns ANTS_OK on success, ANTS_ERROR_INVALID_ARG on a null pointer,
 * ANTS_ERROR_MALFORMED if the buffer is too short or version/tee_type are
 * not those of a v4 TDX quote.
 */
ants_error_t ants_tdx_quote_parse(const uint8_t *quote, size_t quote_len, ants_tdx_quote_t *out);

/*
 * Verify the full internal signature chain of a TDX v4 quote against the
 * supplied PCK leaf public key:
 *
 *   1. PCK leaf signs SHA-256(QE report)          [needs pck_leaf_pubkey]
 *   2. QE report binds the attestation key
 *      (qe_report.report_data == SHA-256(att_key || qe_auth_data))
 *   3. attestation key signs SHA-256(header || TD body)
 *
 * All three must hold. The attestation key and QE report are carried in the
 * quote; only the PCK leaf is external. This does NOT validate the PCK
 * certificate chain to the Intel root, nor freshness/revocation/TCB — those
 * are separate, composable checks. A caller that has not yet validated the
 * chain must not treat a pass here as a full attestation.
 *
 * Returns ANTS_OK if all three signatures/bindings hold; ANTS_ERROR_MALFORMED
 * on a too-short/inconsistent quote, wrong version/key-type/tee-type,
 * unsupported certification-data type, oversized QE auth data, or any failed
 * signature/binding; ANTS_ERROR_INVALID_ARG on a null pointer.
 */
ants_error_t
ants_tdx_quote_verify_signature(const uint8_t *quote,
                                size_t quote_len,
                                const uint8_t pck_leaf_pubkey[ANTS_TDX_PCK_PUBKEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_TEE_H */
