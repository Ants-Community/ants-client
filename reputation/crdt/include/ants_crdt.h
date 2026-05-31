/*
 * ants_crdt.h — Layer 1: the consensus-free fault G-Set (Component #7,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * The architecture's load-bearing negative layer. The ONLY thing the
 * protocol gossips globally about reputation is a grow-only set (G-Set)
 * CRDT of self-authenticating fault proofs. You can only add, never
 * remove; every element proves its own validity:
 *
 *   FaultProof {
 *     subject:    peer_id   // who is accused (32-byte Ed25519 pubkey)
 *     fault_type: enum      // equivocation | invalid-transition | ...
 *     evidence:   bytes     // type-specific, self-contained
 *     epoch:      u64       // when (for pruning + ordering)
 *   }
 *
 *   VERIFY(π) → bool   is a PURE, DETERMINISTIC, CONTEXT-FREE function.
 *
 * The critical property (RFC-0004 §"Layer 1"): VERIFY requires no external
 * state. Given only the proof bytes, every honest peer computes the same
 * verdict — no quorum, no view, no "as of" qualifier. That is what lets a
 * global reputation layer exist WITHOUT consensus: a monotone,
 * self-authenticating fact needs one honest gossip path, ever — not an
 * honest majority (RFC-0004 §"The structural win").
 *
 * Scope of THIS module (PR1 of Component #7):
 *   - the canonical-CBOR fault-proof wire format (envelope + the
 *     equivocation evidence schema), float-free per RFC-0008 §1.1/§1.3;
 *   - VERIFY(π) for fault_type = equivocation — the gold-standard fault
 *     (RFC-0004 §"Partition recovery / Equivocation slashing"): two
 *     statements signed by the SAME subject over the SAME (domain, epoch,
 *     slot) with DIFFERENT payloads. Verification is two Ed25519 checks
 *     and an inequality — a few lines of obviously-correct code, exactly
 *     as the RFC intends;
 *   - the BLAKE3 content-address used by the G-Set to dedupe proofs.
 *
 * Deliberately NOT here (later PRs, each its own RFC-0004 section): the
 * G-Set container itself (insert/contains/merge/is_slashed), G-Set
 * pruning + the late-joiner protocol (§"G-Set pruning and late-joiner
 * protocol"), archive-node redundancy (§"Archive nodes"), gossip
 * propagation (Component #6), and the other fault types
 * (invalid-state-transition needs the L2 chain; bond-misadmission,
 * selective-disclosure-forgery, vendor-revocation, key-rotation
 * equivocation land as the layers they depend on come online).
 *
 * WIRE FORMAT IS DRAFT. The byte layout below is defined by this module
 * pending formalisation in RFC-0008 (the same status the DHT and cache
 * wire formats carried before their spec sections existed). It MUST be
 * upstreamed to RFC-0008 before any two independent implementations
 * gossip fault proofs to each other.
 *
 * No malloc, no threads, no hidden global state; caller-owned buffers
 * throughout (the G-Set container in a later PR is the first allocator).
 * Spec: RFC-0004 v0.6; RFC-0008 v0.5 §1.1 (canonical CBOR), §2.1 (BLAKE3),
 * §3.1 (Ed25519). Component README: ants-client/reputation/crdt/README.md.
 */

#ifndef ANTS_CRDT_H
#define ANTS_CRDT_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

/* A peer (the fault subject) is its 32-byte Ed25519 public key, the
 * protocol peer-id. Kept local rather than importing the transport type,
 * matching reputation/identity. MUST equal ANTS_ED25519_PUBKEY_SIZE. */
#define ANTS_CRDT_PEER_ID_SIZE 32u

/* Ed25519 signature size (mirrors ANTS_ED25519_SIG_SIZE = 64). Each
 * equivocation statement carries one. */
#define ANTS_CRDT_SIG_SIZE 64u

/* Content-address size: BLAKE3-256 over the canonical proof bytes
 * (mirrors ANTS_BLAKE3_HASH_SIZE = 32). */
#define ANTS_CRDT_CONTENT_ID_SIZE 32u

/*
 * Fault classes (the `fault_type` enum). Integer-stable and append-only,
 * exactly like ants_error_t: a deployed value never changes its number,
 * deprecated values are reserved not recycled, so a peer that meets a
 * future class it does not implement returns a typed "don't know" rather
 * than mis-verifying.
 *
 *   EQUIVOCATION       — the subject signed two conflicting statements
 *                        over the same (domain, epoch, slot). Verifiable
 *                        offline by anyone (RFC-0004 §"Legitimacy =
 *                        cryptographically-attributable enumerated
 *                        fault"). IMPLEMENTED here.
 *   INVALID_TRANSITION — the subject (an L2 committee member) attested an
 *                        invalid state transition. Reserved: verifying it
 *                        needs the L2 chain (Component #8), so VERIFY
 *                        returns ANTS_ERROR_NOT_IMPLEMENTED for now.
 *
 * Values >= ANTS_FAULT__RESERVED_MIN are unassigned; VERIFY rejects them
 * with ANTS_ERROR_UNSUPPORTED_TYPE (fail closed — an unknown fault class
 * is never treated as a valid slash).
 */
#define ANTS_FAULT_EQUIVOCATION       0u
#define ANTS_FAULT_INVALID_TRANSITION 1u
#define ANTS_FAULT__RESERVED_MIN      2u

/*
 * Encoding-size guidance. The encoders never overflow — they return
 * ANTS_ERROR_BUFFER_TOO_SMALL with the buffer untouched if `cap` is short,
 * so the canonical sizing pattern is realloc-on-BUFFER_TOO_SMALL. These
 * macros let a caller size a buffer right the first time.
 *
 * A statement body is a canonical CBOR map(4) {domain, epoch, slot,
 * payload}; everything but the payload fits comfortably under this many
 * bytes (map header + four 1-byte integer keys + three <=9-byte uints +
 * the payload byte-string header).
 */
#define ANTS_CRDT_STATEMENT_OVERHEAD_MAX 48u

/*
 * An equivocation proof envelope wraps the two signed statement bodies.
 * Framing overhead beyond the two body lengths: the envelope map(4)
 * {subject, fault_type, epoch, evidence}, the evidence array(2), the two
 * per-statement array(2) wrappers, two 66-byte signature byte-strings, and
 * the byte-string headers. 256 is a safe ceiling.
 */
#define ANTS_CRDT_EQUIVOCATION_OVERHEAD_MAX 256u

/* ------------------------------------------------------------------------ */
/* Statement encoding (the bytes a subject signs)                           */
/* ------------------------------------------------------------------------ */

/*
 * Encode an equivocation STATEMENT BODY as canonical CBOR (RFC-0008 §1.1)
 * into `buf` — the exact bytes the subject's Ed25519 signature is computed
 * over. Definite-length map(4) of integer-keyed pairs in ascending order:
 *
 *   0: domain  (uint)   protocol context separating one signed-statement
 *                       kind from another (block proposal vs vote vs
 *                       key-rotation announcement, …). Domain separation:
 *                       two statements only equivocate if they share it.
 *                       Value space is assigned by RFC-0008; opaque here.
 *   1: epoch   (uint)   the epoch the statement is about.
 *   2: slot    (uint)   the slot within the (domain, epoch).
 *   3: payload (bytes)  what the subject committed to at that slot. The
 *                       thing that must NOT differ for two signatures over
 *                       the same (domain, epoch, slot) to be honest.
 *
 * Float-free by construction. `payload` may be NULL only if
 * `payload_len` is 0.
 *
 * @return ANTS_OK with *out_len set to the encoded length; INVALID_ARG on
 *         NULL (buf/out_len, or payload with non-zero len);
 *         BUFFER_TOO_SMALL if cap is insufficient (buf untouched).
 */
ants_error_t ants_crdt_statement_encode(uint64_t domain,
                                        uint64_t epoch,
                                        uint64_t slot,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len);

/* ------------------------------------------------------------------------ */
/* Fault-proof encoding                                                      */
/* ------------------------------------------------------------------------ */

/*
 * Build an equivocation FAULT PROOF: pack two already-signed statement
 * bodies into the canonical envelope. Each `sig_*` MUST be the subject's
 * Ed25519 signature over the corresponding `body_*` bytes (as produced by
 * ants_crdt_statement_encode + ants_ed25519_sign); this function does not
 * sign and does not check the signatures — it serialises. VERIFY is the
 * checker.
 *
 * Envelope is a canonical CBOR map(4), integer keys ascending:
 *   0: subject    (bytes 32)   the accused peer-id.
 *   1: fault_type (uint)       ANTS_FAULT_EQUIVOCATION.
 *   2: epoch      (uint)       the contested epoch (== both statements').
 *   3: evidence   (array)      a native CBOR array(2) — NOT a byte-string
 *                              wrapping a sub-document, so the whole proof
 *                              is one canonical document encoded in a
 *                              single pass. Each element is an array(2)
 *                              [ body (bytes), sig (bytes 64) ], where
 *                              `body` is the exact statement bytes the
 *                              subject signed (opaque at the envelope
 *                              level; VERIFY re-decodes it as a statement).
 *
 * The caller is responsible for the two bodies being a genuine
 * equivocation (same domain/epoch/slot, different payload); a malformed
 * "proof" simply fails VERIFY downstream.
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL; BUFFER_TOO_SMALL
 *         if cap is insufficient (buf untouched).
 */
ants_error_t ants_crdt_equivocation_encode(const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE],
                                           uint64_t epoch,
                                           const uint8_t *body_a,
                                           size_t body_a_len,
                                           const uint8_t sig_a[ANTS_CRDT_SIG_SIZE],
                                           const uint8_t *body_b,
                                           size_t body_b_len,
                                           const uint8_t sig_b[ANTS_CRDT_SIG_SIZE],
                                           uint8_t *buf,
                                           size_t cap,
                                           size_t *out_len);

/* ------------------------------------------------------------------------ */
/* Fault-proof decoding (structural, no crypto)                             */
/* ------------------------------------------------------------------------ */

/*
 * A decoded view over a fault-proof envelope. All pointers ALIAS into the
 * caller's input buffer (no copy); the view is valid only while that
 * buffer lives. The decode validates the envelope's structure and
 * canonical encoding but performs NO cryptographic check — use
 * ants_crdt_verify for the verdict.
 */
typedef struct {
    const uint8_t *subject;  /* 32 bytes, aliases input            */
    uint64_t fault_type;     /* one of ANTS_FAULT_*                 */
    uint64_t epoch;          /* contested epoch                     */
    const uint8_t *evidence; /* type-specific bytes, aliases input  */
    size_t evidence_len;     /* length of evidence                  */
} ants_fault_proof_view_t;

/*
 * Decode + canonically validate a fault-proof envelope into `out`. Does
 * NOT verify signatures or evidence semantics; it only proves the bytes
 * are a well-formed canonical envelope and extracts the four fields.
 *
 * @return ANTS_OK with *out populated (pointers alias `buf`);
 *         INVALID_ARG on NULL;
 *         MALFORMED if the bytes are not a well-formed envelope;
 *         NON_CANONICAL if well-formed but the encoding violates
 *         RFC 8949 §4.2.1 (non-shortest int, unsorted keys, trailing
 *         bytes, indefinite length, disallowed major type).
 */
ants_error_t
ants_crdt_fault_proof_decode(const uint8_t *buf, size_t len, ants_fault_proof_view_t *out);

/* ------------------------------------------------------------------------ */
/* VERIFY(π) — the pure, deterministic, context-free verdict                */
/* ------------------------------------------------------------------------ */

/*
 * VERIFY(π): is `buf[0..len)` a VALID fault proof? Pure, deterministic,
 * context-free (RFC-0004 §"Layer 1") — the same bytes yield the same
 * verdict on every honest peer, with no external state. This is the
 * gate the G-Set applies before admitting (and re-applies on merge —
 * never trust a peer's claim that a proof verifies).
 *
 * For ANTS_FAULT_EQUIVOCATION, VERIFY returns ANTS_OK iff ALL hold:
 *   - the envelope and both statement bodies are well-formed canonical
 *     CBOR;
 *   - both statements share the envelope's epoch, and share each other's
 *     domain and slot;
 *   - the two payloads DIFFER (same commitment is not a fault);
 *   - both signatures verify under `subject` over their respective body
 *     bytes (two Ed25519 checks).
 *
 * @return ANTS_OK              π is a valid fault proof (VERIFY == true);
 *         ANTS_ERROR_INVALID_ARG    buf is NULL or len is 0;
 *         ANTS_ERROR_NON_CANONICAL  well-formed but non-canonical CBOR;
 *         ANTS_ERROR_UNSUPPORTED_TYPE  unknown/unassigned fault class
 *                                   (>= ANTS_FAULT__RESERVED_MIN) — fail
 *                                   closed, never a valid slash;
 *         ANTS_ERROR_NOT_IMPLEMENTED  a defined class this build cannot
 *                                   yet verify (ANTS_FAULT_INVALID_TRANSITION,
 *                                   pending the L2 chain);
 *         ANTS_ERROR_MALFORMED  well-formed canonical CBOR but NOT a valid
 *                                   fault: wrong evidence shape, mismatched
 *                                   (domain/epoch/slot), identical payloads,
 *                                   wrong field lengths, or a bad signature.
 *
 * Insertable-into-the-G-Set ⟺ ants_crdt_verify(...) == ANTS_OK.
 */
ants_error_t ants_crdt_verify(const uint8_t *buf, size_t len);

/* ------------------------------------------------------------------------ */
/* Content address                                                          */
/* ------------------------------------------------------------------------ */

/*
 * Content-address a fault proof: BLAKE3(buf[0..len)) → `out_id`
 * (RFC-0004 reference sketch: `h = BLAKE3(canonical_encode(proof))`). The
 * G-Set is keyed by this id so the same proof from two gossip paths
 * dedupes to one element. Computes the hash over the bytes verbatim; the
 * caller is expected to pass canonical bytes (those that pass VERIFY).
 *
 * @return ANTS_OK with `out_id` set; INVALID_ARG on NULL or len 0.
 */
ants_error_t
ants_crdt_content_id(const uint8_t *buf, size_t len, uint8_t out_id[ANTS_CRDT_CONTENT_ID_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CRDT_H */
