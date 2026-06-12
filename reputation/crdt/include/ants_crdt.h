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
 * Scope of THIS module:
 *   - the canonical-CBOR fault-proof wire format (envelope + the
 *     per-class evidence schemas), float-free per RFC-0008 §1.1/§1.3;
 *   - VERIFY(π) for fault_type = equivocation — the gold-standard fault
 *     (RFC-0004 §"Partition recovery / Equivocation slashing"): two
 *     statements signed by the SAME subject over the SAME (domain, epoch,
 *     slot) with DIFFERENT payloads. Verification is two Ed25519 checks
 *     and an inequality — a few lines of obviously-correct code, exactly
 *     as the RFC intends;
 *   - VERIFY(π) for fault_type = invalid-transition — fabrication made
 *     attributable (RFC-0004 v0.7 §"Why the committee cannot fabricate"):
 *     the subject signed an L2 block whose summary commits bytes that are
 *     not a valid fault proof. One Ed25519 check over the block hash, a
 *     Merkle inclusion fold, and the cited bytes' own VERIFY verdict;
 *   - the BLAKE3 content-address used by the G-Set to dedupe proofs;
 *   - the G-Set container, pruning, and the late-joiner snapshot.
 *
 * Deliberately NOT here (later PRs, each its own RFC-0004 section):
 * archive-node redundancy (§"Archive nodes"), gossip propagation
 * (Component #6), and the remaining fault types (bond-misadmission,
 * selective-disclosure-forgery, vendor-revocation, key-rotation
 * equivocation land as the layers they depend on come online). The G-Set
 * container, pruning + the late-joiner protocol, and the
 * INVALID_TRANSITION fault class landed in later Component #7/#8 PRs and
 * are part of this header now.
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
 *   INVALID_TRANSITION — the subject signed (attested) an L2 block whose
 *                        epoch summary commits, in its confirmed_proofs
 *                        Merkle root, bytes that are NOT a valid Layer-1
 *                        fault proof — fabrication (RFC-0004 v0.7 §"Why
 *                        the committee cannot fabricate"). Deliberately
 *                        SIGNER-attributable: neither committee membership
 *                        nor block finality is required (or verifiable
 *                        context-free) — the signature over the block hash
 *                        is itself the culpable act, exactly like an
 *                        equivocation signature. IMPLEMENTED here; see
 *                        ants_crdt_verify for the conditions.
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

/*
 * An invalid-transition proof envelope wraps the attested block, the
 * signature, the cited committed bytes, and the Merkle inclusion path.
 * Framing overhead beyond (block_len + cited_len + path_len): the envelope
 * map(4), the evidence array(6), the 66-byte signature byte-string, two
 * <=9-byte uints (leaf index, leaf count) and the byte-string headers.
 * 256 is a safe ceiling.
 */
#define ANTS_CRDT_INVALID_TRANSITION_OVERHEAD_MAX 256u

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

/*
 * Build an INVALID_TRANSITION fault proof: pack an attested L2 block, the
 * subject's attestation signature, and the cited committed bytes (with
 * their Merkle inclusion path) into the canonical envelope. Like the
 * equivocation encoder, this serialises only — it does not sign and does
 * not check anything cryptographic; VERIFY is the checker.
 *
 * Envelope is the same canonical CBOR map(4) (subject / fault_type /
 * epoch / evidence) with fault_type = ANTS_FAULT_INVALID_TRANSITION and
 * evidence a native array(6), elements in this fixed order:
 *
 *   0: block  (bytes)     the COMPLETE canonical block encoding (the
 *                         reputation/chain wire form: map(4) {1: height,
 *                         2: prev_block_hash, 3: degraded_seed,
 *                         4: epoch-summary bytes}).
 *   1: sig    (bytes 64)  the subject's Ed25519 signature over the
 *                         32-byte block hash BLAKE3(block) — the exact
 *                         message committee attestations sign
 *                         (reputation/chain finality).
 *   2: cited  (bytes)     the committed bytes the proof claims are not a
 *                         valid fault proof.
 *   3: index  (uint)      the cited leaf's position among the confirmed
 *                         set's leaves.
 *   4: n_leaves (uint)    the confirmed set's total leaf count (>= 1).
 *   5: path   (bytes)     the Merkle sibling hashes from leaf to root, a
 *                         whole number of 32-byte siblings (empty for a
 *                         single-leaf set).
 *
 * `epoch` MUST equal the block's epoch-summary epoch for the proof to
 * verify (the envelope epoch is what G-Set pruning orders by, so it is
 * bound to the contested epoch). `path` may be NULL only if `path_len`
 * is 0.
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL (or empty block
 *         / cited, n_leaves == 0, or index >= n_leaves); BUFFER_TOO_SMALL
 *         if cap is insufficient (buf untouched).
 */
ants_error_t ants_crdt_invalid_transition_encode(const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE],
                                                 uint64_t epoch,
                                                 const uint8_t *block,
                                                 size_t block_len,
                                                 const uint8_t sig[ANTS_CRDT_SIG_SIZE],
                                                 const uint8_t *cited,
                                                 size_t cited_len,
                                                 uint64_t leaf_index,
                                                 uint64_t n_leaves,
                                                 const uint8_t *path,
                                                 size_t path_len,
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
 * For ANTS_FAULT_INVALID_TRANSITION, VERIFY returns ANTS_OK iff ALL hold:
 *   - the evidence is a well-formed array(6) (see the encoder), with
 *     index < n_leaves and the path length exactly matching the
 *     (index, n_leaves) tree position;
 *   - `block` decodes as a canonical reputation/chain block (map(4)
 *     {height, prev_block_hash, degraded_seed, summary}) whose embedded
 *     epoch summary is itself canonical — structural validation only; a
 *     finding's severity VALUE is deliberately not range-checked, so a
 *     future severity cannot make this build mis-verdict a future block;
 *   - the envelope's epoch equals the summary's epoch;
 *   - `sig` verifies under `subject` over the 32-byte block hash
 *     BLAKE3(block) — the attested act;
 *   - BLAKE3(cited), folded at (index, n_leaves) with `path`, reproduces
 *     the summary's confirmed_proofs root — the block really commits the
 *     cited bytes (the Merkle scheme mirrors reputation/chain
 *     bit-for-bit);
 *   - the cited bytes are NOT a valid fault proof, for a reason that is a
 *     PERMANENT property of the bytes: either they fail to decode as a
 *     fault envelope under the pinned RFC-0008 §1.1 canonical profile
 *     (the profile is the wire's foundation — every content-id and
 *     signature depends on it, so it cannot grow), or they decode to a
 *     class this build implements whose VERIFY says MALFORMED or
 *     NON_CANONICAL (a deployed class's rules never change). A cited
 *     proof that VERIFIES is no fabrication (the accusation itself is
 *     MALFORMED). A cited proof of class INVALID_TRANSITION is MALFORMED
 *     evidence (no nesting — the structural recursion bound). A cited
 *     envelope of a class this build cannot judge (unassigned, or a
 *     class verdict of UNSUPPORTED_TYPE / NOT_IMPLEMENTED) yields
 *     NOT_IMPLEMENTED for the whole proof: a typed "don't know", never a
 *     slash — so no build ever admits a proof whose citation another
 *     build deems valid.
 *
 * @return ANTS_OK              π is a valid fault proof (VERIFY == true);
 *         ANTS_ERROR_INVALID_ARG    buf is NULL or len is 0;
 *         ANTS_ERROR_NON_CANONICAL  well-formed but non-canonical CBOR;
 *         ANTS_ERROR_UNSUPPORTED_TYPE  unknown/unassigned fault class
 *                                   (>= ANTS_FAULT__RESERVED_MIN) — fail
 *                                   closed, never a valid slash;
 *         ANTS_ERROR_NOT_IMPLEMENTED  this build cannot reach a definitive
 *                                   verdict (an INVALID_TRANSITION proof
 *                                   citing a fault class it cannot judge)
 *                                   — fail closed, never a valid slash;
 *         ANTS_ERROR_MALFORMED  well-formed canonical CBOR but NOT a valid
 *                                   fault: wrong evidence shape, mismatched
 *                                   (domain/epoch/slot), identical payloads,
 *                                   wrong field lengths, a bad signature, a
 *                                   Merkle path that does not reproduce the
 *                                   root, or a cited proof that verifies.
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

/* ------------------------------------------------------------------------ */
/* The G-Set — the grow-only set of verified fault proofs                    */
/* ------------------------------------------------------------------------ */

/*
 * The Layer-1 CRDT: a grow-only set (G-Set) of self-authenticating fault
 * proofs (RFC-0004 v0.6 §"Layer 1", reference sketch §1390). You can only
 * add, never remove (pruning after L2 epoch-confirmation is a separate,
 * later operation). Every element is a proof that passed VERIFY, so the
 * set's defining invariant is: *every member verifies*.
 *
 * Two honest peers that have received the same proofs hold the same set;
 * the only divergence the protocol admits is which proofs each has seen
 * yet (set convergence, not value disagreement) — which is what gossip
 * (Component #6) closes. Merge is therefore a plain set union, and it is
 * idempotent, commutative, and associative (the CRDT laws).
 *
 * The handle is heap-allocated and OPAQUE — unlike the fixed-size
 * caller-owned `_opaque[CTX_SIZE]` contexts elsewhere in the client, a
 * G-Set is unbounded, so it cannot live in a caller struct. This is the
 * module's first allocator. The set OWNS a private copy of every proof's
 * bytes (it must re-serve them to gossip peers and to late joiners), so
 * the caller's buffer need not outlive the insert.
 */
typedef struct ants_crdt ants_crdt_t;

/*
 * Create an empty G-Set. On success `*out_set` is a handle the caller must
 * later pass to ants_crdt_destroy.
 *
 * @return ANTS_OK with *out_set set; ANTS_ERROR_INVALID_ARG if out_set is
 *         NULL; ANTS_ERROR_MALFORMED on allocation failure (the project's
 *         established out-of-memory convention — see cache/semantic).
 */
ants_error_t ants_crdt_init(ants_crdt_t **out_set);

/* Free a G-Set and every proof it owns. NULL is a no-op. */
void ants_crdt_destroy(ants_crdt_t *set);

/*
 * Insert a serialized fault proof (the gossip-receive path of the
 * reference sketch). VERIFY-gated: runs ants_crdt_verify on the bytes;
 * if that does not return ANTS_OK the proof is rejected and the set is
 * unchanged (the VERIFY verdict is returned verbatim). Never trust a
 * peer's claim that a proof verifies — this is the deserialization
 * boundary where the check is enforced.
 *
 * Idempotent by content-id: inserting a proof already present is ANTS_OK
 * with *out_inserted = false and no duplicate stored. On a new valid
 * proof the set takes a private copy of the bytes.
 *
 * @param out_inserted optional; true iff a new element was added, false if
 *        it was already present. May be NULL.
 * @return ANTS_OK on insert-or-already-present; the VERIFY verdict
 *         (MALFORMED / NON_CANONICAL / UNSUPPORTED_TYPE / NOT_IMPLEMENTED /
 *         INVALID_ARG) on a proof that does not verify; ANTS_ERROR_MALFORMED
 *         on allocation failure.
 */
ants_error_t
ants_crdt_insert(ants_crdt_t *set, const uint8_t *proof, size_t len, bool *out_inserted);

/*
 * Does the set contain the exact proof with this content-id (the BLAKE3
 * address from ants_crdt_content_id)? O(1) expected.
 */
bool ants_crdt_contains(const ants_crdt_t *set,
                        const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE]);

/*
 * is_slashed_locally (RFC-0004 reference sketch §1400): does the set hold
 * ANY proof whose subject == `subject`? This is the query the tenure
 * computation and the serving path gate on — a slashed identity's T is
 * zeroed and it is refused service. O(n) over the set (proofs-per-subject
 * is ~1 in practice; a subject index is a later optimisation).
 */
bool ants_crdt_is_slashed(const ants_crdt_t *set, const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE]);

/* Number of proofs currently in the set. */
size_t ants_crdt_size(const ants_crdt_t *set);

/*
 * Merge `src` into `dst` (CRDT union): every element of `src` not already
 * in `dst` is copied in (a private copy of the bytes). Elements of an
 * ants_crdt_t are verified by the invariant (each passed VERIFY at its own
 * insert), so merge does NOT re-verify — the trust boundary is
 * ants_crdt_insert, not an in-process union of two sets we built. Used to
 * fold a late-joiner snapshot or a peer's set into the local view.
 * Idempotent and commutative.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL; ANTS_ERROR_MALFORMED on
 *         allocation failure (dst may be partially merged — still a valid,
 *         smaller union, since the operation is monotone).
 */
ants_error_t ants_crdt_merge(ants_crdt_t *dst, const ants_crdt_t *src);

/*
 * Visit every proof in the set (iteration order unspecified). The callback
 * receives the content-id and the proof bytes, which ALIAS the set's
 * storage and are valid only for the duration of the call. Returning false
 * stops the iteration early. Used to serialise the set for gossip or a
 * late-joiner snapshot without exposing the internal layout.
 */
typedef bool (*ants_crdt_visit_fn)(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                                   const uint8_t *proof,
                                   size_t len,
                                   void *ctx);
void ants_crdt_enumerate(const ants_crdt_t *set, ants_crdt_visit_fn fn, void *ctx);

/* ------------------------------------------------------------------------ */
/* Pruning + the late-joiner snapshot (RFC-0004 v0.6 §"G-Set pruning and    */
/* late-joiner protocol")                                                   */
/*                                                                          */
/* The G-Set is append-only, which is correct for security (monotone under  */
/* attack) but unbounded over time. The RFC bounds it: once the L2 chain    */
/* confirms an epoch, proofs from that epoch become prunable, with the L2   */
/* Merkle root the canonical record from then on. This PR lands the         */
/* L1-side MECHANISM — prune-by-epoch and the snapshot data plane a late    */
/* joiner imports — driven by a caller-supplied cutoff. The cutoff POLICY   */
/* (which epoch L2 has confirmed) and the historical on-demand fetch +      */
/* Merkle-inclusion check belong to the L2 chain (Component #8), not built  */
/* yet; see the per-function notes.                                         */
/* ------------------------------------------------------------------------ */

/*
 * Prune every proof with `epoch < min_epoch_keep`, bounding storage
 * (RFC-0004 §"G-Set pruning"). Because the table is open-addressed with no
 * tombstones, this rebuilds it compactly around the survivors (their proof
 * bytes are moved, not re-copied or re-verified — survivors already hold
 * the set invariant). The remaining set is still a valid G-Set; pruning a
 * proof does not un-slash anyone whose slash the L2 chain has recorded —
 * that authority moves to L2, which this client does not yet implement, so
 * a caller running without L2 should prune conservatively (keep recent
 * epochs) or not at all.
 *
 * `min_epoch_keep` is the FIRST epoch to retain: a proof is kept iff its
 * envelope epoch is >= min_epoch_keep. The caller supplies it; wiring it to
 * "one epoch after the latest L2-confirmed epoch" is Component #8.
 *
 * @param out_pruned optional; set to the number of proofs removed.
 * @return ANTS_OK (set rebuilt); ANTS_ERROR_INVALID_ARG if set is NULL;
 *         ANTS_ERROR_MALFORMED on allocation failure (set left UNCHANGED).
 */
ants_error_t ants_crdt_prune(ants_crdt_t *set, uint64_t min_epoch_keep, size_t *out_pruned);

/*
 * A safe upper bound, in bytes, for the buffer ants_crdt_snapshot_encode
 * needs for the current set. Lets a caller size the buffer in one shot
 * rather than retry-on-BUFFER_TOO_SMALL. 0 if set is NULL.
 */
size_t ants_crdt_snapshot_bound(const ants_crdt_t *set);

/*
 * Serialise the whole set into one canonical-CBOR frame — a definite-length
 * `array(N)` of the N proof byte-strings — for transfer to a late joiner
 * (RFC-0004 §Late-joiner protocol step 2, "sync the current L1 CRDT").
 *
 * Element ORDER is the set's internal (hash) order, which is unspecified
 * and peer-dependent; the frame is therefore not byte-identical across
 * peers and is NOT itself content-addressed or signed. That is fine: the
 * importer dedupes by content-id, so the imported set is order-independent.
 * Each element IS canonical (it passed VERIFY), and array element order is
 * unconstrained by RFC 8949 §4.2.1, so the frame passes
 * ants_cbor_is_canonical regardless.
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL; BUFFER_TOO_SMALL
 *         if cap is short (use ants_crdt_snapshot_bound).
 */
ants_error_t
ants_crdt_snapshot_encode(const ants_crdt_t *set, uint8_t *buf, size_t cap, size_t *out_len);

/*
 * Import a snapshot frame (from ants_crdt_snapshot_encode on a peer) into
 * `set`, the receiving half of the late-joiner protocol. Every proof is
 * re-run through VERIFY before admission — a snapshot from another peer is
 * the SAME untrusted boundary as gossip, so we never trust the sender's
 * claim that its proofs are valid. A proof that fails VERIFY is SKIPPED
 * (counted in *out_rejected), not fatal: a misbehaving peer cannot abort
 * the whole sync, only fail to contribute its bad entries (the
 * safe-direction default). Valid proofs are unioned in, deduped by
 * content-id (so re-importing is idempotent).
 *
 * A frame that is not well-formed canonical CBOR, or whose elements are not
 * byte-strings, is rejected wholesale (MALFORMED / NON_CANONICAL) — that is
 * a structural failure, distinct from an individual unverifiable proof.
 *
 * @param out_added    optional; number of NEW proofs admitted.
 * @param out_rejected optional; number of elements that failed VERIFY.
 * @return ANTS_OK; INVALID_ARG on NULL/empty; MALFORMED or NON_CANONICAL on
 *         a bad frame; MALFORMED on allocation failure mid-import (the set
 *         keeps whatever was admitted so far — a valid, smaller union).
 */
ants_error_t ants_crdt_snapshot_merge(ants_crdt_t *set,
                                      const uint8_t *buf,
                                      size_t len,
                                      size_t *out_added,
                                      size_t *out_rejected);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CRDT_H */
