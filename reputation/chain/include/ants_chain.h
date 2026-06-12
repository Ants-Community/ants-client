/*
 * ants_chain.h — Layer 2: the PoUH chain as ordered witness (Component #8,
 * RFC-0004 v0.6 §"Layer 2 — the PoUH chain as ordered witness").
 *
 * The architecture's *ordered* reputation layer, and deliberately the
 * unambitious one. Layer 1 (Component #7, the consensus-free fault G-Set)
 * destroys trust immediately, by anyone holding a self-authenticating
 * proof, with no consensus. What Layer 1 cannot do is count: rules of the
 * form "six medium events in thirty days ⇒ escalate" need a global ordered
 * tally across a window, which is what a chain is for and a CRDT is not.
 *
 * The chain is small, slow (30 s blocks, on purpose), and witnesses — it
 * does NOT judge:
 *
 *   - It records EpochSummary objects: {epoch, cutoff_time, a Merkle root
 *     over the Layer-1 fault proofs visible at the cutoff, the pattern
 *     findings crossed at that epoch}. It never records an individual
 *     slash — that already happened at Layer 1.
 *   - A rotating committee of K attested peers (VRF-selected, one CPU one
 *     voice) finalises each block at 2/3 signatures.
 *
 * THE LOAD-BEARING PROPERTY — the committee cannot fabricate. VERIFY(π)
 * (ants_crdt_verify) is pure and deterministic, so a summary that cites a
 * "fault proof" which does not actually verify is detectable by any peer
 * running VERIFY independently. A compromised committee can only SUPPRESS
 * (omit a real proof) or OMIT (miss a pattern) — both recovered by the
 * next independently-selected committee. It cannot fabricate a false
 * slash, cannot reverse an L1 slash (append-only), cannot un-slash a
 * subject. The chain's compromise scenario is DEGRADATION, not corruption
 * (RFC-0004 §"Why the committee cannot fabricate" / §"Graceful
 * degradation").
 *
 * Scope of THIS module (PR1 of Component #8 — SCAFFOLD): the full public
 * surface, the protocol structs (EpochSummary, PatternFinding, Block) and
 * tunable constants, all entry points present and validating against this
 * contract but returning ANTS_ERROR_NOT_IMPLEMENTED until their PR lands:
 *
 *   PR2  confirmed_proofs Merkle root + inclusion proof; EpochSummary
 *        canonical-CBOR codec (pure functions over bytes, no I/O).
 *   PR3  the pattern-rule engine (count L1 events per window/severity →
 *        findings; the §Slash-mechanics severity table).
 *   PR4  VRF committee selection (ECVRF-EDWARDS25519-SHA512-ELL2, RFC 9381)
 *        seeded by prev-block-hash + beacon.
 *   PR5  block hashing + the epoch-atomic signature scheme (Ed25519
 *        multi-sig for K ≤ BLS_TRANSITION_K, BLS12-381 aggregate above) +
 *        2/3 finality verification.
 *   PR6  partition recovery: Σ T_eff fork choice (reusing the §"saturating
 *        T → T_eff" transform from reputation/identity) + the
 *        social-Schelling threshold + same-height equivocation detection.
 *   PR7  drand beacon verification + VRF seed derivation (RFC-0008
 *        §4.2-4.3): the external-entropy input behind PR4's `beacon`
 *        parameter.
 *   PR8  block proposal + proposer election, the pure mempool→block step.
 *        RFC-0004's "mempool" is NOT a queue — the candidate block content
 *        IS the L1 CRDT state visible at the cutoff. Adds the
 *        `degraded_seed` block-header wire flag (RFC-0008 §4.3 drand
 *        outage), inside the signed bytes.
 *
 * WIRE FORMAT IS DRAFT. The byte layouts below (EpochSummary, Block, the
 * confirmed-proofs Merkle construction) are defined by this module pending
 * formalisation in RFC-0008 — the same status the DHT, cache, and L1
 * fault-proof formats carried before their spec sections existed. They
 * MUST be upstreamed before two independent implementations exchange
 * blocks. Numeric tunables (K, block time, the severity windows, T_CAP,
 * θ) are DRAFT b2-class testnet measurements; the RECIPE is the
 * deliverable, the VALUES are illustrative so the code runs and tests.
 *
 * Determinism is load-bearing throughout: every honest peer must compute
 * the same confirmed-proofs root from the same visible set, the same
 * committee from the same seed, the same T_eff from the same tenure, the
 * same finality verdict from the same signatures — no floats on any path a
 * second peer must reproduce (RFC-0009).
 *
 * Spec: RFC-0004 v0.6 §"Layer 2"; RFC-0008 v0.5 §1.1 (canonical CBOR),
 * §2.1 (BLAKE3), §3.1 (Ed25519), §3.3 (epoch-atomic signature scheme),
 * §4.2 (ECVRF). Component README: ants-client/reputation/chain/README.md.
 */

#ifndef ANTS_CHAIN_H
#define ANTS_CHAIN_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Sizes                                                                     */
/* ------------------------------------------------------------------------ */

/* A peer (committee member, fault subject) is its 32-byte Ed25519 public
 * key — the protocol peer-id. Kept local rather than importing the
 * transport type, matching reputation/{crdt,identity}. MUST equal
 * ANTS_ED25519_PUBKEY_SIZE and ANTS_CRDT_PEER_ID_SIZE. */
#define ANTS_CHAIN_PEER_ID_SIZE 32u

/* Ed25519 signature size (mirrors ANTS_ED25519_SIG_SIZE = 64). The
 * committee attestation primitive for K ≤ ANTS_CHAIN_BLS_TRANSITION_K. */
#define ANTS_CHAIN_SIG_SIZE 64u

/* BLAKE3-256 digest: block hash, confirmed-proofs Merkle root/node, and
 * the L1 proof content-id the root commits to (mirrors
 * ANTS_BLAKE3_HASH_SIZE = 32 and ANTS_CRDT_CONTENT_ID_SIZE). */
#define ANTS_CHAIN_HASH_SIZE 32u

/* BLS12-381 min-pubkey-size variant (mirrors the foundation/crypto
 * ants_bls_* wrappers): the aggregate committee-attestation primitive for
 * K > ANTS_CHAIN_BLS_TRANSITION_K. PK in G1 (48 B), signature in G2 (96 B). */
#define ANTS_CHAIN_BLS_PUBKEY_SIZE 48u
#define ANTS_CHAIN_BLS_SIG_SIZE    96u

/* ------------------------------------------------------------------------ */
/* Committee, finality, timing — DRAFT tunables (RFC-0008 §3.3, §7)          */
/* ------------------------------------------------------------------------ */

/* The mature committee size, K = 64 (RFC-0004 §"Consensus mechanism").
 * Bootstrap softening uses a smaller K (5 → 16 → 32 → 64) as the attested
 * population grows; this is the ceiling, not a fixed requirement. */
#define ANTS_CHAIN_COMMITTEE_K_MAX 64u

/* The epoch-atomic signature-scheme transition (RFC-0008 §3.3 with the
 * v0.4 disambiguation): committees of K ≤ 16 attest with an Ed25519
 * multi-signature; K > 16 with a BLS12-381 aggregate. K here is the
 * VRF-selected committee size, NOT an effectively-signing count. */
#define ANTS_CHAIN_BLS_TRANSITION_K 16u

/* 2/3 finality, as an exact integer fraction (no float): a block is final
 * once at least ceil(FINALITY_NUM * K / FINALITY_DEN) committee members
 * have signed it. */
#define ANTS_CHAIN_FINALITY_NUM 2u
#define ANTS_CHAIN_FINALITY_DEN 3u

/* Block-time target and the per-block finality timeout, seconds. Slow on
 * purpose — there is no urgency and slow makes adversarial conditions less
 * profitable. A block that misses 2/3 within the timeout is skipped; the
 * next committee proceeds with the same mempool. DRAFT (RFC-0004 §"Consensus
 * mechanism"). */
#define ANTS_CHAIN_BLOCK_TIME_S       30u
#define ANTS_CHAIN_FINALITY_TIMEOUT_S 120u

/* The saturating fork-choice cap T_CAP (RFC-0008 §7 T_FORK_CHOICE_CAP),
 * mirrored from reputation/identity's ANTS_REP_T_FORK_CHOICE_CAP so the two
 * components agree without a link-time dependency on the value. DRAFT —
 * roughly two years of κ-rate-cap-bound tenure. */
#define ANTS_CHAIN_T_FORK_CHOICE_CAP ((uint64_t)2000000000)

/* The social-Schelling threshold θ, as an exact integer fraction: if BOTH
 * forks have Σ T_eff > θ · Σ T_eff,total the partition is fundamentally
 * balanced and fork choice is handed to the social layer (RFC-0004
 * §"Social-Schelling fallback"). θ is the adversary-fraction tolerance
 * inherited from RFC-0002/0003. DRAFT default 1/3. */
#define ANTS_CHAIN_FORK_THETA_NUM 1u
#define ANTS_CHAIN_FORK_THETA_DEN 3u

/* ------------------------------------------------------------------------ */
/* Bounds                                                                    */
/* ------------------------------------------------------------------------ */

/* Max Merkle depth for the confirmed-proofs root, bounding the online
 * MMR-build stack so a hostile leaf count cannot drive unbounded memory.
 * Depth D admits up to 2^D leaves; 32 covers any plausible single epoch's
 * visible proof set (mirrors inference/orchestration's commit Merkle). */
#define ANTS_CHAIN_MERKLE_MAX_DEPTH 32u

/* Max pattern findings carried in one EpochSummary. A finding is one
 * (subject, rule) escalation; an epoch crossing more than this many is
 * pathological and split across epochs. */
#define ANTS_CHAIN_MAX_PATTERN_FINDINGS 256u

/* Compile-time upper bounds on the encoded sizes: an EpochSummary at the
 * maximum findings count, and a Block (the summary embedded as a byte-string
 * plus the small block header). Used to size the block-hash scratch buffer;
 * callers may size encode buffers from these or from the bound() helpers. */
#define ANTS_CHAIN_EPOCH_SUMMARY_ENCODED_MAX (80u + ANTS_CHAIN_MAX_PATTERN_FINDINGS * 96u)
#define ANTS_CHAIN_BLOCK_ENCODED_MAX         (64u + ANTS_CHAIN_EPOCH_SUMMARY_ENCODED_MAX)

/* ------------------------------------------------------------------------ */
/* Severity (the §Slash-mechanics escalation ladder)                         */
/* ------------------------------------------------------------------------ */

/*
 * Pattern-finding severity. Integer-stable and append-only exactly like
 * ants_error_t and the ANTS_FAULT_* fault classes: a deployed value never
 * changes its number, so a peer meeting a future severity it does not
 * implement treats it as unknown (fail-closed) rather than mis-ranking it.
 * The windows and event-count thresholds that map L1 events to each level
 * are protocol-defined DRAFT b2-class constants applied by the pattern
 * engine (PR3), NOT fixed here.
 *
 *   SOFT      1–2 fault events in the window.
 *   MEDIUM    3–5 events, or one cache-poisoning event.
 *   HARD      6+ events, repeated poisoning, or validator misconduct.
 *   TERMINAL  confirmed Sybil, deliberate consensus attack, repeated hard
 *             — irreversible.
 *
 * Values >= ANTS_CHAIN_SEVERITY__RESERVED_MIN are unassigned and rejected
 * (UNSUPPORTED_TYPE) wherever a severity is validated.
 */
#define ANTS_CHAIN_SEVERITY_SOFT          1u
#define ANTS_CHAIN_SEVERITY_MEDIUM        2u
#define ANTS_CHAIN_SEVERITY_HARD          3u
#define ANTS_CHAIN_SEVERITY_TERMINAL      4u
#define ANTS_CHAIN_SEVERITY__RESERVED_MIN 5u

/* ------------------------------------------------------------------------ */
/* Pattern-rule tunables — DRAFT b2-class (RFC-0004 §Slash mechanics)        */
/* ------------------------------------------------------------------------ */

/* The counting window the pattern engine bins L1 events into — the
 * "...in thirty days" of the §Slash-mechanics table. */
#define ANTS_CHAIN_PATTERN_WINDOW_S 2592000u /* 30 days */

/* Event-count escalation thresholds within the window (RFC-0004
 * §Slash-mechanics): 1-2 events → SOFT, 3-5 → MEDIUM, 6+ → HARD. TERMINAL
 * (confirmed Sybil / deliberate consensus attack / repeated hard) is not a
 * single-window count and is out of scope for the count rule. */
#define ANTS_CHAIN_PATTERN_SOFT_MIN_EVENTS   1u
#define ANTS_CHAIN_PATTERN_MEDIUM_MIN_EVENTS 3u
#define ANTS_CHAIN_PATTERN_HARD_MIN_EVENTS   6u

/* The id of the count-based escalation rule (PR3's single rule). Richer
 * rules — cache-poisoning, validator misconduct — need event typing the L1
 * fault classes don't yet carry, so they land in later PRs with new ids. */
#define ANTS_CHAIN_RULE_FAULT_COUNT_30D 1u

/* ------------------------------------------------------------------------ */
/* Fork-choice outcome                                                       */
/* ------------------------------------------------------------------------ */

/*
 * The verdict of ants_chain_fork_choice. FORK_A / FORK_B name the winning
 * fork by Σ T_eff; SOCIAL_SCHELLING means both forks clear θ — the
 * partition is balanced and recovery is the explicit, well-specified
 * social-fork process, not undefined behaviour (RFC-0004 §"Social-Schelling
 * fallback").
 */
#define ANTS_CHAIN_FORK_A                0
#define ANTS_CHAIN_FORK_B                1
#define ANTS_CHAIN_FORK_SOCIAL_SCHELLING 2

/* ------------------------------------------------------------------------ */
/* Protocol objects                                                          */
/* ------------------------------------------------------------------------ */

/*
 * A pattern finding: the L2 committee's statement that a (subject, rule)
 * escalation threshold was crossed among the L1 proofs visible at the
 * epoch cutoff. It is an INTERPRETATION of self-authenticating facts, not
 * a fact itself — disputable per RFC-0004 §"Slash mechanics" (a separate,
 * larger committee re-counts against the underlying proofs), whereas the
 * L1 slash it summarises stands as long as VERIFY passes.
 */
typedef struct {
    uint8_t subject[ANTS_CHAIN_PEER_ID_SIZE]; /* the accused peer-id        */
    uint64_t rule_id;                         /* which protocol rule fired  */
    uint64_t window_s;                        /* the rule's window, seconds */
    uint64_t count;                           /* events counted in window   */
    uint32_t severity;                        /* one of ANTS_CHAIN_SEVERITY */
} ants_chain_pattern_finding_t;

/*
 * The signable core of an epoch summary (RFC-0004 §"What gets recorded").
 * The committee attestations that finalise it are NOT part of this struct:
 * signatures are computed OVER its canonical encoding, so they cannot be
 * inside the bytes they sign — they ride on the enclosing Block. This is
 * the same "sign a canonical core, attestations wrap it" shape used for the
 * commit-at-send object (inference/orchestration) and the L1 statement
 * body (reputation/crdt).
 *
 * `findings` aliases caller storage; on decode it points into a
 * caller-supplied array (see ants_chain_epoch_summary_decode).
 */
typedef struct {
    uint64_t epoch;
    uint64_t cutoff_time; /* unix seconds; CRDT state observed at this T     */
    uint8_t confirmed_proofs[ANTS_CHAIN_HASH_SIZE]; /* Merkle root over the
                                                     * L1 proofs visible at
                                                     * the cutoff           */
    const ants_chain_pattern_finding_t *findings;
    size_t n_findings;
} ants_chain_epoch_summary_t;

/*
 * One L1 fault event, the input to the pattern engine (PR3). The committee
 * derives these by enumerating the L1 G-Set (ants_crdt_enumerate) and
 * decoding each visible proof's (subject, epoch, fault_type); `timestamp`
 * is the proof's event time used for window counting.
 */
typedef struct {
    uint8_t subject[ANTS_CHAIN_PEER_ID_SIZE];
    uint64_t timestamp;  /* unix seconds of the L1 event */
    uint64_t fault_type; /* one of ANTS_FAULT_* (reputation/crdt)            */
} ants_chain_event_t;

/*
 * A block: its height, the hash of the previous block (the chain link),
 * and the epoch summary it confirms. The committee attestations that
 * finalise it are passed separately to the finality functions (they sign
 * the block hash, which is computed over the canonical encoding of the
 * fields below). `summary.findings` aliases caller storage as above.
 */
typedef struct {
    uint64_t height;
    uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE];
    /* The proposer derived this block's committee from the DEGRADED VRF seed
     * (ants_chain_vrf_seed_degraded) because drand was unavailable (RFC-0008
     * §4.3). Part of the canonical encoding — committee members attest to the
     * degradation claim when they sign the block hash; whether the fallback
     * was legitimate (the 30-second hard floor) is the runtime policy each
     * member checks before signing. */
    bool degraded_seed;
    ants_chain_epoch_summary_t summary;
} ants_chain_block_t;

/* ======================================================================== */
/* PR2 — confirmed_proofs Merkle root + inclusion proof                      */
/* ======================================================================== */

/*
 * Compute the confirmed-proofs Merkle root over the L1 fault proofs a
 * committee observed at the epoch cutoff (RFC-0004 §"What gets recorded":
 * `confirmed_proofs = MerkleRoot(visible_proofs)`). The leaves are the
 * BLAKE3 content-ids of the visible proofs (ants_crdt_content_id), passed
 * STRICTLY ASCENDING — that canonical order is what makes the root
 * reproducible by any honest peer regardless of its G-Set's internal
 * (hash) iteration order. Strict ascent also implies no duplicates, which
 * a set of content-ids satisfies by construction.
 *
 * Domain-separated, malloc-free, with a bounded online MMR build:
 *   leaf  = BLAKE3(0x00 ‖ content_id)
 *   node  = BLAKE3(0x01 ‖ left ‖ right)
 * a lone trailing node is PROMOTED (not duplicated). n == 0 yields the
 * documented empty root BLAKE3(0x02) (an epoch with no visible proofs is
 * legitimate and must have a well-defined root).
 *
 * @return ANTS_OK with `out_root` set; INVALID_ARG on NULL out_root, or
 *         NULL content_ids with n != 0, or n exceeding 2^MERKLE_MAX_DEPTH;
 *         NON_CANONICAL if content_ids are not strictly ascending.
 */
ants_error_t ants_chain_confirmed_root(const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                       size_t n,
                                       uint8_t out_root[ANTS_CHAIN_HASH_SIZE]);

/*
 * Produce the Merkle inclusion path for the leaf at `index` among `n`
 * strictly-ascending content-ids: the sibling hashes from leaf to root,
 * `out_path_len` bytes (a whole number of ANTS_CHAIN_HASH_SIZE-byte
 * siblings). Lets a reader prove a specific L1 proof is committed by an
 * epoch summary's confirmed_proofs without holding the whole visible set.
 *
 * @return ANTS_OK with `out_path`/`out_path_len` set; INVALID_ARG on NULL
 *         or index >= n or n == 0; BUFFER_TOO_SMALL if path_cap is short
 *         (out_path_len set to the needed length); NON_CANONICAL if the
 *         content_ids are not strictly ascending.
 */
ants_error_t ants_chain_confirmed_prove(const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                        size_t n,
                                        size_t index,
                                        uint8_t *out_path,
                                        size_t path_cap,
                                        size_t *out_path_len);

/*
 * Verify an inclusion path: does `leaf_content_id` at `index` among `n`
 * leaves, folded with `path`, reproduce `root`? A cryptographic mismatch
 * is a FALSE VERDICT (*out_ok = false, return ANTS_OK), not an error — only
 * a malformed call is an error (mirrors the inference/orchestration and
 * fault-proof VERIFY conventions).
 *
 * @return ANTS_OK with *out_ok set; INVALID_ARG on NULL, index >= n,
 *         n == 0, or a path_len that is not a whole number of siblings or
 *         disagrees with n.
 */
ants_error_t ants_chain_confirmed_verify(const uint8_t leaf_content_id[ANTS_CHAIN_HASH_SIZE],
                                         size_t index,
                                         size_t n,
                                         const uint8_t *path,
                                         size_t path_len,
                                         const uint8_t root[ANTS_CHAIN_HASH_SIZE],
                                         bool *out_ok);

/* ======================================================================== */
/* PR2 — EpochSummary canonical-CBOR codec                                   */
/* ======================================================================== */

/*
 * A safe upper bound, in bytes, for ants_chain_epoch_summary_encode on
 * `s`, so a caller can size a buffer in one shot instead of
 * retry-on-BUFFER_TOO_SMALL. 0 if s is NULL.
 */
size_t ants_chain_epoch_summary_bound(const ants_chain_epoch_summary_t *s);

/*
 * Encode an EpochSummary as canonical CBOR (RFC-0008 §1.1) — a
 * definite-length, float-free, integer-keyed map in ascending key order,
 * with `findings` as a nested array of fixed-shape maps. This is the exact
 * byte sequence committee attestations sign (via the enclosing block hash).
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL or an out-of-range
 *         severity / n_findings; BUFFER_TOO_SMALL if cap is short (size with
 *         ants_chain_epoch_summary_bound; partial bytes may have been written
 *         into buf, *out_len untouched).
 */
ants_error_t ants_chain_epoch_summary_encode(const ants_chain_epoch_summary_t *s,
                                             uint8_t *buf,
                                             size_t cap,
                                             size_t *out_len);

/*
 * Decode + canonically validate an EpochSummary. Scalar fields and the
 * confirmed_proofs root are copied into `*out_summary`; the variable-length
 * findings are written into the caller-supplied `findings_buf`
 * (`out_summary->findings` is pointed at it). Probe sizing is supported:
 * call with findings_cap == 0 to learn the count in *out_n_findings via
 * BUFFER_TOO_SMALL, then allocate and call again.
 *
 * @return ANTS_OK with *out_summary populated; INVALID_ARG on NULL;
 *         BUFFER_TOO_SMALL if findings_cap is short (*out_n_findings set to
 *         the count); MALFORMED on a structurally bad frame; NON_CANONICAL
 *         on an RFC 8949 §4.2.1 violation; UNSUPPORTED_TYPE on an unknown
 *         severity.
 */
ants_error_t ants_chain_epoch_summary_decode(const uint8_t *buf,
                                             size_t len,
                                             ants_chain_epoch_summary_t *out_summary,
                                             ants_chain_pattern_finding_t *findings_buf,
                                             size_t findings_cap,
                                             size_t *out_n_findings);

/* ======================================================================== */
/* PR3 — the pattern-rule engine                                             */
/* ======================================================================== */

/*
 * Apply the protocol-defined pattern-detection rules (the §Slash-mechanics
 * severity table) to the L1 events visible at the cutoff, emitting the
 * findings whose thresholds are crossed (the reference sketch's
 * `count_events ≥ rule.threshold` loop). Pure and deterministic: the same
 * events and `now` yield the same findings on every honest committee.
 * `events` need not be ordered; the engine bins per subject and window and
 * returns one finding per subject, subject-ascending — a canonical order so
 * the output is byte-identical for the same event SET regardless of listing
 * order.
 *
 * @return ANTS_OK with *out_n set; INVALID_ARG on NULL; BUFFER_TOO_SMALL if
 *         `cap` is short (*out_n set to the count needed).
 */
ants_error_t ants_chain_pattern_scan(const ants_chain_event_t *events,
                                     size_t n_events,
                                     uint64_t now,
                                     ants_chain_pattern_finding_t *out_findings,
                                     size_t cap,
                                     size_t *out_n);

/* ======================================================================== */
/* PR4 — VRF committee selection                                             */
/* ======================================================================== */

/*
 * Select the `k`-member committee for a block from the attested population
 * (RFC-0004 §"Consensus mechanism" step 1): a deterministic, public
 * function of the seed (previous block hash + the external-entropy beacon)
 * that yields `k` DISTINCT population indices. Because it is seeded by a
 * beacon released AFTER the previous block, the selection is unpredictable
 * and non-grindable; because it is deterministic, any peer recomputes the
 * same committee and a selected peer can prove its membership with its own
 * ECVRF sortition proof (PR4 also).
 *
 * @param population_size number of attested peers to choose from.
 * @param k               committee size (≤ population_size, ≤ K_MAX).
 * @return ANTS_OK with `out_indices` and `*out_n` set; INVALID_ARG on NULL,
 *         k 0,
 *         or k > population_size; BUFFER_TOO_SMALL if cap < k.
 */
ants_error_t ants_chain_committee_select(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                         const uint8_t beacon[ANTS_CHAIN_HASH_SIZE],
                                         size_t population_size,
                                         size_t k,
                                         size_t *out_indices,
                                         size_t cap,
                                         size_t *out_n);

/* ======================================================================== */
/* PR5 — block hashing, encoding, and 2/3 finality                           */
/* ======================================================================== */

/*
 * Block hash = BLAKE3 over the canonical encoding of the block
 * (height, prev_block_hash, epoch summary). The message committee members
 * attest to. Deterministic.
 *
 * @return ANTS_OK with `out_hash` set; INVALID_ARG on NULL or an invalid
 *         summary.
 */
ants_error_t ants_chain_block_hash(const ants_chain_block_t *b,
                                   uint8_t out_hash[ANTS_CHAIN_HASH_SIZE]);

/* A safe upper bound for ants_chain_block_encode on `b`. 0 if b is NULL. */
size_t ants_chain_block_bound(const ants_chain_block_t *b);

/*
 * Encode / decode a block as canonical CBOR (the wire form gossiped to the
 * rest of the network for independent verification). Decode fills the
 * nested summary's findings into `findings_buf` with the same probe-sizing
 * contract as ants_chain_epoch_summary_decode.
 */
ants_error_t
ants_chain_block_encode(const ants_chain_block_t *b, uint8_t *buf, size_t cap, size_t *out_len);
ants_error_t ants_chain_block_decode(const uint8_t *buf,
                                     size_t len,
                                     ants_chain_block_t *out_block,
                                     ants_chain_pattern_finding_t *findings_buf,
                                     size_t findings_cap,
                                     size_t *out_n_findings);

/*
 * Verify block finality: does the committee's attestation set carry at
 * least ceil(FINALITY_NUM * k / FINALITY_DEN) valid signatures over
 * `block_hash`? `signed_mask[i]` marks which of the `k` committee members
 * contributed; `attestations` is one Ed25519 signature per SIGNER, packed
 * in ascending member order (so `attestations_len == popcount(mask) *
 * ANTS_CHAIN_SIG_SIZE`, which pins the signer count). Each signer's
 * signature is checked against its committee public key over `block_hash`.
 * A signature shortfall or any invalid signature is a FALSE VERDICT
 * (*out_final = false, return ANTS_OK), not an error.
 *
 * v0.x verifies per-signer Ed25519 for every k. The epoch-atomic BLS12-381
 * AGGREGATE compression for k > BLS_TRANSITION_K (RFC-0008 §3.3) — one
 * 96-byte signature instead of k 64-byte ones — is a deferred WIRE
 * optimisation: it needs the committee's separate BLS public keys (the
 * peer-id here is the Ed25519 key), so it lands with that plumbing. The
 * security is identical; only the attestation size differs.
 *
 * @return ANTS_OK with *out_final set; INVALID_ARG on NULL, k 0 / k > K_MAX,
 *         or attestations_len not equal to popcount(signed_mask) signatures.
 */
ants_error_t ants_chain_finality_verify(const uint8_t block_hash[ANTS_CHAIN_HASH_SIZE],
                                        const uint8_t (*committee_pubkeys)[ANTS_CHAIN_PEER_ID_SIZE],
                                        size_t k,
                                        const uint8_t *attestations,
                                        size_t attestations_len,
                                        const bool *signed_mask,
                                        bool *out_final);

/* ======================================================================== */
/* PR6 — partition recovery: Σ T_eff fork choice                             */
/* ======================================================================== */

/*
 * Cumulative effective tenure of a fork's validator set (RFC-0004 §"Fork
 * choice by Σ T_eff"): the sum of the saturating transform T_eff(T) =
 * T_CAP·(1 − exp(−T/T_CAP)) over the raw tenures of all validators that
 * signed the fork's finalised blocks, computed against the pre-partition
 * agreed state. The saturating transform is reused verbatim from
 * reputation/identity (ants_reputation_t_eff) so two components agree
 * bit-for-bit; the cap bounds any one arbitrarily-old peer's relative
 * weight so the founder cohort cannot hold fork-choice authority forever.
 *
 * @param validator_tenures raw T per fork validator (uncapped).
 * @param t_cap             the saturating cap (ANTS_CHAIN_T_FORK_CHOICE_CAP).
 * @return ANTS_OK with *out_sum_t_eff set; INVALID_ARG on NULL or t_cap 0;
 *         OVERFLOW if the sum would exceed UINT64_MAX.
 */
ants_error_t ants_chain_fork_weight(const uint64_t *validator_tenures,
                                    size_t n,
                                    uint64_t t_cap,
                                    uint64_t *out_sum_t_eff);

/*
 * Decide a partition between two finalised forks by Σ T_eff. The fork with
 * the higher weight wins UNLESS both clear the social-Schelling threshold
 * θ = theta_num/theta_den of the total, in which case the partition is
 * balanced and recovery is handed to the social layer (RFC-0004
 * §"Social-Schelling fallback").
 *
 * @param total_t_eff Σ T_eff over the pre-partition agreed validator set
 *                    (the denominator θ is taken against).
 * @param out_winner  ANTS_CHAIN_FORK_A / _FORK_B / _FORK_SOCIAL_SCHELLING.
 * @return ANTS_OK with *out_winner set; INVALID_ARG on NULL, theta_den 0,
 *         or a weight exceeding total_t_eff.
 */
ants_error_t ants_chain_fork_choice(uint64_t weight_a,
                                    uint64_t weight_b,
                                    uint64_t total_t_eff,
                                    uint64_t theta_num,
                                    uint64_t theta_den,
                                    int *out_winner);

/* ======================================================================== */
/* PR7 — drand beacon verification + VRF seed derivation                    */
/* ======================================================================== */

/* drand group public key and round signature: BLS12-381 in the same
 * min-pubkey-size shape ants_bls_* pins (48-byte compressed G1 pubkey,
 * 96-byte G2 signature). The League of Entropy default chain (scheme
 * "pedersen-bls-chained") is exactly this shape, with the same
 * BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_ ciphersuite as RFC-0008
 * §3.3. */
#define ANTS_CHAIN_DRAND_PUBKEY_SIZE 48u
#define ANTS_CHAIN_DRAND_SIG_SIZE    96u
/* A round's published randomness: SHA-256(signature). */
#define ANTS_CHAIN_BEACON_RANDOMNESS_SIZE 32u

/*
 * One drand round as consumed by the chain (RFC-0008 §4.2), in the
 * CHAINED-scheme form: round N's signature signs
 * SHA-256(previous_signature || round_be64), and the published
 * randomness is SHA-256(signature). How the caller OBTAINS rounds
 * (HTTP relay, gossip, a peer) is out of scope — the chain only
 * verifies and consumes them; which round feeds which block is the
 * block-production runtime's policy (RFC-0008 §4.3 leaves the exact
 * mapping convention open).
 */
typedef struct {
    uint64_t round; /* drand round number (>= 2; see beacon_verify) */
    uint8_t randomness[ANTS_CHAIN_BEACON_RANDOMNESS_SIZE];
    uint8_t signature[ANTS_CHAIN_DRAND_SIG_SIZE];
    uint8_t previous_signature[ANTS_CHAIN_DRAND_SIG_SIZE];
} ants_chain_beacon_t;

/*
 * Verify one chained drand round against the drand group public key
 * (pinned in genesis config per RFC-0010 §drand): BLS-verify
 * `signature` over SHA-256(previous_signature || round_be64), then
 * check randomness == SHA-256(signature).
 *
 * The beacon is UNTRUSTED input: a failed pairing, a malformed point,
 * or a randomness mismatch is a *verdict* (*out_ok = false, ANTS_OK),
 * not an error — the same contract as bond admission.
 *
 * round < 2 is INVALID_ARG: round 1 of a chained drand network signs
 * over the network's genesis seed (a different payload shape), and an
 * ANTS genesis pins `initial_round` well past it (RFC-0010), so the
 * steady-state form is the only one the chain consumes.
 *
 * @return ANTS_OK with *out_ok set; INVALID_ARG on NULL args or
 *         round < 2.
 */
ants_error_t ants_chain_beacon_verify(const ants_chain_beacon_t *beacon,
                                      const uint8_t drand_pubkey[ANTS_CHAIN_DRAND_PUBKEY_SIZE],
                                      bool *out_ok);

/*
 * The VRF seed for a block (RFC-0008 §4.2):
 * BLAKE3.derive_key("ants-v1-vrf-seed",
 *     prev_block_hash || height_be64 || randomness).
 * `randomness` is a VERIFIED round's 32-byte randomness — the
 * "drand_round_value" of the spec text. (That the round value means
 * the randomness rather than the 96-byte signature is a DRAFT
 * precision pending RFC-0008: the randomness is the round's canonical
 * public output, derived from the unforgeable signature.) The output
 * feeds ants_chain_committee_select's `beacon` parameter.
 */
ants_error_t ants_chain_vrf_seed(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                 uint64_t height,
                                 const uint8_t randomness[ANTS_CHAIN_BEACON_RANDOMNESS_SIZE],
                                 uint8_t out_seed[ANTS_CHAIN_HASH_SIZE]);

/*
 * The degraded VRF seed (RFC-0008 §4.3, drand outage):
 * BLAKE3.derive_key("ants-v1-vrf-seed-degraded",
 *     prev_block_hash || height_be64).
 * The outage POLICY (the 30-second hard floor before falling back, the
 * `degraded_seed` block-header flag) belongs to the block-production
 * runtime and its wire format — this is only the deterministic
 * derivation every verifier must agree on.
 */
ants_error_t ants_chain_vrf_seed_degraded(const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                          uint64_t height,
                                          uint8_t out_seed[ANTS_CHAIN_HASH_SIZE]);

/* ======================================================================== */
/* PR8 — block proposal + proposer election                                  */
/* ======================================================================== */

/*
 * Which committee member proposes the block at `height`: the POSITION
 * height mod k into the canonical ascending committee list produced by
 * ants_chain_committee_select (a position, NOT a population index — the
 * caller looks up committee[*out_member]).
 *
 * DRAFT rule. RFC-0004 §"Consensus mechanism" requires only "deterministic
 * within the committee" and leaves the rule unpinned; round-robin by height
 * is the simplest candidate and adds no grinding surface, because the
 * committee SET itself is already beacon-seeded and non-grindable — pinning
 * WHICH member of an unpredictable set proposes gives an adversary nothing
 * to grind toward. Over any k consecutive heights every position proposes
 * exactly once. On a finality timeout the runtime re-attempts with a NEW
 * committee (a later beacon round), not a new position: for a given
 * (committee, height) the proposer is fixed.
 *
 * @return ANTS_OK with *out_member set; INVALID_ARG on NULL out_member,
 *         k == 0, or k > ANTS_CHAIN_COMMITTEE_K_MAX.
 */
ants_error_t ants_chain_proposer(uint64_t height, size_t k, size_t *out_member);

/*
 * Compose a candidate block from the proposer's view of Layer 1 at the
 * epoch cutoff — the pure mempool→block step. RFC-0004's "mempool" is not
 * a queue: the candidate block content IS the L1 CRDT state visible at
 * cutoff_time. The caller (the runtime) enumerates its G-Set once and
 * passes that view down as the proofs' content-ids (STRICTLY ASCENDING,
 * the confirmed_root canonical order) plus the decoded fault events; this
 * function derives confirmed_proofs and the pattern findings and fills
 * `*out_block`.
 *
 * DETERMINISM PIN: the pattern engine runs with now ≡ cutoff_time — never
 * the proposer's wall clock — so a committee member recomputing from the
 * same visible set produces the byte-identical block and hence the same
 * block hash. That recompute-and-compare IS proposal validation: a member
 * signs the proposer's block hash only if it matches its own recomputation
 * (members whose G-Set view lags simply abstain; 2/3 finality absorbs the
 * stragglers). `degraded_seed` is carried verbatim into the block's signed
 * bytes (see ants_chain_block_t).
 *
 * Findings use the decode-style probe contract: call with findings_cap == 0
 * to learn the count via BUFFER_TOO_SMALL + *out_n_findings, then size and
 * call again. On success out_block->summary.findings aliases findings_buf.
 *
 * Which epoch and cutoff map to which height, and which verified beacon
 * round seeded the committee, are the block-production runtime's policy
 * (RFC-0008 §4.3 leaves the mapping convention open) — this function only
 * makes the composition canonical.
 *
 * @return ANTS_OK with *out_block and *out_n_findings set; INVALID_ARG on
 *         NULL prev_block_hash/out_block/out_n_findings, on NULL
 *         content_ids/events with a nonzero count, or if the scan emits
 *         more than ANTS_CHAIN_MAX_PATTERN_FINDINGS findings (a pathological
 *         epoch the runtime must split — see that constant); NON_CANONICAL
 *         if content_ids are not strictly ascending; BUFFER_TOO_SMALL if
 *         findings_cap is short (*out_n_findings set to the count needed).
 */
ants_error_t ants_chain_block_propose(uint64_t height,
                                      const uint8_t prev_block_hash[ANTS_CHAIN_HASH_SIZE],
                                      uint64_t epoch,
                                      uint64_t cutoff_time,
                                      bool degraded_seed,
                                      const uint8_t (*content_ids)[ANTS_CHAIN_HASH_SIZE],
                                      size_t n_ids,
                                      const ants_chain_event_t *events,
                                      size_t n_events,
                                      ants_chain_pattern_finding_t *findings_buf,
                                      size_t findings_cap,
                                      size_t *out_n_findings,
                                      ants_chain_block_t *out_block);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CHAIN_H */
