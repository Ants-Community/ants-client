/*
 * ants_inference.h — Inference orchestration (Component #13).
 *
 * The runtime that *does* inference, *commits* to it, and *dispatches
 * audits*. This is the component that ties the canonical kernels
 * (#12), the embedding model (#11), the semantic cache (#10), and the
 * identity/reputation layer (#9) into the producer- and verifier-side
 * machinery RFC-0003 specifies: a producer answers a request and emits
 * a commit-at-send object bound to the whole computation; a verifier,
 * seeded by a posterior PoUH beacon it cannot have influenced, decides
 * whether to audit, which positions to open, and runs an anytime-valid
 * betting e-process that slashes fraud while bounding the honest
 * false-accusation rate.
 *
 * Spec references:
 *   - RFC-0003 §The commit-at-send primitive — the commit object
 *     (Merkle root over per-position logit-distribution leaves, plus
 *     model hash, input, requester nonce, agent measurement, round),
 *     signed by the attested producer identity.
 *   - RFC-0003 §Anti-grinding challenge derivation — the three
 *     deterministic PRF derivations off the posterior beacon B_{r+1}:
 *     audit? (sel), positions S (pos, strided), auditor V (aud).
 *   - RFC-0003 §The tiered menu — Tier 1 (attestation + sampling),
 *     Tier 2 (cross-check via scheme C / betting e-process), Tier 3
 *     (triangulation).
 *   - RFC-0003 §The betting e-process — M_n = ∏(1 + λ_j·(X_j − μ0)),
 *     slash when M_n ≥ 1/α; Type-I ≤ α by Ville's inequality, with no
 *     independence or variance assumptions on the scores X_j.
 *   - RFC-0009 §5 — the canonical q24 logit representation that makes
 *     the committed per-position distributions, and therefore the
 *     discrepancy scores, bit-exact across honest verifiers.
 *
 * Layering. This header exposes four cleanly separable surfaces, each
 * independently testable and (deliberately) model-agnostic:
 *
 *   1. Commit-at-send — leaf hashing, Merkle root/prove/verify, the
 *      commit struct + its canonical CBOR encoding, and Ed25519
 *      sign/verify over that encoding. Pure functions over bytes; no
 *      model, no I/O.
 *   2. Anti-grinding challenge derivation — the three beacon-bound PRF
 *      derivations. Pure functions; deterministic given (beacon, root).
 *   3. The betting e-process — an incremental verifier that ingests
 *      per-position discrepancy scores and renders a verdict. Pure
 *      state machine over doubles.
 *   4. The serving runtime — the opaque context that loads a model and,
 *      on `serve`, produces (answer envelope, commit, signature). This
 *      is the integration capstone: it composes #12/#11/#10/#9 and is
 *      the last surface to acquire a real implementation, after the
 *      three primitive surfaces above and a model loader exist.
 *
 * API model: caller-allocated buffers and context, no internal
 * allocation beyond what a composed library (ggml, via the kernels /
 * embedding components) allocates inside the opaque context, no
 * threads, no hidden global state, no logging. Matches the C99 +
 * caller-owns-state discipline established by foundation/, network/,
 * cache/, and inference/kernels/.
 *
 * Status (this PR — scaffold): every entry point is declared with its
 * full contract but returns ANTS_ERROR_NOT_IMPLEMENTED (or, for the
 * pure predicates, leaves outputs untouched and returns NOT_IMPLEMENTED)
 * until the per-surface implementation PRs land. The header is the
 * reviewable API-design artifact; the contract tests pin the shapes.
 */

#ifndef ANTS_INFERENCE_H
#define ANTS_INFERENCE_H

#include "ants_common.h"

/* The audited path operates on canonical q24 logit vectors produced by
 * the kernels component (#12). The discrepancy score and the verifier's
 * reference-distribution callback are expressed in those terms, so the
 * orchestration layer genuinely composes ants_canon. */
#include "ants_canon.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Fixed-size byte-string lengths                                           */
/*                                                                          */
/* All hashes are BLAKE3-256, all signatures Ed25519, matching the rest of  */
/* the protocol (RFC-0001). Named here rather than pulled from              */
/* ants_crypto.h so the public surface of this header stays narrow — the    */
/* embedding component (#11) sets the same precedent. The .c file is where  */
/* the crypto dependency is actually taken.                                 */
/* ------------------------------------------------------------------------ */

#define ANTS_INFERENCE_HASH_SIZE        32
#define ANTS_INFERENCE_MERKLE_LEAF_SIZE 32
#define ANTS_INFERENCE_MERKLE_ROOT_SIZE 32
#define ANTS_INFERENCE_BEACON_SIZE      32
#define ANTS_INFERENCE_PUBKEY_SIZE      32
#define ANTS_INFERENCE_PRIVKEY_SIZE     32
#define ANTS_INFERENCE_SIG_SIZE         64

/* Upper bound on Merkle proof length (sibling hashes from leaf to root).
 * A balanced tree over L leaves has depth ⌈log2(L)⌉; capping at 32 admits
 * L up to 2^32, far beyond any realistic answer length (a position count
 * is a uint32). Callers size proof buffers as
 * ANTS_INFERENCE_MERKLE_MAX_DEPTH × ANTS_INFERENCE_HASH_SIZE bytes. */
#define ANTS_INFERENCE_MERKLE_MAX_DEPTH 32

/* ------------------------------------------------------------------------ */
/* Verification tiers (RFC-0003 §The tiered menu)                           */
/*                                                                          */
/* Tier 1 — attestation + spot-sampling. The common case (~90% of           */
/*          traffic): the producer's TEE attestation plus a small audited   */
/*          sample suffices.                                                 */
/* Tier 2 — cross-check. The audited path proper (~8%): a verifier reruns    */
/*          the committed positions under canonical numerics and runs the   */
/*          betting e-process (scheme C).                                    */
/* Tier 3 — triangulation. The escalation path (~2%): multiple independent   */
/*          verifiers, used on dispute or for high-value answers.            */
/* ------------------------------------------------------------------------ */

#define ANTS_INFERENCE_TIER_1 1
#define ANTS_INFERENCE_TIER_2 2
#define ANTS_INFERENCE_TIER_3 3

/* ------------------------------------------------------------------------ */
/* Merkle domain separation (RFC 6962 style)                                */
/*                                                                          */
/* Distinct one-byte prefixes for leaf and internal nodes prevent           */
/* second-preimage attacks that pun an internal node as a leaf. This is a    */
/* DRAFT scheme pending formalization in a future RFC-0003 / RFC-0008        */
/* revision; it is documented here so the reference client and any           */
/* independent implementation agree byte-for-byte in the meantime.           */
/*                                                                          */
/*   leaf_i        = BLAKE3( 0x00 ‖ dist_bytes_i ‖ LE64(position_i) )        */
/*   internal(L,R) = BLAKE3( 0x01 ‖ L ‖ R )                                  */
/*                                                                          */
/* Odd levels promote the lone trailing node unchanged to the next level    */
/* (no duplication), which the prove/verify pair must mirror exactly.       */
/* ------------------------------------------------------------------------ */

#define ANTS_INFERENCE_MERKLE_LEAF_PREFIX 0x00
#define ANTS_INFERENCE_MERKLE_NODE_PREFIX 0x01

/* ------------------------------------------------------------------------ */
/* PRF domain-separation contexts (RFC-0003 §Anti-grinding)                 */
/*                                                                          */
/* The three challenge derivations are independent PRF evaluations over the  */
/* posterior beacon and the producer's commit root, distinguished by these   */
/* domain-separation tags. The PRF is BLAKE3; RFC-0003 writes each derivation */
/* as PRF(B_{r+1} ‖ root ‖ <tag>), so the tag is mixed into the PRF input.    */
/* The exact mixing (trailing-append vs keyed-derive context) is settled in   */
/* the implementation PR; both implementations must agree on it byte-for-     */
/* byte. Held as `extern const char *const` so there is a single definition   */
/* site, matching the embedding component's handling of its pinned ids.       */
/* ------------------------------------------------------------------------ */

/* "audit this answer?" Bernoulli selector. */
extern const char *const ANTS_INFERENCE_PRF_CONTEXT_SEL;
/* which positions to open (strided expansion). */
extern const char *const ANTS_INFERENCE_PRF_CONTEXT_POS;
/* which reputation-weighted verifier is assigned. */
extern const char *const ANTS_INFERENCE_PRF_CONTEXT_AUD;

/* ------------------------------------------------------------------------ */
/* Betting e-process defaults (RFC-0003 §The betting e-process)             */
/* ------------------------------------------------------------------------ */

/* Per-audit false-accusation budget α. Ville's inequality gives Type-I
 * error ≤ α when the slash rule is M_n ≥ 1/α. The protocol default is
 * stringent (a slash is a serious action). */
#define ANTS_INFERENCE_DEFAULT_ALPHA 1e-6

/* Null-hypothesis mean discrepancy μ0: the largest per-position
 * discrepancy an *honest* producer is expected to exhibit under
 * canonical numerics (ideally ≈0; a small positive value absorbs
 * benign noise). PLACEHOLDER pending calibration against the canonical
 * kernels' measured honest-path residual; see RFC-0009 §5.1. */
#define ANTS_INFERENCE_DEFAULT_MU0 0.05

/* Betting-fraction cap. The Kelly-style bet λ_j is clipped to
 * [0, λ_cap]; the natural ceiling is 1/(1−μ0) (beyond which a single
 * X_j = 0 would drive capital negative). PLACEHOLDER, co-calibrated
 * with μ0. */
#define ANTS_INFERENCE_DEFAULT_LAMBDA_CAP 1.0

/* ======================================================================== */
/* 1. Commit-at-send                                                        */
/* ======================================================================== */

/* The commit object a producer emits alongside every answer (RFC-0003
 * §The commit-at-send primitive). It binds the *entire* computation —
 * not just the output tokens — so a later audit can open any committed
 * position and check it against an independent rerun.
 *
 * The Merkle `root` is taken over per-position leaves
 * (`ants_inference_leaf_hash`), one per generated position. The remaining
 * fields bind the context the answer was produced in. The whole struct is
 * canonically encoded (`ants_inference_commit_encode`) and Ed25519-signed
 * by the producer's attested identity key.
 *
 * `audit_threshold` carries the audit probability p as a fixed-point
 * integer `floor(p · 2^64)`: the selector audits iff the 64-bit PRF
 * output is strictly below it. Encoding p this way keeps the wire format
 * float-free and makes the audit? decision bit-exact across verifiers. */
typedef struct {
    /* Merkle root over the per-position logit-distribution leaves. */
    uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE];

    /* H(M): BLAKE3 of the canonical model artifact the answer was
     * produced under. The verifier must rerun under the same model. */
    uint8_t model_hash[ANTS_INFERENCE_HASH_SIZE];

    /* H(x): BLAKE3 of the request input. Binds the commit to the exact
     * prompt; the full input travels in the answer envelope, not here. */
    uint8_t input_hash[ANTS_INFERENCE_HASH_SIZE];

    /* The requester's nonce — freshness, and ties the answer to a
     * specific request so a producer cannot replay an old computation. */
    uint8_t req_nonce[ANTS_INFERENCE_HASH_SIZE];

    /* Agent measurement: the attestation measurement of the producing
     * agent (TEE measurement / code identity), per RFC-0003. */
    uint8_t agent_meas[ANTS_INFERENCE_HASH_SIZE];

    /* PoUH round r the commit is anchored to. The audit challenge is
     * derived from the *posterior* beacon B_{r+1}, which the producer
     * cannot have influenced at commit time. */
    uint64_t round;

    /* Audit probability as floor(p · 2^64) — see struct doc above. */
    uint64_t audit_threshold;

    /* m: number of positions an audit opens (the sample size of the
     * strided position set S). */
    uint32_t m;

    /* L: total number of committed positions (= number of Merkle
     * leaves). Positions are indexed 0 .. L−1. */
    uint32_t length;

    /* The verification tier this answer was served under
     * (ANTS_INFERENCE_TIER_1/2/3). */
    uint8_t tier;
} ants_inference_commit_t;

/*
 * Hash one per-position leaf: leaf = BLAKE3(0x00 ‖ dist_bytes ‖ LE64(position)).
 *
 * `dist_bytes` is the canonical serialization of the position's logit
 * distribution — per RFC-0009 §5, the q24 logit vector little-endian
 * encoded (vocab × 4 bytes). Binding `position` into the leaf prevents an
 * adversary from relocating a committed distribution to a different index.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL dist_bytes/out_leaf or zero dist_len;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_leaf_hash(const uint8_t *dist_bytes,
                                      size_t dist_len,
                                      uint64_t position,
                                      uint8_t out_leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE]);

/*
 * Compute the Merkle root over `n_leaves` contiguous 32-byte leaves using
 * the domain-separated, promote-lone-node scheme documented above.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL leaves/out_root or n_leaves == 0;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_merkle_root(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                        size_t n_leaves,
                                        uint8_t out_root[ANTS_INFERENCE_MERKLE_ROOT_SIZE]);

/*
 * Produce the inclusion proof for the leaf at `index` (0-based) in a tree
 * of `n_leaves`: the ordered list of sibling hashes from the leaf's level
 * up to (but excluding) the root. Written into `out_path` as contiguous
 * 32-byte hashes; the count is returned in `*out_path_len`.
 *
 * `out_path_cap` is the capacity of `out_path` in *hashes* (not bytes);
 * size it at ANTS_INFERENCE_MERKLE_MAX_DEPTH.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers, n_leaves == 0, or index >= n_leaves;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — out_path_cap too small for the proof;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_merkle_prove(const uint8_t (*leaves)[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                         size_t n_leaves,
                                         size_t index,
                                         uint8_t *out_path,
                                         size_t out_path_cap,
                                         size_t *out_path_len);

/*
 * Verify an inclusion proof: recompute the root from `leaf` (the already-
 * hashed leaf, e.g. from `ants_inference_leaf_hash`) at `index` in a tree
 * of `n_leaves` using the `path` siblings, and compare against `root`.
 * The verdict is written to `*out_ok`; a cryptographic mismatch is a
 * `false` verdict, NOT an error return.
 *
 * `path_len` is the number of 32-byte sibling hashes in `path`.
 *
 * Returns:
 *   ANTS_OK — verification ran; consult *out_ok for the result;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers, n_leaves == 0, index >= n_leaves,
 *     or path_len inconsistent with the tree shape;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_merkle_verify(const uint8_t leaf[ANTS_INFERENCE_MERKLE_LEAF_SIZE],
                                          size_t index,
                                          size_t n_leaves,
                                          const uint8_t *path,
                                          size_t path_len,
                                          const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                          bool *out_ok);

/*
 * Canonically encode a commit object for signing / wire transmission.
 * The encoding is a deterministic CBOR map with ascending integer keys
 * (RFC-0008 canonical-CBOR rules): no float fields (p is the integer
 * `audit_threshold`), fixed key order, definite lengths — so two encoders
 * produce byte-identical output and the signature is reproducible.
 *
 * Writes the encoding to `out` (capacity `out_cap`) and the length to
 * `*out_len`.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — out_cap too small;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_commit_encode(const ants_inference_commit_t *commit,
                                          uint8_t *out,
                                          size_t out_cap,
                                          size_t *out_len);

/*
 * Decode a canonical commit encoding produced by
 * `ants_inference_commit_encode`. Rejects non-canonical encodings
 * (out-of-order keys, indefinite lengths, trailing bytes) with
 * ANTS_ERROR_NON_CANONICAL — the audit path must not accept ambiguous
 * commits.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or zero in_len;
 *   ANTS_ERROR_MALFORMED — not valid CBOR / structurally wrong;
 *   ANTS_ERROR_NON_CANONICAL — valid CBOR but not canonical;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t
ants_inference_commit_decode(const uint8_t *in, size_t in_len, ants_inference_commit_t *out);

/*
 * Ed25519-sign the canonical encoding of `commit` with the producer's
 * private key. Equivalent to encode-then-sign, exposed as one call so the
 * producer never has to reproduce the canonical-encoding step.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_commit_sign(const ants_inference_commit_t *commit,
                                        const uint8_t priv[ANTS_INFERENCE_PRIVKEY_SIZE],
                                        uint8_t out_sig[ANTS_INFERENCE_SIG_SIZE]);

/*
 * Verify a producer's signature over `commit` against their public key.
 * The verdict is written to `*out_ok`; an invalid signature is a `false`
 * verdict, NOT an error return.
 *
 * Returns:
 *   ANTS_OK — verification ran; consult *out_ok;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_commit_verify_sig(const ants_inference_commit_t *commit,
                                              const uint8_t pub[ANTS_INFERENCE_PUBKEY_SIZE],
                                              const uint8_t sig[ANTS_INFERENCE_SIG_SIZE],
                                              bool *out_ok);

/* ======================================================================== */
/* 2. Anti-grinding challenge derivation (RFC-0003 §Anti-grinding)          */
/*                                                                          */
/* All three derivations are keyed by the posterior beacon B_{r+1} and the  */
/* producer's commit root — entropy the producer could not bind at commit   */
/* time. They are pure and deterministic: the same (beacon, root) inputs    */
/* yield the same challenge on every verifier, which is what makes the      */
/* audit non-interactive and non-grindable.                                 */
/* ======================================================================== */

/*
 * Decide whether this answer is audited:
 *   audited  ⇔  PRF(beacon ‖ root ‖ "sel")  <  audit_threshold
 * where the PRF output is interpreted as a 64-bit big-endian integer and
 * `audit_threshold` is the commit's floor(p · 2^64). The verdict is
 * written to `*out_audited`.
 *
 * Returns:
 *   ANTS_OK — decision computed; consult *out_audited;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t
ants_inference_challenge_is_audited(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                    const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                    uint64_t audit_threshold,
                                    bool *out_audited);

/*
 * Derive the strided position set S to open: `m` distinct positions in
 * [0, length) expanded deterministically from PRF(beacon ‖ root ‖ "pos").
 * Striding (rather than independent draws) spreads the sample across the
 * answer so a producer cannot cheaply localize fraud to unsampled spans.
 *
 * Writes up to `cap` positions into `out_positions` and the count to
 * `*out_count`. When m > length, the whole answer is opened (count =
 * length).
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers, length == 0, or m == 0;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — cap < min(m, length);
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_challenge_positions(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                                const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                                uint32_t m,
                                                uint32_t length,
                                                uint64_t *out_positions,
                                                size_t cap,
                                                size_t *out_count);

/*
 * Select the assigned verifier: an index in [0, n_verifiers) drawn from
 * PRF(beacon ‖ root ‖ "aud"). The caller maps this index onto the
 * reputation-weighted verifier set (the weighting lives in the
 * reputation component; this function provides the unbiased draw). The
 * index is written to `*out_index`.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or n_verifiers == 0;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_challenge_auditor(const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                              const uint8_t root[ANTS_INFERENCE_MERKLE_ROOT_SIZE],
                                              uint64_t n_verifiers,
                                              uint64_t *out_index);

/* ======================================================================== */
/* 3. The betting e-process (RFC-0003 §The betting e-process)               */
/*                                                                          */
/* An anytime-valid sequential test. For each opened position the verifier  */
/* computes a discrepancy score X_j ∈ [0, 1] between the committed          */
/* distribution and its own canonical rerun, then folds it into the         */
/* capital process                                                          */
/*                                                                          */
/*     M_n = ∏_{j≤n} (1 + λ_j · (X_j − μ0)),   λ_j = clip((μ̂−μ0)/v̂, 0, cap) */
/*                                                                          */
/* and slashes the moment M_n ≥ 1/α. Ville's inequality bounds the honest   */
/* false-accusation probability by α with no independence or variance        */
/* assumptions. λ_j is set by a plug-in predictable mixture using the        */
/* running mean μ̂ and variance v̂ of the scores seen so far.                 */
/*                                                                          */
/* Reproducibility note: the scores X_j are bit-exact across honest          */
/* verifiers (they derive from canonical q24 distributions). Whether the     */
/* capital recursion itself must be bit-reproducible in `double` — or be     */
/* pinned to a fixed-point recipe like the kernels — is an open canonical-   */
/* numerics question for a future RFC-0009 revision. This API uses `double`  */
/* and documents the open item rather than prematurely freezing a recipe.    */
/* ======================================================================== */

typedef enum {
    /* The capital has not crossed 1/α; keep opening positions. A run that
     * exhausts the position set S on CONTINUE is a PASS. */
    ANTS_INFERENCE_VERDICT_CONTINUE = 0,
    /* M_n ≥ 1/α: fraud is established at level α. Terminal. */
    ANTS_INFERENCE_VERDICT_FRAUD = 1,
} ants_inference_verdict_t;

/* The running e-process state. Caller-allocated, initialized by
 * `ants_inference_eprocess_init`, advanced by `ants_inference_eprocess_update`.
 * Exposed (not opaque) because it is a small, stable, plain-old-data value
 * a verifier may want to snapshot, log, or serialize mid-audit. */
typedef struct {
    /* Configuration (set at init, constant thereafter). */
    double alpha;      /* false-accusation budget α */
    double mu0;        /* null-hypothesis mean discrepancy */
    double lambda_cap; /* betting-fraction clip ceiling */

    /* Running state. */
    double capital; /* M_n; starts at 1.0 */
    double mu_hat;  /* running mean of X_j */
    double var_hat; /* running variance estimate of X_j */
    uint64_t n;     /* number of scores folded in */
} ants_inference_eprocess_t;

/*
 * Initialize an e-process. `alpha`, `mu0`, `lambda_cap` configure the test
 * (the ANTS_INFERENCE_DEFAULT_* values are the protocol defaults). Capital
 * starts at 1.0, n at 0.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL ep, or out-of-range parameters
 *     (alpha ∉ (0,1), mu0 ∉ [0,1), lambda_cap < 0);
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_eprocess_init(ants_inference_eprocess_t *ep,
                                          double alpha,
                                          double mu0,
                                          double lambda_cap);

/*
 * Fold one discrepancy score `score` ∈ [0, 1] into the e-process: set the
 * predictable bet λ from the current running statistics, multiply the
 * capital by (1 + λ·(score − μ0)), then update the running mean/variance.
 * The post-update verdict is written to `*out_verdict`.
 *
 * Once FRAUD is returned the process is terminal; further updates are a
 * caller error (the audit loop should stop).
 *
 * Returns:
 *   ANTS_OK — score folded; consult *out_verdict;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or score ∉ [0, 1];
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_eprocess_update(ants_inference_eprocess_t *ep,
                                            double score,
                                            ants_inference_verdict_t *out_verdict);

/*
 * Compute the per-position discrepancy score X ∈ [0, 1] between a
 * reference distribution `p_ref` and a committed distribution
 * `q_committed`, both as canonical q24 logit vectors of length `vocab`.
 * The score feeds `ants_inference_eprocess_update`.
 *
 * The exact metric (e.g. total-variation distance after a canonical
 * softmax, or an L1 distance on probabilities) is NOT yet frozen by the
 * spec; it must be pinned in a future RFC-0003 / RFC-0009 revision so all
 * verifiers compute identical scores. This declaration fixes the
 * signature and the [0, 1] range contract; the implementation PR will
 * carry the chosen, spec-ratified recipe.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or vocab == 0;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_discrepancy(const ants_canon_q24_t *p_ref,
                                        const ants_canon_q24_t *q_committed,
                                        size_t vocab,
                                        double *out_score);

/* ======================================================================== */
/* 4. The serving runtime                                                   */
/*                                                                          */
/* The integration capstone. Opaque, caller-allocated context that loads a  */
/* model and, on `serve`, runs the fast path or the audited path and emits  */
/* (answer envelope, commit, signature). Composes the kernels (#12),        */
/* embedding (#11), semantic cache (#10), and identity (#9) components, so   */
/* its real implementation lands only after those and the three primitive   */
/* surfaces above are in place. Declared now so the full component API is    */
/* reviewable as one artifact.                                              */
/* ======================================================================== */

/* Conservative oversize for ABI stability while the internal layout is in
 * flux (the runtime will hold a model handle plus audited-path scratch;
 * the bulk model weights stay in caller buffers, never copied here). The
 * .c file pins the true bound with the compile-time size-check idiom and
 * this constant is tightened once `serve` is implemented and measured. */
#define ANTS_INFERENCE_CTX_SIZE 131072

typedef union {
    uint8_t _opaque[ANTS_INFERENCE_CTX_SIZE];
    uint64_t _align;
} ants_inference_t;

/* Runtime configuration. All buffers are caller-owned and must outlive the
 * context; the library copies nothing large. */
typedef struct {
    /* The canonical model artifact (e.g. a quantized weight blob the
     * kernels component consumes). Hashed to populate commit.model_hash. */
    const uint8_t *model_weights;
    size_t model_weights_len;

    /* The producer's Ed25519 private key (32 bytes at this address),
     * used to sign each commit. Caller-owned so the caller controls
     * zeroization; the library does not copy it into the context beyond
     * what signing requires. */
    const uint8_t *producer_priv;
} ants_inference_config_t;

/* One inference request. */
typedef struct {
    const uint8_t *input; /* request bytes (e.g. the prompt) */
    size_t input_len;
    uint8_t tier;                                /* requested verification tier */
    uint8_t req_nonce[ANTS_INFERENCE_HASH_SIZE]; /* requester freshness nonce */
    uint64_t round;                              /* current PoUH round r */
} ants_inference_request_t;

/* One inference response. The variable-length answer envelope is written
 * into the caller's `answer_buf`; the fixed-size commit, public key, and
 * signature are returned by value/inline. */
typedef struct {
    /* Caller-owned output buffer for the CBOR answer envelope (the answer
     * plus the openings machinery a verifier needs). */
    uint8_t *answer_buf;
    size_t answer_cap;
    size_t answer_len; /* out: bytes written into answer_buf */

    /* out: the signed commit and its signature + the producer pubkey that
     * signs it, so a relayer/verifier can check the signature immediately. */
    ants_inference_commit_t commit;
    uint8_t producer_pub[ANTS_INFERENCE_PUBKEY_SIZE];
    uint8_t commit_sig[ANTS_INFERENCE_SIG_SIZE];
} ants_inference_response_t;

/*
 * Initialize a serving context against a model. Hashes the model artifact
 * and derives the producer public key from the configured private key.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL ctx/config or missing model/key;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase (model loader not yet wired).
 */
ants_error_t ants_inference_init(ants_inference_t *ctx, const ants_inference_config_t *config);

/*
 * Tear down a serving context. Releases any internal model state. The
 * caller's model/key buffers are NOT freed (the library never owned them).
 * Safe on a zeroed (never-initialized) context.
 */
ants_error_t ants_inference_destroy(ants_inference_t *ctx);

/*
 * Serve one request: run inference under the requested tier and produce
 * the answer envelope, the commit-at-send object, and the producer's
 * signature over it. The audited path (Tier ≥ 2) generates per-position
 * canonical q24 distributions, Merkle-commits them, and records the audit
 * parameters (p, m, L) in the returned commit.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers or unknown tier;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — answer_cap too small for the envelope;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_serve(ants_inference_t *ctx,
                                  const ants_inference_request_t *req,
                                  ants_inference_response_t *resp);

/* Verifier-side reference-distribution callback. Given the answer's prefix
 * up to `position` (the tokens 0..position−1, as the verifier reconstructs
 * them) and the committed model, recompute the canonical q24 logit vector
 * the producer *should* have emitted at `position`. Written into `out_dist`
 * (capacity `out_dist_cap` q24 values); the actual vocab length is returned
 * in `*out_vocab`. `user` carries the verifier's model/runtime handle.
 *
 * Return ANTS_OK on success or an ants_error_t on failure; a non-OK return
 * aborts the audit with that code. */
typedef ants_error_t (*ants_inference_reference_fn)(void *user,
                                                    const uint8_t *prefix,
                                                    size_t prefix_len,
                                                    uint64_t position,
                                                    ants_canon_q24_t *out_dist,
                                                    size_t out_dist_cap,
                                                    size_t *out_vocab);

/*
 * Run a full Tier-2 audit of one answer (the verifier capstone, mirroring
 * RFC-0003's reference `audit()` sketch):
 *   1. derive audit? from (beacon, commit.root, commit.audit_threshold);
 *      if not audited, set *out_verdict = CONTINUE (= "not audited") and
 *      return ANTS_OK;
 *   2. derive the strided position set S;
 *   3. for each position: open (dist, path) from the answer envelope,
 *      verify the Merkle path against commit.root, recompute the reference
 *      distribution via `ref_fn`, score the discrepancy, and fold it into
 *      the e-process — short-circuiting on FRAUD.
 * The terminal verdict is written to `*out_verdict`.
 *
 * `answer_buf`/`answer_len` is the producer's answer envelope; `beacon` is
 * the posterior PoUH beacon B_{r+1}.
 *
 * Returns:
 *   ANTS_OK — audit ran to a verdict; consult *out_verdict;
 *   ANTS_ERROR_INVALID_ARG — NULL pointers;
 *   ANTS_ERROR_MALFORMED — answer envelope could not be parsed / an opening
 *     failed its Merkle check;
 *   ANTS_ERROR_NOT_IMPLEMENTED — scaffold phase.
 */
ants_error_t ants_inference_audit(const ants_inference_commit_t *commit,
                                  const uint8_t *answer_buf,
                                  size_t answer_len,
                                  const uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE],
                                  ants_inference_reference_fn ref_fn,
                                  void *ref_user,
                                  const ants_inference_eprocess_t *eprocess_params,
                                  ants_inference_verdict_t *out_verdict);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_INFERENCE_H */
