/*
 * ants_chain_runtime.h — the L2 block-production runtime (Component #8,
 * RFC-0004 §"Consensus mechanism: PoUH"; the composition the pure
 * functions in ants_chain.h leave to "the block-production runtime").
 *
 * One state machine per node. It decides, from the node's own clock and
 * the messages it is handed, when this node proposes, whether it signs a
 * proposal, when a block is final, and when an attempt is skipped. It owns
 * no I/O, no clock and no memory: the caller feeds it the time (`now`,
 * unix seconds), the proposals and attestations that arrived, and a view of
 * Layer 1; it hands back, through callbacks, the proposals and
 * attestations to broadcast and every newly final head. That keeps the
 * whole loop deterministic and testable in-process (many simulated nodes,
 * a fake clock) before any of it touches the wire.
 *
 * v1 (RFC-0010 Phase 1, "trustee-signed") rules, DRAFT pending RFC-0004:
 *
 *   Population.  The genesis trustees, strictly ascending by peer-id. With
 *     RFC-0005 v1 verify-and-tag no peer is attested yet, so the attested
 *     population the mature protocol draws from is empty; Phase 1 block
 *     production is trustee-signed by design.
 *   Heights are sequential. With head H final, the node attempts height
 *     h = H+1 on prev = hash(H). The committee for (prev, h) is
 *     ants_chain_committee_select over the population with
 *     k = min(n_trustees, k_phase), seeded by
 *     ants_chain_vrf_seed_degraded(prev, h) — v1 has no drand fetcher, so
 *     every block is a degraded-seed block (RFC-0008 §4.3; "common" in
 *     Phase 1). The proposer is committee position h mod k.
 *   Proposal.  The proposer waits out the drand hard floor
 *     (ANTS_CHAIN_RT_DRAND_FLOOR_S) from the attempt's start and at least
 *     ANTS_CHAIN_BLOCK_TIME_S past the head's cutoff, then composes the
 *     block with cutoff_time = now from its Layer-1 view at that cutoff
 *     (ants_chain_block_propose), signs it and broadcasts both.
 *   Validation is recompute-and-compare: a committee member signs a
 *     proposal for its current attempt only if the cutoff lies in
 *     [head cutoff + BLOCK_TIME, now + CLOCK_SKEW] and its OWN view at that
 *     cutoff composes the byte-identical block. A member signs at most one
 *     block per height, ever (signing two is attributable equivocation,
 *     RFC-0004 §Equivocation slashing). Members whose view lags abstain.
 *   Finality at ceil(2k/3) valid attestations (ants_chain_finality_verify).
 *   Skip.  An attempt not final ANTS_CHAIN_FINALITY_TIMEOUT_S after it
 *     started is skipped: the node moves to h+1 on the SAME prev — a new
 *     committee and proposer, and no member ever needs to sign a second
 *     block at a height. Heights can therefore have gaps.
 *   Adoption.  Any block the node can prove final — its committee is
 *     recomputable from the block's own (prev, height) and the static
 *     population — with height above the head becomes the new head, even
 *     when its prev is not the local head (a node that fell behind or
 *     joined late catches up on finality, not on history; full chain sync
 *     is later work).
 *
 * Epochs: a block's epoch is (cutoff - genesis_time) / EPOCH_DURATION.
 */

#ifndef ANTS_CHAIN_RUNTIME_H
#define ANTS_CHAIN_RUNTIME_H

#include "ants_chain.h"
#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RFC-0008 §4.3: how long a proposer waits for a drand round before it may
 * fall back to the degraded seed — a hard floor. v1 has no fetcher, so the
 * proposer of every attempt waits it out. */
#define ANTS_CHAIN_RT_DRAND_FLOOR_S 30u

/* RFC-0008 §7 EPOCH_DURATION. */
#define ANTS_CHAIN_RT_EPOCH_DURATION_S 86400u

/* How far in the future (by the member's clock) a proposal's cutoff may lie
 * and still be signed. DRAFT. */
#define ANTS_CHAIN_RT_CLOCK_SKEW_S 10u

/* RFC-0010 Phase 1 committee ceiling: K = min(N, 5). */
#define ANTS_CHAIN_RT_PHASE1_K 5u

/* Proposals and own attestations are re-broadcast this often while their
 * attempt is open, so a member that joined late or missed a frame still
 * gets them. */
#define ANTS_CHAIN_RT_REBROADCAST_S 10u

/* ------------------------------------------------------------------------ */
/* Messages                                                                 */
/* ------------------------------------------------------------------------ */

/* A committee member's signature over a block hash. `height` is carried so
 * a receiver can file the attestation before it holds the proposal. */
typedef struct {
    uint64_t height;
    uint8_t block_hash[ANTS_CHAIN_HASH_SIZE];
    uint8_t signer[ANTS_CHAIN_PEER_ID_SIZE];
    uint8_t sig[ANTS_CHAIN_SIG_SIZE];
} ants_chain_attestation_t;

/* The node's final head. Height 0 is genesis (hash = genesis_hash,
 * cutoff = genesis_time). */
typedef struct {
    uint64_t height;
    uint8_t hash[ANTS_CHAIN_HASH_SIZE];
    uint64_t cutoff_time;
    uint64_t epoch;
    bool degraded_seed;
} ants_chain_head_t;

/* ------------------------------------------------------------------------ */
/* Callbacks                                                                */
/* ------------------------------------------------------------------------ */

/* Sign a 32-byte block hash with the node's Ed25519 identity key. */
typedef ants_error_t (*ants_chain_rt_sign_fn)(const uint8_t hash[ANTS_CHAIN_HASH_SIZE],
                                              uint8_t out_sig[ANTS_CHAIN_SIG_SIZE],
                                              void *ctx);

/*
 * The node's Layer-1 view at `cutoff`: the content-ids of the visible fault
 * proofs signed at or before `cutoff`, STRICTLY ASCENDING, and the decoded
 * fault events (RFC-0004 reference sketch: visible = signed_at <= cutoff).
 * The arrays are borrowed until the callback is next invoked. A view that
 * cannot be produced is an error: the node then abstains (or, as proposer,
 * does not propose this tick).
 */
typedef ants_error_t (*ants_chain_rt_view_fn)(uint64_t cutoff,
                                              const uint8_t (**out_ids)[ANTS_CHAIN_HASH_SIZE],
                                              size_t *out_n_ids,
                                              const ants_chain_event_t **out_events,
                                              size_t *out_n_events,
                                              void *ctx);

/* Broadcast a proposal (the canonical block encoding, RFC-0008 §11.6). */
typedef void (*ants_chain_rt_proposal_fn)(const uint8_t *block, size_t len, void *ctx);

/* Broadcast an attestation. */
typedef void (*ants_chain_rt_attestation_fn)(const ants_chain_attestation_t *att, void *ctx);

/* A new head became final (produced locally, or adopted). */
typedef void (*ants_chain_rt_final_fn)(const ants_chain_head_t *head, void *ctx);

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Genesis (the v1 subset of RFC-0010's GenesisState). Trustees MUST be
     * strictly ascending; 1..ANTS_CHAIN_COMMITTEE_K_MAX of them. */
    const uint8_t (*trustees)[ANTS_CHAIN_PEER_ID_SIZE];
    size_t n_trustees;
    uint64_t genesis_time;
    uint8_t genesis_hash[ANTS_CHAIN_HASH_SIZE];
    /* Committee ceiling for the phase: k = min(n_trustees, k_phase).
     * ANTS_CHAIN_RT_PHASE1_K in v1. */
    size_t k_phase;

    /* This node's peer-id. A node that is not a trustee runs as an
     * observer: it never proposes or signs, but tracks and adopts heads. */
    uint8_t self[ANTS_CHAIN_PEER_ID_SIZE];

    ants_chain_rt_sign_fn sign_fn; /* required for a trustee */
    void *sign_ctx;
    ants_chain_rt_view_fn view_fn; /* required for a trustee */
    void *view_ctx;
    ants_chain_rt_proposal_fn proposal_fn; /* may be NULL */
    ants_chain_rt_attestation_fn attestation_fn;
    ants_chain_rt_final_fn final_fn;
    void *out_ctx; /* cookie for the three output callbacks */
} ants_chain_rt_config_t;

/* ------------------------------------------------------------------------ */
/* Engine                                                                   */
/* ------------------------------------------------------------------------ */

#define ANTS_CHAIN_RT_CTX_SIZE 196608

typedef union {
    uint8_t _opaque[ANTS_CHAIN_RT_CTX_SIZE];
    uint64_t _align;
} ants_chain_rt_t;

/* Start at genesis (head height 0) with the first attempt (height 1)
 * opening at `now`. INVALID_ARG on NULL, trustees not strictly ascending or
 * out of range, k_phase 0, now < genesis_time, or a trustee node without
 * sign_fn / view_fn. The trustee array is copied. */
ants_error_t
ants_chain_rt_init(ants_chain_rt_t *rt, const ants_chain_rt_config_t *cfg, uint64_t now);

/* Advance on the clock: propose when this node is the attempt's proposer
 * and the floors have passed, re-broadcast, and skip a timed-out attempt.
 * Call at least every few seconds. */
void ants_chain_rt_tick(ants_chain_rt_t *rt, uint64_t now);

/* A proposal arrived (canonical block bytes). Malformed or irrelevant
 * input is ignored — the returned code only reports why, for logging:
 * ANTS_OK when filed (and signed, if this node is an eligible member whose
 * recomputation matched); MALFORMED / NON_CANONICAL on undecodable bytes;
 * UNSUPPORTED_TYPE for a non-degraded block (v1 holds no beacon to
 * recompute its committee). */
ants_error_t
ants_chain_rt_on_proposal(ants_chain_rt_t *rt, const uint8_t *block, size_t len, uint64_t now);

/* An attestation arrived. Filed if its signer is a trustee and its height
 * is above the head; signatures are checked when finality is evaluated. */
void ants_chain_rt_on_attestation(ants_chain_rt_t *rt,
                                  const ants_chain_attestation_t *att,
                                  uint64_t now);

/* The current final head. */
void ants_chain_rt_head(const ants_chain_rt_t *rt, ants_chain_head_t *out);

/* The height of the attempt in progress (head height + 1 + skips). */
uint64_t ants_chain_rt_attempt_height(const ants_chain_rt_t *rt);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_CHAIN_RUNTIME_H */
