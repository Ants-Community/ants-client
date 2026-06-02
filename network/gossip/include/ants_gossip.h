/*
 * ants_gossip.h — Gossip overlay: L1 CRDT propagation (Component #6,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * The transport of the reputation layer. Layer 1 (reputation/crdt,
 * Component #7) defines the grow-only set of self-authenticating fault
 * proofs and the VERIFY predicate; THIS component is the epidemic
 * dissemination that carries a proof from the peer that detected a fault
 * to every other honest peer. The reference sketch (RFC-0004 §"A reference
 * sketch") is exactly three lines:
 *
 *     def on_receive_proof(self, π):
 *         if not verify_fault(π): rate_limit(sender); return   # drop garbage
 *         if π in self.proof_set: return                       # dedup: stop
 *         self.proof_set.add(π); apply_slash(π); self.gossip(π) # forward
 *
 * The dedup line is what makes the epidemic terminate and what makes the
 * one-honest-path property hold: a proof needs only ONE honest path from
 * detector to victim within the propagation window `T_prop` to slash
 * globally (RFC-0004 §"The structural win") — not an honest majority.
 *
 * DESIGN: transport-agnostic. This component is the dissemination LOGIC —
 * receive, VERIFY-and-apply (by inserting into the caller's L1 G-Set),
 * dedup, and forward to a fanout of view peers — with the actual byte
 * delivery left to a caller-supplied `send_fn`. The canonical binding of
 * send_fn opens an `ants_transport` bidi stream per peer and writes the
 * frame; a test binds it to an in-process queue. Keeping transport behind
 * the callback makes the dissemination core fully testable without a live
 * QUIC handshake, and lets the same engine drive any delivery substrate.
 * Wiring send_fn to real transport streams + the inbound demux is a later
 * PR (mirrors how cache/semantic landed its local engine before the
 * 7b/7c transport phases).
 *
 * The G-Set is the dedup oracle: `ants_crdt_insert` already runs VERIFY,
 * stores a private copy, and reports whether the proof was NEW — so the
 * engine reuses it directly rather than re-implementing verify-or-dedup.
 * A proof that fails VERIFY is counted (the attributable-fault / rate-limit
 * hook of RFC-0004 §DoS) but never forwarded; a duplicate is silently
 * dropped (the epidemic terminates); only a genuinely new valid proof is
 * forwarded onward, excluding the peer it arrived from.
 *
 * Scope of THIS module (Component #6):
 *   - the peer view (the set of neighbours we gossip to) + add/remove;
 *   - the eager-push wire frame (one fault proof per frame), canonical
 *     CBOR per RFC-0008 §1.1;
 *   - the dissemination engine: ants_gossip_submit (local origination) +
 *     ants_gossip_on_message (receive → insert → forward), with fanout,
 *     dedup via the G-Set, sender-exclusion, and per-peer reject counting;
 *   - lazy-pull anti-entropy (IHAVE/IWANT): ants_gossip_announce advertises
 *     the local proof digest, a peer pulls what it lacks, and on_message
 *     serves the request — catch-up for proofs the eager push missed;
 *   - propagation instrumentation: aggregate counters (ants_gossip_get_stats)
 *     and a per-new-proof observation hook (ants_gossip_set_observer) that
 *     timestamp when each proof is first seen — the raw material a testnet
 *     correlates across nodes to check T_prop against the T_beacon budget;
 *   - reject accountability (ants_gossip_set_reject_handler /
 *     ants_gossip_peer_reject_count): a per-peer tally of proofs that failed
 *     VERIFY — the local "rate-limit the sender" half of RFC-0004 §DoS;
 *   - the real-ants_transport binding (uni-stream push + inbound demux) at
 *     the foot of this header.
 *
 * Deliberately NOT here: anti-eclipse peer SAMPLING from the DHT (RFC-0005) —
 * the view is still caller-managed — and a globally-attributable *emitted*
 * fault proof against a garbage relayer, which needs signed forwards (a wire
 * change) plus a fault class (RFC-0004 §DoS, "a relayer who signs forwards").
 * (The persistent per-connection outbound channel, the `T_prop < T_beacon`
 * instrumentation, and LOCAL reject accountability — rate-limit the sender —
 * have since landed; see the transport binding below, §Instrumentation, and
 * §Reject accountability respectively.)
 *
 * WIRE FORMAT IS DRAFT, defined by this module pending formalisation in
 * RFC-0008 (the same status the DHT and cache wire formats carried before
 * their spec sections existed). It MUST be upstreamed before two
 * independent implementations gossip to each other.
 *
 * Caller-driven, no malloc, no threads, no hidden global state: the engine
 * state (including the peer view) lives in a caller-allocated opaque ctx,
 * exactly like ants_transport / ants_dht. Spec: RFC-0004 v0.6; RFC-0008
 * v0.5 §1.1. Component README: ants-client/network/gossip/README.md.
 */

#ifndef ANTS_GOSSIP_H
#define ANTS_GOSSIP_H

#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_transport.h" /* for the transport binding at the foot of this header */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Parameters                                                               */
/* ------------------------------------------------------------------------ */

/* A peer is its 32-byte Ed25519 public key (== protocol peer-id), matching
 * ants_crdt / ants_transport. MUST equal ANTS_CRDT_PEER_ID_SIZE. */
#define ANTS_GOSSIP_PEER_ID_SIZE 32u

/* Maximum neighbours in the peer view. A real deployment samples a small
 * view from the DHT for anti-eclipse (RFC-0005); 64 is a generous ceiling
 * for the fixed-size, malloc-free view. Adding past it returns
 * ANTS_ERROR_BUFFER_TOO_SMALL. */
#define ANTS_GOSSIP_MAX_VIEW 64u

/* Default fanout `f`: how many view peers each NEW proof is forwarded to
 * (RFC-0004 §"The propagation bound", `T_prop ≈ c·Δ·log N` with fanout f).
 * DRAFT — the real f is a b2-class testnet measurement trading bandwidth
 * (higher f) against propagation latency (lower f → larger T_prop). */
#define ANTS_GOSSIP_DEFAULT_FANOUT 6u

/* Default cap on an inbound frame, bytes. A push frame is one fault proof
 * plus a few bytes of envelope; a fault proof is a few hundred bytes. 4 KiB
 * is comfortable headroom and bounds the decode work per message
 * (RFC-0004 §DoS). Frames larger than the configured cap are rejected
 * MALFORMED without decoding. */
#define ANTS_GOSSIP_DEFAULT_MAX_FRAME 4096u

/* Encoded size of a push frame: the envelope overhead beyond the proof
 * bytes (map(2) header, two integer keys, the byte-string header). 16 is a
 * safe ceiling; a caller sizing a send buffer uses proof_len + this. */
#define ANTS_GOSSIP_PUSH_OVERHEAD_MAX 16u

/*
 * Gossip message types (the frame's `type` field). Integer-stable and
 * append-only, like ants_error_t and the fault-class enum: a deployed value
 * never changes its number.
 *   PUSH  — eager push of a single fault proof.
 *   IHAVE — lazy-pull digest: "I hold these content-ids" (anti-entropy).
 *   IWANT — lazy-pull request: "send me these content-ids".
 * Decoding an unknown type fails closed with ANTS_ERROR_UNSUPPORTED_TYPE.
 */
#define ANTS_GOSSIP_MSG_PUSH  0u
#define ANTS_GOSSIP_MSG_IHAVE 1u
#define ANTS_GOSSIP_MSG_IWANT 2u

/* Maximum content-ids carried in one IHAVE/IWANT frame. 64 ids × 32 bytes +
 * envelope sits well under the default 4 KiB frame cap; anti-entropy here is
 * incremental (bulk late-joiner sync is the Component #7 G-Set snapshot), so
 * a bounded digest per round is by design. A frame carrying more ids than
 * this is rejected MALFORMED. */
#define ANTS_GOSSIP_MAX_IDS 64u

/* ------------------------------------------------------------------------ */
/* Outbound delivery callback                                               */
/* ------------------------------------------------------------------------ */

/*
 * Deliver `frame[0..len)` to `peer_id`. The engine calls this once per
 * chosen fanout peer when forwarding a new proof. The frame bytes are
 * valid only for the duration of the call (they live in the engine's stack
 * frame); a transport binding must copy them into its own send buffer if
 * it cannot write synchronously. The callback does not report success: the
 * gossip layer is best-effort by design (lost frames are recovered by the
 * epidemic's redundancy and by the late-joiner snapshot), so delivery
 * failures are the transport's concern, not the dissemination logic's.
 *
 * @param peer_id  the 32-byte neighbour to send to.
 * @param frame    the canonical push frame.
 * @param ctx      the send_ctx cookie from ants_gossip_init.
 */
typedef void (*ants_gossip_send_fn)(const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE],
                                    const uint8_t *frame,
                                    size_t len,
                                    void *ctx);

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Peers to forward each new proof to. 0 → ANTS_GOSSIP_DEFAULT_FANOUT.
     * Clamped to the current view size at forward time. */
    size_t fanout;
    /* Reject inbound frames larger than this (bytes). 0 →
     * ANTS_GOSSIP_DEFAULT_MAX_FRAME. */
    size_t max_frame_bytes;
} ants_gossip_config_t;

/* ------------------------------------------------------------------------ */
/* Opaque context                                                           */
/*                                                                          */
/* Caller-allocated, same idiom as ants_transport / ants_dht: a union of an */
/* _opaque[] byte buffer with a uint64_t _align anchor (so a cast to the    */
/* internal struct is well-defined on alignment-strict targets). The .c     */
/* enforces the real size via the compile-time-assert idiom. Holds the      */
/* peer view, the rotation cursor, the G-Set pointer, self-id, config, and  */
/* the send callback — no allocation, the view is a fixed array.            */
/* ------------------------------------------------------------------------ */

#define ANTS_GOSSIP_CTX_SIZE 8192

typedef union {
    uint8_t _opaque[ANTS_GOSSIP_CTX_SIZE];
    uint64_t _align;
} ants_gossip_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle + peer view                                                    */
/* ------------------------------------------------------------------------ */

/*
 * Initialise a gossip engine.
 *
 * @param g         caller-allocated context.
 * @param gset      the local L1 G-Set (Component #7) this engine
 *                  disseminates into. Borrowed, not owned; must outlive g.
 * @param self_id   this peer's 32-byte id (so the engine never forwards to
 *                  itself even if it appears in the view).
 * @param cfg       optional; NULL applies all defaults.
 * @param send_fn   outbound delivery callback (must be non-NULL).
 * @param send_ctx  cookie passed to send_fn (may be NULL).
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL g / gset / self_id /
 *         send_fn, or a cfg.fanout exceeding ANTS_GOSSIP_MAX_VIEW.
 */
ants_error_t ants_gossip_init(ants_gossip_t *g,
                              ants_crdt_t *gset,
                              const uint8_t self_id[ANTS_GOSSIP_PEER_ID_SIZE],
                              const ants_gossip_config_t *cfg,
                              ants_gossip_send_fn send_fn,
                              void *send_ctx);

/*
 * Add a neighbour to the peer view. Idempotent (adding a peer already in
 * the view is ANTS_OK, no duplicate). Adding `self_id` is a no-op success
 * (the engine never gossips to itself). The view is the set of peers the
 * engine forwards to; PR1 takes it as caller-managed (anti-eclipse DHT
 * sampling is a later PR).
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL; ANTS_ERROR_BUFFER_TOO_SMALL
 *         if the view is full (ANTS_GOSSIP_MAX_VIEW).
 */
ants_error_t ants_gossip_add_peer(ants_gossip_t *g,
                                  const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE]);

/*
 * Remove a neighbour from the peer view. Removing a peer not present is
 * ANTS_OK (idempotent).
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL.
 */
ants_error_t ants_gossip_remove_peer(ants_gossip_t *g,
                                     const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE]);

/* Number of peers currently in the view. 0 if g is NULL. */
size_t ants_gossip_peer_count(const ants_gossip_t *g);

/* ------------------------------------------------------------------------ */
/* Push-frame wire codec (canonical CBOR, RFC-0008 §1.1)                    */
/* ------------------------------------------------------------------------ */

/*
 * Encode a single-proof PUSH frame: canonical CBOR map(2), integer keys
 * ascending:
 *   0: type  (uint)   ANTS_GOSSIP_MSG_PUSH.
 *   1: proof (bytes)  the canonical fault-proof envelope (as produced by
 *                     ants_crdt_equivocation_encode); opaque here — the
 *                     receiver re-runs VERIFY on it.
 * Float-free. Exposed for the transport binding and for tests; the engine
 * uses it internally when forwarding.
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL or proof_len 0;
 *         BUFFER_TOO_SMALL if cap is insufficient (buf untouched).
 */
ants_error_t ants_gossip_push_encode(const uint8_t *proof,
                                     size_t proof_len,
                                     uint8_t *buf,
                                     size_t cap,
                                     size_t *out_len);

/*
 * Decode + canonically validate a PUSH frame. On success `*out_proof`
 * aliases into `buf` (no copy) and `*out_proof_len` is its length. Does NOT
 * run VERIFY on the proof — that is the engine's job on insert.
 *
 * @return ANTS_OK; INVALID_ARG on NULL/len 0; MALFORMED if not a
 *         well-formed PUSH frame; NON_CANONICAL if well-formed but violates
 *         RFC 8949 §4.2.1; UNSUPPORTED_TYPE if the type field is a known-
 *         reserved-but-unimplemented or unknown gossip message type.
 */
ants_error_t ants_gossip_push_decode(const uint8_t *buf,
                                     size_t len,
                                     const uint8_t **out_proof,
                                     size_t *out_proof_len);

/* ------------------------------------------------------------------------ */
/* Dissemination engine                                                     */
/* ------------------------------------------------------------------------ */

/*
 * Locally originate a fault proof (this peer detected the fault). The proof
 * is VERIFY-inserted into the G-Set; if it is NEW, a PUSH frame is built
 * and sent to up-to-fanout view peers via send_fn. If the proof is already
 * in the set, this is a no-op (it was gossiped when first seen) and
 * *out_forwarded is 0.
 *
 * @param out_forwarded optional; the number of peers the frame was sent to
 *                      (0 if the proof was a duplicate or the view empty).
 * @return ANTS_OK on insert-or-duplicate; the VERIFY verdict from
 *         ants_crdt_insert (MALFORMED / NON_CANONICAL / UNSUPPORTED_TYPE /
 *         NOT_IMPLEMENTED) if the proof does not verify; INVALID_ARG on
 *         NULL g / proof / proof_len 0; ANTS_ERROR_MALFORMED if the G-Set
 *         insert hits allocation failure.
 */
ants_error_t
ants_gossip_submit(ants_gossip_t *g, const uint8_t *proof, size_t proof_len, size_t *out_forwarded);

/*
 * Handle a gossip frame received from `from_peer`, dispatching by its
 * message type. A lazy-pull IHAVE/IWANT (see §Lazy-pull anti-entropy below)
 * is answered back to `from_peer` only: IHAVE → an IWANT naming the ids the
 * local G-Set lacks; IWANT → a PUSH of each requested proof held.
 * out_new / out_rejected stay 0 for IHAVE/IWANT (no proof is inserted by the
 * frame itself; pulled proofs surface as out_new on the PUSH that answers).
 * A PUSH frame feeds its carried proof through the reference-sketch path:
 *   - VERIFY-insert into the G-Set;
 *   - if it fails VERIFY → *out_rejected += 1 (the rate-limit /
 *     attributable-fault hook), the proof is dropped, NOT forwarded;
 *   - if it is NEW → *out_new += 1 and the proof is forwarded to fanout
 *     view peers EXCLUDING from_peer (so it does not bounce back);
 *   - if it is a duplicate → dropped silently (the epidemic terminates).
 *
 * A frame that is not a well-formed canonical PUSH frame, or exceeds the
 * configured max_frame_bytes, is rejected wholesale (return MALFORMED /
 * NON_CANONICAL / UNSUPPORTED_TYPE) — distinct from a well-framed message
 * carrying an unverifiable proof, which is the counted per-proof reject.
 *
 * @param from_peer    the neighbour the frame arrived on (excluded from
 *                     forwarding). May be NULL if the source is unknown, in
 *                     which case no peer is excluded.
 * @param out_new      optional; 1 if the proof was new and forwarded, else 0.
 * @param out_rejected optional; 1 if the proof failed VERIFY, else 0.
 * @return ANTS_OK if the frame was well-formed (regardless of whether its
 *         proof was new, duplicate, or rejected); INVALID_ARG on NULL g /
 *         frame / len 0; MALFORMED / NON_CANONICAL / UNSUPPORTED_TYPE on a
 *         malformed frame; ANTS_ERROR_MALFORMED on G-Set allocation failure.
 */
ants_error_t ants_gossip_on_message(ants_gossip_t *g,
                                    const uint8_t from_peer[ANTS_GOSSIP_PEER_ID_SIZE],
                                    const uint8_t *frame,
                                    size_t len,
                                    size_t *out_new,
                                    size_t *out_rejected);

/* ------------------------------------------------------------------------ */
/* Instrumentation — the T_prop budget (RFC-0004 v0.6 §"The propagation     */
/* bound")                                                                  */
/*                                                                          */
/* Layer 1's security rests on a single timing budget: a fault proof must    */
/* reach the honest subgraph FASTER than the verifier beacon rotates, i.e.   */
/* `T_prop < T_beacon` (RFC-0004 §"The structural win"). The engine cannot   */
/* know T_prop on its own — it is a network-wide quantity — but it can       */
/* expose the raw material a testnet correlates across nodes to measure it,  */
/* WITHOUT a wire-format change and WITHOUT a clock-sync assumption (no       */
/* absolute timestamp ever crosses the wire):                                */
/*   - aggregate counters (ants_gossip_stats_t): how many proofs this node    */
/*     originated, learned new from a peer, dropped as duplicate, rejected,   */
/*     and forwarded, plus the IHAVE/IWANT anti-entropy tallies;              */
/*   - a per-new-proof observation hook: each time a proof is FIRST inserted  */
/*     (locally or from a peer) the engine stamps its local monotonic clock   */
/*     and calls the observer with the proof's content-id, that stamp, and    */
/*     which path introduced it. A collector keyed by content-id — using the  */
/*     per-node clock offsets it already tracks — reconstructs the end-to-end */
/*     propagation distribution: the detector's LOCAL stamp is t0, every PEER */
/*     stamp is an arrival, and T_prop is their spread.                       */
/* Both are passive and optional: counters cost a few increments; the         */
/* observer costs one content-id hash per new proof, and only when a hook is  */
/* registered. The MEASUREMENT (clock alignment, percentiles, the budget      */
/* check itself) is the harness's job — this is the INSTRUMENTATION.          */
/* ------------------------------------------------------------------------ */

/* Which path first introduced a proof, passed to the observation hook. */
#define ANTS_GOSSIP_PROOF_ORIGIN_LOCAL 0 /* this node detected it (ants_gossip_submit)        */
#define ANTS_GOSSIP_PROOF_ORIGIN_PEER  1 /* learned new from a peer (ants_gossip_on_message)  */

/*
 * Aggregate, monotone-increasing engine counters, all counting EVENTS since
 * ants_gossip_init. A snapshot copy is returned by ants_gossip_get_stats; the
 * engine never resets them.
 */
typedef struct {
    uint64_t originated;     /* new proofs introduced locally (submit)        */
    uint64_t received_new;   /* new proofs first learned from a peer (PUSH)   */
    uint64_t duplicates;     /* inbound PUSH proofs already held (dedup stop) */
    uint64_t rejected;       /* inbound PUSH proofs that failed VERIFY        */
    uint64_t forwarded;      /* eager-push frames sent onward (fanout total)  */
    uint64_t ihave_sent;     /* IHAVE digests sent (ants_gossip_announce)     */
    uint64_t ihave_received; /* IHAVE digests handled                         */
    uint64_t iwant_sent;     /* IWANT pull-requests sent (answering an IHAVE) */
    uint64_t iwant_received; /* IWANT pull-requests handled                   */
    uint64_t pulled_served;  /* PUSH frames sent in answer to an IWANT        */
    uint64_t first_seen_us;  /* monotonic stamp of the FIRST new proof (0 until one is seen) */
    uint64_t last_seen_us;   /* monotonic stamp of the most recent new proof  */
} ants_gossip_stats_t;

/*
 * Copy the engine's current counters into *out.
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL g / out.
 */
ants_error_t ants_gossip_get_stats(const ants_gossip_t *g, ants_gossip_stats_t *out);

/*
 * Per-new-proof observation hook (see §Instrumentation above). Called once,
 * synchronously, the first time a proof is inserted into the G-Set via this
 * engine — NOT for duplicates and NOT for proofs that fail VERIFY. `content_id`
 * aliases a stack buffer valid only for the call (copy it to retain).
 * `first_seen_us` is this node's CLOCK_MONOTONIC reading at insert (microseconds,
 * comparable only to this node's own stamps). `origin` is one of
 * ANTS_GOSSIP_PROOF_ORIGIN_LOCAL / _PEER.
 */
typedef void (*ants_gossip_observe_fn)(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                                       uint64_t first_seen_us,
                                       int origin,
                                       void *ctx);

/*
 * Register (or clear) the observation hook. Optional; an engine with no
 * observer skips the hook (and its content-id hash). fn == NULL disables it.
 * Takes effect immediately for subsequent inserts.
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if g is NULL.
 */
ants_error_t ants_gossip_set_observer(ants_gossip_t *g, ants_gossip_observe_fn fn, void *ctx);

/* ------------------------------------------------------------------------ */
/* Reject accountability — rate-limit the sender (RFC-0004 §DoS)            */
/*                                                                          */
/* Invalid-proof spam (W3) is bounded, not prevented: a relayer flooding     */
/* unverifiable proofs costs every receiver an O(f) VERIFY per novel frame.  */
/* The reference sketch's response is `rate_limit(sender_of(π))`. The frame   */
/* source is the transport-authenticated `from_peer` (QUIC mutual auth), so a */
/* receiver KNOWS locally who relayed garbage — enough to throttle or drop    */
/* that peer. It is NOT enough to PROVE it to a third party: a globally-       */
/* attributable, gossipable fault proof would need the relayer's signature    */
/* over the forward (a wire change) plus a fault class — deferred (RFC-0004    */
/* §DoS, "a relayer who signs forwards"). So this is the LOCAL half: the       */
/* engine tallies rejects per source peer and fires a hook with the running    */
/* count; the CALLER enforces policy (transport disconnect, view eviction).    */
/* ------------------------------------------------------------------------ */

/* Max distinct peers tracked for reject accounting. When full, the lowest-
 * count slot is reused, so a flood of one-off garbage from many peers never
 * evicts a persistent offender. */
#define ANTS_GOSSIP_REJECT_TABLE_SIZE 64u

/*
 * Reject hook: called once per inbound proof that FAILS VERIFY, with the source
 * peer and its running reject count (>= 1). Fires only when the source is known
 * (a NULL from_peer in ants_gossip_on_message is unattributable — tallied in
 * stats.rejected only). The caller uses the count to apply its own rate-limit /
 * disconnect policy. peer_id aliases a buffer valid only for the call.
 */
typedef void (*ants_gossip_reject_fn)(const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE],
                                      uint64_t reject_count,
                                      void *ctx);

/*
 * Register (or clear, fn == NULL) the reject hook. Optional; takes effect
 * immediately. @return ANTS_OK; ANTS_ERROR_INVALID_ARG if g is NULL.
 */
ants_error_t ants_gossip_set_reject_handler(ants_gossip_t *g, ants_gossip_reject_fn fn, void *ctx);

/*
 * The running count of inbound proofs from `peer_id` that failed VERIFY. 0 if
 * g / peer_id is NULL or the peer is untracked (none rejected, or evicted from a
 * full table). O(n) over the bounded reject table.
 */
uint64_t ants_gossip_peer_reject_count(const ants_gossip_t *g,
                                       const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE]);

/* ------------------------------------------------------------------------ */
/* Lazy-pull anti-entropy (IHAVE / IWANT)                                   */
/*                                                                          */
/* The eager push is best-effort: a frame lost in flight, or a peer that    */
/* joined the view after a proof swept through, leaves a gap the push will   */
/* not refill on its own. Lazy pull closes it. A peer periodically          */
/* advertises a digest of the content-ids it holds (IHAVE); a receiver that  */
/* is missing some replies with an IWANT naming exactly those; the           */
/* advertiser answers each wanted id with an ordinary PUSH. on_message       */
/* dispatches all three types, so the same receive entry point drives the    */
/* whole protocol, and the IHAVE→IWANT / IWANT→PUSH replies go to from_peer  */
/* only. Bulk late-joiner sync remains the Component #7 G-Set snapshot; this */
/* is incremental catch-up, so each digest/request is bounded to             */
/* ANTS_GOSSIP_MAX_IDS ids.                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Encode an IHAVE / IWANT frame: canonical CBOR map(2), integer keys
 * ascending:
 *   0: type (uint)           ANTS_GOSSIP_MSG_IHAVE / _IWANT.
 *   1: ids  (array of bytes) `n` content-ids, each ANTS_CRDT_CONTENT_ID_SIZE.
 * `n` must be in 1..ANTS_GOSSIP_MAX_IDS. Exposed for tests and external
 * drivers; the engine builds these internally for announce / pull replies.
 *
 * @return ANTS_OK with *out_len set; INVALID_ARG on NULL or n out of range;
 *         BUFFER_TOO_SMALL if cap is insufficient (buf untouched).
 */
ants_error_t ants_gossip_ihave_encode(const uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                                      size_t n,
                                      uint8_t *buf,
                                      size_t cap,
                                      size_t *out_len);
ants_error_t ants_gossip_iwant_encode(const uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                                      size_t n,
                                      uint8_t *buf,
                                      size_t cap,
                                      size_t *out_len);

/*
 * Originate a lazy-pull round: build an IHAVE digest of up to
 * ANTS_GOSSIP_MAX_IDS content-ids the local G-Set holds and send it to
 * up-to-fanout view peers (the same rotating selection as push). A node
 * calls this periodically (an anti-entropy tick); peers missing any
 * advertised proof pull it via IWANT. With an empty G-Set or empty view,
 * nothing is sent and *out_sent is 0.
 *
 * @param out_sent optional; the number of peers the IHAVE was sent to.
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL g.
 */
ants_error_t ants_gossip_announce(ants_gossip_t *g, size_t *out_sent);

/* ------------------------------------------------------------------------ */
/* Transport binding (Component #6 PR2)                                     */
/*                                                                          */
/* The canonical wiring of the engine's send_fn to a real ants_transport,    */
/* plus the inbound demux that feeds received frames back into the engine.   */
/* The engine (above) stays transport-agnostic; this binding is the glue,    */
/* so the in-process engine tests keep working without a QUIC handshake.     */
/*                                                                          */
/* The binding opens ONE persistent UNIDIRECTIONAL stream per connection      */
/* (RFC-0004 §Layer 1 propagation is one-way; the transport reserves uni      */
/* streams for exactly this, see ants_transport.h) and reuses it for every    */
/* proof forwarded to that peer — so the number of retained outbound handles  */
/* is bounded by the connection count, not the proof volume. Because the      */
/* stream is never FIN'd per message, each frame is length-delimited: a       */
/* 2-byte big-endian length prefix precedes the frame bytes. The receiver's   */
/* inbound demux deframes the continuous byte stream back into individual     */
/* frames and hands each to ants_gossip_on_message. (picoquic copies each     */
/* send into its own ordered queue, so a frame is queued whole or not at all  */
/* — no partial frame ever corrupts the framing; a rare queue-full drops a    */
/* whole frame, best-effort.)                                                 */
/*                                                                          */
/* Connection discovery is REACTIVE: the binding learns (peer_id → conn)     */
/* from CONN_READY events and uses those connections for sends. It does NOT  */
/* dial — the caller (bootstrap, the DHT, or a later anti-eclipse PR that    */
/* samples the view from the DHT) owns dialing. A send to a peer the binding */
/* has no live connection to is dropped: gossip is best-effort by design     */
/* (the epidemic's redundancy and the Component #7 late-joiner snapshot      */
/* recover dropped frames).                                                  */
/*                                                                          */
/* Outbound stream lifetime: the transport leaves locally-opened handles to  */
/* the caller and fires no "send complete" event for a one-way stream, so a  */
/* handle is freed only when its connection closes (CONN_CLOSED). The         */
/* persistent-per-connection channel means at most                           */
/* ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS handles (one per live           */
/* connection) are ever held — proof volume no longer fills the pool. A peer  */
/* with no live connection, or one whose channel cannot be opened, drops the  */
/* forward best-effort (the epidemic's redundancy + the #7 snapshot recover   */
/* it).                                                                       */
/*                                                                          */
/* TEARDOWN ORDER: ants_transport_destroy MUST run BEFORE                    */
/* ants_gossip_transport_destroy whenever the binding may hold outbound      */
/* handles, so transport_destroy's CONN_CLOSED callbacks free them while     */
/* picoquic still owns the connection (same rule the DHT follows for its     */
/* heap conns/streams).                                                      */
/* ------------------------------------------------------------------------ */

/* Maximum live (peer_id → conn) mappings. One per gossip neighbour we have a
 * connection to; sized to the view ceiling. */
#define ANTS_GOSSIP_TRANSPORT_MAX_CONNS 64u

/* Maximum concurrent inbound gossip streams being accumulated. A peer pushes
 * one proof per stream and FINs promptly, so concurrency is low. */
#define ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS 32u

/* Per-inbound-stream accumulation cap (bytes): one length-prefixed frame —
 * the engine's default max frame plus the 2-byte length prefix. The deframer
 * drains complete frames as they arrive, so the buffer never holds more than
 * one in-progress prefixed frame; a declared length over the engine cap, or a
 * frame that otherwise cannot be deframed, releases the stream. */
#define ANTS_GOSSIP_TRANSPORT_INBOUND_RECV_CAP (ANTS_GOSSIP_DEFAULT_MAX_FRAME + 2u)

/* Maximum persistent outbound channels — one unidirectional stream per live
 * connection (see the lifetime note above). Bounded by the connection count,
 * not the proof volume. */
#define ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS 64u

/* Caller-allocated opaque context for the binding, same idiom as the engine
 * / transport / dht: a byte buffer with a uint64_t alignment anchor; the .c
 * enforces the real size via the compile-time-assert idiom. Holds the engine
 * + transport back-pointers and the three registries (conns, inbound streams,
 * retained outbound streams). The binding heap-allocates per-stream handles
 * and inbound accumulation buffers, like the DHT. */
#define ANTS_GOSSIP_TRANSPORT_CTX_SIZE 16384

typedef union {
    uint8_t _opaque[ANTS_GOSSIP_TRANSPORT_CTX_SIZE];
    uint64_t _align;
} ants_gossip_transport_t;

/*
 * Initialise the transport binding.
 *
 * Wiring is two calls, in this order:
 *
 *     ants_gossip_transport_init(&binding, &engine, &transport);
 *     ants_gossip_init(&engine, gset, self_id, cfg,
 *                      ants_gossip_transport_send, &binding);
 *
 * The binding stores the engine pointer (used by the inbound demux to call
 * ants_gossip_on_message) and the transport pointer (used to open streams);
 * the engine stores the binding as its send_ctx. `engine` need not be
 * initialised yet at this call — only the pointer is captured.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on any NULL argument.
 */
ants_error_t ants_gossip_transport_init(ants_gossip_transport_t *b,
                                        ants_gossip_t *engine,
                                        ants_transport_t *transport);

/*
 * The engine send_fn binding: opens a uni stream to `peer_id` (if a live
 * connection is known) and writes `frame` with FIN. `ctx` MUST be the
 * ants_gossip_transport_t* passed to ants_gossip_init as send_ctx. Matches
 * the ants_gossip_send_fn signature. Best-effort: silently drops when no
 * connection is known or the outbound pool is exhausted.
 */
void ants_gossip_transport_send(const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE],
                                const uint8_t *frame,
                                size_t len,
                                void *ctx);

/*
 * Hand a transport event to the binding. Call this from inside the caller's
 * single registered transport event_fn (the transport allows only one), the
 * same delegation pattern as ants_dht_handle_transport_event:
 *
 *     static ants_error_t my_event(const ants_transport_event_t *ev, void *c) {
 *         my_app_t *app = c;
 *         ants_dht_handle_transport_event(&app->dht, ev);
 *         ants_gossip_transport_handle_event(&app->gossip_binding, ev);
 *         return ANTS_OK;
 *     }
 *
 * Consumes: CONN_READY (register peer_id → conn), CONN_CLOSED (free this
 * conn's retained outbound handles + inbound accumulators, drop the mapping),
 * and inbound STREAM_OPENED/READABLE/FIN/RESET (accumulate a pushed frame and,
 * on FIN, feed it to the engine). Events that belong to another subsystem
 * (e.g. the DHT's own streams) are left untouched — a stream the binding did
 * not open as inbound is a cheap no-op. Does NOT call back into the
 * transport for inbound handling; forwarding triggered by on_message goes
 * through the engine's send_fn (this binding's send), which opens new streams
 * on OTHER connections — safe per the transport's callback contract.
 *
 * @return ANTS_OK (including when the event was not the binding's);
 *         ANTS_ERROR_INVALID_ARG on NULL args.
 */
ants_error_t ants_gossip_transport_handle_event(ants_gossip_transport_t *b,
                                                const ants_transport_event_t *event);

/* Number of live (peer_id → conn) mappings the binding currently holds. 0 if
 * b is NULL. Introspection for tests / diagnostics. */
size_t ants_gossip_transport_conn_count(const ants_gossip_transport_t *b);

/*
 * Tear down the binding: free every retained outbound stream handle and
 * inbound accumulation buffer. Idempotent on a zeroed binding. See the
 * TEARDOWN ORDER note above — destroy the transport first.
 */
void ants_gossip_transport_destroy(ants_gossip_transport_t *b);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_GOSSIP_H */
