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
 * Scope of THIS module (PR1 of Component #6):
 *   - the peer view (the set of neighbours we gossip to) + add/remove;
 *   - the eager-push wire frame (one fault proof per frame), canonical
 *     CBOR per RFC-0008 §1.1;
 *   - the dissemination engine: ants_gossip_submit (local origination) +
 *     ants_gossip_on_message (receive → insert → forward), with fanout,
 *     dedup via the G-Set, sender-exclusion, and per-peer reject counting.
 *
 * Deliberately NOT here (later PRs): wiring send_fn to real
 * ants_transport bidi streams + the inbound stream demux; lazy-pull
 * (IHAVE/IWANT) anti-entropy for catch-up (the G-Set snapshot from
 * Component #7 already covers bulk late-joiner sync); anti-eclipse peer
 * SAMPLING from the DHT (RFC-0005) — PR1 takes the view as given by the
 * caller; the `T_prop < T_beacon` budget instrumentation; and turning a
 * relay's reject counter into an actual emitted fault proof.
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
 *   PUSH — eager push of a single fault proof. IMPLEMENTED here.
 * IHAVE / IWANT (lazy-pull anti-entropy) are reserved for a later PR;
 * decoding an unknown type fails closed with ANTS_ERROR_UNSUPPORTED_TYPE.
 */
#define ANTS_GOSSIP_MSG_PUSH      0u
#define ANTS_GOSSIP_MSG__RESERVED 1u

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
 * Handle a gossip frame received from `from_peer`. Decodes the PUSH frame
 * and feeds the carried proof through the reference-sketch path:
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

#ifdef __cplusplus
}
#endif

#endif /* ANTS_GOSSIP_H */
