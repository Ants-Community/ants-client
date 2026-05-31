/*
 * gossip.c — Gossip overlay: L1 CRDT propagation (Component #6,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * PR1: the transport-agnostic dissemination engine + the eager-push wire
 * frame. The reference-sketch path (receive → VERIFY-and-apply → dedup →
 * forward to fanout) runs over the caller's real L1 G-Set, with byte
 * delivery behind a send callback. See ants_gossip.h for the design.
 *
 * The G-Set (ants_crdt_insert) is the VERIFY-and-dedup oracle: it runs
 * VERIFY, stores a private copy, and reports NEW vs duplicate — so this
 * engine never re-implements verify-or-dedup, it just routes the outcome.
 *
 * No malloc, no threads, no hidden global state; the engine state (peer
 * view included) lives in the caller's opaque ctx. Spec: RFC-0004 v0.6;
 * RFC-0008 v0.5 §1.1 (canonical CBOR).
 */

#include "ants_gossip.h"

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Push-frame schema (DRAFT, defined here — see header)                      */
/*   map(2) { 0: type(uint), 1: proof(bytes) }                              */
/* ------------------------------------------------------------------------ */

enum { GOSSIP_KEY_TYPE = 0, GOSSIP_KEY_PROOF = 1 };
#define GOSSIP_PUSH_PAIRS 2

/* Largest proof we will frame for forwarding, so the send buffer is a
 * bounded stack array. A fault proof is a few hundred bytes; this is the
 * default max-frame minus the envelope overhead, the symmetric bound to
 * what on_message will accept by default. */
#define GOSSIP_MAX_PROOF (ANTS_GOSSIP_DEFAULT_MAX_FRAME - ANTS_GOSSIP_PUSH_OVERHEAD_MAX)

/* ------------------------------------------------------------------------ */
/* Engine state (lives in the caller's opaque ctx)                           */
/* ------------------------------------------------------------------------ */

struct gossip_state {
    ants_crdt_t *gset; /* borrowed L1 G-Set; the dedup oracle      */
    ants_gossip_send_fn send_fn;
    void *send_ctx;
    uint8_t self_id[ANTS_GOSSIP_PEER_ID_SIZE];
    size_t fanout;          /* resolved (default applied)              */
    size_t max_frame_bytes; /* resolved                               */
    size_t n_view;          /* peers in the view                       */
    size_t rotation;        /* cursor for deterministic fanout pick     */
    uint8_t view[ANTS_GOSSIP_MAX_VIEW][ANTS_GOSSIP_PEER_ID_SIZE];
};

/* The opaque ctx must be large enough to hold the real state. */
typedef char gossip_ctx_size_check[(sizeof(struct gossip_state) <= ANTS_GOSSIP_CTX_SIZE) ? 1 : -1];

static struct gossip_state *state_of(ants_gossip_t *g)
{
    /* Cast through void* so -Wcast-align stays quiet: the union's uint64_t
     * _align member guarantees 8-byte alignment of _opaque, so the cast is
     * sound. Same idiom as network/dht's dht_state(). */
    return (struct gossip_state *)(void *)g->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Push-frame wire codec                                                     */
/* ------------------------------------------------------------------------ */

ants_error_t ants_gossip_push_encode(const uint8_t *proof,
                                     size_t proof_len,
                                     uint8_t *buf,
                                     size_t cap,
                                     size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (proof == NULL || buf == NULL || out_len == NULL || proof_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_map(&enc, GOSSIP_PUSH_PAIRS)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, GOSSIP_KEY_TYPE)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, ANTS_GOSSIP_MSG_PUSH)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, GOSSIP_KEY_PROOF)) != ANTS_OK ||
        (rc = ants_cbor_enc_bytes(&enc, proof, proof_len)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_gossip_push_decode(const uint8_t *buf,
                                     size_t len,
                                     const uint8_t **out_proof,
                                     size_t *out_proof_len)
{
    ants_cbor_dec_t dec;
    ants_cbor_type_t ty;
    size_t n;
    uint64_t k, type;
    ants_error_t rc;

    if (buf == NULL || out_proof == NULL || out_proof_len == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Whole-frame canonical gate first: cleanly separates "not even CBOR"
     * (MALFORMED) from "well-formed but non-canonical" (NON_CANONICAL). */
    rc = ants_cbor_is_canonical(buf, len);
    if (rc != ANTS_OK) {
        return rc;
    }
    if (ants_cbor_dec_init(&dec, buf, len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_map(&dec, &n) != ANTS_OK || n != GOSSIP_PUSH_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    /* key 0: type. */
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &k) != ANTS_OK || k != GOSSIP_KEY_TYPE) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &type) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (type != ANTS_GOSSIP_MSG_PUSH) {
        /* Known-reserved or unknown gossip message type — fail closed. */
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    /* key 1: proof. */
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &k) != ANTS_OK || k != GOSSIP_KEY_PROOF) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_BYTES) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_bytes(&dec, out_proof, out_proof_len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_finalise(&dec) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle + peer view                                                    */
/* ------------------------------------------------------------------------ */

ants_error_t ants_gossip_init(ants_gossip_t *g,
                              ants_crdt_t *gset,
                              const uint8_t self_id[ANTS_GOSSIP_PEER_ID_SIZE],
                              const ants_gossip_config_t *cfg,
                              ants_gossip_send_fn send_fn,
                              void *send_ctx)
{
    struct gossip_state *s;

    if (g == NULL || gset == NULL || self_id == NULL || send_fn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (cfg != NULL && cfg->fanout > ANTS_GOSSIP_MAX_VIEW) {
        return ANTS_ERROR_INVALID_ARG;
    }

    s = state_of(g);
    memset(s, 0, sizeof *s);
    s->gset = gset;
    s->send_fn = send_fn;
    s->send_ctx = send_ctx;
    memcpy(s->self_id, self_id, ANTS_GOSSIP_PEER_ID_SIZE);
    s->fanout = (cfg != NULL && cfg->fanout != 0) ? cfg->fanout : ANTS_GOSSIP_DEFAULT_FANOUT;
    s->max_frame_bytes = (cfg != NULL && cfg->max_frame_bytes != 0) ? cfg->max_frame_bytes
                                                                    : ANTS_GOSSIP_DEFAULT_MAX_FRAME;
    s->n_view = 0;
    s->rotation = 0;
    return ANTS_OK;
}

/* Index of peer_id in the view, or -1. */
static int view_find(const struct gossip_state *s, const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE])
{
    size_t i;
    for (i = 0; i < s->n_view; i++) {
        if (memcmp(s->view[i], peer_id, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
            return (int)i;
        }
    }
    return -1;
}

ants_error_t ants_gossip_add_peer(ants_gossip_t *g, const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE])
{
    struct gossip_state *s;

    if (g == NULL || peer_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);

    /* Never gossip to ourselves: silently ignore self in the view. */
    if (memcmp(peer_id, s->self_id, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
        return ANTS_OK;
    }
    if (view_find(s, peer_id) >= 0) {
        return ANTS_OK; /* idempotent */
    }
    if (s->n_view >= ANTS_GOSSIP_MAX_VIEW) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(s->view[s->n_view], peer_id, ANTS_GOSSIP_PEER_ID_SIZE);
    s->n_view++;
    return ANTS_OK;
}

ants_error_t ants_gossip_remove_peer(ants_gossip_t *g,
                                     const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE])
{
    struct gossip_state *s;
    int idx;

    if (g == NULL || peer_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);
    idx = view_find(s, peer_id);
    if (idx < 0) {
        return ANTS_OK; /* idempotent */
    }
    /* Compact: move the last entry into the hole (order is irrelevant). */
    if ((size_t)idx != s->n_view - 1) {
        memcpy(s->view[idx], s->view[s->n_view - 1], ANTS_GOSSIP_PEER_ID_SIZE);
    }
    s->n_view--;
    return ANTS_OK;
}

size_t ants_gossip_peer_count(const ants_gossip_t *g)
{
    if (g == NULL) {
        return 0;
    }
    return ((const struct gossip_state *)(const void *)g->_opaque)->n_view;
}

/* ------------------------------------------------------------------------ */
/* Forwarding                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Forward `proof` to up to `fanout` view peers, skipping `exclude` (the
 * peer it arrived from; NULL excludes none). Peers are chosen by a rotating
 * cursor so successive forwards cover the whole view over time without an
 * RNG (same deterministic-rotation discipline as the ledger's optimistic
 * unchoke). Returns the number of peers actually sent to.
 */
static size_t forward_proof(struct gossip_state *s,
                            const uint8_t *proof,
                            size_t proof_len,
                            const uint8_t *exclude)
{
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    size_t frame_len = 0;
    size_t sent = 0;
    size_t want, scanned;

    if (s->n_view == 0 || proof_len > GOSSIP_MAX_PROOF) {
        return 0;
    }
    if (ants_gossip_push_encode(proof, proof_len, frame, sizeof frame, &frame_len) != ANTS_OK) {
        return 0;
    }

    want = (s->fanout < s->n_view) ? s->fanout : s->n_view;

    /* Walk the view from the rotating cursor; send to the first `want`
     * peers that are not the excluded sender. Scan at most the whole view
     * so a view of all-excluded (size 1 == sender) terminates. */
    for (scanned = 0; scanned < s->n_view && sent < want; scanned++) {
        size_t i = (s->rotation + scanned) % s->n_view;
        if (exclude != NULL && memcmp(s->view[i], exclude, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
            continue;
        }
        s->send_fn(s->view[i], frame, frame_len, s->send_ctx);
        sent++;
    }
    /* Advance the cursor past the peers we considered, so the next forward
     * starts where this one left off (spreads load across the view). */
    if (s->n_view > 0) {
        s->rotation = (s->rotation + scanned) % s->n_view;
    }
    return sent;
}

/* ------------------------------------------------------------------------ */
/* Dissemination engine                                                     */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_gossip_submit(ants_gossip_t *g, const uint8_t *proof, size_t proof_len, size_t *out_forwarded)
{
    struct gossip_state *s;
    bool inserted = false;
    ants_error_t rc;

    if (out_forwarded != NULL) {
        *out_forwarded = 0;
    }
    if (g == NULL || proof == NULL || proof_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);

    /* VERIFY-and-dedup via the G-Set. */
    rc = ants_crdt_insert(s->gset, proof, proof_len, &inserted);
    if (rc != ANTS_OK) {
        return rc; /* proof did not verify (or OOM) */
    }
    if (!inserted) {
        return ANTS_OK; /* already known → already gossiped; no-op */
    }
    /* New proof we originated → forward to fanout (exclude nobody). */
    {
        size_t fwd = forward_proof(s, proof, proof_len, NULL);
        if (out_forwarded != NULL) {
            *out_forwarded = fwd;
        }
    }
    return ANTS_OK;
}

ants_error_t ants_gossip_on_message(ants_gossip_t *g,
                                    const uint8_t from_peer[ANTS_GOSSIP_PEER_ID_SIZE],
                                    const uint8_t *frame,
                                    size_t len,
                                    size_t *out_new,
                                    size_t *out_rejected)
{
    struct gossip_state *s;
    const uint8_t *proof = NULL;
    size_t proof_len = 0;
    bool inserted = false;
    ants_error_t rc;

    if (out_new != NULL) {
        *out_new = 0;
    }
    if (out_rejected != NULL) {
        *out_rejected = 0;
    }
    if (g == NULL || frame == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);

    /* Oversized frames are rejected without decoding (RFC-0004 §DoS). */
    if (len > s->max_frame_bytes) {
        return ANTS_ERROR_MALFORMED;
    }
    /* Decode the frame; a malformed frame is a whole-message failure. */
    rc = ants_gossip_push_decode(frame, len, &proof, &proof_len);
    if (rc != ANTS_OK) {
        return rc; /* MALFORMED / NON_CANONICAL / UNSUPPORTED_TYPE */
    }

    /* Feed the carried proof through VERIFY-and-dedup. */
    rc = ants_crdt_insert(s->gset, proof, proof_len, &inserted);
    if (rc == ANTS_ERROR_INVALID_ARG) {
        return rc; /* structural arg error, not a proof verdict */
    }
    if (rc != ANTS_OK) {
        /* The proof did not VERIFY: count it (the rate-limit /
         * attributable-fault hook) and drop it. The FRAME was well-formed,
         * so the call itself succeeds — a peer relaying a bad proof is a
         * per-proof event, not a transport error. */
        if (out_rejected != NULL) {
            *out_rejected = 1;
        }
        return ANTS_OK;
    }
    if (!inserted) {
        return ANTS_OK; /* duplicate → epidemic terminates here */
    }
    /* New valid proof → forward onward, excluding the peer it came from. */
    {
        size_t fwd = forward_proof(s, proof, proof_len, from_peer);
        (void)fwd; /* forwarding is best-effort; count "new", not "sent" */
        if (out_new != NULL) {
            *out_new = 1;
        }
    }
    return ANTS_OK;
}
