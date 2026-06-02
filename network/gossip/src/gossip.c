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

/* POSIX feature test — required on glibc to expose clock_gettime() /
 * CLOCK_MONOTONIC / struct timespec from <time.h> for the propagation
 * instrumentation clock. macOS exposes them by default; this define is benign
 * there. Must precede every system header. Mirrors network/dht. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_gossip.h"

#include "ants_cbor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------------ */
/* Clock — monotonic microseconds for the propagation instrumentation        */
/* (first-seen / last-seen stamps + the per-new-proof observation hook). We   */
/* compare only deltas, so CLOCK_MONOTONIC avoids NTP back-jumps; the         */
/* CLOCK_REALTIME fallback is paranoia for unusual builds. Mirrors            */
/* network/dht's dht_now_us().                                                */
/* ------------------------------------------------------------------------ */

static uint64_t gossip_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            return 0;
        }
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* ------------------------------------------------------------------------ */
/* Frame schema (DRAFT, defined here — see header). Every gossip frame is a  */
/* canonical-CBOR map(2): { 0: type(uint), 1: payload }. PUSH's payload is   */
/* the fault-proof byte-string; IHAVE/IWANT's is an array of content-id      */
/* byte-strings. GOSSIP_KEY_PROOF and GOSSIP_KEY_IDS are the same key (1),    */
/* named per payload kind.                                                   */
/* ------------------------------------------------------------------------ */

enum { GOSSIP_KEY_TYPE = 0, GOSSIP_KEY_PROOF = 1, GOSSIP_KEY_IDS = 1 };
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
    ants_gossip_observe_fn observe_fn; /* optional per-new-proof hook (NULL = off) */
    void *observe_ctx;
    uint8_t self_id[ANTS_GOSSIP_PEER_ID_SIZE];
    size_t fanout;             /* resolved (default applied)              */
    size_t max_frame_bytes;    /* resolved                               */
    size_t n_view;             /* peers in the view                       */
    size_t rotation;           /* cursor for deterministic fanout pick     */
    bool seen_any;             /* gates stats.first_seen_us (the clock can read 0) */
    ants_gossip_stats_t stats; /* propagation instrumentation (T_prop budget)      */
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

/* Encode an IHAVE/IWANT frame: map(2){0:type, 1: array(n) of content-id
 * bytes}. Shared by the public ihave/iwant encoders, by announce, and by the
 * IHAVE→IWANT pull-request path. */
static ants_error_t ids_encode(uint64_t type,
                               const uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                               size_t n,
                               uint8_t *buf,
                               size_t cap,
                               size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;
    size_t i;

    if (ids == NULL || buf == NULL || out_len == NULL || n == 0 || n > ANTS_GOSSIP_MAX_IDS) {
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
        (rc = ants_cbor_enc_uint(&enc, type)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, GOSSIP_KEY_IDS)) != ANTS_OK ||
        (rc = ants_cbor_enc_array(&enc, n)) != ANTS_OK) {
        return rc;
    }
    for (i = 0; i < n; i++) {
        if ((rc = ants_cbor_enc_bytes(&enc, ids[i], ANTS_CRDT_CONTENT_ID_SIZE)) != ANTS_OK) {
            return rc;
        }
    }
    if ((rc = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_gossip_ihave_encode(const uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                                      size_t n,
                                      uint8_t *buf,
                                      size_t cap,
                                      size_t *out_len)
{
    return ids_encode(ANTS_GOSSIP_MSG_IHAVE, ids, n, buf, cap, out_len);
}

ants_error_t ants_gossip_iwant_encode(const uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                                      size_t n,
                                      uint8_t *buf,
                                      size_t cap,
                                      size_t *out_len)
{
    return ids_encode(ANTS_GOSSIP_MSG_IWANT, ids, n, buf, cap, out_len);
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

/* Read just the message type (key 0) from a frame, after the whole-frame
 * canonical gate — so on_message can dispatch before the type-specific
 * decode. Same canonical-then-parse discipline as push_decode. */
static ants_error_t peek_frame_type(const uint8_t *buf, size_t len, uint64_t *out_type)
{
    ants_cbor_dec_t dec;
    ants_cbor_type_t ty;
    size_t n;
    uint64_t k;
    ants_error_t rc;

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
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &k) != ANTS_OK || k != GOSSIP_KEY_TYPE) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, out_type) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* Decode an IHAVE/IWANT frame (type must equal expect_type) into out_ids,
 * copying its content-ids; *out_count is the number decoded. The caller runs
 * the canonical gate via peek_frame_type first. An empty or over-cap id
 * array, a wrong type, a wrong-width id, or any structural deviation is
 * MALFORMED. */
static ants_error_t ids_decode(const uint8_t *buf,
                               size_t len,
                               uint64_t expect_type,
                               uint8_t (*out_ids)[ANTS_CRDT_CONTENT_ID_SIZE],
                               size_t cap,
                               size_t *out_count)
{
    ants_cbor_dec_t dec;
    ants_cbor_type_t ty;
    size_t n, m, i;
    uint64_t k, type;

    if (ants_cbor_dec_init(&dec, buf, len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_map(&dec, &n) != ANTS_OK || n != GOSSIP_PUSH_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    /* key 0: type == expect_type. */
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &k) != ANTS_OK || k != GOSSIP_KEY_TYPE) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &type) != ANTS_OK || type != expect_type) {
        return ANTS_ERROR_MALFORMED;
    }
    /* key 1: ids (array of 32-byte content-ids). */
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(&dec, &k) != ANTS_OK || k != GOSSIP_KEY_IDS) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_ARRAY) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_array(&dec, &m) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (m == 0 || m > cap) {
        return ANTS_ERROR_MALFORMED;
    }
    for (i = 0; i < m; i++) {
        const uint8_t *p = NULL;
        size_t plen = 0;
        if (ants_cbor_dec_peek_type(&dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_BYTES) {
            return ANTS_ERROR_MALFORMED;
        }
        if (ants_cbor_dec_bytes(&dec, &p, &plen) != ANTS_OK || plen != ANTS_CRDT_CONTENT_ID_SIZE) {
            return ANTS_ERROR_MALFORMED;
        }
        memcpy(out_ids[i], p, ANTS_CRDT_CONTENT_ID_SIZE);
    }
    if (ants_cbor_dec_finalise(&dec) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    *out_count = m;
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

ants_error_t ants_gossip_get_stats(const ants_gossip_t *g, ants_gossip_stats_t *out)
{
    if (g == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    *out = ((const struct gossip_state *)(const void *)g->_opaque)->stats;
    return ANTS_OK;
}

ants_error_t ants_gossip_set_observer(ants_gossip_t *g, ants_gossip_observe_fn fn, void *ctx)
{
    struct gossip_state *s;

    if (g == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);
    s->observe_fn = fn;
    s->observe_ctx = ctx;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Forwarding                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Send a prebuilt `frame` to up to `fanout` view peers, skipping `exclude`
 * (NULL excludes none). Peers are chosen by a rotating cursor so successive
 * sends cover the whole view over time without an RNG (same deterministic-
 * rotation discipline as the ledger's optimistic unchoke). Returns the number
 * of peers actually sent to. Used for both eager-push forwarding and the
 * lazy-pull IHAVE announce.
 */
static size_t
fanout_send(struct gossip_state *s, const uint8_t *frame, size_t frame_len, const uint8_t *exclude)
{
    size_t sent = 0;
    size_t want, scanned;

    if (s->n_view == 0) {
        return 0;
    }
    want = (s->fanout < s->n_view) ? s->fanout : s->n_view;

    /* Walk the view from the rotating cursor; send to the first `want` peers
     * that are not the excluded sender. Scan at most the whole view so a view
     * of all-excluded (size 1 == sender) terminates. */
    for (scanned = 0; scanned < s->n_view && sent < want; scanned++) {
        size_t i = (s->rotation + scanned) % s->n_view;
        if (exclude != NULL && memcmp(s->view[i], exclude, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
            continue;
        }
        s->send_fn(s->view[i], frame, frame_len, s->send_ctx);
        sent++;
    }
    /* Advance the cursor past the peers we considered, so the next send starts
     * where this one left off (spreads load across the view). */
    s->rotation = (s->rotation + scanned) % s->n_view;
    return sent;
}

/*
 * Forward a single fault `proof` to the fanout as an eager PUSH, skipping
 * `exclude` (the peer it arrived from; NULL excludes none). Returns the number
 * of peers actually sent to.
 */
static size_t forward_proof(struct gossip_state *s,
                            const uint8_t *proof,
                            size_t proof_len,
                            const uint8_t *exclude)
{
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    size_t frame_len = 0;

    if (s->n_view == 0 || proof_len > GOSSIP_MAX_PROOF) {
        return 0;
    }
    if (ants_gossip_push_encode(proof, proof_len, frame, sizeof frame, &frame_len) != ANTS_OK) {
        return 0;
    }
    return fanout_send(s, frame, frame_len, exclude);
}

/* Stamp + observe a proof the engine has just inserted as NEW — the single
 * place first_seen/last_seen advance and the observer fires. `origin` is
 * ANTS_GOSSIP_PROOF_ORIGIN_LOCAL or _PEER. */
static void record_new_proof(struct gossip_state *s, const uint8_t *proof, size_t len, int origin)
{
    uint64_t now = gossip_now_us();
    if (!s->seen_any) {
        s->stats.first_seen_us = now;
        s->seen_any = true;
    }
    s->stats.last_seen_us = now;
    if (s->observe_fn != NULL) {
        uint8_t cid[ANTS_CRDT_CONTENT_ID_SIZE];
        if (ants_crdt_content_id(proof, len, cid) == ANTS_OK) {
            s->observe_fn(cid, now, origin, s->observe_ctx);
        }
    }
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
        size_t fwd;
        s->stats.originated++;
        record_new_proof(s, proof, proof_len, ANTS_GOSSIP_PROOF_ORIGIN_LOCAL);
        fwd = forward_proof(s, proof, proof_len, NULL);
        s->stats.forwarded += fwd;
        if (out_forwarded != NULL) {
            *out_forwarded = fwd;
        }
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lazy-pull anti-entropy (IHAVE / IWANT)                                    */
/* ------------------------------------------------------------------------ */

/* Enumerate visitor: collect up to cc->cap content-ids into cc->ids. */
struct collect_ids_ctx {
    uint8_t (*ids)[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t count;
    size_t cap;
};
static bool collect_ids_visit(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                              const uint8_t *proof,
                              size_t len,
                              void *ctx)
{
    struct collect_ids_ctx *c = ctx;
    (void)proof;
    (void)len;
    if (c->count >= c->cap) {
        return false; /* digest full → stop enumerating */
    }
    memcpy(c->ids[c->count], content_id, ANTS_CRDT_CONTENT_ID_SIZE);
    c->count++;
    return c->count < c->cap;
}

ants_error_t ants_gossip_announce(ants_gossip_t *g, size_t *out_sent)
{
    struct gossip_state *s;
    uint8_t ids[ANTS_GOSSIP_MAX_IDS][ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    struct collect_ids_ctx cc;
    size_t frame_len = 0;
    ants_error_t rc;

    if (out_sent != NULL) {
        *out_sent = 0;
    }
    if (g == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = state_of(g);
    if (s->n_view == 0) {
        return ANTS_OK; /* nobody to advertise to */
    }

    cc.ids = ids;
    cc.count = 0;
    cc.cap = ANTS_GOSSIP_MAX_IDS;
    ants_crdt_enumerate(s->gset, collect_ids_visit, &cc);
    if (cc.count == 0) {
        return ANTS_OK; /* empty G-Set → nothing to advertise */
    }

    rc = ids_encode(ANTS_GOSSIP_MSG_IHAVE, ids, cc.count, frame, sizeof frame, &frame_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    {
        size_t sent = fanout_send(s, frame, frame_len, NULL);
        s->stats.ihave_sent += sent;
        if (out_sent != NULL) {
            *out_sent = sent;
        }
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Inbound dispatch handlers (called by ants_gossip_on_message)              */
/* ------------------------------------------------------------------------ */

/* PUSH: VERIFY-insert the carried proof; forward if new, count if rejected. */
static ants_error_t handle_push(struct gossip_state *s,
                                const uint8_t *from_peer,
                                const uint8_t *frame,
                                size_t len,
                                size_t *out_new,
                                size_t *out_rejected)
{
    const uint8_t *proof = NULL;
    size_t proof_len = 0;
    bool inserted = false;
    ants_error_t rc;

    rc = ants_gossip_push_decode(frame, len, &proof, &proof_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_crdt_insert(s->gset, proof, proof_len, &inserted);
    if (rc == ANTS_ERROR_INVALID_ARG) {
        return rc; /* structural arg error, not a proof verdict */
    }
    if (rc != ANTS_OK) {
        /* The proof did not VERIFY: count it (the rate-limit /
         * attributable-fault hook) and drop it. The FRAME was well-formed,
         * so the call itself succeeds — a peer relaying a bad proof is a
         * per-proof event, not a transport error. */
        s->stats.rejected++;
        if (out_rejected != NULL) {
            *out_rejected = 1;
        }
        return ANTS_OK;
    }
    if (!inserted) {
        s->stats.duplicates++;
        return ANTS_OK; /* duplicate → epidemic terminates here */
    }
    /* New valid proof → forward onward, excluding the peer it came from. */
    s->stats.received_new++;
    record_new_proof(s, proof, proof_len, ANTS_GOSSIP_PROOF_ORIGIN_PEER);
    s->stats.forwarded += forward_proof(s, proof, proof_len, from_peer);
    if (out_new != NULL) {
        *out_new = 1;
    }
    return ANTS_OK;
}

/* IHAVE: reply to from_peer with an IWANT naming the advertised ids the local
 * G-Set lacks. No reply if we hold them all, or if from_peer is unknown. */
static ants_error_t
handle_ihave(struct gossip_state *s, const uint8_t *from_peer, const uint8_t *frame, size_t len)
{
    uint8_t ids[ANTS_GOSSIP_MAX_IDS][ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t want[ANTS_GOSSIP_MAX_IDS][ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t frame_out[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    size_t n = 0, n_want = 0, i, frame_len = 0;
    ants_error_t rc;

    rc = ids_decode(frame, len, ANTS_GOSSIP_MSG_IHAVE, ids, ANTS_GOSSIP_MAX_IDS, &n);
    if (rc != ANTS_OK) {
        return rc;
    }
    s->stats.ihave_received++;
    if (from_peer == NULL) {
        return ANTS_OK; /* cannot direct a reply at an unknown source */
    }
    for (i = 0; i < n; i++) {
        if (!ants_crdt_contains(s->gset, ids[i])) {
            memcpy(want[n_want++], ids[i], ANTS_CRDT_CONTENT_ID_SIZE);
        }
    }
    if (n_want == 0) {
        return ANTS_OK; /* already hold everything advertised */
    }
    rc = ids_encode(ANTS_GOSSIP_MSG_IWANT, want, n_want, frame_out, sizeof frame_out, &frame_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    s->send_fn(from_peer, frame_out, frame_len, s->send_ctx);
    s->stats.iwant_sent++;
    return ANTS_OK;
}

/* IWANT serving (enumerate visitor): for each held proof whose content-id was
 * requested, PUSH it back to the requester. */
struct serve_iwant_ctx {
    struct gossip_state *s;
    const uint8_t *target;
    const uint8_t (*want)[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t n_want;
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
};
static bool serve_iwant_visit(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                              const uint8_t *proof,
                              size_t len,
                              void *ctx)
{
    struct serve_iwant_ctx *c = ctx;
    size_t i, frame_len = 0;

    for (i = 0; i < c->n_want; i++) {
        if (memcmp(content_id, c->want[i], ANTS_CRDT_CONTENT_ID_SIZE) == 0) {
            if (len <= GOSSIP_MAX_PROOF &&
                ants_gossip_push_encode(proof, len, c->frame, sizeof c->frame, &frame_len) ==
                    ANTS_OK) {
                c->s->send_fn(c->target, c->frame, frame_len, c->s->send_ctx);
                c->s->stats.pulled_served++;
            }
            break; /* this proof matched one wanted id; move on */
        }
    }
    return true; /* serve every match → keep enumerating */
}

/* IWANT: serve each requested content-id we hold back to from_peer as a PUSH. */
static ants_error_t
handle_iwant(struct gossip_state *s, const uint8_t *from_peer, const uint8_t *frame, size_t len)
{
    uint8_t want[ANTS_GOSSIP_MAX_IDS][ANTS_CRDT_CONTENT_ID_SIZE];
    size_t n_want = 0;
    struct serve_iwant_ctx c;
    ants_error_t rc;

    rc = ids_decode(frame, len, ANTS_GOSSIP_MSG_IWANT, want, ANTS_GOSSIP_MAX_IDS, &n_want);
    if (rc != ANTS_OK) {
        return rc;
    }
    s->stats.iwant_received++;
    if (from_peer == NULL) {
        return ANTS_OK;
    }
    c.s = s;
    c.target = from_peer;
    c.want = want;
    c.n_want = n_want;
    ants_crdt_enumerate(s->gset, serve_iwant_visit, &c);
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
    uint64_t type = 0;
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
    /* Canonical gate + read the message type, then dispatch. A malformed or
     * non-canonical frame is a whole-message failure. */
    rc = peek_frame_type(frame, len, &type);
    if (rc != ANTS_OK) {
        return rc; /* MALFORMED / NON_CANONICAL */
    }
    switch (type) {
    case ANTS_GOSSIP_MSG_PUSH:
        return handle_push(s, from_peer, frame, len, out_new, out_rejected);
    case ANTS_GOSSIP_MSG_IHAVE:
        return handle_ihave(s, from_peer, frame, len);
    case ANTS_GOSSIP_MSG_IWANT:
        return handle_iwant(s, from_peer, frame, len);
    default:
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
}
