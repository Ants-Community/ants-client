/*
 * gossip_transport.c — Gossip overlay transport binding (Component #6 PR2,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * Wires the transport-agnostic dissemination engine (gossip.c) to a real
 * ants_transport: the engine's send_fn opens a unidirectional QUIC stream
 * per forwarded proof, and the inbound demux accumulates a peer's pushed
 * frame until FIN and feeds it to ants_gossip_on_message. See the
 * "Transport binding" section of ants_gossip.h for the full design.
 *
 * Three registries live in the caller's opaque ctx:
 *   - conns[]    : (peer_id → conn), learned from CONN_READY, used by send
 *                  to map a fanout peer to a live connection;
 *   - inbound[]  : per inbound stream, a lazily-allocated accumulation buffer
 *                  (heap), released on FIN/RESET or the conn's CONN_CLOSED;
 *   - outbound[] : retained handles for the uni streams we opened to forward
 *                  proofs. The transport leaves locally-opened handles to the
 *                  caller and fires no completion event for a one-way stream,
 *                  so each is held until its connection closes; the pool is
 *                  bounded and further forwards are dropped best-effort.
 *
 * Per-stream handles and accumulation buffers are heap-allocated (so the
 * registries hold pointers, not 1 KB inline structs) — the same ownership
 * model as network/dht's dht_rpc / dht_server. The transport never frees a
 * locally-opened handle; we reclaim it on CONN_CLOSED, by which point
 * picoquic has no further callbacks targeting that stream_ctx.
 */

#include "ants_gossip.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Registry entry types + engine state (lives in the caller's opaque ctx)    */
/* ------------------------------------------------------------------------ */

struct gt_conn {
    bool in_use;
    ants_transport_conn_t *conn;
    uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE];
};

struct gt_inbound {
    bool in_use;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* identity key; not owned (transport's) */
    uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE];
    uint8_t *recv_buf; /* heap, lazy-alloc on first readable */
    size_t recv_len;
    size_t recv_cap;
};

struct gt_outbound {
    bool in_use;
    ants_transport_conn_t *conn;     /* swept on this conn's CONN_CLOSED   */
    ants_transport_stream_t *stream; /* heap; freed on CONN_CLOSED/destroy */
};

struct gossip_transport_state {
    ants_gossip_t *engine;       /* borrowed; inbound FINs feed on_message    */
    ants_transport_t *transport; /* borrowed; (unused directly — streams are
                                  * opened on the conns learned via events)   */
    struct gt_conn conns[ANTS_GOSSIP_TRANSPORT_MAX_CONNS];
    struct gt_inbound inbound[ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS];
    struct gt_outbound outbound[ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS];
};

/* The opaque ctx must be large enough to hold the real state. */
typedef char gossip_transport_ctx_size_check
    [(sizeof(struct gossip_transport_state) <= ANTS_GOSSIP_TRANSPORT_CTX_SIZE) ? 1 : -1];

static struct gossip_transport_state *state_of(ants_gossip_transport_t *b)
{
    /* The union's uint64_t _align member guarantees 8-byte alignment of
     * _opaque, so the cast through void* is sound (same idiom as gossip.c /
     * dht). */
    return (struct gossip_transport_state *)(void *)b->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Connection registry (peer_id → conn)                                      */
/* ------------------------------------------------------------------------ */

static ants_transport_conn_t *conn_find_by_peer(struct gossip_transport_state *s,
                                                const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_CONNS; i++) {
        if (s->conns[i].in_use &&
            memcmp(s->conns[i].peer_id, peer_id, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
            return s->conns[i].conn;
        }
    }
    return NULL;
}

/* Register (or refresh) a peer_id → conn mapping. A peer that reconnects on a
 * new conn refreshes its existing slot; a full registry drops the mapping
 * (sends to that peer then fall through to best-effort drop). */
static void conn_register(struct gossip_transport_state *s,
                          const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE],
                          ants_transport_conn_t *conn)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_CONNS; i++) {
        if (s->conns[i].in_use &&
            memcmp(s->conns[i].peer_id, peer_id, ANTS_GOSSIP_PEER_ID_SIZE) == 0) {
            s->conns[i].conn = conn; /* refresh */
            return;
        }
    }
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_CONNS; i++) {
        if (!s->conns[i].in_use) {
            s->conns[i].in_use = true;
            s->conns[i].conn = conn;
            memcpy(s->conns[i].peer_id, peer_id, ANTS_GOSSIP_PEER_ID_SIZE);
            return;
        }
    }
    /* Full — drop (best-effort). */
}

static void conn_remove(struct gossip_transport_state *s, const ants_transport_conn_t *conn)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_CONNS; i++) {
        if (s->conns[i].in_use && s->conns[i].conn == conn) {
            memset(&s->conns[i], 0, sizeof s->conns[i]);
        }
    }
}

size_t ants_gossip_transport_conn_count(const ants_gossip_transport_t *b)
{
    if (b == NULL) {
        return 0;
    }
    const struct gossip_transport_state *s =
        (const struct gossip_transport_state *)(const void *)b->_opaque;
    size_t n = 0;
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_CONNS; i++) {
        if (s->conns[i].in_use) {
            n++;
        }
    }
    return n;
}

/* ------------------------------------------------------------------------ */
/* Inbound stream registry                                                   */
/* ------------------------------------------------------------------------ */

static struct gt_inbound *inbound_find_by_stream(struct gossip_transport_state *s,
                                                 const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS; i++) {
        if (s->inbound[i].in_use && s->inbound[i].stream == stream) {
            return &s->inbound[i];
        }
    }
    return NULL;
}

static struct gt_inbound *inbound_alloc(struct gossip_transport_state *s,
                                        ants_transport_conn_t *conn,
                                        ants_transport_stream_t *stream,
                                        const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS; i++) {
        if (!s->inbound[i].in_use) {
            struct gt_inbound *slot = &s->inbound[i];
            slot->in_use = true;
            slot->conn = conn;
            slot->stream = stream;
            memcpy(slot->peer_id, peer_id, ANTS_GOSSIP_PEER_ID_SIZE);
            slot->recv_buf = NULL;
            slot->recv_len = 0;
            slot->recv_cap = 0;
            return slot;
        }
    }
    return NULL; /* full — a sibling subsystem may still take the stream */
}

static void inbound_release(struct gt_inbound *slot)
{
    if (slot->recv_buf != NULL) {
        free(slot->recv_buf);
    }
    memset(slot, 0, sizeof *slot);
}

/* On FIN the accumulated bytes are a complete push frame: hand them to the
 * engine (which decodes, VERIFY-inserts, dedups, and may forward — the
 * forward goes back through this binding's send on OTHER conns). A frame the
 * engine cannot decode is rejected there; we release either way and never
 * reset, so a stream that belongs to another subsystem is left for it to
 * claim (same politeness as dht_server's process_fin). */
static void process_inbound_fin(struct gossip_transport_state *s, struct gt_inbound *slot)
{
    if (slot->recv_buf != NULL && slot->recv_len > 0) {
        (void)ants_gossip_on_message(
            s->engine, slot->peer_id, slot->recv_buf, slot->recv_len, NULL, NULL);
    }
    inbound_release(slot);
}

/* ------------------------------------------------------------------------ */
/* Outbound stream registry                                                  */
/* ------------------------------------------------------------------------ */

static struct gt_outbound *outbound_alloc(struct gossip_transport_state *s)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS; i++) {
        if (!s->outbound[i].in_use) {
            return &s->outbound[i];
        }
    }
    return NULL; /* pool exhausted — drop the forward (best-effort) */
}

/* Free every retained outbound handle bound to `conn`. Called on CONN_CLOSED,
 * after which picoquic issues no further callbacks for these streams. */
static void outbound_sweep_conn(struct gossip_transport_state *s, const ants_transport_conn_t *conn)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS; i++) {
        if (s->outbound[i].in_use && s->outbound[i].conn == conn) {
            free(s->outbound[i].stream);
            memset(&s->outbound[i], 0, sizeof s->outbound[i]);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_gossip_transport_init(ants_gossip_transport_t *b,
                                        ants_gossip_t *engine,
                                        ants_transport_t *transport)
{
    if (b == NULL || engine == NULL || transport == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct gossip_transport_state *s = state_of(b);
    memset(s, 0, sizeof *s);
    s->engine = engine;
    s->transport = transport;
    return ANTS_OK;
}

void ants_gossip_transport_send(const uint8_t peer_id[ANTS_GOSSIP_PEER_ID_SIZE],
                                const uint8_t *frame,
                                size_t len,
                                void *ctx)
{
    if (ctx == NULL || peer_id == NULL || frame == NULL || len == 0) {
        return;
    }
    struct gossip_transport_state *s = state_of((ants_gossip_transport_t *)ctx);

    ants_transport_conn_t *conn = conn_find_by_peer(s, peer_id);
    if (conn == NULL) {
        return; /* no live connection to this peer — best-effort drop */
    }
    struct gt_outbound *slot = outbound_alloc(s);
    if (slot == NULL) {
        return; /* outbound pool exhausted — drop */
    }
    ants_transport_stream_t *stream =
        (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
    if (stream == NULL) {
        return; /* slot left free (not marked in_use) */
    }
    if (ants_transport_open_uni_stream(conn, stream) != ANTS_OK) {
        /* open failed → picoquic holds no reference to the handle → safe to
         * free immediately. */
        free(stream);
        return;
    }
    /* picoquic now references the handle as the stream's app ctx — retain it
     * until CONN_CLOSED regardless of whether the send succeeds. */
    slot->in_use = true;
    slot->conn = conn;
    slot->stream = stream;
    (void)ants_transport_stream_send(stream, frame, len, true /* fin */);
}

ants_error_t ants_gossip_transport_handle_event(ants_gossip_transport_t *b,
                                                const ants_transport_event_t *event)
{
    if (b == NULL || event == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct gossip_transport_state *s = state_of(b);

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        conn_register(s, event->peer_id.bytes, event->conn);
        return ANTS_OK;

    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        outbound_sweep_conn(s, event->conn);
        for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS; i++) {
            if (s->inbound[i].in_use && s->inbound[i].conn == event->conn) {
                inbound_release(&s->inbound[i]);
            }
        }
        conn_remove(s, event->conn);
        return ANTS_OK;

    default:
        break;
    }

    if (event->stream == NULL) {
        return ANTS_OK;
    }

    /* A peer-initiated stream → bind an accumulation slot. (Our own outbound
     * uni streams never surface STREAM_OPENED to us.) */
    if (event->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        if (inbound_find_by_stream(s, event->stream) == NULL) {
            (void)inbound_alloc(s, event->conn, event->stream, event->peer_id.bytes);
            /* full → no-op; a sibling dispatcher may still take the stream */
        }
        return ANTS_OK;
    }

    struct gt_inbound *slot = inbound_find_by_stream(s, event->stream);
    if (slot == NULL) {
        return ANTS_OK; /* not one of ours (outbound, another subsystem, or
                         * overran the registry) */
    }

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        if (event->payload == NULL || event->payload_len == 0) {
            break;
        }
        if (slot->recv_buf == NULL) {
            slot->recv_buf = (uint8_t *)malloc(ANTS_GOSSIP_TRANSPORT_INBOUND_RECV_CAP);
            if (slot->recv_buf == NULL) {
                inbound_release(slot);
                break;
            }
            slot->recv_cap = ANTS_GOSSIP_TRANSPORT_INBOUND_RECV_CAP;
            slot->recv_len = 0;
        }
        if (event->payload_len > slot->recv_cap - slot->recv_len) {
            /* Overflows the frame cap — not a valid gossip push frame. Stop
             * accumulating; release (no reset, so a sibling can claim it). */
            inbound_release(slot);
            break;
        }
        memcpy(slot->recv_buf + slot->recv_len, event->payload, event->payload_len);
        slot->recv_len += event->payload_len;
        break;

    case ANTS_TRANSPORT_EV_STREAM_FIN:
        process_inbound_fin(s, slot);
        break;

    case ANTS_TRANSPORT_EV_STREAM_RESET:
        inbound_release(slot);
        break;

    default:
        break;
    }
    return ANTS_OK;
}

void ants_gossip_transport_destroy(ants_gossip_transport_t *b)
{
    if (b == NULL) {
        return;
    }
    struct gossip_transport_state *s = state_of(b);
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS; i++) {
        if (s->outbound[i].in_use) {
            free(s->outbound[i].stream);
            memset(&s->outbound[i], 0, sizeof s->outbound[i]);
        }
    }
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_INBOUND_STREAMS; i++) {
        if (s->inbound[i].in_use) {
            inbound_release(&s->inbound[i]);
        }
    }
    memset(s, 0, sizeof *s);
}
