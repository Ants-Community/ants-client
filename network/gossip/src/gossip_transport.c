/*
 * gossip_transport.c — Gossip overlay transport binding (Component #6 PR2,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * Wires the transport-agnostic dissemination engine (gossip.c) to a real
 * ants_transport: the engine's send_fn writes each forwarded proof, length-
 * prefixed, on a persistent per-connection unidirectional QUIC stream, and
 * the inbound demux deframes a peer's pushed byte stream and feeds each frame
 * to ants_gossip_on_message. See the "Transport binding" section of
 * ants_gossip.h for the full design.
 *
 * Three registries live in the caller's opaque ctx:
 *   - conns[]    : (peer_id → conn), learned from CONN_READY, used by send
 *                  to map a fanout peer to a live connection;
 *   - inbound[]  : per inbound stream, a lazily-allocated accumulation buffer
 *                  (heap), released on FIN/RESET or the conn's CONN_CLOSED;
 *   - outbound[] : one PERSISTENT unidirectional stream per connection, reused
 *                  for every proof forwarded to that peer. Frames are length-
 *                  prefixed (2-byte big-endian) since the stream is never FIN'd
 *                  per message. The transport fires no completion event for a
 *                  one-way stream, so the handle is freed on the connection's
 *                  CONN_CLOSED; the channel count is bounded by the connection
 *                  count, not the proof volume.
 *
 * Per-channel handles and inbound accumulation buffers are heap-allocated (so
 * the registries hold pointers, not 1 KB inline structs) — the same ownership
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

/* Length prefix (bytes) framing each frame on the persistent per-connection
 * outbound stream: 2-byte big-endian, since the stream is never FIN'd per
 * message and the receiver must re-delimit the continuous byte stream. A
 * gossip frame is <= ANTS_GOSSIP_DEFAULT_MAX_FRAME, which fits a u16. */
#define GT_LEN_PREFIX 2u

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

/* Deframe complete [u16 BE len][frame] units from the head of the accumulation
 * buffer, handing each frame to the engine and shifting the buffer down. The
 * forward an inserted proof triggers goes back through this binding's send on
 * OTHER connections. Returns true if the slot is still alive (a partial tail
 * may remain, awaiting more bytes); false if a malformed length (zero, or over
 * the engine's frame cap) released the slot — we release rather than reset, so
 * a stream that belongs to another subsystem is left for it to claim (same
 * politeness as dht_server's process_fin). */
static bool inbound_drain(struct gossip_transport_state *s, struct gt_inbound *slot)
{
    while (slot->recv_len >= GT_LEN_PREFIX) {
        size_t flen = ((size_t)slot->recv_buf[0] << 8) | (size_t)slot->recv_buf[1];
        if (flen == 0 || flen > ANTS_GOSSIP_DEFAULT_MAX_FRAME) {
            inbound_release(slot);
            return false;
        }
        if (slot->recv_len < GT_LEN_PREFIX + flen) {
            break; /* need more bytes for this frame */
        }
        (void)ants_gossip_on_message(
            s->engine, slot->peer_id, slot->recv_buf + GT_LEN_PREFIX, flen, NULL, NULL);
        {
            size_t consumed = GT_LEN_PREFIX + flen;
            size_t rest = slot->recv_len - consumed;
            if (rest > 0) {
                memmove(slot->recv_buf, slot->recv_buf + consumed, rest);
            }
            slot->recv_len = rest;
        }
    }
    return true;
}

/* Append a READABLE payload, draining complete frames as the buffer fills so
 * it never holds more than one in-progress prefixed frame. recv_buf is lazily
 * allocated; an allocation failure or a malformed frame releases the slot. */
static void
inbound_feed(struct gossip_transport_state *s, struct gt_inbound *slot, const uint8_t *p, size_t n)
{
    if (slot->recv_buf == NULL) {
        slot->recv_buf = (uint8_t *)malloc(ANTS_GOSSIP_TRANSPORT_INBOUND_RECV_CAP);
        if (slot->recv_buf == NULL) {
            inbound_release(slot);
            return;
        }
        slot->recv_cap = ANTS_GOSSIP_TRANSPORT_INBOUND_RECV_CAP;
        slot->recv_len = 0;
    }
    while (n > 0) {
        size_t space = slot->recv_cap - slot->recv_len;
        size_t take = (n < space) ? n : space;
        if (take == 0) {
            /* Buffer full yet no complete frame could be drained → not
             * well-formed gossip framing. */
            inbound_release(slot);
            return;
        }
        memcpy(slot->recv_buf + slot->recv_len, p, take);
        slot->recv_len += take;
        p += take;
        n -= take;
        if (!inbound_drain(s, slot)) {
            return; /* slot released (malformed) */
        }
    }
}

/* FIN (or conn half-close): drain any remaining complete frames, then release.
 * A trailing partial frame is discarded — a well-behaved sender frames whole
 * proofs. */
static void process_inbound_fin(struct gossip_transport_state *s, struct gt_inbound *slot)
{
    if (inbound_drain(s, slot)) {
        inbound_release(slot);
    }
}

/* ------------------------------------------------------------------------ */
/* Outbound stream registry (one persistent channel per connection)          */
/* ------------------------------------------------------------------------ */

/* The live channel for `conn`, or NULL if none is open yet. Keyed by conn (not
 * peer_id) so a peer that reconnects on a fresh conn opens a fresh channel and
 * the stale one is swept by the old conn's CONN_CLOSED. */
static struct gt_outbound *outbound_find_by_conn(struct gossip_transport_state *s,
                                                 const ants_transport_conn_t *conn)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS; i++) {
        if (s->outbound[i].in_use && s->outbound[i].conn == conn) {
            return &s->outbound[i];
        }
    }
    return NULL;
}

static struct gt_outbound *outbound_alloc(struct gossip_transport_state *s)
{
    for (size_t i = 0; i < ANTS_GOSSIP_TRANSPORT_MAX_OUTBOUND_STREAMS; i++) {
        if (!s->outbound[i].in_use) {
            return &s->outbound[i];
        }
    }
    return NULL; /* pool exhausted (one channel per conn) — drop (best-effort) */
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

    /* Find (or lazily open) the persistent channel for this connection. */
    struct gt_outbound *slot = outbound_find_by_conn(s, conn);
    if (slot == NULL) {
        slot = outbound_alloc(s);
        if (slot == NULL) {
            return; /* channel pool exhausted (one per conn) — drop */
        }
        ants_transport_stream_t *stream =
            (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
        if (stream == NULL) {
            return; /* slot left free (not marked in_use) */
        }
        if (ants_transport_open_uni_stream(conn, stream) != ANTS_OK) {
            /* open failed → picoquic holds no reference → safe to free now. */
            free(stream);
            return;
        }
        /* picoquic now references the handle as the stream's app ctx — retain
         * it until this connection's CONN_CLOSED. */
        slot->in_use = true;
        slot->conn = conn;
        slot->stream = stream;
    }

    /* Frame the proof as [u16 BE len][frame] and queue it on the persistent
     * stream WITHOUT FIN. picoquic copies the whole buffer into its ordered
     * send queue (all-or-nothing), so no partial frame can corrupt the
     * receiver's deframing; a rare queue-full drops this whole frame. */
    {
        uint8_t out[GT_LEN_PREFIX + ANTS_GOSSIP_DEFAULT_MAX_FRAME];
        out[0] = (uint8_t)((len >> 8) & 0xFFu);
        out[1] = (uint8_t)(len & 0xFFu);
        memcpy(out + GT_LEN_PREFIX, frame, len);
        (void)ants_transport_stream_send(slot->stream, out, GT_LEN_PREFIX + len, false);
    }
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
        /* Gossip push channels are uni-only (see the binding contract
         * above); a peer-initiated BIDI stream is another subsystem's
         * (a DHT RPC request). Leave it to that dispatcher. */
        if (ants_transport_stream_is_bidi(event->stream)) {
            return ANTS_OK;
        }
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
        inbound_feed(s, slot, event->payload, event->payload_len);
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
