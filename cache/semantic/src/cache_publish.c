/*
 * cache_publish.c — Component #10 step 7b: DHT-routed publish.
 *
 * State machine that takes a producer-signed cache-entry and replicates
 * it to N shard-holders selected by a DHT lookup on the entry's LSH
 * shard_key.
 *
 * Phases:
 *   LOOKUP   — waiting for ants_dht_lookup completion
 *   DELIVER  — dialing each peer, opening a bidi stream, sending the
 *              CBOR-encoded entry with FIN, waiting for the peer's FIN
 *              (treated as ack: the peer's stream-side close after a
 *              successful handle_inbound_entry)
 *   DONE     — completion callback fired (exactly once)
 *
 * Per-slot status mirrors a small linear progression:
 *   EMPTY → DIALING → AWAITING_FIN → ACKED
 *                  ↘ FAILED (on dial / handshake / stream error)
 *
 * The publish does not own the conn/stream lifecycle past the publish
 * itself: per-slot conn + stream are heap-allocated by us, kept alive
 * for the duration of the publish, and freed during _destroy. The
 * caller MUST destroy the publish BEFORE destroying the underlying
 * transport (mirroring the bootstrap-conn-lifetime convention already
 * documented in dht.c). Otherwise the transport's CONN_CLOSED callback
 * may reference the slot's conn buffer after free.
 */

#include "ants_semantic_cache.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration of the shard-key entry point exposed by cache.c.
 * Declared here (not in the public header) to avoid pulling cache.c
 * internals into the publish module. */
ants_error_t ants_semantic_cache_shard_key(const float embedding[ANTS_EMBED_DIM],
                                           ants_semantic_cache_shard_key_t *out_key);

/* Magic ("SCPB" = Semantic Cache PuBlish) lets us reject calls on a
 * zeroed or already-destroyed ctx without crashing. Same pattern as
 * ANTS_SEMANTIC_CACHE_STATE_MAGIC and the rest of the codebase. */
#define ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC 0x53435042u

typedef enum { PHASE_INVALID = 0, PHASE_LOOKUP, PHASE_DELIVER, PHASE_DONE } publish_phase_t;

typedef enum {
    SLOT_EMPTY = 0,
    SLOT_DIALING,
    SLOT_AWAITING_FIN,
    SLOT_ACKED,
    SLOT_FAILED
} publish_slot_status_t;

typedef struct {
    publish_slot_status_t status;
    ants_dht_peer_t peer;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream;
} publish_slot_t;

struct publish_state {
    uint32_t magic;
    uint32_t _pad;

    publish_phase_t phase;

    ants_dht_t *dht;
    ants_transport_t *transport;

    uint8_t *entry_cbor;
    size_t entry_cbor_len;

    ants_semantic_cache_shard_key_t shard_key;

    ants_dht_lookup_t lookup;
    bool lookup_active;

    publish_slot_t slots[ANTS_SEMANTIC_CACHE_PUBLISH_MAX_REPLICATION];
    uint32_t slot_count;
    uint32_t replication_factor;

    ants_semantic_cache_publish_complete_fn_t complete_fn;
    void *complete_ctx;
    bool completion_fired;
    uint32_t acked_count;
    uint32_t failed_count;
};

typedef char ants_semantic_cache_publish_state_size_check
    [(sizeof(struct publish_state) <= sizeof(((ants_semantic_cache_publish_t *)0)->_opaque)) ? 1
                                                                                             : -1];

static struct publish_state *state_of(ants_semantic_cache_publish_t *p)
{
    /* Double-cast via void* silences -Wcast-align: the _align field of
     * the union guarantees uint64_t alignment for the opaque buffer. */
    return (struct publish_state *)(void *)p->_opaque;
}

/* Free per-slot heap resources. After this returns the slot's conn /
 * stream pointers are NULL; status is left untouched (caller may have
 * already marked SLOT_ACKED / SLOT_FAILED). Disconnects the conn
 * server-side first if the transport is still alive. */
static void slot_release(publish_slot_t *s, ants_transport_t *transport)
{
    if (s->stream) {
        (void)ants_transport_stream_close(s->stream);
        free(s->stream);
        s->stream = NULL;
    }
    if (s->conn) {
        if (transport) {
            (void)ants_transport_peer_disconnect(s->conn, 0);
        }
        free(s->conn);
        s->conn = NULL;
    }
}

/* Fire the completion callback if every slot has terminated. Idempotent. */
static void maybe_complete(struct publish_state *st)
{
    if (st->completion_fired) {
        return;
    }
    if (st->phase != PHASE_DELIVER) {
        return;
    }
    if (st->acked_count + st->failed_count < st->slot_count) {
        return;
    }

    st->completion_fired = true;
    st->phase = PHASE_DONE;
    ants_error_t status = (st->acked_count > 0) ? ANTS_OK : ANTS_ERROR_PEER_UNREACHABLE;
    if (st->complete_fn) {
        st->complete_fn(status, st->acked_count, st->complete_ctx);
    }
}

ants_error_t ants_semantic_cache_publish_init(ants_semantic_cache_publish_t *publish,
                                              ants_dht_t *dht,
                                              ants_transport_t *transport,
                                              const ants_semantic_cache_entry_t *entry,
                                              uint32_t replication_factor,
                                              ants_semantic_cache_publish_complete_fn_t complete_fn,
                                              void *complete_ctx)
{
    if (!publish || !dht || !transport || !entry || !complete_fn) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (replication_factor == 0) {
        replication_factor = ANTS_SEMANTIC_CACHE_DEFAULT_REPLICATION;
    }
    if (replication_factor > ANTS_SEMANTIC_CACHE_PUBLISH_MAX_REPLICATION) {
        return ANTS_ERROR_INVALID_ARG;
    }

    memset(publish, 0, sizeof *publish);
    struct publish_state *st = state_of(publish);

    /* Pre-encode the entry once; reused verbatim per slot. The encoder
     * does NOT support probe-mode (buf=NULL, cap=0 → INVALID_ARG —
     * see ants_semantic_cache.h doc-comment; that note is stale and is
     * tracked for fix in a follow-up). Allocate a generous starting
     * buffer; on BUFFER_TOO_SMALL, *out_len carries the required size
     * so we realloc and retry. Initial 8 KiB covers the typical
     * realistic ceiling (embedding 4 KiB + small response/model + fixed
     * fields); larger responses fall through to the realloc path. */
    size_t cap = 8192;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        return ANTS_ERROR_MALFORMED;
    }
    size_t written = 0;
    ants_error_t err = ants_semantic_cache_entry_encode(entry, buf, cap, &written);
    if (err == ANTS_ERROR_BUFFER_TOO_SMALL) {
        uint8_t *bigger = realloc(buf, written);
        if (!bigger) {
            free(buf);
            return ANTS_ERROR_MALFORMED;
        }
        buf = bigger;
        cap = written;
        err = ants_semantic_cache_entry_encode(entry, buf, cap, &written);
    }
    if (err != ANTS_OK) {
        free(buf);
        return err;
    }

    /* Compute the shard_key from the entry's embedding. */
    ants_semantic_cache_shard_key_t shard_key = 0;
    err = ants_semantic_cache_shard_key(entry->embedding, &shard_key);
    if (err != ANTS_OK) {
        free(buf);
        return err;
    }

    st->magic = ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC;
    st->phase = PHASE_LOOKUP;
    st->dht = dht;
    st->transport = transport;
    st->entry_cbor = buf;
    st->entry_cbor_len = written;
    st->shard_key = shard_key;
    st->replication_factor = replication_factor;
    st->complete_fn = complete_fn;
    st->complete_ctx = complete_ctx;

    /* Issue the lookup. Failure cleans up the heap entry buffer. */
    err = ants_dht_lookup(dht, shard_key, &st->lookup);
    if (err != ANTS_OK) {
        free(buf);
        memset(publish, 0, sizeof *publish);
        return err;
    }
    st->lookup_active = true;
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_publish_tick(ants_semantic_cache_publish_t *publish)
{
    if (!publish) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct publish_state *st = state_of(publish);
    if (st->magic != ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC) {
        /* Zeroed / never-initialised ctx: silent no-op so callers can
         * safely tick over an unused publish slot. */
        return ANTS_OK;
    }
    if (st->phase != PHASE_DELIVER) {
        return ANTS_OK;
    }

    for (uint32_t i = 0; i < st->slot_count; i++) {
        publish_slot_t *s = &st->slots[i];
        if (s->status != SLOT_EMPTY) {
            continue;
        }

        ants_transport_conn_t *conn = malloc(sizeof *conn);
        if (!conn) {
            s->status = SLOT_FAILED;
            st->failed_count++;
            continue;
        }
        memset(conn, 0, sizeof *conn);

        ants_error_t err =
            ants_transport_dial(st->transport, s->peer.multiaddr, &s->peer.peer_id, conn);
        if (err != ANTS_OK) {
            free(conn);
            s->status = SLOT_FAILED;
            st->failed_count++;
            continue;
        }
        s->conn = conn;
        s->status = SLOT_DIALING;
    }

    maybe_complete(st);
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_publish_handle_dht_event(ants_semantic_cache_publish_t *publish,
                                                          const ants_dht_event_t *event)
{
    if (!publish || !event) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct publish_state *st = state_of(publish);
    if (st->magic != ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC) {
        return ANTS_OK;
    }
    if (event->kind != ANTS_DHT_EV_LOOKUP_COMPLETE && event->kind != ANTS_DHT_EV_LOOKUP_TIMEOUT) {
        return ANTS_OK;
    }
    if (event->lookup != &st->lookup) {
        return ANTS_OK;
    }
    if (!st->lookup_active) {
        return ANTS_OK;
    }
    st->lookup_active = false;

    if (st->phase != PHASE_LOOKUP) {
        return ANTS_OK;
    }

    /* Populate slots from the DHT result. Cap at replication_factor; the
     * tail of the lookup result (if any) is discarded. */
    uint32_t n_avail = (uint32_t)event->peer_count;
    if (n_avail > st->replication_factor) {
        n_avail = st->replication_factor;
    }
    for (uint32_t i = 0; i < n_avail; i++) {
        st->slots[i].status = SLOT_EMPTY;
        st->slots[i].peer = event->peers[i];
    }
    st->slot_count = n_avail;
    st->phase = PHASE_DELIVER;

    /* If the lookup returned zero peers we are done (failure). The
     * caller's next _tick or _handle_transport_event would also notice;
     * fire immediately so the caller doesn't need an extra tick. */
    maybe_complete(st);
    return ANTS_OK;
}

/* Locate the slot whose conn or stream pointer matches the event. The
 * pointers were heap-allocated by us so identity is a reliable handle.
 * Returns -1 if no slot matches. */
static int find_slot_by_conn(struct publish_state *st, const ants_transport_conn_t *conn)
{
    if (!conn) {
        return -1;
    }
    for (uint32_t i = 0; i < st->slot_count; i++) {
        if (st->slots[i].conn == conn) {
            return (int)i;
        }
    }
    return -1;
}

static int find_slot_by_stream(struct publish_state *st, const ants_transport_stream_t *stream)
{
    if (!stream) {
        return -1;
    }
    for (uint32_t i = 0; i < st->slot_count; i++) {
        if (st->slots[i].stream == stream) {
            return (int)i;
        }
    }
    return -1;
}

ants_error_t
ants_semantic_cache_publish_handle_transport_event(ants_semantic_cache_publish_t *publish,
                                                   const ants_transport_event_t *event)
{
    if (!publish || !event) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct publish_state *st = state_of(publish);
    if (st->magic != ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC) {
        return ANTS_OK;
    }
    if (st->phase != PHASE_DELIVER) {
        return ANTS_OK;
    }

    int idx = find_slot_by_conn(st, event->conn);
    if (idx < 0) {
        idx = find_slot_by_stream(st, event->stream);
    }
    if (idx < 0) {
        return ANTS_OK;
    }
    publish_slot_t *s = &st->slots[idx];

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY: {
        if (s->status != SLOT_DIALING) {
            break;
        }
        ants_transport_stream_t *stream = malloc(sizeof *stream);
        if (!stream) {
            s->status = SLOT_FAILED;
            st->failed_count++;
            break;
        }
        memset(stream, 0, sizeof *stream);

        ants_error_t err = ants_transport_open_bidi_stream(s->conn, stream);
        if (err != ANTS_OK) {
            free(stream);
            s->status = SLOT_FAILED;
            st->failed_count++;
            break;
        }
        s->stream = stream;

        err = ants_transport_stream_send(stream, st->entry_cbor, st->entry_cbor_len, true);
        if (err != ANTS_OK) {
            (void)ants_transport_stream_close(stream);
            free(stream);
            s->stream = NULL;
            s->status = SLOT_FAILED;
            st->failed_count++;
            break;
        }
        s->status = SLOT_AWAITING_FIN;
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_FIN: {
        if (s->status == SLOT_AWAITING_FIN) {
            s->status = SLOT_ACKED;
            st->acked_count++;
        }
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_READABLE: {
        /* Server-side handle_inbound_entry does not currently emit an
         * ack payload, but if a future protocol version does we drain
         * silently so picoquic doesn't accumulate. */
        if (event->stream) {
            uint8_t scratch[64];
            size_t n = 0;
            (void)ants_transport_stream_recv(event->stream, scratch, sizeof scratch, &n);
        }
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_RESET: {
        if (s->status != SLOT_ACKED) {
            s->status = SLOT_FAILED;
            st->failed_count++;
        }
        break;
    }

    case ANTS_TRANSPORT_EV_CONN_CLOSED: {
        if (s->status != SLOT_ACKED) {
            s->status = SLOT_FAILED;
            st->failed_count++;
        }
        /* The conn is gone server-side. Free the stream first (close is
         * harmless on an already-reset stream), then free the conn — the
         * transport's CONN_CLOSED callback always fires before our buffer
         * becomes unreachable internally, so it's safe to free here. */
        if (s->stream) {
            (void)ants_transport_stream_close(s->stream);
            free(s->stream);
            s->stream = NULL;
        }
        if (s->conn) {
            free(s->conn);
            s->conn = NULL;
        }
        break;
    }

    default:
        break;
    }

    maybe_complete(st);
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_publish_destroy(ants_semantic_cache_publish_t *publish)
{
    if (!publish) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct publish_state *st = state_of(publish);
    if (st->magic != ANTS_SEMANTIC_CACHE_PUBLISH_MAGIC) {
        memset(publish, 0, sizeof *publish);
        return ANTS_OK;
    }

    if (st->lookup_active) {
        (void)ants_dht_lookup_cancel(&st->lookup);
        st->lookup_active = false;
    }

    for (uint32_t i = 0; i < st->slot_count; i++) {
        slot_release(&st->slots[i], st->transport);
    }

    if (st->entry_cbor) {
        free(st->entry_cbor);
        st->entry_cbor = NULL;
    }

    memset(publish, 0, sizeof *publish);
    return ANTS_OK;
}
