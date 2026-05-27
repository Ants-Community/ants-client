/*
 * cache_server.c — Component #10 step 7b.2: server-side dispatch.
 *
 * Sibling to network/dht/src/dht_server.c: when a publish-side state
 * machine opens a bidi stream to deliver a cache-entry write or a
 * lookup request, the receiving peer's transport event_fn fans the
 * events out to BOTH dispatchers (DHT + cache server). The DHT server
 * runs first and silently releases its slot when the inbound bytes
 * don't peek as a DHT envelope (since step 7b.2); the cache server
 * then claims the stream by top-level CBOR map size — 9 for an entry
 * write, 4 for a lookup request — and either persists the record or
 * encodes a top-K response. Either way the server signals completion
 * by FIN-closing its side of the stream, which the publish-side state
 * machine interprets as ACK.
 *
 * Slot lifecycle mirrors the DHT pattern: alloc on STREAM_OPENED,
 * lazy-malloc recv_buf on first STREAM_READABLE, process + free on
 * STREAM_FIN, force-free on STREAM_RESET and CONN_CLOSED. Each event
 * handler returns ANTS_OK for foreign streams so the server can run
 * inside a fan-out chain with the DHT + any publish state machines.
 *
 * The server holds a non-owning back-pointer to the cache. The cache
 * MUST outlive the server, and the server MUST be destroyed before the
 * underlying transport (CONN_CLOSED fan-out from the transport's
 * destroy path would otherwise reference our slot pointers after the
 * recv_buf heap is reclaimed). Same convention dht.c uses for the
 * bootstrap_entries / pending_dials lifetime.
 */

#include "ants_semantic_cache.h"

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Magic ("SCSV" = Semantic Cache SerVer) discriminates a fully-init
 * server context from a zeroed (never-init) ctx for _destroy /
 * _handle_transport_event safety. Same pattern as the rest of the
 * codebase (ANTS, ANTC, ANSE, CNCS, SCPB). */
#define ANTS_SEMANTIC_CACHE_SERVER_MAGIC 0x53435356u

/* Response-buffer cap for an inbound lookup. HANDLE_LOOKUP_SERVER_CAP
 * is 15 matches; each match worst-case is ~5 KiB (4 KiB embedding +
 * ~1 KiB CBOR fields). 96 KiB covers the upper envelope with margin;
 * handle_inbound_lookup returns BUFFER_TOO_SMALL if a future expansion
 * pushes past the cap, which the server treats as an internal error
 * and signals via stream_reset. */
#define CACHE_SERVER_RESP_BUF_SIZE (96u * 1024u)

struct cache_server_inbound_stream {
    bool in_use;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream;
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
};

struct cache_server_state {
    uint32_t magic;
    uint32_t _pad;
    ants_semantic_cache_t *cache;
    struct cache_server_inbound_stream
        inbound_streams[ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS];
};

typedef char ants_semantic_cache_server_state_size_check
    [(sizeof(struct cache_server_state) <= sizeof(((ants_semantic_cache_server_t *)0)->_opaque))
         ? 1
         : -1];

static struct cache_server_state *state_of(ants_semantic_cache_server_t *server)
{
    /* Double-cast via void* silences -Wcast-align: the _align field of
     * the union guarantees uint64_t alignment for the opaque buffer. */
    return (struct cache_server_state *)(void *)server->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Inbound stream registry                                                  */
/* ------------------------------------------------------------------------ */

static struct cache_server_inbound_stream *
inbound_find_by_stream(struct cache_server_state *state, const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS; i++) {
        if (state->inbound_streams[i].in_use && state->inbound_streams[i].stream == stream) {
            return &state->inbound_streams[i];
        }
    }
    return NULL;
}

static struct cache_server_inbound_stream *inbound_alloc(struct cache_server_state *state,
                                                         ants_transport_conn_t *conn,
                                                         ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS; i++) {
        if (!state->inbound_streams[i].in_use) {
            struct cache_server_inbound_stream *slot = &state->inbound_streams[i];
            slot->in_use = true;
            slot->conn = conn;
            slot->stream = stream;
            slot->recv_buf = NULL;
            slot->recv_len = 0;
            slot->recv_cap = 0;
            return slot;
        }
    }
    return NULL;
}

static void inbound_release(struct cache_server_inbound_stream *slot)
{
    if (slot->recv_buf != NULL) {
        free(slot->recv_buf);
    }
    memset(slot, 0, sizeof *slot);
}

/* ------------------------------------------------------------------------ */
/* Peek + dispatch                                                          */
/* ------------------------------------------------------------------------ */

/* Look at the top-level CBOR map size without consuming the inner
 * fields. Returns the decoder's error verbatim on bad CBOR. Entry
 * writes peek as map(10) (the signature field is included on the
 * wire; only the signing payload omits it as map(9)); lookup
 * requests as map(4); anything else means the stream isn't a cache
 * message and the slot is released silently so the transport can
 * clean it up at CONN_CLOSED. */
static ants_error_t peek_top_map_size(const uint8_t *buf, size_t len, size_t *out_map_n)
{
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    return ants_cbor_dec_map(&dec, out_map_n);
}

static void process_fin(struct cache_server_state *state, struct cache_server_inbound_stream *slot)
{
    if (slot->recv_buf == NULL || slot->recv_len == 0) {
        /* Empty stream — not ours. Release without reset; sibling
         * dispatchers (DHT server / future subsystems) may still want
         * the event. */
        inbound_release(slot);
        return;
    }

    size_t map_n = 0;
    ants_error_t err = peek_top_map_size(slot->recv_buf, slot->recv_len, &map_n);
    if (err != ANTS_OK) {
        /* Doesn't look like a CBOR map — release silently. The DHT
         * server's process_fin already silent-releases on a peek
         * mismatch; this matches that contract on the cache side. */
        inbound_release(slot);
        return;
    }

    if (map_n == 10) {
        /* Entry write. handle_inbound_entry decodes + Ed25519-verifies
         * + put_records. On success, send a FIN-only sentinel so the
         * publish-side state machine sees STREAM_FIN and marks the
         * slot ACKED. On any decode/verify error, reset the stream so
         * the requester counts the slot as FAILED. */
        err =
            ants_semantic_cache_handle_inbound_entry(state->cache, slot->recv_buf, slot->recv_len);
        if (err == ANTS_OK) {
            (void)ants_transport_stream_send(slot->stream, NULL, 0, true /* fin */);
        } else {
            (void)ants_transport_stream_reset(slot->stream, 1 /* malformed */);
        }
        inbound_release(slot);
        return;
    }

    if (map_n == 4) {
        /* Lookup request. The response can be up to ~75 KiB worst-
         * case (15 matches × ~5 KiB); heap-allocate so the inbound-
         * stream slot's stack-resident state stays small. */
        uint8_t *resp_buf = (uint8_t *)malloc(CACHE_SERVER_RESP_BUF_SIZE);
        if (resp_buf == NULL) {
            (void)ants_transport_stream_reset(slot->stream, 2 /* internal */);
            inbound_release(slot);
            return;
        }
        size_t resp_len = 0;
        err = ants_semantic_cache_handle_inbound_lookup(state->cache,
                                                        slot->recv_buf,
                                                        slot->recv_len,
                                                        resp_buf,
                                                        CACHE_SERVER_RESP_BUF_SIZE,
                                                        &resp_len);
        if (err == ANTS_OK) {
            (void)ants_transport_stream_send(slot->stream, resp_buf, resp_len, true /* fin */);
        } else {
            (void)ants_transport_stream_reset(slot->stream, 1 /* malformed */);
        }
        free(resp_buf);
        inbound_release(slot);
        return;
    }

    /* Map size doesn't match either of our two RPCs — could be a DHT
     * envelope (map 2 or 3) or any other protocol future revisions add.
     * Silent release. */
    inbound_release(slot);
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_server_init(ants_semantic_cache_server_t *server,
                                             ants_semantic_cache_t *cache)
{
    if (server == NULL || cache == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(server, 0, sizeof *server);
    struct cache_server_state *state = state_of(server);
    state->magic = ANTS_SEMANTIC_CACHE_SERVER_MAGIC;
    state->cache = cache;
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_server_handle_transport_event(ants_semantic_cache_server_t *server,
                                                               const ants_transport_event_t *event)
{
    if (server == NULL || event == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct cache_server_state *state = state_of(server);
    if (state->magic != ANTS_SEMANTIC_CACHE_SERVER_MAGIC) {
        /* Zeroed / never-initialised ctx: silent no-op so callers can
         * safely fan events out to an unused server slot. */
        return ANTS_OK;
    }

    /* CONN_CLOSED: sweep any inbound streams that belonged to this conn. */
    if (event->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        for (size_t i = 0; i < ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS; i++) {
            if (state->inbound_streams[i].in_use && state->inbound_streams[i].conn == event->conn) {
                inbound_release(&state->inbound_streams[i]);
            }
        }
        return ANTS_OK;
    }

    if (event->stream == NULL) {
        return ANTS_OK;
    }

    /* STREAM_OPENED on a peer-initiated stream → allocate a slot. We
     * don't know yet whether it's a DHT or cache stream; the DHT
     * server makes the same eager grab. process_fin's peek step
     * adjudicates later. */
    if (event->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        if (inbound_find_by_stream(state, event->stream) == NULL) {
            (void)inbound_alloc(state, event->conn, event->stream);
            /* Registry full: silent no-op. The sender will see the
             * stream close without ACK and count the slot as FAILED;
             * a future capacity-bump constant addresses real flooding. */
        }
        return ANTS_OK;
    }

    struct cache_server_inbound_stream *slot = inbound_find_by_stream(state, event->stream);
    if (slot == NULL) {
        return ANTS_OK;
    }

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE: {
        if (event->payload == NULL || event->payload_len == 0) {
            break;
        }
        if (slot->recv_buf == NULL) {
            slot->recv_buf = (uint8_t *)malloc(ANTS_SEMANTIC_CACHE_SERVER_INBOUND_RECV_CAP);
            if (slot->recv_buf == NULL) {
                inbound_release(slot);
                break;
            }
            slot->recv_cap = ANTS_SEMANTIC_CACHE_SERVER_INBOUND_RECV_CAP;
            slot->recv_len = 0;
        }
        if (event->payload_len > slot->recv_cap - slot->recv_len) {
            /* Oversized request — release silently. The sender will
             * see the stream close without ack and treat the slot as
             * FAILED; reset would propagate noise to a sender whose
             * intent we can't infer past the recv cap. */
            inbound_release(slot);
            break;
        }
        memcpy(slot->recv_buf + slot->recv_len, event->payload, event->payload_len);
        slot->recv_len += event->payload_len;
        break;
    }
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        process_fin(state, slot);
        break;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        inbound_release(slot);
        break;
    default:
        break;
    }
    return ANTS_OK;
}

ants_error_t ants_semantic_cache_server_destroy(ants_semantic_cache_server_t *server)
{
    if (server == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct cache_server_state *state = state_of(server);
    if (state->magic == ANTS_SEMANTIC_CACHE_SERVER_MAGIC) {
        for (size_t i = 0; i < ANTS_SEMANTIC_CACHE_SERVER_MAX_INBOUND_STREAMS; i++) {
            if (state->inbound_streams[i].in_use) {
                inbound_release(&state->inbound_streams[i]);
            }
        }
    }
    memset(server, 0, sizeof *server);
    return ANTS_OK;
}
