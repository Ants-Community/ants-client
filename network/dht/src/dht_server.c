/*
 * dht_server.c — Server-side dispatch for inbound DHT requests.
 *
 * Hooks into the transport-event delegation path after the outbound
 * dht_rpc handler. On STREAM_OPENED we bind a slot in the inbound
 * stream registry; on STREAM_READABLE we accumulate request bytes
 * (lazy-alloc recv_buf); on STREAM_FIN we peek + decode + dispatch
 * to one of four request handlers + send the response with FIN +
 * release the slot.
 *
 * Token discipline: GET_PEERS_RESP carries a 16-byte token derived
 * from BLAKE3(server_secret || peer_id). ANNOUNCE_PEER_REQ must echo
 * a valid token (one we'd have issued to the same peer) or the
 * announce is rejected with no state change.
 *
 * K-closest selection: FIND_NODE_RESP and GET_PEERS_RESP fallback
 * walk every routing-table bucket, compute XOR distance to the
 * target, and keep the K=20 closest in an insertion-sorted result
 * array. Walk is O(N_peers); N is bounded by 256·K = 5120 entries
 * which is small enough that a full scan beats maintaining a
 * separate sorted index.
 */

#include "dht_server.h"

#include "ants_cbor.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_transport.h"
#include "dht_internal.h"
#include "dht_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Maximum encoded response size — sized for the worst-case
 * GET_PEERS_RESP with K=20 peers (~1.9 KB) plus headroom. */
#define DHT_SERVER_RESP_BUF_SIZE 4096

/* ------------------------------------------------------------------------ */
/* Cast helpers                                                             */
/* ------------------------------------------------------------------------ */

static struct ants_dht_state *dht_get_state(ants_dht_t *dht)
{
    return (struct ants_dht_state *)(void *)dht->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Inbound stream registry                                                  */
/* ------------------------------------------------------------------------ */

static struct ants_dht_inbound_stream *inbound_find_by_stream(struct ants_dht_state *state,
                                                              const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_INBOUND_STREAMS; i++) {
        if (state->inbound_streams[i].in_use && state->inbound_streams[i].stream == stream) {
            return &state->inbound_streams[i];
        }
    }
    return NULL;
}

static struct ants_dht_inbound_stream *inbound_alloc(struct ants_dht_state *state,
                                                     ants_transport_conn_t *conn,
                                                     ants_transport_stream_t *stream,
                                                     const ants_peer_id_t *peer_id)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_INBOUND_STREAMS; i++) {
        if (!state->inbound_streams[i].in_use) {
            struct ants_dht_inbound_stream *slot = &state->inbound_streams[i];
            slot->in_use = true;
            slot->conn = conn;
            slot->stream = stream;
            slot->peer_id = *peer_id;
            slot->recv_buf = NULL;
            slot->recv_len = 0;
            slot->recv_cap = 0;
            return slot;
        }
    }
    return NULL;
}

static void inbound_release(struct ants_dht_inbound_stream *slot)
{
    if (slot->recv_buf != NULL) {
        free(slot->recv_buf);
    }
    memset(slot, 0, sizeof *slot);
}

/* ------------------------------------------------------------------------ */
/* Token derivation                                                         */
/* ------------------------------------------------------------------------ */

void ants_dht_server_compute_token(const struct ants_dht_state *state,
                                   const ants_peer_id_t *peer,
                                   uint8_t out_token[16])
{
    uint8_t buf[32 + ANTS_PEER_ID_SIZE];
    memcpy(buf, state->server_secret, 32);
    memcpy(buf + 32, peer->bytes, ANTS_PEER_ID_SIZE);
    uint8_t hash[ANTS_BLAKE3_HASH_SIZE];
    (void)ants_blake3_hash(buf, sizeof buf, hash);
    memcpy(out_token, hash, 16);
}

static bool token_is_valid(const struct ants_dht_state *state,
                           const ants_peer_id_t *peer,
                           const uint8_t token[16])
{
    uint8_t expected[16];
    ants_dht_server_compute_token(state, peer, expected);
    /* Constant-time compare to avoid timing side-channel — phase 6+ may
     * roll a wrapper, for now bounded 16-byte compare via XOR-accumulate. */
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++) {
        diff |= (uint8_t)(expected[i] ^ token[i]);
    }
    return diff == 0;
}

/* ------------------------------------------------------------------------ */
/* K-closest peers from the routing table                                   */
/*                                                                          */
/* Walks every bucket once, computes XOR distance to `target`, and keeps   */
/* the K closest in `out_peers`, sorted ascending by distance. Returns the */
/* count written.                                                           */
/* ------------------------------------------------------------------------ */

struct kclosest_entry {
    ants_dht_peer_t peer;
    uint8_t distance[ANTS_PEER_ID_SIZE];
};

static int dist_cmp(const uint8_t a[ANTS_PEER_ID_SIZE], const uint8_t b[ANTS_PEER_ID_SIZE])
{
    return memcmp(a, b, ANTS_PEER_ID_SIZE);
}

static void xor_distance(const uint8_t a[ANTS_PEER_ID_SIZE],
                         const uint8_t b[ANTS_PEER_ID_SIZE],
                         uint8_t out[ANTS_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_PEER_ID_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static size_t find_kclosest_peers(const struct ants_dht_state *state,
                                  const uint8_t target[ANTS_PEER_ID_SIZE],
                                  ants_dht_peer_t out_peers[ANTS_DHT_K])
{
    struct kclosest_entry top[ANTS_DHT_K];
    size_t top_count = 0;

    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (const struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL;
             e = e->next) {
            uint8_t dist[ANTS_PEER_ID_SIZE];
            xor_distance(target, e->peer.peer_id.bytes, dist);

            /* Insertion sort into `top`, capped at K. */
            size_t pos = top_count;
            for (size_t j = 0; j < top_count; j++) {
                if (dist_cmp(dist, top[j].distance) < 0) {
                    pos = j;
                    break;
                }
            }
            if (pos == ANTS_DHT_K) {
                continue; /* worse than current worst */
            }
            size_t end = top_count < ANTS_DHT_K ? top_count : ANTS_DHT_K - 1;
            for (size_t j = end; j > pos; j--) {
                top[j] = top[j - 1];
            }
            top[pos].peer = e->peer;
            memcpy(top[pos].distance, dist, ANTS_PEER_ID_SIZE);
            if (top_count < ANTS_DHT_K) {
                top_count++;
            }
        }
    }

    for (size_t i = 0; i < top_count; i++) {
        out_peers[i] = top[i].peer;
    }
    return top_count;
}

/* ------------------------------------------------------------------------ */
/* Announce set                                                             */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_server_upsert_announce(struct ants_dht_state *state,
                                             ants_dht_shard_key_t shard_key,
                                             const ants_dht_peer_t *announcer,
                                             uint64_t now_us)
{
    /* Refresh if the (shard_key, peer_id) pair already exists. */
    for (size_t i = 0; i < ANTS_DHT_MAX_ANNOUNCES; i++) {
        if (state->announces[i].in_use && state->announces[i].shard_key == shard_key &&
            memcmp(state->announces[i].announcer.peer_id.bytes,
                   announcer->peer_id.bytes,
                   ANTS_PEER_ID_SIZE) == 0) {
            state->announces[i].announcer = *announcer;
            state->announces[i].last_seen_us = now_us;
            return ANTS_OK;
        }
    }
    /* Insert into a free slot. */
    for (size_t i = 0; i < ANTS_DHT_MAX_ANNOUNCES; i++) {
        if (!state->announces[i].in_use) {
            state->announces[i].in_use = true;
            state->announces[i].shard_key = shard_key;
            state->announces[i].announcer = *announcer;
            state->announces[i].last_seen_us = now_us;
            return ANTS_OK;
        }
    }
    /* Full — evict the oldest entry (smallest last_seen_us). Phase 6.1+
     * will add proper TTL-based expiry. */
    size_t oldest = 0;
    for (size_t i = 1; i < ANTS_DHT_MAX_ANNOUNCES; i++) {
        if (state->announces[i].last_seen_us < state->announces[oldest].last_seen_us) {
            oldest = i;
        }
    }
    state->announces[oldest].in_use = true;
    state->announces[oldest].shard_key = shard_key;
    state->announces[oldest].announcer = *announcer;
    state->announces[oldest].last_seen_us = now_us;
    return ANTS_OK;
}

/* Collect every announcer for `shard_key`, up to K entries. */
static size_t announce_lookup(const struct ants_dht_state *state,
                              ants_dht_shard_key_t shard_key,
                              ants_dht_peer_t out_peers[ANTS_DHT_K])
{
    size_t count = 0;
    for (size_t i = 0; i < ANTS_DHT_MAX_ANNOUNCES && count < ANTS_DHT_K; i++) {
        if (state->announces[i].in_use && state->announces[i].shard_key == shard_key) {
            out_peers[count++] = state->announces[i].announcer;
        }
    }
    return count;
}

/* ------------------------------------------------------------------------ */
/* Per-RPC handlers                                                         */
/* ------------------------------------------------------------------------ */

static ants_error_t handle_ping(struct ants_dht_state *state,
                                struct ants_dht_inbound_stream *slot,
                                uint8_t *resp_buf,
                                size_t resp_cap,
                                size_t *out_resp_len)
{
    (void)state;
    ants_dht_ping_req_t req;
    memset(&req, 0, sizeof req);
    ants_error_t err = ants_dht_wire_decode_ping_req(slot->recv_buf, slot->recv_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    ants_dht_ping_resp_t resp;
    resp.txid = req.txid;
    return ants_dht_wire_encode_ping_resp(resp_buf, resp_cap, out_resp_len, &resp);
}

static ants_error_t handle_find_node(struct ants_dht_state *state,
                                     struct ants_dht_inbound_stream *slot,
                                     uint8_t *resp_buf,
                                     size_t resp_cap,
                                     size_t *out_resp_len)
{
    ants_dht_find_node_req_t req;
    memset(&req, 0, sizeof req);
    ants_error_t err = ants_dht_wire_decode_find_node_req(slot->recv_buf, slot->recv_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    ants_dht_find_node_resp_t resp;
    memset(&resp, 0, sizeof resp);
    resp.txid = req.txid;
    resp.peer_count = find_kclosest_peers(state, req.target.bytes, resp.peers);
    return ants_dht_wire_encode_find_node_resp(resp_buf, resp_cap, out_resp_len, &resp);
}

static ants_error_t handle_get_peers(struct ants_dht_state *state,
                                     struct ants_dht_inbound_stream *slot,
                                     uint8_t *resp_buf,
                                     size_t resp_cap,
                                     size_t *out_resp_len)
{
    ants_dht_get_peers_req_t req;
    memset(&req, 0, sizeof req);
    ants_error_t err = ants_dht_wire_decode_get_peers_req(slot->recv_buf, slot->recv_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    ants_dht_get_peers_resp_t resp;
    memset(&resp, 0, sizeof resp);
    resp.txid = req.txid;
    /* Try announces first; fall back to K-closest from routing table. */
    resp.peer_count = announce_lookup(state, req.key, resp.peers);
    if (resp.peer_count == 0) {
        /* Fallback: shard-key expansion target = BLAKE3(key_le). */
        uint8_t key_le[8];
        for (int i = 0; i < 8; i++) {
            key_le[i] = (uint8_t)((req.key >> (i * 8)) & 0xFFu);
        }
        uint8_t target[ANTS_BLAKE3_HASH_SIZE];
        (void)ants_blake3_hash(key_le, sizeof key_le, target);
        resp.peer_count = find_kclosest_peers(state, target, resp.peers);
    }
    /* Token for any subsequent ANNOUNCE_PEER from this peer. */
    ants_dht_server_compute_token(state, &slot->peer_id, resp.token);
    return ants_dht_wire_encode_get_peers_resp(resp_buf, resp_cap, out_resp_len, &resp);
}

static ants_error_t handle_announce_peer(struct ants_dht_state *state,
                                         struct ants_dht_inbound_stream *slot,
                                         uint8_t *resp_buf,
                                         size_t resp_cap,
                                         size_t *out_resp_len)
{
    ants_dht_announce_peer_req_t req;
    memset(&req, 0, sizeof req);
    ants_error_t err = ants_dht_wire_decode_announce_peer_req(slot->recv_buf, slot->recv_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    if (!token_is_valid(state, &slot->peer_id, req.token)) {
        /* Reject — no announce state change. The RESP still carries
         * the same txid so the requester gets a clean RPC completion;
         * future protocol revisions may add an error code field, but
         * the current wire format only has the txid here. */
        ants_dht_announce_peer_resp_t resp;
        resp.txid = req.txid;
        return ants_dht_wire_encode_announce_peer_resp(resp_buf, resp_cap, out_resp_len, &resp);
    }

    /* The announcer is the inbound peer. We don't yet have its
     * multiaddr (the transport's conn_peer_addr is not implemented in
     * phase 3); use the empty string for now. */
    ants_dht_peer_t announcer;
    memset(&announcer, 0, sizeof announcer);
    announcer.peer_id = slot->peer_id;
    (void)ants_dht_server_upsert_announce(state, req.key, &announcer, dht_now_us());

    ants_dht_announce_peer_resp_t resp;
    resp.txid = req.txid;
    return ants_dht_wire_encode_announce_peer_resp(resp_buf, resp_cap, out_resp_len, &resp);
}

/* ------------------------------------------------------------------------ */
/* Decode + dispatch                                                        */
/* ------------------------------------------------------------------------ */

static void process_fin(ants_dht_t *dht, struct ants_dht_inbound_stream *slot)
{
    struct ants_dht_state *state = dht_get_state(dht);
    if (slot->recv_buf == NULL || slot->recv_len == 0) {
        /* Empty request — could be a peer-initiated stream that another
         * subsystem (e.g. cache_server) is meant to handle. Release the
         * slot silently rather than reset; sibling dispatchers running
         * after us on the same event chain still get their chance. */
        inbound_release(slot);
        return;
    }
    ants_dht_msg_type_t type;
    ants_error_t err = ants_dht_wire_peek_type(slot->recv_buf, slot->recv_len, &type);
    if (err != ANTS_OK) {
        /* Doesn't look like a DHT envelope — silent release so a sibling
         * dispatcher (cache_server, future subsystems) can claim the
         * stream. Reset would propagate to the requester as STREAM_RESET
         * and abort a perfectly valid non-DHT stream. */
        inbound_release(slot);
        return;
    }

    uint8_t resp_buf[DHT_SERVER_RESP_BUF_SIZE];
    size_t resp_len = 0;
    switch (type) {
    case ANTS_DHT_MSG_PING:
        err = handle_ping(state, slot, resp_buf, sizeof resp_buf, &resp_len);
        break;
    case ANTS_DHT_MSG_FIND_NODE:
        err = handle_find_node(state, slot, resp_buf, sizeof resp_buf, &resp_len);
        break;
    case ANTS_DHT_MSG_GET_PEERS:
        err = handle_get_peers(state, slot, resp_buf, sizeof resp_buf, &resp_len);
        break;
    case ANTS_DHT_MSG_ANNOUNCE_PEER:
        err = handle_announce_peer(state, slot, resp_buf, sizeof resp_buf, &resp_len);
        break;
    default:
        /* peek_type confirmed it's a DHT envelope but the type is a
         * response — clients shouldn't open a server stream with that.
         * It IS our protocol but malformed, so reset is correct here. */
        (void)ants_transport_stream_reset(slot->stream, 1);
        inbound_release(slot);
        return;
    }

    if (err == ANTS_OK) {
        (void)ants_transport_stream_send(slot->stream, resp_buf, resp_len, true /* fin */);
    } else {
        (void)ants_transport_stream_reset(slot->stream, 2 /* internal */);
    }
    inbound_release(slot);
}

/* ------------------------------------------------------------------------ */
/* Event dispatcher                                                         */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_server_handle_event(ants_dht_t *dht, const ants_transport_event_t *event)
{
    if (dht == NULL || event == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = dht_get_state(dht);

    /* CONN_CLOSED: sweep any inbound streams that belonged to this conn. */
    if (event->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        for (size_t i = 0; i < ANTS_DHT_MAX_INBOUND_STREAMS; i++) {
            if (state->inbound_streams[i].in_use && state->inbound_streams[i].conn == event->conn) {
                inbound_release(&state->inbound_streams[i]);
            }
        }
        return ANTS_OK;
    }

    if (event->stream == NULL) {
        return ANTS_OK;
    }

    /* STREAM_OPENED on a peer-initiated stream → bind a slot. (The
     * outbound dht_rpc dispatcher runs FIRST and would have claimed
     * the event if this were one of its own; if we got here it's
     * unequivocally an inbound stream.) */
    if (event->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        struct ants_dht_inbound_stream *slot = inbound_find_by_stream(state, event->stream);
        if (slot == NULL) {
            slot = inbound_alloc(state, event->conn, event->stream, &event->peer_id);
            /* Registry full → no-op; a sibling dispatcher (cache_server,
             * etc.) may still take the stream. Reset would close a
             * stream we can't prove is ours. */
        }
        return ANTS_OK;
    }

    struct ants_dht_inbound_stream *slot = inbound_find_by_stream(state, event->stream);
    if (slot == NULL) {
        /* Not one of ours. Could be a stream the application owns,
         * or one that overran the registry — either way, no-op. */
        return ANTS_OK;
    }

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE: {
        if (event->payload == NULL || event->payload_len == 0) {
            break;
        }
        if (slot->recv_buf == NULL) {
            slot->recv_buf = (uint8_t *)malloc(ANTS_DHT_INBOUND_RECV_CAP);
            if (slot->recv_buf == NULL) {
                inbound_release(slot);
                break;
            }
            slot->recv_cap = ANTS_DHT_INBOUND_RECV_CAP;
            slot->recv_len = 0;
        }
        if (event->payload_len > slot->recv_cap - slot->recv_len) {
            /* Overflows the DHT-side recv cap — but a sibling dispatcher
             * (cache_server etc.) may still want the stream, and big
             * payloads are the cache's normal case (4 KiB embeddings).
             * Silent release so we stop accumulating; no reset. */
            inbound_release(slot);
            break;
        }
        memcpy(slot->recv_buf + slot->recv_len, event->payload, event->payload_len);
        slot->recv_len += event->payload_len;
        break;
    }
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        process_fin(dht, slot);
        break;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        inbound_release(slot);
        break;
    default:
        break;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Bulk cleanup                                                             */
/* ------------------------------------------------------------------------ */

void ants_dht_server_drop_all(ants_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }
    struct ants_dht_state *state = dht_get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_INBOUND_STREAMS; i++) {
        if (state->inbound_streams[i].in_use) {
            inbound_release(&state->inbound_streams[i]);
        }
    }
}
