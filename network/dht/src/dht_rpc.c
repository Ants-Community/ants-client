/*
 * dht_rpc.c — Outbound RPC dispatch over transport bidi streams.
 *
 * Implementation of dht_rpc.h. Owns the pending-RPC registry that
 * lives inside struct ants_dht_state. Each slot tracks one in-flight
 * RPC: its heap-allocated stream, lazy-allocated response accumulator,
 * the expected response type, and the caller's completion handler.
 *
 * Stream ownership: send_* allocates the ants_transport_stream_t on
 * the heap (so the slot can hold a pointer rather than a 1 KB inline
 * struct). The transport treats the pointer as caller-owned (it never
 * calls free() on it); we reclaim it on STREAM_FIN / STREAM_RESET /
 * CONN_CLOSED, by which point picoquic is guaranteed to have no more
 * scheduled callbacks targeting that stream_ctx.
 *
 * Response accumulator: recv_buf is allocated lazily on the first
 * STREAM_READABLE for the slot (most responses fit in a single
 * fragment, but the contract has to handle multiples). recv_cap is
 * ANTS_DHT_RPC_RECV_CAP; overflow fails the RPC with BUFFER_TOO_SMALL.
 */

#include "dht_rpc.h"

#include "ants_cbor.h"
#include "dht_internal.h"
#include "dht_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Maximum size of an encoded request envelope. The biggest is
 * ANNOUNCE_PEER_REQ at ~50 bytes; 256 gives generous headroom. */
#define DHT_RPC_REQ_BUF_SIZE 256

/* ------------------------------------------------------------------------ */
/* Slot lookup helpers                                                      */
/* ------------------------------------------------------------------------ */

static struct ants_dht_state *get_state(ants_dht_t *dht)
{
    return (struct ants_dht_state *)(void *)dht->_opaque;
}

static struct ants_dht_pending_rpc *alloc_slot(struct ants_dht_state *state)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_RPCS; i++) {
        if (!state->pending[i].in_use) {
            return &state->pending[i];
        }
    }
    return NULL;
}

static struct ants_dht_pending_rpc *find_slot_by_stream(struct ants_dht_state *state,
                                                        const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_RPCS; i++) {
        if (state->pending[i].in_use && state->pending[i].stream == stream) {
            return &state->pending[i];
        }
    }
    return NULL;
}

/* Allocate a fresh transaction id. Skips 0 on wrap (reserved sentinel). */
static uint32_t next_txid(struct ants_dht_state *state)
{
    if (state->next_txid == 0) {
        state->next_txid = 1;
    }
    return state->next_txid++;
}

/* Free heap resources held by a slot and mark it free. Idempotent. */
static void release_slot(struct ants_dht_pending_rpc *slot)
{
    if (slot->recv_buf != NULL) {
        free(slot->recv_buf);
    }
    if (slot->stream != NULL) {
        free(slot->stream);
    }
    memset(slot, 0, sizeof *slot);
}

/* Fire the completion handler with the given status + response pointer,
 * then reclaim the slot. The caller must NOT touch the slot after this. */
static void fail_slot(struct ants_dht_pending_rpc *slot, ants_error_t status)
{
    ants_dht_rpc_completion_fn cb = slot->completion;
    void *ctx = slot->completion_ctx;
    release_slot(slot);
    if (cb != NULL) {
        cb(status, NULL, ctx);
    }
}

static void complete_slot(struct ants_dht_pending_rpc *slot, const void *resp)
{
    ants_dht_rpc_completion_fn cb = slot->completion;
    void *ctx = slot->completion_ctx;
    release_slot(slot);
    if (cb != NULL) {
        cb(ANTS_OK, resp, ctx);
    }
}

/* ------------------------------------------------------------------------ */
/* Send helper                                                              */
/*                                                                          */
/* Allocates a slot + heap stream, opens a bidi stream on the conn, sends   */
/* the already-encoded request bytes + FIN, and arms the completion. On    */
/* any failure path the slot is reclaimed and the original error returned. */
/* ------------------------------------------------------------------------ */

static ants_error_t arm_and_send(struct ants_dht_state *state,
                                 ants_transport_conn_t *conn,
                                 ants_dht_msg_type_t expected_resp_type,
                                 uint32_t txid,
                                 const uint8_t *encoded,
                                 size_t encoded_len,
                                 ants_dht_rpc_completion_fn completion,
                                 void *completion_ctx)
{
    struct ants_dht_pending_rpc *slot = alloc_slot(state);
    if (slot == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    ants_transport_stream_t *stream =
        (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
    if (stream == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    memset(stream, 0, sizeof *stream);

    /* Mark in_use first so any nested event during open/send finds the
     * slot. Stream is set before open_bidi_stream so the transport
     * stores its picoquic stream_id inside our heap buffer. */
    slot->in_use = true;
    slot->expected_resp_type = (uint8_t)expected_resp_type;
    slot->txid = txid;
    slot->conn = conn;
    slot->stream = stream;
    slot->recv_buf = NULL;
    slot->recv_len = 0;
    slot->recv_cap = 0;
    slot->completion = completion;
    slot->completion_ctx = completion_ctx;

    ants_error_t err = ants_transport_open_bidi_stream(conn, stream);
    if (err != ANTS_OK) {
        /* Cannot fire completion here — the caller is in the middle of
         * the send_* call and expects errors via the return value, not
         * the completion. Zero the completion before release_slot. */
        slot->completion = NULL;
        release_slot(slot);
        return err;
    }
    err = ants_transport_stream_send(stream, encoded, encoded_len, true /* fin */);
    if (err != ANTS_OK) {
        slot->completion = NULL;
        release_slot(slot);
        return err;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* send_* primitives                                                        */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_rpc_send_ping(ants_dht_t *dht,
                                    ants_transport_conn_t *conn,
                                    ants_dht_rpc_completion_fn completion,
                                    void *ctx)
{
    if (dht == NULL || conn == NULL || completion == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = get_state(dht);
    uint32_t txid = next_txid(state);
    ants_dht_ping_req_t req;
    req.txid = txid;

    uint8_t buf[DHT_RPC_REQ_BUF_SIZE];
    size_t enc_len = 0;
    ants_error_t err = ants_dht_wire_encode_ping_req(buf, sizeof buf, &enc_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    return arm_and_send(state, conn, ANTS_DHT_MSG_PING_RESP, txid, buf, enc_len, completion, ctx);
}

ants_error_t ants_dht_rpc_send_find_node(ants_dht_t *dht,
                                         ants_transport_conn_t *conn,
                                         const ants_peer_id_t *target,
                                         ants_dht_rpc_completion_fn completion,
                                         void *ctx)
{
    if (dht == NULL || conn == NULL || target == NULL || completion == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = get_state(dht);
    uint32_t txid = next_txid(state);
    ants_dht_find_node_req_t req;
    req.txid = txid;
    req.target = *target;

    uint8_t buf[DHT_RPC_REQ_BUF_SIZE];
    size_t enc_len = 0;
    ants_error_t err = ants_dht_wire_encode_find_node_req(buf, sizeof buf, &enc_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    return arm_and_send(
        state, conn, ANTS_DHT_MSG_FIND_NODE_RESP, txid, buf, enc_len, completion, ctx);
}

ants_error_t ants_dht_rpc_send_get_peers(ants_dht_t *dht,
                                         ants_transport_conn_t *conn,
                                         ants_dht_shard_key_t key,
                                         ants_dht_rpc_completion_fn completion,
                                         void *ctx)
{
    if (dht == NULL || conn == NULL || completion == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = get_state(dht);
    uint32_t txid = next_txid(state);
    ants_dht_get_peers_req_t req;
    req.txid = txid;
    req.key = key;

    uint8_t buf[DHT_RPC_REQ_BUF_SIZE];
    size_t enc_len = 0;
    ants_error_t err = ants_dht_wire_encode_get_peers_req(buf, sizeof buf, &enc_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    return arm_and_send(
        state, conn, ANTS_DHT_MSG_GET_PEERS_RESP, txid, buf, enc_len, completion, ctx);
}

ants_error_t ants_dht_rpc_send_announce_peer(ants_dht_t *dht,
                                             ants_transport_conn_t *conn,
                                             ants_dht_shard_key_t key,
                                             const uint8_t token[ANTS_DHT_TOKEN_SIZE],
                                             ants_dht_rpc_completion_fn completion,
                                             void *ctx)
{
    if (dht == NULL || conn == NULL || token == NULL || completion == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = get_state(dht);
    uint32_t txid = next_txid(state);
    ants_dht_announce_peer_req_t req;
    req.txid = txid;
    req.key = key;
    memcpy(req.token, token, ANTS_DHT_TOKEN_SIZE);

    uint8_t buf[DHT_RPC_REQ_BUF_SIZE];
    size_t enc_len = 0;
    ants_error_t err = ants_dht_wire_encode_announce_peer_req(buf, sizeof buf, &enc_len, &req);
    if (err != ANTS_OK) {
        return err;
    }
    return arm_and_send(
        state, conn, ANTS_DHT_MSG_ANNOUNCE_PEER_RESP, txid, buf, enc_len, completion, ctx);
}

/* ------------------------------------------------------------------------ */
/* Response decode dispatch                                                 */
/*                                                                          */
/* On STREAM_FIN the slot's recv_buf holds the complete CBOR-encoded        */
/* response. peek the type discriminator; if it matches the expected type, */
/* decode into a stack-resident response struct and pass to completion.    */
/* Type mismatches fail with MALFORMED (the peer sent a wrong-shape RPC). */
/* ------------------------------------------------------------------------ */

static void decode_and_complete(struct ants_dht_pending_rpc *slot)
{
    /* If the peer sent zero bytes followed by FIN, the buffer was never
     * allocated. CBOR can't represent that as a valid message — fail. */
    if (slot->recv_buf == NULL || slot->recv_len == 0) {
        fail_slot(slot, ANTS_ERROR_NON_CANONICAL);
        return;
    }

    ants_dht_msg_type_t got_type;
    ants_error_t err = ants_dht_wire_peek_type(slot->recv_buf, slot->recv_len, &got_type);
    if (err != ANTS_OK) {
        fail_slot(slot, err);
        return;
    }
    if ((uint8_t)got_type != slot->expected_resp_type) {
        fail_slot(slot, ANTS_ERROR_MALFORMED);
        return;
    }

    /* Decode into a type-specific struct and dispatch. Each resp struct
     * carries its own txid; mismatches are also MALFORMED. */
    switch (got_type) {
    case ANTS_DHT_MSG_PING_RESP: {
        ants_dht_ping_resp_t resp;
        memset(&resp, 0, sizeof resp);
        err = ants_dht_wire_decode_ping_resp(slot->recv_buf, slot->recv_len, &resp);
        if (err != ANTS_OK) {
            fail_slot(slot, err);
            return;
        }
        if (resp.txid != slot->txid) {
            fail_slot(slot, ANTS_ERROR_MALFORMED);
            return;
        }
        complete_slot(slot, &resp);
        return;
    }
    case ANTS_DHT_MSG_FIND_NODE_RESP: {
        ants_dht_find_node_resp_t resp;
        memset(&resp, 0, sizeof resp);
        err = ants_dht_wire_decode_find_node_resp(slot->recv_buf, slot->recv_len, &resp);
        if (err != ANTS_OK) {
            fail_slot(slot, err);
            return;
        }
        if (resp.txid != slot->txid) {
            fail_slot(slot, ANTS_ERROR_MALFORMED);
            return;
        }
        complete_slot(slot, &resp);
        return;
    }
    case ANTS_DHT_MSG_GET_PEERS_RESP: {
        ants_dht_get_peers_resp_t resp;
        memset(&resp, 0, sizeof resp);
        err = ants_dht_wire_decode_get_peers_resp(slot->recv_buf, slot->recv_len, &resp);
        if (err != ANTS_OK) {
            fail_slot(slot, err);
            return;
        }
        if (resp.txid != slot->txid) {
            fail_slot(slot, ANTS_ERROR_MALFORMED);
            return;
        }
        complete_slot(slot, &resp);
        return;
    }
    case ANTS_DHT_MSG_ANNOUNCE_PEER_RESP: {
        ants_dht_announce_peer_resp_t resp;
        memset(&resp, 0, sizeof resp);
        err = ants_dht_wire_decode_announce_peer_resp(slot->recv_buf, slot->recv_len, &resp);
        if (err != ANTS_OK) {
            fail_slot(slot, err);
            return;
        }
        if (resp.txid != slot->txid) {
            fail_slot(slot, ANTS_ERROR_MALFORMED);
            return;
        }
        complete_slot(slot, &resp);
        return;
    }
    default:
        /* Request types or unknown — same wrong-shape failure. */
        fail_slot(slot, ANTS_ERROR_MALFORMED);
        return;
    }
}

/* ------------------------------------------------------------------------ */
/* Event dispatcher                                                         */
/* ------------------------------------------------------------------------ */

static ants_error_t handle_readable(struct ants_dht_pending_rpc *slot,
                                    const ants_transport_event_t *event)
{
    if (event->payload == NULL || event->payload_len == 0) {
        return ANTS_OK;
    }
    /* Lazy-alloc recv_buf on first fragment. */
    if (slot->recv_buf == NULL) {
        slot->recv_buf = (uint8_t *)malloc(ANTS_DHT_RPC_RECV_CAP);
        if (slot->recv_buf == NULL) {
            fail_slot(slot, ANTS_ERROR_MALFORMED);
            return ANTS_OK;
        }
        slot->recv_cap = ANTS_DHT_RPC_RECV_CAP;
        slot->recv_len = 0;
    }
    /* Check for overflow before memcpy. */
    if (event->payload_len > slot->recv_cap - slot->recv_len) {
        fail_slot(slot, ANTS_ERROR_BUFFER_TOO_SMALL);
        return ANTS_OK;
    }
    memcpy(slot->recv_buf + slot->recv_len, event->payload, event->payload_len);
    slot->recv_len += event->payload_len;
    return ANTS_OK;
}

ants_error_t ants_dht_rpc_handle_event(ants_dht_t *dht, const ants_transport_event_t *event)
{
    if (dht == NULL || event == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = get_state(dht);

    /* CONN_CLOSED fires once per closed conn; sweep every slot tied to
     * it. Other events are stream-scoped — look up by stream pointer. */
    if (event->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_RPCS; i++) {
            struct ants_dht_pending_rpc *slot = &state->pending[i];
            if (slot->in_use && slot->conn == event->conn) {
                fail_slot(slot, ANTS_ERROR_PEER_UNREACHABLE);
            }
        }
        return ANTS_OK;
    }

    if (event->stream == NULL) {
        return ANTS_OK;
    }
    struct ants_dht_pending_rpc *slot = find_slot_by_stream(state, event->stream);
    if (slot == NULL) {
        /* Not one of our RPCs. */
        return ANTS_OK;
    }

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        return handle_readable(slot, event);
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        decode_and_complete(slot);
        return ANTS_OK;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        fail_slot(slot, ANTS_ERROR_STREAM_RESET);
        return ANTS_OK;
    default:
        /* CONN_READY, STREAM_OPENED, STREAM_WRITABLE — not relevant on
         * the outbound-RPC client path. */
        return ANTS_OK;
    }
}

/* ------------------------------------------------------------------------ */
/* Bulk cleanup                                                             */
/* ------------------------------------------------------------------------ */

void ants_dht_rpc_drop_all(ants_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }
    struct ants_dht_state *state = get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_RPCS; i++) {
        struct ants_dht_pending_rpc *slot = &state->pending[i];
        if (slot->in_use) {
            fail_slot(slot, ANTS_ERROR_PEER_UNREACHABLE);
        }
    }
}
