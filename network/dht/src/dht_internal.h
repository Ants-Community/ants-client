/*
 * dht_internal.h — Private storage layout for the DHT.
 *
 * Shared between dht.c (lifecycle, routing-table, test hooks) and
 * dht_rpc.c (RPC dispatch over transport streams). Not installed,
 * not exposed to downstream consumers.
 *
 * The public ants_dht_t is a uint8_t[ANTS_DHT_CTX_SIZE] union; we
 * cast it to struct ants_dht_state. The compile-time-assertion in
 * dht.c (ants_dht_state_size_check) verifies the layout fits.
 */

#ifndef ANTS_DHT_INTERNAL_H
#define ANTS_DHT_INTERNAL_H

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ */
/* K-bucket entry + bucket head                                             */
/*                                                                          */
/* Standard Kademlia layout: 256 buckets, one per leading-bit-prefix length */
/* of XOR(local, peer); each bucket holds up to ANTS_DHT_K = 20 entries     */
/* in a singly-linked list with MRU at head.                                */
/* ------------------------------------------------------------------------ */

struct ants_dht_bucket_entry {
    ants_dht_peer_t peer;
    uint64_t last_seen_us;
    struct ants_dht_bucket_entry *next;
};

struct ants_dht_bucket {
    struct ants_dht_bucket_entry *head;
    size_t count;
};

/* ------------------------------------------------------------------------ */
/* Pending-RPC registry                                                     */
/*                                                                          */
/* Each in-flight RPC owns a slot. The DHT allocates the per-RPC bidi      */
/* stream and the response accumulator buffer on the heap (so neither      */
/* lives in this fixed-size record). On STREAM_FIN we decode and fire the  */
/* completion handler; on STREAM_RESET / CONN_CLOSED we fire with the      */
/* error status and reclaim the heap. The slot is "free" when in_use=0.    */
/*                                                                          */
/* Capacity sized for alpha=3 in-flight per active lookup × ~20 concurrent */
/* lookups + maintenance RPCs (PING / refresh). 64 is comfortably above    */
/* expected steady-state for a single peer.                                */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_PENDING_RPCS 64

/* Maximum response size we'll accept before failing the RPC with
 * BUFFER_TOO_SMALL. GET_PEERS_RESP with K=20 peers is the worst case
 * at ~1.9 KB; 4 KB gives ~2x margin. */
#define ANTS_DHT_RPC_RECV_CAP 4096

/* Completion callback fired when an in-flight RPC resolves (success or
 * failure). Defined here rather than in dht_rpc.h so the pending_rpc
 * struct below can hold a pointer of this type without a header cycle.
 *
 *   status  — ANTS_OK if a well-formed response of the expected type
 *             arrived, otherwise one of:
 *               ANTS_ERROR_NON_CANONICAL    response failed CBOR decode
 *               ANTS_ERROR_BUFFER_TOO_SMALL response exceeded RECV_CAP
 *               ANTS_ERROR_STREAM_RESET     peer reset the stream
 *               ANTS_ERROR_PEER_UNREACHABLE the connection died
 *               ANTS_ERROR_MALFORMED        peer sent wrong type
 *
 *   resp    — on ANTS_OK, pointer to a decoded response struct of the
 *             type the caller's send_* call requested:
 *               send_ping           → const ants_dht_ping_resp_t *
 *               send_find_node      → const ants_dht_find_node_resp_t *
 *               send_get_peers      → const ants_dht_get_peers_resp_t *
 *               send_announce_peer  → const ants_dht_announce_peer_resp_t *
 *             Pointer valid for the duration of the callback only.
 *             NULL on any non-OK status.
 *
 *   ctx     — opaque pointer caller registered at send time. */
typedef void (*ants_dht_rpc_completion_fn)(ants_error_t status, const void *resp, void *ctx);

struct ants_dht_pending_rpc {
    /* True iff this slot is occupied. */
    bool in_use;
    /* Expected response type discriminator (matches sent request).
     * Stored as uint8_t for compactness; encodes ants_dht_msg_type_t
     * values 5..8 (the four _RESP types). 0 = no expectation. */
    uint8_t expected_resp_type;
    /* uint16 padding to align txid on 4-byte boundary. */
    uint16_t _pad;
    /* Per-RPC transaction id; mirrored in the request envelope and
     * validated against the response on decode. Generated from a
     * monotonic counter in struct ants_dht_state. */
    uint32_t txid;
    /* The connection the stream lives on. Used to handle CONN_CLOSED:
     * any pending RPC whose conn matches the closed conn is failed
     * with PEER_UNREACHABLE and reclaimed. */
    ants_transport_conn_t *conn;
    /* The bidi stream this RPC owns. Heap-allocated by send_*; freed
     * on completion / failure. Comparison against event->stream is how
     * we route incoming transport events to the right slot. */
    ants_transport_stream_t *stream;
    /* Accumulator for the CBOR response body. NULL until the first
     * STREAM_READABLE; allocated lazily at ANTS_DHT_RPC_RECV_CAP. */
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
    /* Completion handler + opaque cookie. */
    ants_dht_rpc_completion_fn completion;
    void *completion_ctx;
};

/* ------------------------------------------------------------------------ */
/* Top-level DHT state                                                      */
/*                                                                          */
/* Cast over ants_dht_t::_opaque. Size-checked at compile time in dht.c.   */
/* ------------------------------------------------------------------------ */

struct ants_dht_state {
    ants_transport_t *transport;
    ants_peer_id_t local_peer_id;
    ants_dht_event_fn event_fn;
    void *event_ctx;
    uint32_t refresh_interval_ms;
    uint32_t lookup_deadline_ms;
    uint32_t announce_republish_ms;
    /* Monotonic counter handing out fresh per-RPC txids. Starts at 1;
     * 0 is reserved (sentinel "no txid"). Wrap is acceptable — the
     * (stream-pointer, txid) pair is what's actually unique; txid
     * alone is just a redundancy check against response/request
     * mismatches. */
    uint32_t next_txid;
    /* 256-bucket routing table. */
    struct ants_dht_bucket buckets[ANTS_DHT_BUCKET_COUNT];
    /* In-flight RPC registry. Scanned linearly on every transport
     * event (O(64)) — overhead negligible vs. CBOR decode cost. */
    struct ants_dht_pending_rpc pending[ANTS_DHT_MAX_PENDING_RPCS];
};

#endif /* ANTS_DHT_INTERNAL_H */
