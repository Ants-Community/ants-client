/*
 * dht_rpc.h — RPC dispatch over transport bidi streams (PRIVATE).
 *
 * Phase 4 deliverable. Implements the outbound (client) side of the
 * four Kademlia RPC pairs declared in dht_wire.h:
 *
 *   PING          → PING_RESP
 *   FIND_NODE     → FIND_NODE_RESP
 *   GET_PEERS     → GET_PEERS_RESP
 *   ANNOUNCE_PEER → ANNOUNCE_PEER_RESP
 *
 * Each send_* primitive:
 *   1. Allocates a fresh slot in the pending-RPC registry (heap +
 *      stream + recv_buf are owned by the slot).
 *   2. Encodes the request as a canonical CBOR envelope per
 *      dht_wire.h.
 *   3. Opens a bidi stream on the supplied connection, sends the
 *      encoded request with FIN, and arms the completion handler.
 *
 * The response flows in via ants_dht_handle_transport_event, which
 * the application-level caller invokes from inside their transport
 * event_fn. STREAM_READABLE accumulates into the slot's recv_buf;
 * STREAM_FIN triggers decode + completion + slot reclamation;
 * STREAM_RESET fails the slot with ANTS_ERROR_STREAM_RESET;
 * CONN_CLOSED fails every slot on that conn with PEER_UNREACHABLE.
 *
 * Server-side dispatch (decoding inbound requests, generating
 * responses) lives in dht.c phase 5+ — it's tightly coupled with
 * the iterative-lookup state machine and the announcement set.
 *
 * This header is private to the DHT implementation. tests link via
 * the test hooks exposed in dht.c (ants_dht__test_send_*).
 */

#ifndef ANTS_DHT_RPC_H
#define ANTS_DHT_RPC_H

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_transport.h"
#include "dht_internal.h"
#include "dht_wire.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Outbound RPC primitives                                                  */
/*                                                                          */
/* All four primitives share the same shape:                                */
/*   - dht must be initialised against a live transport.                    */
/*   - conn must have completed handshake (CONN_READY observed).            */
/*   - completion is required (cannot be NULL); ctx may be NULL.            */
/*                                                                          */
/* Returns:                                                                 */
/*   ANTS_OK                       request queued; completion will fire.    */
/*   ANTS_ERROR_INVALID_ARG        NULL args or wrong-shape input.          */
/*   ANTS_ERROR_BUFFER_TOO_SMALL   pending-RPC registry exhausted.          */
/*   ANTS_ERROR_MALFORMED          heap allocation failed.                  */
/*   (transport error)             open_bidi_stream / stream_send failed.   */
/* On error, the completion does NOT fire (the slot is reclaimed before    */
/* returning) — the caller's return-value check is sufficient.             */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_rpc_send_ping(ants_dht_t *dht,
                                    ants_transport_conn_t *conn,
                                    ants_dht_rpc_completion_fn completion,
                                    void *ctx);

ants_error_t ants_dht_rpc_send_find_node(ants_dht_t *dht,
                                         ants_transport_conn_t *conn,
                                         const ants_peer_id_t *target,
                                         ants_dht_rpc_completion_fn completion,
                                         void *ctx);

ants_error_t ants_dht_rpc_send_get_peers(ants_dht_t *dht,
                                         ants_transport_conn_t *conn,
                                         ants_dht_shard_key_t key,
                                         ants_dht_rpc_completion_fn completion,
                                         void *ctx);

ants_error_t ants_dht_rpc_send_announce_peer(ants_dht_t *dht,
                                             ants_transport_conn_t *conn,
                                             ants_dht_shard_key_t key,
                                             const uint8_t token[ANTS_DHT_TOKEN_SIZE],
                                             ants_dht_rpc_completion_fn completion,
                                             void *ctx);

/* ------------------------------------------------------------------------ */
/* Transport-event dispatcher                                               */
/*                                                                          */
/* Invoked by ants_dht_handle_transport_event (which is the public entry  */
/* the caller wires from their own transport event_fn). Inspects the event */
/* and routes it to the right slot:                                         */
/*                                                                          */
/*   STREAM_READABLE → accumulate payload (lazy-alloc recv_buf on first    */
/*                     fragment); fail with BUFFER_TOO_SMALL on overflow.   */
/*   STREAM_FIN      → decode the buffered response, fire completion,      */
/*                     release the slot.                                    */
/*   STREAM_RESET    → fire completion(STREAM_RESET), release the slot.    */
/*   CONN_CLOSED     → fail every slot on this conn with PEER_UNREACHABLE. */
/*                                                                          */
/* Other event kinds (CONN_READY, STREAM_OPENED, STREAM_WRITABLE) are      */
/* ignored — they're not relevant to the outbound-RPC client path.         */
/*                                                                          */
/* Returns ANTS_OK on success, including the case where the event did not  */
/* belong to any pending slot. NULL args return ANTS_ERROR_INVALID_ARG.    */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_rpc_handle_event(ants_dht_t *dht, const ants_transport_event_t *event);

/* ------------------------------------------------------------------------ */
/* Cleanup helper                                                           */
/*                                                                          */
/* Reclaims every pending RPC slot, freeing recv_buf + stream and calling  */
/* each registered completion with PEER_UNREACHABLE. Used by               */
/* ants_dht_destroy to ensure no heap leaks on teardown.                   */
/* ------------------------------------------------------------------------ */

void ants_dht_rpc_drop_all(ants_dht_t *dht);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_DHT_RPC_H */
