/*
 * dht_server.h — Server-side DHT dispatch (PRIVATE).
 *
 * Phase 6 deliverable. Handles inbound DHT requests: peer-initiated
 * bidi streams carrying PING_REQ / FIND_NODE_REQ / GET_PEERS_REQ /
 * ANNOUNCE_PEER_REQ, generates the corresponding response, sends it
 * back on the same stream with FIN.
 *
 * Per-stream state lives in struct ants_dht_inbound_stream (in
 * dht_internal.h). The dispatcher hooks into the same transport-
 * event delegation path as dht_rpc, but reacts only to events whose
 * stream pointer does NOT belong to any outbound pending RPC.
 *
 * Token discipline (BitTorrent style): GET_PEERS_RESP carries a
 * 16-byte token derived from BLAKE3(server_secret || peer_id);
 * ANNOUNCE_PEER_REQ must echo a valid token or the announce is
 * rejected. Phase 6 uses a fixed server_secret (derived from
 * local_peer_id at init); phase 6.1+ will rotate it.
 *
 * Routing-table responses (FIND_NODE_RESP, GET_PEERS_RESP fallback)
 * return up to K=20 closest peers to the target/shard-key from the
 * local routing table, sorted ascending by XOR distance.
 */

#ifndef ANTS_DHT_SERVER_H
#define ANTS_DHT_SERVER_H

#include "ants_common.h"
#include "ants_dht.h"
#include "ants_transport.h"
#include "dht_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dispatch a transport event through the server-side path. Returns
 * ANTS_OK regardless of whether the event was handled (events that
 * don't match any inbound stream are no-ops). NULL guards in caller.
 *
 * Hook order: ants_dht_handle_transport_event invokes
 *   1. ants_dht_rpc_handle_event   (outbound RPC dispatcher)
 *   2. ants_dht_server_handle_event (this — inbound server dispatcher)
 * Each runs to completion; the second sees the event regardless of
 * whether the first handled it. The two registries don't overlap
 * (pending[] tracks outbound stream pointers; inbound_streams[]
 * tracks the peer-allocated stream pointers from STREAM_OPENED) so
 * at most one handler does real work per event. */
ants_error_t ants_dht_server_handle_event(ants_dht_t *dht, const ants_transport_event_t *event);

/* Compute the 16-byte token a GET_PEERS_RESP would carry for `peer`.
 * Exposed so phase 7's integration test can validate token correctness;
 * production callers should never touch this. */
void ants_dht_server_compute_token(const struct ants_dht_state *state,
                                   const ants_peer_id_t *peer,
                                   uint8_t out_token[16]);

/* Server-side bulk cleanup: free heap recv_buf on every inbound slot
 * and zero them. Called from ants_dht_destroy. */
void ants_dht_server_drop_all(ants_dht_t *dht);

/* Insert / refresh an announce. Used by both the server-side
 * ANNOUNCE_PEER handler and (phase 7+) any external test seeding.
 * Returns ANTS_OK on success, ANTS_ERROR_BUFFER_TOO_SMALL when the
 * announce set is full and no LRU slot can be reclaimed. */
ants_error_t ants_dht_server_upsert_announce(struct ants_dht_state *state,
                                             ants_dht_shard_key_t shard_key,
                                             const ants_dht_peer_t *announcer,
                                             uint64_t now_us);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_DHT_SERVER_H */
