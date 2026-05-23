/*
 * dht_lookup.h — Iterative-lookup state machine (PRIVATE).
 *
 * Phase 5 deliverable. Implements the standard Kademlia iterative
 * GET_PEERS loop on top of the phase-4 RPC dispatch:
 *
 *   1. Seed the candidate set from routing-table entries that have
 *      a known transport connection (conn != NULL).
 *   2. While inflight_count < α and candidates UNQUERIED remain:
 *      pick the closest UNQUERIED candidate; issue GET_PEERS via
 *      ants_dht_rpc_send_get_peers; mark INFLIGHT.
 *   3. On RPC completion: ANSWERED on success (fold peers[] into the
 *      candidate set), FAILED on error.
 *   4. When inflight_count==0 and no UNQUERIED candidates remain →
 *      convergence; fire LOOKUP_COMPLETE with up to K closest
 *      ANSWERED peers.
 *
 * Cancellation: ants_dht_lookup_do_cancel marks the lookup completed
 * and invalidates every completion record. Late-firing RPC completions
 * see valid=false and no-op (the slot was already reclaimed by
 * dht_rpc's release_slot path).
 *
 * Server-side dispatch (decoding inbound GET_PEERS and producing
 * responses) is NOT in this module — phase 6 lands it alongside
 * bootstrap and the periodic maintenance loop. Tests therefore use a
 * manual server-side responder (same pattern as test_rpc_round_trip).
 */

#ifndef ANTS_DHT_LOOKUP_H
#define ANTS_DHT_LOOKUP_H

#include "ants_common.h"
#include "ants_dht.h"
#include "dht_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start a lookup against `dht` for `target_key`. Initialises the
 * caller-supplied `out_lookup`, registers it in the DHT's active-lookup
 * slot table, seeds the candidate set from the routing table, and
 * issues the first batch of RPCs.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_BUFFER_TOO_SMALL if all ANTS_DHT_MAX_ACTIVE_LOOKUPS
 *     slots are in use.
 *
 * On completion or timeout, LOOKUP_COMPLETE / LOOKUP_TIMEOUT events
 * fire via the DHT's registered event_fn. */
ants_error_t ants_dht_lookup_start(ants_dht_t *dht,
                                   ants_dht_shard_key_t target_key,
                                   ants_dht_lookup_t *out_lookup);

/* Cancel an in-flight lookup. Invalidates all completion records and
 * marks the lookup completed (no events fire after cancellation).
 * Idempotent on already-completed lookups. */
ants_error_t ants_dht_lookup_do_cancel(ants_dht_lookup_t *lookup);

/* Tick: scan all active lookups, advance each one (issue more RPCs if
 * inflight < α, check for convergence). Called from ants_dht_tick.
 * Returns ANTS_OK unconditionally. */
ants_error_t ants_dht_lookup_advance_all(ants_dht_t *dht);

/* Phase 6.1.c dial-promote callbacks invoked from dht.c's transport
 * event dispatcher. promote_dialed_peer flips every INFLIGHT_DIAL
 * candidate matching peer_id back to UNQUERIED with the supplied conn
 * so the next lookup_advance issues GET_PEERS; fail_dialing_candidates
 * marks them FAILED (CONN_CLOSED before CONN_READY). Both are no-ops
 * if no lookup is awaiting that peer. */
void ants_dht_lookup_promote_dialed_peer(ants_dht_t *dht,
                                         const ants_peer_id_t *peer_id,
                                         ants_transport_conn_t *conn);
void ants_dht_lookup_fail_dialing_candidates(ants_dht_t *dht, const ants_peer_id_t *peer_id);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_DHT_LOOKUP_H */
