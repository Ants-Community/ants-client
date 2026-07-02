/*
 * dht_lookup.c — Iterative-lookup state machine.
 *
 * Implementation of dht_lookup.h. The DHT registers each active
 * lookup in state->active_lookups (back-pointers to caller-allocated
 * ants_dht_lookup_t buffers); tick() advances each one, and the RPC
 * completion handler folds responses back into the lookup's
 * candidate set.
 *
 * The candidate set is kept sorted ascending by XOR distance from
 * the target peer-id (= BLAKE3(target_key_le_bytes)). Each candidate
 * is in one of four states: UNQUERIED (newly inserted), INFLIGHT
 * (GET_PEERS sent), ANSWERED (response folded in), FAILED (no conn
 * or RPC error). Convergence = inflight_count == 0 AND no UNQUERIED
 * candidates remain; at that point LOOKUP_COMPLETE fires with up to
 * K closest ANSWERED peers.
 *
 * Late completions (RPC fires after lookup completed or cancelled)
 * see `record->valid == false` and no-op — the dht_rpc slot is still
 * reclaimed by release_slot before the completion is invoked.
 */

#include "dht_lookup.h"

#include "ants_crypto.h"
#include "ants_dht.h"
#include "ants_transport.h"
#include "dht_internal.h"
#include "dht_rpc.h"
#include "dht_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Cast helpers                                                             */
/* ------------------------------------------------------------------------ */

static struct ants_dht_lookup_state *lookup_get_state(ants_dht_lookup_t *l)
{
    return (struct ants_dht_lookup_state *)(void *)l->_opaque;
}

static ants_dht_lookup_t *lookup_state_to_handle(struct ants_dht_lookup_state *state)
{
    /* state lives at the start of lookup_t::_opaque[0]; both addresses
     * coincide via the union layout. */
    return (ants_dht_lookup_t *)(void *)state;
}

static struct ants_dht_state *dht_get_state(ants_dht_t *dht)
{
    return (struct ants_dht_state *)(void *)dht->_opaque;
}

/* ------------------------------------------------------------------------ */
/* XOR distance helpers                                                     */
/* ------------------------------------------------------------------------ */

static void xor_distance(const uint8_t a[ANTS_PEER_ID_SIZE],
                         const uint8_t b[ANTS_PEER_ID_SIZE],
                         uint8_t out[ANTS_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_PEER_ID_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/* Lexicographic compare of two distance vectors (big-endian XOR). */
static int dist_cmp(const uint8_t a[ANTS_PEER_ID_SIZE], const uint8_t b[ANTS_PEER_ID_SIZE])
{
    return memcmp(a, b, ANTS_PEER_ID_SIZE);
}

/* ------------------------------------------------------------------------ */
/* Candidate set                                                            */
/* ------------------------------------------------------------------------ */

/* Insert peer into the candidate set, keeping the array sorted ascending
 * by XOR distance from target_peer_id. Dedupes by peer_id (refreshing conn
 * if we now have one and the existing entry had NULL). When full, the new
 * candidate is dropped — phase 5 keeps this simple; phase 6+ may evict the
 * worst answered/failed entry if the newcomer is closer. */
static void cand_insert_sorted(struct ants_dht_lookup_state *lookup,
                               const ants_dht_peer_t *peer,
                               ants_transport_conn_t *conn)
{
    /* Skip self. */
    struct ants_dht_state *state = dht_get_state(lookup->parent);
    if (memcmp(peer->peer_id.bytes, state->local_peer_id.bytes, ANTS_PEER_ID_SIZE) == 0) {
        return;
    }

    /* Dedupe by peer_id. */
    for (size_t i = 0; i < lookup->candidate_count; i++) {
        if (memcmp(lookup->candidates[i].peer.peer_id.bytes,
                   peer->peer_id.bytes,
                   ANTS_PEER_ID_SIZE) == 0) {
            if (lookup->candidates[i].conn == NULL && conn != NULL) {
                lookup->candidates[i].conn = conn;
            }
            return;
        }
    }

    uint8_t dist[ANTS_PEER_ID_SIZE];
    xor_distance(lookup->target_peer_id, peer->peer_id.bytes, dist);

    /* Find sorted insertion position. */
    size_t pos = lookup->candidate_count;
    for (size_t i = 0; i < lookup->candidate_count; i++) {
        if (dist_cmp(dist, lookup->candidates[i].distance) < 0) {
            pos = i;
            break;
        }
    }

    /* If set is full, drop the new entry (phase 5 simple policy). */
    if (lookup->candidate_count == ANTS_DHT_LOOKUP_CANDIDATE_CAP) {
        return;
    }

    /* Shift right and insert. */
    for (size_t i = lookup->candidate_count; i > pos; i--) {
        lookup->candidates[i] = lookup->candidates[i - 1];
    }
    memset(&lookup->candidates[pos], 0, sizeof lookup->candidates[pos]);
    lookup->candidates[pos].peer = *peer;
    lookup->candidates[pos].conn = conn;
    memcpy(lookup->candidates[pos].distance, dist, ANTS_PEER_ID_SIZE);
    lookup->candidates[pos].state = (uint8_t)ANTS_DHT_LOOKUP_CAND_UNQUERIED;
    lookup->candidate_count++;
}

/* Seed the candidate set from every routing-table entry. NULL-conn
 * entries are included (phase 6.1.c will dial-promote them on first
 * query attempt — see issue_rpc_for_candidate). Pre-6.1.c this filter
 * skipped NULL-conn entries, which made them dead weight in the routing
 * table; with dial-promote they're a live discovery channel. */
static void seed_candidates_from_routing(struct ants_dht_lookup_state *lookup,
                                         const struct ants_dht_state *state)
{
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (const struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL;
             e = e->next) {
            cand_insert_sorted(lookup, &e->peer, e->conn);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Active-lookup registry                                                   */
/* ------------------------------------------------------------------------ */

/* Find slot in state->active_lookups that points at `handle`. */
static size_t active_slot_for(struct ants_dht_state *state, const ants_dht_lookup_t *handle)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        if (state->active_lookups[i] == handle) {
            return i;
        }
    }
    return (size_t)-1;
}

static void unregister_lookup(struct ants_dht_state *state, ants_dht_lookup_t *handle)
{
    size_t slot = active_slot_for(state, handle);
    if (slot != (size_t)-1) {
        state->active_lookups[slot] = NULL;
    }
}

/* ------------------------------------------------------------------------ */
/* LOOKUP_COMPLETE event                                                    */
/* ------------------------------------------------------------------------ */

static void fire_lookup_complete(struct ants_dht_lookup_state *lookup)
{
    if (lookup->completed) {
        return;
    }
    lookup->completed = true;

    struct ants_dht_state *state = dht_get_state(lookup->parent);

    if (lookup->is_probe) {
        /* Anti-eclipse axis S2 (RFC-0005 §"Anti-eclipse peer sampling"):
         * the probe's purpose is routing-table enrichment, not an answer.
         * Fold every ANSWERED candidate into the routing table — ANSWERED
         * means the peer was actually reached over the mutually-
         * authenticated transport (seeded conn or lazy dial with
         * expected_peer_id pinning) and answered a GET_PEERS, so the fold
         * admits only verified-reachable identities; peers merely NAMED in
         * responses never enter the table (poisoning a probe response does
         * not poison the table). kbucket_insert never evicts on insert
         * (full buckets reject), so probes enrich but cannot displace.
         * New peers fire PEER_DISCOVERED via dht_routing_upsert; the
         * completion fires TABLE_REFRESHED carrying the probe key instead
         * of LOOKUP_COMPLETE — random-target results must not reach
         * shard-lookup consumers as answers. */
        uint64_t now_us = dht_now_us();
        for (size_t i = 0; i < lookup->candidate_count; i++) {
            struct ants_dht_lookup_candidate *cand = &lookup->candidates[i];
            if (cand->state == (uint8_t)ANTS_DHT_LOOKUP_CAND_ANSWERED) {
                (void)dht_routing_upsert(lookup->parent, &cand->peer, cand->conn, now_us);
            }
        }
        if (state->event_fn != NULL) {
            ants_dht_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = ANTS_DHT_EV_TABLE_REFRESHED;
            ev.shard_key = lookup->target_key;
            (void)state->event_fn(&ev, state->event_ctx);
        }
    } else {
        /* Snapshot the K closest ANSWERED peers into a stack buffer. The
         * candidate set is already sorted ascending by distance, so a
         * single pass picks them up in order. */
        ants_dht_peer_t result_peers[ANTS_DHT_K];
        size_t result_count = 0;
        for (size_t i = 0; i < lookup->candidate_count && result_count < ANTS_DHT_K; i++) {
            if (lookup->candidates[i].state == (uint8_t)ANTS_DHT_LOOKUP_CAND_ANSWERED) {
                result_peers[result_count++] = lookup->candidates[i].peer;
            }
        }

        if (state->event_fn != NULL) {
            ants_dht_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = ANTS_DHT_EV_LOOKUP_COMPLETE;
            ev.lookup = lookup_state_to_handle(lookup);
            ev.peers = result_peers;
            ev.peer_count = result_count;
            ev.shard_key = lookup->target_key;
            (void)state->event_fn(&ev, state->event_ctx);
        }
    }

    /* Invalidate inflight records — late-firing completions will no-op. */
    for (size_t i = 0; i < ANTS_DHT_LOOKUP_INFLIGHT_CAP; i++) {
        lookup->inflight_recs[i].valid = false;
    }

    unregister_lookup(state, lookup_state_to_handle(lookup));
}

/* ------------------------------------------------------------------------ */
/* RPC completion handler                                                   */
/* ------------------------------------------------------------------------ */

static void on_rpc_complete(ants_error_t status, const void *resp, void *ctx)
{
    struct ants_dht_lookup_completion_record *rec = (struct ants_dht_lookup_completion_record *)ctx;
    if (rec == NULL || !rec->valid) {
        return;
    }
    rec->valid = false;

    struct ants_dht_lookup_state *lookup = lookup_get_state(rec->lookup_handle);
    if (lookup->completed) {
        return;
    }

    if ((size_t)rec->candidate_idx >= lookup->candidate_count) {
        /* Index out of range — shouldn't happen because cand_insert_sorted
         * cannot shift INFLIGHT entries past CAP (drop-new policy). Defend
         * with a no-op anyway. */
        if (lookup->inflight_count > 0) {
            lookup->inflight_count--;
        }
        return;
    }

    struct ants_dht_lookup_candidate *cand = &lookup->candidates[rec->candidate_idx];

    if (status == ANTS_OK && resp != NULL) {
        cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_ANSWERED;
        const ants_dht_get_peers_resp_t *gp = (const ants_dht_get_peers_resp_t *)resp;
        for (size_t i = 0; i < gp->peer_count; i++) {
            /* New peers come with no known conn — phase 6 maintenance
             * promotes them by dialing. */
            cand_insert_sorted(lookup, &gp->peers[i], NULL);
        }
    } else {
        cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_FAILED;
    }

    if (lookup->inflight_count > 0) {
        lookup->inflight_count--;
    }
}

/* ------------------------------------------------------------------------ */
/* Issue an RPC for a single candidate                                      */
/* ------------------------------------------------------------------------ */

/* Phase 6.1.c: lazily dial a NULL-conn candidate that has a known
 * multiaddr. Allocates a pending_dials slot + heap conn, kicks off
 * `ants_transport_dial`, flips the candidate to INFLIGHT_DIAL. On
 * CONN_READY (delivered via ants_dht_lookup_promote_dialed_peer) the
 * candidate goes back to UNQUERIED with the live conn and the next
 * lookup_advance issues GET_PEERS for real. Returns true if the dial
 * was issued, false if dial-promote was rejected (no multiaddr, no
 * free slot, malloc failure, transport_dial error). On false the
 * candidate is marked FAILED. */
static bool try_dial_promote(struct ants_dht_lookup_state *lookup,
                             struct ants_dht_lookup_candidate *cand)
{
    if (cand->peer.multiaddr[0] == '\0') {
        return false;
    }
    struct ants_dht_state *state = dht_get_state(lookup->parent);
    if (state->transport == NULL) {
        return false;
    }
    struct ants_dht_pending_dial *pd = NULL;
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_DIALS; i++) {
        if (!state->pending_dials[i].in_use) {
            pd = &state->pending_dials[i];
            break;
        }
    }
    if (pd == NULL) {
        return false;
    }
    ants_transport_conn_t *conn = (ants_transport_conn_t *)malloc(sizeof(ants_transport_conn_t));
    if (conn == NULL) {
        return false;
    }
    memset(conn, 0, sizeof *conn);
    ants_error_t err =
        ants_transport_dial(state->transport, cand->peer.multiaddr, &cand->peer.peer_id, conn);
    if (err != ANTS_OK) {
        free(conn);
        return false;
    }
    memset(pd, 0, sizeof *pd);
    pd->in_use = true;
    pd->promoted = false;
    pd->conn = conn;
    pd->expected_peer_id = cand->peer.peer_id;
    size_t addr_len = strlen(cand->peer.multiaddr);
    if (addr_len >= sizeof pd->multiaddr) {
        addr_len = sizeof pd->multiaddr - 1;
    }
    memcpy(pd->multiaddr, cand->peer.multiaddr, addr_len);
    pd->multiaddr[addr_len] = '\0';
    cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL;
    /* inflight_count NOT incremented: that counter is for in-flight
     * GET_PEERS RPCs, not for in-flight dials. The convergence check
     * looks at INFLIGHT_DIAL separately. */
    return true;
}

/* Returns true if INFLIGHT was set (one slot of α is now occupied); false
 * if the candidate was FAILED immediately (no conn, or send_get_peers
 * returned an error). */
static bool issue_rpc_for_candidate(struct ants_dht_lookup_state *lookup, size_t cand_idx)
{
    struct ants_dht_lookup_candidate *cand = &lookup->candidates[cand_idx];

    if (cand->conn == NULL) {
        /* Phase 6.1.c: if we know the peer's multiaddr, lazy-dial it
         * and wait for CONN_READY instead of giving up. */
        if (try_dial_promote(lookup, cand)) {
            return false; /* inflight_count not consumed; INFLIGHT_DIAL state set */
        }
        cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_FAILED;
        return false;
    }

    /* Find a free completion record. We size the record array to
     * INFLIGHT_CAP = α, so under normal flow at least one is always
     * free when inflight_count < α. Defensive check anyway. */
    struct ants_dht_lookup_completion_record *rec = NULL;
    for (size_t i = 0; i < ANTS_DHT_LOOKUP_INFLIGHT_CAP; i++) {
        if (!lookup->inflight_recs[i].valid) {
            rec = &lookup->inflight_recs[i];
            break;
        }
    }
    if (rec == NULL) {
        cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_FAILED;
        return false;
    }

    rec->valid = true;
    rec->lookup_handle = lookup_state_to_handle(lookup);
    rec->candidate_idx = (uint32_t)cand_idx;

    ants_error_t err = ants_dht_rpc_send_get_peers(
        lookup->parent, cand->conn, lookup->target_key, on_rpc_complete, rec);
    if (err != ANTS_OK) {
        rec->valid = false;
        cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_FAILED;
        return false;
    }

    cand->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_INFLIGHT;
    lookup->inflight_count++;
    return true;
}

/* ------------------------------------------------------------------------ */
/* Lookup tick                                                              */
/* ------------------------------------------------------------------------ */

static void lookup_advance(struct ants_dht_lookup_state *lookup)
{
    if (lookup->completed) {
        return;
    }

    /* Issue new RPCs until inflight count saturates or no UNQUERIED
     * candidates remain. Walking from the head of the sorted candidate
     * array picks the closest unqueried candidate each round. */
    while (lookup->inflight_count < ANTS_DHT_LOOKUP_INFLIGHT_CAP) {
        size_t idx = (size_t)-1;
        for (size_t i = 0; i < lookup->candidate_count; i++) {
            if (lookup->candidates[i].state == (uint8_t)ANTS_DHT_LOOKUP_CAND_UNQUERIED) {
                idx = i;
                break;
            }
        }
        if (idx == (size_t)-1) {
            break;
        }
        /* If issue_rpc_for_candidate fails to mark INFLIGHT (e.g. no
         * conn), state becomes FAILED and we continue the loop — no
         * inflight slot consumed, so the next iteration tries the next
         * UNQUERIED candidate. */
        (void)issue_rpc_for_candidate(lookup, idx);
    }

    /* Convergence: no in-flight RPCs, no in-flight dials, and every
     * candidate has been resolved (ANSWERED or FAILED). INFLIGHT_DIAL
     * candidates count as in-progress just like INFLIGHT — they're
     * waiting on CONN_READY before they can transition to INFLIGHT. */
    if (lookup->inflight_count == 0) {
        for (size_t i = 0; i < lookup->candidate_count; i++) {
            uint8_t s = lookup->candidates[i].state;
            if (s == (uint8_t)ANTS_DHT_LOOKUP_CAND_UNQUERIED ||
                s == (uint8_t)ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL) {
                return;
            }
        }
        fire_lookup_complete(lookup);
    }
}

/* ------------------------------------------------------------------------ */
/* Public-to-module entry points                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_lookup_start(ants_dht_t *dht,
                                   ants_dht_shard_key_t target_key,
                                   ants_dht_lookup_t *out_lookup,
                                   bool is_probe)
{
    struct ants_dht_state *state = dht_get_state(dht);

    /* Find a free active-lookups slot. */
    size_t slot = (size_t)-1;
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        if (state->active_lookups[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == (size_t)-1) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Initialise the lookup_state in the caller's opaque buffer. */
    memset(out_lookup->_opaque, 0, sizeof out_lookup->_opaque);
    struct ants_dht_lookup_state *lookup = lookup_get_state(out_lookup);
    lookup->in_use = true;
    lookup->completed = false;
    lookup->is_probe = is_probe;
    lookup->parent = dht;
    lookup->target_key = target_key;

    /* Derive target_peer_id = BLAKE3(target_key as 8 little-endian bytes). */
    uint8_t key_le[8];
    for (int i = 0; i < 8; i++) {
        key_le[i] = (uint8_t)((target_key >> (i * 8)) & 0xFFu);
    }
    ants_error_t err = ants_blake3_hash(key_le, sizeof key_le, lookup->target_peer_id);
    if (err != ANTS_OK) {
        return err;
    }

    state->active_lookups[slot] = out_lookup;

    /* Seed candidates from the routing table. Initial advance happens on
     * the next ants_dht_tick — keeping it out of the call chain avoids
     * firing LOOKUP_COMPLETE synchronously from inside lookup_start
     * (which would surprise callers iterating active lookups). */
    seed_candidates_from_routing(lookup, state);

    return ANTS_OK;
}

ants_error_t ants_dht_lookup_do_cancel(ants_dht_lookup_t *lookup_handle)
{
    if (lookup_handle == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_lookup_state *lookup = lookup_get_state(lookup_handle);
    if (!lookup->in_use || lookup->completed) {
        return ANTS_OK; /* idempotent */
    }
    lookup->completed = true;
    /* Invalidate inflight records so late completions no-op. The
     * underlying dht_rpc slots will be reclaimed by release_slot when
     * their STREAM_FIN / STREAM_RESET / CONN_CLOSED arrives. */
    for (size_t i = 0; i < ANTS_DHT_LOOKUP_INFLIGHT_CAP; i++) {
        lookup->inflight_recs[i].valid = false;
    }
    struct ants_dht_state *state = dht_get_state(lookup->parent);
    /* Disarm any pending RPC slot still pointing into this handle's
     * completion records. The caller may legally reuse the handle
     * after cancel (the header requires validity only "until the
     * lookup completes ... or is cancelled"), and lookup_start memsets
     * it — re-validating the SAME record addresses for the next
     * lookup. Without the disarm, a late terminal event on an old slot
     * (a straggler response, a reset, a conn close) would fire
     * on_rpc_complete against the new lookup's record and corrupt it —
     * e.g. marking a candidate ANSWERED with a stale response, a hole
     * in the probe's verified-only-fold contract. The slot itself is
     * still reclaimed by its own stream/conn event; the complete/fail
     * paths already tolerate a NULL completion. */
    uintptr_t recs_lo = (uintptr_t)&lookup->inflight_recs[0];
    uintptr_t recs_hi = (uintptr_t)&lookup->inflight_recs[ANTS_DHT_LOOKUP_INFLIGHT_CAP];
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_RPCS; i++) {
        struct ants_dht_pending_rpc *slot = &state->pending[i];
        uintptr_t ctx = (uintptr_t)slot->completion_ctx;
        if (slot->in_use && ctx >= recs_lo && ctx < recs_hi) {
            slot->completion = NULL;
            slot->completion_ctx = NULL;
        }
    }
    unregister_lookup(state, lookup_handle);
    return ANTS_OK;
}

ants_error_t ants_dht_lookup_advance_all(ants_dht_t *dht)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = dht_get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        ants_dht_lookup_t *h = state->active_lookups[i];
        if (h == NULL) {
            continue;
        }
        struct ants_dht_lookup_state *lookup = lookup_get_state(h);
        if (!lookup->completed) {
            lookup_advance(lookup);
        }
    }
    return ANTS_OK;
}

void ants_dht_lookup_promote_dialed_peer(ants_dht_t *dht,
                                         const ants_peer_id_t *peer_id,
                                         ants_transport_conn_t *conn)
{
    if (dht == NULL || peer_id == NULL) {
        return;
    }
    struct ants_dht_state *state = dht_get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        ants_dht_lookup_t *h = state->active_lookups[i];
        if (h == NULL) {
            continue;
        }
        struct ants_dht_lookup_state *lookup = lookup_get_state(h);
        if (lookup->completed) {
            continue;
        }
        for (size_t j = 0; j < lookup->candidate_count; j++) {
            struct ants_dht_lookup_candidate *c = &lookup->candidates[j];
            if (c->state == (uint8_t)ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL &&
                memcmp(c->peer.peer_id.bytes, peer_id->bytes, ANTS_PEER_ID_SIZE) == 0) {
                c->conn = conn;
                c->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_UNQUERIED;
            }
        }
    }
}

void ants_dht_lookup_fail_dialing_candidates(ants_dht_t *dht, const ants_peer_id_t *peer_id)
{
    if (dht == NULL || peer_id == NULL) {
        return;
    }
    struct ants_dht_state *state = dht_get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        ants_dht_lookup_t *h = state->active_lookups[i];
        if (h == NULL) {
            continue;
        }
        struct ants_dht_lookup_state *lookup = lookup_get_state(h);
        if (lookup->completed) {
            continue;
        }
        for (size_t j = 0; j < lookup->candidate_count; j++) {
            struct ants_dht_lookup_candidate *c = &lookup->candidates[j];
            if (c->state == (uint8_t)ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL &&
                memcmp(c->peer.peer_id.bytes, peer_id->bytes, ANTS_PEER_ID_SIZE) == 0) {
                c->state = (uint8_t)ANTS_DHT_LOOKUP_CAND_FAILED;
            }
        }
    }
}

void ants_dht_lookup_invalidate_conn(ants_dht_t *dht, const ants_transport_conn_t *conn)
{
    if (dht == NULL || conn == NULL) {
        return;
    }
    struct ants_dht_state *state = dht_get_state(dht);
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        ants_dht_lookup_t *h = state->active_lookups[i];
        if (h == NULL) {
            continue;
        }
        struct ants_dht_lookup_state *lookup = lookup_get_state(h);
        if (lookup->completed) {
            continue;
        }
        for (size_t j = 0; j < lookup->candidate_count; j++) {
            struct ants_dht_lookup_candidate *c = &lookup->candidates[j];
            if (c->conn == conn) {
                /* The candidate itself stays queryable: with conn NULL
                 * the advance loop falls back to try_dial_promote (or
                 * FAILs it), and the probe's ANSWERED fold upserts a
                 * known-only entry instead of a dangling pointer. */
                c->conn = NULL;
            }
        }
    }
}
