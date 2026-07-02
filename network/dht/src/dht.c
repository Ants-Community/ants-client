/*
 * dht.c — Kademlia DHT (shard-key variant).
 *
 * Lifecycle, k-bucket routing table, public-API entry points, and the
 * RPC-event delegation hook. The actual outbound RPC machinery (CBOR
 * encode + bidi stream + completion handler) lives in dht_rpc.c; the
 * shared state layout is defined in dht_internal.h.
 *
 * Implementation phases:
 *   - Phase 1: API surface stub, opaque-ctx size check, init/destroy
 *     lifecycle that just zeroes the buffer.                  [done]
 *   - Phase 2: k-bucket data structure + XOR distance helpers. [done]
 *   - Phase 3: Wire-message CBOR codec (PING, FIND_NODE, GET_PEERS,
 *     ANNOUNCE_PEER and their responses).                     [done]
 *   - Phase 4: RPC dispatch over transport bidi streams.      [done]
 *   - Phase 5: Iterative lookup state machine.                [done]
 *   - Phase 6: Bootstrap + server-side dispatch + announces.  [done]
 *   - Phase 6.1.a: refresh PING + dead_strikes eviction.      [done]
 *   - Phase 6.1.b: announce republish chain.                  [done]
 *   - Phase 6.1.c: dial-promote during lookup.                [done]
 *   - Phase 7: Two-node integration test exchanging real lookups. [done]
 */

/* POSIX feature test — required on glibc to expose clock_gettime() and
 * CLOCK_MONOTONIC from <time.h>. macOS exposes them by default; this
 * define is benign there. Must precede every system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_dht.h"

#include "ants_crypto.h"
#include "dht_internal.h"
#include "dht_lookup.h"
#include "dht_rpc.h"
#include "dht_server.h"
#include "dht_wire.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------------ */
/* Clock                                                                    */
/*                                                                          */
/* Phase 6.1 introduces real wall-clock-ish time for refresh-tick / republish-*/
/* tick scheduling and for stamping bucket entries' last_seen_us. We use     */
/* CLOCK_MONOTONIC because we only compare deltas and never want negative   */
/* jumps from NTP resync. Falls back to CLOCK_REALTIME only if the          */
/* monotonic clock genuinely isn't available — POSIX requires it on every   */
/* platform we support, so the fallback is paranoia for unusual builds.    */
/* ------------------------------------------------------------------------ */

uint64_t dht_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            return 0;
        }
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* ------------------------------------------------------------------------ */
/* Storage layout                                                           */
/*                                                                          */
/* struct ants_dht_state, ants_dht_bucket, ants_dht_pending_rpc all live in */
/* dht_internal.h so dht_rpc.c can share them. Only the size-check assert  */
/* against the public ANTS_DHT_CTX_SIZE stays here.                        */
/* ------------------------------------------------------------------------ */

typedef char ants_dht_state_size_check
    [(sizeof(struct ants_dht_state) <= sizeof(((ants_dht_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* XOR distance + bucket index                                              */
/* ------------------------------------------------------------------------ */

/* Write the 32-byte XOR of two peer IDs into out_dist. The XOR is then
 * compared lexicographically to order peers by Kademlia distance. */
static void xor_distance(const uint8_t a[ANTS_PEER_ID_SIZE],
                         const uint8_t b[ANTS_PEER_ID_SIZE],
                         uint8_t out_dist[ANTS_PEER_ID_SIZE])
{
    for (size_t i = 0; i < ANTS_PEER_ID_SIZE; i++) {
        out_dist[i] = a[i] ^ b[i];
    }
}

/* Bucket index for a peer relative to our local id. Returns 0..255
 * (0 = closest neighbours, 255 = farthest), or UINT32_MAX when XOR is
 * all-zero (peer == self — never insert into table). */
static uint32_t bucket_index_for_peer(const struct ants_dht_state *state,
                                      const ants_peer_id_t *peer_id)
{
    uint8_t dist[ANTS_PEER_ID_SIZE];
    xor_distance(state->local_peer_id.bytes, peer_id->bytes, dist);

    /* Find the position of the most-significant set bit in `dist`,
     * interpreting byte 0 as the high-order byte (big-endian). The
     * bucket index is that bit position (0 = lowest bit, 255 = highest). */
    for (size_t i = 0; i < ANTS_PEER_ID_SIZE; i++) {
        uint8_t b = dist[i];
        if (b == 0) {
            continue;
        }
        /* Within this byte, find the MSB index (0..7 from low to high). */
        uint32_t hi_bit_in_byte = 7;
        while ((b & (uint8_t)(1u << hi_bit_in_byte)) == 0 && hi_bit_in_byte > 0) {
            hi_bit_in_byte--;
        }
        /* byte i contributes bits at positions (255 - i*8 - 7) .. (255 - i*8).
         * So the global bit index is: (255 - i*8 - 7) + hi_bit_in_byte. */
        return (uint32_t)((ANTS_PEER_ID_SIZE - 1 - i) * 8) + hi_bit_in_byte;
    }
    return UINT32_MAX;
}

/* ------------------------------------------------------------------------ */
/* K-bucket operations                                                      */
/* ------------------------------------------------------------------------ */

/* Insert (or refresh) a peer in the appropriate bucket. Returns:
 *   ANTS_OK              — inserted or refreshed
 *   ANTS_ERROR_INVALID_ARG  — peer == self (XOR distance is zero)
 *   ANTS_ERROR_BUFFER_TOO_SMALL — bucket full and peer not already present
 *   ANTS_ERROR_MALFORMED — malloc failed
 *
 * Pre-existing entries are moved to the head (most-recently-seen) and
 * their last_seen_us is bumped to `now_us`. The `conn` parameter may be
 * NULL ("known peer, not dialed yet"); a non-NULL conn on a refresh
 * updates the entry in-place — this is how phase 6 bootstrap "promotes"
 * a peer from known-only to known-and-dialed without re-inserting. */
static ants_error_t kbucket_insert(struct ants_dht_state *state,
                                   const ants_dht_peer_t *peer,
                                   ants_transport_conn_t *conn,
                                   uint64_t now_us)
{
    uint32_t bidx = bucket_index_for_peer(state, &peer->peer_id);
    if (bidx == UINT32_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_bucket *bucket = &state->buckets[bidx];

    /* Check for an existing entry (move-to-head). */
    struct ants_dht_bucket_entry **link = &bucket->head;
    while (*link != NULL) {
        if (memcmp((*link)->peer.peer_id.bytes, peer->peer_id.bytes, ANTS_PEER_ID_SIZE) == 0) {
            struct ants_dht_bucket_entry *hit = *link;
            *link = hit->next; /* unlink */
            /* Update multiaddr in case the peer moved. */
            memcpy(hit->peer.multiaddr, peer->multiaddr, sizeof hit->peer.multiaddr);
            /* Only overwrite conn if the caller supplied one. Refreshing
             * a known-and-dialed peer with conn=NULL should NOT downgrade
             * it to "known-only" — the conn is still valid. */
            if (conn != NULL) {
                hit->conn = conn;
            }
            hit->last_seen_us = now_us;
            hit->next = bucket->head;
            bucket->head = hit;
            return ANTS_OK;
        }
        link = &(*link)->next;
    }

    /* Not present. Check capacity. */
    if (bucket->count >= ANTS_DHT_K) {
        /* Phase 6 will implement LRU-eviction-on-PING. For now, reject. */
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    struct ants_dht_bucket_entry *node = (struct ants_dht_bucket_entry *)malloc(sizeof *node);
    if (node == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    memset(node, 0, sizeof *node);
    node->peer = *peer;
    node->conn = conn;
    node->last_seen_us = now_us;
    node->next = bucket->head;
    bucket->head = node;
    bucket->count++;
    return ANTS_OK;
}

/* Remove a peer by ID. Returns ANTS_OK on removal, ANTS_ERROR_NOT_IMPLEMENTED
 * if the peer wasn't present (caller treats that as "no-op success" — we use
 * NOT_IMPLEMENTED here only because we don't have a distinct "not found"
 * error code). */
static ants_error_t kbucket_remove(struct ants_dht_state *state, const ants_peer_id_t *peer_id)
{
    uint32_t bidx = bucket_index_for_peer(state, peer_id);
    if (bidx == UINT32_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_bucket *bucket = &state->buckets[bidx];
    struct ants_dht_bucket_entry **link = &bucket->head;
    while (*link != NULL) {
        if (memcmp((*link)->peer.peer_id.bytes, peer_id->bytes, ANTS_PEER_ID_SIZE) == 0) {
            struct ants_dht_bucket_entry *hit = *link;
            *link = hit->next;
            free(hit);
            bucket->count--;
            return ANTS_OK;
        }
        link = &(*link)->next;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED; /* not found */
}

/* Total count across all buckets. O(buckets) — 256 cheap loads. */
static size_t kbucket_total_count(const struct ants_dht_state *state)
{
    size_t total = 0;
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        total += state->buckets[i].count;
    }
    return total;
}

/* Walk all buckets, copying up to `cap` peers into `out_peers`. Returns
 * ANTS_ERROR_BUFFER_TOO_SMALL with *out_count = total available when
 * cap is too small. */
static ants_error_t kbucket_enumerate(const struct ants_dht_state *state,
                                      ants_dht_peer_t *out_peers,
                                      size_t cap,
                                      size_t *out_count)
{
    size_t total = kbucket_total_count(state);
    *out_count = total;
    if (cap < total) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    size_t written = 0;
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (const struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL;
             e = e->next) {
            out_peers[written++] = e->peer;
        }
    }
    return ANTS_OK;
}

/* Free all heap-allocated bucket entries. Called from ants_dht_destroy. */
static void kbucket_drop_all(struct ants_dht_state *state)
{
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        struct ants_dht_bucket_entry *e = state->buckets[i].head;
        while (e != NULL) {
            struct ants_dht_bucket_entry *next = e->next;
            free(e);
            e = next;
        }
        state->buckets[i].head = NULL;
        state->buckets[i].count = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* Refresh tick — periodic PING + dead-strike eviction                      */
/*                                                                          */
/* Every refresh_interval_ms/4 we walk the routing table; any entry whose   */
/* last_seen_us is older than refresh_interval_ms (and isn't already        */
/* awaiting a PING response) gets a liveness PING. On PING_RESP the entry's */
/* dead_strikes resets to 0 and last_seen_us is bumped; on PING failure     */
/* dead_strikes increments. Three strikes (ANTS_DHT_DEAD_STRIKE_THRESHOLD)  */
/* evicts the entry and fires PEER_EVICTED.                                  */
/*                                                                          */
/* The completion context is heap-allocated because we can't keep a pointer */
/* to the bucket entry — it may be freed by destroy/remove between PING    */
/* issuance and response. The peer_id is the stable handle we re-resolve    */
/* on completion via bucket-index lookup.                                   */
/* ------------------------------------------------------------------------ */

struct refresh_ping_ctx {
    ants_dht_t *dht;
    ants_peer_id_t peer_id;
};

static struct ants_dht_bucket_entry *find_entry_by_peer_id(struct ants_dht_state *state,
                                                           const ants_peer_id_t *peer_id)
{
    uint32_t bidx = bucket_index_for_peer(state, peer_id);
    if (bidx == UINT32_MAX) {
        return NULL;
    }
    for (struct ants_dht_bucket_entry *e = state->buckets[bidx].head; e != NULL; e = e->next) {
        if (memcmp(e->peer.peer_id.bytes, peer_id->bytes, ANTS_PEER_ID_SIZE) == 0) {
            return e;
        }
    }
    return NULL;
}

/* Phase 6 replacement-cache helpers, defined after issue_refresh_ping
 * (which dht_bucket_full_admit calls). Forward-declared here because the
 * production insert path and the PING completion sit above them. */
static void dht_bucket_full_admit(ants_dht_t *dht,
                                  const ants_dht_peer_t *peer,
                                  ants_transport_conn_t *conn,
                                  uint32_t bidx);
static void dht_apply_ping_result(ants_dht_t *dht, const ants_peer_id_t *peer_id, bool ok);

/* Cross-module production insert path (declared in dht_internal.h): wraps
 * kbucket_insert and fires PEER_DISCOVERED when the peer is genuinely new.
 * The header has promised that event for bootstrap- and lookup-discovered
 * peers since phase 0; every production insert site routes through here so
 * the promise holds uniformly (test hooks stay raw — silent by design). */
ants_error_t dht_routing_upsert(ants_dht_t *dht,
                                const ants_dht_peer_t *peer,
                                ants_transport_conn_t *conn,
                                uint64_t now_us)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    bool was_present = find_entry_by_peer_id(state, &peer->peer_id) != NULL;
    ants_error_t err = kbucket_insert(state, peer, conn, now_us);
    if (err == ANTS_OK && !was_present && state->event_fn != NULL) {
        ants_dht_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = ANTS_DHT_EV_PEER_DISCOVERED;
        ev.peer = *peer;
        (void)state->event_fn(&ev, state->event_ctx);
    } else if (err == ANTS_ERROR_BUFFER_TOO_SMALL) {
        /* Phase 6: the bucket is full. Park the newcomer and probe the
         * least-recently-seen entry so a dead node can be replaced. The
         * peer is not in the active table yet, so the return stays
         * BUFFER_TOO_SMALL and PEER_DISCOVERED is deferred to promotion. */
        uint32_t bidx = bucket_index_for_peer(state, &peer->peer_id);
        if (bidx != UINT32_MAX) {
            dht_bucket_full_admit(dht, peer, conn, bidx);
        }
    }
    return err;
}

static void refresh_ping_completion(ants_error_t status, const void *resp, void *ctx)
{
    (void)resp;
    struct refresh_ping_ctx *rctx = (struct refresh_ping_ctx *)ctx;
    if (rctx == NULL) {
        return;
    }
    /* All strike/eviction bookkeeping lives in dht_apply_ping_result so the
     * full-bucket probe path (phase 6) and the periodic refresh sweep drive
     * exactly the same logic — and so tests can exercise it deterministically
     * without a live transport. */
    dht_apply_ping_result(rctx->dht, &rctx->peer_id, status == ANTS_OK);
    free(rctx);
}

/* Issue a liveness PING for one bucket entry. Caller already checked the
 * staleness condition; this function just marks the entry in-flight and
 * dispatches the RPC. On dispatch failure (e.g. registry full) the entry
 * stays "stale" — the next sweep will retry. */
static void issue_refresh_ping(ants_dht_t *dht, struct ants_dht_bucket_entry *entry)
{
    struct refresh_ping_ctx *rctx =
        (struct refresh_ping_ctx *)malloc(sizeof(struct refresh_ping_ctx));
    if (rctx == NULL) {
        return;
    }
    rctx->dht = dht;
    rctx->peer_id = entry->peer.peer_id;
    entry->ping_in_flight = true;
    ants_error_t err = ants_dht_rpc_send_ping(dht, entry->conn, refresh_ping_completion, rctx);
    if (err != ANTS_OK) {
        /* The RPC layer never fired our completion when it returns an
         * error from the send call (see dht_rpc.c arm_and_send), so we
         * own the ctx and must reclaim it. Clear in-flight too so the
         * next sweep can retry. */
        entry->ping_in_flight = false;
        free(rctx);
    }
}

/* ------------------------------------------------------------------------ */
/* Phase 6 — full-bucket replacement cache                                  */
/*                                                                          */
/* When a peer would land in a full bucket, dht_routing_upsert parks it     */
/* here (dht_bucket_full_admit) and probes the bucket's least-recently-seen */
/* reachable entry. If that entry later fails its liveness probe and is     */
/* evicted, dht_apply_ping_result promotes the parked peer into the freed   */
/* slot. A live entry keeps its place — that is Kademlia's eviction-        */
/* resistance, and the reason a parked peer is held rather than admitted    */
/* eagerly.                                                                 */
/* ------------------------------------------------------------------------ */

/* The entry in `bucket` that is least-recently-seen AND reachable (has a
 * live conn we can PING). Returns NULL if the bucket has no reachable
 * entry — an undialed (conn == NULL) entry cannot be liveness-probed, so
 * it is never picked. "Least-recently-seen" is by last_seen_us, not list
 * position: a successful refresh PING bumps last_seen_us without moving the
 * entry, so last_seen_us is the truthful recency signal. */
static struct ants_dht_bucket_entry *bucket_find_lru_conn_entry(struct ants_dht_bucket *bucket)
{
    struct ants_dht_bucket_entry *lru = NULL;
    for (struct ants_dht_bucket_entry *e = bucket->head; e != NULL; e = e->next) {
        if (e->conn == NULL) {
            continue;
        }
        if (lru == NULL || e->last_seen_us < lru->last_seen_us) {
            lru = e;
        }
    }
    return lru;
}

/* Park `peer` as the standing replacement for bucket `bidx`. One slot per
 * bucket (newest pending wins); if the bucket already has a parked peer it
 * is overwritten. If the global pool is exhausted the newcomer is dropped
 * silently — it will be re-offered by the next lookup/gossip that names it. */
static void dht_park_replacement(struct ants_dht_state *state,
                                 const ants_dht_peer_t *peer,
                                 ants_transport_conn_t *conn,
                                 uint32_t bidx)
{
    struct ants_dht_replacement *free_slot = NULL;
    for (size_t i = 0; i < ANTS_DHT_MAX_REPLACEMENTS; i++) {
        struct ants_dht_replacement *r = &state->replacements[i];
        if (r->in_use) {
            if (bucket_index_for_peer(state, &r->peer.peer_id) == bidx) {
                r->peer = *peer;
                r->conn = conn;
                return;
            }
        } else if (free_slot == NULL) {
            free_slot = r;
        }
    }
    if (free_slot == NULL) {
        return;
    }
    free_slot->in_use = true;
    free_slot->peer = *peer;
    free_slot->conn = conn;
}

/* Promote the peer parked for bucket `bidx` (if any) into the routing
 * table — called right after an entry in that bucket is evicted, so a slot
 * is free. Fires PEER_DISCOVERED for the promoted peer. At most one
 * promotion per freed slot. */
static void dht_promote_replacement(ants_dht_t *dht, uint32_t bidx)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    for (size_t i = 0; i < ANTS_DHT_MAX_REPLACEMENTS; i++) {
        struct ants_dht_replacement *r = &state->replacements[i];
        if (!r->in_use || bucket_index_for_peer(state, &r->peer.peer_id) != bidx) {
            continue;
        }
        ants_dht_peer_t peer = r->peer;
        ants_transport_conn_t *conn = r->conn;
        r->in_use = false;
        ants_error_t err = kbucket_insert(state, &peer, conn, dht_now_us());
        if (err == ANTS_OK && state->event_fn != NULL) {
            ants_dht_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = ANTS_DHT_EV_PEER_DISCOVERED;
            ev.peer = peer;
            (void)state->event_fn(&ev, state->event_ctx);
        }
        return;
    }
}

/* Full-bucket admit (phase 6): park the newcomer and ensure the bucket's
 * least-recently-seen reachable entry is being liveness-probed. If a probe
 * is already in flight for that entry, it suffices. */
static void dht_bucket_full_admit(ants_dht_t *dht,
                                  const ants_dht_peer_t *peer,
                                  ants_transport_conn_t *conn,
                                  uint32_t bidx)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    dht_park_replacement(state, peer, conn, bidx);
    struct ants_dht_bucket_entry *lru = bucket_find_lru_conn_entry(&state->buckets[bidx]);
    if (lru != NULL && !lru->ping_in_flight) {
        issue_refresh_ping(dht, lru);
    }
}

/* Apply the outcome of a liveness PING to its routing entry — shared by the
 * refresh sweep and (via the test hook) phase-6 tests. On success: reset
 * dead_strikes, bump last_seen_us. On failure: bump dead_strikes and, on
 * reaching the threshold, evict the entry (PEER_EVICTED) and promote any
 * peer parked for that bucket (PEER_DISCOVERED). A no-op if the entry was
 * already removed (e.g. by CONN_CLOSED) between PING issue and completion. */
static void dht_apply_ping_result(ants_dht_t *dht, const ants_peer_id_t *peer_id, bool ok)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    struct ants_dht_bucket_entry *entry = find_entry_by_peer_id(state, peer_id);
    if (entry == NULL) {
        return;
    }
    entry->ping_in_flight = false;
    if (ok) {
        entry->dead_strikes = 0;
        entry->last_seen_us = dht_now_us();
        return;
    }
    entry->dead_strikes++;
    if (entry->dead_strikes >= ANTS_DHT_DEAD_STRIKE_THRESHOLD) {
        uint32_t bidx = bucket_index_for_peer(state, peer_id);
        ants_dht_peer_t evicted = entry->peer;
        (void)kbucket_remove(state, peer_id);
        if (state->event_fn != NULL) {
            ants_dht_event_t ev;
            memset(&ev, 0, sizeof ev);
            ev.kind = ANTS_DHT_EV_PEER_EVICTED;
            ev.peer = evicted;
            (void)state->event_fn(&ev, state->event_ctx);
        }
        dht_promote_replacement(dht, bidx);
    }
}

/* Walk every bucket and PING any stale, conn-bearing, not-already-pending
 * entries. Runs on every tick; the bucket walk is cheap (~few thousand
 * pointer derefs even with a full table) and the `ping_in_flight` flag
 * prevents the same entry from being PINGed twice in the same RTT. Returns
 * true if the sweep ran (i.e. refresh is enabled), so the caller knows
 * whether to fire TABLE_REFRESHED. */
static bool refresh_tick(ants_dht_t *dht, uint64_t now_us)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    if (state->refresh_interval_ms == 0) {
        return false;
    }

    uint64_t stale_us = (uint64_t)state->refresh_interval_ms * 1000ULL;
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL; e = e->next) {
            if (e->conn == NULL || e->ping_in_flight) {
                continue;
            }
            /* last_seen_us of 0 means "never recorded a real time" — a
             * test hook may have inserted with now_us=0. Treat as stale
             * if any time has elapsed since init. */
            uint64_t since = (e->last_seen_us == 0) ? stale_us : (now_us - e->last_seen_us);
            if (since >= stale_us) {
                issue_refresh_ping(dht, e);
            }
        }
    }
    if (state->event_fn != NULL) {
        ants_dht_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = ANTS_DHT_EV_TABLE_REFRESHED;
        (void)state->event_fn(&ev, state->event_ctx);
    }
    return true;
}

/* ------------------------------------------------------------------------ */
/* Announce republish — propagate local announces to K-closest storers      */
/*                                                                          */
/* Phase 6 stored `ants_dht_announce(key)` only in local + self-server      */
/* sets. Phase 6.1.b adds the canonical Kademlia announce-propagation       */
/* chain: for every local announce due for republish (last_republished_at + */
/* announce_republish_ms <= now), walk the routing table for the K peers    */
/* closest (by XOR distance) to BLAKE3(shard_key_le); send GET_PEERS to     */
/* obtain a token; on token receipt send ANNOUNCE_PEER; on the first        */
/* ANNOUNCE_PEER_RESP of the cycle, fire ANNOUNCE_CONFIRMED.                */
/*                                                                          */
/* Failure at any link of the chain just frees the ctx — republish is       */
/* best-effort, the next cycle retries. Token is BLAKE3(server_secret ||    */
/* peer_id), stable across a server's lifetime in phase 6, so a smarter     */
/* future revision could cache it and skip GET_PEERS on subsequent cycles.  */
/* ------------------------------------------------------------------------ */

struct republish_chain_ctx {
    ants_dht_t *dht;
    ants_dht_shard_key_t shard_key;
    ants_transport_conn_t *target_conn;
    ants_peer_id_t target_peer_id;
};

static void mark_announce_confirmed(struct ants_dht_state *state, ants_dht_shard_key_t shard_key)
{
    for (size_t i = 0; i < ANTS_DHT_MAX_LOCAL_ANNOUNCES; i++) {
        if (state->local_announces[i].in_use && state->local_announces[i].shard_key == shard_key &&
            !state->local_announces[i].confirmed_this_cycle) {
            state->local_announces[i].confirmed_this_cycle = true;
            if (state->event_fn != NULL) {
                ants_dht_event_t ev;
                memset(&ev, 0, sizeof ev);
                ev.kind = ANTS_DHT_EV_ANNOUNCE_CONFIRMED;
                ev.shard_key = shard_key;
                (void)state->event_fn(&ev, state->event_ctx);
            }
            return;
        }
    }
}

static void republish_announce_completion(ants_error_t status, const void *resp, void *ctx)
{
    (void)resp;
    struct republish_chain_ctx *rctx = (struct republish_chain_ctx *)ctx;
    if (rctx == NULL) {
        return;
    }
    if (status == ANTS_OK) {
        struct ants_dht_state *state = (struct ants_dht_state *)(void *)rctx->dht->_opaque;
        mark_announce_confirmed(state, rctx->shard_key);
    }
    free(rctx);
}

static void republish_get_peers_completion(ants_error_t status, const void *resp, void *ctx)
{
    struct republish_chain_ctx *rctx = (struct republish_chain_ctx *)ctx;
    if (rctx == NULL) {
        return;
    }
    if (status != ANTS_OK || resp == NULL) {
        free(rctx);
        return;
    }
    const ants_dht_get_peers_resp_t *gp = (const ants_dht_get_peers_resp_t *)resp;
    /* The chain reuses the ctx across the GET_PEERS → ANNOUNCE_PEER hop;
     * if send_announce_peer rejects the call (returning non-OK), we own
     * the ctx and reclaim it ourselves. On success the completion will
     * free it. */
    ants_error_t err = ants_dht_rpc_send_announce_peer(rctx->dht,
                                                       rctx->target_conn,
                                                       rctx->shard_key,
                                                       gp->token,
                                                       republish_announce_completion,
                                                       rctx);
    if (err != ANTS_OK) {
        free(rctx);
    }
}

/* Find up to K bucket entries closest by XOR distance to `target` that
 * have a live conn (republish must reach an actual peer, NULL-conn
 * candidates are skipped — 6.1.c dial-promote will pick them up). Writes
 * pointers into out_entries; returns the count written. Walks all
 * buckets — same O(N) insertion-sort pattern as dht_server.c's
 * find_kclosest_peers, but filtering for conn != NULL. */
static size_t find_kclosest_conn_entries(struct ants_dht_state *state,
                                         const uint8_t target[ANTS_PEER_ID_SIZE],
                                         struct ants_dht_bucket_entry *out_entries[ANTS_DHT_K])
{
    uint8_t distances[ANTS_DHT_K][ANTS_PEER_ID_SIZE];
    size_t count = 0;
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL; e = e->next) {
            if (e->conn == NULL) {
                continue;
            }
            uint8_t dist[ANTS_PEER_ID_SIZE];
            xor_distance(target, e->peer.peer_id.bytes, dist);
            /* Insertion sort: find position, shift, insert. */
            size_t pos = count;
            for (size_t j = 0; j < count; j++) {
                if (memcmp(dist, distances[j], ANTS_PEER_ID_SIZE) < 0) {
                    pos = j;
                    break;
                }
            }
            if (pos == ANTS_DHT_K) {
                continue;
            }
            size_t end = count < ANTS_DHT_K ? count : ANTS_DHT_K - 1;
            for (size_t j = end; j > pos; j--) {
                out_entries[j] = out_entries[j - 1];
                memcpy(distances[j], distances[j - 1], ANTS_PEER_ID_SIZE);
            }
            out_entries[pos] = e;
            memcpy(distances[pos], dist, ANTS_PEER_ID_SIZE);
            if (count < ANTS_DHT_K) {
                count++;
            }
        }
    }
    return count;
}

/* Issue the GET_PEERS leg of the republish chain for one (shard, target)
 * pair. On success the chain transitions through GET_PEERS_RESP →
 * ANNOUNCE_PEER → ANNOUNCE_PEER_RESP via the completion handlers. */
static void issue_republish_for(ants_dht_t *dht,
                                ants_dht_shard_key_t shard_key,
                                struct ants_dht_bucket_entry *target)
{
    struct republish_chain_ctx *rctx =
        (struct republish_chain_ctx *)malloc(sizeof(struct republish_chain_ctx));
    if (rctx == NULL) {
        return;
    }
    rctx->dht = dht;
    rctx->shard_key = shard_key;
    rctx->target_conn = target->conn;
    rctx->target_peer_id = target->peer.peer_id;
    ants_error_t err = ants_dht_rpc_send_get_peers(
        dht, target->conn, shard_key, republish_get_peers_completion, rctx);
    if (err != ANTS_OK) {
        free(rctx);
    }
}

/* For every local announce whose republish interval has elapsed, walk
 * the routing table for the K closest live-conn peers to the shard's
 * peer-id target and kick off the GET_PEERS → ANNOUNCE_PEER chain. */
static void republish_tick(ants_dht_t *dht, uint64_t now_us)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    if (state->announce_republish_ms == 0) {
        return;
    }
    uint64_t republish_us = (uint64_t)state->announce_republish_ms * 1000ULL;
    for (size_t i = 0; i < ANTS_DHT_MAX_LOCAL_ANNOUNCES; i++) {
        struct ants_dht_local_announce *la = &state->local_announces[i];
        if (!la->in_use) {
            continue;
        }
        uint64_t since = (la->last_republished_at_us == 0) ? republish_us
                                                           : (now_us - la->last_republished_at_us);
        if (since < republish_us) {
            continue;
        }
        /* Mark the new cycle BEFORE issuing RPCs so a fast completion
         * doesn't observe stale state. */
        la->last_republished_at_us = now_us;
        la->confirmed_this_cycle = false;
        /* Project shard_key into peer-id space. Same projection the
         * lookup machinery uses (dht_lookup.c) and the server's
         * GET_PEERS fallback (dht_server.c). */
        uint8_t key_le[8];
        for (int j = 0; j < 8; j++) {
            key_le[j] = (uint8_t)((la->shard_key >> (j * 8)) & 0xFFu);
        }
        uint8_t target[ANTS_BLAKE3_HASH_SIZE];
        (void)ants_blake3_hash(key_le, sizeof key_le, target);
        struct ants_dht_bucket_entry *closest[ANTS_DHT_K];
        size_t n = find_kclosest_conn_entries(state, target, closest);
        for (size_t k = 0; k < n; k++) {
            issue_republish_for(dht, la->shard_key, closest[k]);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Per-lookup state size check                                              */
/*                                                                          */
/* The real layout lives in dht_internal.h (shared with dht_lookup.c). The */
/* size assertion here ensures it fits within the caller-visible           */
/* ANTS_DHT_LOOKUP_CTX_SIZE buffer.                                         */
/* ------------------------------------------------------------------------ */

typedef char ants_dht_lookup_state_size_check
    [(sizeof(struct ants_dht_lookup_state) <= sizeof(((ants_dht_lookup_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_init(ants_dht_t *dht, const ants_dht_config_t *config)
{
    if (dht == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* event_fn is required so the caller can observe DHT events. The
     * transport pointer is required so we have a substrate for RPCs. */
    if (config->transport == NULL || config->event_fn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(dht->_opaque, 0, sizeof dht->_opaque);
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    state->transport = config->transport;
    state->local_peer_id = config->local_peer_id;
    state->event_fn = config->event_fn;
    state->event_ctx = config->event_ctx;
    state->refresh_interval_ms = config->refresh_interval_ms;
    state->lookup_deadline_ms = config->lookup_deadline_ms;
    state->announce_republish_ms = config->announce_republish_ms;
    /* txid 0 is reserved as a sentinel; start handing out at 1. */
    state->next_txid = 1;
    /* server_secret = BLAKE3(local_peer_id). Phase 6 uses a fixed
     * value — phase 6.1+ will rotate it on a slow schedule. The
     * derivation makes the token deterministic per-peer so two ANTS
     * implementations running off the same local_peer_id will
     * accept each other's tokens (useful for hot-restart). */
    (void)ants_blake3_hash(state->local_peer_id.bytes, ANTS_PEER_ID_SIZE, state->server_secret);
    return ANTS_OK;
}

ants_error_t ants_dht_destroy(ants_dht_t *dht)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    /* Cancel every active lookup first so that the RPC drop_all below
     * doesn't fire completion handlers into stale lookup records — the
     * cancellation invalidates all completion records up-front, then
     * release_slot's call to the (still-registered) completion sees
     * valid=false and no-ops. */
    for (size_t i = 0; i < ANTS_DHT_MAX_ACTIVE_LOOKUPS; i++) {
        ants_dht_lookup_t *h = state->active_lookups[i];
        if (h != NULL) {
            (void)ants_dht_lookup_do_cancel(h);
        }
    }
    /* Reclaim every in-flight RPC's heap (stream + recv_buf), firing
     * each completion with PEER_UNREACHABLE so callers learn the RPC
     * was abandoned. Idempotent on a zeroed dht: pending[] is all
     * zero, the scan is a no-op. */
    ants_dht_rpc_drop_all(dht);
    /* Reclaim server-side inbound stream accumulators (recv_buf heap). */
    ants_dht_server_drop_all(dht);
    /* Free any heap-allocated bootstrap conn buffers. Free regardless
     * of `in_use` because handle_bootstrap_conn_closed marks entries
     * dead (in_use=false) without freeing — the leak window closes
     * here. The caller MUST have called ants_transport_destroy first
     * (otherwise picoquic may still hold references to these conns
     * and the upcoming transport_destroy will UAF). */
    for (size_t i = 0; i < ANTS_DHT_MAX_BOOTSTRAP_PEERS; i++) {
        if (state->bootstrap_entries[i].conn != NULL) {
            free(state->bootstrap_entries[i].conn);
            state->bootstrap_entries[i].conn = NULL;
            state->bootstrap_entries[i].in_use = false;
        }
    }
    /* Same lazy-free discipline for phase 6.1.c dial-promote heap conns. */
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_DIALS; i++) {
        if (state->pending_dials[i].conn != NULL) {
            free(state->pending_dials[i].conn);
            state->pending_dials[i].conn = NULL;
            state->pending_dials[i].in_use = false;
            state->pending_dials[i].promoted = false;
        }
    }
    /* Drop any heap-allocated bucket entries before zeroing the buffer.
     * Idempotent on a never-init'd (zeroed) dht: all bucket heads are
     * NULL, the loop is a no-op. */
    kbucket_drop_all(state);
    memset(dht->_opaque, 0, sizeof dht->_opaque);
    return ANTS_OK;
}

uint32_t ants_dht_tick(ants_dht_t *dht)
{
    if (dht == NULL) {
        return UINT32_MAX;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    /* Advance every active iterative lookup: issue more RPCs if alpha
     * isn't saturated, check for convergence, fire LOOKUP_COMPLETE on
     * any lookup that just converged. */
    (void)ants_dht_lookup_advance_all(dht);
    /* Phase 6.1: periodic liveness sweep + announce-republish chain. */
    uint64_t now_us = dht_now_us();
    (void)refresh_tick(dht, now_us);
    republish_tick(dht, now_us);
    /* Wake-delay hint = the smaller of refresh_interval_ms/4 and
     * announce_republish_ms/4 (or UINT32_MAX when both timers are off).
     * The caller may tick sooner when transport I/O arrives. */
    uint32_t wake = UINT32_MAX;
    if (state->refresh_interval_ms != 0) {
        wake = state->refresh_interval_ms / 4u;
    }
    if (state->announce_republish_ms != 0) {
        uint32_t rwake = state->announce_republish_ms / 4u;
        if (rwake < wake) {
            wake = rwake;
        }
    }
    return wake;
}

/* ------------------------------------------------------------------------ */
/* Bootstrap                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_dht_bootstrap(ants_dht_t *dht, const char *multiaddr, const ants_peer_id_t *expected_peer_id)
{
    if (dht == NULL || multiaddr == NULL || expected_peer_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;

    if (state->transport == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    size_t multiaddr_len = strlen(multiaddr);
    if (multiaddr_len == 0 || multiaddr_len >= ANTS_MULTIADDR_MAX_LEN) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Find a free bootstrap entry. */
    struct ants_dht_bootstrap_entry *be = NULL;
    for (size_t i = 0; i < ANTS_DHT_MAX_BOOTSTRAP_PEERS; i++) {
        if (!state->bootstrap_entries[i].in_use) {
            be = &state->bootstrap_entries[i];
            break;
        }
    }
    if (be == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Heap-allocate the conn so its address is stable across the
     * dial → CONN_READY callback chain. Freed on CONN_CLOSED or in
     * ants_dht_destroy. */
    ants_transport_conn_t *conn = (ants_transport_conn_t *)malloc(sizeof(ants_transport_conn_t));
    if (conn == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    memset(conn, 0, sizeof *conn);

    ants_error_t err = ants_transport_dial(state->transport, multiaddr, expected_peer_id, conn);
    if (err != ANTS_OK) {
        free(conn);
        return err;
    }

    be->in_use = true;
    be->owner = state;
    be->conn = conn;
    be->expected_peer_id = *expected_peer_id;
    be->promoted = false;
    memcpy(be->multiaddr, multiaddr, multiaddr_len);
    be->multiaddr[multiaddr_len] = '\0';
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Announcements                                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_announce(ants_dht_t *dht, ants_dht_shard_key_t shard_key)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;

    /* Idempotent: refresh if already in the set. */
    for (size_t i = 0; i < ANTS_DHT_MAX_LOCAL_ANNOUNCES; i++) {
        if (state->local_announces[i].in_use && state->local_announces[i].shard_key == shard_key) {
            return ANTS_OK;
        }
    }
    /* Insert. Slot may have been previously used (unannounce → reannounce
     * round-trip); zero the maintenance fields so the new announce gets
     * republished immediately on the next tick rather than inheriting
     * stale last_republished_at_us from the previous use. */
    for (size_t i = 0; i < ANTS_DHT_MAX_LOCAL_ANNOUNCES; i++) {
        if (!state->local_announces[i].in_use) {
            memset(&state->local_announces[i], 0, sizeof state->local_announces[i]);
            state->local_announces[i].in_use = true;
            state->local_announces[i].shard_key = shard_key;
            /* Also record ourselves in the server-side announce set so a
             * GET_PEERS query from a peer who routes us hits an actual
             * entry rather than the K-closest fallback. The self-entry's
             * multiaddr is what other peers will dial when they want to
             * deliver records to this shard — fill it from the
             * transport's local listen address so the publish-side dial
             * path can resolve "responsible peer" → "where to send the
             * stream". Inbound-announce-from-peers (handle_announce_peer)
             * still uses an empty multiaddr because the conn's observed
             * peer_addr is the connect source, not the peer's listen
             * address; that gap will need an in-protocol multiaddr
             * exchange to close. */
            ants_dht_peer_t self;
            memset(&self, 0, sizeof self);
            self.peer_id = state->local_peer_id;
            if (state->transport != NULL) {
                (void)ants_transport_local_addr(
                    state->transport, self.multiaddr, sizeof self.multiaddr);
            }
            (void)ants_dht_server_upsert_announce(state, shard_key, &self, dht_now_us());
            return ANTS_OK;
        }
    }
    return ANTS_ERROR_BUFFER_TOO_SMALL;
}

ants_error_t ants_dht_unannounce(ants_dht_t *dht, ants_dht_shard_key_t shard_key)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    /* Idempotent on absent key. */
    for (size_t i = 0; i < ANTS_DHT_MAX_LOCAL_ANNOUNCES; i++) {
        if (state->local_announces[i].in_use && state->local_announces[i].shard_key == shard_key) {
            state->local_announces[i].in_use = false;
        }
    }
    /* Drop the matching self-entry from the server-side announce set too. */
    for (size_t i = 0; i < ANTS_DHT_MAX_ANNOUNCES; i++) {
        if (state->announces[i].in_use && state->announces[i].shard_key == shard_key &&
            memcmp(state->announces[i].announcer.peer_id.bytes,
                   state->local_peer_id.bytes,
                   ANTS_PEER_ID_SIZE) == 0) {
            state->announces[i].in_use = false;
        }
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lookups                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_dht_lookup(ants_dht_t *dht, ants_dht_shard_key_t shard_key, ants_dht_lookup_t *out_lookup)
{
    if (dht == NULL || out_lookup == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ants_dht_lookup_start(dht, shard_key, out_lookup, false);
}

ants_error_t
ants_dht_probe(ants_dht_t *dht, ants_dht_shard_key_t random_key, ants_dht_lookup_t *out_probe)
{
    if (dht == NULL || out_probe == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ants_dht_lookup_start(dht, random_key, out_probe, true);
}

ants_error_t ants_dht_lookup_cancel(ants_dht_lookup_t *lookup)
{
    if (lookup == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ants_dht_lookup_do_cancel(lookup);
}

/* ------------------------------------------------------------------------ */
/* Routing-table introspection                                              */
/* ------------------------------------------------------------------------ */

size_t ants_dht_routing_table_size(const ants_dht_t *dht)
{
    if (dht == NULL) {
        return 0;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    return kbucket_total_count(state);
}

ants_error_t ants_dht_routing_table_enumerate(const ants_dht_t *dht,
                                              ants_dht_peer_t *out_peers,
                                              size_t cap,
                                              size_t *out_count)
{
    if (dht == NULL || out_count == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (out_peers == NULL && cap > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    return kbucket_enumerate(state, out_peers, cap, out_count);
}

/* Bucket-diverse sample: a round-robin sweep across all buckets, taking one
 * entry of each non-empty bucket per sweep (depth 0, then 1, ...) until n_out
 * is reached or the table is exhausted. Spreading one-per-bucket before taking
 * a second from any bucket maximises XOR distance-class diversity (RFC-0005
 * §"Anti-eclipse peer sampling", axis S1) — a fat bucket cannot dominate the
 * sample. Each peer occupies exactly one bucket, so the result has no
 * duplicates.
 *
 * `rotation` (axis S3) shifts WHICH cross-section of the table the sweep
 * returns: it rotates the bucket visit order (so a different region of the
 * keyspace fills the sample first when n_out < table size) and the
 * within-bucket start offset (so successive epochs draw different entries
 * from a fat bucket). At depth d a bucket of `count` entries contributes
 * entry (d + rotation mod count) mod count — a cyclic shift, so each depth
 * still takes a distinct entry and rotation 0 degenerates to the plain
 * head-order sweep (== axis S1 exactly). The rotation value is a plain
 * counter, not a secret: churn is the defence (a static eclipse must keep
 * re-winning the view), unpredictability is axis S2's job. */
static size_t kbucket_sample(const struct ants_dht_state *state,
                             uint64_t rotation,
                             ants_dht_peer_t *out,
                             size_t n_out)
{
    size_t written = 0;
    size_t depth = 0;
    int progress;

    do {
        progress = 0;
        for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT && written < n_out; i++) {
            size_t b = (size_t)((rotation + i) % ANTS_DHT_BUCKET_COUNT);
            const struct ants_dht_bucket *bucket = &state->buckets[b];
            if (depth >= bucket->count) {
                continue;
            }
            size_t idx = (depth + (size_t)(rotation % bucket->count)) % bucket->count;
            const struct ants_dht_bucket_entry *e = bucket->head;
            for (size_t k = 0; k < idx && e != NULL; k++) {
                e = e->next;
            }
            if (e != NULL) {
                out[written++] = e->peer;
                progress = 1;
            }
        }
        depth++;
    } while (progress && written < n_out);
    return written;
}

size_t ants_dht_sample_peers(const ants_dht_t *dht, ants_dht_peer_t *out_peers, size_t n_out)
{
    return ants_dht_sample_peers_rotated(dht, 0, out_peers, n_out);
}

size_t ants_dht_sample_peers_rotated(const ants_dht_t *dht,
                                     uint64_t rotation,
                                     ants_dht_peer_t *out_peers,
                                     size_t n_out)
{
    if (dht == NULL || out_peers == NULL || n_out == 0) {
        return 0;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    return kbucket_sample(state, rotation, out_peers, n_out);
}

/* ------------------------------------------------------------------------ */
/* Bootstrap event hooks                                                    */
/*                                                                          */
/* Promotion path: a bootstrap dial returns immediately, but the conn       */
/* isn't usable until CONN_READY fires. When it does, the event's peer_id  */
/* identifies the remote; if the conn matches a pending bootstrap entry,   */
/* we insert into the routing table and issue a self-FIND_NODE to seed     */
/* nearby buckets via the seed peer's view.                                 */
/* ------------------------------------------------------------------------ */

static void bootstrap_find_node_completion(ants_error_t status, const void *resp, void *ctx)
{
    (void)resp;
    /* The lookup machinery is the proper path for fold-peers-into-
     * routing-table; this RPC is just for seeding via the FIND_NODE_RESP
     * from the bootstrap peer's perspective. Phase 6 keeps it simple:
     * the response is observed but its peers aren't folded back. Phase 7
     * end-to-end test uses ants_dht_lookup for real discovery.
     *
     * A successful round-trip IS the join signal, though: the seed
     * answered a DHT RPC over the pinned connection. Surface it as
     * BOOTSTRAP_COMPLETE so the node can observe "joined via seed X"
     * rather than inferring it from the handshake alone. On failure
     * (conn dropped, RPC timeout) no event fires — the slot recycles
     * via CONN_CLOSED and the caller may bootstrap again. */
    struct ants_dht_bootstrap_entry *be = (struct ants_dht_bootstrap_entry *)ctx;
    if (status != ANTS_OK || be == NULL || be->owner == NULL) {
        return;
    }
    struct ants_dht_state *state = be->owner;
    if (state->event_fn != NULL) {
        ants_dht_event_t ev;
        memset(&ev, 0, sizeof ev);
        ev.kind = ANTS_DHT_EV_BOOTSTRAP_COMPLETE;
        ev.peer.peer_id = be->expected_peer_id;
        memcpy(ev.peer.multiaddr, be->multiaddr, sizeof ev.peer.multiaddr);
        (void)state->event_fn(&ev, state->event_ctx);
    }
}

static void handle_bootstrap_conn_ready(ants_dht_t *dht, const ants_transport_event_t *event)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    for (size_t i = 0; i < ANTS_DHT_MAX_BOOTSTRAP_PEERS; i++) {
        struct ants_dht_bootstrap_entry *be = &state->bootstrap_entries[i];
        if (!be->in_use || be->conn != event->conn || be->promoted) {
            continue;
        }
        /* Insert the bootstrap peer into the routing table with its
         * live conn. (Skip self silently — kbucket_insert checks.)
         * Fires PEER_DISCOVERED when new, per the event's contract. */
        ants_dht_peer_t peer;
        memset(&peer, 0, sizeof peer);
        peer.peer_id = event->peer_id;
        memcpy(peer.multiaddr, be->multiaddr, sizeof peer.multiaddr);
        (void)dht_routing_upsert(dht, &peer, be->conn, dht_now_us());
        be->promoted = true;

        /* Seed nearby buckets by issuing FIND_NODE on our own peer_id.
         * The entry rides along as completion ctx so the response can
         * fire BOOTSTRAP_COMPLETE; the entry outlives the RPC (it stays
         * in_use until CONN_CLOSED, and a closed conn fails the RPC
         * before the slot recycles). */
        (void)ants_dht_rpc_send_find_node(
            dht, be->conn, &state->local_peer_id, bootstrap_find_node_completion, be);
        break;
    }
}

static void handle_bootstrap_conn_closed(ants_dht_t *dht, const ants_transport_event_t *event)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    /* Mark the entry dead but DO NOT free(be->conn) yet — picoquic's
     * disconnect path keeps using the conn state for a few lines after
     * firing CONN_CLOSED (it nulls cs->cnx, etc.). We free the heap
     * buffer in ants_dht_destroy, after the transport has been fully
     * torn down. The leak window is exactly one destroy call. */
    for (size_t i = 0; i < ANTS_DHT_MAX_BOOTSTRAP_PEERS; i++) {
        struct ants_dht_bootstrap_entry *be = &state->bootstrap_entries[i];
        if (be->in_use && be->conn == event->conn) {
            be->in_use = false;
            be->promoted = false;
            /* be->conn stays non-NULL — destroy will free it. */
        }
    }
    /* Also clear any routing-table entry whose conn matches the closed
     * conn, so phase 5 lookups don't try to use a dead conn. */
    for (size_t i = 0; i < ANTS_DHT_BUCKET_COUNT; i++) {
        for (struct ants_dht_bucket_entry *e = state->buckets[i].head; e != NULL; e = e->next) {
            if (e->conn == event->conn) {
                e->conn = NULL;
            }
        }
    }
    /* Phase 6: drop any parked replacement reached through the closed conn.
     * The newcomer was worth holding only because we had a live link to it;
     * promoting it with a dead conn would seed the table with a stale entry. */
    for (size_t i = 0; i < ANTS_DHT_MAX_REPLACEMENTS; i++) {
        if (state->replacements[i].in_use && state->replacements[i].conn == event->conn) {
            state->replacements[i].in_use = false;
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Pending-dial (phase 6.1.c) event hooks                                   */
/*                                                                          */
/* When a lookup issues a lazy dial via try_dial_promote, the dial is       */
/* recorded in pending_dials[]. On CONN_READY for that conn: promote the    */
/* peer into the routing table (the dial work isn't lost when the lookup   */
/* completes) and flip every INFLIGHT_DIAL candidate awaiting this         */
/* peer_id back to UNQUERIED so lookup_advance issues GET_PEERS. On         */
/* CONN_CLOSED before CONN_READY: mark matching candidates FAILED.         */
/* ------------------------------------------------------------------------ */

static void handle_pending_dial_conn_ready(ants_dht_t *dht, const ants_transport_event_t *event)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_DIALS; i++) {
        struct ants_dht_pending_dial *pd = &state->pending_dials[i];
        if (!pd->in_use || pd->promoted || pd->conn != event->conn) {
            continue;
        }
        /* Verify the connecting peer is the one we expected. The
         * transport already enforces this for dial() with an expected
         * peer_id, but defence-in-depth costs nothing here. */
        if (memcmp(event->peer_id.bytes, pd->expected_peer_id.bytes, ANTS_PEER_ID_SIZE) != 0) {
            continue;
        }
        ants_dht_peer_t peer;
        memset(&peer, 0, sizeof peer);
        peer.peer_id = pd->expected_peer_id;
        memcpy(peer.multiaddr, pd->multiaddr, sizeof peer.multiaddr);
        (void)dht_routing_upsert(dht, &peer, pd->conn, dht_now_us());
        ants_dht_lookup_promote_dialed_peer(dht, &pd->expected_peer_id, pd->conn);
        pd->promoted = true;
        /* Slot stays in_use until destroy frees pd->conn — same lazy
         * lifetime model as bootstrap_entries[]. */
        break;
    }
}

static void handle_pending_dial_conn_closed(ants_dht_t *dht, const ants_transport_event_t *event)
{
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    for (size_t i = 0; i < ANTS_DHT_MAX_PENDING_DIALS; i++) {
        struct ants_dht_pending_dial *pd = &state->pending_dials[i];
        if (!pd->in_use || pd->conn != event->conn) {
            continue;
        }
        if (!pd->promoted) {
            /* Dial failed before CONN_READY: surface as candidate
             * FAILED to every awaiting lookup. */
            ants_dht_lookup_fail_dialing_candidates(dht, &pd->expected_peer_id);
        }
        pd->in_use = false;
        pd->promoted = false;
        /* pd->conn stays non-NULL — destroy will free it. Same
         * picoquic-lifetime concern as bootstrap_entries[]. */
    }
}

/* ------------------------------------------------------------------------ */
/* Transport event delegation                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_handle_transport_event(ants_dht_t *dht, const ants_transport_event_t *event)
{
    if (dht == NULL || event == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Bootstrap-specific hooks first so the conn/routing state is in
     * shape when the rpc / server dispatchers see the event. Pending-
     * dial hooks run next: they promote lookup-dialed peers into the
     * routing table and flip waiting candidates to UNQUERIED (or FAILED
     * on CONN_CLOSED before CONN_READY). */
    if (event->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        handle_bootstrap_conn_ready(dht, event);
        handle_pending_dial_conn_ready(dht, event);
    } else if (event->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        handle_bootstrap_conn_closed(dht, event);
        handle_pending_dial_conn_closed(dht, event);
    }
    /* Outbound RPC dispatch (responses for ants_dht_rpc_send_*). */
    (void)ants_dht_rpc_handle_event(dht, event);
    /* Server-side dispatch (inbound peer-initiated requests). */
    (void)ants_dht_server_handle_event(dht, event);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Internal test hooks                                                      */
/*                                                                          */
/* Production code never calls these — they bypass the lookup/bootstrap     */
/* state machines (which land in phases 5-6) and let phase 2-4 tests       */
/* exercise the lower-level primitives directly. Forward declarations      */
/* here silence -Wmissing-prototypes; tests pick them up via extern.       */
/*                                                                          */
/* Not in ants_dht.h so callers compiled against the public header don't    */
/* see them.                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_dht__test_insert_peer(ants_dht_t *dht, const ants_dht_peer_t *peer, uint64_t now_us);
ants_error_t ants_dht__test_insert_peer_with_conn(ants_dht_t *dht,
                                                  const ants_dht_peer_t *peer,
                                                  ants_transport_conn_t *conn,
                                                  uint64_t now_us);
ants_error_t ants_dht__test_remove_peer(ants_dht_t *dht, const ants_peer_id_t *peer_id);
uint32_t ants_dht__test_bucket_index(const ants_dht_t *dht, const ants_peer_id_t *peer_id);

/* Snapshot of an entry's maintenance fields. Used by refresh-tick tests
 * to verify last_seen_us / dead_strikes transitions without exposing the
 * internal struct layout. */
typedef struct {
    bool exists;
    uint64_t last_seen_us;
    uint8_t dead_strikes;
    bool ping_in_flight;
} ants_dht__test_entry_state_t;
void ants_dht__test_get_entry_state(const ants_dht_t *dht,
                                    const ants_peer_id_t *peer_id,
                                    ants_dht__test_entry_state_t *out);
uint64_t ants_dht__test_now_us(void);

ants_error_t ants_dht__test_send_ping(ants_dht_t *dht,
                                      ants_transport_conn_t *conn,
                                      ants_dht_rpc_completion_fn completion,
                                      void *ctx);
ants_error_t ants_dht__test_send_find_node(ants_dht_t *dht,
                                           ants_transport_conn_t *conn,
                                           const ants_peer_id_t *target,
                                           ants_dht_rpc_completion_fn completion,
                                           void *ctx);
ants_error_t ants_dht__test_send_get_peers(ants_dht_t *dht,
                                           ants_transport_conn_t *conn,
                                           ants_dht_shard_key_t key,
                                           ants_dht_rpc_completion_fn completion,
                                           void *ctx);
ants_error_t ants_dht__test_send_announce_peer(ants_dht_t *dht,
                                               ants_transport_conn_t *conn,
                                               ants_dht_shard_key_t key,
                                               const uint8_t token[ANTS_DHT_TOKEN_SIZE],
                                               ants_dht_rpc_completion_fn completion,
                                               void *ctx);

ants_error_t
ants_dht__test_insert_peer(ants_dht_t *dht, const ants_dht_peer_t *peer, uint64_t now_us)
{
    if (dht == NULL || peer == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    return kbucket_insert(state, peer, NULL, now_us);
}

ants_error_t ants_dht__test_insert_peer_with_conn(ants_dht_t *dht,
                                                  const ants_dht_peer_t *peer,
                                                  ants_transport_conn_t *conn,
                                                  uint64_t now_us)
{
    if (dht == NULL || peer == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    return kbucket_insert(state, peer, conn, now_us);
}

ants_error_t ants_dht__test_remove_peer(ants_dht_t *dht, const ants_peer_id_t *peer_id)
{
    if (dht == NULL || peer_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    return kbucket_remove(state, peer_id);
}

uint32_t ants_dht__test_bucket_index(const ants_dht_t *dht, const ants_peer_id_t *peer_id)
{
    if (dht == NULL || peer_id == NULL) {
        return UINT32_MAX;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    return bucket_index_for_peer(state, peer_id);
}

ants_error_t ants_dht__test_send_ping(ants_dht_t *dht,
                                      ants_transport_conn_t *conn,
                                      ants_dht_rpc_completion_fn completion,
                                      void *ctx)
{
    return ants_dht_rpc_send_ping(dht, conn, completion, ctx);
}

ants_error_t ants_dht__test_send_find_node(ants_dht_t *dht,
                                           ants_transport_conn_t *conn,
                                           const ants_peer_id_t *target,
                                           ants_dht_rpc_completion_fn completion,
                                           void *ctx)
{
    return ants_dht_rpc_send_find_node(dht, conn, target, completion, ctx);
}

ants_error_t ants_dht__test_send_get_peers(ants_dht_t *dht,
                                           ants_transport_conn_t *conn,
                                           ants_dht_shard_key_t key,
                                           ants_dht_rpc_completion_fn completion,
                                           void *ctx)
{
    return ants_dht_rpc_send_get_peers(dht, conn, key, completion, ctx);
}

ants_error_t ants_dht__test_send_announce_peer(ants_dht_t *dht,
                                               ants_transport_conn_t *conn,
                                               ants_dht_shard_key_t key,
                                               const uint8_t token[ANTS_DHT_TOKEN_SIZE],
                                               ants_dht_rpc_completion_fn completion,
                                               void *ctx)
{
    return ants_dht_rpc_send_announce_peer(dht, conn, key, token, completion, ctx);
}

size_t ants_dht__test_server_announce_count(const ants_dht_t *dht, ants_dht_shard_key_t shard_key);
size_t ants_dht__test_server_announce_count(const ants_dht_t *dht, ants_dht_shard_key_t shard_key)
{
    if (dht == NULL) {
        return 0;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    size_t n = 0;
    for (size_t i = 0; i < ANTS_DHT_MAX_ANNOUNCES; i++) {
        if (state->announces[i].in_use && state->announces[i].shard_key == shard_key) {
            n++;
        }
    }
    return n;
}

void ants_dht__test_get_entry_state(const ants_dht_t *dht,
                                    const ants_peer_id_t *peer_id,
                                    ants_dht__test_entry_state_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (dht == NULL || peer_id == NULL) {
        return;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    uint32_t bidx = bucket_index_for_peer(state, peer_id);
    if (bidx == UINT32_MAX) {
        return;
    }
    for (const struct ants_dht_bucket_entry *e = state->buckets[bidx].head; e != NULL;
         e = e->next) {
        if (memcmp(e->peer.peer_id.bytes, peer_id->bytes, ANTS_PEER_ID_SIZE) == 0) {
            out->exists = true;
            out->last_seen_us = e->last_seen_us;
            out->dead_strikes = e->dead_strikes;
            out->ping_in_flight = e->ping_in_flight;
            return;
        }
    }
}

uint64_t ants_dht__test_now_us(void)
{
    return dht_now_us();
}

/* Phase 6 test hooks. Drive the production insert path and the strike/
 * eviction/promotion machinery directly so the replacement-cache state
 * machine can be exercised deterministically without a live transport. */
ants_error_t ants_dht__test_routing_upsert(ants_dht_t *dht,
                                           const ants_dht_peer_t *peer,
                                           ants_transport_conn_t *conn,
                                           uint64_t now_us);
ants_error_t ants_dht__test_routing_upsert(ants_dht_t *dht,
                                           const ants_dht_peer_t *peer,
                                           ants_transport_conn_t *conn,
                                           uint64_t now_us)
{
    if (dht == NULL || peer == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return dht_routing_upsert(dht, peer, conn, now_us);
}

void ants_dht__test_apply_ping_result(ants_dht_t *dht, const ants_peer_id_t *peer_id, bool ok);
void ants_dht__test_apply_ping_result(ants_dht_t *dht, const ants_peer_id_t *peer_id, bool ok)
{
    if (dht == NULL || peer_id == NULL) {
        return;
    }
    dht_apply_ping_result(dht, peer_id, ok);
}

size_t ants_dht__test_replacement_count(const ants_dht_t *dht);
size_t ants_dht__test_replacement_count(const ants_dht_t *dht)
{
    if (dht == NULL) {
        return 0;
    }
    const struct ants_dht_state *state = (const struct ants_dht_state *)(const void *)dht->_opaque;
    size_t n = 0;
    for (size_t i = 0; i < ANTS_DHT_MAX_REPLACEMENTS; i++) {
        if (state->replacements[i].in_use) {
            n++;
        }
    }
    return n;
}
