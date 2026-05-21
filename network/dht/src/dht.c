/*
 * dht.c — Kademlia DHT (shard-key variant) stub.
 *
 * v1.0 scaffold: every function returns ANTS_ERROR_NOT_IMPLEMENTED
 * (or the documented safe default for observers). The API surface is
 * pinned in ants_dht.h so upstream components (cache/semantic,
 * reputation, anti-eclipse) can integrate against it immediately;
 * the real implementation against the k-bucket data structure, XOR-
 * distance routing, and CBOR-encoded RPCs lands in subsequent PRs.
 *
 * Implementation phases (planned, matching transport's progression):
 *   - Phase 1 (this PR): API surface stub, opaque-ctx size check,
 *     init/destroy lifecycle that just zeroes the buffer.
 *   - Phase 2: k-bucket data structure + XOR distance helpers.
 *   - Phase 3: Wire-message CBOR codec (PING, FIND_NODE, GET_PEERS,
 *     ANNOUNCE_PEER and their responses).
 *   - Phase 4: RPC dispatch over transport bidi streams.
 *   - Phase 5: Iterative lookup state machine.
 *   - Phase 6: Bootstrap + maintenance (refresh, republish).
 *   - Phase 7: Two-node integration test exchanging real lookups.
 */

#include "ants_dht.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* K-bucket data structures                                                 */
/*                                                                          */
/* Standard Kademlia layout:                                                */
/*   - 256 buckets, one per leading-bit-prefix length of XOR(local, peer);  */
/*   - Each bucket holds up to ANTS_DHT_K = 20 entries.                     */
/*   - Entries are heap-allocated linked-list nodes; the bucket head holds  */
/*     a pointer + a count for O(1) size queries.                           */
/*                                                                          */
/* Insertion policy (phase 2): if the peer is already present, refresh its  */
/* last_seen and move it to the most-recently-seen end of the bucket. If    */
/* the bucket is full, REJECT the new entry (BUFFER_TOO_SMALL). The LRU-    */
/* eviction-on-PING policy from the Kademlia paper lands in phase 6 once    */
/* we can issue PING RPCs over the transport.                                */
/* ------------------------------------------------------------------------ */

struct ants_dht_bucket_entry {
    ants_dht_peer_t peer;
    /* Monotonic timestamp (we use ants_transport_tick-cadence wall time
     * in microseconds via picoquic_current_time at the bridge, but the
     * unit's irrelevant for correctness — only relative ordering is). */
    uint64_t last_seen_us;
    struct ants_dht_bucket_entry *next;
};

struct ants_dht_bucket {
    /* Singly-linked list; head is the most-recently-seen entry. New
     * inserts go at head; on-touch (already-present) entries get moved
     * to head. Bucket-tail (LRU) is the eviction candidate. */
    struct ants_dht_bucket_entry *head;
    size_t count;
};

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* The public ants_dht_t is a uint8_t[32768] union; we cast it to this     */
/* internal struct. Phase 2 adds the bucket array (256 buckets × 16 bytes  */
/* per bucket head = ~4 KB); entries live on the heap.                     */
/* ------------------------------------------------------------------------ */

struct ants_dht_state {
    ants_transport_t *transport;
    ants_peer_id_t local_peer_id;
    ants_dht_event_fn event_fn;
    void *event_ctx;
    uint32_t refresh_interval_ms;
    uint32_t lookup_deadline_ms;
    uint32_t announce_republish_ms;
    /* Phase 2: 256-bucket routing table. Phase 5+ adds active-lookup
     * registry and announcement set. */
    struct ants_dht_bucket buckets[ANTS_DHT_BUCKET_COUNT];
};

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
 * their last_seen_us is bumped to `now_us`. */
static ants_error_t
kbucket_insert(struct ants_dht_state *state, const ants_dht_peer_t *peer, uint64_t now_us)
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
    node->peer = *peer;
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
/* Per-lookup state (phase 5 fills this in)                                 */
/* ------------------------------------------------------------------------ */

struct ants_dht_lookup_state {
    /* Placeholder — phase 5 adds: target shard_key, candidate set,
     * in-flight count, deadline, result peers. */
    int unused;
};

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
    return ANTS_OK;
}

ants_error_t ants_dht_destroy(ants_dht_t *dht)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    /* Drop any heap-allocated bucket entries before zeroing the buffer.
     * Idempotent on a never-init'd (zeroed) dht: all bucket heads are
     * NULL, the loop is a no-op. Phase 5+ will also reclaim active-
     * lookup state here. */
    kbucket_drop_all(state);
    memset(dht->_opaque, 0, sizeof dht->_opaque);
    return ANTS_OK;
}

uint32_t ants_dht_tick(ants_dht_t *dht)
{
    /* No state to drive in phase 1 — return "idle" so the caller's
     * poll loop doesn't busy-spin on us. */
    (void)dht;
    return UINT32_MAX;
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
    /* Phase 6 implements: ants_transport_dial + insert-on-handshake. */
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------------ */
/* Announcements                                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_announce(ants_dht_t *dht, ants_dht_shard_key_t shard_key)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    (void)shard_key;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_dht_unannounce(ants_dht_t *dht, ants_dht_shard_key_t shard_key)
{
    if (dht == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    (void)shard_key;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
    (void)shard_key;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_dht_lookup_cancel(ants_dht_lookup_t *lookup)
{
    if (lookup == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
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

/* ------------------------------------------------------------------------ */
/* Internal test hook                                                       */
/*                                                                          */
/* Production code never calls this — it inserts into the routing table     */
/* without dialing the peer or verifying liveness. Used by unit tests in    */
/* phase 2 to populate the table for k-bucket logic verification before     */
/* the bootstrap (phase 6) and lookup (phase 5) paths are wired.            */
/*                                                                          */
/* Not in ants_dht.h so callers compiled against the public header don't    */
/* see it; tests link directly against libants_dht.a via an extern decl.   */
/* Forward declarations here silence -Wmissing-prototypes without exposing  */
/* a separate internal header.                                              */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_dht__test_insert_peer(ants_dht_t *dht, const ants_dht_peer_t *peer, uint64_t now_us);
ants_error_t ants_dht__test_remove_peer(ants_dht_t *dht, const ants_peer_id_t *peer_id);
uint32_t ants_dht__test_bucket_index(const ants_dht_t *dht, const ants_peer_id_t *peer_id);

ants_error_t
ants_dht__test_insert_peer(ants_dht_t *dht, const ants_dht_peer_t *peer, uint64_t now_us)
{
    if (dht == NULL || peer == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_dht_state *state = (struct ants_dht_state *)(void *)dht->_opaque;
    return kbucket_insert(state, peer, now_us);
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
