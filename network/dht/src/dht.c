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
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* The public ants_dht_t is a uint8_t[32768] union; we cast it to this     */
/* internal struct. Phase-1 only stores the transport pointer and the      */
/* caller-supplied event callback so they can be retrieved by future      */
/* phases — no routing/lookup state yet.                                   */
/* ------------------------------------------------------------------------ */

struct ants_dht_state {
    ants_transport_t *transport;
    ants_peer_id_t local_peer_id;
    ants_dht_event_fn event_fn;
    void *event_ctx;
    uint32_t refresh_interval_ms;
    uint32_t lookup_deadline_ms;
    uint32_t announce_republish_ms;
    /* Phase 2+ extends with: k-bucket table, active-lookup registry,
     * announcement set, etc. */
};

typedef char ants_dht_state_size_check
    [(sizeof(struct ants_dht_state) <= sizeof(((ants_dht_t *)0)->_opaque)) ? 1 : -1];

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
    /* Phase 2+ will reclaim the heap-allocated routing-table entries
     * and active-lookup state here. Phase 1 just zeroes the buffer. */
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
    /* Phase 1: routing table is always empty. Safe default for observers
     * (per the same convention as ants_transport_peer_list returning 0). */
    (void)dht;
    return 0;
}

ants_error_t ants_dht_routing_table_enumerate(const ants_dht_t *dht,
                                              ants_dht_peer_t *out_peers,
                                              size_t cap,
                                              size_t *out_count)
{
    if (dht == NULL || out_count == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    (void)out_peers;
    (void)cap;
    *out_count = 0;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
