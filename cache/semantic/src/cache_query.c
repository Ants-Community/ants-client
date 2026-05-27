/*
 * cache_query.c — Component #10 step 7c: DHT-routed lookup.
 *
 * State machine that takes a query embedding + threshold + top_k +
 * hamming_radius and aggregates matches from the network's responsible
 * shard-holders. Mirrors cache_publish.c at the structural level:
 *
 *   LOOKUP   — waiting for ants_dht_lookup completion
 *   DELIVER  — dialing each peer in parallel, opening a bidi stream,
 *              sending the CBOR lookup_request with FIN, accumulating
 *              the peer's response on STREAM_READABLE, decoding on
 *              STREAM_FIN
 *   DONE     — completion callback fired with aggregated matches
 *              copied into the caller's buffers (exactly once)
 *
 * Per-slot status follows a small linear progression:
 *   EMPTY → DIALING → AWAITING_RESPONSE → RESPONDED
 *                  ↘ FAILED (on dial / handshake / stream / decode error)
 *
 * Memory ownership:
 *  - Per-slot conn (8 KiB heap each), stream (1 KiB heap), recv_buf
 *    (16 KiB lazy heap), decoded_matches (heap, count from response),
 *    decoded_embeddings (heap, count × 4 KiB) live for the query's
 *    lifetime; freed during _destroy. Caller MUST call _destroy AFTER
 *    transport_destroy (mirroring the publish convention and the
 *    bootstrap-conn-lifetime rule).
 *  - The caller's out_matches[i].entry.embedding fields point into the
 *    caller-owned out_embeddings buffer after aggregation (deep-copied).
 *    All other pointer fields (response, embedding_model, response_model,
 *    attestation) ALIAS into per-slot recv_buf bytes — they become
 *    invalid after _destroy. The header documents this lifetime contract.
 *
 * Status semantics on completion:
 *   ANTS_OK                     — ≥1 peer responded with a decodable
 *                                 response (matches may be zero — that's a
 *                                 legitimate miss-above-threshold result)
 *   ANTS_ERROR_PEER_UNREACHABLE — zero peers responded (all dial / stream /
 *                                 decode failures, or DHT returned empty)
 */

#include "ants_semantic_cache.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration of the shard-key entry point exposed by cache.c.
 * Same pattern as cache_publish.c — declared here (not in the public
 * header) to avoid pulling cache.c internals into the query module. */
ants_error_t ants_semantic_cache_shard_key(const float embedding[ANTS_EMBED_DIM],
                                           ants_semantic_cache_shard_key_t *out_key);

/* Magic ("SCQR" = Semantic Cache QueRy) lets us reject calls on a zeroed
 * or already-destroyed ctx without crashing. Same pattern as ANTS,
 * ANTC, ANSE, CNCS, SCPB, SCSV. */
#define ANTS_SEMANTIC_CACHE_QUERY_MAGIC 0x53435152u

/* Per-stream accumulator cap. Mirrors the cache server's inbound recv
 * cap; the largest legitimate response is HANDLE_LOOKUP_SERVER_CAP=15
 * matches × ~5 KiB ≈ 80 KiB. 96 KiB covers the upper envelope with
 * margin; oversized responses release the slot as FAILED. */
#define QUERY_RECV_CAP (96u * 1024u)

/* Max matches a single peer is allowed to return. Mirrors the cache.c
 * HANDLE_LOOKUP_SERVER_CAP constant; a response with more matches than
 * this is treated as a protocol violation and the slot fails. Kept as
 * a local constant rather than pulling cache.c internals into the
 * public header. */
#define QUERY_PEER_RESPONSE_CAP 15u

typedef enum {
    QUERY_PHASE_INVALID = 0,
    QUERY_PHASE_LOOKUP,
    QUERY_PHASE_DELIVER,
    QUERY_PHASE_DONE
} query_phase_t;

typedef enum {
    QUERY_SLOT_EMPTY = 0,
    QUERY_SLOT_DIALING,
    QUERY_SLOT_AWAITING_RESPONSE,
    QUERY_SLOT_RESPONDED,
    QUERY_SLOT_FAILED
} query_slot_status_t;

typedef struct {
    query_slot_status_t status;
    ants_dht_peer_t peer;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream;
    /* Raw response accumulator (CBOR bytes from the peer). Lazy-malloc'd
     * on first STREAM_READABLE; freed at _destroy (NOT on STREAM_FIN,
     * because the decoded matches' pointer fields alias into these
     * bytes). */
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
    /* Decoded matches + their decoded embeddings. Allocated on
     * STREAM_FIN once the response array size is known. Sized at most
     * QUERY_PEER_RESPONSE_CAP. */
    ants_semantic_cache_lookup_match_t *decoded_matches;
    float *decoded_embeddings;
    size_t n_decoded;
} query_slot_t;

struct query_state {
    uint32_t magic;
    uint32_t _pad;

    query_phase_t phase;

    ants_dht_t *dht;
    ants_transport_t *transport;

    /* Encoded lookup_request CBOR. Reused across all slots, freed at
     * _destroy. */
    uint8_t *request_cbor;
    size_t request_cbor_len;

    /* Query parameters (preserved across the state machine). */
    ants_semantic_cache_shard_key_t shard_key;
    uint32_t top_k;
    uint32_t fanout;

    /* DHT lookup handle (inline so the query carries its own state in
     * one allocation). */
    ants_dht_lookup_t lookup;
    bool lookup_active;

    /* Per-slot fan-out state. */
    query_slot_t slots[ANTS_SEMANTIC_CACHE_QUERY_MAX_FANOUT];
    uint32_t slot_count;
    uint32_t responded_count;
    uint32_t failed_count;

    /* Caller-owned aggregation buffers. */
    ants_semantic_cache_lookup_match_t *out_matches;
    float *out_embeddings;
    size_t cap_matches;

    /* Completion callback. */
    ants_semantic_cache_query_complete_fn_t complete_fn;
    void *complete_ctx;
    bool completion_fired;
};

typedef char ants_semantic_cache_query_state_size_check
    [(sizeof(struct query_state) <= sizeof(((ants_semantic_cache_query_t *)0)->_opaque)) ? 1 : -1];

static struct query_state *state_of(ants_semantic_cache_query_t *q)
{
    /* Double-cast via void* silences -Wcast-align: the _align field of
     * the union guarantees uint64_t alignment for the opaque buffer. */
    return (struct query_state *)(void *)q->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Per-slot teardown                                                        */
/* ------------------------------------------------------------------------ */

static void slot_release(query_slot_t *s, ants_transport_t *transport)
{
    if (s->stream) {
        (void)ants_transport_stream_close(s->stream);
        free(s->stream);
        s->stream = NULL;
    }
    if (s->conn) {
        if (transport) {
            (void)ants_transport_peer_disconnect(s->conn, 0);
        }
        free(s->conn);
        s->conn = NULL;
    }
    if (s->recv_buf) {
        free(s->recv_buf);
        s->recv_buf = NULL;
    }
    if (s->decoded_matches) {
        free(s->decoded_matches);
        s->decoded_matches = NULL;
    }
    if (s->decoded_embeddings) {
        free(s->decoded_embeddings);
        s->decoded_embeddings = NULL;
    }
    s->recv_len = 0;
    s->recv_cap = 0;
    s->n_decoded = 0;
}

/* ------------------------------------------------------------------------ */
/* Aggregation                                                              */
/* ------------------------------------------------------------------------ */

/* True iff (producer, prompt_hash) of A == B's. */
static bool entry_dup_key_equal(const ants_semantic_cache_entry_t *a,
                                const ants_semantic_cache_entry_t *b)
{
    return memcmp(a->producer, b->producer, ANTS_SEMANTIC_CACHE_PEER_ID_LEN) == 0 &&
           memcmp(a->prompt_hash, b->prompt_hash, ANTS_SEMANTIC_CACHE_PROMPT_HASH_LEN) == 0;
}

/* Aggregate every decoded match across all slots, dedup by
 * (producer, prompt_hash), sort desc by similarity, cap by min(top_k,
 * cap_matches), copy into caller buffers (deep-copy embedding floats; re-
 * point entry.embedding to caller-owned slot). Return the count written.
 *
 * O(N²) over the candidate set N ≤ MAX_FANOUT × QUERY_PEER_RESPONSE_CAP
 * = 8 × 15 = 120 — trivially fast, no need for a hash table. */
static size_t aggregate_matches(struct query_state *st)
{
    /* Step 1: collect pointers to every successfully-decoded match. */
    const ants_semantic_cache_lookup_match_t
        *candidates[ANTS_SEMANTIC_CACHE_QUERY_MAX_FANOUT * QUERY_PEER_RESPONSE_CAP];
    size_t n_candidates = 0;
    for (uint32_t i = 0; i < st->slot_count; i++) {
        query_slot_t *s = &st->slots[i];
        if (s->status != QUERY_SLOT_RESPONDED) {
            continue;
        }
        for (size_t j = 0; j < s->n_decoded; j++) {
            if (n_candidates >= sizeof candidates / sizeof candidates[0]) {
                /* Shouldn't happen given the per-peer cap, but stay
                 * defensive against a protocol-extension future. */
                break;
            }
            candidates[n_candidates++] = &s->decoded_matches[j];
        }
    }

    /* Step 2: dedup by (producer, prompt_hash). Keep the higher-
     * similarity occurrence; mark losers with NULL. */
    for (size_t i = 0; i < n_candidates; i++) {
        if (candidates[i] == NULL) {
            continue;
        }
        for (size_t j = i + 1; j < n_candidates; j++) {
            if (candidates[j] == NULL) {
                continue;
            }
            if (entry_dup_key_equal(&candidates[i]->entry, &candidates[j]->entry)) {
                if (candidates[j]->similarity > candidates[i]->similarity) {
                    candidates[i] = candidates[j];
                }
                candidates[j] = NULL;
            }
        }
    }

    /* Compact non-NULL entries to the front. */
    size_t n_unique = 0;
    for (size_t i = 0; i < n_candidates; i++) {
        if (candidates[i] != NULL) {
            candidates[n_unique++] = candidates[i];
        }
    }

    /* Step 3: insertion-sort desc by similarity. n_unique ≤ 120 — O(N²)
     * is fine. Insertion-sort is stable: equal similarities preserve
     * the slot-order which is acceptable (no further tie-break
     * specified by the protocol; producers earn similarity off the
     * embedding, not order). */
    for (size_t i = 1; i < n_unique; i++) {
        const ants_semantic_cache_lookup_match_t *cur = candidates[i];
        size_t j = i;
        while (j > 0 && candidates[j - 1]->similarity < cur->similarity) {
            candidates[j] = candidates[j - 1];
            j--;
        }
        candidates[j] = cur;
    }

    /* Step 4: cap. */
    size_t cap = st->cap_matches;
    if (st->top_k > 0 && st->top_k < cap) {
        cap = st->top_k;
    }
    size_t n_out = (n_unique < cap) ? n_unique : cap;

    /* Step 5: copy chosen matches into caller buffers. The non-
     * embedding pointer fields (response, embedding_model, response_
     * model, attestation) alias the slot recv_buf and stay valid until
     * _destroy. The embedding field is deep-copied into caller-owned
     * out_embeddings and re-pointed. */
    for (size_t i = 0; i < n_out; i++) {
        const ants_semantic_cache_lookup_match_t *src = candidates[i];
        st->out_matches[i] = *src;
        float *dst_emb = &st->out_embeddings[i * (size_t)ANTS_EMBED_DIM];
        memcpy(dst_emb, src->entry.embedding, (size_t)ANTS_EMBED_DIM * sizeof(float));
        st->out_matches[i].entry.embedding = dst_emb;
    }

    return n_out;
}

/* ------------------------------------------------------------------------ */
/* Completion                                                               */
/* ------------------------------------------------------------------------ */

static void maybe_complete(struct query_state *st)
{
    if (st->completion_fired) {
        return;
    }
    if (st->phase != QUERY_PHASE_DELIVER) {
        return;
    }
    if (st->responded_count + st->failed_count < st->slot_count) {
        return;
    }

    st->completion_fired = true;
    st->phase = QUERY_PHASE_DONE;

    ants_error_t status;
    size_t n_matches = 0;
    if (st->responded_count > 0) {
        status = ANTS_OK;
        n_matches = aggregate_matches(st);
    } else {
        status = ANTS_ERROR_PEER_UNREACHABLE;
    }

    if (st->complete_fn) {
        st->complete_fn(status, st->responded_count, n_matches, st->complete_ctx);
    }
}

/* ------------------------------------------------------------------------ */
/* Init                                                                     */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_query_init(ants_semantic_cache_query_t *query,
                                            ants_dht_t *dht,
                                            ants_transport_t *transport,
                                            const float embedding[ANTS_EMBED_DIM],
                                            float similarity_threshold,
                                            uint32_t top_k,
                                            uint32_t hamming_radius,
                                            uint32_t fanout,
                                            ants_semantic_cache_lookup_match_t *out_matches,
                                            float *out_embeddings,
                                            size_t cap_matches,
                                            ants_semantic_cache_query_complete_fn_t complete_fn,
                                            void *complete_ctx)
{
    if (!query || !dht || !transport || !embedding || !out_matches || !out_embeddings ||
        !complete_fn) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (cap_matches == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (hamming_radius > ANTS_SEMANTIC_CACHE_MAX_HAMMING_RADIUS) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (fanout == 0) {
        fanout = ANTS_SEMANTIC_CACHE_QUERY_DEFAULT_FANOUT;
    }
    if (fanout > ANTS_SEMANTIC_CACHE_QUERY_MAX_FANOUT) {
        return ANTS_ERROR_INVALID_ARG;
    }

    memset(query, 0, sizeof *query);
    struct query_state *st = state_of(query);

    /* Pre-encode the lookup_request once; reused verbatim per slot.
     * The request encoder also rejects probe-mode (NULL/0); use the
     * realloc-on-BUFFER_TOO_SMALL idiom shared with publish. The
     * request body is small (~4.1 KiB embedding + 32 B header), so a
     * 5 KiB initial cap covers it. */
    size_t cap = 5120;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        return ANTS_ERROR_MALFORMED;
    }
    size_t written = 0;
    ants_error_t err = ants_semantic_cache_lookup_request_encode(
        embedding, similarity_threshold, top_k, hamming_radius, buf, cap, &written);
    if (err == ANTS_ERROR_BUFFER_TOO_SMALL) {
        uint8_t *bigger = realloc(buf, written);
        if (!bigger) {
            free(buf);
            return ANTS_ERROR_MALFORMED;
        }
        buf = bigger;
        cap = written;
        err = ants_semantic_cache_lookup_request_encode(
            embedding, similarity_threshold, top_k, hamming_radius, buf, cap, &written);
    }
    if (err != ANTS_OK) {
        free(buf);
        return err;
    }

    /* Compute the shard_key from the query embedding. */
    ants_semantic_cache_shard_key_t shard_key = 0;
    err = ants_semantic_cache_shard_key(embedding, &shard_key);
    if (err != ANTS_OK) {
        free(buf);
        return err;
    }

    st->magic = ANTS_SEMANTIC_CACHE_QUERY_MAGIC;
    st->phase = QUERY_PHASE_LOOKUP;
    st->dht = dht;
    st->transport = transport;
    st->request_cbor = buf;
    st->request_cbor_len = written;
    st->shard_key = shard_key;
    st->top_k = top_k;
    st->fanout = fanout;
    st->out_matches = out_matches;
    st->out_embeddings = out_embeddings;
    st->cap_matches = cap_matches;
    st->complete_fn = complete_fn;
    st->complete_ctx = complete_ctx;

    /* Issue the lookup. Failure cleans up the heap request buffer. */
    err = ants_dht_lookup(dht, shard_key, &st->lookup);
    if (err != ANTS_OK) {
        free(buf);
        memset(query, 0, sizeof *query);
        return err;
    }
    st->lookup_active = true;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Tick (drives dial requests after LOOKUP)                                 */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_query_tick(ants_semantic_cache_query_t *query)
{
    if (!query) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct query_state *st = state_of(query);
    if (st->magic != ANTS_SEMANTIC_CACHE_QUERY_MAGIC) {
        return ANTS_OK;
    }
    if (st->phase != QUERY_PHASE_DELIVER) {
        return ANTS_OK;
    }

    for (uint32_t i = 0; i < st->slot_count; i++) {
        query_slot_t *s = &st->slots[i];
        if (s->status != QUERY_SLOT_EMPTY) {
            continue;
        }

        ants_transport_conn_t *conn = malloc(sizeof *conn);
        if (!conn) {
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            continue;
        }
        memset(conn, 0, sizeof *conn);

        ants_error_t err =
            ants_transport_dial(st->transport, s->peer.multiaddr, &s->peer.peer_id, conn);
        if (err != ANTS_OK) {
            free(conn);
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            continue;
        }
        s->conn = conn;
        s->status = QUERY_SLOT_DIALING;
    }

    maybe_complete(st);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* DHT event handler                                                        */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_query_handle_dht_event(ants_semantic_cache_query_t *query,
                                                        const ants_dht_event_t *event)
{
    if (!query || !event) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct query_state *st = state_of(query);
    if (st->magic != ANTS_SEMANTIC_CACHE_QUERY_MAGIC) {
        return ANTS_OK;
    }
    if (event->kind != ANTS_DHT_EV_LOOKUP_COMPLETE && event->kind != ANTS_DHT_EV_LOOKUP_TIMEOUT) {
        return ANTS_OK;
    }
    if (event->lookup != &st->lookup) {
        return ANTS_OK;
    }
    if (!st->lookup_active) {
        return ANTS_OK;
    }
    st->lookup_active = false;

    if (st->phase != QUERY_PHASE_LOOKUP) {
        return ANTS_OK;
    }

    /* Populate slots from the DHT result, capped at fanout. */
    uint32_t n_avail = (uint32_t)event->peer_count;
    if (n_avail > st->fanout) {
        n_avail = st->fanout;
    }
    for (uint32_t i = 0; i < n_avail; i++) {
        st->slots[i].status = QUERY_SLOT_EMPTY;
        st->slots[i].peer = event->peers[i];
    }
    st->slot_count = n_avail;
    st->phase = QUERY_PHASE_DELIVER;

    /* Empty lookup result → complete immediately as PEER_UNREACHABLE. */
    maybe_complete(st);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Per-slot lookup helpers                                                  */
/* ------------------------------------------------------------------------ */

static int find_slot_by_conn(struct query_state *st, const ants_transport_conn_t *conn)
{
    if (!conn) {
        return -1;
    }
    for (uint32_t i = 0; i < st->slot_count; i++) {
        if (st->slots[i].conn == conn) {
            return (int)i;
        }
    }
    return -1;
}

static int find_slot_by_stream(struct query_state *st, const ants_transport_stream_t *stream)
{
    if (!stream) {
        return -1;
    }
    for (uint32_t i = 0; i < st->slot_count; i++) {
        if (st->slots[i].stream == stream) {
            return (int)i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------------ */
/* Response decode (on STREAM_FIN)                                          */
/* ------------------------------------------------------------------------ */

/* Decode the slot's accumulated recv_buf into decoded_matches +
 * decoded_embeddings. Slot transitions to RESPONDED on success,
 * FAILED on any decode error or excess match count. */
static void decode_slot_response(struct query_state *st, query_slot_t *s)
{
    if (s->recv_buf == NULL || s->recv_len == 0) {
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }

    /* Probe: cap_matches=0 with NULL buffers returns BUFFER_TOO_SMALL
     * with *out_n set to the wire's actual match count (or ANTS_OK if
     * the response carries zero matches). */
    size_t n_in_response = 0;
    ants_error_t err = ants_semantic_cache_lookup_response_decode(
        s->recv_buf, s->recv_len, NULL, NULL, 0, &n_in_response);
    if (err != ANTS_OK && err != ANTS_ERROR_BUFFER_TOO_SMALL) {
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }

    if (n_in_response > QUERY_PEER_RESPONSE_CAP) {
        /* Protocol violation — peer returned more than the server cap.
         * Treat as a failed slot; future protocol expansion can raise
         * the local cap. */
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }

    if (n_in_response == 0) {
        /* Legitimate empty response — the peer found no matches above
         * threshold. Mark the slot as RESPONDED (counts toward the
         * "we got a real answer" bucket) with zero decoded entries. */
        s->n_decoded = 0;
        s->status = QUERY_SLOT_RESPONDED;
        st->responded_count++;
        return;
    }

    /* Allocate per-slot decoded arrays sized to the actual response. */
    ants_semantic_cache_lookup_match_t *matches = malloc(n_in_response * sizeof *matches);
    if (!matches) {
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }
    float *embeddings = malloc(n_in_response * (size_t)ANTS_EMBED_DIM * sizeof(float));
    if (!embeddings) {
        free(matches);
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }

    size_t n_decoded = 0;
    err = ants_semantic_cache_lookup_response_decode(
        s->recv_buf, s->recv_len, matches, embeddings, n_in_response, &n_decoded);
    if (err != ANTS_OK || n_decoded != n_in_response) {
        free(matches);
        free(embeddings);
        s->status = QUERY_SLOT_FAILED;
        st->failed_count++;
        return;
    }

    s->decoded_matches = matches;
    s->decoded_embeddings = embeddings;
    s->n_decoded = n_decoded;
    s->status = QUERY_SLOT_RESPONDED;
    st->responded_count++;
}

/* ------------------------------------------------------------------------ */
/* Transport event handler                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_query_handle_transport_event(ants_semantic_cache_query_t *query,
                                                              const ants_transport_event_t *event)
{
    if (!query || !event) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct query_state *st = state_of(query);
    if (st->magic != ANTS_SEMANTIC_CACHE_QUERY_MAGIC) {
        return ANTS_OK;
    }
    if (st->phase != QUERY_PHASE_DELIVER) {
        return ANTS_OK;
    }

    int idx = find_slot_by_conn(st, event->conn);
    if (idx < 0) {
        idx = find_slot_by_stream(st, event->stream);
    }
    if (idx < 0) {
        return ANTS_OK;
    }
    query_slot_t *s = &st->slots[idx];

    switch (event->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY: {
        if (s->status != QUERY_SLOT_DIALING) {
            break;
        }
        ants_transport_stream_t *stream = malloc(sizeof *stream);
        if (!stream) {
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            break;
        }
        memset(stream, 0, sizeof *stream);

        ants_error_t err = ants_transport_open_bidi_stream(s->conn, stream);
        if (err != ANTS_OK) {
            free(stream);
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            break;
        }
        s->stream = stream;

        err = ants_transport_stream_send(stream, st->request_cbor, st->request_cbor_len, true);
        if (err != ANTS_OK) {
            (void)ants_transport_stream_close(stream);
            free(stream);
            s->stream = NULL;
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            break;
        }
        s->status = QUERY_SLOT_AWAITING_RESPONSE;
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_READABLE: {
        if (s->status != QUERY_SLOT_AWAITING_RESPONSE) {
            break;
        }
        if (event->payload == NULL || event->payload_len == 0) {
            break;
        }
        if (s->recv_buf == NULL) {
            s->recv_buf = malloc(QUERY_RECV_CAP);
            if (!s->recv_buf) {
                s->status = QUERY_SLOT_FAILED;
                st->failed_count++;
                break;
            }
            s->recv_cap = QUERY_RECV_CAP;
            s->recv_len = 0;
        }
        if (event->payload_len > s->recv_cap - s->recv_len) {
            /* Oversized response — release as FAILED. */
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
            break;
        }
        memcpy(s->recv_buf + s->recv_len, event->payload, event->payload_len);
        s->recv_len += event->payload_len;
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_FIN: {
        if (s->status != QUERY_SLOT_AWAITING_RESPONSE) {
            break;
        }
        decode_slot_response(st, s);
        break;
    }

    case ANTS_TRANSPORT_EV_STREAM_RESET: {
        if (s->status != QUERY_SLOT_RESPONDED && s->status != QUERY_SLOT_FAILED) {
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
        }
        break;
    }

    case ANTS_TRANSPORT_EV_CONN_CLOSED: {
        if (s->status != QUERY_SLOT_RESPONDED && s->status != QUERY_SLOT_FAILED) {
            s->status = QUERY_SLOT_FAILED;
            st->failed_count++;
        }
        /* The conn is gone server-side. Free the stream + conn heap
         * (same convention as publish: the transport's CONN_CLOSED
         * always fires before our buffer becomes unreachable
         * internally). Decoded heap + recv_buf survive into _destroy
         * because the caller's aggregated out_matches alias into
         * recv_buf and we must not invalidate them mid-flight. */
        if (s->stream) {
            (void)ants_transport_stream_close(s->stream);
            free(s->stream);
            s->stream = NULL;
        }
        if (s->conn) {
            free(s->conn);
            s->conn = NULL;
        }
        break;
    }

    default:
        break;
    }

    maybe_complete(st);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Destroy                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_semantic_cache_query_destroy(ants_semantic_cache_query_t *query)
{
    if (!query) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct query_state *st = state_of(query);
    if (st->magic != ANTS_SEMANTIC_CACHE_QUERY_MAGIC) {
        memset(query, 0, sizeof *query);
        return ANTS_OK;
    }

    if (st->lookup_active) {
        (void)ants_dht_lookup_cancel(&st->lookup);
        st->lookup_active = false;
    }

    for (uint32_t i = 0; i < st->slot_count; i++) {
        slot_release(&st->slots[i], st->transport);
    }

    if (st->request_cbor) {
        free(st->request_cbor);
        st->request_cbor = NULL;
    }

    memset(query, 0, sizeof *query);
    return ANTS_OK;
}
