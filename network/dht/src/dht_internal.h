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

/* Monotonic wall-clock-ish time source, microseconds. Defined in dht.c;
 * shared across the DHT translation units so anywhere we stamp a
 * last_seen_us / last_republished_at_us / last_announced_us value uses
 * the same clock. */
uint64_t dht_now_us(void);

/* Insert (or refresh) a peer in the routing table — the cross-module
 * production insert path (bootstrap promotion, pending-dial promotion,
 * probe fold). Wraps kbucket_insert and fires ANTS_DHT_EV_PEER_DISCOVERED
 * through the registered event_fn when the peer is genuinely new (NOT on
 * refresh of an existing entry, and never for a self-insert).
 *
 * Phase 6: a full bucket no longer drops the peer. It is parked in the
 * replacement cache and the least-recently-seen entry is probed; the
 * call still returns ANTS_ERROR_BUFFER_TOO_SMALL (the peer is not in the
 * active table yet) and PEER_DISCOVERED is deferred until the peer is
 * actually promoted into a freed slot. Defined in dht.c. */
ants_error_t dht_routing_upsert(ants_dht_t *dht,
                                const ants_dht_peer_t *peer,
                                ants_transport_conn_t *conn,
                                uint64_t now_us);

/* ------------------------------------------------------------------------ */
/* K-bucket entry + bucket head                                             */
/*                                                                          */
/* Standard Kademlia layout: 256 buckets, one per leading-bit-prefix length */
/* of XOR(local, peer); each bucket holds up to ANTS_DHT_K = 20 entries     */
/* in a singly-linked list with MRU at head.                                */
/* ------------------------------------------------------------------------ */

struct ants_dht_bucket_entry {
    ants_dht_peer_t peer;
    /* Transport connection to this peer, if known. NULL means the peer
     * is known (we have its peer_id + multiaddr) but we haven't dialled
     * it yet — phase 5 lookups skip these; phase 6 maintenance lazily
     * dials them and updates the conn pointer in-place. */
    ants_transport_conn_t *conn;
    /* Wall-clock-ish time (us, CLOCK_MONOTONIC) the entry was last
     * observed responsive — bumped on insert/refresh and on every
     * successful liveness PING. Drives refresh-tick eligibility. */
    uint64_t last_seen_us;
    /* Consecutive failed liveness PINGs since the last success. Reset to
     * 0 on PING_RESP; incremented on PING failure (STREAM_RESET,
     * PEER_UNREACHABLE, decode error). On reaching
     * ANTS_DHT_DEAD_STRIKE_THRESHOLD the entry is evicted. */
    uint8_t dead_strikes;
    /* True between issuing a refresh PING and observing its completion.
     * Suppresses issuing a second PING for the same entry while one is
     * in flight (which would waste an RPC slot and double-count strikes
     * on failure). */
    bool ping_in_flight;
    /* Pad to align `next` on an 8-byte boundary on 64-bit platforms.
     * Explicit to keep the struct layout predictable for review. */
    uint8_t _pad[6];
    struct ants_dht_bucket_entry *next;
};

struct ants_dht_bucket {
    struct ants_dht_bucket_entry *head;
    size_t count;
};

/* ------------------------------------------------------------------------ */
/* Replacement cache (phase 6 — full-bucket LRU eviction)                   */
/*                                                                          */
/* Kademlia / BEP-5 behaviour: when a peer would be inserted into a full    */
/* bucket, it is parked here instead of being dropped, and the bucket's     */
/* least-recently-seen reachable entry is liveness-probed. If that entry    */
/* later fails its probe (dead-strike threshold) and is evicted, the freed  */
/* slot is filled from this cache and PEER_DISCOVERED fires for the parked  */
/* peer. A live least-recently-seen entry keeps its slot — long-lived peers */
/* resist eviction, which is the property that makes Kademlia routing       */
/* tables hard to poison.                                                   */
/*                                                                          */
/* One standing replacement per bucket (newest pending wins); a global pool */
/* of ANTS_DHT_MAX_REPLACEMENTS slots bounds the total. The pool is small   */
/* because only the few buckets near the local id ever fill. The parked     */
/* conn is borrowed (owned by bootstrap_entries[] / pending_dials[]); a     */
/* parked replacement whose conn closes is dropped in CONN_CLOSED. A richer */
/* multi-entry-per-bucket cache is a phase 6.1+ refinement.                 */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_REPLACEMENTS 8

struct ants_dht_replacement {
    bool in_use;
    uint8_t _pad[7];
    /* Borrowed connection to the parked peer (NOT owned here). */
    ants_transport_conn_t *conn;
    ants_dht_peer_t peer;
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
/* Iterative-lookup state                                                   */
/*                                                                          */
/* Cast over ants_dht_lookup_t::_opaque. One lookup runs the standard      */
/* Kademlia iterative GET_PEERS loop: starting from a seed set drawn from  */
/* the routing table (conn-bearing entries only), it issues α RPCs at a   */
/* time toward the closest unqueried candidates; each response feeds new   */
/* peers back into the candidate set, sorted ascending by XOR distance    */
/* from the target. Convergence is "no more queryable candidates" (every  */
/* known candidate is ANSWERED or FAILED); a LOOKUP_COMPLETE event fires  */
/* with the K closest answered peers.                                     */
/* ------------------------------------------------------------------------ */

/* Maximum candidates the lookup tracks (sorted by ascending XOR distance
 * from target). Sized so the whole lookup_state fits in the 16 KB
 * ANTS_DHT_LOOKUP_CTX_SIZE budget. Each candidate carries the full
 * ants_dht_peer_t (~288 B incl. multiaddr) plus distance + state. */
#define ANTS_DHT_LOOKUP_CANDIDATE_CAP 40

/* Concurrent in-flight RPCs per lookup. Mirrors ANTS_DHT_ALPHA — the
 * Kademlia paper's parallelism parameter. */
#define ANTS_DHT_LOOKUP_INFLIGHT_CAP ANTS_DHT_ALPHA

/* Per-candidate state in the iterative lookup. */
typedef enum {
    ANTS_DHT_LOOKUP_CAND_UNQUERIED = 0,    /* In candidate set, not yet queried. */
    ANTS_DHT_LOOKUP_CAND_INFLIGHT = 1,     /* GET_PEERS sent, awaiting response. */
    ANTS_DHT_LOOKUP_CAND_ANSWERED = 2,     /* Response received and processed. */
    ANTS_DHT_LOOKUP_CAND_FAILED = 3,       /* RPC failed (no conn / RPC error). */
    ANTS_DHT_LOOKUP_CAND_INFLIGHT_DIAL = 4 /* Lazy dial in flight, awaiting CONN_READY. */
} ants_dht_lookup_cand_state_t;

struct ants_dht_lookup_candidate {
    ants_dht_peer_t peer;
    /* Transport connection to this peer. NULL → caller (via the routing
     * table) doesn't have a conn yet; the candidate is kept (visible to
     * upper layers) but FAILED at the first query attempt. Phase 6 will
     * lazily promote NULL-conn candidates by dialing them. */
    ants_transport_conn_t *conn;
    /* Pre-computed XOR(target_peer_id, peer.peer_id). Compare lexicographically
     * (big-endian) to determine ordering. */
    uint8_t distance[ANTS_PEER_ID_SIZE];
    uint8_t state; /* ants_dht_lookup_cand_state_t */
    uint8_t _pad[7];
};

/* Per-in-flight RPC: the completion handler points at one of these
 * records. valid=false means the lookup has been cancelled / completed
 * and the late-firing completion should no-op. The DHT's pending_rpc
 * slot still gets reclaimed in either case (release_slot runs before
 * the completion fires). */
struct ants_dht_lookup_completion_record {
    bool valid;
    uint8_t _pad[7];
    ants_dht_lookup_t *lookup_handle;
    uint32_t candidate_idx;
    uint32_t _pad2;
};

struct ants_dht_lookup_state {
    /* Slot occupancy. true between ants_dht_lookup and either
     * LOOKUP_COMPLETE / LOOKUP_TIMEOUT firing or ants_dht_lookup_cancel
     * returning. */
    bool in_use;
    /* true once a LOOKUP_COMPLETE / LOOKUP_TIMEOUT event has fired (so
     * late completions don't fire it again). */
    bool completed;
    /* Probe mode (anti-eclipse axis S2, ants_dht_probe): on convergence
     * the ANSWERED candidates are folded into the routing table and a
     * TABLE_REFRESHED event fires instead of LOOKUP_COMPLETE — the
     * result set of a random-target lookup is maintenance, not an
     * answer, and must not reach shard-lookup consumers. */
    bool is_probe;
    uint8_t _pad[5];
    ants_dht_t *parent;
    ants_dht_shard_key_t target_key;
    /* BLAKE3(target_key_le_bytes) — the target in peer-id space. The DHT
     * routes by full 256-bit XOR; the shard-key projection lives here. */
    uint8_t target_peer_id[ANTS_PEER_ID_SIZE];
    /* Candidate set, sorted ascending by `distance`. */
    struct ants_dht_lookup_candidate candidates[ANTS_DHT_LOOKUP_CANDIDATE_CAP];
    size_t candidate_count;
    /* Number of candidates currently in INFLIGHT state. */
    size_t inflight_count;
    /* Completion records — one slot per concurrent in-flight RPC. */
    struct ants_dht_lookup_completion_record inflight_recs[ANTS_DHT_LOOKUP_INFLIGHT_CAP];
};

/* Maximum concurrent active lookups per DHT. Increase if upper layers
 * (cache/embedding doing Hamming-N near-neighbour expansion) need it. */
#define ANTS_DHT_MAX_ACTIVE_LOOKUPS 8

/* ------------------------------------------------------------------------ */
/* Server-side inbound-stream tracking                                      */
/*                                                                          */
/* For each peer-initiated bidi stream that delivers a DHT request, we      */
/* accumulate bytes here until STREAM_FIN — same accumulator pattern as     */
/* the outbound pending_rpc but indexed by inbound stream pointer. The     */
/* response is written back on the same stream + FIN; the slot is then     */
/* freed.                                                                   */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_INBOUND_STREAMS 32
#define ANTS_DHT_INBOUND_RECV_CAP    4096

struct ants_dht_inbound_stream {
    bool in_use;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream;
    /* Peer identity, captured from the STREAM_OPENED event's peer_id
     * field. Needed by GET_PEERS_RESP token derivation and by
     * ANNOUNCE_PEER's announcer-binding. */
    ants_peer_id_t peer_id;
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
};

/* ------------------------------------------------------------------------ */
/* Announce set                                                             */
/*                                                                          */
/* Records of peers that announced (via ANNOUNCE_PEER RPC) they host a      */
/* particular shard. GET_PEERS responses serve this set when asked about    */
/* a shard we have announces for; otherwise they fall back to the K-       */
/* closest peers from our routing table.                                    */
/*                                                                          */
/* Phase 6 keeps storage simple and bounded — no expiry timer; the array   */
/* is reused round-robin once full. Maintenance (phase 6.1+) will add      */
/* expiry by last_seen + republish.                                        */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_ANNOUNCES 32

struct ants_dht_announce {
    bool in_use;
    ants_dht_shard_key_t shard_key;
    ants_dht_peer_t announcer;
    uint64_t last_seen_us;
};

/* ------------------------------------------------------------------------ */
/* Bootstrap registry                                                       */
/*                                                                          */
/* Tracks dials initiated by ants_dht_bootstrap so the event-delegation    */
/* path knows to promote those peers into the routing table on CONN_READY  */
/* and to free the heap-allocated conn buffer on CONN_CLOSED / destroy.   */
/* ------------------------------------------------------------------------ */

/* Capacity lives in ants_dht.h (ANTS_DHT_MAX_BOOTSTRAP_PEERS) — it is
 * part of the public bootstrap contract so callers can size seed lists
 * against it. */

struct ants_dht_state;

struct ants_dht_bootstrap_entry {
    bool in_use;
    /* Back-pointer to the owning dht state, so the self-FIND_NODE
     * completion (which receives this entry as its ctx) can fire
     * BOOTSTRAP_COMPLETE through the state's event_fn. */
    struct ants_dht_state *owner;
    /* Heap-allocated by ants_dht_bootstrap so it outlives the call stack.
     * Freed on CONN_CLOSED (transport guarantees no further callbacks
     * once it fires) or on dht_destroy if still open. */
    ants_transport_conn_t *conn;
    ants_peer_id_t expected_peer_id;
    /* Has the handshake completed and the peer been inserted into the
     * routing table? Set to true on CONN_READY. */
    bool promoted;
    char multiaddr[ANTS_MULTIADDR_MAX_LEN];
};

/* ------------------------------------------------------------------------ */
/* Local announces (shards we host)                                         */
/*                                                                          */
/* Phase 6 records the shard keys we've asked the network to remember us   */
/* for, via ants_dht_announce. The active-republish loop in phase 6.1+    */
/* will scan this set and re-emit ANNOUNCE_PEER RPCs. For now it's just a  */
/* membership set so ants_dht_unannounce works.                            */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_LOCAL_ANNOUNCES 16

/* ------------------------------------------------------------------------ */
/* Pending dials (phase 6.1.c dial-promote)                                 */
/*                                                                          */
/* When a lookup encounters a closer-than-current candidate that has a      */
/* known multiaddr but no live conn yet, it issues a lazy dial via the      */
/* transport and tracks it here until either CONN_READY (promote the conn   */
/* into the routing table, flip matching candidates to UNQUERIED) or        */
/* CONN_CLOSED (mark matching candidates FAILED). Cap is small because      */
/* concurrent lookups α=3 each; in practice we'll have at most a handful   */
/* of dial-promotes in flight at once.                                      */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_PENDING_DIALS 16

struct ants_dht_pending_dial {
    bool in_use;
    /* True once CONN_READY promoted the conn into the routing table.
     * The slot stays in_use until destroy frees the heap conn; this
     * flag stops a subsequent CONN_CLOSED from re-promoting (it has
     * already been folded into routing). */
    bool promoted;
    uint8_t _pad[6];
    /* Heap-allocated by issue_rpc_for_candidate so its address is
     * stable across the dial → CONN_READY callback chain. Freed on
     * CONN_CLOSED or in ants_dht_destroy (same lifetime model as
     * bootstrap_entries[]). */
    ants_transport_conn_t *conn;
    ants_peer_id_t expected_peer_id;
    char multiaddr[ANTS_MULTIADDR_MAX_LEN];
};

struct ants_dht_local_announce {
    bool in_use;
    /* True once we've fired ANNOUNCE_CONFIRMED for the current cycle
     * (i.e. at least one storer ACKed). Reset to false at the start of
     * every new republish cycle so each cycle produces at most one
     * event regardless of how many K-closest storers ACK. */
    bool confirmed_this_cycle;
    uint8_t _pad[6];
    ants_dht_shard_key_t shard_key;
    /* Wall-clock-ish time (us) the current cycle's chain was kicked
     * off. 0 = never republished — next tick will republish immediately.
     * The next cycle starts once now_us - last_republished_at_us
     * exceeds announce_republish_ms. */
    uint64_t last_republished_at_us;
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
    /* Full-bucket replacement cache (phase 6). Peers that would land in a
     * full bucket are parked here and promoted when an entry is evicted. */
    struct ants_dht_replacement replacements[ANTS_DHT_MAX_REPLACEMENTS];
    /* In-flight RPC registry. Scanned linearly on every transport
     * event (O(64)) — overhead negligible vs. CBOR decode cost. */
    struct ants_dht_pending_rpc pending[ANTS_DHT_MAX_PENDING_RPCS];
    /* Active-lookup back-pointers. Each entry points to a caller-
     * allocated ants_dht_lookup_t, registered by ants_dht_lookup and
     * cleared by ants_dht_lookup_cancel or LOOKUP_COMPLETE / TIMEOUT. */
    ants_dht_lookup_t *active_lookups[ANTS_DHT_MAX_ACTIVE_LOOKUPS];
    /* Server-side: inbound stream accumulators (peer-initiated requests). */
    struct ants_dht_inbound_stream inbound_streams[ANTS_DHT_MAX_INBOUND_STREAMS];
    /* Server-side: announce records (peer X hosts shard Y). */
    struct ants_dht_announce announces[ANTS_DHT_MAX_ANNOUNCES];
    /* Bootstrap dials in progress / completed. */
    struct ants_dht_bootstrap_entry bootstrap_entries[ANTS_DHT_MAX_BOOTSTRAP_PEERS];
    /* Lookup-initiated dials in progress / promoted. Same heap-conn
     * lifetime as bootstrap_entries[]: freed in destroy. */
    struct ants_dht_pending_dial pending_dials[ANTS_DHT_MAX_PENDING_DIALS];
    /* Local-host announce set (shards we've announced via ants_dht_announce). */
    struct ants_dht_local_announce local_announces[ANTS_DHT_MAX_LOCAL_ANNOUNCES];
    /* Server secret for GET_PEERS_RESP token derivation. Initialised by
     * ants_dht_init to a deterministic-but-unpredictable value (we use
     * BLAKE3(local_peer_id) — sufficient for phase 6's no-rotation token
     * scheme; phase 6.1+ will rotate every few epochs). */
    uint8_t server_secret[32];
};

#endif /* ANTS_DHT_INTERNAL_H */
