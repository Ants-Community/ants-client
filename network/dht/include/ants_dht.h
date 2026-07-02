/*
 * ants_dht.h — Kademlia DHT, shard-key variant (Component #5).
 *
 * Provides peer-rendezvous over the P2P transport. Sits below
 * cache/semantic (which uses shard-key lookups to find peers hosting
 * an embedding's region) and above network/transport (which provides
 * the QUIC streams that DHT RPC messages travel on).
 *
 * Spec references:
 *   - RFC-0002 §DHT routing — the shard-key model (64-bit LSH
 *     projection), responsible-peer selection, near-neighbour expansion.
 *   - RFC-0010 §First peer's flow — bootstrap with GenesisState's
 *     bootstrap_dht_seeds.
 *   - RFC-0008 §DHT wire formats — message schemas (CBOR-encoded
 *     over bidi streams). Drafted in parallel with this header's
 *     implementation phases.
 *
 * Implementation strategy:
 *
 *   - Standard Kademlia (BitTorrent mainline DHT family) over peer-id
 *     keyspace. Peer IDs are 32-byte Ed25519 pubkeys (RFC-0010); XOR
 *     distance is computed over the full 256-bit pubkey.
 *
 *   - Shard-key lookups use the "announce + find peers" pattern from
 *     BitTorrent DHT: peers hosting a shard ANNOUNCE that fact at the
 *     K closest nodes (by XOR distance) to the shard-key's expansion
 *     into the peer-id keyspace. Lookups perform iterative FIND_NODE
 *     toward the expansion, then GET_PEERS at the converged closest
 *     nodes. Near-neighbour expansion (Hamming-1/2 around the target
 *     shard-key) is performed by the caller; the DHT layer just
 *     resolves one shard-key per lookup.
 *
 *   - Shard-key → peer-id expansion: BLAKE3(shard_key_le_bytes) gives
 *     a 32-byte routing target deterministically. Two peers computing
 *     the expansion of the same shard-key arrive at the same target.
 *
 *   - Routing table: standard 256-bucket k-bucket layout (one per
 *     bit-prefix length), K = ANTS_DHT_K replicas per bucket.
 *
 *   - RPC discipline: one DHT RPC per bidi stream. Request and
 *     response are length-prefixed CBOR objects. Stream lifetime
 *     equals one round-trip — no reuse, no multiplexing beyond what
 *     QUIC already provides at the connection level.
 *
 * API model: non-blocking, caller-driven. Mirrors the transport API:
 * caller invokes ants_dht_tick() periodically; events surface through
 * a single registered callback. The library spawns no threads, does
 * no logging, and the public API surface allocates no memory beyond
 * what the caller hands in (heap is used internally for k-bucket
 * entries and active-lookup state, same pattern as transport's
 * inbound-conn bootstrap).
 */

#ifndef ANTS_DHT_H
#define ANTS_DHT_H

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Kademlia parameters                                                      */
/*                                                                          */
/* These are protocol constants visible cross-network. Changing them is a   */
/* compat break. Values follow BitTorrent mainline conventions (K=20,       */
/* alpha=3) which have a decade of empirical robustness data behind them.   */
/* ------------------------------------------------------------------------ */

/* Replication factor: each routing-table bucket holds up to K peers, and
 * each shard announcement is replicated at the K closest peers to the
 * shard-key expansion. */
#define ANTS_DHT_K 20

/* Lookup parallelism: at most this many in-flight RPCs per iterative
 * FIND_NODE/GET_PEERS lookup. Higher α reduces tail latency but bursts
 * the network. 3 is the Kademlia paper's recommendation. */
#define ANTS_DHT_ALPHA 3

/* Routing-table bucket count. One bucket per leading-bit-prefix length
 * of the XOR distance, so for 256-bit peer IDs we have 256 buckets. */
#define ANTS_DHT_BUCKET_COUNT 256

/* Number of consecutive failed liveness PINGs after which a routing-table
 * entry is evicted. Each refresh sweep that PINGs the entry and gets no
 * (or a failed) response increments dead_strikes; on a successful PING it
 * resets to zero. Three strikes is the BitTorrent mainline convention. */
#define ANTS_DHT_DEAD_STRIKE_THRESHOLD 3

/* Concurrently-pending bootstrap capacity: at most this many
 * ants_dht_bootstrap dials can be outstanding at once (a slot frees when
 * its connection closes). Callers sizing a seed list against this bound
 * — e.g. a node config — should validate against it rather than discover
 * ANTS_ERROR_BUFFER_TOO_SMALL at runtime. */
#define ANTS_DHT_MAX_BOOTSTRAP_PEERS 8

/* ------------------------------------------------------------------------ */
/* Shard-key type                                                           */
/*                                                                          */
/* Per RFC-0002 §DHT routing: 64-bit identifier derived from an embedding   */
/* via LSH (sign of projection onto 64 pseudorandom hyperplanes). The DHT   */
/* layer treats it as an opaque 64-bit handle; the LSH machinery lives in   */
/* cache/embedding.                                                          */
/* ------------------------------------------------------------------------ */

typedef uint64_t ants_dht_shard_key_t;

/* ------------------------------------------------------------------------ */
/* Opaque context types                                                     */
/*                                                                          */
/* Caller allocates. Sizes are oversized so internal layout changes don't   */
/* break ABI for downstream components compiled against this header. The    */
/* .c file enforces actual bounds via the compile-time-assertion idiom      */
/* (typedef char ..._size_check[(cond) ? 1 : -1]).                         */
/* ------------------------------------------------------------------------ */

/* Top-level DHT state. Holds the routing table, the active-lookups
 * registry, the announcements set, and a back-pointer to the transport.
 * Sized for ~5000 routing-table entries plus active lookup state. */
#define ANTS_DHT_CTX_SIZE 32768

/* Per-lookup state. Tracks the iterative-search candidate set (up to
 * 2K peers carrying full peer_id + multiaddr per entry), in-flight
 * queries, and the converged result set. Larger than the original
 * 8 KB estimate because each candidate carries the full ants_dht_peer_t
 * (32 B peer_id + 256 B multiaddr) for downstream consumers. */
#define ANTS_DHT_LOOKUP_CTX_SIZE 16384

typedef union {
    uint8_t _opaque[ANTS_DHT_CTX_SIZE];
    uint64_t _align;
} ants_dht_t;

typedef union {
    uint8_t _opaque[ANTS_DHT_LOOKUP_CTX_SIZE];
    uint64_t _align;
} ants_dht_lookup_t;

/* ------------------------------------------------------------------------ */
/* Peer descriptor                                                          */
/*                                                                          */
/* What a DHT lookup actually returns: the peer's identity (pubkey) plus    */
/* the network address(es) we know about. Caller dials these via the       */
/* transport layer.                                                          */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Ed25519 peer identity. Cross-layer canonical handle. */
    ants_peer_id_t peer_id;

    /* Textual multiaddr the peer last announced. ANTS_MULTIADDR_MAX_LEN
     * is the buffer size; the string is NUL-terminated within. */
    char multiaddr[ANTS_MULTIADDR_MAX_LEN];
} ants_dht_peer_t;

/* ------------------------------------------------------------------------ */
/* Event model                                                              */
/*                                                                          */
/* The DHT surfaces I/O events through a single registered callback. As     */
/* with transport, the callback runs synchronously from ants_dht_tick(),   */
/* never from a separate thread. The callback may freely call back into    */
/* ants_dht_* on the same dht for the lookup/conn that triggered it.       */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_dht_event_kind_t;

/* A new peer has been added to the routing table (ev.peer carries it).
 * Fires from every production insert path: bootstrap promotion, lazy
 * dial-promotion during a lookup, and the probe fold (ants_dht_probe).
 * Refreshes of already-present peers do NOT re-fire it. */
#define ANTS_DHT_EV_PEER_DISCOVERED ((ants_dht_event_kind_t)1)

/* A peer has been evicted from the routing table (failed PING quorum,
 * stale beyond timeout). After this event the peer_id MAY still appear
 * in cached lookup results until they age out. */
#define ANTS_DHT_EV_PEER_EVICTED ((ants_dht_event_kind_t)2)

/* An active lookup converged on its result set. ev.lookup is the
 * caller's handle from ants_dht_lookup; ev.peers / ev.peer_count carry
 * the final list (UP TO ANTS_DHT_K entries, sorted by XOR distance from
 * the lookup target). Buffer is valid for the duration of the callback;
 * caller must copy what they want to retain. */
#define ANTS_DHT_EV_LOOKUP_COMPLETE ((ants_dht_event_kind_t)3)

/* A lookup failed to converge within its configured deadline / RPC
 * budget. peer_count may still be non-zero (best-effort partial result);
 * caller decides whether to use it or retry. */
#define ANTS_DHT_EV_LOOKUP_TIMEOUT ((ants_dht_event_kind_t)4)

/* Our local announce for a shard-key was acknowledged by at least one
 * storer. ev.shard_key carries the announced key. */
#define ANTS_DHT_EV_ANNOUNCE_CONFIRMED ((ants_dht_event_kind_t)5)

/* Maintenance completed. Fires (a) from the periodic refresh sweep
 * (bucket refresh, announcement republish; ev.shard_key == 0) and (b)
 * when a random-target probe converges (ants_dht_probe; ev.shard_key
 * carries the probe key, letting the caller correlate and reuse the
 * probe's lookup buffer). Observers use it to track the DHT's "healthy
 * heartbeat" cadence. */
#define ANTS_DHT_EV_TABLE_REFRESHED ((ants_dht_event_kind_t)6)

/* A bootstrap seed completed: the pinned dial was promoted into the
 * routing table AND the self-FIND_NODE issued through it received the
 * seed's response — the full join round-trip, not just the handshake.
 * ev.peer carries the seed (peer_id = the pinned identity, multiaddr =
 * the dialed address). Fires at most once per ants_dht_bootstrap call;
 * a seed whose connection drops before responding never fires it. */
#define ANTS_DHT_EV_BOOTSTRAP_COMPLETE ((ants_dht_event_kind_t)7)

typedef struct {
    ants_dht_event_kind_t kind;

    /* The peer this event pertains to. Set for PEER_DISCOVERED and
     * PEER_EVICTED; zeroed otherwise. */
    ants_dht_peer_t peer;

    /* For LOOKUP_* events: the caller's lookup handle (so they can
     * correlate to the call that started it) and the result set.
     * Buffer ownership: payload valid only during the callback. */
    const ants_dht_lookup_t *lookup;
    const ants_dht_peer_t *peers;
    size_t peer_count;

    /* For ANNOUNCE_CONFIRMED: the key we successfully announced. */
    ants_dht_shard_key_t shard_key;
} ants_dht_event_t;

/*
 * Event callback signature. Returns ANTS_OK to acknowledge; any other
 * return code is stored as the dht's last-error and surfaced via the
 * next API call.
 *
 * The callback MUST NOT call ants_dht_destroy on the dht it's nested
 * under. Destruction must be deferred to after tick() returns.
 */
typedef ants_error_t (*ants_dht_event_fn)(const ants_dht_event_t *event, void *user_ctx);

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* The transport this DHT will run its RPCs over. MUST already be
     * initialised (ants_transport_init) and remain alive for the dht's
     * full lifetime. The DHT will dial bootstrap peers and open bidi
     * streams via this transport. */
    ants_transport_t *transport;

    /* Our local peer ID. Same value used to initialise the transport;
     * pinned in the DHT so we know which peer-id space we route in
     * (and so we never insert ourselves into our own routing table). */
    ants_peer_id_t local_peer_id;

    /* Event callback (required, cannot be NULL) + opaque cookie (may be
     * NULL if event_fn doesn't need it). */
    ants_dht_event_fn event_fn;
    void *event_ctx;

    /* Routing-table refresh interval in milliseconds. Every bucket
     * that has been idle for this long is pinged for liveness; stale
     * entries are evicted. Recommended caller-side default: 60000 ms
     * (1 minute). 0 means "no automatic refresh" — useful for tests. */
    uint32_t refresh_interval_ms;

    /* Lookup deadline in milliseconds. An iterative lookup that hasn't
     * converged within this window fires LOOKUP_TIMEOUT with its
     * best-effort partial result. Recommended: 5000 ms. */
    uint32_t lookup_deadline_ms;

    /* Announcement republish interval in milliseconds. We re-emit our
     * ANNOUNCE_PEER messages at the K closest nodes for each shard we
     * host this often, to absorb churn in the closest-N set.
     * Recommended: 1800000 ms (30 minutes). */
    uint32_t announce_republish_ms;
} ants_dht_config_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Initialise the DHT against an existing transport. On success the
 * routing table is empty and the dht has zero known peers. The caller
 * MUST seed it via ants_dht_bootstrap (one or more known-good peers)
 * before lookups can succeed.
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG if any required config field is NULL/zero
 *     or if the transport pointer is NULL.
 */
ants_error_t ants_dht_init(ants_dht_t *dht, const ants_dht_config_t *config);

/*
 * Tear down the DHT. Cancels all in-flight lookups, drops the routing
 * table, releases any heap state. After this returns the dht buffer
 * may be freed or reused. Does NOT destroy the underlying transport —
 * that's the caller's responsibility.
 *
 * MUST NOT be called from inside an event callback.
 */
ants_error_t ants_dht_destroy(ants_dht_t *dht);

/*
 * Drive the DHT state machine forward. Should be invoked from the same
 * loop that ticks the transport — typically alongside ants_transport_tick.
 *
 * On each call:
 *   1. Process any timed-out in-flight RPCs;
 *   2. Advance active iterative lookups (issue next-batch queries to
 *      closer peers, harvest received responses from transport streams);
 *   3. Fire any DHT events the caller's event_fn should observe;
 *   4. Re-emit announcements and refresh stale buckets if their
 *      timers have elapsed.
 *
 * Returns the milliseconds until the DHT next wants attention. The
 * caller should treat this as an upper bound on its idle-sleep window
 * and re-tick sooner if the transport reports earlier traffic. As with
 * transport_tick, UINT32_MAX means "idle — wake on incoming I/O".
 */
uint32_t ants_dht_tick(ants_dht_t *dht);

/* ------------------------------------------------------------------------ */
/* Bootstrap                                                                */
/*                                                                          */
/* The DHT cannot find peers until it knows some. Bootstrap adds known      */
/* peers to the routing table directly, dialing them via the transport so   */
/* they're verified before being treated as routing fodder.                 */
/* ------------------------------------------------------------------------ */

/*
 * Seed the routing table with a known peer. The DHT will:
 *   1. Dial the multiaddr via the transport (with expected_peer_id =
 *      the expected_peer_id arg);
 *   2. Once the handshake completes, insert the peer into the bucket
 *      keyed by XOR(local_peer_id, expected_peer_id);
 *   3. Issue a FIND_NODE on our own local_peer_id to populate nearby
 *      buckets via the peer's view of the network.
 *
 * Multiple bootstrap calls can be issued — up to
 * ANTS_DHT_MAX_BOOTSTRAP_PEERS pending at once. They're processed in
 * parallel; the routing table will eventually contain the union of
 * what each seed peer surfaced.
 *
 * Returns ANTS_OK once the bootstrap request is queued, NOT once the
 * handshake completes (that surfaces via PEER_DISCOVERED; the full
 * join round-trip via BOOTSTRAP_COMPLETE).
 *
 * Errors:
 *   ANTS_ERROR_INVALID_ARG — NULL dht/multiaddr/expected_peer_id;
 *   ANTS_ERROR_PEER_UNREACHABLE — transport refused the dial;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — all bootstrap slots are pending
 *     (slots free when their connections close).
 */
ants_error_t
ants_dht_bootstrap(ants_dht_t *dht, const char *multiaddr, const ants_peer_id_t *expected_peer_id);

/* ------------------------------------------------------------------------ */
/* Shard announcements                                                      */
/*                                                                          */
/* Tell the network that we host a particular shard. The DHT performs an    */
/* iterative FIND_NODE toward the shard-key's peer-id expansion and emits   */
/* ANNOUNCE_PEER RPCs to the K closest peers it finds. The announcement is  */
/* refreshed automatically on the announce_republish_ms cadence.            */
/* ------------------------------------------------------------------------ */

/*
 * Announce that we host the shard identified by shard_key. Returns once
 * the announce is queued; ANNOUNCE_CONFIRMED fires when at least one
 * storer ACKs.
 */
ants_error_t ants_dht_announce(ants_dht_t *dht, ants_dht_shard_key_t shard_key);

/*
 * Withdraw a previous announce. The next republish cycle will skip
 * this shard; peers that already cached us for it will let the entry
 * age out on their side (typically 2× our republish interval).
 */
ants_error_t ants_dht_unannounce(ants_dht_t *dht, ants_dht_shard_key_t shard_key);

/* ------------------------------------------------------------------------ */
/* Lookups                                                                  */
/*                                                                          */
/* Find peers responsible for a shard. The lookup performs an iterative     */
/* FIND_NODE toward the shard-key's peer-id expansion, then GET_PEERS at    */
/* the converged closest set. Results arrive via ANTS_DHT_EV_LOOKUP_COMPLETE */
/* (or LOOKUP_TIMEOUT) through the registered event_fn.                    */
/* ------------------------------------------------------------------------ */

/*
 * Start an iterative lookup for `shard_key`. The caller-allocated
 * `out_lookup` buffer is initialised and MUST remain valid until the
 * lookup completes (LOOKUP_COMPLETE / LOOKUP_TIMEOUT events fire) or
 * is cancelled.
 *
 * Returns ANTS_OK once the lookup is queued. Failure modes:
 *   ANTS_ERROR_INVALID_ARG — NULL args;
 *   ANTS_ERROR_BUFFER_TOO_SMALL — too many concurrent lookups for the
 *     dht's internal capacity.
 *
 * Near-neighbour Hamming expansion (looking up shard_key ± Hamming-1
 * to absorb LSH boundary effects, per RFC-0002 §DHT routing) is the
 * CALLER's responsibility — they issue multiple ants_dht_lookup calls
 * with their candidate near-neighbour keys, then union the results.
 * Doing the expansion at the DHT layer would couple it to the LSH
 * specifics which live in cache/embedding.
 */
ants_error_t
ants_dht_lookup(ants_dht_t *dht, ants_dht_shard_key_t shard_key, ants_dht_lookup_t *out_lookup);

/*
 * Cancel an in-flight lookup. No LOOKUP_COMPLETE / LOOKUP_TIMEOUT
 * event fires after cancellation. Idempotent on already-completed
 * lookups (returns ANTS_OK).
 */
ants_error_t ants_dht_lookup_cancel(ants_dht_lookup_t *lookup);

/*
 * Random-target probe — anti-eclipse axis S2 (RFC-0005 §"Anti-eclipse peer
 * sampling"). Runs the same iterative machinery as ants_dht_lookup toward
 * `random_key`, but with maintenance completion semantics: on convergence
 * the ANSWERED candidates are folded into the routing table (firing
 * PEER_DISCOVERED for each genuinely new peer) and a TABLE_REFRESHED event
 * fires with ev.shard_key == random_key; no LOOKUP_COMPLETE fires, so
 * probe results never reach shard-lookup consumers as answers.
 *
 * Security contract:
 *   - `random_key` MUST be unpredictable to an adversary (drawn from a
 *     CSPRNG by the caller per refresh epoch). The lib deliberately has no
 *     entropy source — unpredictability is the caller's contribution, and
 *     tests get determinism for free. The lookup target is
 *     BLAKE3(random_key as 8 LE bytes), uniform over the keyspace, so an
 *     adversary cannot pre-position identities around a victim's future
 *     probe targets.
 *   - Only VERIFIED peers enter the table: ANSWERED means reached over the
 *     mutually-authenticated transport (lazy dial pins expected_peer_id)
 *     and answered a GET_PEERS. Peers merely NAMED in a response are never
 *     folded — answering a probe cannot poison the table by listing Sybils.
 *   - Probes enrich but never displace: inserts into full buckets are
 *     rejected (eviction happens only via the liveness-PING dead-strike
 *     path), so an adversary cannot use our own probes to flush honest
 *     peers.
 *
 * Probes share the lookup slots (ANTS_DHT_MAX_ACTIVE_LOOKUPS), the RPC
 * registry and the pending-dial slots with real lookups; callers SHOULD
 * keep at most one probe in flight (one per view-refresh epoch is the
 * intended cadence). Cancel with ants_dht_lookup_cancel like any lookup.
 * Returns ANTS_OK, ANTS_ERROR_INVALID_ARG on NULL args, or
 * ANTS_ERROR_BUFFER_TOO_SMALL when all lookup slots are busy.
 */
ants_error_t
ants_dht_probe(ants_dht_t *dht, ants_dht_shard_key_t random_key, ants_dht_lookup_t *out_probe);

/* ------------------------------------------------------------------------ */
/* Transport event delegation                                               */
/*                                                                          */
/* The transport layer accepts a single registered event_fn — the caller's. */
/* The DHT therefore cannot register its own callback directly; instead it  */
/* needs the caller to forward transport events into the DHT from inside    */
/* their own event_fn. This is the one piece of cooperation a DHT-using     */
/* application must wire up:                                                */
/*                                                                          */
/*     static ants_error_t my_transport_event(                              */
/*         const ants_transport_event_t *ev, void *ctx)                     */
/*     {                                                                    */
/*         my_app_t *app = ctx;                                             */
/*         ants_dht_handle_transport_event(&app->dht, ev);                  */
/*         // ... any application-specific event handling (e.g. gossip)    */
/*         return ANTS_OK;                                                  */
/*     }                                                                    */
/*                                                                          */
/* The DHT inspects each event and consumes the ones that belong to one of  */
/* its in-flight RPCs (matched by stream pointer); all others are ignored,  */
/* leaving the caller free to handle them as they wish. Calling this with   */
/* a non-DHT event is a cheap no-op (one pointer scan, then return).        */
/* ------------------------------------------------------------------------ */

/*
 * Hand a transport event to the DHT for dispatch. Returns ANTS_OK on
 * success, including the case where the event did not belong to any
 * DHT-owned stream or connection. Returns ANTS_ERROR_INVALID_ARG on
 * NULL args.
 *
 * Designed to be called from inside the caller's own transport
 * event_fn. Note the reentrancy this implies — all of it permitted by
 * the transport's event model (callbacks may call ants_transport_* on
 * the conn/stream that triggered them):
 *   - promotion paths (bootstrap CONN_READY, lazy dial-promotion) call
 *     back into the transport (stream open/send for the self-FIND_NODE)
 *     and fire the DHT's own event_fn synchronously (PEER_DISCOVERED,
 *     BOOTSTRAP_COMPLETE) — nested inside the transport callback;
 *   - RPC responses complete through the per-RPC completion handler
 *     registered at send time.
 * The hard rule stands: never call ants_dht_destroy or
 * ants_transport_destroy from inside the nested callbacks.
 */
ants_error_t ants_dht_handle_transport_event(ants_dht_t *dht, const ants_transport_event_t *event);

/* ------------------------------------------------------------------------ */
/* Routing-table introspection                                              */
/* ------------------------------------------------------------------------ */

/*
 * Number of peers currently in the routing table. Useful for observability
 * and for upper layers (e.g. anti-eclipse) that want to verify routing
 * diversity before extending trust.
 */
size_t ants_dht_routing_table_size(const ants_dht_t *dht);

/*
 * Enumerate up to `cap` peers from the routing table into `out_peers`.
 * Writes the actual count to `*out_count`. Returns
 * ANTS_ERROR_BUFFER_TOO_SMALL with `*out_count` set to the required cap
 * when the buffer is too small. Returns peers in no particular order;
 * caller sorts if they care.
 */
ants_error_t ants_dht_routing_table_enumerate(const ants_dht_t *dht,
                                              ants_dht_peer_t *out_peers,
                                              size_t cap,
                                              size_t *out_count);

/*
 * Sample up to `n_out` bucket-diverse peers from the routing table into
 * `out_peers`, for an anti-eclipse gossip view (RFC-0005 §"Anti-eclipse peer
 * sampling", axis S1 — the bucket-diverse draw). A round-robin sweep takes
 * peers spread across the 256 XOR distance-class buckets rather than clustering
 * in the nearest ones, so an adversary must surround a victim across the whole
 * keyspace, not just one neighbourhood. Returns the number of peers written
 * (<= n_out, <= routing-table size); 0 on NULL args, n_out == 0, or an empty
 * table. Equivalent to ants_dht_sample_peers_rotated with rotation == 0.
 *
 * Peers are returned regardless of live-connection state — reachability is the
 * caller's / transport's concern.
 */
size_t ants_dht_sample_peers(const ants_dht_t *dht, ants_dht_peer_t *out_peers, size_t n_out);

/*
 * Rotated bucket-diverse sample — anti-eclipse axis S3 (RFC-0005
 * §"Anti-eclipse peer sampling"). Same diversity guarantees as
 * ants_dht_sample_peers; `rotation` additionally shifts WHICH cross-section
 * of the table fills the sample: the bucket visit order rotates (a different
 * keyspace region fills first when n_out < table size) and the within-bucket
 * start offset rotates (successive epochs draw different entries from a fat
 * bucket). rotation == 0 is exactly the axis-S1 draw.
 *
 * `rotation` is a plain per-refresh counter, NOT a secret: S3's defence is
 * churn — a static eclipse cannot lock in because the view keeps moving and
 * the adversary must keep re-winning it — while unpredictability of new
 * peer inflow is axis S2's job (ants_dht_probe). Rotation only bites when
 * the table holds more peers than the view (otherwise every rotation
 * returns the whole table); pair it with probes, which keep the table
 * strictly larger than the view.
 *
 * The composed per-epoch refresh a conforming node runs (RFC-0005 wiring:
 * sample in the DHT, view in the gossip engine, glue in the node):
 *
 *     ants_dht_probe(dht, csprng_u64(), &probe);        // S2: enrich
 *     n = ants_dht_sample_peers_rotated(dht, epoch++,   // S1+S3: draw
 *                                       view, VIEW_SIZE);
 *     // diff `view` against the gossip engine's current peers:
 *     // ants_gossip_remove_peer the departed, ants_gossip_add_peer the new
 */
size_t ants_dht_sample_peers_rotated(const ants_dht_t *dht,
                                     uint64_t rotation,
                                     ants_dht_peer_t *out_peers,
                                     size_t n_out);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_DHT_H */
