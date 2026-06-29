/*
 * ants_transport.h — P2P transport layer (Component #4).
 *
 * Sits below network/dht (Kademlia routing by shard-key) and
 * network/gossip (L1 CRDT propagation). Provides encrypted,
 * authenticated, multiplexed peer-to-peer streams over QUIC via
 * vendored picoquic.
 *
 * Spec references:
 *   - RFC-0002 §DHT routing — request/response stream usage.
 *   - RFC-0004 §Layer 1 + §DoS — gossip discipline, rate-limit hooks.
 *   - RFC-0005 §Sybil economics + §The attestation flow — identity
 *     binding via Ed25519 pubkey; attestation verified by upper layer.
 *   - RFC-0010 §First peer's flow — bootstrap dial sequence.
 *
 * Implementation strategy:
 *   - Vendored picoquic (BSD-3, IETF reference QUIC) under deps/picoquic.
 *     Picoquic's tick + callback architecture maps directly onto this
 *     header's API model.
 *   - Vendored picotls (BSD-3, picoquic's TLS 1.3 backend) under
 *     deps/picotls.
 *   - TLS identity binding via RFC 7250 raw public keys: the Ed25519
 *     peer pubkey IS the TLS auth key; no X.509 wrapping, no CA.
 *   - Private-key access via a caller-supplied sign callback (see
 *     ants_transport_sign_fn). The transport never holds the private
 *     key directly. This lets a TEE-resident key sign the handshake
 *     transcript without leaving the enclave.
 *
 * API model: non-blocking. The caller drives the event loop by calling
 * ants_transport_tick() and reading the OS socket(s). Discrete I/O
 * events surface through a single registered callback. The library
 * spawns no threads, does no logging, and calls no malloc — all memory
 * is caller-provided per project convention.
 *
 * Status: implemented — the QUIC transport (Component #4) is
 * feature-complete. A few peer-address / peer-id introspection accessors
 * return ANTS_ERROR_NOT_IMPLEMENTED in v1.0, where the transport carries
 * no durable peer state yet.
 */

#ifndef ANTS_TRANSPORT_H
#define ANTS_TRANSPORT_H

#include "ants_common.h"
#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Peer identity                                                            */
/*                                                                          */
/* Per RFC-0010 line 57, the protocol-level peer identity IS the raw        */
/* Ed25519 public key — not a hash, not a multihash. Every cross-layer      */
/* reference (DHT lookups, gossip subjects, reputation fault proofs) uses   */
/* the same 32-byte handle, and the transport binds the QUIC session to    */
/* this key via RFC 7250 raw-pubkey TLS authentication.                    */
/* ------------------------------------------------------------------------ */

#define ANTS_PEER_ID_SIZE ANTS_ED25519_PUBKEY_SIZE /* 32 */

typedef struct {
    uint8_t bytes[ANTS_PEER_ID_SIZE];
} ants_peer_id_t;

/* ------------------------------------------------------------------------ */
/* Multiaddr                                                                */
/*                                                                          */
/* Per RFC-0010 §First peer's flow, GenesisState carries bootstrap          */
/* multiaddrs. The transport accepts the textual multiaddr form (libp2p     */
/* convention: /ip4/1.2.3.4/udp/4242/quic-v1) plus optional /p2p/<id>       */
/* trailer when the caller already knows the expected identity.            */
/*                                                                          */
/* Max length: 256 bytes covers a fully-qualified DNS-name + port + QUIC    */
/* + /p2p/<32-byte-pubkey-as-base58> with margin. Longer strings reject     */
/* with ANTS_ERROR_INVALID_ARG.                                              */
/* ------------------------------------------------------------------------ */

#define ANTS_MULTIADDR_MAX_LEN 256

/* ------------------------------------------------------------------------ */
/* Opaque context types                                                     */
/*                                                                          */
/* Caller allocates. Sizes are deliberately oversized so vendored picoquic  */
/* version bumps don't break ABI; the .c file enforces the actual bound    */
/* via the compile-time-assertion idiom from foundation/crypto              */
/* (typedef char ..._size_check[(cond) ? 1 : -1]).                         */
/*                                                                          */
/* Layout: union of an _opaque[] byte buffer with a uint64_t _align        */
/* anchor, forcing the underlying buffer to uint64_t alignment so a        */
/* subsequent cast to the vendored type is well-defined on alignment-     */
/* strict targets (same pattern as ants_blake3_ctx_t).                     */
/*                                                                          */
/* The sizes below are v1.0 starting estimates. After picoquic is vendored */
/* and the implementation lands, a follow-up PR may tighten them based on  */
/* sizeof(picoquic_quic_t) / sizeof(picoquic_cnx_t) measurements. Until    */
/* then we trade ~200 KB of headroom (per a 30-peer client) for ABI        */
/* safety against picoquic growth.                                          */
/* ------------------------------------------------------------------------ */

#define ANTS_TRANSPORT_CTX_SIZE        16384 /* picoquic_quic_t + margin */
#define ANTS_TRANSPORT_CONN_CTX_SIZE   8192  /* picoquic_cnx_t + margin  */
#define ANTS_TRANSPORT_STREAM_CTX_SIZE 1024  /* per-stream wrapper       */

typedef union {
    uint8_t _opaque[ANTS_TRANSPORT_CTX_SIZE];
    uint64_t _align;
} ants_transport_t;

typedef union {
    uint8_t _opaque[ANTS_TRANSPORT_CONN_CTX_SIZE];
    uint64_t _align;
} ants_transport_conn_t;

typedef union {
    uint8_t _opaque[ANTS_TRANSPORT_STREAM_CTX_SIZE];
    uint64_t _align;
} ants_transport_stream_t;

/* ------------------------------------------------------------------------ */
/* Event model                                                              */
/*                                                                          */
/* The transport surfaces I/O events through a single registered callback. */
/* The callback runs synchronously from ants_transport_tick(), never from  */
/* a separate thread. Each event delivery is non-reentrant for the same    */
/* connection — the callback may call ants_transport_* functions on the    */
/* conn/stream that triggered it without recursion concern.                 */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_transport_event_kind_t;

/* A new (inbound or outbound) connection completed its handshake. The
 * peer's Ed25519 pubkey is now bound to conn. Upper layer should verify
 * TEE attestation (out-of-band over a stream the peer opens, per
 * RFC-0005). */
#define ANTS_TRANSPORT_EV_CONN_READY ((ants_transport_event_kind_t)1)

/* The connection terminated (peer-initiated, transport-initiated, or
 * timeout). conn becomes invalid after the callback returns. */
#define ANTS_TRANSPORT_EV_CONN_CLOSED ((ants_transport_event_kind_t)2)

/* A new inbound stream opened by the remote peer. The callback may read
 * from it via ants_transport_stream_recv(). */
#define ANTS_TRANSPORT_EV_STREAM_OPENED ((ants_transport_event_kind_t)3)

/* The stream has bytes available. payload + payload_len are valid for
 * the duration of the callback; the library reclaims the buffer on
 * return. Copy what you need. */
#define ANTS_TRANSPORT_EV_STREAM_READABLE ((ants_transport_event_kind_t)4)

/* The peer signalled clean end-of-stream (FIN). No further bytes arrive.
 * The stream handle is still valid for ants_transport_stream_send if it
 * was bidirectional and we haven't ourselves closed our half. */
#define ANTS_TRANSPORT_EV_STREAM_FIN ((ants_transport_event_kind_t)5)

/* The peer reset the stream (QUIC RESET_STREAM frame). Whatever bytes we
 * received before this are still valid; no more will come. The stream is
 * unusable for further send/recv. Maps to ANTS_ERROR_STREAM_RESET when
 * surfaced to a synchronous send/recv caller. */
#define ANTS_TRANSPORT_EV_STREAM_RESET ((ants_transport_event_kind_t)6)

/* Stream is now writable after flow-control back-pressure. Caller may
 * resume sending. */
#define ANTS_TRANSPORT_EV_STREAM_WRITABLE ((ants_transport_event_kind_t)7)

typedef struct {
    ants_transport_event_kind_t kind;
    /* The connection the event pertains to. Never NULL. */
    ants_transport_conn_t *conn;
    /* The stream, when the event is stream-scoped. NULL for connection-
     * scoped events (CONN_READY, CONN_CLOSED). */
    ants_transport_stream_t *stream;
    /* The peer's Ed25519 pubkey, mirrored here for callback convenience
     * (avoids round-tripping through ants_transport_conn_peer_id). */
    ants_peer_id_t peer_id;
    /* Event-specific data. payload is owned by the library; valid only
     * within the callback. payload_len = 0 when the event carries no
     * data (CONN_READY, CONN_CLOSED, STREAM_OPENED, STREAM_FIN,
     * STREAM_RESET, STREAM_WRITABLE). */
    const uint8_t *payload;
    size_t payload_len;
    /* For STREAM_RESET / CONN_CLOSED: peer-supplied error code if any
     * (mirrors QUIC's application error code). 0 when not applicable. */
    uint64_t error_code;
} ants_transport_event_t;

/*
 * Event callback signature. user_ctx is whatever the caller registered.
 * Returns ANTS_OK to acknowledge; any other return value is stored in
 * the conn's last-error field and surfaced via the next stream/conn
 * call. The library does no logging itself.
 *
 * The callback MUST NOT call ants_transport_destroy() on the transport
 * it's nested under. Destruction must be deferred to after tick()
 * returns.
 */
typedef ants_error_t (*ants_transport_event_fn)(const ants_transport_event_t *event,
                                                void *user_ctx);

/* ------------------------------------------------------------------------ */
/* Sign callback                                                            */
/*                                                                          */
/* The transport never holds the private key directly. Instead, it calls   */
/* this callback during the TLS 1.3 handshake to sign the transcript with  */
/* the local Ed25519 secret key. This lets a TEE-resident key sign the    */
/* handshake without exposing material outside the enclave; a non-TEE      */
/* deployment supplies an in-memory-key callback like:                     */
/*                                                                          */
/*     static ants_error_t my_sign(const uint8_t *transcript,              */
/*                                  size_t len,                            */
/*                                  uint8_t out_sig[64],                   */
/*                                  void *ctx) {                            */
/*         const uint8_t *priv = (const uint8_t *)ctx;                     */
/*         return ants_ed25519_sign(priv, transcript, len, out_sig);       */
/*     }                                                                    */
/*                                                                          */
/* The callback must succeed quickly (it runs on the transport tick        */
/* thread). It must NOT mutate transport state or call back into the       */
/* transport.                                                               */
/* ------------------------------------------------------------------------ */

typedef ants_error_t (*ants_transport_sign_fn)(const uint8_t *transcript,
                                               size_t transcript_len,
                                               uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                                               void *sign_ctx);

/* ------------------------------------------------------------------------ */
/* Configuration                                                            */
/*                                                                          */
/* Caller-supplied at init time. All fields are non-optional — the         */
/* defaults are the responsibility of the caller, who knows the network    */
/* phase (RFC-0010 §Phase transitions) and the deployment environment.    */
/* ------------------------------------------------------------------------ */

typedef struct {
    /* Local Ed25519 public key. Presented to peers as the TLS 1.3 raw
     * public key (RFC 7250). The MATCHING private key is held by the
     * caller and accessed only via sign_fn — the transport never sees
     * it in plaintext. */
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];

    /* TLS handshake transcript signature callback. Required (cannot be
     * NULL). See the ants_transport_sign_fn comment above for the
     * in-memory-key minimal example. */
    ants_transport_sign_fn sign_fn;
    /* Opaque context passed to sign_fn on every invocation. May be
     * NULL if sign_fn doesn't need it. */
    void *sign_ctx;

    /* Listening address. NULL → no listener (dial-only client).
     * Format: same multiaddr textual form as dial_addr accepts. */
    const char *listen_multiaddr;

    /* Idle timeout in milliseconds. Connections with no application
     * traffic for this long are torn down. Recommended caller-side
     * default: 30000 ms. 0 means "no timeout" and is permitted but not
     * recommended for production. */
    uint32_t idle_timeout_ms;

    /* Maximum number of concurrent connections. Bounds memory: each
     * inbound CONN_READY is rejected at the handshake if accepting
     * would exceed this. Caller should size against expected DHT degree
     * (typically 20-50) plus gossip degree plus margin. */
    uint32_t max_connections;

    /* Maximum number of concurrent streams per connection. Bounds
     * per-peer fanout. Per RFC-0004 §The propagation bound, gossip
     * fanout f is typically 6-12; the transport adds margin (e.g., 64)
     * so the upper layer's stream-multiplexing strategy isn't
     * constrained. */
    uint32_t max_streams_per_conn;

    /* Event callback + opaque cookie. Both required (cannot be NULL). */
    ants_transport_event_fn event_fn;
    void *event_ctx;
} ants_transport_config_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

/*
 * Initialise the transport with caller-supplied configuration. On
 * success, the transport is in dial-ready state; if
 * config->listen_multiaddr is non-NULL, the listener is bound and
 * accepting handshakes after the next call to ants_transport_tick().
 *
 * Returns:
 *   ANTS_OK on success;
 *   ANTS_ERROR_INVALID_ARG if any required field is NULL/zero;
 *   ANTS_ERROR_PEER_UNREACHABLE if the listen address could not be bound.
 */
ants_error_t ants_transport_init(ants_transport_t *t, const ants_transport_config_t *config);

/*
 * Tear down the transport. All connections and streams are immediately
 * closed (peers see QUIC CONNECTION_CLOSE with the supplied close_code).
 * After this returns, the transport_t buffer may be freed or reused.
 *
 * MUST NOT be called from inside an event callback. The caller is
 * responsible for deferring destruction until after tick() returns.
 */
ants_error_t ants_transport_destroy(ants_transport_t *t, uint64_t close_code);

/*
 * Drive the event loop forward.
 *
 * On each call:
 *   1. Process pending inbound packets from the OS socket(s);
 *   2. Fire event callbacks for every discrete event observed;
 *   3. Hand outbound packets back to the OS socket via sendto().
 *
 * Returns the number of milliseconds until the next scheduled wake
 * (i.e., the maximum the caller may sleep before calling tick() again).
 * 0 means "call me again immediately". UINT32_MAX means "idle — no
 * time-driven work pending; wake on socket readable".
 *
 * Idiomatic caller loop:
 *
 *     while (running) {
 *         uint32_t wait_ms = ants_transport_tick(&t);
 *         struct pollfd fds[1] = { { .fd = sock, .events = POLLIN } };
 *         poll(fds, 1, wait_ms == UINT32_MAX ? -1 : (int)wait_ms);
 *     }
 */
uint32_t ants_transport_tick(ants_transport_t *t);

/* ------------------------------------------------------------------------ */
/* Dialing                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Initiate an outbound connection to a peer at `multiaddr`.
 *
 * If `expected_peer_id` is non-NULL, the handshake fails closed
 * (ANTS_ERROR_PEER_MISMATCH surfaced via CONN_CLOSED) if the remote
 * peer presents a different Ed25519 pubkey. This is the anti-MITM
 * defence used for GenesisState bootstrap_dht_seeds (RFC-0010 step 5)
 * where the trusted peer_id is known a priori.
 *
 * If `expected_peer_id` is NULL, the handshake binds whatever pubkey
 * the peer presents and the upper layer (DHT, reputation) is
 * responsible for attestation verification before extending trust.
 *
 * The dial is non-blocking. Success is signalled by a CONN_READY event
 * for `*out_conn`; failure by CONN_CLOSED with an error_code mapping
 * to one of: ANTS_ERROR_PEER_UNREACHABLE, ANTS_ERROR_HANDSHAKE_FAILED,
 * ANTS_ERROR_PEER_MISMATCH.
 *
 * Returns:
 *   ANTS_OK if the dial was accepted into the queue;
 *   ANTS_ERROR_INVALID_ARG on bad multiaddr or NULL args;
 *   ANTS_ERROR_BUFFER_TOO_SMALL if max_connections has been reached.
 */
ants_error_t ants_transport_dial(ants_transport_t *t,
                                 const char *multiaddr,
                                 const ants_peer_id_t *expected_peer_id,
                                 ants_transport_conn_t *out_conn);

/* ------------------------------------------------------------------------ */
/* Streams                                                                  */
/*                                                                          */
/* Bidi for DHT request/response (RFC-0002 §lookup protocol). Uni for       */
/* gossip broadcast (RFC-0004 §Layer 1 propagation rule).                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_open_bidi_stream(ants_transport_conn_t *conn,
                                             ants_transport_stream_t *out_stream);

ants_error_t ants_transport_open_uni_stream(ants_transport_conn_t *conn,
                                            ants_transport_stream_t *out_stream);

/*
 * Send bytes on a stream. May return ANTS_ERROR_BUFFER_TOO_SMALL if the
 * QUIC flow-control window is full; the caller should buffer the
 * remainder and resume on STREAM_WRITABLE.
 *
 * If `fin` is true, the stream is closed for further sends after these
 * bytes drain.
 */
ants_error_t ants_transport_stream_send(ants_transport_stream_t *stream,
                                        const uint8_t *data,
                                        size_t len,
                                        bool fin);

/*
 * Receive bytes from a stream. Returns ANTS_OK with *out_len = 0 if no
 * bytes are currently available; ANTS_ERROR_STREAM_RESET if the peer
 * reset the stream.
 */
ants_error_t ants_transport_stream_recv(ants_transport_stream_t *stream,
                                        uint8_t *out,
                                        size_t cap,
                                        size_t *out_len);

/* Close our side of a stream. Sends FIN. */
ants_error_t ants_transport_stream_close(ants_transport_stream_t *stream);

/*
 * Reset a stream with an application error code. Maps to QUIC
 * RESET_STREAM. Used by the gossip layer's per-stream cut hook for
 * RFC-0004 §DoS rate-limit enforcement.
 */
ants_error_t ants_transport_stream_reset(ants_transport_stream_t *stream, uint64_t error_code);

/* ------------------------------------------------------------------------ */
/* Flow control / introspection                                             */
/*                                                                          */
/* The transport exposes the remaining QUIC flow-control budget so the     */
/* upper layer can implement per-stream pacing. Per RFC-0004 §DoS, novel-  */
/* proof rate limits are an upper-layer concern; this is the visibility    */
/* the transport provides to make them implementable.                       */
/* ------------------------------------------------------------------------ */

/*
 * Bytes the stream may send before blocking on the peer's flow-control
 * window. UINT64_MAX → effectively unbounded (the local sender has not
 * yet received any flow-control limit from the peer, which is normal
 * very early in a stream's life).
 */
uint64_t ants_transport_stream_send_window(const ants_transport_stream_t *stream);

uint64_t ants_transport_stream_bytes_sent(const ants_transport_stream_t *stream);
uint64_t ants_transport_stream_bytes_received(const ants_transport_stream_t *stream);

/* ------------------------------------------------------------------------ */
/* Connection introspection                                                 */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_conn_peer_id(const ants_transport_conn_t *conn,
                                         ants_peer_id_t *out_peer_id);

/*
 * Return the peer's observed network address as a textual multiaddr.
 * `out_buf` is caller-provided; cap should be at least
 * ANTS_MULTIADDR_MAX_LEN.
 */
ants_error_t
ants_transport_conn_peer_addr(const ants_transport_conn_t *conn, char *out_buf, size_t cap);

/*
 * Close an entire connection. All streams are reset; the peer sees QUIC
 * CONNECTION_CLOSE with the supplied code. Used by the upper layer to
 * evict peers caught flooding across multiple streams.
 */
ants_error_t ants_transport_peer_disconnect(ants_transport_conn_t *conn, uint64_t error_code);

/*
 * Enumerate currently-connected peers. Caller-provided buffer; the
 * library fills it with up to `cap` entries and writes the actual count
 * to `*out_count`. Returns ANTS_ERROR_BUFFER_TOO_SMALL with *out_count
 * = the required cap if the buffer is too small.
 *
 * This is the visibility the anti-eclipse layer uses (RFC-0005). The
 * transport does NOT enforce topology diversity itself.
 */
ants_error_t ants_transport_peer_list(const ants_transport_t *t,
                                      ants_peer_id_t *out_peers,
                                      size_t cap,
                                      size_t *out_count);

/*
 * Return the transport's bound local address as a textual multiaddr
 * (e.g. "/ip4/127.0.0.1/udp/41329/quic-v1"). Useful when the listener
 * was configured with port 0 (kernel-assigned) and the caller needs to
 * communicate the actual port to potential dialers. Returns
 * ANTS_ERROR_NOT_IMPLEMENTED when the transport has no listening
 * socket (dial-only client).
 */
ants_error_t ants_transport_local_addr(const ants_transport_t *t, char *out_buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_TRANSPORT_H */
