/*
 * ants_attest.h — attestation presentation (RFC-0008 §11.12) and the v1
 * handshake gate (RFC-0005 §v1 admission posture: verify-and-tag).
 *
 * After a connection's handshake each side MAY ask the other for its TEE
 * attestation: an ATTEST_REQ (type 9) on a fresh bidirectional stream,
 * answered by an ATTEST_RESP (type 10) on the same stream. The two ride
 * the §11.2 bidi-RPC envelope, so they share the DHT's stream discipline
 * and its type registry; this module is a SIBLING dispatcher of the DHT
 * server — both see every inbound bidi stream, each claims only its own
 * envelope types and silently releases the rest.
 *
 * The receiving side turns the answer into a per-connection VERDICT:
 *
 *   UNATTESTED — the peer has nothing to present (empty body), presented
 *                a vendor this build cannot verify yet (v1.x vendors —
 *                fail closed, not a protocol error), or presented valid
 *                evidence that is no longer fresh;
 *   ATTESTED   — ants_attestation_verify (chain to the pinned vendor
 *                root, report signature, report_data bound to THIS
 *                connection's authenticated peer-id and issued_at) and
 *                ants_attestation_is_fresh both pass;
 *   REJECTED   — the peer presented evidence that fails verification, or
 *                spoke the exchange malformed. RFC-0005: presenting
 *                false evidence is worse than presenting none.
 *
 * The module reports verdicts; POLICY is the caller's. The v1 daemon
 * admits UNATTESTED peers, tags ATTESTED ones, and disconnects REJECTED
 * ones. The bound key is never taken from the wire: it is the peer-id
 * the transport authenticated (ants_transport_conn_peer_id).
 *
 * Integration — forward every transport event, like the DHT:
 *
 *     static ants_error_t on_transport_event(const ants_transport_event_t *ev,
 *                                            void *ctx) {
 *         app_t *app = ctx;
 *         ants_dht_handle_transport_event(&app->dht, ev);
 *         ants_attest_handle_transport_event(&app->attest, ev, time(NULL));
 *         return ANTS_OK;
 *     }
 *
 * On CONN_READY the module sends its own ATTEST_REQ automatically (when
 * config.request_on_ready is set); inbound requests are answered with the
 * local presentation, or with the empty body when there is none — every
 * v1 node, until ants_attestation_generate exists on real hardware.
 *
 * Single-threaded, driven from inside the transport's event callback.
 * Heap: stream handles and response buffers are allocated lazily per
 * exchange and freed when it ends (the DHT RPC pattern).
 */

#ifndef ANTS_ATTEST_H
#define ANTS_ATTEST_H

#include "ants_common.h"
#include "ants_tee.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Wire constants (RFC-0008 §11.11 / §11.12 / §7)                           */
/* ------------------------------------------------------------------------ */

/* Bidi-RPC envelope types (§11.11 registry: 1-8 DHT, 9-10 attestation). */
#define ANTS_ATTEST_MSG_REQ  9u
#define ANTS_ATTEST_MSG_RESP 10u

/* ATTESTATION_MAX_BLOB_BYTES (pinned): a larger blob is malformed. */
#define ANTS_ATTEST_MAX_BLOB_BYTES 16384u
/* ATTESTATION_MAX_RESP_BYTES (receiver default): a larger ATTEST_RESP
 * envelope is rejected without decoding. */
#define ANTS_ATTEST_MAX_RESP_BYTES 20480u

/* ------------------------------------------------------------------------ */
/* Presentation                                                             */
/* ------------------------------------------------------------------------ */

/*
 * What a peer presents. `present == false` is the empty body ("nothing to
 * present"); the other fields are then ignored. `blob` is borrowed: on
 * encode the caller keeps it alive for the call; on decode it points into
 * the decoded buffer.
 */
typedef struct {
    bool present;
    ants_tee_vendor_t vendor; /* never ANTS_TEE_VENDOR_UNKNOWN when present */
    int64_t issued_at_unix;   /* >= 0: the wire field is unsigned */
    int64_t expires_at_unix;  /* >= 0; 0 = the vendor carries no hard expiry */
    const uint8_t *blob;
    size_t blob_len; /* 1 .. ANTS_ATTEST_MAX_BLOB_BYTES */
} ants_attest_presentation_t;

/* ------------------------------------------------------------------------ */
/* Codec                                                                    */
/*                                                                          */
/* Canonical CBOR per RFC-0008 §1.1. Envelope = {0: type, 1: txid, 2: body}; */
/* an empty body omits key 2 (map(2)) and an explicit empty body is         */
/* non-canonical (§11.2). presentation = {0: vendor, 1: issued_at,          */
/* 2: expires_at, 3: blob}. Decoders are strict: wrong type, unknown or     */
/* out-of-order keys, trailing bytes, vendor 0, an empty or oversized blob, */
/* or a txid above 2^32-1 are rejected.                                     */
/* ------------------------------------------------------------------------ */

/* Peek the envelope type of a bidi-RPC message without decoding the body.
 * Returns ANTS_OK with any type value (the caller decides whether it is
 * theirs); an error when the bytes are not an envelope head at all. */
ants_error_t ants_attest_wire_peek_type(const uint8_t *buf, size_t len, uint64_t *out_type);

ants_error_t ants_attest_wire_encode_req(uint8_t *buf, size_t cap, size_t *out_len, uint32_t txid);
ants_error_t ants_attest_wire_decode_req(const uint8_t *buf, size_t len, uint32_t *out_txid);

ants_error_t ants_attest_wire_encode_resp(uint8_t *buf,
                                          size_t cap,
                                          size_t *out_len,
                                          uint32_t txid,
                                          const ants_attest_presentation_t *p);
ants_error_t ants_attest_wire_decode_resp(const uint8_t *buf,
                                          size_t len,
                                          uint32_t *out_txid,
                                          ants_attest_presentation_t *out);

/* ------------------------------------------------------------------------ */
/* Verdicts                                                                 */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_attest_verdict_t;

#define ANTS_ATTEST_VERDICT_NONE       ((ants_attest_verdict_t)0) /* no answer (yet) */
#define ANTS_ATTEST_VERDICT_UNATTESTED ((ants_attest_verdict_t)1)
#define ANTS_ATTEST_VERDICT_ATTESTED   ((ants_attest_verdict_t)2)
#define ANTS_ATTEST_VERDICT_REJECTED   ((ants_attest_verdict_t)3)

typedef struct {
    /* The connection the verdict is about, and its authenticated peer. */
    ants_transport_conn_t *conn;
    ants_peer_id_t peer_id;
    ants_attest_verdict_t verdict;
    /* What was presented (ANTS_TEE_VENDOR_UNKNOWN / 0 for an empty body or
     * a malformed answer). */
    ants_tee_vendor_t vendor;
    int64_t issued_at_unix;
} ants_attest_result_t;

/* Fired once per connection, from inside ants_attest_handle_transport_event
 * (i.e. inside the transport callback). The callback may call
 * ants_transport_peer_disconnect on result->conn; it MUST NOT destroy the
 * transport or the attest context. */
typedef void (*ants_attest_verdict_fn)(const ants_attest_result_t *result, void *ctx);

/* ------------------------------------------------------------------------ */
/* Engine                                                                   */
/* ------------------------------------------------------------------------ */

/* Connections the engine tracks at once (one outbound exchange + one
 * cached verdict each). MUST be >= the transport's max_connections: a
 * peer that never answers then holds only its own connection's slot,
 * released at CONN_CLOSED. */
#define ANTS_ATTEST_MAX_CONNS 64

#define ANTS_ATTEST_CTX_SIZE  32768

typedef union {
    uint8_t _opaque[ANTS_ATTEST_CTX_SIZE];
    uint64_t _align;
} ants_attest_t;

typedef struct {
    /* What this node answers ATTEST_REQ with. NULL (or present == false)
     * → the empty body. When set, the blob must stay alive for the
     * engine's lifetime. */
    const ants_attest_presentation_t *local;
    /* RFC-0005 ATTESTATION_FRESHNESS_WINDOW in seconds (> 0). */
    int64_t freshness_window_seconds;
    /* Send our ATTEST_REQ on every CONN_READY. */
    bool request_on_ready;
    /* Verdict callback (may be NULL) + cookie. */
    ants_attest_verdict_fn verdict_fn;
    void *verdict_ctx;
} ants_attest_config_t;

/* Returns ANTS_ERROR_INVALID_ARG on NULL args, a non-positive window, or a
 * local presentation that would not encode (vendor 0, empty/oversized
 * blob, negative times). */
ants_error_t ants_attest_init(ants_attest_t *a, const ants_attest_config_t *config);

/* Free every per-exchange buffer. Call after the transport is destroyed
 * (or once no more events will be forwarded). Idempotent. */
void ants_attest_destroy(ants_attest_t *a);

/* Ask the peer on `conn` for its attestation. One request per connection:
 * a second call while the first is outstanding, or after a verdict, is a
 * no-op returning ANTS_OK. ANTS_ERROR_BUFFER_TOO_SMALL when every
 * outbound slot is busy. */
ants_error_t ants_attest_request(ants_attest_t *a, ants_transport_conn_t *conn);

/* Forward EVERY transport event. `now_unix` is the verifier's wall clock
 * (seconds), used for the freshness check of any verdict this event
 * completes. Events that are not the module's are cheap no-ops. */
void ants_attest_handle_transport_event(ants_attest_t *a,
                                        const ants_transport_event_t *ev,
                                        int64_t now_unix);

/* The cached verdict for `conn` (ANTS_ATTEST_VERDICT_NONE when there is
 * none yet, or the connection is unknown). Cleared on CONN_CLOSED. */
ants_attest_verdict_t ants_attest_verdict_for(const ants_attest_t *a,
                                              const ants_transport_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_ATTEST_H */
