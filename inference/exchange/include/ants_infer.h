/*
 * ants_infer.h — the inference exchange (RFC-0008 §11.14): a requester asks
 * a producer for an answer, the producer returns the signed §11.8 commit and
 * the full answer envelope, and the requester checks them on arrival.
 *
 * INFER_REQ (type 11) and INFER_RESP (type 12) ride the §11.2 bidi-RPC
 * envelope, one exchange per bidirectional stream. Like network/attest this
 * module is a SIBLING dispatcher of the DHT server: every inbound bidi
 * stream is seen by all of them, and each claims only its own envelope
 * types and silently releases the rest.
 *
 * The producer side is a callback: the engine decodes the request and hands
 * it to `serve_fn`, which either answers or declines. The engine owns the
 * wire and nothing else — which model runs, which head height becomes the
 * commit's `round`, and whom to serve are the caller's.
 *
 * The requester side turns the INFER_RESP into a VERDICT:
 *
 *   ANSWERED  — ants_inference_answer_check passed under the peer-id the
 *               transport authenticated for this connection (never a key
 *               from the wire), so a relayed answer cannot pass;
 *   DECLINED  — the empty body;
 *   REJECTED  — the check failed, or the response was malformed, oversized,
 *               or echoed the wrong txid;
 *   NO_ANSWER — the stream was reset, the connection closed, or the
 *               request timed out (ants_infer_tick) first.
 *
 * Integration — forward every transport event, like the DHT and attest:
 *
 *     ants_dht_handle_transport_event(&app->dht, ev);
 *     ants_attest_handle_transport_event(&app->attest, ev, now);
 *     ants_infer_handle_transport_event(&app->infer, ev);
 *
 * Single-threaded, driven from inside the transport's event callback; the
 * producer callback runs synchronously there. Heap: stream handles and
 * message buffers are allocated per exchange and freed when it ends.
 */

#ifndef ANTS_INFER_H
#define ANTS_INFER_H

#include "ants_common.h"
#include "ants_inference.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Wire constants (RFC-0008 §11.11 / §11.14 / §7)                           */
/* ------------------------------------------------------------------------ */

/* Bidi-RPC envelope types (§11.11: 1-8 DHT, 9-10 attestation, 11-12 here). */
#define ANTS_INFER_MSG_REQ  11u
#define ANTS_INFER_MSG_RESP 12u

/* INFER_MAX_INPUT_BYTES (pinned): a larger request input is malformed. */
#define ANTS_INFER_MAX_INPUT_BYTES 4096u
/* INFER_MAX_POSITIONS (pinned) — the orchestration decoder's bound. */
#define ANTS_INFER_MAX_POSITIONS 64u
/* INFER_MAX_RESP_BYTES (pinned): a larger INFER_RESP is rejected undecoded. */
#define ANTS_INFER_MAX_RESP_BYTES 131072u
/* The largest conformant INFER_REQ envelope: the input plus the envelope,
 * the tier and the nonce (≈ 50 bytes of CBOR). Not a wire constant — a
 * receiver bound derived from the input cap. */
#define ANTS_INFER_MAX_REQ_BYTES (ANTS_INFER_MAX_INPUT_BYTES + 128u)

typedef char ants_infer_positions_match_model
    [(ANTS_INFER_MAX_POSITIONS == ANTS_INFERENCE_REF_SEQLEN_MAX) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Messages                                                                 */
/* ------------------------------------------------------------------------ */

/* An INFER_REQ body. `input` is borrowed (on decode it points into the
 * decoded buffer). `tier` is any value up to 2^31-1 on the wire; a producer
 * declines tiers it does not serve. */
typedef struct {
    const uint8_t *input;
    size_t input_len; /* 1 .. ANTS_INFER_MAX_INPUT_BYTES */
    uint32_t tier;
    uint8_t req_nonce[ANTS_INFERENCE_HASH_SIZE];
} ants_infer_request_t;

/* An INFER_RESP answer body. `present == false` is the empty body
 * (declined). `commit` and `envelope` are borrowed. */
typedef struct {
    bool present;
    const uint8_t *commit; /* the §11.8 commit encoding */
    size_t commit_len;     /* 1 .. ANTS_INFERENCE_COMMIT_ENCODED_MAX */
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE];
    const uint8_t *envelope; /* the §11.8 answer envelope */
    size_t envelope_len;     /* >= 1 */
} ants_infer_answer_t;

/* ------------------------------------------------------------------------ */
/* Codec — canonical CBOR per RFC-0008 §1.1, strict decoders                */
/* ------------------------------------------------------------------------ */

/* Peek the envelope type of a bidi-RPC message. ANTS_OK with any type; an
 * error when the bytes are not an envelope head at all. */
ants_error_t ants_infer_wire_peek_type(const uint8_t *buf, size_t len, uint64_t *out_type);

ants_error_t ants_infer_wire_encode_req(uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len,
                                        uint32_t txid,
                                        const ants_infer_request_t *req);
ants_error_t ants_infer_wire_decode_req(const uint8_t *buf,
                                        size_t len,
                                        uint32_t *out_txid,
                                        ants_infer_request_t *out);

ants_error_t ants_infer_wire_encode_resp(uint8_t *buf,
                                         size_t cap,
                                         size_t *out_len,
                                         uint32_t txid,
                                         const ants_infer_answer_t *a);
/* ANTS_ERROR_BUFFER_TOO_SMALL when len > ANTS_INFER_MAX_RESP_BYTES. */
ants_error_t ants_infer_wire_decode_resp(const uint8_t *buf,
                                         size_t len,
                                         uint32_t *out_txid,
                                         ants_infer_answer_t *out);

/* ------------------------------------------------------------------------ */
/* Engine                                                                   */
/* ------------------------------------------------------------------------ */

typedef int32_t ants_infer_verdict_t;

#define ANTS_INFER_VERDICT_NO_ANSWER ((ants_infer_verdict_t)0)
#define ANTS_INFER_VERDICT_ANSWERED  ((ants_infer_verdict_t)1)
#define ANTS_INFER_VERDICT_DECLINED  ((ants_infer_verdict_t)2)
#define ANTS_INFER_VERDICT_REJECTED  ((ants_infer_verdict_t)3)

/* What the producer callback fills to answer. The engine points `envelope`
 * at a scratch buffer of `envelope_cap` bytes before the call; the callback
 * writes the envelope there and sets `envelope_len`. */
typedef struct {
    uint8_t commit[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    size_t commit_len;
    uint8_t sig[ANTS_INFERENCE_SIG_SIZE];
    uint8_t *envelope;
    size_t envelope_cap;
    size_t envelope_len;
} ants_infer_served_t;

/* Producer callback. Return true to answer (with `out` filled), false to
 * decline. Runs inside the transport callback; it may not destroy the
 * transport or the engine. `requester` is the connection's authenticated
 * peer-id. */
typedef bool (*ants_infer_serve_fn)(void *ctx,
                                    const ants_peer_id_t *requester,
                                    const ants_infer_request_t *req,
                                    ants_infer_served_t *out);

typedef struct {
    ants_transport_conn_t *conn;
    ants_peer_id_t peer_id; /* the producer, as the transport authenticated it */
    ants_infer_verdict_t verdict;
    void *cookie; /* the caller's, from ants_infer_request */
    /* ANSWERED only: the decoded commit, and the envelope bytes — valid for
     * the duration of the callback. */
    ants_inference_commit_t commit;
    const uint8_t *envelope;
    size_t envelope_len;
} ants_infer_result_t;

/* Requester callback, once per ants_infer_request that returned ANTS_OK. It
 * may call ants_transport_peer_disconnect on result->conn; it MUST NOT
 * destroy the transport or the engine. A request it makes on a connection
 * that is closing (a NO_ANSWER delivered from CONN_CLOSED) is refused with
 * ANTS_ERROR_PEER_UNREACHABLE. */
typedef void (*ants_infer_result_fn)(const ants_infer_result_t *result, void *ctx);

/* The bridge a reference producer's serve_fn uses: run
 * ants_inference_serve on `req` under `ctx` (whose producer key MUST be the
 * node's transport identity, or every requester rejects the answer), with
 * the commit's `round` = `round`, and fill `out`. Returns ANTS_OK to answer;
 * any error means decline — ANTS_ERROR_INVALID_ARG for a tier outside 1..3,
 * or whatever the serve or the commit encoding surfaced. */
ants_error_t ants_infer_serve_reference(ants_inference_t *ctx,
                                        uint64_t round,
                                        const ants_infer_request_t *req,
                                        ants_infer_served_t *out);

/* Outbound exchanges in flight at once. */
#define ANTS_INFER_MAX_OUTBOUND 16

/* Connections the producer side is sized for. MUST be >= the transport's
 * max_connections: every connection may hold 2 inbound INFER_REQs (a third
 * concurrent one from the same connection is not answered — the requester
 * times out), and the table holds 2 per connection, so a peer that never
 * finishes its requests holds only its own connection's share: exhausting
 * the producer takes exhausting the transport's connection cap first (the
 * network/attest sizing rule). */
#define ANTS_INFER_MAX_CONNS 64

#define ANTS_INFER_CTX_SIZE  16384

typedef union {
    uint8_t _opaque[ANTS_INFER_CTX_SIZE];
    uint64_t _align;
} ants_infer_t;

typedef struct {
    /* Producer side. NULL → every request is declined. */
    ants_infer_serve_fn serve_fn;
    void *serve_ctx;
    /* Requester side (may be NULL). */
    ants_infer_result_fn result_fn;
    void *result_ctx;
    /* How long an outbound request may wait for its INFER_RESP before
     * ants_infer_tick gives up on it (NO_ANSWER). 0 → no timeout. */
    uint64_t timeout_ms;
} ants_infer_config_t;

ants_error_t ants_infer_init(ants_infer_t *e, const ants_infer_config_t *config);

/* Free every per-exchange buffer, WITHOUT firing callbacks. Call after the
 * transport is destroyed (or once no more events will be forwarded).
 * Idempotent. */
void ants_infer_destroy(ants_infer_t *e);

/* Ask the producer on `conn` for an answer. `req->input` is copied. Returns
 * ANTS_ERROR_INVALID_ARG on a request that would not encode (empty or
 * oversized input), ANTS_ERROR_BUFFER_TOO_SMALL when every outbound slot is
 * busy, or the transport's error when the stream cannot be opened.
 * `now_ms` starts the request's timeout clock (any monotonic ms). */
ants_error_t ants_infer_request(ants_infer_t *e,
                                ants_transport_conn_t *conn,
                                const ants_infer_request_t *req,
                                uint64_t now_ms,
                                void *cookie);

/* Expire outbound requests older than config.timeout_ms: each is reset,
 * released, and reported NO_ANSWER. Call from the event loop's tick. */
void ants_infer_tick(ants_infer_t *e, uint64_t now_ms);

/* Forward EVERY transport event; events that are not the module's are
 * cheap no-ops. */
void ants_infer_handle_transport_event(ants_infer_t *e, const ants_transport_event_t *ev);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_INFER_H */
