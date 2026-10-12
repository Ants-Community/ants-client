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
 * After an ANSWERED exchange the requester may pay for it with a receipt
 * (§11.15): RECEIPT_OFFER (13) carries the §11.9 body, nonce =
 * BLAKE3(commit)[0:16], and the requester's signature; the producer
 * countersigns in RECEIPT_ACK (14) — at most once per nonce, only for an
 * answer it served to this requester within RECEIPT_WINDOW, at no less
 * than the reference rate, with the timestamp within RECEIPT_CLOCK_SKEW —
 * or refuses with the empty body. The producer remembers what it served
 * (ANTS_INFER_MAX_SERVED answers); filing the receipt is the caller's
 * (receipt_fn).
 *
 * Integration — forward every transport event, like the DHT and attest:
 *
 *     ants_dht_handle_transport_event(&app->dht, ev);
 *     ants_attest_handle_transport_event(&app->attest, ev, now);
 *     ants_infer_handle_transport_event(&app->infer, ev, now);
 *
 * Single-threaded, driven from inside the transport's event callback; the
 * producer callback runs synchronously there. Heap: stream handles and
 * message buffers are allocated per exchange and freed when it ends.
 */

#ifndef ANTS_INFER_H
#define ANTS_INFER_H

#include "ants_common.h"
#include "ants_inference.h"
#include "ants_reputation.h"
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

/* The receipt exchange (§11.15): types 13/14 on the same envelope. */
#define ANTS_INFER_MSG_RECEIPT_OFFER 13u
#define ANTS_INFER_MSG_RECEIPT_ACK   14u
/* RECEIPT_MAX_OFFER_BYTES (pinned): a larger RECEIPT_OFFER is malformed. */
#define ANTS_INFER_RECEIPT_MAX_OFFER_BYTES 512u
/* RECEIPT_MAX_ACK_BYTES (pinned): a larger RECEIPT_ACK is malformed. */
#define ANTS_INFER_RECEIPT_MAX_ACK_BYTES 128u
/* INFER_REF_UNCS_PER_POSITION (calibratable): the v1 reference rate, the
 * least a producer countersigns per committed position. */
#define ANTS_INFER_REF_UNCS_PER_POSITION 1000u
/* RECEIPT_WINDOW (calibratable): how long a served answer stays
 * receiptable, seconds. */
#define ANTS_INFER_RECEIPT_WINDOW_S 600u
/* RECEIPT_CLOCK_SKEW (calibratable): how far a receipt's timestamp may be
 * from the producer's clock, seconds. */
#define ANTS_INFER_RECEIPT_CLOCK_SKEW_S 300u

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

/* A RECEIPT_OFFER body: the §11.9 receipt-body encoding and the client's
 * signature over it. `body` is borrowed. */
typedef struct {
    const uint8_t *body;
    size_t body_len; /* 1 .. ANTS_REP_RECEIPT_BODY_ENCODED_MAX */
    uint8_t client_sig[ANTS_REP_SIG_SIZE];
} ants_infer_offer_t;

/* A RECEIPT_ACK body. `present == false` is the empty body (refused). */
typedef struct {
    bool present;
    uint8_t server_sig[ANTS_REP_SIG_SIZE];
} ants_infer_ack_t;

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

ants_error_t ants_infer_wire_encode_offer(uint8_t *buf,
                                          size_t cap,
                                          size_t *out_len,
                                          uint32_t txid,
                                          const ants_infer_offer_t *o);
/* ANTS_ERROR_BUFFER_TOO_SMALL when len > ANTS_INFER_RECEIPT_MAX_OFFER_BYTES. */
ants_error_t ants_infer_wire_decode_offer(const uint8_t *buf,
                                          size_t len,
                                          uint32_t *out_txid,
                                          ants_infer_offer_t *out);

ants_error_t ants_infer_wire_encode_ack(uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len,
                                        uint32_t txid,
                                        const ants_infer_ack_t *a);
ants_error_t ants_infer_wire_decode_ack(const uint8_t *buf,
                                        size_t len,
                                        uint32_t *out_txid,
                                        ants_infer_ack_t *out);

/* ------------------------------------------------------------------------ */
/* Receipts (§11.15)                                                        */
/* ------------------------------------------------------------------------ */

/* The receipt nonce of an answer: BLAKE3(commit encoding)[0:16]. */
ants_error_t ants_infer_receipt_nonce(const ants_inference_commit_t *commit,
                                      uint8_t out[ANTS_REP_NONCE_SIZE]);

/* A requester's receipt for an answered `commit`: server = the producer's
 * peer-id (the one the connection authenticated), client = the public key
 * of `client_priv`, ncs_value = ANTS_INFER_REF_UNCS_PER_POSITION ×
 * commit.length, timestamp = `now_unix`, nonce from the commit — and the
 * client signature over the body. `out->server_sig` is zeroed. */
ants_error_t ants_infer_receipt_prepare(const ants_inference_commit_t *commit,
                                        const ants_peer_id_t *server,
                                        const uint8_t client_priv[ANTS_INFERENCE_PRIVKEY_SIZE],
                                        uint64_t now_unix,
                                        ants_reputation_receipt_t *out);

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

typedef int32_t ants_infer_receipt_verdict_t;

#define ANTS_INFER_RECEIPT_NO_ANSWER ((ants_infer_receipt_verdict_t)0)
#define ANTS_INFER_RECEIPT_ACKED     ((ants_infer_receipt_verdict_t)1)
#define ANTS_INFER_RECEIPT_REFUSED   ((ants_infer_receipt_verdict_t)2)
#define ANTS_INFER_RECEIPT_REJECTED  ((ants_infer_receipt_verdict_t)3)

typedef struct {
    ants_transport_conn_t *conn;
    ants_peer_id_t peer_id; /* the producer, as the transport authenticated it */
    ants_infer_receipt_verdict_t verdict;
    void *cookie; /* the caller's, from ants_infer_offer_receipt */
    /* ACKED: the complete receipt, both signatures verified. Otherwise the
     * receipt as offered (no server signature). */
    ants_reputation_receipt_t receipt;
} ants_infer_receipt_result_t;

/* Requester callback, once per ants_infer_offer_receipt that returned
 * ANTS_OK. Same restrictions as ants_infer_result_fn. */
typedef void (*ants_infer_receipt_result_fn)(const ants_infer_receipt_result_t *result, void *ctx);

/* Producer: sign `msg` with the node identity (the key whose public half is
 * config.local_id). */
typedef ants_error_t (*ants_infer_sign_fn)(void *ctx,
                                           const uint8_t *msg,
                                           size_t msg_len,
                                           uint8_t out_sig[ANTS_REP_SIG_SIZE]);

/* Producer: a receipt was countersigned and must be filed in the node's
 * receipt bag. Called before the ACK is sent. */
typedef void (*ants_infer_receipt_fn)(void *ctx, const ants_reputation_receipt_t *receipt);

/* Producer: has the node ever filed a receipt with this nonce? The served
 * table forgets answers after RECEIPT_WINDOW, but the commit of an answer is
 * deterministic (a replayed INFER_REQ is answered with the same commit), so
 * "at most one receipt per nonce" needs the node's whole history: the bag. */
typedef bool (*ants_infer_receipt_paid_fn)(void *ctx, const uint8_t nonce[ANTS_REP_NONCE_SIZE]);

/* Answers the producer remembers as receiptable (RECEIPT_WINDOW). A nonce
 * is recorded once, for the first requester it was served to. When the
 * table is full, answers already paid are forgotten first, then the oldest
 * — whose receipt can then no longer be countersigned. */
#define ANTS_INFER_MAX_SERVED 256

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

#define ANTS_INFER_CTX_SIZE  65536

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

    /* Receipts, producer side (§11.15). `receipt_sign_fn` NULL → every
     * RECEIPT_OFFER is refused. `local_id` is the node's peer-id: the
     * `server` an offer must name. */
    ants_peer_id_t local_id;
    ants_infer_sign_fn receipt_sign_fn;
    void *receipt_sign_ctx;
    ants_infer_receipt_fn receipt_fn;
    void *receipt_ctx;
    /* NULL → only the served table is consulted (a nonce can then be paid
     * again once its entry is gone). */
    ants_infer_receipt_paid_fn receipt_paid_fn;
    void *receipt_paid_ctx;
    /* Receipts, requester side (may be NULL). */
    ants_infer_receipt_result_fn receipt_result_fn;
    void *receipt_result_ctx;
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

/* Offer `receipt` (body + client_sig, as ants_infer_receipt_prepare makes
 * it) to the producer on `conn`. Same errors and timeout as
 * ants_infer_request; the verdict arrives through receipt_result_fn. */
ants_error_t ants_infer_offer_receipt(ants_infer_t *e,
                                      ants_transport_conn_t *conn,
                                      const ants_reputation_receipt_t *receipt,
                                      uint64_t now_ms,
                                      void *cookie);

/* Expire outbound requests older than config.timeout_ms: each is reset,
 * released, and reported NO_ANSWER. Call from the event loop's tick. */
void ants_infer_tick(ants_infer_t *e, uint64_t now_ms);

/* Forward EVERY transport event; events that are not the module's are
 * cheap no-ops. `now_unix` is the node's wall clock in seconds: it stamps
 * served answers and checks a receipt's window and timestamp. */
void ants_infer_handle_transport_event(ants_infer_t *e,
                                       const ants_transport_event_t *ev,
                                       uint64_t now_unix);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_INFER_H */
