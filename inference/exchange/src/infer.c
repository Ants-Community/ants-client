/*
 * infer.c — the inference exchange engine (RFC-0008 §11.14) and the
 * receipt exchange that pays for an answer (§11.15).
 *
 * Three fixed tables live in the caller's opaque buffer:
 *   - outbound exchanges: our INFER_REQ or RECEIPT_OFFER in flight on a
 *     stream we opened (heap stream handle, a copy of what we asked for the
 *     check, a response buffer allocated on first byte — the DHT RPC
 *     lifetime);
 *   - served answers: what this node answered, to whom, and when — the
 *     only answers it will countersign a receipt for, once each;
 *   - inbound streams: peer-initiated bidi streams. Every such stream is
 *     also seen by the DHT server and network/attest, so a stream is first
 *     CLASSIFIED from its envelope head (a few bytes) and released at once
 *     when it is not an INFER_REQ — a peer's concurrent DHT RPCs therefore
 *     never sit in this table. Release is silent: the stream may be a
 *     sibling's, so it is never reset.
 */

#include "ants_infer.h"

#include "ants_crypto.h"
#include "ants_inference.h"
#include "ants_reputation.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Inbound INFER_REQs one connection may hold at once, so one peer cannot
 * crowd out everyone else's requests — and the table holds that many for
 * every connection the transport can admit (see ANTS_INFER_MAX_CONNS). */
#define INFER_MAX_INBOUND_PER_CONN 2
#define INFER_MAX_INBOUND          (INFER_MAX_INBOUND_PER_CONN * ANTS_INFER_MAX_CONNS)
/* Bytes that always contain a complete envelope head: map(1) + key 0 (1)
 * + a one-byte type (1) + key 1 (1) + txid (<= 5) + key 2 (1). Any longer
 * type number is not ours. */
#define INFER_HEAD_PREFIX 10
/* Room the producer leaves in INFER_RESP for the envelope head, the commit
 * and the signature (≈ 290 bytes at most). */
#define INFER_RESP_OVERHEAD 512

enum { OUT_INFER = 0, OUT_RECEIPT = 1 };

typedef char infer_nonce_size_check[(ANTS_REP_NONCE_SIZE <= ANTS_INFERENCE_HASH_SIZE) ? 1 : -1];

struct infer_outbound {
    bool in_use;
    uint8_t kind; /* OUT_INFER | OUT_RECEIPT */
    /* Local allocation failure: no verdict (it says nothing about the
     * peer). The slot stays until the stream ends — freeing the stream
     * handle mid-stream would leave the transport writing into it. */
    bool local_oom;
    bool oversized;
    uint32_t txid;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* heap, ours */
    void *cookie;
    uint64_t started_ms;
    uint8_t *input; /* heap copy of the request input */
    size_t input_len;
    uint32_t tier;
    uint8_t req_nonce[ANTS_INFERENCE_HASH_SIZE];
    ants_reputation_receipt_t receipt; /* OUT_RECEIPT: what we offered */
    uint8_t *buf;                      /* heap, lazily: ANTS_INFER_MAX_RESP_BYTES */
    size_t len;
};

/* An answer this node served: receiptable once, by its requester, within
 * RECEIPT_WINDOW. */
struct infer_served {
    bool in_use;
    bool receipted;
    uint8_t nonce[ANTS_REP_NONCE_SIZE];
    uint8_t client[ANTS_REP_PEER_ID_SIZE];
    uint32_t length;
    uint64_t served_at;
};

struct infer_inbound {
    bool in_use;
    bool claimed; /* the head said INFER_REQ or RECEIPT_OFFER */
    uint8_t _pad[2];
    uint32_t type; /* once claimed */
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* the transport's */
    uint8_t *buf;                    /* heap once claimed: inbound_cap(type) */
    size_t len;
    uint8_t head[INFER_HEAD_PREFIX]; /* before the claim */
};

struct infer_state {
    ants_infer_config_t cfg;
    /* The connection whose CONN_CLOSED is being delivered: a request on it
     * from inside a NO_ANSWER callback is refused (it would bind a stream
     * to a connection about to be freed). */
    const ants_transport_conn_t *closing;
    uint64_t now_unix; /* the clock of the event being handled */
    uint32_t next_txid;
    uint8_t _pad[4];
    struct infer_outbound out[ANTS_INFER_MAX_OUTBOUND];
    struct infer_inbound in[INFER_MAX_INBOUND];
    struct infer_served served[ANTS_INFER_MAX_SERVED];
};

typedef char infer_state_fits_opaque
    [(sizeof(struct infer_state) <= sizeof(((ants_infer_t *)0)->_opaque)) ? 1 : -1];

static struct infer_state *get_state(ants_infer_t *e)
{
    return (struct infer_state *)(void *)e->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_infer_init(ants_infer_t *e, const ants_infer_config_t *config)
{
    struct infer_state *s;
    if (e == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(e->_opaque, 0, sizeof e->_opaque);
    s = get_state(e);
    s->cfg = *config;
    s->next_txid = 1;
    return ANTS_OK;
}

static void outbound_release(struct infer_outbound *o)
{
    free(o->buf);
    free(o->input);
    free(o->stream);
    memset(o, 0, sizeof *o);
}

static void inbound_release(struct infer_inbound *in)
{
    free(in->buf);
    memset(in, 0, sizeof *in);
}

void ants_infer_destroy(ants_infer_t *e)
{
    struct infer_state *s;
    size_t i;
    if (e == NULL) {
        return;
    }
    s = get_state(e);
    for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
        if (s->out[i].in_use) {
            outbound_release(&s->out[i]);
        }
    }
    for (i = 0; i < INFER_MAX_INBOUND; i++) {
        if (s->in[i].in_use) {
            inbound_release(&s->in[i]);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Outbound: our request, their answer                                      */
/* ------------------------------------------------------------------------ */

static void emit(struct infer_state *s, const ants_infer_result_t *r)
{
    if (s->cfg.result_fn != NULL) {
        s->cfg.result_fn(r, s->cfg.result_ctx);
    }
}

static void emit_receipt(struct infer_state *s, const ants_infer_receipt_result_t *r)
{
    if (s->cfg.receipt_result_fn != NULL) {
        s->cfg.receipt_result_fn(r, s->cfg.receipt_result_ctx);
    }
}

/* Report NO_ANSWER for `o` (the peer-id may be unknown by now). */
static void emit_no_answer(struct infer_state *s, const struct infer_outbound *o)
{
    ants_infer_result_t r;
    if (o->kind == OUT_RECEIPT) {
        ants_infer_receipt_result_t rr;
        memset(&rr, 0, sizeof rr);
        rr.conn = o->conn;
        (void)ants_transport_conn_peer_id(o->conn, &rr.peer_id);
        rr.verdict = ANTS_INFER_RECEIPT_NO_ANSWER;
        rr.cookie = o->cookie;
        rr.receipt = o->receipt;
        emit_receipt(s, &rr);
        return;
    }
    memset(&r, 0, sizeof r);
    r.conn = o->conn;
    (void)ants_transport_conn_peer_id(o->conn, &r.peer_id);
    r.verdict = ANTS_INFER_VERDICT_NO_ANSWER;
    r.cookie = o->cookie;
    emit(s, &r);
}

/* A free outbound slot for `conn`, or NULL (with *err set). */
static struct infer_outbound *
outbound_alloc(struct infer_state *s, const ants_transport_conn_t *conn, ants_error_t *err)
{
    size_t i;
    if (conn == s->closing) {
        *err = ANTS_ERROR_PEER_UNREACHABLE;
        return NULL;
    }
    for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
        if (!s->out[i].in_use) {
            return &s->out[i];
        }
    }
    *err = ANTS_ERROR_BUFFER_TOO_SMALL;
    return NULL;
}

static uint32_t next_txid(struct infer_state *s)
{
    uint32_t txid = s->next_txid++;
    if (s->next_txid == 0) {
        s->next_txid = 1;
    }
    return txid;
}

/* Open a stream for the prepared slot `o` and send `msg` with FIN. The slot
 * is claimed before the open, so a nested event finds it; on failure it is
 * released. */
static ants_error_t outbound_launch(struct infer_outbound *o,
                                    ants_transport_conn_t *conn,
                                    uint32_t txid,
                                    const uint8_t *msg,
                                    size_t msg_len,
                                    uint64_t now_ms,
                                    void *cookie)
{
    ants_error_t err;
    ants_transport_stream_t *stream =
        (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
    if (stream == NULL) {
        outbound_release(o);
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memset(stream, 0, sizeof *stream);
    o->in_use = true;
    o->txid = txid;
    o->conn = conn;
    o->stream = stream;
    o->cookie = cookie;
    o->started_ms = now_ms;
    if ((err = ants_transport_open_bidi_stream(conn, stream)) != ANTS_OK ||
        (err = ants_transport_stream_send(stream, msg, msg_len, true)) != ANTS_OK) {
        /* A no-op when the open itself failed. */
        (void)ants_transport_stream_unbind(stream);
        outbound_release(o);
        return err;
    }
    return ANTS_OK;
}

ants_error_t ants_infer_request(ants_infer_t *e,
                                ants_transport_conn_t *conn,
                                const ants_infer_request_t *req,
                                uint64_t now_ms,
                                void *cookie)
{
    struct infer_state *s;
    struct infer_outbound *o;
    uint8_t *msg;
    size_t msg_len;
    uint32_t txid;
    ants_error_t err = ANTS_OK;

    if (e == NULL || conn == NULL || req == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = get_state(e);
    if ((o = outbound_alloc(s, conn, &err)) == NULL) {
        return err;
    }
    txid = next_txid(s);
    msg = (uint8_t *)malloc(ANTS_INFER_MAX_REQ_BYTES);
    if (msg == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    err = ants_infer_wire_encode_req(msg, ANTS_INFER_MAX_REQ_BYTES, &msg_len, txid, req);
    if (err != ANTS_OK) {
        free(msg);
        return err;
    }
    o->input = (uint8_t *)malloc(req->input_len);
    if (o->input == NULL) {
        free(msg);
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(o->input, req->input, req->input_len);
    o->input_len = req->input_len;
    o->tier = req->tier;
    memcpy(o->req_nonce, req->req_nonce, sizeof o->req_nonce);
    o->kind = OUT_INFER;
    err = outbound_launch(o, conn, txid, msg, msg_len, now_ms, cookie);
    free(msg);
    return err;
}

ants_error_t ants_infer_offer_receipt(ants_infer_t *e,
                                      ants_transport_conn_t *conn,
                                      const ants_reputation_receipt_t *receipt,
                                      uint64_t now_ms,
                                      void *cookie)
{
    struct infer_state *s;
    struct infer_outbound *o;
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    uint8_t msg[ANTS_INFER_RECEIPT_MAX_OFFER_BYTES];
    size_t body_len;
    size_t msg_len;
    ants_infer_offer_t offer;
    uint32_t txid;
    ants_error_t err = ANTS_OK;

    if (e == NULL || conn == NULL || receipt == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = get_state(e);
    if ((o = outbound_alloc(s, conn, &err)) == NULL) {
        return err;
    }
    if ((err = ants_reputation_receipt_body_encode(receipt, body, sizeof body, &body_len)) !=
        ANTS_OK) {
        return err;
    }
    txid = next_txid(s);
    memset(&offer, 0, sizeof offer);
    offer.body = body;
    offer.body_len = body_len;
    memcpy(offer.client_sig, receipt->client_sig, sizeof offer.client_sig);
    if ((err = ants_infer_wire_encode_offer(msg, sizeof msg, &msg_len, txid, &offer)) != ANTS_OK) {
        return err;
    }
    o->kind = OUT_RECEIPT;
    o->receipt = *receipt;
    memset(o->receipt.server_sig, 0, sizeof o->receipt.server_sig);
    return outbound_launch(o, conn, txid, msg, msg_len, now_ms, cookie);
}

static struct infer_outbound *outbound_by_stream(struct infer_state *s,
                                                 const ants_transport_stream_t *stream)
{
    size_t i;
    for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
        if (s->out[i].in_use && s->out[i].stream == stream) {
            return &s->out[i];
        }
    }
    return NULL;
}

/* Turn a complete RECEIPT_ACK into a verdict. */
static void receipt_conclude(struct infer_state *s, struct infer_outbound *o)
{
    ants_infer_receipt_result_t r;
    ants_infer_ack_t a;
    uint32_t txid = 0;
    bool ok = false;
    ants_error_t err = ANTS_ERROR_MALFORMED;

    memset(&r, 0, sizeof r);
    r.conn = o->conn;
    r.cookie = o->cookie;
    r.receipt = o->receipt;
    if (ants_transport_conn_peer_id(o->conn, &r.peer_id) != ANTS_OK) {
        r.verdict = ANTS_INFER_RECEIPT_NO_ANSWER;
        emit_receipt(s, &r);
        return;
    }
    if (o->buf != NULL && !o->oversized) {
        err = ants_infer_wire_decode_ack(o->buf, o->len, &txid, &a);
    }
    if (err != ANTS_OK || txid != o->txid) {
        r.verdict = ANTS_INFER_RECEIPT_REJECTED;
    } else if (!a.present) {
        r.verdict = ANTS_INFER_RECEIPT_REFUSED;
    } else {
        /* The countersignature must make the receipt whole: both signatures
         * over the same body, the server's by the key this connection
         * authenticated (the receipt names it as `server`). */
        memcpy(r.receipt.server_sig, a.server_sig, sizeof a.server_sig);
        if (memcmp(r.receipt.server, r.peer_id.bytes, sizeof r.receipt.server) == 0 &&
            ants_reputation_receipt_verify(&r.receipt, &ok) == ANTS_OK && ok) {
            r.verdict = ANTS_INFER_RECEIPT_ACKED;
        } else {
            memset(r.receipt.server_sig, 0, sizeof r.receipt.server_sig);
            r.verdict = ANTS_INFER_RECEIPT_REJECTED;
        }
    }
    emit_receipt(s, &r);
}

/* Turn a complete INFER_RESP into a verdict. */
static void infer_conclude(struct infer_state *s, struct infer_outbound *o)
{
    ants_infer_result_t r;
    ants_infer_answer_t a;
    uint32_t txid = 0;
    bool ok = false;
    ants_error_t err = ANTS_ERROR_MALFORMED;

    memset(&r, 0, sizeof r);
    r.conn = o->conn;
    r.cookie = o->cookie;
    /* The key the commit must verify under is the one the TLS handshake on
     * this connection authenticated — never one claimed on the wire. */
    if (ants_transport_conn_peer_id(o->conn, &r.peer_id) != ANTS_OK) {
        r.verdict = ANTS_INFER_VERDICT_NO_ANSWER; /* conn already torn down */
        emit(s, &r);
        return;
    }
    if (o->buf != NULL && !o->oversized) {
        err = ants_infer_wire_decode_resp(o->buf, o->len, &txid, &a);
    }
    if (err != ANTS_OK || txid != o->txid) {
        r.verdict = ANTS_INFER_VERDICT_REJECTED; /* spoke the exchange malformed */
    } else if (!a.present) {
        r.verdict = ANTS_INFER_VERDICT_DECLINED;
    } else if (o->tier > UINT8_MAX ||
               ants_inference_answer_check(a.commit,
                                           a.commit_len,
                                           a.sig,
                                           r.peer_id.bytes,
                                           a.envelope,
                                           a.envelope_len,
                                           o->input,
                                           o->input_len,
                                           (uint8_t)o->tier,
                                           o->req_nonce,
                                           &r.commit,
                                           &ok) != ANTS_OK ||
               !ok) {
        r.verdict = ANTS_INFER_VERDICT_REJECTED;
    } else {
        r.verdict = ANTS_INFER_VERDICT_ANSWERED;
        r.envelope = a.envelope;
        r.envelope_len = a.envelope_len;
    }
    emit(s, &r);
}

static void outbound_conclude(struct infer_state *s, struct infer_outbound *o)
{
    if (o->kind == OUT_RECEIPT) {
        receipt_conclude(s, o);
    } else {
        infer_conclude(s, o);
    }
}

/* The most an answer to `o` may carry: an INFER_RESP, or a RECEIPT_ACK
 * (≈ 75 bytes when countersigned). */
static size_t outbound_cap(const struct infer_outbound *o)
{
    return o->kind == OUT_RECEIPT ? (size_t)ANTS_INFER_RECEIPT_MAX_ACK_BYTES
                                  : (size_t)ANTS_INFER_MAX_RESP_BYTES;
}

static void
outbound_on_event(struct infer_state *s, struct infer_outbound *o, const ants_transport_event_t *ev)
{
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        if (ev->payload == NULL || ev->payload_len == 0 || o->oversized || o->local_oom) {
            return;
        }
        if (o->buf == NULL) {
            o->buf = (uint8_t *)malloc(outbound_cap(o));
            if (o->buf == NULL) {
                o->local_oom = true;
                return;
            }
        }
        if (ev->payload_len > outbound_cap(o) - o->len) {
            /* Oversized: rejected without decoding, at FIN. */
            free(o->buf);
            o->buf = NULL;
            o->oversized = true;
            return;
        }
        memcpy(o->buf + o->len, ev->payload, ev->payload_len);
        o->len += ev->payload_len;
        return;
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        if (o->local_oom) {
            emit_no_answer(s, o);
        } else {
            outbound_conclude(s, o);
        }
        outbound_release(o);
        return;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        emit_no_answer(s, o);
        outbound_release(o);
        return;
    default:
        return;
    }
}

void ants_infer_tick(ants_infer_t *e, uint64_t now_ms)
{
    struct infer_state *s;
    size_t i;
    if (e == NULL) {
        return;
    }
    s = get_state(e);
    if (s->cfg.timeout_ms == 0) {
        return;
    }
    for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
        struct infer_outbound *o = &s->out[i];
        if (!o->in_use || now_ms < o->started_ms || now_ms - o->started_ms < s->cfg.timeout_ms) {
            continue;
        }
        /* Give up: tell the peer, detach the handle from the transport
         * before freeing it, then report. */
        (void)ants_transport_stream_reset(o->stream, 3);
        (void)ants_transport_stream_unbind(o->stream);
        emit_no_answer(s, o);
        outbound_release(o);
    }
}

/* ------------------------------------------------------------------------ */
/* Inbound: their request, our answer                                       */
/* ------------------------------------------------------------------------ */

static struct infer_inbound *inbound_by_stream(struct infer_state *s,
                                               const ants_transport_stream_t *stream)
{
    size_t i;
    for (i = 0; i < INFER_MAX_INBOUND; i++) {
        if (s->in[i].in_use && s->in[i].stream == stream) {
            return &s->in[i];
        }
    }
    return NULL;
}

/* The most a claimed inbound stream may carry, by envelope type. */
static size_t inbound_cap(uint32_t type)
{
    return type == ANTS_INFER_MSG_RECEIPT_OFFER ? ANTS_INFER_RECEIPT_MAX_OFFER_BYTES
                                                : ANTS_INFER_MAX_REQ_BYTES;
}

/* ---- served answers ------------------------------------------------------ */

static bool served_live(const struct infer_served *v, uint64_t now)
{
    return v->in_use && now >= v->served_at && now - v->served_at <= ANTS_INFER_RECEIPT_WINDOW_S;
}

/* Remember an answer we just sent: its receipt nonce, its requester, its
 * length — once per nonce. */
static void served_record(struct infer_state *s,
                          const ants_peer_id_t *client,
                          const uint8_t *commit,
                          size_t commit_len)
{
    ants_inference_commit_t c;
    uint8_t h[ANTS_INFERENCE_HASH_SIZE];
    struct infer_served *slot = NULL;
    size_t i;
    if (ants_inference_commit_decode(commit, commit_len, &c) != ANTS_OK ||
        ants_blake3_hash(commit, commit_len, h) != ANTS_OK) {
        return;
    }
    /* One entry per nonce: a replayed request is answered with the same
     * commit, and the answer belongs to whoever it was served to first. */
    for (i = 0; i < ANTS_INFER_MAX_SERVED; i++) {
        struct infer_served *v = &s->served[i];
        if (served_live(v, s->now_unix) && memcmp(v->nonce, h, sizeof v->nonce) == 0) {
            return;
        }
    }
    /* A free or expired slot; else an answer already paid; else the oldest. */
    for (i = 0; i < ANTS_INFER_MAX_SERVED && slot == NULL; i++) {
        if (!served_live(&s->served[i], s->now_unix)) {
            slot = &s->served[i];
        }
    }
    for (i = 0; i < ANTS_INFER_MAX_SERVED && slot == NULL; i++) {
        if (s->served[i].receipted) {
            slot = &s->served[i];
        }
    }
    /* Every entry is live and unpaid: forget the oldest. */
    if (slot == NULL) {
        slot = &s->served[0];
        for (i = 1; i < ANTS_INFER_MAX_SERVED; i++) {
            if (s->served[i].served_at < slot->served_at) {
                slot = &s->served[i];
            }
        }
    }
    memset(slot, 0, sizeof *slot);
    slot->in_use = true;
    memcpy(slot->nonce, h, sizeof slot->nonce);
    memcpy(slot->client, client->bytes, sizeof slot->client);
    slot->length = c.length;
    slot->served_at = s->now_unix;
}

static struct infer_served *
served_find(struct infer_state *s, const uint8_t nonce[ANTS_REP_NONCE_SIZE], const uint8_t *client)
{
    size_t i;
    for (i = 0; i < ANTS_INFER_MAX_SERVED; i++) {
        struct infer_served *v = &s->served[i];
        if (served_live(v, s->now_unix) && memcmp(v->nonce, nonce, sizeof v->nonce) == 0 &&
            memcmp(v->client, client, sizeof v->client) == 0) {
            return v;
        }
    }
    return NULL;
}

/* The §11.15 producer rules. On success the countersignature is written to
 * `out_sig`, the served answer is marked receipted, and the receipt filed. */
static bool offer_countersign(struct infer_state *s,
                              const ants_transport_conn_t *conn,
                              const ants_infer_offer_t *offer,
                              uint8_t out_sig[ANTS_REP_SIG_SIZE])
{
    ants_reputation_receipt_t r;
    ants_peer_id_t client;
    struct infer_served *v;
    uint64_t skew;

    if (s->cfg.receipt_sign_fn == NULL || ants_transport_conn_peer_id(conn, &client) != ANTS_OK) {
        return false;
    }
    /* 1. a canonical body naming us as server and this connection's peer as
     *    client. The strict decoder re-encodes to exactly these bytes, so a
     *    signature over them is a signature over the body. */
    if (ants_reputation_receipt_body_decode(offer->body, offer->body_len, &r) != ANTS_OK ||
        memcmp(r.server, s->cfg.local_id.bytes, sizeof r.server) != 0 ||
        memcmp(r.client, client.bytes, sizeof r.client) != 0) {
        return false;
    }
    /* 2. the client's signature */
    if (ants_ed25519_verify(r.client, offer->body, offer->body_len, offer->client_sig) != ANTS_OK) {
        return false;
    }
    /* 3. an answer we served this client, in the window, not yet paid */
    v = served_find(s, r.nonce, r.client);
    if (v == NULL || v->receipted) {
        return false;
    }
    if (s->cfg.receipt_paid_fn != NULL &&
        s->cfg.receipt_paid_fn(s->cfg.receipt_paid_ctx, r.nonce)) {
        v->receipted = true; /* paid before this entry existed */
        return false;
    }
    /* 4. at least the reference rate (length <= 64: no overflow) */
    if (r.ncs_value < (uint64_t)ANTS_INFER_REF_UNCS_PER_POSITION * v->length) {
        return false;
    }
    /* 5. the timestamp near our clock */
    skew = r.timestamp_unix_s > s->now_unix ? r.timestamp_unix_s - s->now_unix
                                            : s->now_unix - r.timestamp_unix_s;
    if (skew > ANTS_INFER_RECEIPT_CLOCK_SKEW_S) {
        return false;
    }
    if (s->cfg.receipt_sign_fn(s->cfg.receipt_sign_ctx, offer->body, offer->body_len, out_sig) !=
        ANTS_OK) {
        return false;
    }
    v->receipted = true;
    memcpy(r.client_sig, offer->client_sig, sizeof r.client_sig);
    memcpy(r.server_sig, out_sig, sizeof r.server_sig);
    if (s->cfg.receipt_fn != NULL) {
        s->cfg.receipt_fn(s->cfg.receipt_ctx, &r);
    }
    return true;
}

/* Answer a complete RECEIPT_OFFER. */
static void inbound_offer(struct infer_state *s, struct infer_inbound *in)
{
    ants_infer_offer_t offer;
    ants_infer_ack_t ack;
    uint8_t out[128];
    size_t out_len;
    uint32_t txid;

    if (ants_infer_wire_decode_offer(in->buf, in->len, &txid, &offer) != ANTS_OK) {
        (void)ants_transport_stream_reset(in->stream, 1); /* ours, malformed */
        return;
    }
    memset(&ack, 0, sizeof ack);
    ack.present = offer_countersign(s, in->conn, &offer, ack.server_sig);
    if (ants_infer_wire_encode_ack(out, sizeof out, &out_len, txid, &ack) == ANTS_OK) {
        (void)ants_transport_stream_send(in->stream, out, out_len, true);
    } else {
        (void)ants_transport_stream_reset(in->stream, 2);
    }
}

/* Answer a complete INFER_REQ. */
static void inbound_answer(struct infer_state *s, struct infer_inbound *in)
{
    ants_infer_request_t req;
    ants_infer_answer_t a;
    ants_infer_served_t served;
    ants_peer_id_t requester;
    uint32_t txid;
    uint8_t *out;
    size_t out_len;
    bool answer = false;
    ants_error_t err;

    if (ants_infer_wire_decode_req(in->buf, in->len, &txid, &req) != ANTS_OK) {
        (void)ants_transport_stream_reset(in->stream, 1); /* ours, malformed */
        return;
    }
    out = (uint8_t *)malloc(ANTS_INFER_MAX_RESP_BYTES);
    memset(&served, 0, sizeof served);
    served.envelope = (uint8_t *)malloc(ANTS_INFER_MAX_RESP_BYTES - INFER_RESP_OVERHEAD);
    if (out == NULL || served.envelope == NULL) {
        free(out);
        free(served.envelope);
        (void)ants_transport_stream_reset(in->stream, 2);
        return;
    }
    served.envelope_cap = ANTS_INFER_MAX_RESP_BYTES - INFER_RESP_OVERHEAD;

    memset(&a, 0, sizeof a);
    if (s->cfg.serve_fn != NULL && ants_transport_conn_peer_id(in->conn, &requester) == ANTS_OK) {
        answer = s->cfg.serve_fn(s->cfg.serve_ctx, &requester, &req, &served);
    }
    if (answer) {
        a.present = true;
        a.commit = served.commit;
        a.commit_len = served.commit_len;
        memcpy(a.sig, served.sig, sizeof a.sig);
        a.envelope = served.envelope;
        a.envelope_len = served.envelope_len;
    }
    err = ants_infer_wire_encode_resp(
        out, ANTS_INFER_MAX_RESP_BYTES, &out_len, txid, answer ? &a : NULL);
    if (err != ANTS_OK && answer) {
        /* The callback's answer would not encode: decline instead. */
        err = ants_infer_wire_encode_resp(out, ANTS_INFER_MAX_RESP_BYTES, &out_len, txid, NULL);
    }
    if (err == ANTS_OK) {
        if (answer && a.present) {
            served_record(s, &requester, served.commit, served.commit_len);
        }
        (void)ants_transport_stream_send(in->stream, out, out_len, true);
    } else {
        (void)ants_transport_stream_reset(in->stream, 2);
    }
    free(out);
    free(served.envelope);
}

/* Classify an unclaimed stream from its head. Returns false when the slot
 * was released (not ours, or no memory). */
static bool inbound_classify(struct infer_inbound *in, bool at_fin)
{
    uint64_t type;
    if (in->len < INFER_HEAD_PREFIX && !at_fin) {
        return true; /* need more bytes */
    }
    if (ants_infer_wire_peek_type(in->head, in->len, &type) != ANTS_OK ||
        (type != ANTS_INFER_MSG_REQ && type != ANTS_INFER_MSG_RECEIPT_OFFER)) {
        inbound_release(in); /* a sibling's stream — leave it alone */
        return false;
    }
    in->type = (uint32_t)type;
    in->buf = (uint8_t *)malloc(inbound_cap(in->type));
    if (in->buf == NULL) {
        (void)ants_transport_stream_reset(in->stream, 2);
        inbound_release(in);
        return false;
    }
    memcpy(in->buf, in->head, in->len);
    in->claimed = true;
    return true;
}

static void inbound_on_event(struct infer_state *s, const ants_transport_event_t *ev)
{
    struct infer_inbound *in;
    size_t i;

    if (ev->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        size_t held = 0;
        if (!ants_transport_stream_is_bidi(ev->stream) || inbound_by_stream(s, ev->stream)) {
            return;
        }
        for (i = 0; i < INFER_MAX_INBOUND; i++) {
            if (s->in[i].in_use && s->in[i].conn == ev->conn) {
                held++;
            }
        }
        if (held >= INFER_MAX_INBOUND_PER_CONN) {
            return; /* this peer already has its share in flight */
        }
        for (i = 0; i < INFER_MAX_INBOUND; i++) {
            if (!s->in[i].in_use) {
                s->in[i].in_use = true;
                s->in[i].conn = ev->conn;
                s->in[i].stream = ev->stream;
                return;
            }
        }
        return; /* full: the requester times out */
    }
    in = inbound_by_stream(s, ev->stream);
    if (in == NULL) {
        return;
    }
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE: {
        const uint8_t *p = ev->payload;
        size_t n = ev->payload_len;
        if (p == NULL || n == 0) {
            return;
        }
        if (!in->claimed) {
            size_t take = INFER_HEAD_PREFIX - in->len;
            if (take > n) {
                take = n;
            }
            memcpy(in->head + in->len, p, take);
            in->len += take;
            p += take;
            n -= take;
            if (!inbound_classify(in, false)) {
                return;
            }
            if (!in->claimed) {
                return; /* still short of a full head */
            }
        }
        if (n > inbound_cap(in->type) - in->len) {
            /* Larger than any conformant message of its type: ours and
             * malformed. */
            (void)ants_transport_stream_reset(in->stream, 1);
            inbound_release(in);
            return;
        }
        memcpy(in->buf + in->len, p, n);
        in->len += n;
        return;
    }
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        if (!in->claimed && !inbound_classify(in, true)) {
            return;
        }
        if (in->type == ANTS_INFER_MSG_RECEIPT_OFFER) {
            inbound_offer(s, in);
        } else {
            inbound_answer(s, in);
        }
        inbound_release(in);
        return;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        inbound_release(in);
        return;
    default:
        return;
    }
}

/* ------------------------------------------------------------------------ */
/* Event entry point                                                        */
/* ------------------------------------------------------------------------ */

void ants_infer_handle_transport_event(ants_infer_t *e,
                                       const ants_transport_event_t *ev,
                                       uint64_t now_unix)
{
    struct infer_state *s;
    struct infer_outbound *o;
    size_t i;
    if (e == NULL || ev == NULL) {
        return;
    }
    s = get_state(e);
    s->now_unix = now_unix;
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        s->closing = ev->conn;
        for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
            if (s->out[i].in_use && s->out[i].conn == ev->conn) {
                emit_no_answer(s, &s->out[i]);
                outbound_release(&s->out[i]);
            }
        }
        for (i = 0; i < INFER_MAX_INBOUND; i++) {
            if (s->in[i].in_use && s->in[i].conn == ev->conn) {
                inbound_release(&s->in[i]);
            }
        }
        s->closing = NULL;
        return;
    }
    if (ev->stream == NULL) {
        return;
    }
    o = outbound_by_stream(s, ev->stream);
    if (o != NULL) {
        outbound_on_event(s, o, ev);
        return;
    }
    inbound_on_event(s, ev);
}

/* ------------------------------------------------------------------------ */
/* Reference producer bridge                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_infer_serve_reference(ants_inference_t *ctx,
                                        uint64_t round,
                                        const ants_infer_request_t *req,
                                        ants_infer_served_t *out)
{
    ants_inference_request_t ireq;
    ants_inference_response_t iresp;
    ants_error_t err;
    if (ctx == NULL || req == NULL || out == NULL || out->envelope == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (req->tier < ANTS_INFERENCE_TIER_1 || req->tier > ANTS_INFERENCE_TIER_3) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(&ireq, 0, sizeof ireq);
    memset(&iresp, 0, sizeof iresp);
    ireq.input = req->input;
    ireq.input_len = req->input_len;
    ireq.tier = (uint8_t)req->tier;
    memcpy(ireq.req_nonce, req->req_nonce, sizeof ireq.req_nonce);
    ireq.round = round;
    iresp.answer_buf = out->envelope;
    iresp.answer_cap = out->envelope_cap;
    if ((err = ants_inference_serve(ctx, &ireq, &iresp)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_inference_commit_encode(
             &iresp.commit, out->commit, sizeof out->commit, &out->commit_len)) != ANTS_OK) {
        return err;
    }
    memcpy(out->sig, iresp.commit_sig, sizeof out->sig);
    out->envelope_len = iresp.answer_len;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Receipt helpers                                                          */
/* ------------------------------------------------------------------------ */

ants_error_t ants_infer_receipt_nonce(const ants_inference_commit_t *commit,
                                      uint8_t out[ANTS_REP_NONCE_SIZE])
{
    uint8_t enc[ANTS_INFERENCE_COMMIT_ENCODED_MAX];
    uint8_t h[ANTS_INFERENCE_HASH_SIZE];
    size_t len;
    ants_error_t err;
    if (commit == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((err = ants_inference_commit_encode(commit, enc, sizeof enc, &len)) != ANTS_OK ||
        (err = ants_blake3_hash(enc, len, h)) != ANTS_OK) {
        return err;
    }
    memcpy(out, h, ANTS_REP_NONCE_SIZE);
    return ANTS_OK;
}

ants_error_t ants_infer_receipt_prepare(const ants_inference_commit_t *commit,
                                        const ants_peer_id_t *server,
                                        const uint8_t client_priv[ANTS_INFERENCE_PRIVKEY_SIZE],
                                        uint64_t now_unix,
                                        ants_reputation_receipt_t *out)
{
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len;
    ants_error_t err;
    if (commit == NULL || server == NULL || client_priv == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);
    memcpy(out->server, server->bytes, sizeof out->server);
    if ((err = ants_ed25519_pubkey_from_priv(client_priv, out->client)) != ANTS_OK ||
        (err = ants_infer_receipt_nonce(commit, out->nonce)) != ANTS_OK) {
        return err;
    }
    out->ncs_value = (uint64_t)ANTS_INFER_REF_UNCS_PER_POSITION * commit->length;
    out->timestamp_unix_s = now_unix;
    if ((err = ants_reputation_receipt_body_encode(out, body, sizeof body, &body_len)) != ANTS_OK) {
        return err;
    }
    return ants_ed25519_sign(client_priv, body, body_len, out->client_sig);
}
