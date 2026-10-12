/*
 * infer.c — the inference exchange engine (RFC-0008 §11.14).
 *
 * Two fixed tables live in the caller's opaque buffer:
 *   - outbound exchanges: our INFER_REQ in flight on a stream we opened
 *     (heap stream handle, a copy of the request for the answer check, a
 *     response buffer allocated on first byte — the DHT RPC lifetime);
 *   - inbound streams: peer-initiated bidi streams. Every such stream is
 *     also seen by the DHT server and network/attest, so a stream is first
 *     CLASSIFIED from its envelope head (a few bytes) and released at once
 *     when it is not an INFER_REQ — a peer's concurrent DHT RPCs therefore
 *     never sit in this table. Release is silent: the stream may be a
 *     sibling's, so it is never reset.
 */

#include "ants_infer.h"

#include "ants_inference.h"
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

struct infer_outbound {
    bool in_use;
    /* Local allocation failure: no verdict (it says nothing about the
     * peer). The slot stays until the stream ends — freeing the stream
     * handle mid-stream would leave the transport writing into it. */
    bool local_oom;
    bool oversized;
    uint8_t _pad;
    uint32_t txid;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* heap, ours */
    void *cookie;
    uint64_t started_ms;
    uint8_t *input; /* heap copy of the request input */
    size_t input_len;
    uint32_t tier;
    uint8_t req_nonce[ANTS_INFERENCE_HASH_SIZE];
    uint8_t *buf; /* heap, lazily: ANTS_INFER_MAX_RESP_BYTES */
    size_t len;
};

struct infer_inbound {
    bool in_use;
    bool claimed; /* the head said INFER_REQ: `buf` holds the message */
    uint8_t _pad[6];
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* the transport's */
    uint8_t *buf;                    /* heap once claimed: ANTS_INFER_MAX_REQ_BYTES */
    size_t len;
    uint8_t head[INFER_HEAD_PREFIX]; /* before the claim */
};

struct infer_state {
    ants_infer_config_t cfg;
    /* The connection whose CONN_CLOSED is being delivered: a request on it
     * from inside a NO_ANSWER callback is refused (it would bind a stream
     * to a connection about to be freed). */
    const ants_transport_conn_t *closing;
    uint32_t next_txid;
    uint8_t _pad[4];
    struct infer_outbound out[ANTS_INFER_MAX_OUTBOUND];
    struct infer_inbound in[INFER_MAX_INBOUND];
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

/* Report NO_ANSWER for `o` (the peer-id may be unknown by now). */
static void emit_no_answer(struct infer_state *s, const struct infer_outbound *o)
{
    ants_infer_result_t r;
    memset(&r, 0, sizeof r);
    r.conn = o->conn;
    (void)ants_transport_conn_peer_id(o->conn, &r.peer_id);
    r.verdict = ANTS_INFER_VERDICT_NO_ANSWER;
    r.cookie = o->cookie;
    emit(s, &r);
}

ants_error_t ants_infer_request(ants_infer_t *e,
                                ants_transport_conn_t *conn,
                                const ants_infer_request_t *req,
                                uint64_t now_ms,
                                void *cookie)
{
    struct infer_state *s;
    struct infer_outbound *o = NULL;
    uint8_t *msg;
    size_t msg_len;
    uint32_t txid;
    ants_transport_stream_t *stream;
    ants_error_t err;
    size_t i;

    if (e == NULL || conn == NULL || req == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    s = get_state(e);
    if (conn == s->closing) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    for (i = 0; i < ANTS_INFER_MAX_OUTBOUND; i++) {
        if (!s->out[i].in_use) {
            o = &s->out[i];
            break;
        }
    }
    if (o == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    txid = s->next_txid++;
    if (s->next_txid == 0) {
        s->next_txid = 1;
    }
    msg = (uint8_t *)malloc(ANTS_INFER_MAX_REQ_BYTES);
    if (msg == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    err = ants_infer_wire_encode_req(msg, ANTS_INFER_MAX_REQ_BYTES, &msg_len, txid, req);
    if (err != ANTS_OK) {
        free(msg);
        return err;
    }
    stream = (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
    o->input = (uint8_t *)malloc(req->input_len);
    if (stream == NULL || o->input == NULL) {
        free(stream);
        free(o->input);
        o->input = NULL;
        free(msg);
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memset(stream, 0, sizeof *stream);
    memcpy(o->input, req->input, req->input_len);
    o->input_len = req->input_len;
    o->tier = req->tier;
    memcpy(o->req_nonce, req->req_nonce, sizeof o->req_nonce);
    /* Claim the slot before opening, so a nested event finds it. */
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
        free(msg);
        return err;
    }
    free(msg);
    return ANTS_OK;
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

/* Turn a complete INFER_RESP into a verdict. */
static void outbound_conclude(struct infer_state *s, struct infer_outbound *o)
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

static void
outbound_on_event(struct infer_state *s, struct infer_outbound *o, const ants_transport_event_t *ev)
{
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        if (ev->payload == NULL || ev->payload_len == 0 || o->oversized || o->local_oom) {
            return;
        }
        if (o->buf == NULL) {
            o->buf = (uint8_t *)malloc(ANTS_INFER_MAX_RESP_BYTES);
            if (o->buf == NULL) {
                o->local_oom = true;
                return;
            }
        }
        if (ev->payload_len > ANTS_INFER_MAX_RESP_BYTES - o->len) {
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
        type != ANTS_INFER_MSG_REQ) {
        inbound_release(in); /* a sibling's stream — leave it alone */
        return false;
    }
    in->buf = (uint8_t *)malloc(ANTS_INFER_MAX_REQ_BYTES);
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
        if (n > ANTS_INFER_MAX_REQ_BYTES - in->len) {
            /* Larger than any conformant INFER_REQ: ours and malformed. */
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
        inbound_answer(s, in);
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

void ants_infer_handle_transport_event(ants_infer_t *e, const ants_transport_event_t *ev)
{
    struct infer_state *s;
    struct infer_outbound *o;
    size_t i;
    if (e == NULL || ev == NULL) {
        return;
    }
    s = get_state(e);
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
