/*
 * attest.c — the attestation exchange engine (RFC-0008 §11.12) and the
 * per-connection verdicts of the v1 handshake gate (RFC-0005).
 *
 * Three fixed tables live in the caller's opaque buffer:
 *   - outbound exchanges: our ATTEST_REQ in flight on a stream we opened
 *     (heap stream handle + lazily-allocated response buffer, freed when
 *     the exchange ends — the DHT RPC lifetime pattern);
 *   - inbound streams: peer-initiated bidi streams accumulating until FIN,
 *     to find out whether they carry an ATTEST_REQ. Every such stream is
 *     ALSO seen by the DHT server; each side claims only its own envelope
 *     types and silently releases the rest (never resets: the stream may
 *     be the sibling's);
 *   - verdicts, keyed by connection, cleared on CONN_CLOSED.
 */

#include "ants_attest.h"

#include "ants_tee.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* One outbound exchange and one verdict per connection, so sizing both
 * tables at ANTS_ATTEST_MAX_CONNS (>= the transport's max_connections —
 * the caller's contract) means a peer that never answers can only ever
 * hold its own connection's slot: exhausting the gate takes exhausting
 * the transport's connection cap first. */
#define ATTEST_MAX_OUTBOUND ANTS_ATTEST_MAX_CONNS
#define ATTEST_MAX_INBOUND  32
#define ATTEST_MAX_VERDICTS ANTS_ATTEST_MAX_CONNS
/* Inbound streams one connection may hold in the table at once — so a
 * single peer opening many never-finished bidi streams cannot crowd out
 * everyone else's ATTEST_REQ. */
#define ATTEST_MAX_INBOUND_PER_CONN 2
/* An ATTEST_REQ is an 8-byte-ish map(2); a peer-initiated stream that
 * grows past this is not ours (DHT requests, future protocols). */
#define ATTEST_INBOUND_CAP 64

struct attest_outbound {
    bool in_use;
    /* Local allocation failure: the answer is dropped and no verdict is
     * given (it says nothing about the peer). The slot stays until the
     * stream ends — freeing the stream handle mid-stream would leave the
     * transport writing into it. */
    bool local_oom;
    uint8_t _pad[2];
    uint32_t txid;
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* heap, ours */
    uint8_t *buf;                    /* heap, lazily: ANTS_ATTEST_MAX_RESP_BYTES */
    size_t len;
};

struct attest_inbound {
    bool in_use;
    uint8_t _pad[7];
    ants_transport_conn_t *conn;
    ants_transport_stream_t *stream; /* the transport's */
    size_t len;
    uint8_t buf[ATTEST_INBOUND_CAP];
};

struct attest_verdict_entry {
    const ants_transport_conn_t *conn; /* NULL = free */
    ants_attest_verdict_t verdict;
    uint8_t _pad[4];
};

struct attest_state {
    ants_attest_presentation_t local; /* present == false: answer {} */
    int64_t freshness_window_seconds;
    bool request_on_ready;
    uint8_t _pad[3];
    uint32_t next_txid;
    ants_attest_verdict_fn verdict_fn;
    void *verdict_ctx;
    struct attest_outbound out[ATTEST_MAX_OUTBOUND];
    struct attest_inbound in[ATTEST_MAX_INBOUND];
    struct attest_verdict_entry verdicts[ATTEST_MAX_VERDICTS];
};

typedef char attest_state_fits_opaque
    [(sizeof(struct attest_state) <= sizeof(((ants_attest_t *)0)->_opaque)) ? 1 : -1];

static struct attest_state *get_state(ants_attest_t *a)
{
    return (struct attest_state *)(void *)a->_opaque;
}

static const struct attest_state *get_state_const(const ants_attest_t *a)
{
    return (const struct attest_state *)(const void *)a->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_attest_init(ants_attest_t *a, const ants_attest_config_t *config)
{
    if (a == NULL || config == NULL || config->freshness_window_seconds <= 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (config->local != NULL && config->local->present) {
        /* Refuse a local presentation that would not encode — better at
         * init than on every inbound request. */
        uint8_t *probe = (uint8_t *)malloc(ANTS_ATTEST_MAX_RESP_BYTES);
        if (probe == NULL) {
            return ANTS_ERROR_BUFFER_TOO_SMALL;
        }
        size_t probe_len;
        ants_error_t err = ants_attest_wire_encode_resp(
            probe, ANTS_ATTEST_MAX_RESP_BYTES, &probe_len, UINT32_MAX, config->local);
        free(probe);
        if (err != ANTS_OK) {
            return ANTS_ERROR_INVALID_ARG;
        }
    }
    memset(a->_opaque, 0, sizeof a->_opaque);
    struct attest_state *s = get_state(a);
    if (config->local != NULL) {
        s->local = *config->local;
    }
    s->freshness_window_seconds = config->freshness_window_seconds;
    s->request_on_ready = config->request_on_ready;
    s->next_txid = 1;
    s->verdict_fn = config->verdict_fn;
    s->verdict_ctx = config->verdict_ctx;
    return ANTS_OK;
}

static void outbound_release(struct attest_outbound *o)
{
    free(o->buf);
    free(o->stream);
    memset(o, 0, sizeof *o);
}

void ants_attest_destroy(ants_attest_t *a)
{
    if (a == NULL) {
        return;
    }
    struct attest_state *s = get_state(a);
    for (size_t i = 0; i < ATTEST_MAX_OUTBOUND; i++) {
        if (s->out[i].in_use) {
            outbound_release(&s->out[i]);
        }
    }
    memset(s->in, 0, sizeof s->in);
    memset(s->verdicts, 0, sizeof s->verdicts);
}

/* ------------------------------------------------------------------------ */
/* Verdict table                                                            */
/* ------------------------------------------------------------------------ */

static struct attest_verdict_entry *verdict_find(struct attest_state *s,
                                                 const ants_transport_conn_t *conn)
{
    for (size_t i = 0; i < ATTEST_MAX_VERDICTS; i++) {
        if (s->verdicts[i].conn == conn) {
            return &s->verdicts[i];
        }
    }
    return NULL;
}

ants_attest_verdict_t ants_attest_verdict_for(const ants_attest_t *a,
                                              const ants_transport_conn_t *conn)
{
    if (a == NULL || conn == NULL) {
        return ANTS_ATTEST_VERDICT_NONE;
    }
    const struct attest_state *s = get_state_const(a);
    for (size_t i = 0; i < ATTEST_MAX_VERDICTS; i++) {
        if (s->verdicts[i].conn == conn) {
            return s->verdicts[i].verdict;
        }
    }
    return ANTS_ATTEST_VERDICT_NONE;
}

/* Record the verdict (best effort: a full table still reports it through
 * the callback, it just is not cached) and fire the callback. */
static void verdict_emit(struct attest_state *s, const ants_attest_result_t *r)
{
    struct attest_verdict_entry *e = verdict_find(s, r->conn);
    if (e == NULL) {
        e = verdict_find(s, NULL);
    }
    if (e != NULL) {
        e->conn = r->conn;
        e->verdict = r->verdict;
    }
    if (s->verdict_fn != NULL) {
        s->verdict_fn(r, s->verdict_ctx);
    }
}

/* ------------------------------------------------------------------------ */
/* Outbound: our request, their answer                                      */
/* ------------------------------------------------------------------------ */

ants_error_t ants_attest_request(ants_attest_t *a, ants_transport_conn_t *conn)
{
    if (a == NULL || conn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct attest_state *s = get_state(a);
    /* One request per connection. */
    if (verdict_find(s, conn) != NULL) {
        return ANTS_OK;
    }
    struct attest_outbound *o = NULL;
    for (size_t i = 0; i < ATTEST_MAX_OUTBOUND; i++) {
        if (s->out[i].in_use && s->out[i].conn == conn) {
            return ANTS_OK;
        }
        if (o == NULL && !s->out[i].in_use) {
            o = &s->out[i];
        }
    }
    if (o == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t txid = s->next_txid++;
    if (s->next_txid == 0) {
        s->next_txid = 1;
    }
    uint8_t req[16];
    size_t req_len;
    ants_error_t err = ants_attest_wire_encode_req(req, sizeof req, &req_len, txid);
    if (err != ANTS_OK) {
        return err;
    }
    ants_transport_stream_t *stream =
        (ants_transport_stream_t *)malloc(sizeof(ants_transport_stream_t));
    if (stream == NULL) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memset(stream, 0, sizeof *stream);
    /* Claim the slot before opening, so a nested event during open/send
     * finds it. */
    o->in_use = true;
    o->txid = txid;
    o->conn = conn;
    o->stream = stream;
    if ((err = ants_transport_open_bidi_stream(conn, stream)) != ANTS_OK ||
        (err = ants_transport_stream_send(stream, req, req_len, true)) != ANTS_OK) {
        /* If the open succeeded the stream is bound: detach it before the
         * handle is freed (a no-op when the open itself failed). */
        (void)ants_transport_stream_unbind(stream);
        outbound_release(o);
        return err;
    }
    return ANTS_OK;
}

static struct attest_outbound *outbound_by_stream(struct attest_state *s,
                                                  const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ATTEST_MAX_OUTBOUND; i++) {
        if (s->out[i].in_use && s->out[i].stream == stream) {
            return &s->out[i];
        }
    }
    return NULL;
}

/* Turn a complete ATTEST_RESP into the connection's verdict. */
static void outbound_conclude(struct attest_state *s, struct attest_outbound *o, int64_t now)
{
    ants_attest_result_t r;
    memset(&r, 0, sizeof r);
    r.conn = o->conn;
    /* The key the evidence must bind is the one the TLS handshake on this
     * connection authenticated — never one claimed on the wire. */
    if (ants_transport_conn_peer_id(o->conn, &r.peer_id) != ANTS_OK) {
        return; /* conn already torn down: no verdict to give */
    }

    uint32_t txid = 0;
    ants_attest_presentation_t p;
    ants_error_t err = ANTS_ERROR_MALFORMED;
    if (o->buf != NULL) {
        err = ants_attest_wire_decode_resp(o->buf, o->len, &txid, &p);
    }
    if (err != ANTS_OK || txid != o->txid) {
        r.verdict = ANTS_ATTEST_VERDICT_REJECTED; /* spoke the exchange malformed */
    } else if (!p.present) {
        r.verdict = ANTS_ATTEST_VERDICT_UNATTESTED;
    } else {
        r.vendor = p.vendor;
        r.issued_at_unix = p.issued_at_unix;
        ants_attestation_t att;
        memset(&att, 0, sizeof att);
        att.vendor = p.vendor;
        memcpy(att.peer_pubkey, r.peer_id.bytes, sizeof att.peer_pubkey);
        att.issued_at_unix = p.issued_at_unix;
        att.expires_at_unix = p.expires_at_unix;
        att.vendor_blob = p.blob;
        att.vendor_blob_len = p.blob_len;
        ants_error_t v = ants_attestation_verify(&att);
        if (v == ANTS_ERROR_NOT_IMPLEMENTED) {
            /* A vendor this build cannot verify yet: fail closed to "not
             * attested" — not evidence of anything false. */
            r.verdict = ANTS_ATTEST_VERDICT_UNATTESTED;
        } else if (v != ANTS_OK) {
            r.verdict = ANTS_ATTEST_VERDICT_REJECTED;
        } else if (!ants_attestation_is_fresh(&att, now, s->freshness_window_seconds)) {
            /* Genuine but stale (or issued beyond the clock skew): the peer
             * must refresh; until then it is simply not attested. */
            r.verdict = ANTS_ATTEST_VERDICT_UNATTESTED;
        } else {
            r.verdict = ANTS_ATTEST_VERDICT_ATTESTED;
        }
    }
    verdict_emit(s, &r);
}

static void outbound_on_event(struct attest_state *s,
                              struct attest_outbound *o,
                              const ants_transport_event_t *ev,
                              int64_t now)
{
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        if (ev->payload == NULL || ev->payload_len == 0 || o->len == SIZE_MAX) {
            return; /* nothing to add, or already oversized */
        }
        if (o->buf == NULL) {
            o->buf = (uint8_t *)malloc(ANTS_ATTEST_MAX_RESP_BYTES);
            if (o->buf == NULL) {
                o->local_oom = true;
                o->len = SIZE_MAX;
                return;
            }
        }
        if (ev->payload_len > ANTS_ATTEST_MAX_RESP_BYTES - o->len) {
            /* Oversized answer: rejected without decoding. Drop what we
             * hold so the conclusion at FIN sees a malformed (empty)
             * buffer; keep the slot to deliver that verdict then. */
            free(o->buf);
            o->buf = NULL;
            o->len = SIZE_MAX;
            return;
        }
        memcpy(o->buf + o->len, ev->payload, ev->payload_len);
        o->len += ev->payload_len;
        return;
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        if (!o->local_oom) {
            outbound_conclude(s, o, now);
        }
        outbound_release(o);
        return;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        /* No answer: no verdict (the peer may simply not speak §11.12). */
        outbound_release(o);
        return;
    default:
        return;
    }
}

/* ------------------------------------------------------------------------ */
/* Inbound: their request, our answer                                       */
/* ------------------------------------------------------------------------ */

static struct attest_inbound *inbound_by_stream(struct attest_state *s,
                                                const ants_transport_stream_t *stream)
{
    for (size_t i = 0; i < ATTEST_MAX_INBOUND; i++) {
        if (s->in[i].in_use && s->in[i].stream == stream) {
            return &s->in[i];
        }
    }
    return NULL;
}

static void inbound_answer(struct attest_state *s, struct attest_inbound *in)
{
    uint64_t type;
    if (ants_attest_wire_peek_type(in->buf, in->len, &type) != ANTS_OK ||
        type != ANTS_ATTEST_MSG_REQ) {
        return; /* a sibling's stream (DHT RPC, ...) — leave it alone */
    }
    uint32_t txid;
    if (ants_attest_wire_decode_req(in->buf, in->len, &txid) != ANTS_OK) {
        (void)ants_transport_stream_reset(in->stream, 1); /* ours, malformed */
        return;
    }
    size_t cap = s->local.present ? ANTS_ATTEST_MAX_RESP_BYTES : 32;
    uint8_t *resp = (uint8_t *)malloc(cap);
    if (resp == NULL) {
        (void)ants_transport_stream_reset(in->stream, 2);
        return;
    }
    size_t resp_len;
    if (ants_attest_wire_encode_resp(resp, cap, &resp_len, txid, &s->local) == ANTS_OK) {
        (void)ants_transport_stream_send(in->stream, resp, resp_len, true);
    } else {
        (void)ants_transport_stream_reset(in->stream, 2);
    }
    free(resp);
}

static void inbound_on_event(struct attest_state *s, const ants_transport_event_t *ev)
{
    if (ev->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
        if (!ants_transport_stream_is_bidi(ev->stream) || inbound_by_stream(s, ev->stream)) {
            return;
        }
        size_t held = 0;
        for (size_t i = 0; i < ATTEST_MAX_INBOUND; i++) {
            if (s->in[i].in_use && s->in[i].conn == ev->conn) {
                held++;
            }
        }
        if (held >= ATTEST_MAX_INBOUND_PER_CONN) {
            return; /* this peer already has its share in flight */
        }
        for (size_t i = 0; i < ATTEST_MAX_INBOUND; i++) {
            if (!s->in[i].in_use) {
                s->in[i].in_use = true;
                s->in[i].conn = ev->conn;
                s->in[i].stream = ev->stream;
                s->in[i].len = 0;
                return;
            }
        }
        return; /* full: not answering is safe — the requester gets no verdict */
    }
    struct attest_inbound *in = inbound_by_stream(s, ev->stream);
    if (in == NULL) {
        return;
    }
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_STREAM_READABLE:
        if (ev->payload == NULL || ev->payload_len == 0) {
            return;
        }
        if (ev->payload_len > sizeof in->buf - in->len) {
            memset(in, 0, sizeof *in); /* too big for a request: not ours */
            return;
        }
        memcpy(in->buf + in->len, ev->payload, ev->payload_len);
        in->len += ev->payload_len;
        return;
    case ANTS_TRANSPORT_EV_STREAM_FIN:
        inbound_answer(s, in);
        memset(in, 0, sizeof *in);
        return;
    case ANTS_TRANSPORT_EV_STREAM_RESET:
        memset(in, 0, sizeof *in);
        return;
    default:
        return;
    }
}

/* ------------------------------------------------------------------------ */
/* Event entry point                                                        */
/* ------------------------------------------------------------------------ */

void ants_attest_handle_transport_event(ants_attest_t *a,
                                        const ants_transport_event_t *ev,
                                        int64_t now_unix)
{
    if (a == NULL || ev == NULL) {
        return;
    }
    struct attest_state *s = get_state(a);
    switch (ev->kind) {
    case ANTS_TRANSPORT_EV_CONN_READY:
        if (s->request_on_ready && ev->conn != NULL) {
            (void)ants_attest_request(a, ev->conn);
        }
        return;
    case ANTS_TRANSPORT_EV_CONN_CLOSED:
        for (size_t i = 0; i < ATTEST_MAX_OUTBOUND; i++) {
            if (s->out[i].in_use && s->out[i].conn == ev->conn) {
                outbound_release(&s->out[i]);
            }
        }
        for (size_t i = 0; i < ATTEST_MAX_INBOUND; i++) {
            if (s->in[i].in_use && s->in[i].conn == ev->conn) {
                memset(&s->in[i], 0, sizeof s->in[i]);
            }
        }
        for (size_t i = 0; i < ATTEST_MAX_VERDICTS; i++) {
            if (s->verdicts[i].conn == ev->conn) {
                memset(&s->verdicts[i], 0, sizeof s->verdicts[i]);
            }
        }
        return;
    default:
        break;
    }
    if (ev->stream == NULL) {
        return;
    }
    struct attest_outbound *o = outbound_by_stream(s, ev->stream);
    if (o != NULL) {
        outbound_on_event(s, o, ev, now_unix);
        return;
    }
    inbound_on_event(s, ev);
}
