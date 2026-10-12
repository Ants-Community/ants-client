/*
 * test_infer.c — RFC-0008 §11.14 codec + the inference exchange engine.
 *
 * Codec: canonical bytes written out by hand (independent of the encoder)
 * and the strict-decoder rejections. Engine: two real transports over
 * loopback QUIC. B produces with the pinned v1 reference model through
 * ants_infer_serve_reference; A requests and checks. Covered:
 *   - an honest answer → ANSWERED, and A — holding only the pinned model —
 *     runs the full audit on it (the cross-node auditability the pinned
 *     generator exists for);
 *   - a decline → DECLINED;
 *   - a tampered envelope → REJECTED (the §11.8 integrity gate);
 *   - an answer signed by a key that is not B's transport identity (a
 *     relayed answer) → REJECTED;
 *   - malformed / wrong-txid / oversized raw replies → REJECTED;
 *   - a producer that never answers → NO_ANSWER at the timeout;
 *   - a peer holding two non-INFER bidi streams open → its INFER_REQ is
 *     still served (streams are classified by their head, not held).
 */

/* POSIX feature test — nanosleep() on glibc. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_infer.h"
#include "ants_inference.h"
#include "ants_transport.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                 \
    do {                                                                                           \
        ants_error_t _a = (actual);                                                                \
        ants_error_t _e = (expected);                                                              \
        if (_a != _e) {                                                                            \
            failures++;                                                                            \
            fprintf(stderr,                                                                        \
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Codec                                                                    */
/* ------------------------------------------------------------------------ */

/* INFER_REQ, txid 7, input "ab", tier 2, nonce 0x11 x 32 — by hand. */
static size_t hand_req(uint8_t *b)
{
    static const uint8_t head[] = {0xa3,
                                   0x00,
                                   0x0b,
                                   0x01,
                                   0x07,
                                   0x02,
                                   0xa3,
                                   0x00,
                                   0x42,
                                   'a',
                                   'b',
                                   0x01,
                                   0x02,
                                   0x02,
                                   0x58,
                                   0x20};
    memcpy(b, head, sizeof head);
    memset(b + sizeof head, 0x11, 32);
    return sizeof head + 32;
}

static void test_wire_req(void)
{
    uint8_t want[64];
    size_t want_len = hand_req(want);
    uint8_t buf[ANTS_INFER_MAX_REQ_BYTES + 16];
    size_t len = 0;
    uint32_t txid = 0;
    uint64_t type = 0;
    ants_infer_request_t r;
    ants_infer_request_t in;

    memset(&in, 0, sizeof in);
    in.input = (const uint8_t *)"ab";
    in.input_len = 2;
    in.tier = 2;
    memset(in.req_nonce, 0x11, 32);
    CHECK_EQ(ants_infer_wire_encode_req(buf, sizeof buf, &len, 7, &in), ANTS_OK);
    CHECK(len == want_len && memcmp(buf, want, len) == 0);

    CHECK_EQ(ants_infer_wire_peek_type(want, want_len, &type), ANTS_OK);
    CHECK(type == ANTS_INFER_MSG_REQ);
    CHECK_EQ(ants_infer_wire_decode_req(want, want_len, &txid, &r), ANTS_OK);
    CHECK(txid == 7 && r.input_len == 2 && memcmp(r.input, "ab", 2) == 0 && r.tier == 2);
    CHECK(r.req_nonce[0] == 0x11 && r.req_nonce[31] == 0x11);

    /* trailing byte */
    {
        uint8_t t[80];
        memcpy(t, want, want_len);
        t[want_len] = 0x00;
        CHECK(ants_infer_wire_decode_req(t, want_len + 1, &txid, &r) != ANTS_OK);
    }
    /* empty input (0x40) */
    {
        uint8_t t[64];
        static const uint8_t h[] = {
            0xa3, 0x00, 0x0b, 0x01, 0x07, 0x02, 0xa3, 0x00, 0x40, 0x01, 0x02, 0x02, 0x58, 0x20};
        memcpy(t, h, sizeof h);
        memset(t + sizeof h, 0x11, 32);
        CHECK_EQ(ants_infer_wire_decode_req(t, sizeof h + 32, &txid, &r), ANTS_ERROR_MALFORMED);
    }
    /* a 31-byte nonce */
    {
        uint8_t t[64];
        memcpy(t, want, want_len);
        t[15] = 0x1f;
        CHECK_EQ(ants_infer_wire_decode_req(t, want_len - 1, &txid, &r), ANTS_ERROR_MALFORMED);
    }
    /* tier 2^31 (0x1a 80 00 00 00) */
    {
        uint8_t t[80];
        static const uint8_t h[] = {0xa3, 0x00, 0x0b, 0x01, 0x07, 0x02, 0xa3, 0x00, 0x42, 'a',
                                    'b',  0x01, 0x1a, 0x80, 0x00, 0x00, 0x00, 0x02, 0x58, 0x20};
        memcpy(t, h, sizeof h);
        memset(t + sizeof h, 0x11, 32);
        CHECK_EQ(ants_infer_wire_decode_req(t, sizeof h + 32, &txid, &r), ANTS_ERROR_MALFORMED);
    }
    /* a fourth body key (closed map) */
    {
        uint8_t t[80];
        memcpy(t, want, want_len);
        t[6] = 0xa4;
        t[want_len] = 0x03;
        t[want_len + 1] = 0x00;
        CHECK(ants_infer_wire_decode_req(t, want_len + 2, &txid, &r) != ANTS_OK);
    }
    /* no body / the response type */
    {
        static const uint8_t nobody[] = {0xa2, 0x00, 0x0b, 0x01, 0x07};
        uint8_t t[80];
        CHECK(ants_infer_wire_decode_req(nobody, sizeof nobody, &txid, &r) != ANTS_OK);
        memcpy(t, want, want_len);
        t[2] = 0x0c;
        CHECK(ants_infer_wire_decode_req(t, want_len, &txid, &r) != ANTS_OK);
    }
    /* input over the pinned cap: refused by the encoder, rejected by the
     * decoder */
    {
        static uint8_t big[ANTS_INFER_MAX_INPUT_BYTES + 1];
        static uint8_t t[ANTS_INFER_MAX_REQ_BYTES + 64];
        size_t n = 0;
        memset(big, 'x', sizeof big);
        in.input = big;
        in.input_len = sizeof big;
        CHECK_EQ(ants_infer_wire_encode_req(buf, sizeof buf, &len, 7, &in), ANTS_ERROR_INVALID_ARG);
        in.input_len = ANTS_INFER_MAX_INPUT_BYTES;
        CHECK_EQ(ants_infer_wire_encode_req(buf, sizeof buf, &len, 7, &in), ANTS_OK);
        CHECK(len <= ANTS_INFER_MAX_REQ_BYTES);
        /* hand-build the 4097-byte version: bstr head 0x59 10 01 */
        memcpy(t,
               (const uint8_t[]){0xa3, 0x00, 0x0b, 0x01, 0x07, 0x02, 0xa3, 0x00, 0x59, 0x10, 0x01},
               11);
        n = 11;
        memset(t + n, 'x', sizeof big);
        n += sizeof big;
        memcpy(t + n, (const uint8_t[]){0x01, 0x02, 0x02, 0x58, 0x20}, 5);
        n += 5;
        memset(t + n, 0x11, 32);
        n += 32;
        CHECK_EQ(ants_infer_wire_decode_req(t, n, &txid, &r), ANTS_ERROR_MALFORMED);
    }
}

static void test_wire_resp(void)
{
    static const uint8_t declined[] = {0xa2, 0x00, 0x0c, 0x01, 0x07};
    static const uint8_t explicit_empty[] = {0xa3, 0x00, 0x0c, 0x01, 0x07, 0x02, 0xa0};
    uint8_t full[96];
    size_t full_len;
    uint8_t buf[256];
    size_t len = 0;
    uint32_t txid = 0;
    ants_infer_answer_t a;
    ants_infer_answer_t in;

    /* declined, both ways */
    CHECK_EQ(ants_infer_wire_encode_resp(buf, sizeof buf, &len, 7, NULL), ANTS_OK);
    CHECK(len == sizeof declined && memcmp(buf, declined, len) == 0);
    CHECK_EQ(ants_infer_wire_decode_resp(declined, sizeof declined, &txid, &a), ANTS_OK);
    CHECK(txid == 7 && !a.present);
    CHECK(ants_infer_wire_decode_resp(explicit_empty, sizeof explicit_empty, &txid, &a) != ANTS_OK);

    /* full: commit "c", sig 0x22 x 64, envelope "e" */
    {
        static const uint8_t h[] = {
            0xa3, 0x00, 0x0c, 0x01, 0x07, 0x02, 0xa3, 0x00, 0x41, 'c', 0x01, 0x58, 0x40};
        memcpy(full, h, sizeof h);
        memset(full + sizeof h, 0x22, 64);
        full[sizeof h + 64] = 0x02;
        full[sizeof h + 65] = 0x41;
        full[sizeof h + 66] = 'e';
        full_len = sizeof h + 67;
    }
    memset(&in, 0, sizeof in);
    in.present = true;
    in.commit = (const uint8_t *)"c";
    in.commit_len = 1;
    memset(in.sig, 0x22, 64);
    in.envelope = (const uint8_t *)"e";
    in.envelope_len = 1;
    CHECK_EQ(ants_infer_wire_encode_resp(buf, sizeof buf, &len, 7, &in), ANTS_OK);
    CHECK(len == full_len && memcmp(buf, full, len) == 0);
    CHECK_EQ(ants_infer_wire_decode_resp(full, full_len, &txid, &a), ANTS_OK);
    CHECK(a.present && a.commit_len == 1 && a.commit[0] == 'c' && a.envelope_len == 1 &&
          a.envelope[0] == 'e' && a.sig[63] == 0x22);

    /* a 63-byte signature */
    {
        uint8_t t[96];
        memcpy(t, full, 11);
        t[11] = 0x58;
        t[12] = 0x3f;
        memset(t + 13, 0x22, 63);
        memcpy(t + 76, full + 77, 3);
        CHECK_EQ(ants_infer_wire_decode_resp(t, 79, &txid, &a), ANTS_ERROR_MALFORMED);
    }
    /* an empty envelope */
    {
        uint8_t t[96];
        memcpy(t, full, full_len);
        t[full_len - 2] = 0x40;
        CHECK_EQ(ants_infer_wire_decode_resp(t, full_len - 1, &txid, &a), ANTS_ERROR_MALFORMED);
    }
    /* a commit over the encoded-commit cap, refused by the encoder */
    {
        static uint8_t big[ANTS_INFERENCE_COMMIT_ENCODED_MAX + 1];
        static uint8_t out[1024];
        in.commit = big;
        in.commit_len = sizeof big;
        CHECK_EQ(ants_infer_wire_encode_resp(out, sizeof out, &len, 7, &in),
                 ANTS_ERROR_INVALID_ARG);
    }
    /* over the response cap: rejected undecoded */
    {
        uint8_t *huge = (uint8_t *)calloc(1, ANTS_INFER_MAX_RESP_BYTES + 1);
        CHECK(huge != NULL);
        if (huge != NULL) {
            memcpy(huge, full, full_len);
            CHECK_EQ(ants_infer_wire_decode_resp(huge, ANTS_INFER_MAX_RESP_BYTES + 1, &txid, &a),
                     ANTS_ERROR_BUFFER_TOO_SMALL);
            free(huge);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Engine over loopback QUIC                                                */
/* ------------------------------------------------------------------------ */

static void tick_pace(void)
{
    struct timespec ts = {0, 1000000L}; /* 1 ms */
    nanosleep(&ts, NULL);
}

static ants_error_t real_sign(const uint8_t *transcript,
                              size_t transcript_len,
                              uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                              void *sign_ctx)
{
    return ants_ed25519_sign((const uint8_t *)sign_ctx, transcript, transcript_len, out_sig);
}

/* The v1 model, built once (4-aligned). */
static union {
    uint32_t a;
    uint8_t b[ANTS_INFERENCE_REF_MODEL_V1_BYTES];
} g_model;
static size_t g_model_len;

enum { P_HONEST, P_DECLINE, P_TAMPER };

typedef struct {
    ants_inference_t *inf;
    int mode;
    int served;
} producer_t;

static bool producer_serve(void *ctx,
                           const ants_peer_id_t *requester,
                           const ants_infer_request_t *req,
                           ants_infer_served_t *out)
{
    producer_t *p = (producer_t *)ctx;
    (void)requester;
    p->served++;
    if (p->mode == P_DECLINE || ants_infer_serve_reference(p->inf, 42, req, out) != ANTS_OK) {
        return false;
    }
    if (p->mode == P_TAMPER) {
        out->envelope[out->envelope_len - 1] ^= 0xFFu;
    }
    return true;
}

enum { B_ENGINE, B_SILENT, B_RAW };

typedef struct {
    ants_infer_t *infer;      /* NULL: this side runs no engine */
    const uint8_t *raw_reply; /* B_RAW: reply to any FIN'd inbound stream */
    size_t raw_reply_len;
    bool raw_patch_txid; /* copy the request's txid byte into the reply */
    int results;
    ants_infer_result_t last;
    uint8_t envelope[ANTS_INFER_MAX_RESP_BYTES];
    size_t envelope_len;
    ants_transport_conn_t *ready_conn;
    /* On NO_ANSWER, try another request on the same (closing) conn. */
    bool rerequest;
    ants_error_t rerequest_rc;
} side_t;

static void on_result(const ants_infer_result_t *r, void *ctx)
{
    side_t *s = (side_t *)ctx;
    s->results++;
    s->last = *r;
    s->envelope_len = 0;
    if (r->verdict == ANTS_INFER_VERDICT_ANSWERED && r->envelope_len <= sizeof s->envelope) {
        memcpy(s->envelope, r->envelope, r->envelope_len);
        s->envelope_len = r->envelope_len;
    }
    s->last.envelope = NULL;
    if (s->rerequest && r->verdict == ANTS_INFER_VERDICT_NO_ANSWER) {
        ants_infer_request_t again;
        memset(&again, 0, sizeof again);
        again.input = (const uint8_t *)"again";
        again.input_len = 5;
        again.tier = 2;
        s->rerequest_rc = ants_infer_request(s->infer, r->conn, &again, 0, NULL);
    }
}

static ants_error_t side_event(const ants_transport_event_t *ev, void *ctx)
{
    side_t *s = (side_t *)ctx;
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        s->ready_conn = ev->conn;
    }
    if (s->raw_reply != NULL) {
        static uint8_t txid_byte;
        if (ev->kind == ANTS_TRANSPORT_EV_STREAM_READABLE && ev->payload_len > 4) {
            txid_byte = ev->payload[4]; /* a3 00 0b 01 <txid> for small txids */
        } else if (ev->kind == ANTS_TRANSPORT_EV_STREAM_FIN) {
            uint8_t *copy = (uint8_t *)malloc(s->raw_reply_len);
            if (copy != NULL) {
                memcpy(copy, s->raw_reply, s->raw_reply_len);
                if (s->raw_patch_txid) {
                    copy[4] = txid_byte;
                }
                (void)ants_transport_stream_send(ev->stream, copy, s->raw_reply_len, true);
                free(copy);
            }
        }
        return ANTS_OK;
    }
    if (s->infer != NULL) {
        ants_infer_handle_transport_event(s->infer, ev);
    }
    return ANTS_OK;
}

typedef struct {
    int b_mode;
    int producer_mode;
    /* the producer signs with this key instead of B's transport key */
    bool producer_foreign_key;
    const uint8_t *raw;
    size_t raw_len;
    bool raw_patch_txid;
    /* A opens this many non-INFER bidi streams (held open) first */
    int sibling_streams;
    /* A's engine timeout; the run then drives A's tick with fake time */
    uint64_t timeout_ms;
    /* A hangs up its own connection mid-request, and re-requests on it
     * from the NO_ANSWER callback */
    bool a_hangs_up;
} run_opts_t;

static uint8_t g_a_pub[32];
static uint8_t g_b_pub[32];

static void run_pair(const run_opts_t *o, side_t *a, side_t *b, producer_t *prod)
{
    uint8_t a_priv[32], b_priv[32], foreign_priv[32];
    static ants_infer_t inf_a, inf_b;
    static ants_inference_t model_ctx;
    static ants_transport_t ta, tb;
    static ants_transport_conn_t conn;
    ants_infer_config_t cfg;
    ants_inference_config_t mcfg;
    ants_transport_config_t tcfg;
    ants_peer_id_t expect;
    ants_infer_request_t req;
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    static ants_transport_stream_t sib[4];
    int i;

    memset(a_priv, 0x41, sizeof a_priv);
    memset(b_priv, 0x42, sizeof b_priv);
    memset(foreign_priv, 0x43, sizeof foreign_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, g_a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, g_b_pub), ANTS_OK);

    memset(a, 0, sizeof *a);
    memset(b, 0, sizeof *b);
    memset(prod, 0, sizeof *prod);
    a->rerequest = o->a_hangs_up;

    memset(&cfg, 0, sizeof cfg);
    cfg.result_fn = on_result;
    cfg.result_ctx = a;
    cfg.timeout_ms = o->timeout_ms;
    CHECK_EQ(ants_infer_init(&inf_a, &cfg), ANTS_OK);
    a->infer = &inf_a;

    if (o->b_mode == B_ENGINE) {
        memset(&mcfg, 0, sizeof mcfg);
        mcfg.model_weights = g_model.b;
        mcfg.model_weights_len = g_model_len;
        mcfg.producer_priv = o->producer_foreign_key ? foreign_priv : b_priv;
        CHECK_EQ(ants_inference_init(&model_ctx, &mcfg), ANTS_OK);
        prod->inf = &model_ctx;
        prod->mode = o->producer_mode;
        memset(&cfg, 0, sizeof cfg);
        cfg.serve_fn = producer_serve;
        cfg.serve_ctx = prod;
        CHECK_EQ(ants_infer_init(&inf_b, &cfg), ANTS_OK);
        b->infer = &inf_b;
    } else if (o->b_mode == B_RAW) {
        b->raw_reply = o->raw;
        b->raw_reply_len = o->raw_len;
        b->raw_patch_txid = o->raw_patch_txid;
    }

    memset(&tb, 0, sizeof tb);
    memset(&ta, 0, sizeof ta);
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, g_b_pub, 32);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = b_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = b;
    tcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &tcfg), ANTS_OK);
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, g_a_pub, 32);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = a_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = a;
    CHECK_EQ(ants_transport_init(&ta, &tcfg), ANTS_OK);

    memset(&conn, 0, sizeof conn);
    memcpy(expect.bytes, g_b_pub, 32);
    CHECK_EQ(ants_transport_dial(&ta, baddr, &expect, &conn), ANTS_OK);
    for (i = 0; i < 2000 && a->ready_conn == NULL; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }
    CHECK(a->ready_conn == &conn);

    /* Sibling streams: a DHT FIND_NODE head (longer than the classify
     * prefix), sent WITHOUT a FIN so the stream stays open. */
    for (i = 0; i < o->sibling_streams && i < 4; i++) {
        uint8_t fn[48] = {0xa3,
                          0x00,
                          0x02,
                          0x01,
                          0x07,
                          0x02,
                          0xa1,
                          0x66,
                          't',
                          'a',
                          'r',
                          'g',
                          'e',
                          't',
                          0x58,
                          0x20};
        memset(fn + 16, 0x55, 32);
        memset(&sib[i], 0, sizeof sib[i]);
        CHECK_EQ(ants_transport_open_bidi_stream(&conn, &sib[i]), ANTS_OK);
        CHECK_EQ(ants_transport_stream_send(&sib[i], fn, sizeof fn, false), ANTS_OK);
    }
    for (i = 0; i < 50 && o->sibling_streams > 0; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }

    memset(&req, 0, sizeof req);
    req.input = (const uint8_t *)"hello, colony";
    req.input_len = 13;
    req.tier = 2;
    memset(req.req_nonce, 0x5a, 32);
    CHECK_EQ(ants_infer_request(&inf_a, &conn, &req, 0, (void *)&conn), ANTS_OK);

    for (i = 0; i < 3000 && a->results == 0; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (o->a_hangs_up && i == 300) {
            CHECK_EQ(ants_transport_peer_disconnect(&conn, 0), ANTS_OK);
        }
        if (o->timeout_ms > 0 && i == 300) {
            ants_infer_tick(&inf_a, o->timeout_ms - 1); /* not yet */
            CHECK(a->results == 0);
            ants_infer_tick(&inf_a, o->timeout_ms);
        }
    }
    CHECK(a->results == 1);
    CHECK(a->last.conn == &conn && a->last.cookie == (void *)&conn);
    if (a->last.verdict != ANTS_INFER_VERDICT_NO_ANSWER) {
        CHECK(memcmp(a->last.peer_id.bytes, g_b_pub, 32) == 0);
    }

    for (i = 0; i < o->sibling_streams && i < 4; i++) {
        (void)ants_transport_stream_unbind(&sib[i]);
    }
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    ants_infer_destroy(&inf_a);
    if (o->b_mode == B_ENGINE) {
        ants_infer_destroy(&inf_b);
        CHECK_EQ(ants_inference_destroy(&model_ctx), ANTS_OK);
    }
}

static side_t g_a, g_b;
static producer_t g_prod;

static void test_engine_answered_and_auditable(void)
{
    run_opts_t o;
    static ants_inference_t verifier;
    ants_inference_config_t mcfg;
    uint8_t vpriv[32];
    uint8_t beacon[ANTS_INFERENCE_BEACON_SIZE];
    ants_inference_eprocess_t ep;
    ants_inference_verdict_t v = ANTS_INFERENCE_VERDICT_FRAUD;

    memset(&o, 0, sizeof o);
    o.b_mode = B_ENGINE;
    o.producer_mode = P_HONEST;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_prod.served == 1);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_ANSWERED);
    CHECK(g_a.last.commit.round == 42 && g_a.last.commit.tier == 2 && g_a.last.commit.length == 16);
    CHECK(g_a.envelope_len > 16u * 256u * 4u);

    /* A, holding nothing but the pinned v1 model, audits B's answer. The
     * verifier's own key is irrelevant: the rerun needs only the model. */
    memset(vpriv, 0x77, sizeof vpriv);
    memset(&mcfg, 0, sizeof mcfg);
    mcfg.model_weights = g_model.b;
    mcfg.model_weights_len = g_model_len;
    mcfg.producer_priv = vpriv;
    CHECK_EQ(ants_inference_init(&verifier, &mcfg), ANTS_OK);
    memset(beacon, 0x3c, sizeof beacon);
    CHECK_EQ(ants_inference_eprocess_init(&ep,
                                          ANTS_INFERENCE_DEFAULT_ALPHA,
                                          ANTS_INFERENCE_DEFAULT_MU0,
                                          ANTS_INFERENCE_DEFAULT_LAMBDA_CAP),
             ANTS_OK);
    CHECK_EQ(
        ants_inference_audit(&g_a.last.commit,
                             g_a.envelope,
                             g_a.envelope_len,
                             beacon,
                             (ants_inference_reference_fn)ants_inference_reference_distribution,
                             &verifier,
                             &ep,
                             &v),
        ANTS_OK);
    CHECK(v == ANTS_INFERENCE_VERDICT_CONTINUE); /* tier 2: audited, and passed */
    CHECK_EQ(ants_inference_destroy(&verifier), ANTS_OK);
}

static void test_engine_declined(void)
{
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_ENGINE;
    o.producer_mode = P_DECLINE;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_prod.served == 1);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_DECLINED);
}

static void test_engine_rejects_tampered_envelope(void)
{
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_ENGINE;
    o.producer_mode = P_TAMPER;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_REJECTED);
}

static void test_engine_rejects_foreign_signer(void)
{
    /* A perfectly valid answer — signed by a key that is not the peer-id
     * this connection authenticated (what a relayer would deliver). */
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_ENGINE;
    o.producer_mode = P_HONEST;
    o.producer_foreign_key = true;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_prod.served == 1);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_REJECTED);
}

static void test_engine_rejects_raw_replies(void)
{
    run_opts_t o;
    /* A well-formed DECLINED with the right txid is accepted as such... */
    static const uint8_t declined[] = {0xa2, 0x00, 0x0c, 0x01, 0x01};
    static const uint8_t garbage[] = {0xff, 0x00, 0x01};
    memset(&o, 0, sizeof o);
    o.b_mode = B_RAW;
    o.raw = declined;
    o.raw_len = sizeof declined;
    o.raw_patch_txid = true;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_DECLINED);

    /* ...the same bytes echoing another txid are not. */
    {
        static uint8_t wrong[sizeof declined];
        memcpy(wrong, declined, sizeof declined);
        wrong[4] = 0x17;
        o.raw = wrong;
        o.raw_patch_txid = false;
        run_pair(&o, &g_a, &g_b, &g_prod);
        CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_REJECTED);
    }

    o.raw = garbage;
    o.raw_len = sizeof garbage;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_REJECTED);

    /* Over the response cap: rejected without decoding. */
    {
        uint8_t *huge = (uint8_t *)calloc(1, ANTS_INFER_MAX_RESP_BYTES + 1);
        CHECK(huge != NULL);
        if (huge != NULL) {
            memcpy(huge, declined, sizeof declined);
            o.raw = huge;
            o.raw_len = ANTS_INFER_MAX_RESP_BYTES + 1;
            o.raw_patch_txid = true;
            run_pair(&o, &g_a, &g_b, &g_prod);
            CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_REJECTED);
            free(huge);
        }
    }
}

static void test_engine_silent_peer_times_out(void)
{
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_SILENT;
    o.timeout_ms = 5000;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_NO_ANSWER);
}

static void test_engine_no_request_on_closing_conn(void)
{
    /* The NO_ANSWER for a request outstanding at CONN_CLOSED is delivered
     * from inside that event; a new request on the same connection from
     * there would bind a stream to a connection about to be freed. */
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_SILENT;
    o.a_hangs_up = true;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_NO_ANSWER);
    CHECK_EQ(g_a.rerequest_rc, ANTS_ERROR_PEER_UNREACHABLE);
}

static void test_engine_siblings_do_not_hold_slots(void)
{
    /* Two DHT-looking bidi streams held open fill a per-connection cap of
     * 2 if streams are held until FIN; classified by their head, they are
     * released at once and the INFER_REQ that follows is served. */
    run_opts_t o;
    memset(&o, 0, sizeof o);
    o.b_mode = B_ENGINE;
    o.producer_mode = P_HONEST;
    o.sibling_streams = 2;
    run_pair(&o, &g_a, &g_b, &g_prod);
    CHECK(g_prod.served == 1);
    CHECK(g_a.last.verdict == ANTS_INFER_VERDICT_ANSWERED);
}

static void test_args(void)
{
    ants_infer_t e;
    ants_infer_config_t cfg;
    ants_infer_request_t req;
    ants_transport_conn_t conn;
    memset(&cfg, 0, sizeof cfg);
    memset(&req, 0, sizeof req);
    memset(&conn, 0, sizeof conn);
    CHECK_EQ(ants_infer_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_infer_init(&e, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_infer_init(&e, &cfg), ANTS_OK);
    CHECK_EQ(ants_infer_request(&e, NULL, &req, 0, NULL), ANTS_ERROR_INVALID_ARG);
    /* empty input: would not encode */
    CHECK_EQ(ants_infer_request(&e, &conn, &req, 0, NULL), ANTS_ERROR_INVALID_ARG);
    ants_infer_destroy(&e);
    ants_infer_destroy(&e);
    ants_infer_destroy(NULL);
}

int main(void)
{
    CHECK_EQ(ants_inference_ref_model_v1_build(g_model.b, sizeof g_model.b, &g_model_len), ANTS_OK);

    test_wire_req();
    test_wire_resp();
    test_args();
    test_engine_answered_and_auditable();
    test_engine_declined();
    test_engine_rejects_tampered_envelope();
    test_engine_rejects_foreign_signer();
    test_engine_rejects_raw_replies();
    test_engine_silent_peer_times_out();
    test_engine_siblings_do_not_hold_slots();
    test_engine_no_request_on_closing_conn();

    if (failures > 0) {
        fprintf(stderr, "test_infer: %d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "test_infer: all checks passed\n");
    return 0;
}
