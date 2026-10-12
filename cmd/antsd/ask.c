/*
 * cmd/antsd/ask.c — `antsd ask`: one inference request to a node.
 *
 * A one-shot requester: a throwaway Ed25519 identity (a requester needs a
 * TLS key, not a reputation), one QUIC connection pinned to the producer's
 * peer-id, one INFER_REQ (RFC-0008 §11.14). The answer is checked by the
 * exchange engine — commit signature under the peer-id this connection
 * authenticated, the commit against the request, the envelope against the
 * commit (the §11.8 integrity gate) — and the verdict printed. The audit
 * against B_{r+1} is not run here: v1 pins no beacon for it yet (RFC-0008
 * §10).
 */
#define _POSIX_C_SOURCE 200809L

#include "ask.h"

#include "util.h"

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_infer.h"
#include "ants_inference.h"
#include "ants_transport.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* How long the whole exchange may take: handshake plus answer. */
#define ANTSD_ASK_DEADLINE_MS 30000u

typedef struct {
    ants_infer_t *infer;
    ants_transport_conn_t *ready;
    bool closed;
    bool done;
    ants_infer_verdict_t verdict;
    ants_inference_commit_t commit;
    uint8_t tokens[ANTS_INFER_MAX_POSITIONS];
    size_t n_tokens;
} ask_state_t;

static ants_error_t ask_sign(const uint8_t *transcript,
                             size_t transcript_len,
                             uint8_t out_sig[ANTS_ED25519_SIG_SIZE],
                             void *sign_ctx)
{
    return ants_ed25519_sign((const uint8_t *)sign_ctx, transcript, transcript_len, out_sig);
}

static ants_error_t ask_event(const ants_transport_event_t *ev, void *ctx)
{
    ask_state_t *st = (ask_state_t *)ctx;
    if (st->infer != NULL) {
        ants_infer_handle_transport_event(st->infer, ev);
    }
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        st->ready = ev->conn;
    } else if (ev->kind == ANTS_TRANSPORT_EV_CONN_CLOSED) {
        st->closed = true;
    }
    return ANTS_OK;
}

/* The generated tokens: key 1 of the (already checked) answer envelope. */
static void envelope_tokens(const uint8_t *env, size_t len, ask_state_t *st)
{
    ants_cbor_dec_t dec;
    size_t n;
    uint64_t key;
    const uint8_t *p;
    size_t plen;
    if (ants_cbor_dec_init(&dec, env, len) != ANTS_OK || ants_cbor_dec_map(&dec, &n) != ANTS_OK ||
        ants_cbor_dec_uint(&dec, &key) != ANTS_OK ||
        ants_cbor_dec_bytes(&dec, &p, &plen) != ANTS_OK ||
        ants_cbor_dec_uint(&dec, &key) != ANTS_OK ||
        ants_cbor_dec_bytes(&dec, &p, &plen) != ANTS_OK || plen > sizeof st->tokens) {
        return;
    }
    memcpy(st->tokens, p, plen);
    st->n_tokens = plen;
}

static void ask_result(const ants_infer_result_t *r, void *ctx)
{
    ask_state_t *st = (ask_state_t *)ctx;
    st->done = true;
    st->verdict = r->verdict;
    if (r->verdict == ANTS_INFER_VERDICT_ANSWERED) {
        st->commit = r->commit;
        envelope_tokens(r->envelope, r->envelope_len, st);
    }
}

static uint64_t ask_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void ask_nap(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (long)ms * 1000000L;
    nanosleep(&ts, NULL);
}

static const char *verdict_name(ants_infer_verdict_t v)
{
    switch (v) {
    case ANTS_INFER_VERDICT_ANSWERED:
        return "answered";
    case ANTS_INFER_VERDICT_DECLINED:
        return "declined";
    case ANTS_INFER_VERDICT_REJECTED:
        return "rejected";
    default:
        return "no-answer";
    }
}

int antsd_cmd_ask(const char *addr, const char *peer_hex, const char *prompt, unsigned tier)
{
    static ants_transport_t transport; /* 16 KB — off the stack */
    static ants_infer_t infer;
    static ants_transport_conn_t conn;
    static ask_state_t st;
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    ants_peer_id_t expect;
    ants_transport_config_t tcfg;
    ants_infer_config_t xcfg;
    ants_infer_request_t req;
    size_t prompt_len = strlen(prompt);
    bool sent = false;
    ants_error_t rc;
    int exit_code = 1;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (antsd_hex_parse(peer_hex, expect.bytes, sizeof expect.bytes) != 0) {
        fprintf(stderr, "antsd: peer id must be 64 hex digits\n");
        return 2;
    }
    if (prompt_len == 0 || prompt_len > ANTS_INFER_MAX_INPUT_BYTES) {
        fprintf(stderr, "antsd: prompt must be 1..%u bytes\n", ANTS_INFER_MAX_INPUT_BYTES);
        return 2;
    }
    if (antsd_read_random(priv, sizeof priv) != 0 ||
        ants_ed25519_pubkey_from_priv(priv, pub) != ANTS_OK) {
        fprintf(stderr, "antsd: could not make a throwaway identity\n");
        return 1;
    }

    memset(&st, 0, sizeof st);
    memset(&xcfg, 0, sizeof xcfg);
    xcfg.result_fn = ask_result;
    xcfg.result_ctx = &st;
    xcfg.timeout_ms = ANTSD_ASK_DEADLINE_MS;
    if (ants_infer_init(&infer, &xcfg) != ANTS_OK) {
        return 1;
    }
    st.infer = &infer;

    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, pub, sizeof pub);
    tcfg.sign_fn = ask_sign;
    tcfg.sign_ctx = priv;
    tcfg.event_fn = ask_event;
    tcfg.event_ctx = &st;
    rc = ants_transport_init(&transport, &tcfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: transport init failed: %s\n", ants_strerror(rc));
        ants_infer_destroy(&infer);
        return 1;
    }
    memset(&conn, 0, sizeof conn);
    rc = ants_transport_dial(&transport, addr, &expect, &conn);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: dial %s failed: %s\n", addr, ants_strerror(rc));
        ants_transport_destroy(&transport, 0);
        ants_infer_destroy(&infer);
        return 1;
    }

    memset(&req, 0, sizeof req);
    req.input = (const uint8_t *)prompt;
    req.input_len = prompt_len;
    req.tier = tier;
    if (antsd_read_random(req.req_nonce, sizeof req.req_nonce) != 0) {
        ants_transport_destroy(&transport, 0);
        ants_infer_destroy(&infer);
        return 1;
    }

    uint64_t start = ask_now_ms();
    while (!st.done && !(st.closed && !sent) && ask_now_ms() - start < ANTSD_ASK_DEADLINE_MS) {
        ants_transport_tick(&transport);
        if (st.ready != NULL && !sent) {
            rc = ants_infer_request(&infer, st.ready, &req, ask_now_ms(), NULL);
            if (rc != ANTS_OK) {
                fprintf(stderr, "antsd: request failed: %s\n", ants_strerror(rc));
                break;
            }
            sent = true;
        }
        ants_infer_tick(&infer, ask_now_ms());
        ask_nap(1);
    }

    if (!sent) {
        printf("antsd: ask verdict=no-answer (no connection to %s)\n", addr);
    } else {
        printf("antsd: ask verdict=%s\n", verdict_name(st.verdict));
    }
    if (st.done && st.verdict == ANTS_INFER_VERDICT_ANSWERED) {
        char hex[ANTS_INFERENCE_HASH_SIZE * 2 + 1];
        char text[ANTS_INFER_MAX_POSITIONS + 1];
        antsd_hex_format(st.commit.model_hash, sizeof st.commit.model_hash, hex, sizeof hex);
        printf("antsd: ask round=%" PRIu64 " tier=%u positions=%u model=%s\n",
               st.commit.round,
               (unsigned)st.commit.tier,
               (unsigned)st.commit.length,
               hex);
        antsd_hex_format(st.commit.root, sizeof st.commit.root, hex, sizeof hex);
        printf("antsd: ask root=%s\n", hex);
        for (size_t i = 0; i < st.n_tokens; i++) {
            uint8_t c = st.tokens[i];
            text[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        text[st.n_tokens] = '\0';
        printf("antsd: ask tokens=\"%s\"\n", text);
        exit_code = 0;
    }

    /* Close politely: ants_transport_destroy does not put a
     * CONNECTION_CLOSE on the wire, so without this the node would hold
     * the connection until its idle timeout. */
    if (st.ready != NULL && !st.closed) {
        (void)ants_transport_peer_disconnect(st.ready, 0);
        for (int i = 0; i < 100 && !st.closed; i++) {
            ants_transport_tick(&transport);
            ask_nap(1);
        }
    }
    ants_transport_destroy(&transport, 0);
    ants_infer_destroy(&infer);
    memset(priv, 0, sizeof priv);
    return exit_code;
}
