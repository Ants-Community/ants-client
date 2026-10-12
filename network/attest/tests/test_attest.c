/*
 * test_attest.c — RFC-0008 §11.12 codec + the verify-and-tag engine.
 *
 * Codec: canonical bytes written out by hand (independent of the encoder)
 * and the strict-decoder rejections. Engine: two real transports over
 * loopback QUIC, each running an attest engine, covering every verdict a
 * v1 network can actually produce:
 *   - empty presentations both ways          → UNATTESTED (each side);
 *   - a GENUINE Intel TDX quote presented by a peer it is not bound to
 *     (the real quote's report_data is third-party bytes) → REJECTED —
 *     false evidence, the case the gate exists for;
 *   - a vendor this build cannot verify yet (ARM CCA) → UNATTESTED;
 *   - a malformed answer (raw bytes, vendor 0) → REJECTED;
 *   - a peer that never answers               → no verdict, nothing leaks.
 * ATTESTED needs evidence bound to a live peer-id, i.e.
 * ants_attestation_generate on real confidential-compute hardware — the
 * same hardware gate as foundation/tee's positive end-to-end test.
 */

/* POSIX feature test — nanosleep() on glibc. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 199309L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include "ants_attest.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_tee.h"
#include "ants_transport.h"

#include "tdx_kat_vectors.h"

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

/* 2025-01-01T00:00:00Z — inside the TDX KAT's certificate windows, so the
 * genuine quote's evidence verifies and the binding is what decides. */
#define NOW_VALID ((int64_t)1735689600)

/* ------------------------------------------------------------------------ */
/* Codec                                                                    */
/* ------------------------------------------------------------------------ */

static void test_wire_req(void)
{
    /* {0: 9, 1: 7} */
    static const uint8_t want[] = {0xa2, 0x00, 0x09, 0x01, 0x07};
    uint8_t buf[16];
    size_t len = 0;
    CHECK_EQ(ants_attest_wire_encode_req(buf, sizeof buf, &len, 7), ANTS_OK);
    CHECK(len == sizeof want && memcmp(buf, want, len) == 0);
    uint32_t txid = 0;
    CHECK_EQ(ants_attest_wire_decode_req(want, sizeof want, &txid), ANTS_OK);
    CHECK(txid == 7);
    uint64_t type = 0;
    CHECK_EQ(ants_attest_wire_peek_type(want, sizeof want, &type), ANTS_OK);
    CHECK(type == ANTS_ATTEST_MSG_REQ);

    /* An explicit empty body is non-canonical: {0: 9, 1: 7, 2: {}}. */
    static const uint8_t explicit_empty[] = {0xa3, 0x00, 0x09, 0x01, 0x07, 0x02, 0xa0};
    CHECK_EQ(ants_attest_wire_decode_req(explicit_empty, sizeof explicit_empty, &txid),
             ANTS_ERROR_NON_CANONICAL);
    /* A DHT PING ({0: 1, 1: 7}) peeks as type 1 and is not a request. */
    static const uint8_t ping[] = {0xa2, 0x00, 0x01, 0x01, 0x07};
    CHECK_EQ(ants_attest_wire_peek_type(ping, sizeof ping, &type), ANTS_OK);
    CHECK(type == 1);
    CHECK_EQ(ants_attest_wire_decode_req(ping, sizeof ping, &txid), ANTS_ERROR_NON_CANONICAL);
    /* txid above 2^32-1: {0: 9, 1: 0x100000000}. */
    static const uint8_t big_txid[] = {
        0xa2, 0x00, 0x09, 0x01, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    CHECK_EQ(ants_attest_wire_decode_req(big_txid, sizeof big_txid, &txid),
             ANTS_ERROR_NON_CANONICAL);
    /* Trailing byte. */
    static const uint8_t trailing[] = {0xa2, 0x00, 0x09, 0x01, 0x07, 0x00};
    CHECK(ants_attest_wire_decode_req(trailing, sizeof trailing, &txid) != ANTS_OK);
}

static void test_wire_resp(void)
{
    uint8_t buf[64];
    size_t len = 0;
    uint32_t txid = 0;
    ants_attest_presentation_t p;

    /* Empty answer: {0: 10, 1: 7}. */
    static const uint8_t empty[] = {0xa2, 0x00, 0x0a, 0x01, 0x07};
    CHECK_EQ(ants_attest_wire_encode_resp(buf, sizeof buf, &len, 7, NULL), ANTS_OK);
    CHECK(len == sizeof empty && memcmp(buf, empty, len) == 0);
    CHECK_EQ(ants_attest_wire_decode_resp(empty, sizeof empty, &txid, &p), ANTS_OK);
    CHECK(txid == 7 && !p.present);

    /* A presentation: {0: 10, 1: 7, 2: {0: 2, 1: 1735689600, 2: 0, 3: h'616263'}}. */
    static const uint8_t full[] = {0xa3, 0x00, 0x0a, 0x01, 0x07, 0x02, 0xa4, 0x00,
                                   0x02, 0x01, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x02,
                                   0x00, 0x03, 0x43, 0x61, 0x62, 0x63};
    static const uint8_t abc[] = {'a', 'b', 'c'};
    ants_attest_presentation_t in;
    memset(&in, 0, sizeof in);
    in.present = true;
    in.vendor = ANTS_TEE_VENDOR_AMD_SEV_SNP;
    in.issued_at_unix = NOW_VALID;
    in.expires_at_unix = 0;
    in.blob = abc;
    in.blob_len = sizeof abc;
    CHECK_EQ(ants_attest_wire_encode_resp(buf, sizeof buf, &len, 7, &in), ANTS_OK);
    CHECK(len == sizeof full && memcmp(buf, full, len) == 0);
    CHECK_EQ(ants_attest_wire_decode_resp(full, sizeof full, &txid, &p), ANTS_OK);
    CHECK(txid == 7 && p.present && p.vendor == ANTS_TEE_VENDOR_AMD_SEV_SNP);
    CHECK(p.issued_at_unix == NOW_VALID && p.expires_at_unix == 0);
    CHECK(p.blob_len == 3 && p.blob == full + sizeof full - 3); /* borrowed */

    /* Strict-decoder rejections, each a one-byte mutation of `full`. */
    uint8_t m[sizeof full];
    memcpy(m, full, sizeof m);
    m[8] = 0x00; /* vendor 0 */
    CHECK_EQ(ants_attest_wire_decode_resp(m, sizeof m, &txid, &p), ANTS_ERROR_MALFORMED);
    CHECK(!p.present);
    memcpy(m, full, sizeof m);
    m[7] = 0x01; /* key 1 where key 0 belongs */
    CHECK_EQ(ants_attest_wire_decode_resp(m, sizeof m, &txid, &p), ANTS_ERROR_NON_CANONICAL);
    memcpy(m, full, sizeof m);
    m[2] = 0x09; /* type 9 (a request) */
    CHECK_EQ(ants_attest_wire_decode_resp(m, sizeof m, &txid, &p), ANTS_ERROR_NON_CANONICAL);

    /* Explicit empty body: {0: 10, 1: 7, 2: {}}. */
    static const uint8_t explicit_empty[] = {0xa3, 0x00, 0x0a, 0x01, 0x07, 0x02, 0xa0};
    CHECK_EQ(ants_attest_wire_decode_resp(explicit_empty, sizeof explicit_empty, &txid, &p),
             ANTS_ERROR_NON_CANONICAL);
    /* Empty blob: ... 3: h''. */
    static const uint8_t empty_blob[] = {
        0xa3, 0x00, 0x0a, 0x01, 0x07, 0x02, 0xa4, 0x00, 0x02, 0x01, 0x00, 0x02, 0x00, 0x03, 0x40};
    CHECK_EQ(ants_attest_wire_decode_resp(empty_blob, sizeof empty_blob, &txid, &p),
             ANTS_ERROR_MALFORMED);

    /* Blob size limit: ATTESTATION_MAX_BLOB_BYTES encodes, one more is
     * refused by the encoder and rejected by the decoder. */
    uint8_t *blob = (uint8_t *)calloc(1, ANTS_ATTEST_MAX_BLOB_BYTES + 1);
    uint8_t *big = (uint8_t *)malloc(ANTS_ATTEST_MAX_RESP_BYTES + 64);
    CHECK(blob != NULL && big != NULL);
    if (blob != NULL && big != NULL) {
        in.blob = blob;
        in.blob_len = ANTS_ATTEST_MAX_BLOB_BYTES;
        CHECK_EQ(ants_attest_wire_encode_resp(big, ANTS_ATTEST_MAX_RESP_BYTES + 64, &len, 7, &in),
                 ANTS_OK);
        CHECK_EQ(ants_attest_wire_decode_resp(big, len, &txid, &p), ANTS_OK);
        in.blob_len = ANTS_ATTEST_MAX_BLOB_BYTES + 1;
        CHECK_EQ(ants_attest_wire_encode_resp(big, ANTS_ATTEST_MAX_RESP_BYTES + 64, &len, 7, &in),
                 ANTS_ERROR_INVALID_ARG);
        /* Hand-patch the oversized blob into a valid frame: the bstr head
         * at offset 18 is 0x59 + u16 length; one more byte of blob. */
        in.blob_len = ANTS_ATTEST_MAX_BLOB_BYTES;
        CHECK_EQ(ants_attest_wire_encode_resp(big, ANTS_ATTEST_MAX_RESP_BYTES + 64, &len, 7, &in),
                 ANTS_OK);
        CHECK(big[18] == 0x59);
        big[19] = (uint8_t)((ANTS_ATTEST_MAX_BLOB_BYTES + 1) >> 8);
        big[20] = (uint8_t)((ANTS_ATTEST_MAX_BLOB_BYTES + 1) & 0xFF);
        big[len] = 0x00;
        CHECK_EQ(ants_attest_wire_decode_resp(big, len + 1, &txid, &p), ANTS_ERROR_MALFORMED);
        /* Above the response cap: rejected before decoding. */
        CHECK_EQ(ants_attest_wire_decode_resp(big, ANTS_ATTEST_MAX_RESP_BYTES + 1, &txid, &p),
                 ANTS_ERROR_BUFFER_TOO_SMALL);
    }
    free(blob);
    free(big);

    /* Encoder refuses presentations that would not decode. */
    in.blob = abc;
    in.blob_len = sizeof abc;
    in.vendor = ANTS_TEE_VENDOR_UNKNOWN;
    CHECK_EQ(ants_attest_wire_encode_resp(buf, sizeof buf, &len, 7, &in), ANTS_ERROR_INVALID_ARG);
    in.vendor = ANTS_TEE_VENDOR_INTEL_TDX;
    in.issued_at_unix = -1;
    CHECK_EQ(ants_attest_wire_encode_resp(buf, sizeof buf, &len, 7, &in), ANTS_ERROR_INVALID_ARG);
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

typedef struct {
    ants_attest_t *attest; /* NULL: this side runs no engine (silent peer) */
    /* Raw-answer mode: reply to any inbound bidi request with these bytes
     * instead of running the engine's answer path. */
    const uint8_t *raw_reply;
    size_t raw_reply_len;
    ants_transport_stream_t *raw_stream;
    /* Verdict observed by this side about its peer. */
    int verdicts;
    ants_attest_result_t last;
    ants_transport_conn_t *ready_conn;
} side_t;

static void on_verdict(const ants_attest_result_t *r, void *ctx)
{
    side_t *s = (side_t *)ctx;
    s->verdicts++;
    s->last = *r;
}

static ants_error_t side_event(const ants_transport_event_t *ev, void *ctx)
{
    side_t *s = (side_t *)ctx;
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        s->ready_conn = ev->conn;
    }
    if (s->raw_reply != NULL) {
        if (ev->kind == ANTS_TRANSPORT_EV_STREAM_OPENED) {
            s->raw_stream = ev->stream;
        } else if (ev->kind == ANTS_TRANSPORT_EV_STREAM_FIN && ev->stream == s->raw_stream) {
            (void)ants_transport_stream_send(ev->stream, s->raw_reply, s->raw_reply_len, true);
        }
        return ANTS_OK;
    }
    if (s->attest != NULL) {
        ants_attest_handle_transport_event(s->attest, ev, NOW_VALID);
    }
    return ANTS_OK;
}

/* One A (dialer) ↔ B (listener) run. A always runs an engine with
 * request_on_ready; B runs one answering with `b_local` unless `b_mode`
 * says otherwise. Drives until A has a verdict (or the budget runs out). */
enum { B_ENGINE, B_SILENT, B_RAW };

static void run_pair(int b_mode,
                     const ants_attest_presentation_t *b_local,
                     const uint8_t *raw,
                     size_t raw_len,
                     side_t *out_a,
                     side_t *out_b)
{
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE], a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE], b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x31, sizeof a_priv);
    memset(b_priv, 0x32, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    static ants_attest_t att_a, att_b;
    memset(out_a, 0, sizeof *out_a);
    memset(out_b, 0, sizeof *out_b);
    out_a->attest = &att_a;

    ants_attest_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    acfg.freshness_window_seconds = ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS;
    acfg.request_on_ready = true;
    acfg.verdict_fn = on_verdict;
    acfg.verdict_ctx = out_a;
    CHECK_EQ(ants_attest_init(&att_a, &acfg), ANTS_OK);

    if (b_mode == B_ENGINE) {
        out_b->attest = &att_b;
        ants_attest_config_t bcfg = acfg;
        bcfg.local = b_local;
        bcfg.verdict_ctx = out_b;
        CHECK_EQ(ants_attest_init(&att_b, &bcfg), ANTS_OK);
    } else if (b_mode == B_RAW) {
        out_b->raw_reply = raw;
        out_b->raw_reply_len = raw_len;
    }

    static ants_transport_t tb, ta;
    memset(&tb, 0, sizeof tb);
    memset(&ta, 0, sizeof ta);
    ants_transport_config_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, b_pub, sizeof b_pub);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = b_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = out_b;
    tcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &tcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, a_pub, sizeof a_pub);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = a_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = out_a;
    CHECK_EQ(ants_transport_init(&ta, &tcfg), ANTS_OK);

    static ants_transport_conn_t conn;
    memset(&conn, 0, sizeof conn);
    ants_peer_id_t expect;
    memcpy(expect.bytes, b_pub, sizeof b_pub);
    CHECK_EQ(ants_transport_dial(&ta, baddr, &expect, &conn), ANTS_OK);

    /* A silent peer never answers: give it a bounded window, then stop. */
    int budget = b_mode == B_SILENT ? 300 : 2000;
    for (int i = 0; i < budget; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (out_a->verdicts > 0 && (b_mode != B_ENGINE || out_b->verdicts > 0)) {
            break;
        }
    }
    if (out_a->verdicts > 0) {
        /* The verdict is about B, on the dialed connection, and cached. */
        CHECK(memcmp(out_a->last.peer_id.bytes, b_pub, sizeof b_pub) == 0);
        CHECK(out_a->last.conn == &conn);
        CHECK(ants_attest_verdict_for(&att_a, &conn) == out_a->last.verdict);
        /* One request per connection: asking again is a no-op. */
        CHECK_EQ(ants_attest_request(&att_a, &conn), ANTS_OK);
    } else {
        CHECK(ants_attest_verdict_for(&att_a, &conn) == ANTS_ATTEST_VERDICT_NONE);
    }

    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    ants_attest_destroy(&att_a); /* frees any exchange still in flight (ASan) */
    if (b_mode == B_ENGINE) {
        ants_attest_destroy(&att_b);
    }
}

static void test_engine_unattested_both_ways(void)
{
    side_t a, b;
    run_pair(B_ENGINE, NULL, NULL, 0, &a, &b);
    CHECK(a.verdicts == 1);
    CHECK(a.last.verdict == ANTS_ATTEST_VERDICT_UNATTESTED);
    CHECK(a.last.vendor == ANTS_TEE_VENDOR_UNKNOWN);
    /* B asked too (request_on_ready on the accepted conn) and got A's {}. */
    CHECK(b.verdicts == 1);
    CHECK(b.last.verdict == ANTS_ATTEST_VERDICT_UNATTESTED);
}

static void test_engine_rejects_unbound_genuine_quote(void)
{
    /* B presents a GENUINE Intel TDX quote. Its chain and signatures are
     * real (the evidence half passes), but its report_data does not bind
     * B's peer-id and issued_at — a relayed / foreign attestation. */
    ants_attest_presentation_t p;
    memset(&p, 0, sizeof p);
    p.present = true;
    p.vendor = ANTS_TEE_VENDOR_INTEL_TDX;
    p.issued_at_unix = NOW_VALID;
    p.blob = TDX_KAT_QUOTE;
    p.blob_len = sizeof TDX_KAT_QUOTE;
    side_t a, b;
    run_pair(B_ENGINE, &p, NULL, 0, &a, &b);
    CHECK(a.verdicts == 1);
    CHECK(a.last.verdict == ANTS_ATTEST_VERDICT_REJECTED);
    CHECK(a.last.vendor == ANTS_TEE_VENDOR_INTEL_TDX);
    CHECK(a.last.issued_at_unix == NOW_VALID);
}

static void test_engine_unverifiable_vendor_is_unattested(void)
{
    static const uint8_t blob[] = {0x01, 0x02, 0x03};
    ants_attest_presentation_t p;
    memset(&p, 0, sizeof p);
    p.present = true;
    p.vendor = ANTS_TEE_VENDOR_ARM_CCA; /* v1.x: not wired in this build */
    p.issued_at_unix = NOW_VALID;
    p.blob = blob;
    p.blob_len = sizeof blob;
    side_t a, b;
    run_pair(B_ENGINE, &p, NULL, 0, &a, &b);
    CHECK(a.verdicts == 1);
    CHECK(a.last.verdict == ANTS_ATTEST_VERDICT_UNATTESTED);
    CHECK(a.last.vendor == ANTS_TEE_VENDOR_ARM_CCA);
}

static void test_engine_rejects_malformed_answer(void)
{
    /* {0: 10, 1: 1, 2: {0: 0, 1: 0, 2: 0, 3: h'00'}} — vendor 0. The txid
     * is A's first (1), so only the vendor makes it malformed. */
    static const uint8_t raw[] = {0xa3,
                                  0x00,
                                  0x0a,
                                  0x01,
                                  0x01,
                                  0x02,
                                  0xa4,
                                  0x00,
                                  0x00,
                                  0x01,
                                  0x00,
                                  0x02,
                                  0x00,
                                  0x03,
                                  0x41,
                                  0x00};
    side_t a, b;
    run_pair(B_RAW, NULL, raw, sizeof raw, &a, &b);
    CHECK(a.verdicts == 1);
    CHECK(a.last.verdict == ANTS_ATTEST_VERDICT_REJECTED);

    /* A well-formed empty answer echoing the WRONG txid is malformed too. */
    static const uint8_t wrong_txid[] = {0xa2, 0x00, 0x0a, 0x01, 0x05};
    run_pair(B_RAW, NULL, wrong_txid, sizeof wrong_txid, &a, &b);
    CHECK(a.verdicts == 1);
    CHECK(a.last.verdict == ANTS_ATTEST_VERDICT_REJECTED);
}

static void test_engine_silent_peer_no_verdict(void)
{
    /* B speaks QUIC but not §11.12 (no engine): A's request goes
     * unanswered, no verdict is ever produced, and destroying everything
     * frees the in-flight exchange (ASan would flag a leak). */
    side_t a, b;
    run_pair(B_SILENT, NULL, NULL, 0, &a, &b);
    CHECK(a.verdicts == 0);
}

static void test_engine_inbound_cap_per_conn(void)
{
    /* A peer holding two never-finished bidi streams on its connection
     * has used up its inbound share: B does not even buffer a third, so
     * A's ATTEST_REQ on it goes unanswered. (The share is per connection,
     * so a flooder starves only itself.) Control: the same request
     * without the stalled streams is answered — every other engine test. */
    uint8_t a_priv[ANTS_ED25519_PRIVKEY_SIZE], a_pub[ANTS_ED25519_PUBKEY_SIZE];
    uint8_t b_priv[ANTS_ED25519_PRIVKEY_SIZE], b_pub[ANTS_ED25519_PUBKEY_SIZE];
    memset(a_priv, 0x41, sizeof a_priv);
    memset(b_priv, 0x42, sizeof b_priv);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(a_priv, a_pub), ANTS_OK);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(b_priv, b_pub), ANTS_OK);

    static ants_attest_t att_a, att_b;
    static side_t a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    a.attest = &att_a;
    b.attest = &att_b;
    ants_attest_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.freshness_window_seconds = ANTS_TEE_DEFAULT_FRESHNESS_WINDOW_SECONDS;
    cfg.verdict_fn = on_verdict;
    cfg.verdict_ctx = &a;
    CHECK_EQ(ants_attest_init(&att_a, &cfg), ANTS_OK); /* no request_on_ready */
    cfg.verdict_ctx = &b;
    CHECK_EQ(ants_attest_init(&att_b, &cfg), ANTS_OK);

    static ants_transport_t ta, tb;
    memset(&ta, 0, sizeof ta);
    memset(&tb, 0, sizeof tb);
    ants_transport_config_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, b_pub, sizeof b_pub);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = b_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = &b;
    tcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &tcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);
    memset(&tcfg, 0, sizeof tcfg);
    memcpy(tcfg.pub, a_pub, sizeof a_pub);
    tcfg.sign_fn = real_sign;
    tcfg.sign_ctx = a_priv;
    tcfg.event_fn = side_event;
    tcfg.event_ctx = &a;
    CHECK_EQ(ants_transport_init(&ta, &tcfg), ANTS_OK);
    static ants_transport_conn_t conn;
    memset(&conn, 0, sizeof conn);
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 500 && a.ready_conn == NULL; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }
    CHECK(a.ready_conn != NULL);

    /* Two stalled streams: one byte each, never FIN'd. */
    static ants_transport_stream_t stall[2];
    static const uint8_t junk = 0xa2;
    for (int k = 0; k < 2; k++) {
        memset(&stall[k], 0, sizeof stall[k]);
        CHECK_EQ(ants_transport_open_bidi_stream(&conn, &stall[k]), ANTS_OK);
        CHECK_EQ(ants_transport_stream_send(&stall[k], &junk, 1, false), ANTS_OK);
    }
    for (int i = 0; i < 100; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }
    CHECK_EQ(ants_attest_request(&att_a, &conn), ANTS_OK);
    for (int i = 0; i < 300 && a.verdicts == 0; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
    }
    CHECK(a.verdicts == 0);

    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    ants_attest_destroy(&att_a);
    ants_attest_destroy(&att_b);
}

static void test_init_args(void)
{
    static ants_attest_t at;
    ants_attest_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    CHECK_EQ(ants_attest_init(NULL, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_attest_init(&at, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_attest_init(&at, &cfg), ANTS_ERROR_INVALID_ARG); /* window 0 */
    cfg.freshness_window_seconds = 1;
    CHECK_EQ(ants_attest_init(&at, &cfg), ANTS_OK);
    ants_attest_presentation_t bad;
    memset(&bad, 0, sizeof bad);
    bad.present = true; /* vendor 0, no blob */
    cfg.local = &bad;
    CHECK_EQ(ants_attest_init(&at, &cfg), ANTS_ERROR_INVALID_ARG);
    CHECK(ants_attest_verdict_for(NULL, NULL) == ANTS_ATTEST_VERDICT_NONE);
    ants_attest_destroy(NULL);
}

int main(void)
{
    test_wire_req();
    test_wire_resp();
    test_init_args();
    test_engine_unattested_both_ways();
    test_engine_rejects_unbound_genuine_quote();
    test_engine_unverifiable_vendor_is_unattested();
    test_engine_rejects_malformed_answer();
    test_engine_silent_peer_no_verdict();
    test_engine_inbound_cap_per_conn();
    if (failures == 0) {
        printf("test_attest: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_attest: %d check(s) FAILED\n", failures);
    return 1;
}
