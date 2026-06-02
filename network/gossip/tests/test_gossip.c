/*
 * test_gossip.c — Tests for the gossip overlay (Component #6 PR1): the
 * transport-agnostic L1-CRDT dissemination engine + the push-frame codec.
 *
 * The engine is exercised end-to-end against the REAL Component #7 G-Set
 * (ants_crdt) and REAL equivocation proofs signed with REAL Ed25519 keys.
 * Byte delivery is modelled by an in-process "network": each node's send
 * callback enqueues (from, dst, frame); a pump() drains the queue into the
 * destination node's on_message, which may enqueue further forwards — a
 * faithful epidemic simulation that terminates by G-Set dedup, with no
 * QUIC. This lets us assert the load-bearing properties (one new proof
 * reaches every node exactly once; the epidemic stops on duplicates;
 * invalid proofs are rejected not forwarded; a forward never bounces back
 * to its sender) directly.
 */

/* POSIX feature test — required on glibc to expose nanosleep() / struct
 * timespec from <time.h> for the real-QUIC tick spin-loop. macOS exposes them
 * by default; this keeps the Linux CI jobs (gcc/clang) compiling without
 * _GNU_SOURCE. Mirrors the same block in network/dht/tests/test_dht.c. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_crypto.h"
#include "ants_gossip.h"
#include "ants_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

/* ---- proof helpers -------------------------------------------------- */

static void make_key(uint8_t seed, uint8_t priv[32], uint8_t pub[32])
{
    memset(priv, seed, 32);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
}

/* A real, canonical equivocation proof against subject `s_pub` at `epoch`:
 * two statements signed by s_priv over (domain=2, epoch, slot=1) with
 * different payloads. Returns the encoded length. */
static size_t
make_proof(const uint8_t s_priv[32], const uint8_t s_pub[32], uint64_t epoch, uint8_t proof[512])
{
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    const uint8_t pa[3] = {0xA1, 0xA2, 0xA3};
    const uint8_t pb[3] = {0xB1, 0xB2, 0xB3};
    CHECK_EQ(ants_crdt_statement_encode(2, epoch, 1, pa, sizeof pa, body_a, sizeof body_a, &la),
             ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(s_priv, body_a, la, sig_a), ANTS_OK);
    CHECK_EQ(ants_crdt_statement_encode(2, epoch, 1, pb, sizeof pb, body_b, sizeof body_b, &lb),
             ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(s_priv, body_b, lb, sig_b), ANTS_OK);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 s_pub, epoch, body_a, la, sig_a, body_b, lb, sig_b, proof, 512, &plen),
             ANTS_OK);
    return plen;
}

/* ---- in-process network harness ------------------------------------- */

#define HARNESS_MAX_NODES 4
#define HARNESS_QUEUE_CAP 512

struct harness;

typedef struct {
    uint8_t id[32];
    ants_crdt_t *set;
    ants_gossip_t g;
    struct harness *net; /* back-pointer; send_ctx is this node */
} node_t;

typedef struct {
    uint8_t from[32];
    uint8_t dst[32];
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    size_t len;
} qentry_t;

struct harness {
    node_t nodes[HARNESS_MAX_NODES];
    size_t n_nodes;
    qentry_t q[HARNESS_QUEUE_CAP];
    size_t qhead, qtail;
    size_t total_new;      /* proofs accepted-as-new across all deliveries */
    size_t total_rejected; /* proofs rejected across all deliveries        */
    size_t total_sends;    /* send_fn invocations (frames put on the wire)  */
};

/* send_fn: enqueue a copy of the frame for asynchronous delivery. ctx is
 * the sending node, so the queue records who it came from (the receiver's
 * from_peer for exclusion). */
static void harness_send(const uint8_t peer_id[32], const uint8_t *frame, size_t len, void *ctx)
{
    node_t *from = (node_t *)ctx;
    struct harness *h = from->net;
    qentry_t *e;

    CHECK(len <= ANTS_GOSSIP_DEFAULT_MAX_FRAME);
    CHECK(h->qtail < HARNESS_QUEUE_CAP); /* the small tests never overflow */
    if (h->qtail >= HARNESS_QUEUE_CAP) {
        return;
    }
    e = &h->q[h->qtail++];
    memcpy(e->from, from->id, 32);
    memcpy(e->dst, peer_id, 32);
    memcpy(e->frame, frame, len);
    e->len = len;
    h->total_sends++;
}

static node_t *harness_find(struct harness *h, const uint8_t id[32])
{
    size_t i;
    for (i = 0; i < h->n_nodes; i++) {
        if (memcmp(h->nodes[i].id, id, 32) == 0) {
            return &h->nodes[i];
        }
    }
    return NULL;
}

/* Drain the queue: deliver each frame to its destination's on_message,
 * which may enqueue further forwards. Terminates by G-Set dedup. */
static void harness_pump(struct harness *h)
{
    while (h->qhead < h->qtail) {
        qentry_t *e = &h->q[h->qhead++];
        node_t *dst = harness_find(h, e->dst);
        size_t nw = 0, rj = 0;
        if (dst == NULL) {
            continue; /* unknown destination — dropped */
        }
        CHECK_EQ(ants_gossip_on_message(&dst->g, e->from, e->frame, e->len, &nw, &rj), ANTS_OK);
        h->total_new += nw;
        h->total_rejected += rj;
    }
    /* Reset the queue once drained (indices stay bounded across tests). */
    h->qhead = h->qtail = 0;
}

/* Init `n` nodes with keys seeded by base+i; each gets its own G-Set. */
static void harness_init(struct harness *h, size_t n, uint8_t base)
{
    size_t i;
    memset(h, 0, sizeof *h);
    h->n_nodes = n;
    for (i = 0; i < n; i++) {
        uint8_t priv[32];
        make_key((uint8_t)(base + i), priv, h->nodes[i].id);
        CHECK_EQ(ants_crdt_init(&h->nodes[i].set), ANTS_OK);
        h->nodes[i].net = h;
        CHECK_EQ(
            ants_gossip_init(
                &h->nodes[i].g, h->nodes[i].set, h->nodes[i].id, NULL, harness_send, &h->nodes[i]),
            ANTS_OK);
    }
}

static void harness_destroy(struct harness *h)
{
    size_t i;
    for (i = 0; i < h->n_nodes; i++) {
        ants_crdt_destroy(h->nodes[i].set);
    }
}

/* Connect a -> b (a forwards to b). Directed: only adds b to a's view. */
static void link_dir(node_t *a, node_t *b)
{
    CHECK_EQ(ants_gossip_add_peer(&a->g, b->id), ANTS_OK);
}

/* ---- wire codec tests ----------------------------------------------- */

static void test_push_codec_roundtrip(void)
{
    uint8_t sp[32], su[32], proof[512], frame[600];
    size_t plen, flen = 0;
    const uint8_t *out_proof = NULL;
    size_t out_len = 0;

    make_key(0x40, sp, su);
    plen = make_proof(sp, su, 100, proof);

    CHECK_EQ(ants_gossip_push_encode(proof, plen, frame, sizeof frame, &flen), ANTS_OK);
    CHECK(flen > plen); /* envelope adds a few bytes */
    /* The frame is canonical CBOR. */
    CHECK_EQ(ants_cbor_is_canonical(frame, flen), ANTS_OK);

    CHECK_EQ(ants_gossip_push_decode(frame, flen, &out_proof, &out_len), ANTS_OK);
    CHECK(out_len == plen);
    CHECK(memcmp(out_proof, proof, plen) == 0);
    /* The decoded proof still verifies (it is the exact bytes). */
    CHECK_EQ(ants_crdt_verify(out_proof, out_len), ANTS_OK);
}

static void test_push_codec_errors(void)
{
    uint8_t buf[64];
    size_t len = 0;
    const uint8_t *p = NULL;
    size_t pl = 0;
    const uint8_t proof[4] = {1, 2, 3, 4};
    /* well-formed canonical CBOR but not a PUSH frame (a bare uint). */
    const uint8_t bare[1] = {0x05};
    /* non-canonical: non-shortest uint 23. */
    const uint8_t noncanon[2] = {0x18, 0x17};

    /* NULL / empty args. */
    CHECK_EQ(ants_gossip_push_encode(NULL, 4, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_push_encode(proof, 0, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_push_decode(NULL, 4, &p, &pl), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_push_decode(buf, 0, &p, &pl), ANTS_ERROR_INVALID_ARG);

    /* Too-small encode buffer. */
    CHECK_EQ(ants_gossip_push_encode(proof, 4, buf, 2, &len), ANTS_ERROR_BUFFER_TOO_SMALL);

    /* Bad frames. */
    CHECK_EQ(ants_gossip_push_decode(bare, sizeof bare, &p, &pl), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_gossip_push_decode(noncanon, sizeof noncanon, &p, &pl), ANTS_ERROR_NON_CANONICAL);

    /* A well-formed frame with an unknown message type → UNSUPPORTED_TYPE
     * (PUSH-only decode rejects any non-PUSH type, including IHAVE/IWANT).
     * map(2){0: 99 (unknown type), 1: bytes("x")}. */
    {
        ants_cbor_enc_t enc;
        uint8_t f[32];
        size_t fl = 0;
        const uint8_t x[1] = {0x78};
        CHECK_EQ(ants_cbor_enc_init(&enc, f, sizeof f), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 0), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 99u), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_bytes(&enc, x, sizeof x), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
        fl = ants_cbor_enc_size(&enc);
        CHECK_EQ(ants_gossip_push_decode(f, fl, &p, &pl), ANTS_ERROR_UNSUPPORTED_TYPE);
    }
}

/* ---- peer view tests ------------------------------------------------- */

static void test_view_management(void)
{
    struct harness h;
    node_t *a;
    uint8_t peer[32], peerpriv[32];
    size_t i;

    harness_init(&h, 1, 0x10);
    a = &h.nodes[0];
    CHECK(ants_gossip_peer_count(&a->g) == 0);

    make_key(0x90, peerpriv, peer);
    CHECK_EQ(ants_gossip_add_peer(&a->g, peer), ANTS_OK);
    CHECK(ants_gossip_peer_count(&a->g) == 1);
    /* idempotent. */
    CHECK_EQ(ants_gossip_add_peer(&a->g, peer), ANTS_OK);
    CHECK(ants_gossip_peer_count(&a->g) == 1);
    /* self is silently ignored. */
    CHECK_EQ(ants_gossip_add_peer(&a->g, a->id), ANTS_OK);
    CHECK(ants_gossip_peer_count(&a->g) == 1);
    /* remove. */
    CHECK_EQ(ants_gossip_remove_peer(&a->g, peer), ANTS_OK);
    CHECK(ants_gossip_peer_count(&a->g) == 0);
    /* remove not-present is idempotent. */
    CHECK_EQ(ants_gossip_remove_peer(&a->g, peer), ANTS_OK);

    /* Fill to MAX_VIEW, then one more → BUFFER_TOO_SMALL. */
    for (i = 0; i < ANTS_GOSSIP_MAX_VIEW; i++) {
        uint8_t pid[32], ppriv[32];
        make_key((uint8_t)(0xC0 + i), ppriv, pid);
        CHECK_EQ(ants_gossip_add_peer(&a->g, pid), ANTS_OK);
    }
    CHECK(ants_gossip_peer_count(&a->g) == ANTS_GOSSIP_MAX_VIEW);
    {
        uint8_t over[32], opriv[32];
        make_key(0x3F, opriv, over); /* a fresh id not already in the view */
        CHECK_EQ(ants_gossip_add_peer(&a->g, over), ANTS_ERROR_BUFFER_TOO_SMALL);
    }

    /* NULL guards. */
    CHECK_EQ(ants_gossip_add_peer(NULL, peer), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_remove_peer(NULL, peer), ANTS_ERROR_INVALID_ARG);
    CHECK(ants_gossip_peer_count(NULL) == 0);

    harness_destroy(&h);
}

/* ---- dissemination tests -------------------------------------------- */

static void test_submit_forwards_to_view(void)
{
    struct harness h;
    node_t *a, *b;
    uint8_t sp[32], su[32], proof[512];
    size_t plen, fwd = 0;

    harness_init(&h, 2, 0x10);
    a = &h.nodes[0];
    b = &h.nodes[1];
    link_dir(a, b); /* a forwards to b */

    /* A originates a fault proof against some third party S. */
    make_key(0x77, sp, su);
    plen = make_proof(sp, su, 100, proof);

    CHECK_EQ(ants_gossip_submit(&a->g, proof, plen, &fwd), ANTS_OK);
    CHECK(fwd == 1);                         /* sent to b */
    CHECK(ants_crdt_size(a->set) == 1);      /* A holds it */
    CHECK(ants_crdt_is_slashed(a->set, su)); /* and S is slashed at A */
    CHECK(ants_crdt_size(b->set) == 0);      /* not delivered yet */

    harness_pump(&h);
    CHECK(h.total_new == 1);                 /* B accepted it as new */
    CHECK(ants_crdt_size(b->set) == 1);      /* B now holds it */
    CHECK(ants_crdt_is_slashed(b->set, su)); /* S is slashed at B too */

    /* Re-submitting the same proof at A is a no-op (dedup): no new send. */
    {
        size_t sends_before = h.total_sends;
        fwd = 99;
        CHECK_EQ(ants_gossip_submit(&a->g, proof, plen, &fwd), ANTS_OK);
        CHECK(fwd == 0);
        CHECK(h.total_sends == sends_before);
    }

    harness_destroy(&h);
}

/* A→B→C line: a proof submitted at A reaches C via B, and B does not bounce
 * it back to A (sender exclusion). Each node ends with exactly the proof. */
static void test_line_propagation_and_exclusion(void)
{
    struct harness h;
    node_t *a, *b, *c;
    uint8_t sp[32], su[32], proof[512];
    size_t plen, fwd = 0;

    harness_init(&h, 3, 0x20);
    a = &h.nodes[0];
    b = &h.nodes[1];
    c = &h.nodes[2];
    /* Topology: A↔B and B↔C (B has both A and C in its view). */
    link_dir(a, b);
    link_dir(b, a);
    link_dir(b, c);
    link_dir(c, b);

    make_key(0x78, sp, su);
    plen = make_proof(sp, su, 200, proof);

    CHECK_EQ(ants_gossip_submit(&a->g, proof, plen, &fwd), ANTS_OK);
    CHECK(fwd == 1); /* A → B */
    harness_pump(&h);

    /* B received it new and forwarded to C only — NOT back to A (sender
     * exclusion). C received it new; C's only peer is B, the sender, so C
     * forwards to nobody and the epidemic stops. Net: exactly two new
     * acceptances (B, C), and the proof never bounced back to A. */
    CHECK(h.total_new == 2);
    CHECK(ants_crdt_size(a->set) == 1);
    CHECK(ants_crdt_size(b->set) == 1);
    CHECK(ants_crdt_size(c->set) == 1);
    CHECK(ants_crdt_is_slashed(c->set, su)); /* reached the far end */

    harness_destroy(&h);
}

/* A relays an INVALID proof to B: B rejects it (counted), does not store it,
 * and does not forward it. */
static void test_invalid_proof_rejected_not_forwarded(void)
{
    struct harness h;
    node_t *a, *b, *c;
    uint8_t sp[32], su[32], proof[512], frame[600];
    size_t plen, flen = 0, nw = 0, rj = 0;

    harness_init(&h, 3, 0x30);
    a = &h.nodes[0];
    b = &h.nodes[1];
    c = &h.nodes[2];
    link_dir(b, c); /* if B forwarded, C would receive */

    make_key(0x79, sp, su);
    plen = make_proof(sp, su, 300, proof);
    /* Tamper: flip a byte mid-proof so VERIFY fails. */
    proof[plen / 2] ^= 0xFF;
    CHECK_EQ(ants_gossip_push_encode(proof, plen, frame, sizeof frame, &flen), ANTS_OK);

    /* Deliver the bad frame to B as if from A. The frame is well-formed, so
     * on_message returns OK, but the proof is rejected. */
    CHECK_EQ(ants_gossip_on_message(&b->g, a->id, frame, flen, &nw, &rj), ANTS_OK);
    CHECK(nw == 0);
    CHECK(rj == 1);
    CHECK(ants_crdt_size(b->set) == 0); /* not stored */

    harness_pump(&h);                   /* nothing was queued for C */
    CHECK(ants_crdt_size(c->set) == 0); /* not forwarded */

    harness_destroy(&h);
}

/* A malformed (non-decodable) frame is a whole-message error, distinct from
 * a well-framed message carrying a bad proof. */
static void test_malformed_frame_rejected(void)
{
    struct harness h;
    node_t *b;
    /* A truncated map(2) header with no body: declares two pairs but the
     * buffer ends immediately, so it is unambiguously not well-formed CBOR
     * → MALFORMED (distinct from a well-formed frame carrying a bad proof,
     * which is the per-proof reject path). */
    const uint8_t truncated[1] = {0xA2};
    size_t nw = 9, rj = 9;

    harness_init(&h, 1, 0x40);
    b = &h.nodes[0];

    CHECK_EQ(ants_gossip_on_message(&b->g, NULL, truncated, sizeof truncated, &nw, &rj),
             ANTS_ERROR_MALFORMED);
    CHECK(nw == 0 && rj == 0); /* neither new nor a per-proof reject */

    /* An oversized frame is rejected by the size cap, without decoding. The
     * frame is a real, well-formed PUSH frame (so the rejection is the cap,
     * not malformedness); the cap is set one byte below the frame size. */
    {
        ants_gossip_config_t cfg;
        node_t *s = &h.nodes[0];
        uint8_t frame[600];
        size_t fl = 0;
        uint8_t sp[32], su[32], proof[512];
        size_t plen;
        cfg.fanout = 0;
        make_key(0x55, sp, su);
        plen = make_proof(sp, su, 1, proof);
        CHECK_EQ(ants_gossip_push_encode(proof, plen, frame, sizeof frame, &fl), ANTS_OK);
        CHECK(fl > 0);
        /* Cap one byte below the real frame size → rejected without decoding. */
        cfg.max_frame_bytes = fl - 1;
        CHECK_EQ(ants_gossip_init(&s->g, s->set, s->id, &cfg, harness_send, s), ANTS_OK);
        CHECK_EQ(ants_gossip_on_message(&s->g, NULL, frame, fl, &nw, &rj), ANTS_ERROR_MALFORMED);
        /* The same frame within the cap decodes + inserts fine (new). */
        cfg.max_frame_bytes = fl;
        CHECK_EQ(ants_gossip_init(&s->g, s->set, s->id, &cfg, harness_send, s), ANTS_OK);
        CHECK_EQ(ants_gossip_on_message(&s->g, NULL, frame, fl, &nw, &rj), ANTS_OK);
        CHECK(nw == 1 && rj == 0);
    }

    harness_destroy(&h);
}

static void test_engine_args(void)
{
    struct harness h;
    node_t *a;
    uint8_t proof[4] = {1, 2, 3, 4};
    uint8_t self[32], selfpriv[32];
    ants_crdt_t *set = NULL;
    size_t fwd = 0;

    harness_init(&h, 1, 0x50);
    a = &h.nodes[0];

    /* submit NULL guards. */
    CHECK_EQ(ants_gossip_submit(NULL, proof, 4, &fwd), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_submit(&a->g, NULL, 4, &fwd), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_submit(&a->g, proof, 0, &fwd), ANTS_ERROR_INVALID_ARG);
    /* a non-proof byte string fails VERIFY (MALFORMED), not stored. */
    CHECK_EQ(ants_gossip_submit(&a->g, proof, 4, &fwd), ANTS_ERROR_MALFORMED);
    CHECK(fwd == 0);

    /* init NULL guards. */
    make_key(0x51, selfpriv, self);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    CHECK_EQ(ants_gossip_init(NULL, set, self, NULL, harness_send, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_init(&a->g, NULL, self, NULL, harness_send, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_init(&a->g, set, NULL, NULL, harness_send, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_gossip_init(&a->g, set, self, NULL, NULL, NULL), ANTS_ERROR_INVALID_ARG);
    /* fanout larger than the view ceiling is rejected. */
    {
        ants_gossip_config_t cfg;
        cfg.fanout = ANTS_GOSSIP_MAX_VIEW + 1;
        cfg.max_frame_bytes = 0;
        CHECK_EQ(ants_gossip_init(&a->g, set, self, &cfg, harness_send, NULL),
                 ANTS_ERROR_INVALID_ARG);
    }
    ants_crdt_destroy(set);

    harness_destroy(&h);
}

/* ---- lazy-pull anti-entropy (IHAVE / IWANT) ------------------------- */

/* A holds a proof B is missing (a gap the eager push never filled). A
 * announces its digest; B pulls via IWANT; A serves via PUSH. One pump()
 * drains the whole IHAVE→IWANT→PUSH cascade (each step enqueues the next).
 * End state: B holds the proof and applied the slash. */
static void test_lazy_pull_end_to_end(void)
{
    struct harness h;
    node_t *a, *b;
    uint8_t sp[32], su[32], proof[512];
    size_t plen, sent = 0;
    bool ins = false;

    harness_init(&h, 2, 0x60);
    a = &h.nodes[0];
    b = &h.nodes[1];
    link_dir(a, b); /* A advertises to B (announce fans out over A's view) */

    /* A holds a proof directly (no push), so B has a genuine gap. */
    make_key(0x81, sp, su);
    plen = make_proof(sp, su, 100, proof);
    CHECK_EQ(ants_crdt_insert(a->set, proof, plen, &ins), ANTS_OK);
    CHECK(ins == true);
    CHECK(ants_crdt_size(a->set) == 1);
    CHECK(ants_crdt_size(b->set) == 0);

    CHECK_EQ(ants_gossip_announce(&a->g, &sent), ANTS_OK);
    CHECK(sent == 1); /* IHAVE to B */
    harness_pump(&h); /* IHAVE → IWANT → PUSH, all in one drain */

    CHECK(ants_crdt_size(b->set) == 1);      /* B pulled the proof */
    CHECK(ants_crdt_is_slashed(b->set, su)); /* and applied the slash */

    harness_destroy(&h);
}

/* When B already holds everything A advertises, the IHAVE elicits no IWANT
 * (and therefore no PUSH): exactly one frame — the IHAVE — goes on the wire. */
static void test_lazy_pull_no_gap(void)
{
    struct harness h;
    node_t *a, *b;
    uint8_t sp[32], su[32], proof[512];
    size_t plen, sent = 0, sends_before;
    bool ins = false;

    harness_init(&h, 2, 0x68);
    a = &h.nodes[0];
    b = &h.nodes[1];
    link_dir(a, b);

    make_key(0x82, sp, su);
    plen = make_proof(sp, su, 100, proof);
    CHECK_EQ(ants_crdt_insert(a->set, proof, plen, &ins), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(b->set, proof, plen, &ins), ANTS_OK); /* B already has it */

    sends_before = h.total_sends;
    CHECK_EQ(ants_gossip_announce(&a->g, &sent), ANTS_OK);
    CHECK(sent == 1);
    harness_pump(&h);
    /* Only the IHAVE was ever sent: B wanted nothing, A served nothing. */
    CHECK(h.total_sends == sends_before + 1);
    CHECK(ants_crdt_size(b->set) == 1); /* unchanged */

    harness_destroy(&h);
}

/* announce edge cases: NULL guard, empty view, empty G-Set. */
static void test_announce_edges(void)
{
    struct harness h;
    node_t *a, *b;
    uint8_t sp[32], su[32], proof[512];
    size_t plen, sent = 9;
    bool ins = false;

    CHECK_EQ(ants_gossip_announce(NULL, &sent), ANTS_ERROR_INVALID_ARG);

    harness_init(&h, 2, 0x70);
    a = &h.nodes[0];
    b = &h.nodes[1];

    /* Proofs held but empty view → nothing sent. */
    make_key(0x83, sp, su);
    plen = make_proof(sp, su, 100, proof);
    CHECK_EQ(ants_crdt_insert(a->set, proof, plen, &ins), ANTS_OK);
    sent = 9;
    CHECK_EQ(ants_gossip_announce(&a->g, &sent), ANTS_OK);
    CHECK(sent == 0);

    /* A view but an empty G-Set → nothing sent. */
    link_dir(b, a);
    sent = 9;
    CHECK_EQ(ants_gossip_announce(&b->g, &sent), ANTS_OK); /* b's set is empty */
    CHECK(sent == 0);

    harness_destroy(&h);
}

/* IHAVE codec + inbound edges: a valid IHAVE for an id the node lacks elicits
 * one IWANT; an unknown source (from_peer NULL) cannot be replied to; a
 * wrong-width id is MALFORMED. */
static void test_lazy_pull_codec_and_edges(void)
{
    struct harness h;
    node_t *a, *b;
    uint8_t sp[32], su[32], proof[512];
    uint8_t id[ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t ids[1][ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t frame[ANTS_GOSSIP_DEFAULT_MAX_FRAME];
    size_t plen, flen = 0, nw = 9, rj = 9, sends_before;

    harness_init(&h, 2, 0x78);
    a = &h.nodes[0]; /* receives the IHAVE */
    b = &h.nodes[1];
    link_dir(a, b);

    /* A real proof + its content-id; A does NOT hold it. */
    make_key(0x84, sp, su);
    plen = make_proof(sp, su, 100, proof);
    CHECK_EQ(ants_crdt_content_id(proof, plen, id), ANTS_OK);
    memcpy(ids[0], id, ANTS_CRDT_CONTENT_ID_SIZE);

    /* Valid IHAVE advertising that id, delivered to A from B → A lacks it →
     * A emits exactly one IWANT. */
    CHECK_EQ(ants_gossip_ihave_encode(ids, 1, frame, sizeof frame, &flen), ANTS_OK);
    CHECK_EQ(ants_cbor_is_canonical(frame, flen), ANTS_OK);
    sends_before = h.total_sends;
    CHECK_EQ(ants_gossip_on_message(&a->g, b->id, frame, flen, &nw, &rj), ANTS_OK);
    CHECK(nw == 0 && rj == 0);                /* an IHAVE inserts nothing itself */
    CHECK(h.total_sends == sends_before + 1); /* one IWANT emitted to B */

    /* Same IHAVE from an unknown source → cannot reply, nothing sent. */
    sends_before = h.total_sends;
    CHECK_EQ(ants_gossip_on_message(&a->g, NULL, frame, flen, &nw, &rj), ANTS_OK);
    CHECK(h.total_sends == sends_before);

    /* A wrong-width id (31 bytes) in an otherwise canonical IHAVE → MALFORMED. */
    {
        ants_cbor_enc_t enc;
        uint8_t bad[64];
        size_t bl = 0;
        const uint8_t shortid[31] = {0};
        CHECK_EQ(ants_cbor_enc_init(&enc, bad, sizeof bad), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_map(&enc, 2), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 0), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, ANTS_GOSSIP_MSG_IHAVE), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_array(&enc, 1), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_bytes(&enc, shortid, sizeof shortid), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
        bl = ants_cbor_enc_size(&enc);
        CHECK_EQ(ants_gossip_on_message(&a->g, b->id, bad, bl, &nw, &rj), ANTS_ERROR_MALFORMED);
    }

    harness_destroy(&h);
}

/* ---- real-QUIC transport binding ------------------------------------ */

/* Pace a tick spin-loop: picoquic drives its handshake/retransmit timers off
 * the wall clock, so a no-delay fixed-count loop can exhaust before they
 * fire. A 1 ms sleep per iteration lets real time advance (the same macOS-CI
 * flake mitigation as test_dht.c); the loop still breaks as soon as its
 * predicate holds, so green runs stay fast. */
static void tick_pace(void)
{
    struct timespec ts = {0, 1000000L}; /* 1 ms */
    nanosleep(&ts, NULL);
}

/* In-memory-key sign callback (the minimal binding from ants_transport.h):
 * ctx is the 32-byte Ed25519 private key. */
static ants_error_t gt_sign(const uint8_t *transcript, size_t len, uint8_t out_sig[64], void *ctx)
{
    return ants_ed25519_sign((const uint8_t *)ctx, transcript, len, out_sig);
}

/* Per-node event context: forward every transport event into the gossip
 * binding (the single-event_fn delegation pattern) and count CONN_READYs. */
typedef struct {
    ants_gossip_transport_t *binding;
    int conn_ready;
} gt_node_ctx;

static ants_error_t gt_event(const ants_transport_event_t *ev, void *ctx)
{
    gt_node_ctx *n = (gt_node_ctx *)ctx;
    ants_gossip_transport_handle_event(n->binding, ev);
    if (ev->kind == ANTS_TRANSPORT_EV_CONN_READY) {
        n->conn_ready++;
    }
    return ANTS_OK;
}

/* End-to-end over a real QUIC link: A detects a fault and originates the
 * proof; the binding opens a uni stream to B and writes the push frame; B's
 * inbound demux accumulates it to FIN and feeds the engine, which inserts it
 * into B's real G-Set. The L1 reputation path now runs on the wire:
 * detect → submit → uni-stream → demux → VERIFY-insert → slash. */
static void test_two_node_over_quic(void)
{
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
    make_key(0x33, a_priv, a_pub);
    make_key(0x77, b_priv, b_pub);

    ants_crdt_t *a_set = NULL, *b_set = NULL;
    CHECK_EQ(ants_crdt_init(&a_set), ANTS_OK);
    CHECK_EQ(ants_crdt_init(&b_set), ANTS_OK);

    gt_node_ctx actx, bctx;
    memset(&actx, 0, sizeof actx);
    memset(&bctx, 0, sizeof bctx);

    /* B = listener. */
    ants_transport_t tb = {{0}};
    ants_transport_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    memcpy(bcfg.pub, b_pub, 32);
    bcfg.sign_fn = gt_sign;
    bcfg.sign_ctx = b_priv;
    bcfg.event_fn = gt_event;
    bcfg.event_ctx = &bctx;
    bcfg.listen_multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1";
    CHECK_EQ(ants_transport_init(&tb, &bcfg), ANTS_OK);
    char baddr[ANTS_MULTIADDR_MAX_LEN] = {0};
    CHECK_EQ(ants_transport_local_addr(&tb, baddr, sizeof baddr), ANTS_OK);

    /* A = dialer. */
    ants_transport_t ta = {{0}};
    ants_transport_config_t acfg;
    memset(&acfg, 0, sizeof acfg);
    memcpy(acfg.pub, a_pub, 32);
    acfg.sign_fn = gt_sign;
    acfg.sign_ctx = a_priv;
    acfg.event_fn = gt_event;
    acfg.event_ctx = &actx;
    CHECK_EQ(ants_transport_init(&ta, &acfg), ANTS_OK);

    /* Bindings capture (engine, transport) pointers; engines are then
     * initialised with the binding as send_ctx (the two-call wiring). */
    ants_gossip_transport_t a_bind, b_bind;
    ants_gossip_t a_eng, b_eng;
    CHECK_EQ(ants_gossip_transport_init(&a_bind, &a_eng, &ta), ANTS_OK);
    CHECK_EQ(ants_gossip_transport_init(&b_bind, &b_eng, &tb), ANTS_OK);
    actx.binding = &a_bind;
    bctx.binding = &b_bind;
    CHECK_EQ(ants_gossip_init(&a_eng, a_set, a_pub, NULL, ants_gossip_transport_send, &a_bind),
             ANTS_OK);
    CHECK_EQ(ants_gossip_init(&b_eng, b_set, b_pub, NULL, ants_gossip_transport_send, &b_bind),
             ANTS_OK);

    /* A gossips to B. */
    CHECK_EQ(ants_gossip_add_peer(&a_eng, b_pub), ANTS_OK);

    /* Dial and wait until the dialer's handshake completes (A must know B's
     * connection before it can send). */
    ants_transport_conn_t conn = {{0}};
    CHECK_EQ(ants_transport_dial(&ta, baddr, NULL, &conn), ANTS_OK);
    for (int i = 0; i < 500; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (actx.conn_ready >= 1) {
            break;
        }
    }
    CHECK(actx.conn_ready >= 1);
    /* A learned B's connection from CONN_READY → it can route a forward. */
    CHECK(ants_gossip_transport_conn_count(&a_bind) == 1);

    /* A detects an equivocation by a third party S and originates the proof.
     * It inserts into A's G-Set and forwards to B over a real uni stream. */
    uint8_t s_priv[32], s_pub[32], proof[512];
    size_t plen, fwd = 0;
    make_key(0xCC, s_priv, s_pub);
    plen = make_proof(s_priv, s_pub, 100, proof);
    CHECK_EQ(ants_gossip_submit(&a_eng, proof, plen, &fwd), ANTS_OK);
    CHECK(fwd == 1); /* one fanout peer (B) on the wire */
    CHECK(ants_crdt_size(a_set) == 1);
    CHECK(ants_crdt_is_slashed(a_set, s_pub));
    CHECK(ants_crdt_size(b_set) == 0); /* not yet delivered */

    /* Pump both transports until B ingests the proof from the wire. */
    for (int i = 0; i < 500; i++) {
        tick_pace();
        ants_transport_tick(&ta);
        ants_transport_tick(&tb);
        if (ants_crdt_size(b_set) >= 1) {
            break;
        }
    }
    CHECK(ants_crdt_size(b_set) == 1);         /* received over real QUIC */
    CHECK(ants_crdt_is_slashed(b_set, s_pub)); /* S slashed at B too */
    /* By now B's handshake has completed (it delivered a stream), so B has
     * also learned A's connection. */
    CHECK(ants_gossip_transport_conn_count(&b_bind) == 1);

    /* Persistent channel: A forwards two MORE proofs to B over the SAME uni
     * stream (length-prefixed, no per-message FIN). B's deframer must split
     * the continuous byte stream back into individual frames; the outbound
     * channel count stays one (bounded by connections, not proofs). */
    {
        uint8_t p2[512], p3[512];
        size_t l2, l3, f2 = 0, f3 = 0;
        l2 = make_proof(s_priv, s_pub, 101, p2); /* distinct epochs → distinct */
        l3 = make_proof(s_priv, s_pub, 102, p3); /* content-ids, all vs S      */
        CHECK_EQ(ants_gossip_submit(&a_eng, p2, l2, &f2), ANTS_OK);
        CHECK_EQ(ants_gossip_submit(&a_eng, p3, l3, &f3), ANTS_OK);
        CHECK(f2 == 1 && f3 == 1); /* each forwarded to the one peer (B) */
        for (int i = 0; i < 500; i++) {
            tick_pace();
            ants_transport_tick(&ta);
            ants_transport_tick(&tb);
            if (ants_crdt_size(b_set) >= 3) {
                break;
            }
        }
        CHECK(ants_crdt_size(b_set) == 3);                     /* all three deframed */
        CHECK(ants_gossip_transport_conn_count(&a_bind) == 1); /* still one channel  */
    }

    /* Teardown: transports FIRST so their CONN_CLOSED callbacks free the
     * bindings' retained outbound handles while picoquic still owns the
     * connections; then the bindings; then the G-Sets. */
    CHECK_EQ(ants_transport_destroy(&ta, 0), ANTS_OK);
    CHECK_EQ(ants_transport_destroy(&tb, 0), ANTS_OK);
    ants_gossip_transport_destroy(&a_bind);
    ants_gossip_transport_destroy(&b_bind);
    ants_crdt_destroy(a_set);
    ants_crdt_destroy(b_set);
}

int main(void)
{
    test_push_codec_roundtrip();
    test_push_codec_errors();
    test_view_management();
    test_submit_forwards_to_view();
    test_line_propagation_and_exclusion();
    test_invalid_proof_rejected_not_forwarded();
    test_malformed_frame_rejected();
    test_engine_args();
    test_lazy_pull_end_to_end();
    test_lazy_pull_no_gap();
    test_announce_edges();
    test_lazy_pull_codec_and_edges();
    test_two_node_over_quic();

    if (failures == 0) {
        printf("test_gossip: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_gossip: %d check(s) failed\n", failures);
    return 1;
}
