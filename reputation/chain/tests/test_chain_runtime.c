/*
 * test_chain_runtime.c — the L2 block-production state machine, driven as a
 * small in-process network: several nodes with real Ed25519 keys, a fake
 * clock stepping one second at a time, and a bus that delivers every
 * proposal / attestation a node broadcasts to every other online node.
 *
 * Covered: a healthy committee finalising consecutive heights; an offline
 * proposer (the attempt is skipped after the finality timeout and a later
 * height finalises on the same prev); a member whose Layer-1 view differs
 * (it abstains; 2/3 still finalise; it adopts the result); no quorum (heads
 * stay at genesis, attempts keep skipping); a late observer catching up by
 * adoption; the one-signature-per-height equivocation guard; a forged
 * attestation; a single-trustee chain; init argument checks.
 */

#include "ants_chain.h"
#include "ants_chain_runtime.h"
#include "ants_common.h"
#include "ants_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

#define GENESIS_TIME ((uint64_t)1735689600) /* 2025-01-01T00:00:00Z */
#define MAX_NODES    6
#define BUS_CAP      512
#define MSG_MAX      2048

/* ------------------------------------------------------------------------ */
/* Layer-1 view: a few fault events with timestamps                         */
/* ------------------------------------------------------------------------ */

/* Each item is one visible proof (content-id) and its decoded event; it is
 * visible at cutoff iff its timestamp <= cutoff. */
typedef struct {
    uint8_t id[ANTS_CHAIN_HASH_SIZE];
    ants_chain_event_t ev;
} l1_item_t;

#define L1_ITEMS 3
static l1_item_t g_l1[L1_ITEMS];

static void l1_init(void)
{
    for (int i = 0; i < L1_ITEMS; i++) {
        memset(&g_l1[i], 0, sizeof g_l1[i]);
        memset(g_l1[i].id, 0x10 * (i + 1), ANTS_CHAIN_HASH_SIZE); /* ascending */
        memset(g_l1[i].ev.subject, 0xC0 + i, ANTS_CHAIN_PEER_ID_SIZE);
        g_l1[i].ev.timestamp = GENESIS_TIME + 5 + (uint64_t)i * 40; /* 5, 45, 85 */
        g_l1[i].ev.fault_type = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* Nodes and bus                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    int idx;
    uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE];
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    bool online;
    bool extra_proof; /* sees one extra proof: its view diverges */
    ants_chain_rt_t rt;
    /* view scratch */
    uint8_t ids[L1_ITEMS + 1][ANTS_CHAIN_HASH_SIZE];
    ants_chain_event_t events[L1_ITEMS + 1];
    /* observations */
    int finals;
    uint64_t final_heights[64];
    int attestations_emitted;
    uint64_t attested_heights[64];
} node_t;

typedef struct {
    int from;
    bool is_proposal;
    size_t len;
    uint8_t bytes[MSG_MAX];
    ants_chain_attestation_t att;
} msg_t;

static node_t g_nodes[MAX_NODES];
static int g_n_nodes;
static msg_t g_bus[BUS_CAP];
static int g_bus_n;
static uint64_t g_now;

static ants_error_t
node_sign(const uint8_t hash[ANTS_CHAIN_HASH_SIZE], uint8_t out_sig[ANTS_CHAIN_SIG_SIZE], void *ctx)
{
    node_t *n = (node_t *)ctx;
    return ants_ed25519_sign(n->priv, hash, ANTS_CHAIN_HASH_SIZE, out_sig);
}

static ants_error_t node_view(uint64_t cutoff,
                              const uint8_t (**out_ids)[ANTS_CHAIN_HASH_SIZE],
                              size_t *out_n_ids,
                              const ants_chain_event_t **out_events,
                              size_t *out_n_events,
                              void *ctx)
{
    node_t *n = (node_t *)ctx;
    size_t k = 0;
    for (int i = 0; i < L1_ITEMS; i++) {
        if (g_l1[i].ev.timestamp <= cutoff) {
            memcpy(n->ids[k], g_l1[i].id, ANTS_CHAIN_HASH_SIZE);
            n->events[k] = g_l1[i].ev;
            k++;
        }
    }
    if (n->extra_proof) {
        /* A proof only this node holds (largest id: keeps ascent). */
        memset(n->ids[k], 0xF0, ANTS_CHAIN_HASH_SIZE);
        memset(&n->events[k], 0, sizeof n->events[k]);
        memset(n->events[k].subject, 0xEE, ANTS_CHAIN_PEER_ID_SIZE);
        n->events[k].timestamp = GENESIS_TIME;
        k++;
    }
    *out_ids = (const uint8_t(*)[ANTS_CHAIN_HASH_SIZE])n->ids;
    *out_n_ids = k;
    *out_events = n->events;
    *out_n_events = k;
    return ANTS_OK;
}

static void bus_push_proposal(const uint8_t *block, size_t len, void *ctx)
{
    node_t *n = (node_t *)ctx;
    if (g_bus_n >= BUS_CAP || len > MSG_MAX) {
        failures++;
        fprintf(stderr, "FAIL bus overflow\n");
        return;
    }
    msg_t *m = &g_bus[g_bus_n++];
    m->from = n->idx;
    m->is_proposal = true;
    m->len = len;
    memcpy(m->bytes, block, len);
}

static void bus_push_attestation(const ants_chain_attestation_t *att, void *ctx)
{
    node_t *n = (node_t *)ctx;
    if (n->attestations_emitted < 64) {
        n->attested_heights[n->attestations_emitted] = att->height;
    }
    n->attestations_emitted++;
    if (g_bus_n >= BUS_CAP) {
        failures++;
        fprintf(stderr, "FAIL bus overflow\n");
        return;
    }
    msg_t *m = &g_bus[g_bus_n++];
    m->from = n->idx;
    m->is_proposal = false;
    m->att = *att;
}

static void on_final(const ants_chain_head_t *head, void *ctx)
{
    node_t *n = (node_t *)ctx;
    if (n->finals < 64) {
        n->final_heights[n->finals] = head->height;
    }
    n->finals++;
}

/* Deliver every queued message to every other online node (messages
 * produced during delivery are delivered too). Offline senders' messages
 * are dropped. */
static void bus_drain(void)
{
    int i = 0;
    while (i < g_bus_n) {
        msg_t m = g_bus[i++];
        if (!g_nodes[m.from].online) {
            continue;
        }
        for (int j = 0; j < g_n_nodes; j++) {
            if (j == m.from || !g_nodes[j].online) {
                continue;
            }
            if (m.is_proposal) {
                (void)ants_chain_rt_on_proposal(&g_nodes[j].rt, m.bytes, m.len, g_now);
            } else {
                ants_chain_rt_on_attestation(&g_nodes[j].rt, &m.att, g_now);
            }
        }
    }
    g_bus_n = 0;
}

static void step(uint64_t seconds)
{
    for (uint64_t s = 0; s < seconds; s++) {
        g_now++;
        for (int j = 0; j < g_n_nodes; j++) {
            if (g_nodes[j].online) {
                ants_chain_rt_tick(&g_nodes[j].rt, g_now);
            }
        }
        bus_drain();
    }
}

/* Trustee pubkeys, strictly ascending, copied out of the nodes (the first
 * n_trustees nodes after sorting are the trustees). */
static uint8_t g_trustees[MAX_NODES][ANTS_CHAIN_PEER_ID_SIZE];

static int cmp_node(const void *a, const void *b)
{
    return memcmp(((const node_t *)a)->pub, ((const node_t *)b)->pub, ANTS_ED25519_PUBKEY_SIZE);
}

/* Build `n_total` nodes; the first `n_trustees` (by ascending pubkey) are
 * trustees, the rest observers. All online, views identical. */
static void net_setup(int n_trustees, int n_total, uint8_t seed_base)
{
    memset(g_nodes, 0, sizeof g_nodes);
    g_n_nodes = n_total;
    g_bus_n = 0;
    g_now = GENESIS_TIME;
    for (int i = 0; i < n_total; i++) {
        memset(g_nodes[i].priv, seed_base + i, sizeof g_nodes[i].priv);
        CHECK(ants_ed25519_pubkey_from_priv(g_nodes[i].priv, g_nodes[i].pub) == ANTS_OK);
    }
    /* Trustees = the n_trustees smallest pubkeys among the first n_trustees
     * keys: sort just the trustee prefix. */
    qsort(g_nodes, (size_t)n_trustees, sizeof g_nodes[0], cmp_node);
    for (int i = 0; i < n_trustees; i++) {
        memcpy(g_trustees[i], g_nodes[i].pub, ANTS_CHAIN_PEER_ID_SIZE);
    }
    for (int i = 0; i < n_total; i++) {
        node_t *n = &g_nodes[i];
        n->idx = i;
        n->online = true;
        ants_chain_rt_config_t cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.trustees = (const uint8_t(*)[ANTS_CHAIN_PEER_ID_SIZE])g_trustees;
        cfg.n_trustees = (size_t)n_trustees;
        cfg.genesis_time = GENESIS_TIME;
        memset(cfg.genesis_hash, 0x47, sizeof cfg.genesis_hash);
        cfg.k_phase = ANTS_CHAIN_RT_PHASE1_K;
        memcpy(cfg.self, n->pub, sizeof cfg.self);
        cfg.sign_fn = node_sign;
        cfg.sign_ctx = n;
        cfg.view_fn = node_view;
        cfg.view_ctx = n;
        cfg.proposal_fn = bus_push_proposal;
        cfg.attestation_fn = bus_push_attestation;
        cfg.final_fn = on_final;
        cfg.out_ctx = n;
        CHECK(ants_chain_rt_init(&n->rt, &cfg, g_now) == ANTS_OK);
    }
}

/* Committee position of the proposer for (prev, height), as a trustee
 * index — computed independently through the public pure functions. */
static size_t proposer_trustee(const uint8_t prev[32], uint64_t height, size_t n_trustees)
{
    size_t k = n_trustees < ANTS_CHAIN_RT_PHASE1_K ? n_trustees : ANTS_CHAIN_RT_PHASE1_K;
    uint8_t seed[32];
    CHECK(ants_chain_vrf_seed_degraded(prev, height, seed) == ANTS_OK);
    size_t committee[ANTS_CHAIN_COMMITTEE_K_MAX];
    size_t got = 0;
    CHECK(ants_chain_committee_select(prev, seed, n_trustees, k, committee, 64, &got) == ANTS_OK);
    size_t pos = 0;
    CHECK(ants_chain_proposer(height, k, &pos) == ANTS_OK);
    return committee[pos];
}

static int node_of_trustee(size_t t)
{
    for (int i = 0; i < g_n_nodes; i++) {
        if (memcmp(g_nodes[i].pub, g_trustees[t], 32) == 0) {
            return i;
        }
    }
    return -1;
}

static void heads_agree(int n, uint64_t want_height)
{
    ants_chain_head_t h0;
    ants_chain_rt_head(&g_nodes[0].rt, &h0);
    CHECK(h0.height == want_height);
    for (int i = 1; i < n; i++) {
        ants_chain_head_t hi;
        ants_chain_rt_head(&g_nodes[i].rt, &hi);
        CHECK(hi.height == h0.height);
        CHECK(memcmp(hi.hash, h0.hash, 32) == 0);
    }
}

/* ------------------------------------------------------------------------ */
/* Scenarios                                                                */
/* ------------------------------------------------------------------------ */

static void test_healthy_committee(void)
{
    /* Three trustees, all online: heights 1, 2, 3 finalise in order, one
     * per BLOCK_TIME after the drand floor. */
    net_setup(3, 3, 0x21);
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S - 1);
    for (int i = 0; i < 3; i++) {
        CHECK(g_nodes[i].finals == 0); /* nobody may propose before the floor */
    }
    step(1);
    heads_agree(3, 1);
    ants_chain_head_t h1;
    ants_chain_rt_head(&g_nodes[0].rt, &h1);
    CHECK(h1.cutoff_time == GENESIS_TIME + ANTS_CHAIN_RT_DRAND_FLOOR_S);
    CHECK(h1.degraded_seed && h1.epoch == 0);

    step(2 * ANTS_CHAIN_RT_DRAND_FLOOR_S);
    heads_agree(3, 3);
    for (int i = 0; i < 3; i++) {
        CHECK(g_nodes[i].finals == 3);
        CHECK(g_nodes[i].final_heights[0] == 1 && g_nodes[i].final_heights[1] == 2 &&
              g_nodes[i].final_heights[2] == 3);
    }
    ants_chain_head_t h3;
    ants_chain_rt_head(&g_nodes[1].rt, &h3);
    CHECK(h3.cutoff_time >= h1.cutoff_time + 2 * ANTS_CHAIN_BLOCK_TIME_S);
}

static void test_offline_proposer_is_skipped(void)
{
    /* The proposer of height 1 is offline. Nobody else may propose height
     * 1, so the attempt times out and is skipped; height 2 (same prev:
     * genesis) gets a new proposer and finalises with the other two. */
    net_setup(3, 3, 0x31);
    uint8_t genesis[32];
    memset(genesis, 0x47, sizeof genesis);
    int off = node_of_trustee(proposer_trustee(genesis, 1, 3));
    CHECK(off >= 0);
    g_nodes[off].online = false;
    int on = (off + 1) % 3;

    step(ANTS_CHAIN_FINALITY_TIMEOUT_S - 1);
    ants_chain_head_t h;
    ants_chain_rt_head(&g_nodes[on].rt, &h);
    CHECK(h.height == 0);
    CHECK(ants_chain_rt_attempt_height(&g_nodes[on].rt) == 1);

    step(1); /* timeout: skip to height 2 */
    CHECK(ants_chain_rt_attempt_height(&g_nodes[on].rt) == 2);

    /* k = n = 3: the committee is every trustee in ascending order, so
     * height 2's proposer (position 2) is not height 1's (position 1). */
    CHECK(node_of_trustee(proposer_trustee(genesis, 2, 3)) != off);
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    ants_chain_rt_head(&g_nodes[on].rt, &h);
    CHECK(h.height == 2); /* a gap: height 1 never existed */
    for (int i = 0; i < 3; i++) {
        if (i != off) {
            ants_chain_head_t hi;
            ants_chain_rt_head(&g_nodes[i].rt, &hi);
            CHECK(hi.height == 2 && memcmp(hi.hash, h.hash, 32) == 0);
            CHECK(g_nodes[i].finals == 1 && g_nodes[i].final_heights[0] == 2);
        }
    }
}

static void test_divergent_view_abstains(void)
{
    /* One trustee holds a proof nobody else has: its recomputation of
     * every proposal differs, so it never signs; the other two (2 of 3)
     * still finalise, and it adopts the head they produce. */
    net_setup(3, 3, 0x41);
    uint8_t genesis[32];
    memset(genesis, 0x47, sizeof genesis);
    /* Pick a diverging node that is NOT height 1's proposer, so the
     * proposal itself comes from the shared view. */
    int prop = node_of_trustee(proposer_trustee(genesis, 1, 3));
    int odd = (prop + 1) % 3;
    g_nodes[odd].extra_proof = true;

    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    heads_agree(3, 1);
    for (int i = 0; i < g_nodes[odd].attestations_emitted && i < 64; i++) {
        CHECK(g_nodes[odd].attested_heights[i] != 1);
    }
}

static void test_no_quorum_keeps_skipping(void)
{
    /* Two of three trustees offline: no proposal can reach 2/3. The head
     * stays at genesis and the attempt height advances one per timeout. */
    net_setup(3, 3, 0x51);
    g_nodes[1].online = false;
    g_nodes[2].online = false;
    step(3 * ANTS_CHAIN_FINALITY_TIMEOUT_S);
    ants_chain_head_t h;
    ants_chain_rt_head(&g_nodes[0].rt, &h);
    CHECK(h.height == 0);
    CHECK(g_nodes[0].finals == 0);
    CHECK(ants_chain_rt_attempt_height(&g_nodes[0].rt) == 4);
    /* It signed at most one block per height. */
    for (int i = 0; i < g_nodes[0].attestations_emitted && i < 64; i++) {
        for (int j = i + 1; j < g_nodes[0].attestations_emitted && j < 64; j++) {
            /* re-broadcasts repeat the SAME attestation; distinct heights
             * only ever increase */
            CHECK(g_nodes[0].attested_heights[j] >= g_nodes[0].attested_heights[i]);
        }
    }
}

static void test_late_observer_adopts(void)
{
    /* Three trustees run; a fourth, non-trustee node is offline until the
     * chain is at height 3, then catches up by adopting the next final
     * block (whose prev it has never seen). */
    net_setup(3, 4, 0x61);
    g_nodes[3].online = false;
    step(3 * ANTS_CHAIN_RT_DRAND_FLOOR_S);
    heads_agree(3, 3);
    ants_chain_head_t obs;
    ants_chain_rt_head(&g_nodes[3].rt, &obs);
    CHECK(obs.height == 0);

    g_nodes[3].online = true;
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S + ANTS_CHAIN_RT_REBROADCAST_S);
    ants_chain_head_t t;
    ants_chain_rt_head(&g_nodes[0].rt, &t);
    ants_chain_rt_head(&g_nodes[3].rt, &obs);
    CHECK(t.height >= 4);
    CHECK(obs.height == t.height && memcmp(obs.hash, t.hash, 32) == 0);
    CHECK(g_nodes[3].attestations_emitted == 0); /* observers never sign */
}

static void test_equivocation_guard(void)
{
    /* A member that signed height 1's block is handed a second, different
     * (and otherwise valid) block for height 1: it must not sign again. */
    /* Four trustees (k = 4, finality needs 3): with only the proposer and
     * one other online, height 1 has 2 signatures and stays open. */
    net_setup(4, 4, 0x71);
    uint8_t genesis[32];
    memset(genesis, 0x47, sizeof genesis);
    int prop = node_of_trustee(proposer_trustee(genesis, 1, 4));
    int other = (prop + 1) % 4;
    g_nodes[(prop + 2) % 4].online = false;
    g_nodes[(prop + 3) % 4].online = false;
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    ants_chain_head_t h;
    ants_chain_rt_head(&g_nodes[other].rt, &h);
    CHECK(h.height == 0); /* still open: the injected block is relevant */
    int signed_before = g_nodes[other].attestations_emitted;
    CHECK(signed_before == 1);

    /* Same height and prev, cutoff one second later: a different block that
     * the member's own view would also compose. */
    uint64_t cutoff = GENESIS_TIME + ANTS_CHAIN_RT_DRAND_FLOOR_S + 1;
    node_t *o = &g_nodes[other];
    const uint8_t(*ids)[32];
    size_t n_ids;
    const ants_chain_event_t *ev;
    size_t n_ev;
    CHECK(node_view(cutoff, &ids, &n_ids, &ev, &n_ev, o) == ANTS_OK);
    static ants_chain_pattern_finding_t f[ANTS_CHAIN_MAX_PATTERN_FINDINGS];
    ants_chain_block_t b;
    size_t nf = 0;
    CHECK(ants_chain_block_propose(1,
                                   genesis,
                                   0,
                                   cutoff,
                                   true,
                                   ids,
                                   n_ids,
                                   ev,
                                   n_ev,
                                   f,
                                   ANTS_CHAIN_MAX_PATTERN_FINDINGS,
                                   &nf,
                                   &b) == ANTS_OK);
    uint8_t bytes[MSG_MAX];
    size_t len = 0;
    CHECK(ants_chain_block_encode(&b, bytes, sizeof bytes, &len) == ANTS_OK);
    g_now++;
    /* Unattested, the second block is not even filed... */
    CHECK(ants_chain_rt_on_proposal(&o->rt, bytes, len, g_now) == ANTS_ERROR_UNSUPPORTED_TYPE);
    /* ...so the (byzantine) proposer attests it first, as proposers do. */
    ants_chain_attestation_t pa;
    memset(&pa, 0, sizeof pa);
    pa.height = 1;
    CHECK(ants_chain_block_hash(&b, pa.block_hash) == ANTS_OK);
    memcpy(pa.signer, g_nodes[prop].pub, 32);
    CHECK(ants_ed25519_sign(g_nodes[prop].priv, pa.block_hash, 32, pa.sig) == ANTS_OK);
    CHECK(ants_chain_rt_on_attestation(&o->rt, &pa, g_now) == ANTS_OK);
    CHECK(ants_chain_rt_on_proposal(&o->rt, bytes, len, g_now) == ANTS_OK);
    CHECK(o->attestations_emitted == signed_before);
}

static void test_forged_attestation_ignored(void)
{
    /* Only the height-1 proposer is online (1 of 3 signatures). A forged
     * attestation in another trustee's name — wrong signature — must not
     * count toward the 2/3. */
    net_setup(3, 3, 0x81);
    uint8_t genesis[32];
    memset(genesis, 0x47, sizeof genesis);
    int prop = node_of_trustee(proposer_trustee(genesis, 1, 3));
    for (int i = 0; i < 3; i++) {
        g_nodes[i].online = (i == prop);
    }
    g_nodes[prop].attestations_emitted = 0;
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    CHECK(g_nodes[prop].attestations_emitted == 1);
    ants_chain_attestation_t forged;
    memset(&forged, 0, sizeof forged);
    forged.height = 1;
    /* The proposer's own attestation tells us the block hash. */
    ants_chain_head_t h;
    ants_chain_rt_head(&g_nodes[prop].rt, &h);
    CHECK(h.height == 0);
    /* Re-derive the hash: compose the same block the proposer did. */
    const uint8_t(*ids)[32];
    size_t n_ids;
    const ants_chain_event_t *ev;
    size_t n_ev;
    uint64_t cutoff = GENESIS_TIME + ANTS_CHAIN_RT_DRAND_FLOOR_S;
    CHECK(node_view(cutoff, &ids, &n_ids, &ev, &n_ev, &g_nodes[prop]) == ANTS_OK);
    static ants_chain_pattern_finding_t f[ANTS_CHAIN_MAX_PATTERN_FINDINGS];
    ants_chain_block_t b;
    size_t nf = 0;
    CHECK(ants_chain_block_propose(
              1, genesis, 0, cutoff, true, ids, n_ids, ev, n_ev, f, 256, &nf, &b) == ANTS_OK);
    CHECK(ants_chain_block_hash(&b, forged.block_hash) == ANTS_OK);
    int victim = (prop + 1) % 3;
    memcpy(forged.signer, g_nodes[victim].pub, 32);
    memset(forged.sig, 0x5A, sizeof forged.sig);
    ants_chain_rt_on_attestation(&g_nodes[prop].rt, &forged, g_now);
    ants_chain_rt_head(&g_nodes[prop].rt, &h);
    CHECK(h.height == 0);

    /* Control: the victim's GENUINE attestation does finalise it. */
    CHECK(ants_ed25519_sign(g_nodes[victim].priv, forged.block_hash, 32, forged.sig) == ANTS_OK);
    ants_chain_rt_on_attestation(&g_nodes[prop].rt, &forged, g_now);
    ants_chain_rt_head(&g_nodes[prop].rt, &h);
    CHECK(h.height == 1);
}

static void test_relabelled_attestations_do_not_stall(void)
{
    /* Regression (pre-push review F1): an attestation's height is not
     * signed. Flooding every node with copies of a genuine attestation
     * re-labelled with 200 other heights must neither fill the table nor
     * keep the chain from finalising — the copies collapse onto the one
     * (hash, signer) entry and are refused for forwarding. */
    net_setup(3, 3, 0xA1);
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    heads_agree(3, 1);
    /* Capture a genuine attestation: the proposer re-broadcasts its own. */
    g_bus_n = 0;
    ants_chain_attestation_t genuine;
    memset(&genuine, 0, sizeof genuine);
    bool got = false;
    for (int s = 0; s < (int)ANTS_CHAIN_RT_DRAND_FLOOR_S + 10 && !got; s++) {
        g_now++;
        for (int j = 0; j < g_n_nodes; j++) {
            ants_chain_rt_tick(&g_nodes[j].rt, g_now);
        }
        for (int i = 0; i < g_bus_n && !got; i++) {
            if (!g_bus[i].is_proposal) {
                genuine = g_bus[i].att;
                got = true;
            }
        }
        bus_drain();
    }
    CHECK(got);
    for (int j = 0; j < 3; j++) {
        for (uint64_t k = 0; k < 200; k++) {
            ants_chain_attestation_t fake = genuine;
            fake.height = 1000 + k;
            ants_error_t rc = ants_chain_rt_on_attestation(&g_nodes[j].rt, &fake, g_now);
            CHECK(rc == ANTS_ERROR_UNSUPPORTED_TYPE || rc == ANTS_OK);
            if (k > 0) {
                CHECK(rc == ANTS_ERROR_UNSUPPORTED_TYPE); /* never forwarded twice */
            }
        }
    }
    ants_chain_head_t before;
    ants_chain_rt_head(&g_nodes[0].rt, &before);
    step(3 * ANTS_CHAIN_BLOCK_TIME_S);
    ants_chain_head_t after;
    ants_chain_rt_head(&g_nodes[0].rt, &after);
    CHECK(after.height >= before.height + 2);
    heads_agree(3, after.height);
}

static void test_unattested_block_not_filed(void)
{
    /* Regression (pre-push review F2): blocks carry no proposer signature.
     * A flood of decodable blocks nobody attested must not be filed (so it
     * cannot evict the real proposal) nor forwarded. */
    net_setup(3, 4, 0xB1); /* node 3: an observer */
    static ants_chain_pattern_finding_t f[ANTS_CHAIN_MAX_PATTERN_FINDINGS];
    uint8_t prev[32];
    memset(prev, 0x47, sizeof prev);
    for (uint64_t h = 1; h <= 8; h++) {
        ants_chain_block_t b;
        size_t nf = 0;
        CHECK(ants_chain_block_propose(h,
                                       prev,
                                       0,
                                       GENESIS_TIME + 30 + h,
                                       true,
                                       NULL,
                                       0,
                                       NULL,
                                       0,
                                       f,
                                       ANTS_CHAIN_MAX_PATTERN_FINDINGS,
                                       &nf,
                                       &b) == ANTS_OK);
        uint8_t bytes[MSG_MAX];
        size_t len = 0;
        CHECK(ants_chain_block_encode(&b, bytes, sizeof bytes, &len) == ANTS_OK);
        for (int j = 0; j < 4; j++) {
            CHECK(ants_chain_rt_on_proposal(&g_nodes[j].rt, bytes, len, g_now) ==
                  ANTS_ERROR_UNSUPPORTED_TYPE);
        }
    }
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S + ANTS_CHAIN_RT_REBROADCAST_S);
    heads_agree(4, 1); /* the observer adopts the real block too */
}

static void test_single_trustee(void)
{
    /* k = 1: the lone trustee's own signature is 2/3 of one. */
    net_setup(1, 1, 0x91);
    step(ANTS_CHAIN_RT_DRAND_FLOOR_S);
    heads_agree(1, 1);
    step(ANTS_CHAIN_BLOCK_TIME_S);
    heads_agree(1, 2);
}

static void test_init_args(void)
{
    static ants_chain_rt_t rt;
    uint8_t t[2][32];
    memset(t[0], 0x01, 32);
    memset(t[1], 0x02, 32);
    ants_chain_rt_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.trustees = (const uint8_t(*)[32])t;
    cfg.n_trustees = 2;
    cfg.genesis_time = GENESIS_TIME;
    cfg.k_phase = 5;
    memset(cfg.self, 0x09, 32); /* observer: callbacks optional */
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME) == ANTS_OK);
    CHECK(ants_chain_rt_init(NULL, &cfg, GENESIS_TIME) == ANTS_ERROR_INVALID_ARG);
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME - 1) == ANTS_ERROR_INVALID_ARG);
    cfg.k_phase = 0;
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME) == ANTS_ERROR_INVALID_ARG);
    cfg.k_phase = 5;
    memset(t[1], 0x01, 32); /* not strictly ascending */
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME) == ANTS_ERROR_INVALID_ARG);
    memset(t[1], 0x02, 32);
    memset(cfg.self, 0x01, 32); /* a trustee without sign/view callbacks */
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME) == ANTS_ERROR_INVALID_ARG);
    cfg.n_trustees = 0;
    CHECK(ants_chain_rt_init(&rt, &cfg, GENESIS_TIME) == ANTS_ERROR_INVALID_ARG);
}

static void test_view_window(void)
{
    /* RFC-0004 item 9: a cutoff in epoch e sees epochs [e - 29, e]. */
    const uint64_t g = GENESIS_TIME, d = ANTS_CHAIN_RT_EPOCH_DURATION_S;
    uint64_t lo = 99, hi = 99;
    CHECK(!ants_chain_rt_view_epochs(g, g - 1, &lo, &hi)); /* before genesis */
    CHECK(ants_chain_rt_view_epochs(g, g, &lo, &hi) && lo == 0 && hi == 0);
    CHECK(ants_chain_rt_view_epochs(g, g + 29 * d, &lo, &hi) && lo == 0 && hi == 29);
    CHECK(ants_chain_rt_view_epochs(g, g + 30 * d, &lo, &hi) && lo == 1 && hi == 30);
    CHECK(ants_chain_rt_view_epochs(g, g + 40 * d + d - 1, &lo, &hi) && lo == 11 && hi == 40);
    CHECK(hi - lo + 1 == ANTS_CHAIN_RT_VIEW_WINDOW_EPOCHS);
    CHECK(!ants_chain_rt_view_epochs(g, g, NULL, &hi));
    /* The window is the pattern rules' 30 days. */
    CHECK(ANTS_CHAIN_RT_VIEW_WINDOW_EPOCHS * d == ANTS_CHAIN_PATTERN_WINDOW_S);
}

int main(void)
{
    l1_init();
    test_init_args();
    test_view_window();
    test_healthy_committee();
    test_offline_proposer_is_skipped();
    test_divergent_view_abstains();
    test_no_quorum_keeps_skipping();
    test_late_observer_adopts();
    test_equivocation_guard();
    test_forged_attestation_ignored();
    test_relabelled_attestations_do_not_stall();
    test_unattested_block_not_filed();
    test_single_trustee();
    if (failures == 0) {
        printf("test_chain_runtime: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_chain_runtime: %d check(s) FAILED\n", failures);
    return 1;
}
