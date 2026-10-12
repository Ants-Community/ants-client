/*
 * cmd/antsd/chain.c — the daemon's L2 chain loop (see chain.h).
 *
 * The runtime is pure; this file gives it a world:
 *   - a Layer-1 view: the G-Set's proofs visible at a cutoff, content-ids
 *     ascending, decoded into the pattern engine's events. The proof
 *     envelope carries an `epoch`, not a signing time, so visibility and
 *     the event time are derived from it deterministically: a proof is
 *     visible at `cutoff` iff its epoch has begun by then
 *     (genesis + epoch * EPOCH_DURATION <= cutoff), and its event time is
 *     that epoch's start. Every node holding the same set therefore
 *     composes the same block;
 *   - a signer (the node identity over the block hash);
 *   - the wire: proposals and attestations out as gossip BLOCK / ATTEST
 *     frames, frames in through the gossip chain handler.
 */
#define _POSIX_C_SOURCE 200809L

#include "chain.h"

#include "util.h"

#include "ants_chain.h"
#include "ants_chain_runtime.h"
#include "ants_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef char
    antsd_trustee_capacity_check[(ANTSD_MAX_TRUSTEES == ANTS_CHAIN_COMMITTEE_K_MAX) ? 1 : -1];

/* Proofs a single view can hold; a larger visible set makes this node
 * abstain (and not propose) until pruning brings it back under. */
#define ANTSD_CHAIN_VIEW_MAX 65536u

static uint8_t g_view_ids[ANTSD_CHAIN_VIEW_MAX][ANTS_CHAIN_HASH_SIZE];
static ants_chain_event_t g_view_events[ANTSD_CHAIN_VIEW_MAX];

struct view_walk {
    uint64_t genesis_time;
    uint64_t max_epoch;
    size_t n;
    bool overflow;
};

static bool view_visit(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                       const uint8_t *proof,
                       size_t len,
                       void *ctx)
{
    struct view_walk *w = (struct view_walk *)ctx;
    ants_fault_proof_view_t v;
    if (ants_crdt_fault_proof_decode(proof, len, &v) != ANTS_OK || v.epoch > w->max_epoch) {
        return true; /* not visible at this cutoff */
    }
    if (w->n >= ANTSD_CHAIN_VIEW_MAX) {
        w->overflow = true;
        return false;
    }
    memcpy(g_view_ids[w->n], content_id, ANTS_CHAIN_HASH_SIZE);
    memset(&g_view_events[w->n], 0, sizeof g_view_events[w->n]);
    memcpy(g_view_events[w->n].subject, v.subject, ANTS_CHAIN_PEER_ID_SIZE);
    g_view_events[w->n].timestamp = w->genesis_time + v.epoch * ANTS_CHAIN_RT_EPOCH_DURATION_S;
    g_view_events[w->n].fault_type = v.fault_type;
    w->n++;
    return true;
}

static int cmp_id(const void *a, const void *b)
{
    return memcmp(a, b, ANTS_CHAIN_HASH_SIZE);
}

static ants_error_t chain_view(uint64_t cutoff,
                               const uint8_t (**out_ids)[ANTS_CHAIN_HASH_SIZE],
                               size_t *out_n_ids,
                               const ants_chain_event_t **out_events,
                               size_t *out_n_events,
                               void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    struct view_walk w;
    memset(&w, 0, sizeof w);
    w.genesis_time = c->genesis_time;
    if (cutoff >= c->genesis_time) {
        w.max_epoch = (cutoff - c->genesis_time) / ANTS_CHAIN_RT_EPOCH_DURATION_S;
        ants_crdt_enumerate(c->gset, view_visit, &w);
    }
    if (w.overflow) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    /* Events need no order (the pattern engine bins them); the content-ids
     * must be strictly ascending (the confirmed-proofs canonical order).
     * Sorting the ids alone is fine: the two arrays are consumed
     * independently. */
    qsort(g_view_ids, w.n, sizeof g_view_ids[0], cmp_id);
    *out_ids = (const uint8_t(*)[ANTS_CHAIN_HASH_SIZE])g_view_ids;
    *out_n_ids = w.n;
    *out_events = g_view_events;
    *out_n_events = w.n;
    return ANTS_OK;
}

static ants_error_t chain_sign(const uint8_t hash[ANTS_CHAIN_HASH_SIZE],
                               uint8_t out_sig[ANTS_CHAIN_SIG_SIZE],
                               void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    return ants_ed25519_sign(c->priv, hash, ANTS_CHAIN_HASH_SIZE, out_sig);
}

/* ------------------------------------------------------------------------ */
/* Outbound: runtime → gossip                                               */
/* ------------------------------------------------------------------------ */

static uint8_t g_frame[ANTS_GOSSIP_CHAIN_MAX_BLOCK_FRAME];

static void out_proposal(const uint8_t *block, size_t len, void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    size_t flen = 0;
    if (ants_gossip_block_encode(block, len, g_frame, sizeof g_frame, &flen) != ANTS_OK) {
        return;
    }
    c->proposals++;
    (void)ants_gossip_broadcast_chain(c->gossip, g_frame, flen, NULL);
}

static void out_attestation(const ants_chain_attestation_t *att, void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    ants_gossip_attest_t a;
    a.height = att->height;
    memcpy(a.block_hash, att->block_hash, sizeof a.block_hash);
    memcpy(a.signer, att->signer, sizeof a.signer);
    memcpy(a.sig, att->sig, sizeof a.sig);
    uint8_t frame[256];
    size_t flen = 0;
    if (ants_gossip_attest_encode(&a, frame, sizeof frame, &flen) != ANTS_OK) {
        return;
    }
    c->attestations++;
    (void)ants_gossip_broadcast_chain(c->gossip, frame, flen, NULL);
}

static void out_final(const ants_chain_head_t *head, void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    c->finals++;
    char hex[ANTS_CHAIN_HASH_SIZE * 2 + 1];
    antsd_hex_format(head->hash, sizeof head->hash, hex, sizeof hex);
    printf("antsd: chain final height=%llu hash=%s epoch=%llu%s\n",
           (unsigned long long)head->height,
           hex,
           (unsigned long long)head->epoch,
           head->degraded_seed ? " degraded" : "");
}

/* ------------------------------------------------------------------------ */
/* Inbound: gossip → runtime                                                */
/* ------------------------------------------------------------------------ */

static bool is_trustee(const antsd_chain_t *c, const uint8_t id[ANTS_CHAIN_PEER_ID_SIZE])
{
    for (size_t i = 0; i < c->n_trustees; i++) {
        if (memcmp(c->trustees[i], id, ANTS_CHAIN_PEER_ID_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/* The gossip chain handler (ants_gossip_chain_fn): OK forwards the frame,
 * UNSUPPORTED_TYPE drops it quietly, anything else counts against the
 * sender (RFC-0008 §11.13 receive path). */
static ants_error_t
on_chain_frame(const uint8_t *from_peer, uint64_t type, const uint8_t *frame, size_t len, void *ctx)
{
    antsd_chain_t *c = (antsd_chain_t *)ctx;
    (void)from_peer;
    uint64_t now = (uint64_t)time(NULL);
    if (type == ANTS_GOSSIP_MSG_BLOCK) {
        const uint8_t *block;
        size_t blen;
        ants_error_t rc = ants_gossip_block_decode(frame, len, &block, &blen);
        if (rc != ANTS_OK) {
            return rc;
        }
        /* MALFORMED / NON_CANONICAL for a block that does not decode;
         * UNSUPPORTED_TYPE for a non-degraded block (v1 holds no beacon). */
        return ants_chain_rt_on_proposal(&c->rt, block, blen, now);
    }
    ants_gossip_attest_t a;
    ants_error_t rc = ants_gossip_attest_decode(frame, len, &a);
    if (rc != ANTS_OK) {
        return rc;
    }
    ants_chain_attestation_t att;
    att.height = a.height;
    memcpy(att.block_hash, a.block_hash, sizeof att.block_hash);
    memcpy(att.signer, a.signer, sizeof att.signer);
    memcpy(att.sig, a.sig, sizeof att.sig);
    /* The runtime checks signer membership + the signature (MALFORMED),
     * and drops re-labelled duplicates quietly (UNSUPPORTED_TYPE). */
    return ants_chain_rt_on_attestation(&c->rt, &att, now);
}

/* ------------------------------------------------------------------------ */
/* Public                                                                   */
/* ------------------------------------------------------------------------ */

/* Init the runtime and claim the gossip chain handler. */
static ants_error_t chain_begin(antsd_chain_t *c, uint64_t now)
{
    ants_chain_rt_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.trustees = (const uint8_t(*)[ANTS_CHAIN_PEER_ID_SIZE])c->trustees;
    cfg.n_trustees = c->n_trustees;
    cfg.genesis_time = c->genesis.time;
    memcpy(cfg.genesis_hash, c->genesis.hash, sizeof cfg.genesis_hash);
    cfg.k_phase = ANTS_CHAIN_RT_PHASE1_K;
    memcpy(cfg.self, c->pub, sizeof cfg.self);
    cfg.sign_fn = chain_sign;
    cfg.sign_ctx = c;
    cfg.view_fn = chain_view;
    cfg.view_ctx = c;
    cfg.proposal_fn = out_proposal;
    cfg.attestation_fn = out_attestation;
    cfg.final_fn = out_final;
    cfg.out_ctx = c;
    ants_error_t rc = ants_chain_rt_init(&c->rt, &cfg, now);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_gossip_set_chain_handler(c->gossip, on_chain_frame, c);
    if (rc != ANTS_OK) {
        return rc;
    }
    c->on = true;
    c->pending = false;
    return ANTS_OK;
}

ants_error_t antsd_chain_start(antsd_chain_t *c,
                               const antsd_genesis_t *genesis,
                               const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                               const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                               ants_gossip_t *gossip,
                               ants_crdt_t *gset,
                               uint64_t now)
{
    c->on = false;
    c->pending = false;
    c->gossip = gossip;
    c->gset = gset;
    c->priv = priv;
    c->genesis = *genesis;
    memcpy(c->pub, pub, sizeof c->pub);
    c->genesis_time = genesis->time;
    c->n_trustees = genesis->trustee_count;
    memcpy(c->trustees, genesis->trustees, genesis->trustee_count * ANTS_CHAIN_PEER_ID_SIZE);
    c->trustee = is_trustee(c, pub);
    if (now < genesis->time) {
        /* Operators start their nodes ahead of the agreed genesis time:
         * wait for it rather than run the whole process with the chain off. */
        c->pending = true;
        return ANTS_OK;
    }
    return chain_begin(c, now);
}

void antsd_chain_tick(antsd_chain_t *c, uint64_t now)
{
    if (c->pending && now >= c->genesis.time) {
        if (chain_begin(c, now) == ANTS_OK) {
            printf("antsd: chain on (%s, %zu trustees) at genesis time\n",
                   c->trustee ? "trustee" : "observer",
                   c->n_trustees);
        } else {
            c->pending = false;
            fprintf(stderr, "antsd: chain off: genesis rejected at its own time\n");
        }
    }
    if (c->on) {
        ants_chain_rt_tick(&c->rt, now);
    }
}
