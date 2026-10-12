/*
 * chain_runtime.c — the L2 block-production state machine (see
 * ants_chain_runtime.h for the v1 rules). Composes the pure functions of
 * chain.c; no I/O, no clock, no malloc — all state lives in the caller's
 * opaque buffer.
 */

#include "ants_chain_runtime.h"

#include "ants_chain.h"
#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Proposals held at once: the current attempt's plus a few above the head
 * that may yet prove final (late or skipped-past attempts). */
#define RT_MAX_PROPOSALS 4
/* Attestations held at once: two full committees' worth. */
#define RT_MAX_ATTESTATIONS (2 * ANTS_CHAIN_COMMITTEE_K_MAX)

struct rt_proposal {
    bool used;
    bool degraded;
    uint8_t _pad[6];
    uint64_t height;
    uint64_t cutoff;
    uint64_t epoch;
    uint8_t prev[ANTS_CHAIN_HASH_SIZE];
    uint8_t hash[ANTS_CHAIN_HASH_SIZE];
    size_t len;
    uint8_t bytes[ANTS_CHAIN_BLOCK_ENCODED_MAX];
};

struct rt_state {
    uint8_t trustees[ANTS_CHAIN_COMMITTEE_K_MAX][ANTS_CHAIN_PEER_ID_SIZE];
    size_t n_trustees;
    uint64_t genesis_time;
    size_t k_phase;
    uint8_t self[ANTS_CHAIN_PEER_ID_SIZE];
    bool is_trustee;

    ants_chain_rt_sign_fn sign_fn;
    void *sign_ctx;
    ants_chain_rt_view_fn view_fn;
    void *view_ctx;
    ants_chain_rt_proposal_fn proposal_fn;
    ants_chain_rt_attestation_fn attestation_fn;
    ants_chain_rt_final_fn final_fn;
    void *out_ctx;

    ants_chain_head_t head;

    /* The attempt in progress: height h on prev = head.hash. */
    uint64_t h;
    uint64_t attempt_start;
    size_t k;
    size_t committee[ANTS_CHAIN_COMMITTEE_K_MAX]; /* trustee indices, ascending */
    bool member;
    size_t my_pos;
    size_t proposer_pos;
    int cur;            /* proposal slot this node built or signed this attempt */
    uint64_t last_emit; /* last (re)broadcast of that proposal + our attestation */

    /* Equivocation guard: the highest height this node ever signed. */
    uint64_t last_signed_height;

    struct rt_proposal props[RT_MAX_PROPOSALS];
    bool att_used[RT_MAX_ATTESTATIONS];
    uint64_t att_seq[RT_MAX_ATTESTATIONS]; /* filing order, for FIFO eviction */
    uint64_t next_att_seq;
    ants_chain_attestation_t atts[RT_MAX_ATTESTATIONS];

    /* Decode / compose scratch. */
    ants_chain_pattern_finding_t findings[ANTS_CHAIN_MAX_PATTERN_FINDINGS];
    struct rt_proposal recompute; /* a member's own composition, compared */
};

typedef char
    rt_state_fits_opaque[(sizeof(struct rt_state) <= sizeof(((ants_chain_rt_t *)0)->_opaque)) ? 1
                                                                                              : -1];

static struct rt_state *st(ants_chain_rt_t *rt)
{
    return (struct rt_state *)(void *)rt->_opaque;
}

static const struct rt_state *st_const(const ants_chain_rt_t *rt)
{
    return (const struct rt_state *)(const void *)rt->_opaque;
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

static bool trustee_index(const struct rt_state *s, const uint8_t id[32], size_t *out)
{
    for (size_t i = 0; i < s->n_trustees; i++) {
        if (memcmp(s->trustees[i], id, ANTS_CHAIN_PEER_ID_SIZE) == 0) {
            if (out != NULL) {
                *out = i;
            }
            return true;
        }
    }
    return false;
}

/* The committee for (prev, height) under the v1 degraded seed. */
static ants_error_t committee_for(const struct rt_state *s,
                                  const uint8_t prev[ANTS_CHAIN_HASH_SIZE],
                                  uint64_t height,
                                  size_t out[ANTS_CHAIN_COMMITTEE_K_MAX],
                                  size_t *out_k)
{
    size_t k = s->n_trustees < s->k_phase ? s->n_trustees : s->k_phase;
    uint8_t seed[ANTS_CHAIN_HASH_SIZE];
    ants_error_t err = ants_chain_vrf_seed_degraded(prev, height, seed);
    if (err != ANTS_OK) {
        return err;
    }
    return ants_chain_committee_select(
        prev, seed, s->n_trustees, k, out, ANTS_CHAIN_COMMITTEE_K_MAX, out_k);
}

static uint64_t epoch_of(const struct rt_state *s, uint64_t cutoff)
{
    return (cutoff - s->genesis_time) / ANTS_CHAIN_RT_EPOCH_DURATION_S;
}

/* Compose the block for (height, prev, cutoff) from this node's own view,
 * encode it into `p`. ANTS_OK with p filled (not marked used). */
static ants_error_t compose(struct rt_state *s,
                            uint64_t height,
                            const uint8_t prev[ANTS_CHAIN_HASH_SIZE],
                            uint64_t cutoff,
                            struct rt_proposal *p)
{
    const uint8_t(*ids)[ANTS_CHAIN_HASH_SIZE] = NULL;
    size_t n_ids = 0;
    const ants_chain_event_t *events = NULL;
    size_t n_events = 0;
    ants_error_t err = s->view_fn(cutoff, &ids, &n_ids, &events, &n_events, s->view_ctx);
    if (err != ANTS_OK) {
        return err;
    }
    ants_chain_block_t b;
    size_t n_findings = 0;
    err = ants_chain_block_propose(height,
                                   prev,
                                   epoch_of(s, cutoff),
                                   cutoff,
                                   true, /* v1: every block is degraded-seed */
                                   ids,
                                   n_ids,
                                   events,
                                   n_events,
                                   s->findings,
                                   ANTS_CHAIN_MAX_PATTERN_FINDINGS,
                                   &n_findings,
                                   &b);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_chain_block_encode(&b, p->bytes, sizeof p->bytes, &p->len);
    if (err != ANTS_OK) {
        return err;
    }
    err = ants_chain_block_hash(&b, p->hash);
    if (err != ANTS_OK) {
        return err;
    }
    p->height = height;
    memcpy(p->prev, prev, ANTS_CHAIN_HASH_SIZE);
    p->cutoff = cutoff;
    p->epoch = b.summary.epoch;
    p->degraded = true;
    return ANTS_OK;
}

static struct rt_proposal *prop_find(struct rt_state *s, const uint8_t hash[ANTS_CHAIN_HASH_SIZE])
{
    for (size_t i = 0; i < RT_MAX_PROPOSALS; i++) {
        if (s->props[i].used && memcmp(s->props[i].hash, hash, ANTS_CHAIN_HASH_SIZE) == 0) {
            return &s->props[i];
        }
    }
    return NULL;
}

/* A free proposal slot; when full, evict the lowest-height one that is not
 * the current attempt's. NULL only if every slot is the current one. */
static struct rt_proposal *prop_alloc(struct rt_state *s)
{
    struct rt_proposal *victim = NULL;
    for (size_t i = 0; i < RT_MAX_PROPOSALS; i++) {
        if (!s->props[i].used) {
            return &s->props[i];
        }
        if ((int)i == s->cur) {
            continue;
        }
        if (victim == NULL || s->props[i].height < victim->height) {
            victim = &s->props[i];
        }
    }
    if (victim != NULL) {
        memset(victim, 0, sizeof *victim);
    }
    return victim;
}

/* The attestation on file for (block_hash, signer), or NULL. That pair is
 * an attestation's identity: the signature covers only the hash, and the
 * hash commits the height, so the frame's `height` is an unsigned hint — a
 * copy with a different height is the same attestation, not a new one. */
static ants_chain_attestation_t *att_find(struct rt_state *s,
                                          const uint8_t hash[ANTS_CHAIN_HASH_SIZE],
                                          const uint8_t signer[ANTS_CHAIN_PEER_ID_SIZE])
{
    for (size_t i = 0; i < RT_MAX_ATTESTATIONS; i++) {
        if (s->att_used[i] && memcmp(s->atts[i].block_hash, hash, ANTS_CHAIN_HASH_SIZE) == 0 &&
            memcmp(s->atts[i].signer, signer, ANTS_CHAIN_PEER_ID_SIZE) == 0) {
            return &s->atts[i];
        }
    }
    return NULL;
}

/* File an attestation already known to carry a valid signature, evicting
 * the oldest entry when full. Returns false if (hash, signer) is already
 * on file. */
static bool att_file(struct rt_state *s, const ants_chain_attestation_t *a)
{
    if (att_find(s, a->block_hash, a->signer) != NULL) {
        return false;
    }
    size_t at = RT_MAX_ATTESTATIONS;
    for (size_t i = 0; i < RT_MAX_ATTESTATIONS; i++) {
        if (!s->att_used[i]) {
            at = i;
            break;
        }
        if (at == RT_MAX_ATTESTATIONS || s->att_seq[i] < s->att_seq[at]) {
            at = i;
        }
    }
    s->att_used[at] = true;
    s->atts[at] = *a;
    s->att_seq[at] = ++s->next_att_seq;
    return true;
}

/* Is there at least one population attestation on file for `hash`? */
static bool att_any_for(const struct rt_state *s, const uint8_t hash[ANTS_CHAIN_HASH_SIZE])
{
    for (size_t i = 0; i < RT_MAX_ATTESTATIONS; i++) {
        if (s->att_used[i] && memcmp(s->atts[i].block_hash, hash, ANTS_CHAIN_HASH_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/* Drop everything at or below the head. */
static void purge_below_head(struct rt_state *s)
{
    for (size_t i = 0; i < RT_MAX_PROPOSALS; i++) {
        if (s->props[i].used && s->props[i].height <= s->head.height) {
            memset(&s->props[i], 0, sizeof s->props[i]);
        }
    }
    for (size_t i = 0; i < RT_MAX_ATTESTATIONS; i++) {
        if (s->att_used[i] && s->atts[i].height <= s->head.height) {
            s->att_used[i] = false;
        }
    }
}

static void start_attempt(struct rt_state *s, uint64_t height, uint64_t now)
{
    s->h = height;
    s->attempt_start = now;
    s->cur = -1;
    s->last_emit = 0;
    s->member = false;
    s->k = 0;
    if (committee_for(s, s->head.hash, height, s->committee, &s->k) != ANTS_OK || s->k == 0) {
        return; /* cannot happen with a validated genesis; stay inert */
    }
    size_t mine;
    if (s->is_trustee && trustee_index(s, s->self, &mine)) {
        for (size_t i = 0; i < s->k; i++) {
            if (s->committee[i] == mine) {
                s->member = true;
                s->my_pos = i;
            }
        }
    }
    (void)ants_chain_proposer(height, s->k, &s->proposer_pos);
    purge_below_head(s);
}

/* Sign `p` (this node's current attempt), file and broadcast. */
static void
sign_and_emit(struct rt_state *s, struct rt_proposal *p, bool emit_proposal, uint64_t now)
{
    ants_chain_attestation_t a;
    memset(&a, 0, sizeof a);
    a.height = p->height;
    memcpy(a.block_hash, p->hash, ANTS_CHAIN_HASH_SIZE);
    memcpy(a.signer, s->self, ANTS_CHAIN_PEER_ID_SIZE);
    if (s->sign_fn(p->hash, a.sig, s->sign_ctx) != ANTS_OK) {
        return;
    }
    s->last_signed_height = p->height; /* never sign this height again */
    s->cur = (int)(p - s->props);
    (void)att_file(s, &a);
    /* Attestation BEFORE the block: receivers file (and forward) a block
     * only once a population attestation for its hash is on file. */
    if (s->attestation_fn != NULL) {
        s->attestation_fn(&a, s->out_ctx);
    }
    if (emit_proposal && s->proposal_fn != NULL) {
        s->proposal_fn(p->bytes, p->len, s->out_ctx);
    }
    s->last_emit = now;
}

/* Is `p` final under its own committee? */
static bool is_final(const struct rt_state *s, const struct rt_proposal *p)
{
    size_t committee[ANTS_CHAIN_COMMITTEE_K_MAX];
    size_t k = 0;
    if (!p->degraded || committee_for(s, p->prev, p->height, committee, &k) != ANTS_OK) {
        return false;
    }
    uint8_t pubkeys[ANTS_CHAIN_COMMITTEE_K_MAX][ANTS_CHAIN_PEER_ID_SIZE];
    bool mask[ANTS_CHAIN_COMMITTEE_K_MAX];
    uint8_t sigs[ANTS_CHAIN_COMMITTEE_K_MAX * ANTS_CHAIN_SIG_SIZE];
    size_t n_sigs = 0;
    for (size_t pos = 0; pos < k; pos++) {
        memcpy(pubkeys[pos], s->trustees[committee[pos]], ANTS_CHAIN_PEER_ID_SIZE);
        mask[pos] = false;
        for (size_t i = 0; i < RT_MAX_ATTESTATIONS; i++) {
            const ants_chain_attestation_t *a = &s->atts[i];
            /* Matched by (hash, signer) only: the hash commits the height. */
            if (s->att_used[i] && memcmp(a->block_hash, p->hash, ANTS_CHAIN_HASH_SIZE) == 0 &&
                memcmp(a->signer, pubkeys[pos], ANTS_CHAIN_PEER_ID_SIZE) == 0) {
                mask[pos] = true;
                memcpy(sigs + n_sigs * ANTS_CHAIN_SIG_SIZE, a->sig, ANTS_CHAIN_SIG_SIZE);
                n_sigs++;
                break;
            }
        }
    }
    bool final = false;
    if (ants_chain_finality_verify(
            p->hash, pubkeys, k, sigs, n_sigs * ANTS_CHAIN_SIG_SIZE, mask, &final) != ANTS_OK) {
        return false;
    }
    return final;
}

/* Adopt the highest provably-final proposal above the head, if any. */
static void try_finalize(struct rt_state *s, uint64_t now)
{
    struct rt_proposal *best = NULL;
    for (size_t i = 0; i < RT_MAX_PROPOSALS; i++) {
        struct rt_proposal *p = &s->props[i];
        if (!p->used || p->height <= s->head.height) {
            continue;
        }
        if ((best == NULL || p->height > best->height) && is_final(s, p)) {
            best = p;
        }
    }
    if (best == NULL) {
        return;
    }
    s->head.height = best->height;
    memcpy(s->head.hash, best->hash, ANTS_CHAIN_HASH_SIZE);
    s->head.cutoff_time = best->cutoff;
    s->head.epoch = best->epoch;
    s->head.degraded_seed = best->degraded;
    ants_chain_head_t head = s->head;
    start_attempt(s, head.height + 1, now);
    if (s->final_fn != NULL) {
        s->final_fn(&head, s->out_ctx);
    }
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_chain_rt_init(ants_chain_rt_t *rt, const ants_chain_rt_config_t *cfg, uint64_t now)
{
    if (rt == NULL || cfg == NULL || cfg->trustees == NULL || cfg->n_trustees == 0 ||
        cfg->n_trustees > ANTS_CHAIN_COMMITTEE_K_MAX || cfg->k_phase == 0 ||
        now < cfg->genesis_time) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (size_t i = 1; i < cfg->n_trustees; i++) {
        if (memcmp(cfg->trustees[i - 1], cfg->trustees[i], ANTS_CHAIN_PEER_ID_SIZE) >= 0) {
            return ANTS_ERROR_INVALID_ARG; /* not strictly ascending */
        }
    }
    memset(rt->_opaque, 0, sizeof rt->_opaque);
    struct rt_state *s = st(rt);
    memcpy(s->trustees, cfg->trustees, cfg->n_trustees * ANTS_CHAIN_PEER_ID_SIZE);
    s->n_trustees = cfg->n_trustees;
    s->genesis_time = cfg->genesis_time;
    s->k_phase = cfg->k_phase;
    memcpy(s->self, cfg->self, ANTS_CHAIN_PEER_ID_SIZE);
    s->is_trustee = trustee_index(s, s->self, NULL);
    if (s->is_trustee && (cfg->sign_fn == NULL || cfg->view_fn == NULL)) {
        memset(rt->_opaque, 0, sizeof rt->_opaque);
        return ANTS_ERROR_INVALID_ARG;
    }
    s->sign_fn = cfg->sign_fn;
    s->sign_ctx = cfg->sign_ctx;
    s->view_fn = cfg->view_fn;
    s->view_ctx = cfg->view_ctx;
    s->proposal_fn = cfg->proposal_fn;
    s->attestation_fn = cfg->attestation_fn;
    s->final_fn = cfg->final_fn;
    s->out_ctx = cfg->out_ctx;

    s->head.height = 0;
    memcpy(s->head.hash, cfg->genesis_hash, ANTS_CHAIN_HASH_SIZE);
    s->head.cutoff_time = cfg->genesis_time;
    s->head.epoch = 0;
    s->head.degraded_seed = false;
    start_attempt(s, 1, now);
    return ANTS_OK;
}

void ants_chain_rt_tick(ants_chain_rt_t *rt, uint64_t now)
{
    if (rt == NULL) {
        return;
    }
    struct rt_state *s = st(rt);
    if (now >= s->attempt_start + ANTS_CHAIN_FINALITY_TIMEOUT_S) {
        /* Skipped: the next height, same prev, a new committee. */
        start_attempt(s, s->h + 1, now);
    }
    if (s->member && s->my_pos == s->proposer_pos && s->cur < 0 && s->last_signed_height < s->h &&
        now >= s->attempt_start + ANTS_CHAIN_RT_DRAND_FLOOR_S &&
        now >= s->head.cutoff_time + ANTS_CHAIN_BLOCK_TIME_S) {
        struct rt_proposal *p = prop_alloc(s);
        if (p != NULL && compose(s, s->h, s->head.hash, now, p) == ANTS_OK) {
            p->used = true;
            sign_and_emit(s, p, true, now);
            try_finalize(s, now);
        } else if (p != NULL) {
            memset(p, 0, sizeof *p);
        }
        return;
    }
    if (s->cur >= 0 && now >= s->last_emit + ANTS_CHAIN_RT_REBROADCAST_S) {
        /* Re-broadcast the proposal we hold for this attempt and our
         * attestation on it, for members that missed them. */
        struct rt_proposal *p = &s->props[s->cur];
        const ants_chain_attestation_t *mine = att_find(s, p->hash, s->self);
        if (mine != NULL && s->attestation_fn != NULL) {
            s->attestation_fn(mine, s->out_ctx); /* attestation first, as above */
        }
        if (s->proposal_fn != NULL) {
            s->proposal_fn(p->bytes, p->len, s->out_ctx);
        }
        s->last_emit = now;
    }
}

ants_error_t
ants_chain_rt_on_proposal(ants_chain_rt_t *rt, const uint8_t *block, size_t len, uint64_t now)
{
    if (rt == NULL || block == NULL || len > ANTS_CHAIN_BLOCK_ENCODED_MAX) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct rt_state *s = st(rt);
    ants_chain_block_t b;
    size_t n_findings = 0;
    ants_error_t err = ants_chain_block_decode(
        block, len, &b, s->findings, ANTS_CHAIN_MAX_PATTERN_FINDINGS, &n_findings);
    if (err != ANTS_OK) {
        return err;
    }
    if (!b.degraded_seed) {
        return ANTS_ERROR_UNSUPPORTED_TYPE; /* v1 holds no beacon */
    }
    if (b.height <= s->head.height || b.summary.cutoff_time < s->genesis_time) {
        return ANTS_OK; /* at or below the head: nothing to do */
    }
    uint8_t hash[ANTS_CHAIN_HASH_SIZE];
    if ((err = ants_chain_block_hash(&b, hash)) != ANTS_OK) {
        return err;
    }
    struct rt_proposal *p = prop_find(s, hash);
    if (p == NULL && !att_any_for(s, hash)) {
        /* No population attestation for this block yet: a block carries no
         * proposer signature, so an unattested one could be anyone's. Not
         * filed, not forwarded — the proposer's attestation travels ahead
         * of its block, and re-broadcasts bring the block again. */
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (p == NULL) {
        p = prop_alloc(s);
        if (p == NULL) {
            return ANTS_OK;
        }
        p->used = true;
        p->degraded = true;
        p->height = b.height;
        p->cutoff = b.summary.cutoff_time;
        p->epoch = b.summary.epoch;
        memcpy(p->prev, b.prev_block_hash, ANTS_CHAIN_HASH_SIZE);
        memcpy(p->hash, hash, ANTS_CHAIN_HASH_SIZE);
        memcpy(p->bytes, block, len);
        p->len = len;
    }

    /* Sign it if it is OUR attempt's block and our own recomputation agrees. */
    if (s->member && b.height == s->h && s->last_signed_height < s->h &&
        memcmp(b.prev_block_hash, s->head.hash, ANTS_CHAIN_HASH_SIZE) == 0 &&
        p->cutoff >= s->head.cutoff_time + ANTS_CHAIN_BLOCK_TIME_S &&
        p->cutoff <= now + ANTS_CHAIN_RT_CLOCK_SKEW_S) {
        struct rt_proposal *mine = &s->recompute;
        memset(mine, 0, sizeof *mine);
        if (compose(s, s->h, s->head.hash, p->cutoff, mine) == ANTS_OK &&
            memcmp(mine->hash, p->hash, ANTS_CHAIN_HASH_SIZE) == 0) {
            sign_and_emit(s, p, false, now);
        }
    }
    try_finalize(s, now);
    return ANTS_OK;
}

ants_error_t
ants_chain_rt_on_attestation(ants_chain_rt_t *rt, const ants_chain_attestation_t *att, uint64_t now)
{
    if (rt == NULL || att == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct rt_state *s = st(rt);
    /* Verify before filing: an attestation with a bad signature would
     * otherwise turn the whole finality verdict false for its block. */
    if (!trustee_index(s, att->signer, NULL) ||
        ants_ed25519_verify(att->signer, att->block_hash, ANTS_CHAIN_HASH_SIZE, att->sig) !=
            ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    const ants_chain_attestation_t *known = att_find(s, att->block_hash, att->signer);
    if (known != NULL) {
        /* The same attestation again. An exact repeat (a holder's periodic
         * re-broadcast) may travel on; a copy with a different, unsigned
         * height is a re-labelled duplicate and stops here. */
        return known->height == att->height ? ANTS_OK : ANTS_ERROR_UNSUPPORTED_TYPE;
    }
    if (att->height <= s->head.height) {
        return ANTS_ERROR_UNSUPPORTED_TYPE; /* at or below the head */
    }
    (void)att_file(s, att);
    try_finalize(s, now);
    return ANTS_OK;
}

void ants_chain_rt_head(const ants_chain_rt_t *rt, ants_chain_head_t *out)
{
    if (rt == NULL || out == NULL) {
        return;
    }
    *out = st_const(rt)->head;
}

uint64_t ants_chain_rt_attempt_height(const ants_chain_rt_t *rt)
{
    return rt == NULL ? 0 : st_const(rt)->h;
}
