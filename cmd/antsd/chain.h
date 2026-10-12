/*
 * cmd/antsd/chain.h — the daemon's L2 chain loop: the glue between the
 * block-production runtime (reputation/chain ants_chain_runtime.h), the
 * node's Layer-1 G-Set (its view at a cutoff) and the gossip overlay
 * (RFC-0008 §11.13 BLOCK / ATTEST frames).
 */
#ifndef ANTSD_CHAIN_H
#define ANTSD_CHAIN_H

#include "config.h"

#include "ants_chain_runtime.h"
#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_gossip.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    ants_chain_rt_t rt;
    ants_gossip_t *gossip;
    ants_crdt_t *gset;
    const uint8_t *priv; /* the identity seed (signs block hashes) */
    uint64_t genesis_time;
    uint8_t trustees[ANTSD_MAX_TRUSTEES][ANTS_CHAIN_PEER_ID_SIZE];
    size_t n_trustees;
    bool on;
    bool pending; /* genesis time still ahead: start once it arrives */
    bool trustee;
    antsd_genesis_t genesis;
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    uint64_t finals;
    uint64_t proposals;
    uint64_t attestations;
} antsd_chain_t;

/*
 * Start the chain loop from the config genesis and register the gossip
 * chain handler. `priv` must outlive the loop. A genesis time still in the
 * future is not an error: the loop is left pending (c->pending) and
 * antsd_chain_tick starts it once the time arrives. Returns ANTS_OK with
 * c->on or c->pending set, or the runtime's init error with both off.
 */
ants_error_t antsd_chain_start(antsd_chain_t *c,
                               const antsd_genesis_t *genesis,
                               const uint8_t priv[ANTS_ED25519_PRIVKEY_SIZE],
                               const uint8_t pub[ANTS_ED25519_PUBKEY_SIZE],
                               ants_gossip_t *gossip,
                               ants_crdt_t *gset,
                               uint64_t now);

/* Drive the runtime's clock (propose, re-broadcast, skip); starts a
 * pending loop once the genesis time arrives. */
void antsd_chain_tick(antsd_chain_t *c, uint64_t now);

#endif /* ANTSD_CHAIN_H */
