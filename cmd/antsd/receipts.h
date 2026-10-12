/*
 * cmd/antsd/receipts.h — the node's receipt bag on disk.
 *
 * Every receipt the node countersigns (RFC-0008 §11.15) is appended to a
 * file next to the config, `<config>.receipts`, and the bag is reloaded at
 * start, so the node's A and T (RFC-0004 §"Computing A") survive restarts.
 *
 * The file is LOCAL state, never a wire format: a sequence of records
 *   u16 big-endian body length ‖ body (§11.9 encoding) ‖ server_sig (64)
 *   ‖ client_sig (64)
 * appended in the order they were filed. Loading keeps only receipts whose
 * two signatures verify and that credit this node. Anything from the first
 * record that does not frame (a crash mid-append, a torn write) to the end
 * of the file is truncated away at load, so later appends never land behind
 * garbage; a failed append is truncated back the same way.
 *
 * Every nonce ever filed is remembered (16 bytes each), because §11.15 allows
 * at most one receipt per nonce and the commit behind a nonce is
 * deterministic: a replayed request would otherwise be paid again once the
 * engine's served table forgot it.
 */
#ifndef ANTSD_RECEIPTS_H
#define ANTSD_RECEIPTS_H

#include "ants_common.h"
#include "ants_reputation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char path[1024];
    uint8_t self[ANTS_REP_PEER_ID_SIZE];
    /* The newest ANTS_REP_MAX_RECEIPTS receipts, oldest first. */
    ants_reputation_receipt_t bag[ANTS_REP_MAX_RECEIPTS];
    size_t n;
    size_t skipped;   /* records on disk that did not verify or credit us */
    size_t truncated; /* bytes of torn tail cut at load */
    uint8_t *paid;    /* heap: open-addressed set, paid_cap slots of 16 bytes */
    size_t paid_cap;  /* a power of two, or 0 */
    size_t paid_n;
} antsd_receipts_t;

/* Point `r` at `<config_path>.receipts` for node `self` and load it. A
 * missing file is an empty bag. Returns ANTS_OK, or ANTS_ERROR_INVALID_ARG
 * when the path does not fit. */
ants_error_t antsd_receipts_open(antsd_receipts_t *r,
                                 const char *config_path,
                                 const uint8_t self[ANTS_REP_PEER_ID_SIZE]);

/* Free the nonce set. */
void antsd_receipts_close(antsd_receipts_t *r);

/* Whether a receipt with this nonce was ever filed. */
bool antsd_receipts_paid(const antsd_receipts_t *r, const uint8_t nonce[ANTS_REP_NONCE_SIZE]);

/* Append `rc` to the file and the in-memory bag (the oldest is dropped
 * once the bag is full). Returns ANTS_OK, or ANTS_ERROR_INVALID_ARG when
 * the write failed (the receipt is still kept in memory). */
ants_error_t antsd_receipts_add(antsd_receipts_t *r, const ants_reputation_receipt_t *rc);

/* A and T at `now` over the bag, with the DRAFT reputation parameters.
 * Re-verifies every receipt (≈ 0.3 s for a full bag): call it at start,
 * at shutdown or on demand — never per receipt on the event loop. */
ants_error_t antsd_receipts_reputation(const antsd_receipts_t *r,
                                       uint64_t now,
                                       uint64_t *out_a,
                                       uint64_t *out_t);

#endif /* ANTSD_RECEIPTS_H */
