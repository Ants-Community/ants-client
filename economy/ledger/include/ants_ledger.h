/*
 * ants_ledger.h — Local community-layer economic ledger (Component #14).
 *
 * The per-pair NCS accounting that the community economy runs on
 * (RFC-0001 §"The local ledger"). This is a PLAIN, LOCAL, append-only
 * record — not a blockchain, not shared state, not consensus. Each peer
 * keeps one record per other community-layer peer it has interacted
 * with, makes local decisions from it, and never publishes a total
 * (RFC-0001: "NCS is a unit of measurement, not a currency … no
 * aggregate, no leaderboard").
 *
 * Scope of THIS component (PR1 — the accounting core):
 *   - Per-pair running totals served_to / served_by in u64 micro-NCS
 *     (uNCS), per RFC-0008 §6. Floats are forbidden in ledger
 *     arithmetic ("0.1 + 0.2 != 0.3" is unacceptable in an append-only
 *     economic record); all quantities are u64 uNCS.
 *   - Signed net balance computed ON DEMAND from the two unsigned
 *     totals (never stored), so a balance is always derivable and never
 *     itself an accumulator that could underflow.
 *   - Overflow is a hard error: a credit that would push a total past
 *     UINT64_MAX is rejected and the total is left unchanged, per
 *     RFC-0008 §6 ("Overflow is a protocol error and causes the
 *     involved transaction to be rejected").
 *   - Canonical CBOR (de)serialisation of one peer record, for the
 *     local on-disk log, per RFC-0008 §1.1 / §6.
 *
 * Deliberately NOT in this component yet (documented for the reader,
 * landing in later PRs so each stays small and well-tested):
 *   - the choke / unchoke loop (RFC-0001 §"The choke / unchoke
 *     algorithm": CHOKE_WINDOW, CHOKE_LOOP_INTERVAL, the generosity
 *     ranking) and the optimistic-unchoke slot;
 *   - payment-terms negotiation (RFC-0006).
 * The record carries the fields those will need (quality, choked,
 * timestamps) so the on-disk format does not change when they land.
 *
 * uNCS unit (RFC-0008 §6):
 *   1 NCS  = 1 000 000 uNCS ;  1 uNCS = 1 unit of the u64.
 *   max representable ~ 1.8e13 NCS — more than any single peer's
 *   steady-state lifetime accounting.
 *
 * API model: caller-allocated state, no internal allocation, no
 * threads, no hidden global state. Matches the C99 + caller-owns-state
 * discipline of foundation/, network/, cache/, inference/.
 *
 * Spec: RFC-0001 v0.3 §"The local ledger"; RFC-0008 v0.5 §6 (NCS
 * encoding) + §1.1 (canonical CBOR). The on-the-wire/on-disk record
 * shape below is DRAFT pending an explicit RFC-0008 §"Ledger record"
 * section; it should be upstreamed to the spec before peers persist
 * records they expect to interchange.
 *
 * Component README: ants-client/economy/ledger/README.md.
 */

#ifndef ANTS_LEDGER_H
#define ANTS_LEDGER_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

/* A peer is identified by its 32-byte Ed25519 public key (== the
 * protocol peer-id, RFC-0008). The ledger keeps the size local rather
 * than pulling in the network/transport ants_peer_id_t type, so the
 * economy layer does not depend on the transport layer for a 32-byte
 * array. The value MUST match ANTS_ED25519_PUBKEY_SIZE. */
#define ANTS_LEDGER_PEER_ID_SIZE 32u

/* uNCS per whole NCS (RFC-0008 §6). Exposed so callers converting
 * human-facing NCS to ledger units share one constant. */
#define ANTS_LEDGER_UNCS_PER_NCS 1000000u

/* ------------------------------------------------------------------------ */
/* Peer record                                                              */
/* ------------------------------------------------------------------------ */

/*
 * One peer-pair record: our local view of our economic relationship
 * with exactly one counterparty. RFC-0001 §"The local ledger".
 *
 * served_to   — total work WE have served TO them, in uNCS. Their
 *               unpaid balance with us. Monotonic non-decreasing
 *               (credits only; an append-only record never debits).
 * served_by   — total work THEY have served to US, in uNCS. Our unpaid
 *               balance with them. Monotonic non-decreasing.
 *
 * The signed net balance (served_to - served_by) is NOT stored — it is
 * computed on demand by ants_ledger_net_balance(), so there is no
 * signed accumulator to under/overflow and the two sources of truth
 * stay the two unsigned totals (RFC-0008 §6).
 *
 * The remaining fields are carried so the persisted format is stable
 * when the choke/unchoke PR lands; this PR sets them at init and on
 * record (last_update_unix_s) but does not yet drive decisions from
 * quality / choked.
 */
typedef struct {
    uint8_t peer_id[ANTS_LEDGER_PEER_ID_SIZE];

    uint64_t served_to; /* uNCS we have served to them   */
    uint64_t served_by; /* uNCS they have served to us   */

    /* Unix seconds of the first and most recent interaction. Stored as
     * u64 (not float, not time_t — fixed width for the canonical
     * record). 0 means "unset" (no interaction yet). */
    uint64_t since_unix_s;
    uint64_t last_update_unix_s;

    /* Rolling verified-correct rate in [0, 10000] = fixed-point
     * 0.0000..1.0000 in basis-of-10000 (NO float in the record). Seeded
     * to 10000 (== 1.0) at init. The choke PR will drive this; here it
     * is just carried through (de)serialisation. */
    uint16_t quality_q14k;

    /* Current local choke state for this peer. Carried, not yet driven
     * by a loop in this PR. */
    bool choked;
} ants_ledger_peer_t;

/* ------------------------------------------------------------------------ */
/* Record lifecycle + accounting                                            */
/* ------------------------------------------------------------------------ */

/*
 * Initialise a fresh peer record for `peer_id`. Zeroes both totals,
 * sets quality to 1.0 (== 10000), choked = true (a peer starts choked
 * until the unchoke loop or an optimistic slot serves it — RFC-0001
 * cold start), and stamps since/last_update with `now_unix_s` (pass 0
 * if no clock is available; the field is then "unset").
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec or peer_id is NULL.
 */
ants_error_t ants_ledger_peer_init(ants_ledger_peer_t *rec,
                                   const uint8_t peer_id[ANTS_LEDGER_PEER_ID_SIZE],
                                   uint64_t now_unix_s);

/*
 * Credit work WE served to them: served_to += amount_uncs.
 *
 * Overflow-checked: if served_to + amount_uncs would exceed UINT64_MAX
 * the credit is REJECTED, served_to is left unchanged, and the call
 * returns ANTS_ERROR_OVERFLOW (RFC-0008 §6: overflow is a protocol
 * error and the transaction is rejected). On success last_update_unix_s
 * is set to now_unix_s (when non-zero).
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec is NULL;
 *         ANTS_ERROR_OVERFLOW on overflow (record unchanged).
 */
ants_error_t
ants_ledger_credit_served_to(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s);

/*
 * Credit work THEY served to us: served_by += amount_uncs. Same
 * overflow contract as ants_ledger_credit_served_to.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec is NULL;
 *         ANTS_ERROR_OVERFLOW on overflow (record unchanged).
 */
ants_error_t
ants_ledger_credit_served_by(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s);

/*
 * Compute the signed net balance served_to - served_by, in uNCS, into
 * *out_net. Positive => we are ahead (they owe us work); negative =>
 * we owe them. Computed on demand; never stored.
 *
 * The result is an int64_t. Each total is u64 and can in principle
 * exceed INT64_MAX, so a pathological difference could exceed int64
 * range; that case returns ANTS_ERROR_OVERFLOW rather than a wrapped
 * value. In practice both totals sit far below 2^63 uNCS (~9.2e12 NCS),
 * so this is a guard, not an expected path.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec or out_net is NULL;
 *         ANTS_ERROR_OVERFLOW if the difference exceeds int64 range.
 */
ants_error_t ants_ledger_net_balance(const ants_ledger_peer_t *rec, int64_t *out_net);

/* ------------------------------------------------------------------------ */
/* Canonical serialisation (RFC-0008 §1.1 + §6)                             */
/* ------------------------------------------------------------------------ */

/*
 * Worst-case encoded size of one record, for caller buffer sizing.
 * A 6-pair canonical CBOR map: peer_id (34 B), two u64 totals (9 B
 * each), two u64 timestamps (9 B each), quality (3 B), choked (1 B),
 * plus integer keys and the map header — comfortably under this bound.
 */
#define ANTS_LEDGER_RECORD_ENCODED_MAX 128u

/*
 * Encode one peer record as canonical CBOR (RFC-0008 §1.1) into `buf`.
 * The encoding is a definite-length map of 7 integer-keyed pairs in
 * canonical (ascending) key order:
 *   1: peer_id            (byte string, 32 B)
 *   2: served_to          (uint, uNCS)
 *   3: served_by          (uint, uNCS)
 *   4: since_unix_s       (uint)
 *   5: last_update_unix_s (uint)
 *   6: quality_q14k       (uint)
 *   7: choked             (bool)
 * Float-free by construction (RFC-0008 §1.3 / §6).
 *
 * On success *out_len is the number of bytes written.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL args;
 *         ANTS_ERROR_BUFFER_TOO_SMALL if cap is insufficient (buf
 *         contents then unspecified, *out_len unset).
 */
ants_error_t
ants_ledger_record_encode(const ants_ledger_peer_t *rec, uint8_t *buf, size_t cap, size_t *out_len);

/*
 * Decode one canonical-CBOR peer record from `buf` into `rec`. The
 * decoder is STRICT: a §4.2.1 canonical violation (non-shortest int,
 * out-of-order/duplicate keys, indefinite length, trailing bytes)
 * returns ANTS_ERROR_NON_CANONICAL; any other structural problem
 * (wrong map shape, wrong type, wrong byte-string length, truncation)
 * returns ANTS_ERROR_MALFORMED. A permissive decoder would open
 * hash-malleability on the persisted record, so it fails closed.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL args;
 *         ANTS_ERROR_NON_CANONICAL / ANTS_ERROR_MALFORMED as above.
 */
ants_error_t ants_ledger_record_decode(const uint8_t *buf, size_t len, ants_ledger_peer_t *rec);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_LEDGER_H */
