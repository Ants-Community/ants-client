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
 * Scope so far:
 *   PR1 — the accounting core:
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
 *   PR2 — the choke / unchoke loop (RFC-0001 §"The choke / unchoke
 *   algorithm", constants in RFC-0008 §7):
 *   - A windowed generosity score over a recent-receipts ring buffer
 *     (ants_ledger_record_recv / ants_ledger_generosity).
 *   - ants_ledger_unchoke_round: rank peers by generosity * quality,
 *     unchoke the earned slots, reserve a 1/8 optimistic-unchoke slot.
 *
 * Deliberately NOT in this component yet:
 *   - payment-terms negotiation (RFC-0006).
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

/* Choke/unchoke loop defaults (RFC-0001 §"The choke / unchoke
 * algorithm", consolidated in RFC-0008 §7). All Calibratable — exposed
 * as the shared default; the loop function takes window/slots as
 * parameters so a caller may override. */
#define ANTS_LEDGER_CHOKE_WINDOW_S        1200u /* 20 minutes              */
#define ANTS_LEDGER_CHOKE_LOOP_INTERVAL_S 10u   /* 10 seconds              */
#define ANTS_LEDGER_DEFAULT_SLOTS         8u    /* parallel serve slots    */

/* Optimistic-unchoke reservation: 1 slot in this many is reserved for a
 * peer we have not served recently (network porosity for newcomers).
 * RFC-0008 §7 pins OPTIMISTIC_UNCHOKE_RATIO = 12.5% = 1/8. (NB: the
 * RFC-0001 pseudocode shows `slots // 4`; the §7 constants table and the
 * prose "12.5% of capacity" are authoritative — followed here. The
 * pseudocode/table mismatch is worth an upstream clarification.) */
#define ANTS_LEDGER_OPTIMISTIC_UNCHOKE_DIVISOR 8u

/* Recent-receipts ring-buffer capacity per peer. The windowed generosity
 * score (ants_ledger_generosity) sums at most this many receipts inside
 * the window; a peer sending receipts more frequently has its oldest
 * evicted — faithful to the reference impl's deque(maxlen) semantics
 * (RFC-0001 §"A reference implementation you could write in an
 * afternoon"). 32 keeps one record ~600 B. */
#define ANTS_LEDGER_RECENT_SAMPLES 32u

/* ------------------------------------------------------------------------ */
/* Peer record                                                              */
/* ------------------------------------------------------------------------ */

/*
 * One recent-receipt sample: work the counterparty served to us at a
 * point in time, used by the windowed generosity score. u64 fields, no
 * float (RFC-0008 §6).
 */
typedef struct {
    uint64_t unix_s;      /* when the receipt was recorded */
    uint64_t amount_uncs; /* uNCS they served us in it     */
} ants_ledger_recv_sample_t;

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
 * quality_q14k and choked are driven by the choke/unchoke loop
 * (ants_ledger_unchoke_round); the recent[] ring buffer feeds the
 * windowed generosity score that ranks peers in that loop.
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
     * to 10000 (== 1.0) at init; quality is a *multiplier* on the
     * generosity ranking (RFC-0001), not a replacement for it. */
    uint16_t quality_q14k;

    /* Current local choke state for this peer, set by the unchoke loop:
     * true = we are declining to serve them this round. */
    bool choked;

    /* Recent-receipts ring buffer for the windowed generosity score.
     * recent_head is the index of the next write; recent_count is the
     * number of valid samples (<= ANTS_LEDGER_RECENT_SAMPLES). Oldest
     * sample is at (recent_head - recent_count) mod cap. */
    ants_ledger_recv_sample_t recent[ANTS_LEDGER_RECENT_SAMPLES];
    uint32_t recent_head;
    uint32_t recent_count;
} ants_ledger_peer_t;

/* ------------------------------------------------------------------------ */
/* Record lifecycle + accounting                                            */
/* ------------------------------------------------------------------------ */

/*
 * Initialise a fresh peer record for `peer_id`. Zeroes both totals and
 * the recent-receipts ring buffer, sets quality to 1.0 (== 10000),
 * choked = true (a peer starts choked until the unchoke loop or an
 * optimistic slot serves it — RFC-0001 cold start), and stamps
 * since/last_update with `now_unix_s` (pass 0 if no clock is available;
 * the field is then "unset").
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
/* Choke / unchoke loop (RFC-0001 §"The choke / unchoke algorithm")         */
/* ------------------------------------------------------------------------ */

/*
 * Record a receipt: work THEY served to us. Credits served_by (with the
 * same overflow contract as ants_ledger_credit_served_by) AND pushes a
 * (now_unix_s, amount_uncs) sample into the recent ring buffer so it
 * counts toward the windowed generosity score. This is the path the
 * serving runtime should call for every received service; the bare
 * ants_ledger_credit_served_by remains for raw total adjustments that
 * should NOT feed the generosity window.
 *
 * If the served_by credit overflows, the record is left unchanged and
 * no sample is pushed (ANTS_ERROR_OVERFLOW).
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec is NULL;
 *         ANTS_ERROR_OVERFLOW on served_by overflow (record unchanged).
 */
ants_error_t
ants_ledger_record_recv(ants_ledger_peer_t *rec, uint64_t amount_uncs, uint64_t now_unix_s);

/*
 * Windowed generosity score: the sum, in uNCS, of recent receipts whose
 * timestamp is within `window_s` seconds of `now_unix_s` (i.e.
 * sample.unix_s + window_s >= now_unix_s). This is the "how generous
 * have they been to us recently" measure the unchoke loop ranks on
 * (RFC-0001: reputation is recent behaviour, not accumulated wealth).
 *
 * The sum saturates at UINT64_MAX rather than wrapping (a guard; real
 * 20-minute receipt sums sit far below that). Samples with unix_s == 0
 * (clockless receipts) are treated as always-in-window.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if rec or out_uncs is NULL.
 */
ants_error_t ants_ledger_generosity(const ants_ledger_peer_t *rec,
                                    uint64_t now_unix_s,
                                    uint64_t window_s,
                                    uint64_t *out_uncs);

/*
 * Run one unchoke round over `n_records` caller-owned peer records,
 * setting each record's `choked` flag (RFC-0001 §"The choke / unchoke
 * algorithm"). Decision for the next CHOKE_LOOP_INTERVAL:
 *
 *   1. Rank peers by generosity(window_s) * quality_q14k (a saturating
 *      product; quality is a multiplier, not a replacement — RFC-0001).
 *      The top `earned` peers are unchoked, where
 *      earned = slots - optimistic and
 *      optimistic = max(1, slots / ANTS_LEDGER_OPTIMISTIC_UNCHOKE_DIVISOR).
 *      Ties in score break by peer_id bytewise-ascending (deterministic,
 *      unbiased).
 *   2. Reserve `optimistic` slots for peers NOT earned-unchoked, chosen
 *      round-robin starting at `rotation % (#still-choked)`. The caller
 *      advances `rotation` each round so every peer eventually gets an
 *      optimistic turn — the deterministic, RNG-free stand-in for the
 *      reference impl's random optimistic pick (network porosity for
 *      newcomers; RFC-0001 "optimistic unchoke is non-negotiable").
 *
 * Everything not chosen is choked. With slots == 0 all peers are choked.
 *
 * `score_scratch` must hold at least `n_records` uint64_t — it receives
 * the per-record ranking scores (caller-owned, avoids internal alloc;
 * same caller-buffer pattern as the canonical-kernels attention scratch).
 *
 * @param records       array of n_records peer records (choked is written).
 * @param n_records     number of records (0 is a no-op success).
 * @param now_unix_s    current time for the generosity window.
 * @param window_s      generosity window (e.g. ANTS_LEDGER_CHOKE_WINDOW_S).
 * @param slots         parallel serve slots (e.g. ANTS_LEDGER_DEFAULT_SLOTS).
 * @param rotation      caller-advanced counter for optimistic round-robin.
 * @param score_scratch caller buffer, >= n_records uint64_t.
 * @param scratch_len   length of score_scratch.
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL args (with n_records>0)
 *         or scratch_len < n_records.
 */
ants_error_t ants_ledger_unchoke_round(ants_ledger_peer_t *records,
                                       size_t n_records,
                                       uint64_t now_unix_s,
                                       uint64_t window_s,
                                       uint32_t slots,
                                       uint64_t rotation,
                                       uint64_t *score_scratch,
                                       size_t scratch_len);

/* ------------------------------------------------------------------------ */
/* Canonical serialisation (RFC-0008 §1.1 + §6)                             */
/* ------------------------------------------------------------------------ */

/*
 * Worst-case encoded size of one record, for caller buffer sizing.
 * The 8-pair map's scalar fields cost ~80 B; the recent-receipts array
 * dominates: ANTS_LEDGER_RECENT_SAMPLES entries, each a 2-element array
 * of u64s (worst case 1 + 9 + 9 = 19 B). 32 * 19 + ~90 < 1024.
 */
#define ANTS_LEDGER_RECORD_ENCODED_MAX 1024u

/*
 * Encode one peer record as canonical CBOR (RFC-0008 §1.1) into `buf`.
 * The encoding is a definite-length map of 8 integer-keyed pairs in
 * canonical (ascending) key order:
 *   1: peer_id            (byte string, 32 B)
 *   2: served_to          (uint, uNCS)
 *   3: served_by          (uint, uNCS)
 *   4: since_unix_s       (uint)
 *   5: last_update_unix_s (uint)
 *   6: quality_q14k       (uint)
 *   7: choked             (bool)
 *   8: recent             (array of recent_count [unix_s, amount] pairs,
 *                          normalised oldest-first; the ring head is not
 *                          serialised, so the encoding is canonical
 *                          regardless of internal head position)
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
 * (wrong map shape, wrong type, wrong byte-string length, truncation, a
 * recent[] array longer than ANTS_LEDGER_RECENT_SAMPLES, or a sample
 * sub-array not exactly 2 elements) returns ANTS_ERROR_MALFORMED. A
 * permissive decoder would open hash-malleability on the persisted
 * record, so it fails closed. On success the ring buffer is rebuilt with
 * recent_count samples at indices [0, recent_count).
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL args;
 *         ANTS_ERROR_NON_CANONICAL / ANTS_ERROR_MALFORMED as above.
 */
ants_error_t ants_ledger_record_decode(const uint8_t *buf, size_t len, ants_ledger_peer_t *rec);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_LEDGER_H */
