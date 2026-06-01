/*
 * bond.c — Bond accounting for high-stakes acts (Component #15, RFC-0004
 * v0.6 §"Bonds for high-stakes acts" + §"Bond accounting model").
 *
 * Component #15 is feature-complete at v0.x:
 *   - the local bond ledger (init / count / locked_total / find / bondable_a
 *     / admit / release / slash) with additive multi-act composition;
 *   - the per-class bond formulas (§"Bond formulas");
 *   - the canonical-CBOR bond_admission object the verifier signs + gossips;
 *   - the race-safe admission tie-break (BLAKE3 derive_key, no clock-sync).
 * `A` is supplied by the caller (computed via reputation/identity's
 * ants_reputation_compute); this module owns the locked-bond set, the
 * headroom arithmetic, the formulas, the admission codec, and the tie-break.
 * No malloc, no float, no threads, no hidden state.
 *
 * Spec: RFC-0004 v0.6 §"Bond accounting model"; RFC-0008 v0.5 §6 (u64 μNCS),
 * §7 (constants).
 */

#include "ants_bond.h"

#include "ants_cbor.h"
#include "ants_crypto.h"

#include <string.h>

/* ------------------------------------------------------------------------ */
/* PR1 — the local bond ledger                                               */
/* ------------------------------------------------------------------------ */

void ants_bond_ledger_init(ants_bond_ledger_t *ledger)
{
    if (ledger != NULL) {
        ledger->count = 0;
    }
}

size_t ants_bond_count(const ants_bond_ledger_t *ledger)
{
    return ledger != NULL ? ledger->count : 0;
}

uint64_t ants_bond_locked_total(const ants_bond_ledger_t *ledger)
{
    uint64_t total = 0;
    size_t i;

    if (ledger == NULL) {
        return 0;
    }
    for (i = 0; i < ledger->count; i++) {
        uint64_t a = ledger->locked[i].amount;
        if (a > UINT64_MAX - total) {
            return UINT64_MAX; /* defensive: admission keeps the true sum < 2^64 */
        }
        total += a;
    }
    return total;
}

/* Index of `act_id` in the ledger, or -1 if absent. */
static ptrdiff_t bond_index(const ants_bond_ledger_t *ledger, const uint8_t *act_id)
{
    size_t i;
    for (i = 0; i < ledger->count; i++) {
        if (memcmp(ledger->locked[i].act_id, act_id, ANTS_BOND_ACT_ID_SIZE) == 0) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

const ants_bond_t *ants_bond_find(const ants_bond_ledger_t *ledger,
                                  const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE])
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL) {
        return NULL;
    }
    idx = bond_index(ledger, act_id);
    return idx < 0 ? NULL : &ledger->locked[idx];
}

ants_error_t
ants_bond_bondable_a(const ants_bond_ledger_t *ledger, uint64_t total_a, uint64_t *out_bondable)
{
    uint64_t locked;
    if (ledger == NULL || out_bondable == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    locked = ants_bond_locked_total(ledger);
    *out_bondable = total_a > locked ? total_a - locked : 0;
    return ANTS_OK;
}

ants_error_t ants_bond_admit(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t amount,
                             uint64_t t_start,
                             const uint8_t slash_target[ANTS_BOND_SIG_SIZE],
                             uint64_t total_a,
                             bool *out_admitted)
{
    uint64_t bondable;
    ants_bond_t *slot;

    if (ledger == NULL || act_id == NULL || slash_target == NULL || out_admitted == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* A given act bonds once. */
    if (bond_index(ledger, act_id) >= 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* t_release must not wrap. */
    if (t_start > UINT64_MAX - ANTS_BOND_DISPUTE_WINDOW_S) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (ledger->count >= ANTS_BOND_MAX_LOCKED) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Headroom is an economic verdict, not an error. */
    {
        uint64_t locked = ants_bond_locked_total(ledger);
        bondable = total_a > locked ? total_a - locked : 0;
    }
    if (bondable < amount) {
        *out_admitted = false;
        return ANTS_OK;
    }

    slot = &ledger->locked[ledger->count];
    memcpy(slot->act_id, act_id, ANTS_BOND_ACT_ID_SIZE);
    slot->amount = amount;
    slot->t_start = t_start;
    slot->t_release = t_start + ANTS_BOND_DISPUTE_WINDOW_S;
    memcpy(slot->slash_target, slash_target, ANTS_BOND_SIG_SIZE);
    ledger->count++;

    *out_admitted = true;
    return ANTS_OK;
}

/* Remove the bond at index `idx` by swapping the last entry into its slot. */
static void bond_remove_at(ants_bond_ledger_t *ledger, ptrdiff_t idx)
{
    size_t last = ledger->count - 1;
    if ((size_t)idx != last) {
        ledger->locked[idx] = ledger->locked[last];
    }
    ledger->count--;
}

ants_error_t ants_bond_release(ants_bond_ledger_t *ledger,
                               const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                               bool *out_found)
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    idx = bond_index(ledger, act_id);
    if (idx >= 0) {
        bond_remove_at(ledger, idx);
    }
    if (out_found != NULL) {
        *out_found = (idx >= 0);
    }
    return ANTS_OK;
}

ants_error_t ants_bond_slash(ants_bond_ledger_t *ledger,
                             const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                             uint64_t *out_amount,
                             bool *out_found)
{
    ptrdiff_t idx;
    if (ledger == NULL || act_id == NULL || out_amount == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    idx = bond_index(ledger, act_id);
    if (idx >= 0) {
        *out_amount = ledger->locked[idx].amount;
        bond_remove_at(ledger, idx);
    } else {
        *out_amount = 0;
    }
    if (out_found != NULL) {
        *out_found = (idx >= 0);
    }
    return ANTS_OK;
}

/* ======================================================================== */
/* PR2 — bond formulas (RFC-0004 §"Bond formulas")                           */
/* ======================================================================== */

ants_error_t ants_bond_required_tier3(uint64_t query_stakes, uint64_t n, uint64_t *out)
{
    if (out == NULL || n == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* query_stakes / N per member: N colluders bond query_stakes in total. */
    *out = query_stakes / n;
    return ANTS_OK;
}

ants_error_t ants_bond_required_fork_recovery(uint64_t total_t_at_stake, uint64_t *out)
{
    if (out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* The maximum case: bond the entire T at stake in the pre-fault state. */
    *out = total_t_at_stake;
    return ANTS_OK;
}

ants_error_t
ants_bond_required_value_scaled(uint64_t value, uint64_t mult_num, uint64_t mult_den, uint64_t *out)
{
    uint64_t q;
    uint64_t r;
    uint64_t term1;
    uint64_t term2;

    if (out == NULL || mult_den == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* floor(value * mult_num / mult_den) without a 128-bit intermediate:
     * value = q*mult_den + r, so value*mult_num/mult_den
     *       = q*mult_num + (r*mult_num)/mult_den. Each product is overflow-
     *       checked (r < mult_den, so the second rarely matters). */
    q = value / mult_den;
    r = value % mult_den;
    if (mult_num != 0 && q > UINT64_MAX / mult_num) {
        return ANTS_ERROR_OVERFLOW;
    }
    term1 = q * mult_num;
    if (mult_num != 0 && r > UINT64_MAX / mult_num) {
        return ANTS_ERROR_OVERFLOW;
    }
    term2 = (r * mult_num) / mult_den;
    if (term1 > UINT64_MAX - term2) {
        return ANTS_ERROR_OVERFLOW;
    }
    *out = term1 + term2;
    return ANTS_OK;
}

/* ======================================================================== */
/* PR2 — bond_admission object + race-safe tie-break                         */
/* ======================================================================== */

/* The bond_admission is a canonical CBOR map(5), integer keys ascending. */
#define BOND_ADMISSION_PAIRS 5u
enum { ADM_KEY_ACT = 1, ADM_KEY_PEER = 2, ADM_KEY_AMOUNT = 3, ADM_KEY_VID = 4, ADM_KEY_VIEW = 5 };

static void write_le64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static ants_error_t enc_kv_uint(ants_cbor_enc_t *enc, uint64_t key, uint64_t val)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_uint(enc, val);
}

static ants_error_t enc_kv_bytes(ants_cbor_enc_t *enc, uint64_t key, const uint8_t *b, size_t len)
{
    ants_error_t rc = ants_cbor_enc_uint(enc, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bytes(enc, b, len);
}

/* Collapse the decoder's vocabulary onto the codec contract (NON_CANONICAL
 * kept, everything else structural folds to MALFORMED); mirrors the ledger /
 * chain decoders. */
static ants_error_t norm_decode_err(ants_error_t rc)
{
    if (rc == ANTS_OK || rc == ANTS_ERROR_NON_CANONICAL) {
        return rc;
    }
    return ANTS_ERROR_MALFORMED;
}

static ants_error_t expect_key(ants_cbor_dec_t *dec, uint64_t want)
{
    uint64_t key;
    ants_error_t rc = norm_decode_err(ants_cbor_dec_uint(dec, &key));
    if (rc != ANTS_OK) {
        return rc;
    }
    return key == want ? ANTS_OK : ANTS_ERROR_MALFORMED;
}

static ants_error_t decode_uint_field(ants_cbor_dec_t *dec, uint64_t key, uint64_t *out)
{
    ants_error_t rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_uint(dec, out));
}

static ants_error_t
decode_bytes_field(ants_cbor_dec_t *dec, uint64_t key, uint8_t *dst, size_t want)
{
    const uint8_t *p;
    size_t len;
    ants_error_t rc;

    rc = expect_key(dec, key);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_bytes(dec, &p, &len));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (len != want) {
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(dst, p, want);
    return ANTS_OK;
}

ants_error_t ants_bond_admission_encode(const ants_bond_admission_t *adm,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (adm == NULL || buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, BOND_ADMISSION_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, ADM_KEY_ACT, adm->act_id, ANTS_BOND_ACT_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, ADM_KEY_PEER, adm->peer, ANTS_BOND_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_uint(&enc, ADM_KEY_AMOUNT, adm->amount);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, ADM_KEY_VID, adm->v_id, ANTS_BOND_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = enc_kv_bytes(&enc, ADM_KEY_VIEW, adm->l1_view_hash, ANTS_BOND_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

ants_error_t ants_bond_admission_decode(const uint8_t *buf, size_t len, ants_bond_admission_t *out)
{
    ants_cbor_dec_t dec;
    size_t n_pairs;
    ants_error_t rc;

    if (buf == NULL || len == 0 || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    rc = ants_cbor_dec_init(&dec, buf, len);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = norm_decode_err(ants_cbor_dec_map(&dec, &n_pairs));
    if (rc != ANTS_OK) {
        return rc;
    }
    if (n_pairs != BOND_ADMISSION_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    rc = decode_bytes_field(&dec, ADM_KEY_ACT, out->act_id, ANTS_BOND_ACT_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, ADM_KEY_PEER, out->peer, ANTS_BOND_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_uint_field(&dec, ADM_KEY_AMOUNT, &out->amount);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, ADM_KEY_VID, out->v_id, ANTS_BOND_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = decode_bytes_field(&dec, ADM_KEY_VIEW, out->l1_view_hash, ANTS_BOND_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    return norm_decode_err(ants_cbor_dec_finalise(&dec));
}

ants_error_t ants_bond_tiebreak_key(const uint8_t epoch_seed[ANTS_BOND_HASH_SIZE],
                                    const uint8_t act_id[ANTS_BOND_ACT_ID_SIZE],
                                    const uint8_t v_id[ANTS_BOND_PEER_ID_SIZE],
                                    uint64_t admission_round,
                                    uint8_t out_key[ANTS_BOND_HASH_SIZE])
{
    ants_blake3_ctx_t h;
    uint8_t le[8];
    ants_error_t rc;

    if (epoch_seed == NULL || act_id == NULL || v_id == NULL || out_key == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* BLAKE3.derive_key("ants-v1-bond-tiebreak", epoch_seed ‖ act_id ‖ v_id ‖
     * LE64(round)). The epoch_seed (from the L2 chain) prevents a peer
     * precomputing favourable admission timings. */
    rc = ants_blake3_init_derive(&h, "ants-v1-bond-tiebreak");
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, epoch_seed, ANTS_BOND_HASH_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, act_id, ANTS_BOND_ACT_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_blake3_update(&h, v_id, ANTS_BOND_PEER_ID_SIZE);
    if (rc != ANTS_OK) {
        return rc;
    }
    write_le64(le, admission_round);
    rc = ants_blake3_update(&h, le, sizeof le);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_blake3_final(&h, out_key);
}

bool ants_bond_admission_wins(const uint8_t my_key[ANTS_BOND_HASH_SIZE],
                              const uint8_t other_key[ANTS_BOND_HASH_SIZE])
{
    if (my_key == NULL || other_key == NULL) {
        return false;
    }
    /* The SMALLER key (bytewise) wins; equal keys do not win. */
    return memcmp(my_key, other_key, ANTS_BOND_HASH_SIZE) < 0;
}
