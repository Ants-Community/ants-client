/*
 * ants_reputation.h — The (A, T, κ) reputation spine (Component #9,
 * RFC-0004 §"Tenure: the (A, T, κ) spine" + §"Bond accounting model /
 * Computing A").
 *
 * The keystone the rest of the architecture leans on. Two reputation
 * quantities, both deterministic pure functions of the SAME receipt bag
 * (the set of counterparty-countersigned NCS receipts), differing only
 * in decay rate and (for T) a per-identity accrual rate cap:
 *
 *   A  "active"  fast decay δ_A, uncapped — serving priority, audit-window
 *               bound, genesis retirement, and the bondable quantity.
 *   T  "tenure"  slow decay δ_T, accrual κ-clipped per time bin — verifier
 *               eligibility and stable fork-succession ranking.
 *
 *   A(t) = Σ_i  c_i · decay_A(t − t_i)
 *   T(t) = Σ_bins  min(κ · bin_width, Σ c in bin) · decay_T(t − t_bin)
 *
 * (RFC-0004 §816, §825). κ is what makes time the non-buyable resource:
 * tenure cannot accrue faster than κ per identity, no matter the spend.
 *
 * DETERMINISM IS LOAD-BEARING. Every honest peer must compute the SAME
 * T_X from the same receipt bag (RFC-0004 §"Why fake tenure is
 * strategically inert"), so the decay MUST be bit-exact across hardware.
 * Floating-point exp() is not (RFC-0004 §"A reference sketch": "the
 * production code uses a fixed-point decay table — see RFC-0009 for the
 * canonical-numerics discipline"). This module therefore computes decay
 * in PINNED FIXED-POINT INTEGER arithmetic, no float anywhere:
 *
 *   - decay over k bins = r^k, where r = exp(−δ · bin_width) ∈ (0,1) is a
 *     single per-rate ratio stored as a q32 fixed-point integer
 *     (ANTS_REP_FP_ONE = 2^32 represents 1.0);
 *   - r^k is built by repeated q32 multiply (fp_mul), an exact integer
 *     mul-then-shift — identical on every conformant C target;
 *   - age is quantised to whole bins (age_bins = age_s / bin_width); the
 *     reference sketch already evaluates T's decay per bin, and applying
 *     the same quantisation to A keeps ONE deterministic step unit.
 *
 * Scope of THIS module (Component #9):
 *   - the countersigned NCS receipt (RFC-0004 §"The receipt that matters
 *     for tenure"): body + dual Ed25519 signatures, canonical-CBOR body,
 *     verification;
 *   - the deterministic fixed-point decay primitive;
 *   - ants_reputation_compute: A and T from a receipt bag, invalid
 *     receipts skipped (sketch §1398 "if not verify_receipt: continue");
 *   - the saturating T_eff fork-choice transform (§"The saturating
 *     T → T_eff transform");
 *   - ants_reputation_compute_checked: the L1 slash gate (§"How tenure
 *     interacts with Layer 1"), via a caller-supplied slash predicate;
 *   - the receipt-bag Merkle commitment + inclusion proofs for selective
 *     disclosure (§"Selective disclosure of receipts").
 *
 * Deliberately NOT here (later work): the selective-disclosure A ≥ b subset
 * recompute + compact summaries (layered on the Merkle primitives below);
 * and wiring the slash predicate / bond admission into the live L1 G-Set +
 * L2 chain at the real high-stakes-act call sites. (Bond accounting itself
 * is Component #15, economy/bond.)
 *
 * STATUS OF THE NUMERIC CONSTANTS. The decay ratios, κ, and bin width are
 * **DRAFT placeholders, NOT calibrated** — RFC-0004 §835 makes δ and κ
 * b2-class testnet measurements. The fixed-point *recipe* (this file) is
 * the deliverable; the *values* below are illustrative so the code runs
 * and tests, exactly as the embedding component ships all-zero pinned
 * hashes pending the real checkpoint. The recipe should be upstreamed to
 * RFC-0004 (or a reputation-numerics section in RFC-0009 style) and the
 * values fixed by b2 before peers compute interoperable T.
 *
 * No floats, no malloc, no threads, no hidden global state; caller-owned
 * arrays throughout. Spec: RFC-0004 v0.6; RFC-0008 v0.5 §1.1 (canonical
 * CBOR) + §6 (NCS as u64 μ-NCS). Component README:
 * ants-client/reputation/identity/README.md.
 */

#ifndef ANTS_REPUTATION_H
#define ANTS_REPUTATION_H

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

/* A peer is its 32-byte Ed25519 public key (== protocol peer-id). Kept
 * local rather than importing the network/transport type, so the
 * reputation layer takes no dependency on the transport layer for a
 * 32-byte array. MUST equal ANTS_ED25519_PUBKEY_SIZE. */
#define ANTS_REP_PEER_ID_SIZE 32u

/* Receipt nonce: issuer-fresh, anti-replay (RFC-0004 §"The receipt").
 * 16 bytes (128 bits) is collision-free for an honest issuer that never
 * reuses a nonce with the same client. DRAFT — RFC-0008 does not yet pin
 * the receipt nonce width. */
#define ANTS_REP_NONCE_SIZE 16u

/* Ed25519 signature size (mirrors ANTS_ED25519_SIG_SIZE = 64). */
#define ANTS_REP_SIG_SIZE 64u

/* Fixed-point format for the decay arithmetic: q32 (32 fractional bits).
 * A decay factor / ratio in [0.0, 1.0] is stored as a u64 in
 * [0, ANTS_REP_FP_ONE]. q32 gives ~9-10 significant decimal digits, far
 * beyond what any decay schedule needs, and a u64 product of two q32
 * values never overflows before the shift. */
#define ANTS_REP_FP_BITS 32u
#define ANTS_REP_FP_ONE  (((uint64_t)1) << ANTS_REP_FP_BITS) /* 1.0 in q32 */

/* --- DRAFT placeholder parameters (NOT calibrated — see file header) --- */

/* Decay step / tenure bin width, seconds. Decay is evaluated at this
 * granularity. Placeholder: 1 hour. */
#define ANTS_REP_BIN_WIDTH_S 3600u

/* Per-bin decay ratio r = exp(−δ · bin_width), as q32. Placeholders:
 *   A: r = 0.5  → fast (half the weight gone each bin).
 *   T: r = 0.99 → slow (≈ a few-month half-life at a 1h bin).
 * Illustrative only; real δ_A/δ_T are b2-class (RFC-0004 §835). */
#define ANTS_REP_DECAY_RATIO_A_Q32 (((uint64_t)1) << (ANTS_REP_FP_BITS - 1)) /* 0.5 */
#define ANTS_REP_DECAY_RATIO_T_Q32 ((uint64_t)4252017623)                    /* ≈0.99 */

/* Per-bin tenure accrual cap κ · bin_width, in μ-NCS. Placeholder:
 * 1 NCS per bin. The κ rate cap is b2-class (RFC-0004 §835). */
#define ANTS_REP_KAPPA_UNCS_PER_BIN ((uint64_t)1000000)

/* Fork-choice tenure cap T_CAP (RFC-0008 §7 `T_FORK_CHOICE_CAP`), in
 * μ-NCS, used ONLY by the saturating T_eff transform (RFC-0004 §"The
 * saturating T → T_eff transform"). Placeholder: 2000 NCS — the spec's
 * starting point is "~2 years of κ-bound tenure", a b2-class measurement
 * once κ is fixed. DRAFT, NOT calibrated. */
#define ANTS_REP_T_FORK_CHOICE_CAP ((uint64_t)2000000000)

/* exp(−1) in q32 fixed-point = round(0.367879441… · 2^32). The base for
 * the integer part of the T_eff exponential (exp(−n) = exp(−1)^n via the
 * pinned repeated-multiplication decay_factor). PINNED — part of the
 * canonical recipe; every peer uses this exact constant. */
#define ANTS_REP_EXP_NEG1_Q32 ((uint64_t)1580030169)

/* Number of Taylor terms for the fractional part exp(−f), f ∈ [0,1).
 * 16 is overkill-accurate (the q32 truncation floor at ~2e-9 is reached
 * by N≈10); PINNED so the series is bit-identical across peers — the
 * term count is part of the recipe, not a tunable. */
#define ANTS_REP_TAYLOR_TERMS 16u

/* ------------------------------------------------------------------------ */
/* Receipt                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * A counterparty-countersigned NCS receipt (RFC-0004 §"The receipt that
 * matters for tenure"). The server did `ncs_value` μ-NCS of useful work
 * for the client at `timestamp`; both sign. Only receipts with BOTH
 * valid signatures count toward the server's A and T.
 *
 * The signed body is (server, client, ncs_value, timestamp, nonce); the
 * two signatures are over its canonical CBOR encoding (RFC-0008 §1.1).
 */
typedef struct {
    uint8_t server[ANTS_REP_PEER_ID_SIZE]; /* who did the work (accrues A,T) */
    uint8_t client[ANTS_REP_PEER_ID_SIZE]; /* who countersigns              */
    uint64_t ncs_value;                    /* μ-NCS of work (RFC-0008 §6)    */
    uint64_t timestamp_unix_s;             /* unix seconds                  */
    uint8_t nonce[ANTS_REP_NONCE_SIZE];    /* issuer-fresh anti-replay      */
    uint8_t server_sig[ANTS_REP_SIG_SIZE]; /* server over the body          */
    uint8_t client_sig[ANTS_REP_SIG_SIZE]; /* client countersig over body   */
} ants_reputation_receipt_t;

/*
 * Parameters of the (A, T) computation. Carried as an explicit struct so
 * the b2-calibratable values are inputs, not buried constants; the
 * ANTS_REP_* macros above are the DRAFT defaults
 * (ants_reputation_params_default).
 *
 * decay_ratio_*_q32 are per-bin ratios in (0, ANTS_REP_FP_ONE]; a value
 * of 0 would annihilate all history on the first bin and is rejected.
 */
typedef struct {
    uint64_t decay_ratio_a_q32;  /* A: per-bin r_A in q32   */
    uint64_t decay_ratio_t_q32;  /* T: per-bin r_T in q32   */
    uint64_t kappa_uncs_per_bin; /* T: per-bin accrual cap */
    uint64_t bin_width_s;        /* decay/bin granularity  */
} ants_reputation_params_t;

/* ------------------------------------------------------------------------ */
/* Fixed-point decay primitive (deterministic, no float)                    */
/* ------------------------------------------------------------------------ */

/*
 * q32 multiply: (a · b) >> 32, for a, b each in [0, ANTS_REP_FP_ONE].
 * A value >= 1.0 (>= ANTS_REP_FP_ONE) short-circuits (1.0 · x = x), so
 * the actual multiply runs only when both operands are < 1.0 (each
 * <= 2^32 − 1) and the product is therefore < 2^64 — exact, no overflow.
 * Exposed for tests.
 */
uint64_t ants_reputation_fp_mul(uint64_t a_q32, uint64_t b_q32);

/*
 * Decay factor over `age_bins` whole bins: ratio_q32 ^ age_bins, in q32,
 * computed by **repeated multiplication** — fp_mul applied `age_bins`
 * times starting from 1.0. This exact sequence is the pinned canonical
 * recipe: q32 multiply truncates and is therefore NOT associative, so
 * square-and-multiply would yield a different (also-plausible) bit result
 * and break cross-peer agreement. The *method* is part of the recipe,
 * not just the inputs. The loop is bounded by a zero short-circuit: once
 * the factor underflows to 0 it stays 0 (≤ ~2200 iterations for the
 * slowest realistic ratio), so a large age cannot drive unbounded work.
 *
 * age_bins == 0 returns ANTS_REP_FP_ONE (1.0); a ratio >= 1.0 (no decay)
 * returns ANTS_REP_FP_ONE for any age. The factor falls toward 0 as age
 * grows. Exposed for tests.
 *
 * @return the q32 decay factor in [0, ANTS_REP_FP_ONE].
 */
uint64_t ants_reputation_decay_factor(uint64_t ratio_q32, uint64_t age_bins);

/* ------------------------------------------------------------------------ */
/* Receipt body serialisation + verification                                */
/* ------------------------------------------------------------------------ */

/*
 * Worst-case encoded size of a receipt BODY (the signed part, no
 * signatures): a 5-pair canonical CBOR map — two 32-byte keys, two u64s,
 * one 16-byte nonce, plus integer keys and headers. Comfortably < 128.
 */
#define ANTS_REP_RECEIPT_BODY_ENCODED_MAX 128u

/*
 * Encode the receipt BODY (server, client, ncs_value, timestamp, nonce)
 * as canonical CBOR (RFC-0008 §1.1) into `buf` — the exact bytes both
 * signatures are computed over. Definite-length map of 5 integer-keyed
 * pairs in ascending key order:
 *   1: server (bytes 32)  2: client (bytes 32)  3: ncs_value (uint)
 *   4: timestamp (uint)   5: nonce (bytes 16)
 * Float-free by construction.
 *
 * @return ANTS_OK with *out_len set; ANTS_ERROR_INVALID_ARG on NULL;
 *         ANTS_ERROR_BUFFER_TOO_SMALL if cap is insufficient.
 */
ants_error_t ants_reputation_receipt_body_encode(const ants_reputation_receipt_t *r,
                                                 uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len);

/*
 * Verify a receipt: both the server signature and the client
 * countersignature must validate over the canonical body encoding
 * (RFC-0004 §"A receipt without both signatures does not count").
 *
 * @param r        the receipt.
 * @param out_ok   set to true iff both signatures are valid. A bad
 *                 signature is a *false verdict* (*out_ok=false, return
 *                 ANTS_OK), not an error.
 * @return ANTS_OK with *out_ok set; ANTS_ERROR_INVALID_ARG on NULL.
 */
ants_error_t ants_reputation_receipt_verify(const ants_reputation_receipt_t *r, bool *out_ok);

/* ------------------------------------------------------------------------ */
/* The (A, T) computation                                                    */
/* ------------------------------------------------------------------------ */

/*
 * Fill `params` with the DRAFT placeholder defaults (the ANTS_REP_*
 * macros). @return ANTS_OK; ANTS_ERROR_INVALID_ARG if params is NULL.
 */
ants_error_t ants_reputation_params_default(ants_reputation_params_t *params);

/*
 * Compute A and T for `server_id` from a receipt bag at time `now_unix_s`
 * (RFC-0004 §816 / §825 / reference sketch §1392). Both are u64 μ-NCS.
 *
 * For each receipt in `receipts`:
 *   - skipped unless ants_reputation_receipt_verify says both signatures
 *     are valid AND receipt.server == server_id AND timestamp <= now
 *     (a future-dated receipt does not yet contribute);
 *   - A += ncs_value · decay_A(age_bins)      (uncapped, fast decay);
 *   - the receipt's ncs_value is added into its time bin for T.
 * Then T = Σ_bins min(κ·bin_width, bin_total) · decay_T(bin_age_bins).
 *
 * age_bins = (now − timestamp) / bin_width (floor); bin index =
 * timestamp / bin_width; bin_age = now_bin − receipt_bin. Both totals
 * saturate at UINT64_MAX rather than wrapping (a guard; real reputation
 * sits far below that).
 *
 * T's per-bin grouping is done in-place over the input array with NO
 * allocation and no scratch: each bin is processed once, by its
 * first-occurring receipt (a receipt is a bin's representative iff no
 * earlier verified receipt shares its bin). This is O(n²) in the bag
 * size — acceptable for a cold reputation recompute — so n is capped at
 * ANTS_REP_MAX_RECEIPTS to keep the bound sane.
 *
 * @return ANTS_OK with *out_a / *out_t set; ANTS_ERROR_INVALID_ARG on
 *         NULL, a degenerate param (zero bin_width or zero decay ratio),
 *         or n_receipts > ANTS_REP_MAX_RECEIPTS.
 */
#define ANTS_REP_MAX_RECEIPTS 4096u

ants_error_t ants_reputation_compute(const uint8_t server_id[ANTS_REP_PEER_ID_SIZE],
                                     const ants_reputation_receipt_t *receipts,
                                     size_t n_receipts,
                                     uint64_t now_unix_s,
                                     const ants_reputation_params_t *params,
                                     uint64_t *out_a,
                                     uint64_t *out_t);

/* ------------------------------------------------------------------------ */
/* Saturating T_eff fork-choice transform (RFC-0004 §"The saturating       */
/* T → T_eff transform")                                                    */
/* ------------------------------------------------------------------------ */

/*
 * The saturating transform applied to tenure `t` FOR FORK-CHOICE ONLY:
 *
 *   T_eff(t) = t_cap · (1 − exp(−t / t_cap))
 *
 * (RFC-0004 §492). It bounds the *relative* fork-choice weight of an
 * arbitrarily old peer so the founder cohort cannot retain fork-choice
 * dominance indefinitely (long-tail centralisation). Raw `t` — uncapped
 * — still governs verifier eligibility, bond capacity, and persistence;
 * the cap is applied ONLY here, because fork-choice is the only place one
 * peer's weight *relative to another* sets the network's path. The caller
 * sums T_eff over a fork's validators (Σ T_eff) to compare forks.
 *
 * Properties (all verified; all intentional per the RFC):
 *   - linear for t ≪ t_cap: T_eff(t) ≈ t;
 *   - saturating: T_eff(t) → t_cap as t → ∞, never exceeding t_cap;
 *   - monotone non-decreasing and DETERMINISTIC — every honest peer
 *     computes the same T_eff from the same (t, t_cap), so fork choice
 *     does not split on numerics.
 *
 * Determinism is achieved with NO float: exp(−t/t_cap) is computed in
 * pinned q32 fixed-point by range reduction t/t_cap = n + f —
 *   exp(−(n+f)) = exp(−1)^n · exp(−f),
 * the integer power exp(−1)^n via the same repeated-multiplication
 * decay_factor as the decay primitive (base ANTS_REP_EXP_NEG1_Q32), and
 * the fractional exp(−f), f ∈ [0,1), via a pinned ANTS_REP_TAYLOR_TERMS
 * Horner series. The fraction f and the final t_cap·(1−exp) scaling use
 * overflow-safe integer long-division / multiply-shift (no 128-bit type,
 * no float). The exact method is the canonical recipe.
 *
 * @param t       the peer's raw tenure (μ-NCS), as from ants_reputation_compute.
 * @param t_cap   the fork-choice cap (e.g. ANTS_REP_T_FORK_CHOICE_CAP);
 *                must be > 0.
 * @param out     the effective tenure, in [0, t_cap].
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if out is NULL or t_cap == 0.
 */
ants_error_t ants_reputation_t_eff(uint64_t t, uint64_t t_cap, uint64_t *out);

/* ------------------------------------------------------------------------ */
/* L1 slash interaction (RFC-0004 §"How tenure interacts with Layer 1")     */
/* ------------------------------------------------------------------------ */

/*
 * Predicate: is `peer_id` slashed? The negative half of the (A, T) spine.
 * RFC-0004 §597: "T is negatively zeroed by self-authenticating fault — a
 * confirmed fabrication, equivocation, or cache-poisoning proof against an
 * identity zeroes its T. The zero is applied at L1 propagation time,
 * immediately, locally." The reference sketch's `tenure()` opens with
 * `if is_slashed_locally(peer_id): return 0`.
 *
 * This is a CALLBACK, not a hard dependency, on purpose: the slash *source*
 * is context-dependent and the spine must not hard-wire one.
 *   - The canonical binding is `ants_crdt_is_slashed` over the local L1
 *     G-Set (reputation/crdt, Component #7) — the live, immediate check.
 *   - A late joiner that has not yet synced the relevant proof instead
 *     consults the L2 chain's slashed-identity index and DEFAULTS TO
 *     SLASHED when it cannot retrieve the underlying proof (RFC-0004
 *     §"Late-joiner protocol", the safe direction of error) — a different
 *     binding of the same predicate.
 * Keeping the reputation library free of an `ants_crdt` link also avoids a
 * layering edge: the L1 set, the L2 chain, and any future source all plug
 * into the same seam.
 *
 * @param peer_id   the 32-byte peer-id being scored (== receipt.server).
 * @param ctx       caller cookie (e.g. the ants_crdt_t* G-Set handle).
 * @return true iff a valid fault proof against peer_id is known.
 */
typedef bool (*ants_reputation_is_slashed_fn)(const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                              void *ctx);

/*
 * Compute A and T for `server_id` WITH the L1 slash gate applied first.
 *
 * If `is_slashed` is non-NULL and `is_slashed(server_id, slash_ctx)` returns
 * true, the peer is slashed: BOTH `*out_a` and `*out_t` are set to 0 and the
 * function returns ANTS_OK without inspecting the receipt bag. A slashed
 * identity is "globally dead, permanently" (RFC-0004 §110) — the slash event
 * destroys the whole of its reputation, A as well as T (§"Release and
 * slash"), so a slashed peer has zero standing of any kind, not merely zero
 * tenure. Zeroing is the safe direction of error: a peer wrongly treated as
 * slashed loses serving priority and eligibility but cannot be exploited.
 *
 * If `is_slashed` is NULL, or returns false, this is exactly
 * ants_reputation_compute (same arguments, same result) — the slash gate is
 * the only thing added. The receipt-bag computation, decay recipe, κ-clip,
 * and skip rules are unchanged.
 *
 * @param is_slashed  the L1 slash predicate, or NULL to skip the gate.
 * @param slash_ctx   opaque cookie passed to is_slashed (may be NULL).
 * @return ANTS_OK with *out_a / *out_t set (0/0 if slashed). server_id,
 *         out_a, and out_t are NULL-checked before the slash gate, so a NULL
 *         among them is INVALID_ARG regardless of slash status. On the
 *         non-slashed path the call delegates to ants_reputation_compute and
 *         returns exactly its codes (INVALID_ARG on NULL params, a
 *         degenerate param, or n_receipts > ANTS_REP_MAX_RECEIPTS). A
 *         slashed peer short-circuits to 0/0 without inspecting params or the
 *         receipt bag — the peer is dead, so the bag is never read (matching
 *         the reference sketch's early `return 0`).
 */
ants_error_t ants_reputation_compute_checked(const uint8_t server_id[ANTS_REP_PEER_ID_SIZE],
                                             const ants_reputation_receipt_t *receipts,
                                             size_t n_receipts,
                                             uint64_t now_unix_s,
                                             const ants_reputation_params_t *params,
                                             ants_reputation_is_slashed_fn is_slashed,
                                             void *slash_ctx,
                                             uint64_t *out_a,
                                             uint64_t *out_t);

/* ------------------------------------------------------------------------ */
/* Selective disclosure: the receipt-bag Merkle tree (RFC-0004              */
/* §"Selective disclosure of receipts")                                     */
/* ------------------------------------------------------------------------ */

/*
 * A peer commits its receipt bag as a Merkle tree over the individual
 * receipt leaves and publishes a single root, `bag_root`, when it
 * participates in a high-stakes act. It can then prove "receipt R is in my
 * committed bag" by revealing R plus an O(log n) inclusion path, WITHOUT
 * revealing the rest of its interaction history (RFC-0004 §"Selective
 * disclosure"; the ledger-is-private property of RFC-0001). Proving the
 * actual bound A ≥ b over a revealed subset is the verifier's recompute
 * step, layered on top of these primitives (a later PR).
 *
 * The tree is the SAME domain-separated, promote-lone-trailing BLAKE3
 * construction as reputation/chain's confirmed_proofs root and
 * inference/orchestration's commit Merkle — one canonical scheme across the
 * codebase — with two receipt-specific points:
 *
 *   leaf(R)   = BLAKE3(0x00 ‖ body(R) ‖ server_sig(R) ‖ client_sig(R))
 *   node(L,R) = BLAKE3(0x01 ‖ L ‖ R)        empty-bag root = BLAKE3(0x02)
 *
 * where body(R) is the canonical-CBOR receipt body
 * (ants_reputation_receipt_body_encode). The leaf commits the WHOLE receipt
 * — body AND both signatures — so one leaf hash anchors both the inclusion
 * proof and the countersignature-integrity check to the same bytes.
 *
 * Canonical leaf order is (timestamp_unix_s ASC, then leaf-hash ASC): a
 * total, deterministic order, so every honest peer builds the identical
 * tree from the same bag (determinism is load-bearing, as for A/T). The
 * caller passes receipts already in this order; out-of-order or duplicate
 * receipts are rejected ANTS_ERROR_NON_CANONICAL (the same contract as
 * reputation/chain's strictly-ascending content-ids).
 *
 * The published commitment binds the tree to the peer:
 *   bag_root = BLAKE3.derive_key(ANTS_REP_BAG_ROOT_CONTEXT,
 *                                peer_id ‖ merkle_root)
 * so a subtree cannot be replayed as another identity's bag.
 *
 * DRAFT scheme pending RFC-0008 formalisation (alongside the receipt body
 * and the L1 proof formats). Pure, deterministic, no float, no malloc.
 */

/* BLAKE3 digest size for the bag tree and bag_root. MUST equal
 * ANTS_BLAKE3_HASH_SIZE; kept local so this header takes no crypto-header
 * dependency (mirrors reputation/chain's ANTS_CHAIN_HASH_SIZE). */
#define ANTS_REP_HASH_SIZE 32u

/* Max depth of the receipt-bag tree (promote-lone-trailing over up to
 * 2^DEPTH leaves). 32 matches reputation/chain; the bounded MMR peak stack
 * is [DEPTH+2][HASH] (~1 KB), no allocation. The bag is itself capped at
 * ANTS_REP_MAX_RECEIPTS leaves. */
#define ANTS_REP_BAG_MERKLE_MAX_DEPTH 32u

/* derive_key context binding the bag's Merkle root to the peer-id (RFC-0004
 * §"Selective disclosure"; RFC-0008 §4.1 reserves this string). DRAFT. */
#define ANTS_REP_BAG_ROOT_CONTEXT "ants-v1-receipt-bag-root"

/*
 * Compute `bag_root` over a receipt bag for `peer_id` at commit time.
 *
 * `receipts` MUST be in canonical order (timestamp ASC, then leaf-hash ASC);
 * otherwise ANTS_ERROR_NON_CANONICAL. n == 0 is the empty bag (merkle_root =
 * BLAKE3(0x02)). n is capped at ANTS_REP_MAX_RECEIPTS.
 *
 * @return ANTS_OK with *out_root set; ANTS_ERROR_INVALID_ARG on NULL
 *         out_root/peer_id (or NULL receipts with n != 0) or n over the cap;
 *         ANTS_ERROR_NON_CANONICAL if the bag is not in canonical order.
 */
ants_error_t ants_reputation_bag_root(const ants_reputation_receipt_t *receipts,
                                      size_t n,
                                      const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                      uint8_t out_root[ANTS_REP_HASH_SIZE]);

/*
 * Produce the Merkle inclusion path for the receipt at canonical position
 * `index` in an n-receipt bag. The path is `*out_path_len` bytes — a whole
 * number of ANTS_REP_HASH_SIZE-byte sibling hashes, bottom-up. `receipts`
 * MUST be in canonical order (validated; NON_CANONICAL otherwise) so `index`
 * names the same leaf the verifier will.
 *
 * If `path_cap` is too small, sets *out_path_len to the required size and
 * returns ANTS_ERROR_BUFFER_TOO_SMALL (call again with a large-enough
 * buffer). A bag of n leaves needs at most ceil(log2 n) hashes.
 *
 * @return ANTS_OK with the path written and *out_path_len set;
 *         ANTS_ERROR_INVALID_ARG on NULL, index >= n, n == 0, or n over the
 *         cap; ANTS_ERROR_NON_CANONICAL if out of order;
 *         ANTS_ERROR_BUFFER_TOO_SMALL if path_cap is insufficient.
 */
ants_error_t ants_reputation_bag_prove(const ants_reputation_receipt_t *receipts,
                                       size_t n,
                                       size_t index,
                                       uint8_t *out_path,
                                       size_t path_cap,
                                       size_t *out_path_len);

/*
 * Verify that `receipt` is the leaf at canonical position `index` of an
 * n-leaf bag committed as `bag_root` for `peer_id`, given the inclusion
 * `path` from ants_reputation_bag_prove.
 *
 * This is the STRUCTURAL check only: it recomputes the leaf hash from the
 * receipt bytes, replays the promote-lone-trailing path to the Merkle root,
 * binds it to peer_id via the bag_root derive_key, and compares. It does
 * NOT verify the receipt's countersignatures — a complete acceptance also
 * requires ants_reputation_receipt_verify (both checks bind to the same
 * leaf bytes, RFC-0004 §"Selective disclosure" step 3). Keeping them
 * separate lets the Merkle logic be tested in isolation and lets the
 * verifier order the checks as it likes.
 *
 * @param out_ok  set true iff the inclusion proof is valid against bag_root.
 *                An invalid proof is a *false verdict* (*out_ok = false,
 *                return ANTS_OK), not an error.
 * @return ANTS_OK with *out_ok set; ANTS_ERROR_INVALID_ARG on NULL,
 *         index >= n, n == 0, n over the cap, or a path_len inconsistent
 *         with (index, n).
 */
ants_error_t ants_reputation_bag_verify_inclusion(const ants_reputation_receipt_t *receipt,
                                                  size_t index,
                                                  size_t n,
                                                  const uint8_t *path,
                                                  size_t path_len,
                                                  const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                                  const uint8_t bag_root[ANTS_REP_HASH_SIZE],
                                                  bool *out_ok);

/*
 * One opening in an A >= b proof: a revealed receipt together with its Merkle
 * inclusion proof (the `path` + `index` from ants_reputation_bag_prove)
 * against the peer's committed `bag_root`. `path` points into caller-owned
 * memory that must outlive the verify call.
 */
typedef struct {
    ants_reputation_receipt_t receipt; /* the revealed receipt              */
    size_t index;                      /* its canonical leaf position       */
    const uint8_t *path;               /* inclusion path (bag_prove output) */
    size_t path_len;                   /* path length in bytes              */
} ants_reputation_bag_opening_t;

/*
 * Prover side: choose a subset of the bag whose summed `A` contribution
 * reaches the bound `b`, preferring MOST RECENT receipts first (they have
 * decayed least, so the bound is reached revealing the fewest receipts —
 * minimal information disclosed, RFC-0004 §"Selective disclosure" step 1).
 * Only receipts that count toward A are eligible: both signatures valid,
 * server == peer_id, timestamp <= now. `receipts` MUST be in canonical order
 * (the indices returned are canonical leaf positions for
 * ants_reputation_bag_prove).
 *
 * Writes the chosen canonical indices (most-recent-first) to `out_indices`
 * and sets *out_count. *out_reached is true iff the running sum reached `b`
 * (false means the peer's revealable A is below `b`). `b == 0` is reached
 * immediately with the empty subset.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL, n == 0 / over the cap, or a
 *         degenerate param; ANTS_ERROR_NON_CANONICAL if the bag is not in
 *         canonical order; ANTS_ERROR_BUFFER_TOO_SMALL if more than
 *         `indices_cap` indices are needed to reach `b` (retry with
 *         indices_cap >= n).
 */
ants_error_t ants_reputation_bag_select_for_bound(const ants_reputation_receipt_t *receipts,
                                                  size_t n,
                                                  const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                                  uint64_t now_unix_s,
                                                  const ants_reputation_params_t *params,
                                                  uint64_t b,
                                                  size_t *out_indices,
                                                  size_t indices_cap,
                                                  size_t *out_count,
                                                  bool *out_reached);

/*
 * Verifier side: confirm a peer's A >= b from a set of revealed openings
 * against its committed `bag_root` (RFC-0004 §"Selective disclosure" step 3).
 * Accepts (*out_ok = true) iff EVERY opening
 *   - is a receipt with both signatures valid (countersignature integrity),
 *   - credits this peer (receipt.server == peer_id),
 *   - is not future-dated (timestamp <= now),
 *   - sits at a DISTINCT canonical index (no double-counting), and
 *   - has a valid Merkle inclusion proof against bag_root;
 * AND the sum of the openings' `A` contributions (the same decayed-value
 * recipe as ants_reputation_compute's A) is >= b.
 *
 * This is a LOWER BOUND on the peer's true A (a revealed subset understates,
 * never overstates — RFC-0004 §"Why this is sound"): a peer cannot inflate A
 * because every receipt is countersignature-checked and bound to the
 * committed tree. Any failed opening, or a sum below `b`, is a *false
 * verdict* (*out_ok = false, return ANTS_OK), not an error — the openings are
 * untrusted input. Does NOT itself bound `n` against the true bag size; it
 * verifies each opening against the (peer_id, bag_root, n) the caller states.
 *
 * @return ANTS_OK with *out_ok set; ANTS_ERROR_INVALID_ARG on NULL args
 *         (openings with k != 0, peer_id, bag_root, params, out_ok), a
 *         degenerate param, or k / n over ANTS_REP_MAX_RECEIPTS.
 */
ants_error_t ants_reputation_bag_verify_bound(const ants_reputation_bag_opening_t *openings,
                                              size_t k,
                                              size_t n,
                                              const uint8_t peer_id[ANTS_REP_PEER_ID_SIZE],
                                              const uint8_t bag_root[ANTS_REP_HASH_SIZE],
                                              uint64_t now_unix_s,
                                              const ants_reputation_params_t *params,
                                              uint64_t b,
                                              bool *out_ok);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_REPUTATION_H */
