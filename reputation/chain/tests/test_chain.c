/*
 * test_chain.c — Tests for Layer 2, the PoUH chain as ordered witness
 * (Component #8), now feature-complete at v0.x.
 *
 * The suite covers every entry point and, where a value is computable, checks
 * it against an INDEPENDENT reference rather than mirroring the impl: the
 * confirmed_proofs Merkle root vs leaf/node hashes recomputed by hand with
 * raw BLAKE3 (n = 0..4, incl. the promote-lone-trailing case) + a
 * prove/verify round-trip with a single-byte tamper sweep; the EpochSummary
 * and Block codecs as canonical round-trips (cross-checked with
 * ants_cbor_is_canonical) plus a strict-decode battery (truncation, trailing
 * byte, wrong map size, unknown / out-of-range severity); the pattern
 * engine's severity bands against the documented thresholds; committee
 * selection's structural properties (distinct, in-range, sorted,
 * deterministic, seed-sensitive, k==N full set); 2/3 finality with REAL
 * Ed25519 keypairs at the threshold boundary; and the Σ T_eff fork choice
 * (cross-checked against ants_reputation_t_eff) + the social-Schelling
 * fallback, incl. the overflow-safe θ threshold near UINT64_MAX. The protocol
 * constant invariants are asserted too.
 */

#include "ants_cbor.h"
#include "ants_chain.h"
#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_reputation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
                    "FAIL %s:%d  expected %d, got %d\n",                                           \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    (int)_e,                                                                       \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

/* ---- independent BLAKE3 reference (NOT the impl's helpers) -------------- */

static void ref_leaf(const uint8_t id[32], uint8_t out[32])
{
    const uint8_t prefix = 0x00u;
    ants_blake3_ctx_t h;
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, id, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

static void ref_node(const uint8_t l[32], const uint8_t r[32], uint8_t out[32])
{
    const uint8_t prefix = 0x01u;
    ants_blake3_ctx_t h;
    CHECK_EQ(ants_blake3_init(&h), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, &prefix, 1), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, l, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&h, r, 32), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&h, out), ANTS_OK);
}

/* Strictly-ascending content-ids (distinct first byte). */
static void build_ascending_ids(uint8_t ids[][32], size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        memset(ids[i], 0, 32);
        ids[i][0] = (uint8_t)(i + 1);
    }
}

/* ---- constant invariants ------------------------------------------------ */

static void test_constants(void)
{
    CHECK(ANTS_CHAIN_SEVERITY_SOFT < ANTS_CHAIN_SEVERITY_MEDIUM);
    CHECK(ANTS_CHAIN_SEVERITY_MEDIUM < ANTS_CHAIN_SEVERITY_HARD);
    CHECK(ANTS_CHAIN_SEVERITY_HARD < ANTS_CHAIN_SEVERITY_TERMINAL);
    CHECK(ANTS_CHAIN_SEVERITY_TERMINAL < ANTS_CHAIN_SEVERITY__RESERVED_MIN);
    CHECK(ANTS_CHAIN_BLS_TRANSITION_K < ANTS_CHAIN_COMMITTEE_K_MAX);
    CHECK(ANTS_CHAIN_COMMITTEE_K_MAX == 64u);
    CHECK(ANTS_CHAIN_FINALITY_NUM < ANTS_CHAIN_FINALITY_DEN);
    CHECK(ANTS_CHAIN_FINALITY_NUM > 0u);
    CHECK(ANTS_CHAIN_FORK_THETA_NUM < ANTS_CHAIN_FORK_THETA_DEN);
    CHECK(ANTS_CHAIN_FORK_THETA_NUM > 0u);
    CHECK(ANTS_CHAIN_PEER_ID_SIZE == 32u);
    CHECK(ANTS_CHAIN_SIG_SIZE == 64u);
    CHECK(ANTS_CHAIN_HASH_SIZE == 32u);
    CHECK(ANTS_CHAIN_BLS_PUBKEY_SIZE == 48u);
    CHECK(ANTS_CHAIN_BLS_SIG_SIZE == 96u);
    CHECK(ANTS_CHAIN_FINALITY_TIMEOUT_S > ANTS_CHAIN_BLOCK_TIME_S);
    CHECK(ANTS_CHAIN_FORK_A != ANTS_CHAIN_FORK_B);
    CHECK(ANTS_CHAIN_FORK_A != ANTS_CHAIN_FORK_SOCIAL_SCHELLING);
    CHECK(ANTS_CHAIN_FORK_B != ANTS_CHAIN_FORK_SOCIAL_SCHELLING);
}

/* ---- confirmed_proofs Merkle root vs hand-built reference --------------- */

static void test_confirmed_root_reference(void)
{
    uint8_t ids[4][32];
    uint8_t got[32];
    uint8_t want[32];
    uint8_t l[4][32];
    uint8_t n01[32], n23[32];
    int i;

    build_ascending_ids(ids, 4);
    for (i = 0; i < 4; i++) {
        ref_leaf(ids[i], l[i]);
    }

    /* n == 0 → the empty root BLAKE3(0x02). */
    {
        const uint8_t empty_prefix = 0x02u;
        CHECK_EQ(ants_blake3_hash(&empty_prefix, 1, want), ANTS_OK);
        CHECK_EQ(ants_chain_confirmed_root(NULL, 0, got), ANTS_OK);
        CHECK(memcmp(got, want, 32) == 0);
    }

    /* n == 1 → leaf(id0). */
    CHECK_EQ(ants_chain_confirmed_root(ids, 1, got), ANTS_OK);
    CHECK(memcmp(got, l[0], 32) == 0);

    /* n == 2 → node(leaf0, leaf1). */
    ref_node(l[0], l[1], want);
    CHECK_EQ(ants_chain_confirmed_root(ids, 2, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 3 → node(node(leaf0,leaf1), leaf2) — lone trailing leaf promoted. */
    ref_node(l[0], l[1], n01);
    ref_node(n01, l[2], want);
    CHECK_EQ(ants_chain_confirmed_root(ids, 3, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);

    /* n == 4 → node(node(leaf0,leaf1), node(leaf2,leaf3)). */
    ref_node(l[0], l[1], n01);
    ref_node(l[2], l[3], n23);
    ref_node(n01, n23, want);
    CHECK_EQ(ants_chain_confirmed_root(ids, 4, got), ANTS_OK);
    CHECK(memcmp(got, want, 32) == 0);
}

static void test_confirmed_root_args(void)
{
    uint8_t ids[3][32];
    uint8_t root[32];

    build_ascending_ids(ids, 3);

    /* NULL out_root, or NULL ids with n != 0. */
    CHECK_EQ(ants_chain_confirmed_root(ids, 3, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_confirmed_root(NULL, 3, root), ANTS_ERROR_INVALID_ARG);

    /* Non-ascending (swap two) → NON_CANONICAL. */
    {
        uint8_t tmp[32];
        memcpy(tmp, ids[0], 32);
        memcpy(ids[0], ids[2], 32);
        memcpy(ids[2], tmp, 32);
        CHECK_EQ(ants_chain_confirmed_root(ids, 3, root), ANTS_ERROR_NON_CANONICAL);
    }

    /* Equal adjacent ids (not strictly ascending) → NON_CANONICAL. */
    build_ascending_ids(ids, 3);
    memcpy(ids[1], ids[0], 32);
    CHECK_EQ(ants_chain_confirmed_root(ids, 3, root), ANTS_ERROR_NON_CANONICAL);
}

/* ---- confirmed_proofs inclusion proof round-trip + tamper --------------- */

static void test_confirmed_prove_verify(void)
{
    static const size_t sizes[] = {1, 2, 3, 4, 5, 8};
    size_t si;

    for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        uint8_t ids[8][32];
        uint8_t root[32];
        size_t idx;

        build_ascending_ids(ids, n);
        CHECK_EQ(ants_chain_confirmed_root(ids, n, root), ANTS_OK);

        for (idx = 0; idx < n; idx++) {
            uint8_t path[ANTS_CHAIN_MERKLE_MAX_DEPTH * 32];
            size_t path_len = 0;
            bool ok = false;

            CHECK_EQ(ants_chain_confirmed_prove(ids, n, idx, path, sizeof path, &path_len),
                     ANTS_OK);
            CHECK_EQ(ants_chain_confirmed_verify(ids[idx], idx, n, path, path_len, root, &ok),
                     ANTS_OK);
            CHECK(ok);

            /* Tamper the leaf → false. */
            {
                uint8_t bad[32];
                memcpy(bad, ids[idx], 32);
                bad[0] ^= 0xFFu;
                ok = true;
                CHECK_EQ(ants_chain_confirmed_verify(bad, idx, n, path, path_len, root, &ok),
                         ANTS_OK);
                CHECK(!ok);
            }
            /* Tamper the root → false. */
            {
                uint8_t bad_root[32];
                memcpy(bad_root, root, 32);
                bad_root[0] ^= 0xFFu;
                ok = true;
                CHECK_EQ(
                    ants_chain_confirmed_verify(ids[idx], idx, n, path, path_len, bad_root, &ok),
                    ANTS_OK);
                CHECK(!ok);
            }
            /* Tamper a path byte (when there is one) → false. */
            if (path_len > 0) {
                uint8_t bad_path[ANTS_CHAIN_MERKLE_MAX_DEPTH * 32];
                memcpy(bad_path, path, path_len);
                bad_path[0] ^= 0xFFu;
                ok = true;
                CHECK_EQ(
                    ants_chain_confirmed_verify(ids[idx], idx, n, bad_path, path_len, root, &ok),
                    ANTS_OK);
                CHECK(!ok);
            }
        }
    }
}

static void test_confirmed_prove_args(void)
{
    uint8_t ids[4][32];
    uint8_t path[4 * 32];
    size_t path_len = 0;
    bool ok = false;

    build_ascending_ids(ids, 4);

    /* index out of range. */
    CHECK_EQ(ants_chain_confirmed_prove(ids, 4, 4, path, sizeof path, &path_len),
             ANTS_ERROR_INVALID_ARG);
    /* BUFFER_TOO_SMALL with the needed length reported. */
    CHECK_EQ(ants_chain_confirmed_prove(ids, 4, 0, path, 0, &path_len),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(path_len == 2u * 32u); /* depth-2 perfect tree: 2 siblings */

    /* verify rejects a path_len that is not a whole number of siblings. */
    CHECK_EQ(ants_chain_confirmed_prove(ids, 4, 0, path, sizeof path, &path_len), ANTS_OK);
    CHECK_EQ(ants_chain_confirmed_verify(ids[0], 0, 4, path, path_len - 1, ids[0], &ok),
             ANTS_ERROR_INVALID_ARG);
}

/* ---- EpochSummary codec ------------------------------------------------- */

static void fill_summary(ants_chain_epoch_summary_t *s, ants_chain_pattern_finding_t *f, size_t nf)
{
    size_t i;
    memset(s, 0, sizeof *s);
    s->epoch = 42;
    s->cutoff_time = 1700000000ull;
    for (i = 0; i < 32; i++) {
        s->confirmed_proofs[i] = (uint8_t)(i * 7 + 1);
    }
    for (i = 0; i < nf; i++) {
        memset(&f[i], 0, sizeof f[i]);
        f[i].subject[0] = (uint8_t)(i + 10);
        f[i].rule_id = i + 1;
        f[i].window_s = 2592000ull; /* 30 days */
        f[i].count = i + 3;
        f[i].severity = ANTS_CHAIN_SEVERITY_SOFT + (uint32_t)(i % 4);
    }
    s->findings = nf > 0 ? f : NULL;
    s->n_findings = nf;
}

static void check_roundtrip(size_t nf)
{
    ants_chain_epoch_summary_t in;
    ants_chain_pattern_finding_t fin[6];
    ants_chain_pattern_finding_t fout[6];
    ants_chain_epoch_summary_t out;
    uint8_t buf[1024];
    size_t len = 0;
    size_t out_n = 0;
    size_t i;

    fill_summary(&in, fin, nf);
    CHECK(ants_chain_epoch_summary_bound(&in) <= sizeof buf);
    CHECK_EQ(ants_chain_epoch_summary_encode(&in, buf, sizeof buf, &len), ANTS_OK);
    CHECK(len > 0);
    CHECK_EQ(ants_cbor_is_canonical(buf, len), ANTS_OK);

    CHECK_EQ(ants_chain_epoch_summary_decode(buf, len, &out, fout, 6, &out_n), ANTS_OK);
    CHECK(out.epoch == in.epoch);
    CHECK(out.cutoff_time == in.cutoff_time);
    CHECK(memcmp(out.confirmed_proofs, in.confirmed_proofs, 32) == 0);
    CHECK(out_n == nf);
    CHECK(out.n_findings == nf);
    for (i = 0; i < nf; i++) {
        CHECK(memcmp(fout[i].subject, fin[i].subject, 32) == 0);
        CHECK(fout[i].rule_id == fin[i].rule_id);
        CHECK(fout[i].window_s == fin[i].window_s);
        CHECK(fout[i].count == fin[i].count);
        CHECK(fout[i].severity == fin[i].severity);
    }
}

static void test_epoch_summary_roundtrip(void)
{
    check_roundtrip(0);
    check_roundtrip(1);
    check_roundtrip(3);
    check_roundtrip(6);
}

static void test_epoch_summary_probe_and_strict(void)
{
    ants_chain_epoch_summary_t in;
    ants_chain_pattern_finding_t fin[3];
    ants_chain_epoch_summary_t out;
    ants_chain_pattern_finding_t fout[3];
    uint8_t buf[512];
    size_t len = 0;
    size_t out_n = 0;
    size_t k;

    fill_summary(&in, fin, 3);
    CHECK_EQ(ants_chain_epoch_summary_encode(&in, buf, sizeof buf, &len), ANTS_OK);

    /* Probe: findings_cap == 0 reports the count via BUFFER_TOO_SMALL. */
    CHECK_EQ(ants_chain_epoch_summary_decode(buf, len, &out, NULL, 0, &out_n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 3);

    /* Truncation at every interior prefix → MALFORMED (never a false OK). */
    for (k = 1; k < len; k++) {
        ants_error_t rc = ants_chain_epoch_summary_decode(buf, k, &out, fout, 3, &out_n);
        CHECK(rc != ANTS_OK);
    }

    /* Trailing byte → MALFORMED. */
    {
        uint8_t buf2[513];
        memcpy(buf2, buf, len);
        buf2[len] = 0x00;
        CHECK_EQ(ants_chain_epoch_summary_decode(buf2, len + 1, &out, fout, 3, &out_n),
                 ANTS_ERROR_MALFORMED);
    }

    /* Wrong outer map size: 0xA4 (map of 4) → 0xA3 (map of 3). */
    {
        uint8_t buf3[512];
        memcpy(buf3, buf, len);
        CHECK(buf3[0] == 0xA4u);
        buf3[0] = 0xA3u;
        CHECK_EQ(ants_chain_epoch_summary_decode(buf3, len, &out, fout, 3, &out_n),
                 ANTS_ERROR_MALFORMED);
    }

    /* Unknown severity: the last byte is the final finding's severity value
     * (key 5 then value); patch a valid level to RESERVED_MIN. */
    {
        uint8_t buf4[512];
        memcpy(buf4, buf, len);
        CHECK(buf4[len - 1] < ANTS_CHAIN_SEVERITY__RESERVED_MIN);
        buf4[len - 1] = (uint8_t)ANTS_CHAIN_SEVERITY__RESERVED_MIN;
        CHECK_EQ(ants_chain_epoch_summary_decode(buf4, len, &out, fout, 3, &out_n),
                 ANTS_ERROR_UNSUPPORTED_TYPE);
    }
}

static void test_epoch_summary_encode_args(void)
{
    ants_chain_epoch_summary_t s;
    ants_chain_pattern_finding_t f[1];
    uint8_t buf[256];
    size_t len = 0;

    fill_summary(&s, f, 1);

    CHECK_EQ(ants_chain_epoch_summary_encode(NULL, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_epoch_summary_encode(&s, NULL, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);

    /* Out-of-range severity → INVALID_ARG. */
    f[0].severity = ANTS_CHAIN_SEVERITY__RESERVED_MIN;
    CHECK_EQ(ants_chain_epoch_summary_encode(&s, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    f[0].severity = 0;
    CHECK_EQ(ants_chain_epoch_summary_encode(&s, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);

    /* BUFFER_TOO_SMALL when cap is short. */
    f[0].severity = ANTS_CHAIN_SEVERITY_SOFT;
    CHECK_EQ(ants_chain_epoch_summary_encode(&s, buf, 4, &len), ANTS_ERROR_BUFFER_TOO_SMALL);
}

/* ---- pattern-rule engine ------------------------------------------------ */

/* One subject with `cnt` in-window events lands in `expect_sev`. */
static void check_band(uint64_t cnt, uint32_t expect_sev)
{
    uint64_t now = 100000000ull;
    ants_chain_event_t ev[16];
    ants_chain_pattern_finding_t out[4];
    size_t out_n = 0;
    uint64_t i;

    for (i = 0; i < cnt; i++) {
        memset(&ev[i], 0, sizeof ev[i]);
        ev[i].subject[0] = 7;
        ev[i].timestamp = now - (i + 1) * 10;
    }
    CHECK_EQ(ants_chain_pattern_scan(ev, (size_t)cnt, now, out, 4, &out_n), ANTS_OK);
    CHECK(out_n == 1);
    CHECK(out[0].count == cnt);
    CHECK(out[0].severity == expect_sev);
    CHECK(out[0].rule_id == ANTS_CHAIN_RULE_FAULT_COUNT_30D);
    CHECK(out[0].window_s == ANTS_CHAIN_PATTERN_WINDOW_S);
    CHECK(out[0].subject[0] == 7);
}

static void test_pattern_scan(void)
{
    uint64_t now = 100000000ull;
    ants_chain_event_t ev[16];
    ants_chain_pattern_finding_t out[8];
    size_t out_n = 0;
    size_t k = 0;
    size_t i;

    /* Severity bands by in-window event count (independent of the impl:
     * the expected band follows the documented thresholds). */
    check_band(1, ANTS_CHAIN_SEVERITY_SOFT);
    check_band(2, ANTS_CHAIN_SEVERITY_SOFT);
    check_band(3, ANTS_CHAIN_SEVERITY_MEDIUM);
    check_band(5, ANTS_CHAIN_SEVERITY_MEDIUM);
    check_band(6, ANTS_CHAIN_SEVERITY_HARD);
    check_band(10, ANTS_CHAIN_SEVERITY_HARD);

    /* Empty input → no findings. */
    CHECK_EQ(ants_chain_pattern_scan(NULL, 0, now, out, 8, &out_n), ANTS_OK);
    CHECK(out_n == 0);

    /* Windowing: subject A has 1 in-window, 1 at the exact boundary
     * (excluded: now - ts == WINDOW is not < WINDOW), 1 in the future
     * (excluded); subject B has 6 in-window. Two findings, sorted
     * subject-ascending (A's first byte 1 before B's 2). */
    memset(ev, 0, sizeof ev);
    ev[k].subject[0] = 1;
    ev[k].timestamp = now - 1000;
    k++;
    ev[k].subject[0] = 1;
    ev[k].timestamp = now - ANTS_CHAIN_PATTERN_WINDOW_S;
    k++;
    ev[k].subject[0] = 1;
    ev[k].timestamp = now + 5000;
    k++;
    for (i = 0; i < 6; i++) {
        ev[k].subject[0] = 2;
        ev[k].timestamp = now - (i + 1) * 100;
        k++;
    }

    CHECK_EQ(ants_chain_pattern_scan(ev, k, now, out, 8, &out_n), ANTS_OK);
    CHECK(out_n == 2);
    CHECK(out[0].subject[0] == 1);
    CHECK(out[0].count == 1);
    CHECK(out[0].severity == ANTS_CHAIN_SEVERITY_SOFT);
    CHECK(out[1].subject[0] == 2);
    CHECK(out[1].count == 6);
    CHECK(out[1].severity == ANTS_CHAIN_SEVERITY_HARD);

    /* Determinism + order-independence: reverse the event list, identical
     * findings. Compare FIELD BY FIELD (never memcmp the struct — its
     * trailing padding after `severity` is not zero-initialised). */
    {
        ants_chain_event_t rev[16];
        ants_chain_pattern_finding_t out2[8];
        size_t out_n2 = 0;
        for (i = 0; i < k; i++) {
            rev[i] = ev[k - 1 - i];
        }
        CHECK_EQ(ants_chain_pattern_scan(rev, k, now, out2, 8, &out_n2), ANTS_OK);
        CHECK(out_n2 == out_n);
        for (i = 0; i < out_n; i++) {
            CHECK(memcmp(out[i].subject, out2[i].subject, 32) == 0);
            CHECK(out[i].count == out2[i].count);
            CHECK(out[i].severity == out2[i].severity);
            CHECK(out[i].rule_id == out2[i].rule_id);
            CHECK(out[i].window_s == out2[i].window_s);
        }
    }

    /* BUFFER_TOO_SMALL reports the full count. */
    CHECK_EQ(ants_chain_pattern_scan(ev, k, now, out, 0, &out_n), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 2);
    CHECK_EQ(ants_chain_pattern_scan(ev, k, now, out, 1, &out_n), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 2);

    /* NULL args. */
    CHECK_EQ(ants_chain_pattern_scan(ev, k, now, out, 8, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_pattern_scan(NULL, 2, now, out, 8, &out_n), ANTS_ERROR_INVALID_ARG);
}

/* ---- VRF committee selection -------------------------------------------- */

static void test_committee_select(void)
{
    uint8_t prev[32];
    uint8_t beacon[32];
    uint8_t beacon2[32];
    size_t idx[64];
    size_t idx2[64];
    size_t out_n = 0;
    size_t out_n2 = 0;
    size_t i;

    memset(prev, 0xAB, 32);
    memset(beacon, 0x11, 32);
    memset(beacon2, 0x22, 32);

    /* k of N: k distinct indices in [0,N), strictly ascending. */
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 16, idx, 64, &out_n), ANTS_OK);
    CHECK(out_n == 16);
    for (i = 0; i < out_n; i++) {
        CHECK(idx[i] < 100);
        if (i > 0) {
            CHECK(idx[i - 1] < idx[i]); /* strictly ascending ⇒ distinct */
        }
    }

    /* Deterministic: same inputs → identical committee. */
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 16, idx2, 64, &out_n2), ANTS_OK);
    CHECK(out_n2 == 16);
    for (i = 0; i < 16; i++) {
        CHECK(idx[i] == idx2[i]);
    }

    /* Different beacon → different committee (overwhelmingly likely; idx
     * still holds the first beacon's committee here). */
    CHECK_EQ(ants_chain_committee_select(prev, beacon2, 100, 16, idx2, 64, &out_n2), ANTS_OK);
    {
        bool same = (out_n2 == 16);
        for (i = 0; same && i < 16; i++) {
            if (idx[i] != idx2[i]) {
                same = false;
            }
        }
        CHECK(!same);
    }

    /* k == N → the full set 0..N-1. */
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 8, 8, idx, 64, &out_n), ANTS_OK);
    CHECK(out_n == 8);
    for (i = 0; i < 8; i++) {
        CHECK(idx[i] == i);
    }

    /* BUFFER_TOO_SMALL reports the needed k. */
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 16, idx, 8, &out_n),
             ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 16);

    /* INVALID_ARG: k 0, k > population, NULLs. */
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 0, idx, 64, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 10, 11, idx, 64, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_committee_select(NULL, beacon, 100, 16, idx, 64, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_committee_select(prev, NULL, 100, 16, idx, 64, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 16, NULL, 64, &out_n),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_committee_select(prev, beacon, 100, 16, idx, 64, NULL),
             ANTS_ERROR_INVALID_ARG);
}

/* ---- block hashing + codec ---------------------------------------------- */

static void fill_block(ants_chain_block_t *b, ants_chain_pattern_finding_t *f, size_t nf)
{
    size_t i;
    memset(b, 0, sizeof *b);
    b->height = 7;
    for (i = 0; i < 32; i++) {
        b->prev_block_hash[i] = (uint8_t)(0xF0 - i);
    }
    fill_summary(&b->summary, f, nf);
}

static void test_block(void)
{
    ants_chain_block_t b;
    ants_chain_pattern_finding_t fin[3];
    ants_chain_block_t out;
    ants_chain_pattern_finding_t fout[3];
    uint8_t buf[ANTS_CHAIN_BLOCK_ENCODED_MAX];
    uint8_t buf2[ANTS_CHAIN_BLOCK_ENCODED_MAX + 1];
    uint8_t h1[32];
    uint8_t h2[32];
    uint8_t ref[32];
    size_t len = 0;
    size_t out_n = 0;
    size_t i;
    size_t k;

    fill_block(&b, fin, 3);

    /* bound, encode, canonical. */
    CHECK(ants_chain_block_bound(&b) <= ANTS_CHAIN_BLOCK_ENCODED_MAX);
    CHECK_EQ(ants_chain_block_encode(&b, buf, sizeof buf, &len), ANTS_OK);
    CHECK(len > 0);
    CHECK_EQ(ants_cbor_is_canonical(buf, len), ANTS_OK);

    /* decode round-trip. */
    CHECK_EQ(ants_chain_block_decode(buf, len, &out, fout, 3, &out_n), ANTS_OK);
    CHECK(out.height == b.height);
    CHECK(memcmp(out.prev_block_hash, b.prev_block_hash, 32) == 0);
    CHECK(out.summary.epoch == b.summary.epoch);
    CHECK(out.summary.cutoff_time == b.summary.cutoff_time);
    CHECK(memcmp(out.summary.confirmed_proofs, b.summary.confirmed_proofs, 32) == 0);
    CHECK(out_n == 3);
    CHECK(out.summary.n_findings == 3);
    for (i = 0; i < 3; i++) {
        CHECK(memcmp(fout[i].subject, fin[i].subject, 32) == 0);
        CHECK(fout[i].rule_id == fin[i].rule_id);
        CHECK(fout[i].severity == fin[i].severity);
    }

    /* block_hash == BLAKE3(canonical block encoding) — independent recompute. */
    CHECK_EQ(ants_blake3_hash(buf, len, ref), ANTS_OK);
    CHECK_EQ(ants_chain_block_hash(&b, h1), ANTS_OK);
    CHECK(memcmp(h1, ref, 32) == 0);

    /* determinism. */
    CHECK_EQ(ants_chain_block_hash(&b, h2), ANTS_OK);
    CHECK(memcmp(h1, h2, 32) == 0);

    /* sensitivity: height and prev-hash each change the block hash. */
    {
        ants_chain_block_t b2 = b;
        b2.height = b.height + 1;
        CHECK_EQ(ants_chain_block_hash(&b2, h2), ANTS_OK);
        CHECK(memcmp(h1, h2, 32) != 0);
    }
    {
        ants_chain_block_t b2 = b;
        b2.prev_block_hash[0] ^= 0xFFu;
        CHECK_EQ(ants_chain_block_hash(&b2, h2), ANTS_OK);
        CHECK(memcmp(h1, h2, 32) != 0);
    }

    /* probe decode reports the findings count. */
    CHECK_EQ(ants_chain_block_decode(buf, len, &out, NULL, 0, &out_n), ANTS_ERROR_BUFFER_TOO_SMALL);
    CHECK(out_n == 3);

    /* strict decode: truncation never yields OK. */
    for (k = 1; k < len; k++) {
        CHECK(ants_chain_block_decode(buf, k, &out, fout, 3, &out_n) != ANTS_OK);
    }
    /* trailing byte → MALFORMED. */
    memcpy(buf2, buf, len);
    buf2[len] = 0x00;
    CHECK_EQ(ants_chain_block_decode(buf2, len + 1, &out, fout, 3, &out_n), ANTS_ERROR_MALFORMED);
    /* wrong outer map size: map(3) 0xA3 → map(2) 0xA2. */
    memcpy(buf2, buf, len);
    CHECK(buf2[0] == 0xA3u);
    buf2[0] = 0xA2u;
    CHECK_EQ(ants_chain_block_decode(buf2, len, &out, fout, 3, &out_n), ANTS_ERROR_MALFORMED);

    /* invalid summary inside the block → INVALID_ARG (encode and hash). */
    fin[0].severity = ANTS_CHAIN_SEVERITY__RESERVED_MIN;
    CHECK_EQ(ants_chain_block_encode(&b, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_block_hash(&b, h1), ANTS_ERROR_INVALID_ARG);
    fin[0].severity = ANTS_CHAIN_SEVERITY_SOFT;

    /* NULL args. */
    CHECK_EQ(ants_chain_block_encode(NULL, buf, sizeof buf, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_block_hash(NULL, h1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_block_decode(NULL, len, &out, fout, 3, &out_n), ANTS_ERROR_INVALID_ARG);
}

/* ---- block finality (2/3) ----------------------------------------------- */

/* k deterministic Ed25519 keypairs from a seed byte. */
static void build_committee(uint8_t priv[][32], uint8_t pub[][32], size_t k)
{
    size_t i;
    for (i = 0; i < k; i++) {
        memset(priv[i], 0, 32);
        priv[i][0] = (uint8_t)(i + 1);
        CHECK_EQ(ants_ed25519_pubkey_from_priv(priv[i], pub[i]), ANTS_OK);
    }
}

static void test_finality(void)
{
    enum { K = 4 }; /* threshold = ceil(2*4/3) = 3 */
    uint8_t priv[K][32];
    uint8_t pub[K][32];
    uint8_t sigs[K][64];
    uint8_t att[K * 64];
    uint8_t bh[32];
    bool mask[K];
    bool final = false;
    size_t i;

    build_committee(priv, pub, K);
    memset(bh, 0x5A, 32);
    for (i = 0; i < K; i++) {
        CHECK_EQ(ants_ed25519_sign(priv[i], bh, 32, sigs[i]), ANTS_OK);
    }

    /* 3 of 4 valid signers (members 0,1,2) → final. */
    mask[0] = true;
    mask[1] = true;
    mask[2] = true;
    mask[3] = false;
    memcpy(att + 0 * 64, sigs[0], 64);
    memcpy(att + 1 * 64, sigs[1], 64);
    memcpy(att + 2 * 64, sigs[2], 64);
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 3 * 64, mask, &final), ANTS_OK);
    CHECK(final);

    /* 2 of 4 → below threshold → not final. */
    mask[2] = false;
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 2 * 64, mask, &final), ANTS_OK);
    CHECK(!final);

    /* 3 signers but one signature tampered → only 2 valid → not final. */
    mask[2] = true;
    att[2 * 64] ^= 0xFFu;
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 3 * 64, mask, &final), ANTS_OK);
    CHECK(!final);
    memcpy(att + 2 * 64, sigs[2], 64); /* restore */

    /* Signers (0,2,3), signatures packed in member order → final. */
    mask[0] = true;
    mask[1] = false;
    mask[2] = true;
    mask[3] = true;
    memcpy(att + 0 * 64, sigs[0], 64);
    memcpy(att + 1 * 64, sigs[2], 64);
    memcpy(att + 2 * 64, sigs[3], 64);
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 3 * 64, mask, &final), ANTS_OK);
    CHECK(final);

    /* A signature that does not match its member's pubkey is not counted:
     * mask claims members {0,1,2}, but slot 1 holds member 0's signature →
     * it verifies against pub[1] and fails → 2 valid → not final. */
    mask[0] = true;
    mask[1] = true;
    mask[2] = true;
    mask[3] = false;
    memcpy(att + 0 * 64, sigs[0], 64);
    memcpy(att + 1 * 64, sigs[0], 64);
    memcpy(att + 2 * 64, sigs[2], 64);
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 3 * 64, mask, &final), ANTS_OK);
    CHECK(!final);

    /* attestations_len must equal popcount(mask) signatures. */
    mask[0] = true;
    mask[1] = true;
    mask[2] = true;
    mask[3] = false;
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 2 * 64, mask, &final),
             ANTS_ERROR_INVALID_ARG);

    /* Zero signers: len 0, attestations NULL → not final. */
    mask[0] = false;
    mask[1] = false;
    mask[2] = false;
    mask[3] = false;
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, NULL, 0, mask, &final), ANTS_OK);
    CHECK(!final);

    /* Arg guards. */
    mask[0] = true;
    mask[1] = true;
    mask[2] = true;
    CHECK_EQ(ants_chain_finality_verify(bh, pub, 0, att, 0, mask, &final), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_finality_verify(
                 bh, pub, ANTS_CHAIN_COMMITTEE_K_MAX + 1, att, 3 * 64, mask, &final),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_finality_verify(NULL, pub, K, att, 3 * 64, mask, &final),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_finality_verify(bh, pub, K, att, 3 * 64, mask, NULL),
             ANTS_ERROR_INVALID_ARG);
}

/* ---- partition recovery: Σ T_eff fork choice ---------------------------- */

static void test_fork_weight(void)
{
    uint64_t cap = ANTS_CHAIN_T_FORK_CHOICE_CAP;
    uint64_t got;
    uint64_t te;

    /* Empty fork → 0. */
    CHECK_EQ(ants_chain_fork_weight(NULL, 0, cap, &got), ANTS_OK);
    CHECK(got == 0);

    /* All-zero tenures → 0 (t_eff(0) == 0). */
    {
        uint64_t t[3] = {0, 0, 0};
        CHECK_EQ(ants_chain_fork_weight(t, 3, cap, &got), ANTS_OK);
        CHECK(got == 0);
    }

    /* A single validator equals ants_reputation_t_eff — cross-check the sum
     * against the shared transform itself, not a re-implementation. */
    {
        uint64_t t[1] = {cap};
        CHECK_EQ(ants_reputation_t_eff(cap, cap, &te), ANTS_OK);
        CHECK_EQ(ants_chain_fork_weight(t, 1, cap, &got), ANTS_OK);
        CHECK(got == te);
    }

    /* Linearity: N copies of one tenure sum to N * t_eff(tenure). */
    {
        uint64_t t[4] = {1000000, 1000000, 1000000, 1000000};
        CHECK_EQ(ants_reputation_t_eff(1000000, cap, &te), ANTS_OK);
        CHECK_EQ(ants_chain_fork_weight(t, 4, cap, &got), ANTS_OK);
        CHECK(got == 4 * te);
    }

    /* Saturation: a tenure many caps deep folds to ~cap, never above. */
    {
        uint64_t t[1] = {30 * cap};
        CHECK_EQ(ants_chain_fork_weight(t, 1, cap, &got), ANTS_OK);
        CHECK(got <= cap);
        CHECK(got > cap - cap / 100);
    }

    /* Arg guards. */
    {
        uint64_t t[1] = {5};
        CHECK_EQ(ants_chain_fork_weight(t, 1, 0, &got), ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_chain_fork_weight(t, 1, cap, NULL), ANTS_ERROR_INVALID_ARG);
        CHECK_EQ(ants_chain_fork_weight(NULL, 3, cap, &got), ANTS_ERROR_INVALID_ARG);
    }
}

static void test_fork_choice(void)
{
    int w;

    /* θ = 1/3 of 100 → thresh = 33. A clears (40>33), B does not → the
     * heavier fork (A) wins. */
    CHECK_EQ(ants_chain_fork_choice(40, 10, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_A);

    /* Symmetric → B. */
    CHECK_EQ(ants_chain_fork_choice(10, 40, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_B);

    /* Both clear θ → balanced → social (equal, and unequal-but-both-over). */
    CHECK_EQ(ants_chain_fork_choice(40, 40, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_SOCIAL_SCHELLING);
    CHECK_EQ(ants_chain_fork_choice(40, 35, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_SOCIAL_SCHELLING);

    /* Neither clears → heavier (A); a tie breaks to A deterministically. */
    CHECK_EQ(ants_chain_fork_choice(30, 20, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_A);
    CHECK_EQ(ants_chain_fork_choice(30, 30, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_A);

    /* Exactly at the threshold does NOT clear (strict >): a=33 doesn't clear. */
    CHECK_EQ(ants_chain_fork_choice(33, 20, 100, 1, 3, &w), ANTS_OK);
    CHECK(w == ANTS_CHAIN_FORK_A);

    /* Overflow-safe threshold with total near UINT64_MAX (thresh ~ total/3):
     * A just over the third clears, B just under does not. */
    {
        uint64_t total = UINT64_MAX;
        uint64_t third = total / 3;
        CHECK_EQ(ants_chain_fork_choice(third + 2, third - 1, total, 1, 3, &w), ANTS_OK);
        CHECK(w == ANTS_CHAIN_FORK_A);
    }

    /* Arg guards: theta_den 0, weight > total, NULL out. */
    CHECK_EQ(ants_chain_fork_choice(10, 10, 100, 1, 0, &w), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_fork_choice(101, 10, 100, 1, 3, &w), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_fork_choice(10, 10, 100, 1, 3, NULL), ANTS_ERROR_INVALID_ARG);
}

/* ------------------------------------------------------------------------ */
/* PR7 — drand beacon verification + VRF seed derivation                    */
/* ------------------------------------------------------------------------ */

/* Helper: convert a hex string to bytes. Returns the number of bytes
 * written. Same convention as test_crypto.c. */
static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_cap) {
        return 0;
    }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (uint8_t)byte;
    }
    return n / 2;
}

/* drand default chain (scheme pedersen-bls-chained, chain hash
 * 8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce):
 * the group public key plus two consecutive real rounds, fetched from
 * api.drand.sh on 2026-06-11. Real-world vectors: if beacon_verify's
 * chained-payload derivation (SHA-256(prev_sig || round_be64)) were
 * wrong in any byte, the BLS verification below would fail. */
static const char *DRAND_PUBKEY_HEX =
    "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a5699"
    "37c529eeda66c7293784a9402801af31";
static const char *DRAND_R1000_PREV_HEX =
    "af0d93299a363735fe847f5ea241442c65843dc1bd3a7b79646b3b10072e908b"
    "f034d35cd69d378e3341f139100cd4cd03030399864ef8803a5a4f5e64fccc20"
    "bbae36d1ca22a6ddc43d2630c41105e90598fab11e5c7456df3925d4b577b113";
static const char *DRAND_R1000_SIG_HEX =
    "99bf96de133c3d3937293cfca10c8152b18ab2d034ccecf115658db324d2edc0"
    "0a16a2044cd04a8a38e2a307e5ecff3511315be8d282079faf24098f283e0ed2"
    "c199663b334d2e84c55c032fe469b212c5c2087ebb83a5b25155c3283f5b79ac";
static const char *DRAND_R1000_RAND_HEX =
    "a40d3e0e7e3c71f28b7da2fd339f47f0bcf10910309f5253d7c323ec8cea3212";
static const char *DRAND_R1001_SIG_HEX =
    "b206bc0eae915ff9a8e89e48ff0ac5411b170ba20d92ea2880d9b9f0d6b6b870"
    "d80689792995b97116bf5174c5c5408f052c93908ebabca91dddd5c8974d9e87"
    "4b7d7854806dba75a08acffb029758f289712045ca7fb39b0fef9727a9a91b53";
static const char *DRAND_R1001_RAND_HEX =
    "bb5820c2a9dd740e5d90ab70950246b8881d7ec9b2ee8411a27e35b0372b2119";

static void fill_beacon(ants_chain_beacon_t *b,
                        uint64_t round,
                        const char *rand_hex,
                        const char *sig_hex,
                        const char *prev_hex)
{
    memset(b, 0, sizeof *b);
    b->round = round;
    CHECK(hex_to_bytes(rand_hex, b->randomness, sizeof b->randomness) == 32);
    CHECK(hex_to_bytes(sig_hex, b->signature, sizeof b->signature) == 96);
    CHECK(hex_to_bytes(prev_hex, b->previous_signature, sizeof b->previous_signature) == 96);
}

static void test_beacon_verify_real_rounds(void)
{
    uint8_t pubkey[ANTS_CHAIN_DRAND_PUBKEY_SIZE];
    CHECK(hex_to_bytes(DRAND_PUBKEY_HEX, pubkey, sizeof pubkey) == 48);

    /* Round 1000 verifies against the real group key. */
    ants_chain_beacon_t b1000;
    fill_beacon(&b1000, 1000, DRAND_R1000_RAND_HEX, DRAND_R1000_SIG_HEX, DRAND_R1000_PREV_HEX);
    bool ok = false;
    CHECK_EQ(ants_chain_beacon_verify(&b1000, pubkey, &ok), ANTS_OK);
    CHECK(ok);

    /* Round 1001 chains: its previous_signature IS round 1000's
     * signature. */
    ants_chain_beacon_t b1001;
    fill_beacon(&b1001, 1001, DRAND_R1001_RAND_HEX, DRAND_R1001_SIG_HEX, DRAND_R1000_SIG_HEX);
    ok = false;
    CHECK_EQ(ants_chain_beacon_verify(&b1001, pubkey, &ok), ANTS_OK);
    CHECK(ok);
}

static void test_beacon_verify_rejects(void)
{
    uint8_t pubkey[ANTS_CHAIN_DRAND_PUBKEY_SIZE];
    CHECK(hex_to_bytes(DRAND_PUBKEY_HEX, pubkey, sizeof pubkey) == 48);
    ants_chain_beacon_t good;
    fill_beacon(&good, 1000, DRAND_R1000_RAND_HEX, DRAND_R1000_SIG_HEX, DRAND_R1000_PREV_HEX);
    bool ok = true;
    ants_chain_beacon_t bad;

    /* Tampered signature byte → verdict false (not an error). */
    bad = good;
    bad.signature[17] ^= 0x01u;
    ok = true;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_OK);
    CHECK(!ok);

    /* Wrong round number for this signature. */
    bad = good;
    bad.round = 1002;
    ok = true;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_OK);
    CHECK(!ok);

    /* Tampered previous_signature → different signed payload. */
    bad = good;
    bad.previous_signature[40] ^= 0x80u;
    ok = true;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_OK);
    CHECK(!ok);

    /* Signature valid but published randomness lies. */
    bad = good;
    bad.randomness[0] ^= 0x01u;
    ok = true;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_OK);
    CHECK(!ok);

    /* Corrupted group key (not a valid G1 point) → verdict false. */
    uint8_t bad_pubkey[ANTS_CHAIN_DRAND_PUBKEY_SIZE];
    memcpy(bad_pubkey, pubkey, sizeof bad_pubkey);
    bad_pubkey[20] ^= 0xFFu;
    ok = true;
    CHECK_EQ(ants_chain_beacon_verify(&good, bad_pubkey, &ok), ANTS_OK);
    CHECK(!ok);

    /* Rounds 0 and 1 are out of the steady-state form. NULL guards. */
    bad = good;
    bad.round = 0;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_ERROR_INVALID_ARG);
    bad.round = 1;
    CHECK_EQ(ants_chain_beacon_verify(&bad, pubkey, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_beacon_verify(NULL, pubkey, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_beacon_verify(&good, NULL, &ok), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_beacon_verify(&good, pubkey, NULL), ANTS_ERROR_INVALID_ARG);
}

static void test_vrf_seed(void)
{
    uint8_t prev[ANTS_CHAIN_HASH_SIZE];
    uint8_t randomness[ANTS_CHAIN_BEACON_RANDOMNESS_SIZE];
    for (size_t i = 0; i < sizeof prev; i++) {
        prev[i] = (uint8_t)(0xA0u + i);
    }
    CHECK(hex_to_bytes(DRAND_R1000_RAND_HEX, randomness, sizeof randomness) == 32);
    const uint64_t height = 0x0102030405060708ULL;

    /* Independent reference: recompute via the streaming derive-key
     * API with the BE-64 height hand-rolled here — a different
     * construction from the impl's one-shot derive over a packed
     * buffer. */
    uint8_t height_be[8];
    height_be[0] = 0x01u;
    height_be[1] = 0x02u;
    height_be[2] = 0x03u;
    height_be[3] = 0x04u;
    height_be[4] = 0x05u;
    height_be[5] = 0x06u;
    height_be[6] = 0x07u;
    height_be[7] = 0x08u;
    ants_blake3_ctx_t ctx;
    uint8_t want[ANTS_CHAIN_HASH_SIZE];
    CHECK_EQ(ants_blake3_init_derive(&ctx, "ants-v1-vrf-seed"), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&ctx, prev, sizeof prev), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&ctx, height_be, sizeof height_be), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&ctx, randomness, sizeof randomness), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&ctx, want), ANTS_OK);

    uint8_t seed[ANTS_CHAIN_HASH_SIZE];
    CHECK_EQ(ants_chain_vrf_seed(prev, height, randomness, seed), ANTS_OK);
    CHECK(memcmp(seed, want, sizeof seed) == 0);

    /* Degraded seed: same independent recompute, shorter input, its
     * own context string. */
    CHECK_EQ(ants_blake3_init_derive(&ctx, "ants-v1-vrf-seed-degraded"), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&ctx, prev, sizeof prev), ANTS_OK);
    CHECK_EQ(ants_blake3_update(&ctx, height_be, sizeof height_be), ANTS_OK);
    CHECK_EQ(ants_blake3_final(&ctx, want), ANTS_OK);

    uint8_t degraded[ANTS_CHAIN_HASH_SIZE];
    CHECK_EQ(ants_chain_vrf_seed_degraded(prev, height, degraded), ANTS_OK);
    CHECK(memcmp(degraded, want, sizeof degraded) == 0);

    /* The two domains never collide, and every input matters. */
    CHECK(memcmp(seed, degraded, sizeof seed) != 0);
    uint8_t seed2[ANTS_CHAIN_HASH_SIZE];
    CHECK_EQ(ants_chain_vrf_seed(prev, height + 1, randomness, seed2), ANTS_OK);
    CHECK(memcmp(seed, seed2, sizeof seed) != 0);
    randomness[31] ^= 0x01u;
    CHECK_EQ(ants_chain_vrf_seed(prev, height, randomness, seed2), ANTS_OK);
    CHECK(memcmp(seed, seed2, sizeof seed) != 0);
    randomness[31] ^= 0x01u;
    CHECK_EQ(ants_chain_vrf_seed(prev, height, randomness, seed2), ANTS_OK);
    CHECK(memcmp(seed, seed2, sizeof seed) == 0);

    /* Arg guards. */
    CHECK_EQ(ants_chain_vrf_seed(NULL, height, randomness, seed), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_vrf_seed(prev, height, NULL, seed), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_vrf_seed(prev, height, randomness, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_vrf_seed_degraded(NULL, height, seed), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_chain_vrf_seed_degraded(prev, height, NULL), ANTS_ERROR_INVALID_ARG);
}

int main(void)
{
    test_constants();

    test_confirmed_root_reference();
    test_confirmed_root_args();
    test_confirmed_prove_verify();
    test_confirmed_prove_args();

    test_epoch_summary_roundtrip();
    test_epoch_summary_probe_and_strict();
    test_epoch_summary_encode_args();

    test_pattern_scan();
    test_committee_select();
    test_block();
    test_finality();
    test_fork_weight();
    test_fork_choice();

    test_beacon_verify_real_rounds();
    test_beacon_verify_rejects();
    test_vrf_seed();

    if (failures == 0) {
        printf("test_chain: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_chain: %d check(s) failed\n", failures);
    return 1;
}
