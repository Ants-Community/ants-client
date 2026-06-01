/*
 * test_chain.c — Tests for Layer 2, the PoUH chain as ordered witness
 * (Component #8).
 *
 * PR1 (scaffold): contract tests — the still-deferred entry points return
 * ANTS_ERROR_NOT_IMPLEMENTED, and the protocol constants hold their
 * invariants.
 *
 * PR2: the confirmed_proofs Merkle root + inclusion proof, and the
 * EpochSummary canonical-CBOR codec. The Merkle tests verify against an
 * INDEPENDENT reference — leaf/node hashes recomputed directly with raw
 * BLAKE3 and the small trees composed by hand (n = 0..4, incl. the
 * promote-lone-trailing case at n=3) — rather than mirroring the impl's MMR
 * build, so a divergence in the construction is caught. prove/verify is a
 * round-trip + single-byte tamper sweep against the committed root. The
 * codec is a canonical round-trip (cross-checked with ants_cbor_is_canonical)
 * plus a strict-decode battery (truncation, trailing byte, wrong map size,
 * out-of-range severity, unknown severity).
 */

#include "ants_cbor.h"
#include "ants_chain.h"
#include "ants_common.h"
#include "ants_crypto.h"

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

/* ---- still-deferred entry points report the scaffold state -------------- */

static void test_stubs_not_implemented(void)
{
    uint8_t hash[32] = {0};
    uint8_t pks[2][ANTS_CHAIN_PEER_ID_SIZE] = {{0}};
    uint8_t buf[64] = {0};
    uint8_t sigs[2 * ANTS_CHAIN_SIG_SIZE] = {0};
    bool mask[2] = {true, true};
    bool out_ok = true;
    size_t out_n = 0;
    size_t out_len = 0;
    int winner = -1;
    uint64_t out_u64 = 0;
    ants_chain_block_t block;
    ants_chain_pattern_finding_t findings[2];

    memset(&block, 0, sizeof block);
    memset(findings, 0, sizeof findings);

    CHECK_EQ(ants_chain_block_hash(&block, hash), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(ants_chain_block_bound(&block) == 0);
    CHECK_EQ(ants_chain_block_encode(&block, buf, sizeof buf, &out_len),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_block_decode(buf, sizeof buf, &block, findings, 2, &out_n),
             ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK_EQ(ants_chain_finality_verify(hash, pks, 2, sigs, sizeof sigs, mask, &out_ok),
             ANTS_ERROR_NOT_IMPLEMENTED);
    {
        uint64_t tenures[2] = {1000, 2000};
        CHECK_EQ(ants_chain_fork_weight(tenures, 2, ANTS_CHAIN_T_FORK_CHOICE_CAP, &out_u64),
                 ANTS_ERROR_NOT_IMPLEMENTED);
    }
    CHECK_EQ(ants_chain_fork_choice(
                 10, 20, 100, ANTS_CHAIN_FORK_THETA_NUM, ANTS_CHAIN_FORK_THETA_DEN, &winner),
             ANTS_ERROR_NOT_IMPLEMENTED);
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

    test_stubs_not_implemented();

    if (failures == 0) {
        printf("test_chain: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_chain: %d check(s) failed\n", failures);
    return 1;
}
