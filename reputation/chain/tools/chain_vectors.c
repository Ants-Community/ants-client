/*
 * chain_vectors.c — emit the reputation/chain test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout,
 * with every pinned value produced by the COMPILED ants_chain library —
 * never transcribed by hand — per RFC-0008 §8: "the vectors themselves are
 * generated against the reference implementation". Categories covered
 * (RFC-0008 v0.6 §11.4 + §11.6 + §4.2):
 *
 *   - confirmed-proofs Merkle roots (incl. the empty root and promote-lone
 *     shapes) and inclusion paths;
 *   - the EpochSummary canonical-CBOR encoding;
 *   - the Block canonical-CBOR encoding + block hash, with the
 *     degraded_seed flag flipped to pin its effect inside the signed bytes;
 *   - the VRF seed derivations (live + degraded contexts);
 *   - the proposer rule (height mod k);
 *   - the pattern engine over a small fixed event set.
 *
 * Deterministic by construction: fixed inputs, no clock, no randomness, no
 * floats. Run it twice and the bytes must match. Inputs are synthetic
 * patterns chosen for readability (an id of "32 bytes of 0x02" is easy to
 * reproduce in any language); the OUTPUTS are whatever the library computes.
 *
 * Usage:  chain_vectors > chain.json
 */

#include "ants_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

static void die(const char *what, ants_error_t rc)
{
    fprintf(stderr, "chain_vectors: %s failed: %d\n", what, (int)rc);
    exit(1);
}

static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

/* A content-id / hash filled with one repeated byte: trivially reproducible
 * and, taken with ascending fill values, strictly ascending bytewise — the
 * canonical leaf order ants_chain_confirmed_root requires. */
static void fill_id(uint8_t out[ANTS_CHAIN_HASH_SIZE], uint8_t v)
{
    memset(out, (int)v, ANTS_CHAIN_HASH_SIZE);
}

/* ------------------------------------------------------------------------ */
/* Shared fixtures                                                          */
/* ------------------------------------------------------------------------ */

#define MAX_IDS 8u

static uint8_t g_ids[MAX_IDS][ANTS_CHAIN_HASH_SIZE];

/* The summary every summary/block vector uses: two internally-consistent
 * findings (count 3 in a 30-day window -> MEDIUM, count 7 -> HARD) over the
 * n=3 confirmed root, so the vector doubles as a sane worked example. */
static ants_chain_pattern_finding_t g_findings[2];
static ants_chain_epoch_summary_t g_summary;

static void init_fixtures(void)
{
    uint8_t i;
    for (i = 0; i < MAX_IDS; i++) {
        fill_id(g_ids[i], i);
    }

    fill_id(g_findings[0].subject, 0x11);
    g_findings[0].rule_id = ANTS_CHAIN_RULE_FAULT_COUNT_30D;
    g_findings[0].window_s = ANTS_CHAIN_PATTERN_WINDOW_S;
    g_findings[0].count = 3;
    g_findings[0].severity = ANTS_CHAIN_SEVERITY_MEDIUM;

    fill_id(g_findings[1].subject, 0x22);
    g_findings[1].rule_id = ANTS_CHAIN_RULE_FAULT_COUNT_30D;
    g_findings[1].window_s = ANTS_CHAIN_PATTERN_WINDOW_S;
    g_findings[1].count = 7;
    g_findings[1].severity = ANTS_CHAIN_SEVERITY_HARD;

    g_summary.epoch = 42;
    g_summary.cutoff_time = 1700000000;
    ants_error_t rc = ants_chain_confirmed_root(g_ids, 3, g_summary.confirmed_proofs);
    if (rc != ANTS_OK) {
        die("confirmed_root(fixture)", rc);
    }
    g_summary.findings = g_findings;
    g_summary.n_findings = 2;
}

/* ------------------------------------------------------------------------ */
/* Sections                                                                 */
/* ------------------------------------------------------------------------ */

static void emit_confirmed_roots(void)
{
    static const size_t counts[] = {0, 1, 2, 3, 5, 8};
    size_t c;

    printf("  \"confirmed_root_vectors\": [\n");
    for (c = 0; c < sizeof counts / sizeof counts[0]; c++) {
        const size_t n = counts[c];
        uint8_t root[ANTS_CHAIN_HASH_SIZE];
        ants_error_t rc = ants_chain_confirmed_root(g_ids, n, root);
        if (rc != ANTS_OK) {
            die("confirmed_root", rc);
        }
        printf("    {\n");
        printf("      \"n_leaves\": %zu,\n", n);
        printf("      \"leaves\": \"content_id[i] = 32 bytes of value i, i = 0..n-1\",\n");
        printf("      \"root_hex\": \"");
        print_hex(root, sizeof root);
        printf("\"%s\n", n == 0 ? ",\n      \"notes\": \"empty tree: BLAKE3(0x02)\"" : "");
        printf("    }%s\n", c + 1 < sizeof counts / sizeof counts[0] ? "," : "");
    }
    printf("  ],\n");
}

static void emit_inclusion_proofs(void)
{
    /* (n, index) pairs covering the empty path, both promote-lone shapes,
     * and a full two-level path. */
    static const size_t cases[][2] = {{1, 0}, {3, 2}, {5, 0}, {5, 4}, {8, 5}};
    size_t c;

    printf("  \"inclusion_proof_vectors\": [\n");
    for (c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        const size_t n = cases[c][0];
        const size_t index = cases[c][1];
        uint8_t root[ANTS_CHAIN_HASH_SIZE];
        uint8_t path[ANTS_CHAIN_MERKLE_MAX_DEPTH * ANTS_CHAIN_HASH_SIZE];
        size_t path_len = 0;
        bool ok = false;

        ants_error_t rc = ants_chain_confirmed_root(g_ids, n, root);
        if (rc != ANTS_OK) {
            die("confirmed_root(proof)", rc);
        }
        rc = ants_chain_confirmed_prove(g_ids, n, index, path, sizeof path, &path_len);
        if (rc != ANTS_OK) {
            die("confirmed_prove", rc);
        }
        rc = ants_chain_confirmed_verify(g_ids[index], index, n, path, path_len, root, &ok);
        if (rc != ANTS_OK) {
            die("confirmed_verify", rc);
        }
        if (!ok) {
            die("confirmed_verify verdict", ANTS_ERROR_MALFORMED);
        }

        printf("    {\n");
        printf("      \"n_leaves\": %zu,\n", n);
        printf("      \"leaf_index\": %zu,\n", index);
        printf("      \"path_hex\": \"");
        print_hex(path, path_len);
        printf("\",\n");
        printf("      \"verifies_against_root\": true\n");
        printf("    }%s\n", c + 1 < sizeof cases / sizeof cases[0] ? "," : "");
    }
    printf("  ],\n");
}

static void emit_summary_and_blocks(void)
{
    uint8_t sum_buf[ANTS_CHAIN_EPOCH_SUMMARY_ENCODED_MAX];
    size_t sum_len = 0;
    ants_error_t rc =
        ants_chain_epoch_summary_encode(&g_summary, sum_buf, sizeof sum_buf, &sum_len);
    if (rc != ANTS_OK) {
        die("epoch_summary_encode", rc);
    }

    printf("  \"epoch_summary_vectors\": [\n");
    printf("    {\n");
    printf("      \"epoch\": 42,\n");
    printf("      \"cutoff_time\": 1700000000,\n");
    printf("      \"confirmed_proofs\": \"the n_leaves=3 root above\",\n");
    printf("      \"findings\": [\n");
    printf("        {\"subject\": \"32 bytes of 0x11\", \"rule_id\": 1, \"window_s\": 2592000, "
           "\"count\": 3, \"severity\": 2},\n");
    printf("        {\"subject\": \"32 bytes of 0x22\", \"rule_id\": 1, \"window_s\": 2592000, "
           "\"count\": 7, \"severity\": 3}\n");
    printf("      ],\n");
    printf("      \"encoded_hex\": \"");
    print_hex(sum_buf, sum_len);
    printf("\"\n");
    printf("    }\n");
    printf("  ],\n");

    printf("  \"block_vectors\": [\n");
    int degraded;
    for (degraded = 0; degraded <= 1; degraded++) {
        ants_chain_block_t b;
        uint8_t blk_buf[ANTS_CHAIN_BLOCK_ENCODED_MAX];
        size_t blk_len = 0;
        uint8_t hash[ANTS_CHAIN_HASH_SIZE];

        b.height = 7;
        fill_id(b.prev_block_hash, 0xab);
        b.degraded_seed = degraded != 0;
        b.summary = g_summary;

        rc = ants_chain_block_encode(&b, blk_buf, sizeof blk_buf, &blk_len);
        if (rc != ANTS_OK) {
            die("block_encode", rc);
        }
        rc = ants_chain_block_hash(&b, hash);
        if (rc != ANTS_OK) {
            die("block_hash", rc);
        }

        printf("    {\n");
        printf("      \"height\": 7,\n");
        printf("      \"prev_block_hash\": \"32 bytes of 0xab\",\n");
        printf("      \"degraded_seed\": %s,\n", degraded ? "true" : "false");
        printf("      \"summary\": \"the epoch_summary vector above\",\n");
        printf("      \"encoded_hex\": \"");
        print_hex(blk_buf, blk_len);
        printf("\",\n");
        printf("      \"block_hash_hex\": \"");
        print_hex(hash, sizeof hash);
        printf("\"\n");
        printf("    }%s\n", degraded == 0 ? "," : "");
    }
    printf("  ],\n");
}

static void emit_vrf_seeds(void)
{
    uint8_t prev[ANTS_CHAIN_HASH_SIZE];
    uint8_t randomness[ANTS_CHAIN_BEACON_RANDOMNESS_SIZE];
    uint8_t seed[ANTS_CHAIN_HASH_SIZE];
    fill_id(prev, 0xcd);
    memset(randomness, 0xef, sizeof randomness);

    ants_error_t rc = ants_chain_vrf_seed(prev, 9, randomness, seed);
    if (rc != ANTS_OK) {
        die("vrf_seed", rc);
    }

    printf("  \"vrf_seed_vectors\": [\n");
    printf("    {\n");
    printf("      \"context\": \"ants-v1-vrf-seed\",\n");
    printf("      \"prev_block_hash\": \"32 bytes of 0xcd\",\n");
    printf("      \"height\": 9,\n");
    printf("      \"randomness\": \"32 bytes of 0xef\",\n");
    printf("      \"seed_hex\": \"");
    print_hex(seed, sizeof seed);
    printf("\"\n");
    printf("    },\n");

    rc = ants_chain_vrf_seed_degraded(prev, 9, seed);
    if (rc != ANTS_OK) {
        die("vrf_seed_degraded", rc);
    }
    printf("    {\n");
    printf("      \"context\": \"ants-v1-vrf-seed-degraded\",\n");
    printf("      \"prev_block_hash\": \"32 bytes of 0xcd\",\n");
    printf("      \"height\": 9,\n");
    printf("      \"seed_hex\": \"");
    print_hex(seed, sizeof seed);
    printf("\"\n");
    printf("    }\n");
    printf("  ],\n");
}

static void emit_proposers(void)
{
    static const uint64_t heights[] = {0, 7, 16, 17, 1000000};
    static const size_t ks[] = {5, 5, 16, 16, 64};
    size_t c;

    printf("  \"proposer_vectors\": [\n");
    for (c = 0; c < sizeof heights / sizeof heights[0]; c++) {
        size_t member = 0;
        ants_error_t rc = ants_chain_proposer(heights[c], ks[c], &member);
        if (rc != ANTS_OK) {
            die("proposer", rc);
        }
        printf("    {\"height\": %llu, \"k\": %zu, \"member_position\": %zu}%s\n",
               (unsigned long long)heights[c],
               ks[c],
               member,
               c + 1 < sizeof heights / sizeof heights[0] ? "," : "");
    }
    printf("  ],\n");
}

static void emit_pattern_scan(void)
{
    /* Subject 0x11: three in-window events -> MEDIUM. Subject 0x22: one
     * in-window event -> SOFT. now == the summary fixture's cutoff_time. */
    const uint64_t now = 1700000000;
    ants_chain_event_t events[4];
    ants_chain_pattern_finding_t findings[4];
    size_t n_findings = 0;
    size_t i;

    fill_id(events[0].subject, 0x11);
    events[0].timestamp = now - 100;
    fill_id(events[1].subject, 0x11);
    events[1].timestamp = now - 200;
    fill_id(events[2].subject, 0x11);
    events[2].timestamp = now - 300;
    fill_id(events[3].subject, 0x22);
    events[3].timestamp = now - 50;
    for (i = 0; i < 4; i++) {
        events[i].fault_type = 0; /* ANTS_FAULT_EQUIVOCATION */
    }

    ants_error_t rc = ants_chain_pattern_scan(events, 4, now, findings, 4, &n_findings);
    if (rc != ANTS_OK) {
        die("pattern_scan", rc);
    }

    printf("  \"pattern_scan_vectors\": [\n");
    printf("    {\n");
    printf("      \"now\": 1700000000,\n");
    printf("      \"events\": \"subject 0x11 at now-100/now-200/now-300; subject 0x22 at "
           "now-50 (subjects are 32 repeated bytes)\",\n");
    printf("      \"findings\": [\n");
    for (i = 0; i < n_findings; i++) {
        printf("        {\"subject_byte\": \"0x%02x\", \"rule_id\": %llu, \"window_s\": %llu, "
               "\"count\": %llu, \"severity\": %u}%s\n",
               findings[i].subject[0],
               (unsigned long long)findings[i].rule_id,
               (unsigned long long)findings[i].window_s,
               (unsigned long long)findings[i].count,
               (unsigned)findings[i].severity,
               i + 1 < n_findings ? "," : "");
    }
    printf("      ]\n");
    printf("    }\n");
    printf("  ]\n");
}

/* ------------------------------------------------------------------------ */

int main(void)
{
    init_fixtures();

    printf("{\n");
    printf("  \"primitive\": \"reputation-chain protocol objects: confirmed-proofs Merkle, "
           "EpochSummary, Block, VRF seed, proposer rule, pattern scan\",\n");
    printf("  \"spec\": \"RFC-0008 v0.6 \\u00a711.4 + \\u00a711.6 + \\u00a74.2; RFC-0004 v0.7 "
           "\\u00a7Layer 2\",\n");
    printf("  \"version\": 1,\n");
    printf("  \"generator\": \"ants-client reputation/chain/tools/chain_vectors.c - every value "
           "below is emitted by the compiled ants_chain library, never transcribed by hand "
           "(RFC-0008 \\u00a78)\",\n");
    printf("  \"notes\": \"Canonical CBOR per RFC-0008 \\u00a71.1; hex lowercase. Inputs are "
           "synthetic repeated-byte patterns chosen for cross-language reproducibility. The "
           "pattern-rule thresholds and windows are DRAFT b2-class values (RFC-0008 \\u00a77). "
           "drand beacon rounds are deliberately not in this pack: they verify against the live "
           "drand chain itself (provenance pinned in the reference client's test_chain.c).\",\n");

    emit_confirmed_roots();
    emit_inclusion_proofs();
    emit_summary_and_blocks();
    emit_vrf_seeds();
    emit_proposers();
    emit_pattern_scan();

    printf("}\n");
    return 0;
}
