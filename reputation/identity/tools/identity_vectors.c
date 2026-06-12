/*
 * identity_vectors.c — emit the receipt-bag / selective-disclosure
 * test-vector pack.
 *
 * Prints a JSON document (the ants-test-vectors house format) on stdout,
 * with every pinned value produced by the COMPILED ants_reputation library —
 * never transcribed by hand — per RFC-0008 §8: "the vectors themselves are
 * generated against the reference implementation". Categories covered
 * (RFC-0008 v0.7 §11.9 + §4.1 receipt-bag-root context):
 *
 *   - the countersigned receipt body encoding + both Ed25519 signatures
 *     (RFC 8032 signing is deterministic, so the signatures are vectors);
 *   - bag_root (incl. the empty bag) and inclusion paths;
 *   - the (A, T) computation under the DRAFT default parameters;
 *   - the A >= b proof: prover-side subset selection + verifier verdict;
 *   - the compact summary: bucketing, signed body, full encoding, and the
 *     per-bucket audit verdicts.
 *
 * Deterministic by construction: fixed inputs, no clock, no randomness, no
 * floats. Run it twice and the bytes must match. Inputs are synthetic
 * patterns chosen for readability (a private key of "32 bytes of 0x01" is
 * easy to reproduce in any language); the OUTPUTS are whatever the library
 * computes. Every emitted proof/signature/verdict is VERIFIED through the
 * library's own verifier before being printed — a vector this tool emits
 * has already round-tripped.
 *
 * Usage:  identity_vectors > identity.json
 */

#include "ants_cbor.h"
#include "ants_crypto.h"
#include "ants_reputation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

static void die(const char *what, ants_error_t rc)
{
    fprintf(stderr, "identity_vectors: %s failed: %d\n", what, (int)rc);
    exit(1);
}

static void die_verdict(const char *what)
{
    fprintf(stderr, "identity_vectors: %s verdict was unexpectedly false\n", what);
    exit(1);
}

static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

/* ------------------------------------------------------------------------ */
/* Shared fixtures                                                          */
/* ------------------------------------------------------------------------ */

/* Deterministic keypairs from repeated-byte private keys: server 0x01,
 * client 0x02, an unrelated second server 0x03. */
static uint8_t g_s_priv[32], g_s_pub[32];
static uint8_t g_c_priv[32], g_c_pub[32];
static uint8_t g_x_priv[32], g_x_pub[32];

/* The 4-receipt bag every bag/summary/audit vector uses (canonical order:
 * timestamps strictly ascending). Receipt 2 credits the OTHER server — it
 * is committed in the tree but never creditable to server 0x01, which is
 * exactly the case the eligibility filters must reject. */
static ants_reputation_receipt_t g_bag[4];

static ants_reputation_params_t g_params; /* the DRAFT defaults */

static void make_key(uint8_t seed, uint8_t priv[32], uint8_t pub[32])
{
    ants_error_t rc;
    memset(priv, (int)seed, 32);
    rc = ants_ed25519_pubkey_from_priv(priv, pub);
    if (rc != ANTS_OK) {
        die("pubkey_from_priv", rc);
    }
}

static ants_reputation_receipt_t make_receipt(const uint8_t s_priv[32],
                                              const uint8_t s_pub[32],
                                              uint64_t ncs,
                                              uint64_t ts,
                                              uint8_t nonce_byte)
{
    ants_reputation_receipt_t r;
    uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
    size_t body_len = 0;
    bool ok = false;
    ants_error_t rc;

    memset(&r, 0, sizeof r);
    memcpy(r.server, s_pub, 32);
    memcpy(r.client, g_c_pub, 32);
    r.ncs_value = ncs;
    r.timestamp_unix_s = ts;
    memset(r.nonce, (int)nonce_byte, sizeof r.nonce);
    rc = ants_reputation_receipt_body_encode(&r, body, sizeof body, &body_len);
    if (rc != ANTS_OK) {
        die("receipt_body_encode", rc);
    }
    rc = ants_ed25519_sign(s_priv, body, body_len, r.server_sig);
    if (rc != ANTS_OK) {
        die("sign(server)", rc);
    }
    rc = ants_ed25519_sign(g_c_priv, body, body_len, r.client_sig);
    if (rc != ANTS_OK) {
        die("sign(client)", rc);
    }
    rc = ants_reputation_receipt_verify(&r, &ok);
    if (rc != ANTS_OK) {
        die("receipt_verify", rc);
    }
    if (!ok) {
        die_verdict("receipt_verify");
    }
    return r;
}

static void init_fixtures(void)
{
    ants_error_t rc;

    make_key(0x01, g_s_priv, g_s_pub);
    make_key(0x02, g_c_priv, g_c_pub);
    make_key(0x03, g_x_priv, g_x_pub);

    g_bag[0] = make_receipt(g_s_priv, g_s_pub, (uint64_t)1 << 30, 0, 0x10);
    g_bag[1] = make_receipt(g_s_priv, g_s_pub, (uint64_t)1 << 30, 600, 0x11);
    g_bag[2] = make_receipt(g_x_priv, g_x_pub, 7777, 800, 0x12);
    g_bag[3] = make_receipt(g_s_priv, g_s_pub, 12345, 86400, 0x13);

    rc = ants_reputation_params_default(&g_params);
    if (rc != ANTS_OK) {
        die("params_default", rc);
    }
}

/* ------------------------------------------------------------------------ */
/* Sections                                                                 */
/* ------------------------------------------------------------------------ */

static void emit_keys(void)
{
    printf("  \"key_vectors\": [\n");
    printf("    {\"private\": \"32 bytes of 0x01\", \"role\": \"server\", \"public_hex\": \"");
    print_hex(g_s_pub, 32);
    printf("\"},\n");
    printf("    {\"private\": \"32 bytes of 0x02\", \"role\": \"client\", \"public_hex\": \"");
    print_hex(g_c_pub, 32);
    printf("\"},\n");
    printf("    {\"private\": \"32 bytes of 0x03\", \"role\": \"other-server\", "
           "\"public_hex\": \"");
    print_hex(g_x_pub, 32);
    printf("\"}\n");
    printf("  ],\n");
}

static void emit_receipts(void)
{
    /* (ncs, ts, nonce_byte, server_role) for the 4 bag receipts. */
    static const char *const server_of[4] = {"server", "server", "other-server", "server"};
    size_t i;

    printf("  \"receipt_vectors\": [\n");
    for (i = 0; i < 4; i++) {
        const ants_reputation_receipt_t *r = &g_bag[i];
        uint8_t body[ANTS_REP_RECEIPT_BODY_ENCODED_MAX];
        size_t body_len = 0;
        ants_error_t rc = ants_reputation_receipt_body_encode(r, body, sizeof body, &body_len);
        if (rc != ANTS_OK) {
            die("receipt_body_encode(emit)", rc);
        }
        rc = ants_cbor_is_canonical(body, body_len);
        if (rc != ANTS_OK) {
            die("receipt body is_canonical", rc);
        }

        printf("    {\n");
        printf("      \"server\": \"%s\",\n", server_of[i]);
        printf("      \"client\": \"client\",\n");
        printf("      \"ncs_value\": %llu,\n", (unsigned long long)r->ncs_value);
        printf("      \"timestamp_unix_s\": %llu,\n", (unsigned long long)r->timestamp_unix_s);
        printf("      \"nonce\": \"16 bytes of 0x%02x\",\n", (unsigned)r->nonce[0]);
        printf("      \"body_hex\": \"");
        print_hex(body, body_len);
        printf("\",\n");
        printf("      \"server_sig_hex\": \"");
        print_hex(r->server_sig, sizeof r->server_sig);
        printf("\",\n");
        printf("      \"client_sig_hex\": \"");
        print_hex(r->client_sig, sizeof r->client_sig);
        printf("\",\n");
        printf("      \"both_signatures_verify\": true\n");
        printf("    }%s\n", i + 1 < 4 ? "," : "");
    }
    printf("  ],\n");
}

static void emit_bag(void)
{
    uint8_t empty_root[ANTS_REP_HASH_SIZE];
    uint8_t root[ANTS_REP_HASH_SIZE];
    static const size_t indices[] = {0, 3};
    size_t c;
    ants_error_t rc;

    rc = ants_reputation_bag_root(NULL, 0, g_s_pub, empty_root);
    if (rc != ANTS_OK) {
        die("bag_root(empty)", rc);
    }
    rc = ants_reputation_bag_root(g_bag, 4, g_s_pub, root);
    if (rc != ANTS_OK) {
        die("bag_root", rc);
    }

    printf("  \"bag_root_vectors\": [\n");
    printf("    {\"n_receipts\": 0, \"peer\": \"server\", \"notes\": \"empty bag: merkle root = "
           "BLAKE3(0x02), then the derive_key peer binding\", \"bag_root_hex\": \"");
    print_hex(empty_root, sizeof empty_root);
    printf("\"},\n");
    printf("    {\"n_receipts\": 4, \"peer\": \"server\", \"leaves\": \"the 4 receipts above in "
           "canonical order (timestamp ASC)\", \"bag_root_hex\": \"");
    print_hex(root, sizeof root);
    printf("\"}\n");
    printf("  ],\n");

    printf("  \"bag_inclusion_vectors\": [\n");
    for (c = 0; c < sizeof indices / sizeof indices[0]; c++) {
        const size_t index = indices[c];
        uint8_t path[ANTS_REP_BAG_MERKLE_MAX_DEPTH * ANTS_REP_HASH_SIZE];
        size_t path_len = 0;
        bool ok = false;

        rc = ants_reputation_bag_prove(g_bag, 4, index, path, sizeof path, &path_len);
        if (rc != ANTS_OK) {
            die("bag_prove", rc);
        }
        rc = ants_reputation_bag_verify_inclusion(
            &g_bag[index], index, 4, path, path_len, g_s_pub, root, &ok);
        if (rc != ANTS_OK) {
            die("bag_verify_inclusion", rc);
        }
        if (!ok) {
            die_verdict("bag_verify_inclusion");
        }

        printf("    {\"n_receipts\": 4, \"leaf_index\": %zu, \"path_hex\": \"", index);
        print_hex(path, path_len);
        printf("\", \"verifies_against_bag_root\": true}%s\n",
               c + 1 < sizeof indices / sizeof indices[0] ? "," : "");
    }
    printf("  ],\n");
}

static void emit_compute(void)
{
    const uint64_t now = 86400;
    uint64_t a = 0, t = 0;
    ants_error_t rc = ants_reputation_compute(g_s_pub, g_bag, 4, now, &g_params, &a, &t);
    if (rc != ANTS_OK) {
        die("compute", rc);
    }

    printf("  \"compute_vectors\": [\n");
    printf("    {\n");
    printf("      \"server\": \"server\",\n");
    printf("      \"bag\": \"the 4 receipts above\",\n");
    printf("      \"now_unix_s\": %llu,\n", (unsigned long long)now);
    printf("      \"params\": \"DRAFT defaults: decay_ratio_a_q32 = 2^31 (0.5), "
           "decay_ratio_t_q32 = 4252017623, kappa_uncs_per_bin = 1000000, bin_width_s = "
           "3600\",\n");
    printf("      \"a_uncs\": %llu,\n", (unsigned long long)a);
    printf("      \"t_uncs\": %llu,\n", (unsigned long long)t);
    printf("      \"notes\": \"A is hand-checkable: receipt ages 24/23/0 whole bins under "
           "ratio 0.5 give 2^30>>24 + 2^30>>23 + 12345 = 64 + 128 + 12345 = 12537; the "
           "other-server receipt never credits this peer. T pins the kappa-clip + decay_T "
           "recipe over the same bag.\"\n");
    printf("    }\n");
    printf("  ],\n");
}

static void emit_bound(void)
{
    const uint64_t now = 86400;
    const uint64_t b = 12400;
    size_t indices[4];
    size_t count = 0;
    bool reached = false;
    ants_reputation_bag_opening_t openings[4];
    uint8_t paths[4][ANTS_REP_BAG_MERKLE_MAX_DEPTH * ANTS_REP_HASH_SIZE];
    uint8_t root[ANTS_REP_HASH_SIZE];
    bool ok = false;
    size_t i;
    ants_error_t rc;

    rc = ants_reputation_bag_select_for_bound(
        g_bag, 4, g_s_pub, now, &g_params, b, indices, 4, &count, &reached);
    if (rc != ANTS_OK) {
        die("bag_select_for_bound", rc);
    }
    if (!reached) {
        die_verdict("bag_select_for_bound reached");
    }

    rc = ants_reputation_bag_root(g_bag, 4, g_s_pub, root);
    if (rc != ANTS_OK) {
        die("bag_root(bound)", rc);
    }
    for (i = 0; i < count; i++) {
        size_t path_len = 0;
        rc = ants_reputation_bag_prove(g_bag, 4, indices[i], paths[i], sizeof paths[i], &path_len);
        if (rc != ANTS_OK) {
            die("bag_prove(bound)", rc);
        }
        openings[i].receipt = g_bag[indices[i]];
        openings[i].index = indices[i];
        openings[i].path = paths[i];
        openings[i].path_len = path_len;
    }
    rc =
        ants_reputation_bag_verify_bound(openings, count, 4, g_s_pub, root, now, &g_params, b, &ok);
    if (rc != ANTS_OK) {
        die("bag_verify_bound", rc);
    }
    if (!ok) {
        die_verdict("bag_verify_bound");
    }

    printf("  \"bound_vectors\": [\n");
    printf("    {\n");
    printf("      \"bound_b_uncs\": %llu,\n", (unsigned long long)b);
    printf("      \"now_unix_s\": %llu,\n", (unsigned long long)now);
    printf("      \"selected_indices_most_recent_first\": [");
    for (i = 0; i < count; i++) {
        printf("%zu%s", indices[i], i + 1 < count ? ", " : "");
    }
    printf("],\n");
    printf("      \"reached\": true,\n");
    printf("      \"verifier_accepts_openings\": true,\n");
    printf("      \"notes\": \"hand-checkable: walking most-recent-first, 12345 (index 3) misses "
           "b, the other-server receipt (index 2) is ineligible, +128 (index 1) reaches 12473 >= "
           "12400.\"\n");
    printf("    }\n");
    printf("  ],\n");
}

static void emit_summary(void)
{
    const uint64_t eval = 86400;
    const uint64_t width = 86400;
    ants_reputation_summary_bucket_t buckets[4];
    size_t n_buckets = 0;
    ants_reputation_summary_t s;
    uint8_t body[ANTS_REP_SUMMARY_BODY_ENCODED_MAX];
    uint8_t full[ANTS_REP_SUMMARY_ENCODED_MAX];
    size_t body_len = 0, full_len = 0;
    uint8_t paths[2][ANTS_REP_BAG_MERKLE_MAX_DEPTH * ANTS_REP_HASH_SIZE];
    ants_reputation_bag_opening_t openings[2];
    bool ok = false;
    size_t i;
    ants_error_t rc;

    rc = ants_reputation_summary_build(
        g_bag, 4, g_s_pub, eval, width, &g_params, buckets, 4, &n_buckets);
    if (rc != ANTS_OK) {
        die("summary_build", rc);
    }

    memset(&s, 0, sizeof s);
    memcpy(s.peer_id, g_s_pub, 32);
    rc = ants_reputation_bag_root(g_bag, 4, g_s_pub, s.bag_root);
    if (rc != ANTS_OK) {
        die("bag_root(summary)", rc);
    }
    s.eval_time_unix_s = eval;
    s.bucket_width_s = width;
    s.buckets = buckets;
    s.n_buckets = n_buckets;
    rc = ants_reputation_summary_body_encode(&s, body, sizeof body, &body_len);
    if (rc != ANTS_OK) {
        die("summary_body_encode", rc);
    }
    rc = ants_ed25519_sign(g_s_priv, body, body_len, s.sig);
    if (rc != ANTS_OK) {
        die("sign(summary)", rc);
    }
    rc = ants_reputation_summary_verify(&s, &ok);
    if (rc != ANTS_OK) {
        die("summary_verify", rc);
    }
    if (!ok) {
        die_verdict("summary_verify");
    }
    rc = ants_reputation_summary_encode(&s, full, sizeof full, &full_len);
    if (rc != ANTS_OK) {
        die("summary_encode", rc);
    }
    rc = ants_cbor_is_canonical(body, body_len);
    if (rc != ANTS_OK) {
        die("summary body is_canonical", rc);
    }
    rc = ants_cbor_is_canonical(full, full_len);
    if (rc != ANTS_OK) {
        die("summary full is_canonical", rc);
    }

    printf("  \"summary_vectors\": [\n");
    printf("    {\n");
    printf("      \"peer\": \"server\",\n");
    printf("      \"eval_time_unix_s\": %llu,\n", (unsigned long long)eval);
    printf("      \"bucket_width_s\": %llu,\n", (unsigned long long)width);
    printf("      \"buckets\": [");
    for (i = 0; i < n_buckets; i++) {
        printf("[%llu, %llu]%s",
               (unsigned long long)buckets[i].bucket_index,
               (unsigned long long)buckets[i].total_decayed_uncs,
               i + 1 < n_buckets ? ", " : "");
    }
    printf("],\n");
    printf("      \"body_hex\": \"");
    print_hex(body, body_len);
    printf("\",\n");
    printf("      \"sig_hex\": \"");
    print_hex(s.sig, sizeof s.sig);
    printf("\",\n");
    printf("      \"full_encoded_hex\": \"");
    print_hex(full, full_len);
    printf("\",\n");
    printf("      \"signature_verifies\": true,\n");
    printf("      \"notes\": \"bucket totals are decayed at the summary's own eval_time (the "
           "bit-exact audit instant): bucket 0 = 64 + 128 = 192, bucket 1 = 12345. The "
           "other-server receipt is in the tree but in no bucket.\"\n");
    printf("    }\n");
    printf("  ],\n");

    /* Audit verdicts: full bucket-0 disclosure substantiates; a withheld
     * receipt does not. */
    for (i = 0; i < 2; i++) {
        size_t path_len = 0;
        rc = ants_reputation_bag_prove(g_bag, 4, i, paths[i], sizeof paths[i], &path_len);
        if (rc != ANTS_OK) {
            die("bag_prove(audit)", rc);
        }
        openings[i].receipt = g_bag[i];
        openings[i].index = i;
        openings[i].path = paths[i];
        openings[i].path_len = path_len;
    }
    rc = ants_reputation_summary_audit_bucket(&s, 0, openings, 2, 4, &g_params, &ok);
    if (rc != ANTS_OK) {
        die("summary_audit_bucket(full)", rc);
    }
    if (!ok) {
        die_verdict("summary_audit_bucket(full)");
    }
    printf("  \"summary_audit_vectors\": [\n");
    printf("    {\"audited_bucket_index\": 0, \"openings\": \"leaf indices 0 and 1 with their "
           "inclusion paths\", \"audit_passes\": true},\n");

    rc = ants_reputation_summary_audit_bucket(&s, 0, openings, 1, 4, &g_params, &ok);
    if (rc != ANTS_OK) {
        die("summary_audit_bucket(withheld)", rc);
    }
    if (ok) {
        fprintf(stderr, "identity_vectors: withheld audit unexpectedly passed\n");
        exit(1);
    }
    printf("    {\"audited_bucket_index\": 0, \"openings\": \"leaf index 0 only (64 < the "
           "stated 192)\", \"audit_passes\": false}\n");
    printf("  ]\n");
}

/* ------------------------------------------------------------------------ */

int main(void)
{
    init_fixtures();

    printf("{\n");
    printf("  \"primitive\": \"reputation-identity selective disclosure: countersigned "
           "receipts, receipt-bag commitment + inclusion, (A, T) computation, A >= b proof, "
           "compact summary + per-bucket audit\",\n");
    printf("  \"spec\": \"RFC-0008 v0.7 \\u00a711.9 + \\u00a74.1 "
           "(ants-v1-receipt-bag-root); RFC-0004 v0.7 \\u00a7Selective disclosure of receipts "
           "+ \\u00a7Compact summaries for large peers\",\n");
    printf("  \"version\": 1,\n");
    printf("  \"generator\": \"ants-client reputation/identity/tools/identity_vectors.c - "
           "every value below is emitted by the compiled ants_reputation library, never "
           "transcribed by hand (RFC-0008 \\u00a78); every proof, signature, and verdict was "
           "re-verified through the library before printing\",\n");
    printf("  \"notes\": \"Canonical CBOR per RFC-0008 \\u00a71.1; hex lowercase. Private keys "
           "and nonces are repeated-byte patterns for cross-language reproducibility; Ed25519 "
           "signing (RFC 8032) is deterministic, so the signatures are stable vectors. The "
           "decay/kappa parameters are the reference client's DRAFT defaults - b2-class, NOT "
           "calibrated (RFC-0004 \\u00a7835) - so these vectors pin the RECIPE, and will be "
           "re-emitted with a version bump when calibration lands.\",\n");

    emit_keys();
    emit_receipts();
    emit_bag();
    emit_compute();
    emit_bound();
    emit_summary();

    printf("}\n");
    return 0;
}
