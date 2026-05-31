/*
 * test_crdt.c — Tests for Layer 1, the consensus-free fault G-Set
 * (Component #7 PR1): the self-authenticating fault proof.
 *
 * Covers the statement + equivocation-proof canonical-CBOR codec, the
 * BLAKE3 content-address, and VERIFY(π) for the equivocation fault class.
 * Statements are signed with REAL Ed25519 keys so verification is
 * exercised end-to-end, not mocked. The negative paths assert the precise
 * typed verdict the header promises (a same-payload "proof" is MALFORMED,
 * an unknown class is UNSUPPORTED_TYPE, etc.), and a byte-flip sweep
 * asserts tamper-detection independently of the impl's internals.
 */

#include "ants_cbor.h"
#include "ants_common.h"
#include "ants_crdt.h"
#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
                    "FAIL %s:%d  expected %s (%d), got %s (%d)\n",                                 \
                    __FILE__,                                                                      \
                    __LINE__,                                                                      \
                    ants_strerror(_e),                                                             \
                    (int)_e,                                                                       \
                    ants_strerror(_a),                                                             \
                    (int)_a);                                                                      \
        }                                                                                          \
    } while (0)

/* ---- helpers -------------------------------------------------------- */

static void make_key(uint8_t seed, uint8_t priv[32], uint8_t pub[32])
{
    memset(priv, seed, 32);
    CHECK_EQ(ants_ed25519_pubkey_from_priv(priv, pub), ANTS_OK);
}

/* Encode a statement, sign it with `signer_priv`, return body + sig. */
static void sign_statement(uint64_t domain,
                           uint64_t epoch,
                           uint64_t slot,
                           const uint8_t *payload,
                           size_t payload_len,
                           const uint8_t signer_priv[32],
                           uint8_t body[256],
                           size_t *body_len,
                           uint8_t sig[64])
{
    CHECK_EQ(
        ants_crdt_statement_encode(domain, epoch, slot, payload, payload_len, body, 256, body_len),
        ANTS_OK);
    CHECK_EQ(ants_ed25519_sign(signer_priv, body, *body_len, sig), ANTS_OK);
}

/* Build a canonical fault-proof envelope with an arbitrary fault_type and
 * an empty evidence array — used to exercise the fault_type dispatch
 * (unknown class / not-implemented class) where evidence is never read. */
static ants_error_t build_envelope_ftype(const uint8_t subject[32],
                                         uint64_t fault_type,
                                         uint64_t epoch,
                                         uint8_t *buf,
                                         size_t cap,
                                         size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;
    if ((rc = ants_cbor_enc_init(&enc, buf, cap)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_map(&enc, 4)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 0)) != ANTS_OK ||
        (rc = ants_cbor_enc_bytes(&enc, subject, 32)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 1)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, fault_type)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 2)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, epoch)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 3)) != ANTS_OK ||
        (rc = ants_cbor_enc_array(&enc, 0)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* A canonical, valid equivocation proof: subject signed two statements
 * over the same (domain=9, epoch, slot=3) with different payloads. */
static size_t make_valid_proof(const uint8_t subj_priv[32],
                               const uint8_t subj_pub[32],
                               uint64_t epoch,
                               uint8_t proof[512])
{
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    const uint8_t pa[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint8_t pb[4] = {0x11, 0x22, 0x33, 0x44};

    sign_statement(9, epoch, 3, pa, sizeof pa, subj_priv, body_a, &la, sig_a);
    sign_statement(9, epoch, 3, pb, sizeof pb, subj_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, epoch, body_a, la, sig_a, body_b, lb, sig_b, proof, 512, &plen),
             ANTS_OK);
    return plen;
}

/* ---- tests ---------------------------------------------------------- */

static void test_statement_encode_canonical(void)
{
    uint8_t body[256];
    size_t len = 0;
    const uint8_t payload[3] = {1, 2, 3};
    CHECK_EQ(
        ants_crdt_statement_encode(9, 100, 3, payload, sizeof payload, body, sizeof body, &len),
        ANTS_OK);
    CHECK(len > 0);
    /* The body must itself be canonical CBOR (it is a signed message). */
    CHECK_EQ(ants_cbor_is_canonical(body, len), ANTS_OK);

    /* Empty payload is legal. */
    CHECK_EQ(ants_crdt_statement_encode(0, 0, 0, NULL, 0, body, sizeof body, &len), ANTS_OK);
    CHECK_EQ(ants_cbor_is_canonical(body, len), ANTS_OK);

    /* NULL payload with non-zero len is rejected. */
    CHECK_EQ(ants_crdt_statement_encode(0, 0, 0, NULL, 4, body, sizeof body, &len),
             ANTS_ERROR_INVALID_ARG);
    /* Too-small buffer reports BUFFER_TOO_SMALL, not a crash. */
    CHECK_EQ(ants_crdt_statement_encode(9, 100, 3, payload, sizeof payload, body, 2, &len),
             ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_valid_equivocation_verifies(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t proof[512];
    size_t plen;
    make_key(0x42, subj_priv, subj_pub);
    plen = make_valid_proof(subj_priv, subj_pub, 100, proof);

    /* The proof is canonical and VERIFY accepts it. */
    CHECK_EQ(ants_cbor_is_canonical(proof, plen), ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);
}

static void test_decode_view(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t proof[512];
    size_t plen;
    ants_fault_proof_view_t v;
    make_key(0x07, subj_priv, subj_pub);
    plen = make_valid_proof(subj_priv, subj_pub, 777, proof);

    CHECK_EQ(ants_crdt_fault_proof_decode(proof, plen, &v), ANTS_OK);
    CHECK(v.fault_type == ANTS_FAULT_EQUIVOCATION);
    CHECK(v.epoch == 777);
    CHECK(memcmp(v.subject, subj_pub, 32) == 0);
    CHECK(v.evidence_len > 0);
    CHECK(v.evidence >= proof && v.evidence < proof + plen);
}

static void test_content_id_stable_and_distinct(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t proof1[512], proof2[512];
    size_t l1, l2;
    uint8_t id1[32], id2[32], id3[32];
    make_key(0x55, subj_priv, subj_pub);

    /* Same logical proof encoded twice → identical bytes → identical id. */
    l1 = make_valid_proof(subj_priv, subj_pub, 100, proof1);
    l2 = make_valid_proof(subj_priv, subj_pub, 100, proof2);
    CHECK(l1 == l2);
    CHECK(memcmp(proof1, proof2, l1) == 0);
    CHECK_EQ(ants_crdt_content_id(proof1, l1, id1), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(proof2, l2, id2), ANTS_OK);
    CHECK(memcmp(id1, id2, 32) == 0);

    /* A different epoch → different proof → different id. */
    l2 = make_valid_proof(subj_priv, subj_pub, 101, proof2);
    CHECK_EQ(ants_crdt_content_id(proof2, l2, id3), ANTS_OK);
    CHECK(memcmp(id1, id3, 32) != 0);

    CHECK_EQ(ants_crdt_content_id(NULL, 4, id1), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_content_id(proof1, 0, id1), ANTS_ERROR_INVALID_ARG);
}

static void test_same_payload_is_not_a_fault(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0;
    uint8_t proof[512];
    size_t plen = 0;
    const uint8_t same[4] = {9, 9, 9, 9};
    make_key(0x42, subj_priv, subj_pub);

    /* Two honest signatures over the SAME (domain, epoch, slot, payload)
     * are not an equivocation — a peer may legitimately re-sign. */
    sign_statement(9, 100, 3, same, sizeof same, subj_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 3, same, sizeof same, subj_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

static void test_slot_and_domain_mismatch(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    uint8_t proof[512];
    const uint8_t pa[2] = {1, 2};
    const uint8_t pb[2] = {3, 4};
    make_key(0x42, subj_priv, subj_pub);

    /* Different slot → not the same commitment point → not a fault. */
    sign_statement(9, 100, 3, pa, sizeof pa, subj_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 4, pb, sizeof pb, subj_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* Different domain → statements are about different things. */
    sign_statement(9, 100, 3, pa, sizeof pa, subj_priv, body_a, &la, sig_a);
    sign_statement(8, 100, 3, pb, sizeof pb, subj_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

static void test_envelope_epoch_mismatch(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    uint8_t proof[512];
    const uint8_t pa[2] = {1, 2};
    const uint8_t pb[2] = {3, 4};
    make_key(0x42, subj_priv, subj_pub);

    /* Statements bind epoch 100, but the envelope claims epoch 101. The
     * binding cross-check (statement.epoch == envelope.epoch) must fail. */
    sign_statement(9, 100, 3, pa, sizeof pa, subj_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 3, pb, sizeof pb, subj_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 101, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

static void test_bad_and_wrong_signatures(void)
{
    uint8_t subj_priv[32], subj_pub[32], other_priv[32], other_pub[32];
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    size_t la = 0, lb = 0, plen = 0;
    uint8_t proof[512];
    const uint8_t pa[2] = {1, 2};
    const uint8_t pb[2] = {3, 4};
    make_key(0x42, subj_priv, subj_pub);
    make_key(0x99, other_priv, other_pub);

    /* A zeroed (structurally invalid) signature → not authentic → MALFORMED. */
    sign_statement(9, 100, 3, pa, sizeof pa, subj_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 3, pb, sizeof pb, subj_priv, body_b, &lb, sig_b);
    memset(sig_a, 0, sizeof sig_a);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* Statements signed by `other` but accusing `subject` → the signatures
     * are valid Ed25519 but not under the accused key → MALFORMED. */
    sign_statement(9, 100, 3, pa, sizeof pa, other_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 3, pb, sizeof pb, other_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 subj_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, proof, sizeof proof, &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

static void test_fault_type_dispatch(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t env[128];
    size_t len = 0;
    make_key(0x42, subj_priv, subj_pub);

    /* Defined-but-unimplemented class → NOT_IMPLEMENTED. */
    CHECK_EQ(
        build_envelope_ftype(subj_pub, ANTS_FAULT_INVALID_TRANSITION, 100, env, sizeof env, &len),
        ANTS_OK);
    CHECK_EQ(ants_crdt_verify(env, len), ANTS_ERROR_NOT_IMPLEMENTED);

    /* Unknown/unassigned class → UNSUPPORTED_TYPE (fail closed). */
    CHECK_EQ(build_envelope_ftype(subj_pub, 7, 100, env, sizeof env, &len), ANTS_OK);
    CHECK_EQ(ants_crdt_verify(env, len), ANTS_ERROR_UNSUPPORTED_TYPE);
}

static void test_malformed_and_noncanonical(void)
{
    ants_fault_proof_view_t v;
    /* Non-shortest uint 23 (0x18 0x17): well-formed but non-canonical. */
    const uint8_t noncanon[2] = {0x18, 0x17};
    /* A byte-string header claiming 32 bytes with only 2 present. */
    const uint8_t truncated[4] = {0x58, 0x20, 0x00, 0x00};

    CHECK_EQ(ants_crdt_verify(noncanon, sizeof noncanon), ANTS_ERROR_NON_CANONICAL);
    CHECK_EQ(ants_crdt_fault_proof_decode(noncanon, sizeof noncanon, &v), ANTS_ERROR_NON_CANONICAL);

    CHECK_EQ(ants_crdt_verify(truncated, sizeof truncated), ANTS_ERROR_MALFORMED);
    CHECK_EQ(ants_crdt_fault_proof_decode(truncated, sizeof truncated, &v), ANTS_ERROR_MALFORMED);

    /* Well-formed canonical CBOR that is not a fault-proof envelope (a bare
     * uint) → MALFORMED (wrong structure for the schema). */
    {
        const uint8_t bare_uint[1] = {0x05};
        CHECK_EQ(ants_crdt_verify(bare_uint, sizeof bare_uint), ANTS_ERROR_MALFORMED);
    }
}

static void test_null_and_empty_args(void)
{
    uint8_t buf[16];
    size_t len = 0;
    ants_fault_proof_view_t v;
    uint8_t id[32];
    uint8_t sig[64] = {0};
    uint8_t body[8] = {0};

    CHECK_EQ(ants_crdt_verify(NULL, 10), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_verify(buf, 0), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_fault_proof_decode(NULL, 10, &v), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_fault_proof_decode(buf, 10, NULL), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_content_id(NULL, 10, id), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_statement_encode(0, 0, 0, NULL, 0, NULL, 16, &len), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_equivocation_encode(NULL, 0, body, 8, sig, body, 8, sig, buf, 16, &len),
             ANTS_ERROR_INVALID_ARG);
}

/* Tamper-detection: flipping any single bit of a valid proof must make
 * VERIFY reject it — an assertion independent of the impl's internals.
 * (A flip either breaks the CBOR structure, breaks a signed body, or
 * breaks a signature; none can survive without a signature forgery.) */
static void test_single_byte_tamper_rejected(void)
{
    uint8_t subj_priv[32], subj_pub[32];
    uint8_t proof[512], tampered[512];
    size_t plen, i;
    int bit;
    make_key(0x42, subj_priv, subj_pub);
    plen = make_valid_proof(subj_priv, subj_pub, 100, proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);

    for (i = 0; i < plen; i++) {
        for (bit = 0; bit < 8; bit++) {
            memcpy(tampered, proof, plen);
            tampered[i] ^= (uint8_t)(1u << bit);
            if (memcmp(tampered, proof, plen) == 0) {
                continue;
            }
            if (ants_crdt_verify(tampered, plen) == ANTS_OK) {
                failures++;
                fprintf(stderr,
                        "FAIL %s:%d  tamper at byte %zu bit %d survived VERIFY\n",
                        __FILE__,
                        __LINE__,
                        i,
                        bit);
            }
        }
    }
}

/* ---- G-Set container tests ------------------------------------------ */

struct visit_counter {
    int seen;
    int stop_at; /* 0 = never stop early */
};

static bool visit_count_cb(const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                           const uint8_t *proof,
                           size_t len,
                           void *ctx)
{
    struct visit_counter *vc = (struct visit_counter *)ctx;
    (void)content_id;
    (void)proof;
    (void)len;
    vc->seen++;
    if (vc->stop_at != 0 && vc->seen >= vc->stop_at) {
        return false;
    }
    return true;
}

static void test_gset_init_insert_query(void)
{
    ants_crdt_t *set = NULL;
    uint8_t priv[32], pub[32], other_priv[32], other[32];
    uint8_t proof[512];
    uint8_t id[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t plen;
    bool ins = false;

    make_key(0x21, priv, pub);
    make_key(0x22, other_priv, other);

    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    CHECK(set != NULL);
    CHECK(ants_crdt_size(set) == 0);

    plen = make_valid_proof(priv, pub, 100, proof);
    CHECK_EQ(ants_crdt_content_id(proof, plen, id), ANTS_OK);

    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    CHECK(ins == true);
    CHECK(ants_crdt_size(set) == 1);
    CHECK(ants_crdt_contains(set, id) == true);
    CHECK(ants_crdt_is_slashed(set, pub) == true);
    CHECK(ants_crdt_is_slashed(set, other) == false);

    /* Idempotent: the same proof again is a no-op. */
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    CHECK(ins == false);
    CHECK(ants_crdt_size(set) == 1);

    ants_crdt_destroy(set);
}

static void test_gset_rejects_invalid(void)
{
    ants_crdt_t *set = NULL;
    uint8_t priv[32], pub[32];
    uint8_t proof[512];
    size_t plen;
    const uint8_t bare_uint[1] = {0x05};
    bool ins = true;
    ants_error_t rc;

    make_key(0x31, priv, pub);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);

    /* A tampered valid proof: a flipped byte breaks a body or a signature.
     * The exact verdict depends on where the flip lands, so assert only
     * that the proof is rejected and the set is left unchanged. */
    plen = make_valid_proof(priv, pub, 7, proof);
    proof[plen / 2] ^= 0xFF;
    ins = true;
    rc = ants_crdt_insert(set, proof, plen, &ins);
    CHECK(rc != ANTS_OK);
    CHECK(ins == false);
    CHECK(ants_crdt_size(set) == 0);

    /* Well-formed canonical CBOR that is not a fault-proof envelope. */
    ins = true;
    CHECK_EQ(ants_crdt_insert(set, bare_uint, sizeof bare_uint, &ins), ANTS_ERROR_MALFORMED);
    CHECK(ins == false);
    CHECK(ants_crdt_size(set) == 0);

    /* NULL / empty args. */
    CHECK_EQ(ants_crdt_insert(NULL, proof, plen, &ins), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_insert(set, NULL, plen, &ins), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_insert(set, proof, 0, &ins), ANTS_ERROR_INVALID_ARG);

    /* Query NULL-safety. */
    CHECK(ants_crdt_contains(NULL, NULL) == false);
    CHECK(ants_crdt_is_slashed(NULL, pub) == false);
    CHECK(ants_crdt_size(NULL) == 0);

    ants_crdt_destroy(set);
    ants_crdt_destroy(NULL); /* no-op */
}

static void test_gset_multi_subject(void)
{
    ants_crdt_t *set = NULL;
    uint8_t pa_priv[32], pa[32], pb_priv[32], pb[32], pc_priv[32], pc[32];
    uint8_t proof[512];
    size_t plen;
    bool ins;

    make_key(0x41, pa_priv, pa);
    make_key(0x42, pb_priv, pb);
    make_key(0x43, pc_priv, pc);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);

    plen = make_valid_proof(pa_priv, pa, 1, proof);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    plen = make_valid_proof(pb_priv, pb, 1, proof);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);

    CHECK(ants_crdt_size(set) == 2);
    CHECK(ants_crdt_is_slashed(set, pa) == true);
    CHECK(ants_crdt_is_slashed(set, pb) == true);
    CHECK(ants_crdt_is_slashed(set, pc) == false);

    ants_crdt_destroy(set);
}

static void test_gset_grow_and_enumerate(void)
{
    ants_crdt_t *set = NULL;
    uint8_t priv[32], pub[32];
    uint8_t proof[512], id0[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t plen, i;
    bool ins;
    struct visit_counter vc;
    const size_t N = 200;

    make_key(0x51, priv, pub);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);

    /* 200 distinct proofs (epoch varies) force several table growths from
     * the initial capacity; none may be lost or duplicated. */
    for (i = 0; i < N; i++) {
        plen = make_valid_proof(priv, pub, (uint64_t)i, proof);
        if (i == 0) {
            CHECK_EQ(ants_crdt_content_id(proof, plen, id0), ANTS_OK);
        }
        ins = false;
        CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
        CHECK(ins == true);
    }
    CHECK(ants_crdt_size(set) == N);
    CHECK(ants_crdt_contains(set, id0) == true);
    CHECK(ants_crdt_is_slashed(set, pub) == true);

    /* enumerate visits exactly N. */
    vc.seen = 0;
    vc.stop_at = 0;
    ants_crdt_enumerate(set, visit_count_cb, &vc);
    CHECK(vc.seen == (int)N);

    /* Returning false stops the walk early. */
    vc.seen = 0;
    vc.stop_at = 1;
    ants_crdt_enumerate(set, visit_count_cb, &vc);
    CHECK(vc.seen == 1);

    /* NULL-safety. */
    ants_crdt_enumerate(NULL, visit_count_cb, &vc);
    ants_crdt_enumerate(set, NULL, &vc);

    ants_crdt_destroy(set);
}

static void test_gset_merge(void)
{
    ants_crdt_t *a = NULL, *b = NULL, *empty = NULL;
    uint8_t priv[32], pub[32];
    uint8_t p1[512], p2[512], p3[512];
    size_t l1, l2, l3;
    uint8_t id1[ANTS_CRDT_CONTENT_ID_SIZE], id3[ANTS_CRDT_CONTENT_ID_SIZE];
    bool ins;

    make_key(0x61, priv, pub);
    CHECK_EQ(ants_crdt_init(&a), ANTS_OK);
    CHECK_EQ(ants_crdt_init(&b), ANTS_OK);
    CHECK_EQ(ants_crdt_init(&empty), ANTS_OK);

    l1 = make_valid_proof(priv, pub, 1, p1);
    l2 = make_valid_proof(priv, pub, 2, p2);
    l3 = make_valid_proof(priv, pub, 3, p3);
    CHECK_EQ(ants_crdt_content_id(p1, l1, id1), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(p3, l3, id3), ANTS_OK);

    /* A = {p1, p2}; B = {p2, p3} — p2 shared. */
    CHECK_EQ(ants_crdt_insert(a, p1, l1, &ins), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(a, p2, l2, &ins), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(b, p2, l2, &ins), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(b, p3, l3, &ins), ANTS_OK);

    /* Union, p2 not duplicated. */
    CHECK_EQ(ants_crdt_merge(a, b), ANTS_OK);
    CHECK(ants_crdt_size(a) == 3);
    CHECK(ants_crdt_contains(a, id1) == true);
    CHECK(ants_crdt_contains(a, id3) == true);

    /* Idempotent. */
    CHECK_EQ(ants_crdt_merge(a, b), ANTS_OK);
    CHECK(ants_crdt_size(a) == 3);

    /* Merging an empty set is a no-op; merging a non-empty into an empty
     * copies it (commutative union). */
    CHECK_EQ(ants_crdt_merge(a, empty), ANTS_OK);
    CHECK(ants_crdt_size(a) == 3);
    CHECK_EQ(ants_crdt_merge(empty, a), ANTS_OK);
    CHECK(ants_crdt_size(empty) == 3);

    /* NULL guards. */
    CHECK_EQ(ants_crdt_merge(NULL, b), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_merge(a, NULL), ANTS_ERROR_INVALID_ARG);

    ants_crdt_destroy(a);
    ants_crdt_destroy(b);
    ants_crdt_destroy(empty);
}

/* ---- pruning + snapshot tests --------------------------------------- */

static void test_gset_prune(void)
{
    ants_crdt_t *set = NULL;
    uint8_t priv[32], pub[32];
    uint8_t proof[512];
    uint8_t id1[ANTS_CRDT_CONTENT_ID_SIZE], id4[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t plen, pruned, e;
    bool ins;

    make_key(0x71, priv, pub);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);

    /* Five proofs at epochs 1..5 (distinct proofs, same subject). */
    for (e = 1; e <= 5; e++) {
        plen = make_valid_proof(priv, pub, (uint64_t)e, proof);
        if (e == 1) {
            CHECK_EQ(ants_crdt_content_id(proof, plen, id1), ANTS_OK);
        }
        if (e == 4) {
            CHECK_EQ(ants_crdt_content_id(proof, plen, id4), ANTS_OK);
        }
        CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    }
    CHECK(ants_crdt_size(set) == 5);

    /* Keep epoch >= 3: drops epochs 1 and 2. */
    pruned = 0;
    CHECK_EQ(ants_crdt_prune(set, 3, &pruned), ANTS_OK);
    CHECK(pruned == 2);
    CHECK(ants_crdt_size(set) == 3);
    CHECK(ants_crdt_contains(set, id1) == false);  /* epoch 1 gone */
    CHECK(ants_crdt_contains(set, id4) == true);   /* epoch 4 kept */
    CHECK(ants_crdt_is_slashed(set, pub) == true); /* epochs 3-5 remain */

    /* The rebuilt table still accepts inserts and dedupes. */
    plen = make_valid_proof(priv, pub, 4, proof); /* epoch 4 already present */
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &ins), ANTS_OK);
    CHECK(ins == false);
    CHECK(ants_crdt_size(set) == 3);

    /* Prune everything. */
    pruned = 0;
    CHECK_EQ(ants_crdt_prune(set, 1000, &pruned), ANTS_OK);
    CHECK(pruned == 3);
    CHECK(ants_crdt_size(set) == 0);
    CHECK(ants_crdt_is_slashed(set, pub) == false);

    /* Prune an empty set, and the NULL out-param + NULL set paths. */
    CHECK_EQ(ants_crdt_prune(set, 5, NULL), ANTS_OK);
    CHECK(ants_crdt_size(set) == 0);
    CHECK_EQ(ants_crdt_prune(NULL, 5, &pruned), ANTS_ERROR_INVALID_ARG);

    ants_crdt_destroy(set);
}

static void test_gset_snapshot_roundtrip(void)
{
    ants_crdt_t *a = NULL, *b = NULL;
    uint8_t priv[32], pub[32];
    uint8_t proof[512];
    uint8_t *snap;
    uint8_t id2[ANTS_CRDT_CONTENT_ID_SIZE];
    size_t plen, bound, slen = 0, added, rejected, i;
    bool ins;

    make_key(0x81, priv, pub);
    CHECK_EQ(ants_crdt_init(&a), ANTS_OK);
    CHECK_EQ(ants_crdt_init(&b), ANTS_OK);

    for (i = 1; i <= 3; i++) {
        plen = make_valid_proof(priv, pub, (uint64_t)i, proof);
        if (i == 2) {
            CHECK_EQ(ants_crdt_content_id(proof, plen, id2), ANTS_OK);
        }
        CHECK_EQ(ants_crdt_insert(a, proof, plen, &ins), ANTS_OK);
    }

    bound = ants_crdt_snapshot_bound(a);
    CHECK(bound > 0);
    snap = (uint8_t *)malloc(bound);
    CHECK(snap != NULL);

    CHECK_EQ(ants_crdt_snapshot_encode(a, snap, bound, &slen), ANTS_OK);
    CHECK(slen > 0 && slen <= bound);
    /* The frame is canonical CBOR (array of canonical byte-strings). */
    CHECK_EQ(ants_cbor_is_canonical(snap, slen), ANTS_OK);

    /* Import into a fresh set: all three admitted, none rejected. */
    added = rejected = 999;
    CHECK_EQ(ants_crdt_snapshot_merge(b, snap, slen, &added, &rejected), ANTS_OK);
    CHECK(added == 3);
    CHECK(rejected == 0);
    CHECK(ants_crdt_size(b) == 3);
    CHECK(ants_crdt_contains(b, id2) == true);
    CHECK(ants_crdt_is_slashed(b, pub) == true);

    /* Re-import is idempotent (dedup by content-id). */
    added = rejected = 999;
    CHECK_EQ(ants_crdt_snapshot_merge(b, snap, slen, &added, &rejected), ANTS_OK);
    CHECK(added == 0);
    CHECK(rejected == 0);
    CHECK(ants_crdt_size(b) == 3);

    /* Too-small buffer is reported, not overrun. */
    CHECK_EQ(ants_crdt_snapshot_encode(a, snap, 2, &slen), ANTS_ERROR_BUFFER_TOO_SMALL);

    free(snap);
    ants_crdt_destroy(a);
    ants_crdt_destroy(b);
}

static void test_gset_snapshot_empty(void)
{
    ants_crdt_t *a = NULL, *b = NULL;
    uint8_t snap[16];
    size_t slen = 0, added = 9, rejected = 9;

    CHECK_EQ(ants_crdt_init(&a), ANTS_OK);
    CHECK_EQ(ants_crdt_init(&b), ANTS_OK);

    CHECK_EQ(ants_crdt_snapshot_encode(a, snap, sizeof snap, &slen), ANTS_OK);
    CHECK(slen >= 1); /* at least the array(0) header */
    CHECK_EQ(ants_cbor_is_canonical(snap, slen), ANTS_OK);

    CHECK_EQ(ants_crdt_snapshot_merge(b, snap, slen, &added, &rejected), ANTS_OK);
    CHECK(added == 0);
    CHECK(rejected == 0);
    CHECK(ants_crdt_size(b) == 0);

    ants_crdt_destroy(a);
    ants_crdt_destroy(b);
}

static void test_gset_snapshot_rejects_bad(void)
{
    ants_crdt_t *set = NULL;
    uint8_t priv[32], pub[32];
    uint8_t valid[512];
    uint8_t frame[640];
    ants_cbor_enc_t enc;
    size_t vlen, flen = 0, added = 9, rejected = 9;
    const uint8_t junk[1] = {0x05};           /* canonical bytes, but not a fault proof */
    const uint8_t noncanon[2] = {0x18, 0x17}; /* well-formed, non-canonical */
    const uint8_t truncated[4] = {0x58, 0x20, 0x00, 0x00};

    make_key(0x91, priv, pub);
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    vlen = make_valid_proof(priv, pub, 1, valid);

    /* Hand-build a well-formed frame: array(2)[ bytes(valid), bytes(junk) ].
     * The frame is canonical, but the second element's content is not a
     * valid proof, so it must be skipped (rejected), the first admitted. */
    CHECK_EQ(ants_cbor_enc_init(&enc, frame, sizeof frame), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_array(&enc, 2), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, valid, vlen), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_bytes(&enc, junk, sizeof junk), ANTS_OK);
    CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
    flen = ants_cbor_enc_size(&enc);

    added = rejected = 9;
    CHECK_EQ(ants_crdt_snapshot_merge(set, frame, flen, &added, &rejected), ANTS_OK);
    CHECK(added == 1);
    CHECK(rejected == 1);
    CHECK(ants_crdt_size(set) == 1);
    CHECK(ants_crdt_is_slashed(set, pub) == true);

    /* A structurally bad frame is rejected wholesale, with the precise
     * verdict (not a per-element skip). */
    CHECK_EQ(ants_crdt_snapshot_merge(set, noncanon, sizeof noncanon, &added, &rejected),
             ANTS_ERROR_NON_CANONICAL);
    CHECK_EQ(ants_crdt_snapshot_merge(set, truncated, sizeof truncated, &added, &rejected),
             ANTS_ERROR_MALFORMED);

    /* NULL / empty guards. */
    CHECK_EQ(ants_crdt_snapshot_merge(NULL, frame, flen, &added, &rejected),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_snapshot_merge(set, NULL, flen, &added, &rejected), ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_snapshot_merge(set, frame, 0, &added, &rejected), ANTS_ERROR_INVALID_ARG);
    CHECK(ants_crdt_snapshot_bound(NULL) == 0);
    CHECK_EQ(ants_crdt_snapshot_encode(NULL, frame, sizeof frame, &flen), ANTS_ERROR_INVALID_ARG);

    ants_crdt_destroy(set);
}

int main(void)
{
    test_statement_encode_canonical();
    test_valid_equivocation_verifies();
    test_decode_view();
    test_content_id_stable_and_distinct();
    test_same_payload_is_not_a_fault();
    test_slot_and_domain_mismatch();
    test_envelope_epoch_mismatch();
    test_bad_and_wrong_signatures();
    test_fault_type_dispatch();
    test_malformed_and_noncanonical();
    test_null_and_empty_args();
    test_single_byte_tamper_rejected();

    test_gset_init_insert_query();
    test_gset_rejects_invalid();
    test_gset_multi_subject();
    test_gset_grow_and_enumerate();
    test_gset_merge();

    test_gset_prune();
    test_gset_snapshot_roundtrip();
    test_gset_snapshot_empty();
    test_gset_snapshot_rejects_bad();

    if (failures == 0) {
        printf("test_crdt: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_crdt: %d check(s) failed\n", failures);
    return 1;
}
