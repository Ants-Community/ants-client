/*
 * test_crdt.c — Tests for Layer 1, the consensus-free fault G-Set
 * (Component #7): the self-authenticating fault proof.
 *
 * Covers the statement + fault-proof canonical-CBOR codecs, the BLAKE3
 * content-address, VERIFY(π) for the equivocation and invalid-transition
 * fault classes, and the G-Set container. Statements and block
 * attestations are signed with REAL Ed25519 keys so verification is
 * exercised end-to-end, not mocked; the invalid-transition tests build
 * REAL L2 blocks with the reputation/chain encoders
 * (ants_chain_confirmed_{root,prove}, the block codec), which is what
 * pins crdt.c's restated Merkle/block mirror bit-for-bit against the L2
 * implementation. The negative paths assert the precise typed verdict
 * the header promises (a same-payload "proof" is MALFORMED, an unknown
 * class is UNSUPPORTED_TYPE, etc.), and a byte-flip sweep asserts
 * tamper-detection independently of the impl's internals.
 */

#include "ants_cbor.h"
#include "ants_chain.h"
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

    /* INVALID_TRANSITION is implemented now: an empty evidence array is a
     * shape violation of its array(6) schema → MALFORMED (it used to be
     * NOT_IMPLEMENTED while the class was reserved). */
    CHECK_EQ(
        build_envelope_ftype(subj_pub, ANTS_FAULT_INVALID_TRANSITION, 100, env, sizeof env, &len),
        ANTS_OK);
    CHECK_EQ(ants_crdt_verify(env, len), ANTS_ERROR_MALFORMED);

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

/* ===== invalid-transition: fabrication made attributable ================== */
/* These tests build REAL L2 blocks with the reputation/chain encoders and
 * REAL Ed25519 attestations over the block hash, so crdt.c's restated
 * Merkle fold and block walk are cross-checked bit-for-bit against
 * ants_chain_confirmed_{root,prove} and the chain block codec. */

/* memcmp comparator over bare 32-byte content-ids (ascending — the
 * confirmed_root canonical order). */
static int cmp_content_id(const void *a, const void *b)
{
    return memcmp(a, b, ANTS_CRDT_CONTENT_ID_SIZE);
}

/* A junk leaf: preimage bytes + their content-id, sortable by id. */
typedef struct {
    uint8_t bytes[24];
    uint8_t id[32];
} it_leaf_t;

static int cmp_it_leaf(const void *a, const void *b)
{
    return memcmp(((const it_leaf_t *)a)->id, ((const it_leaf_t *)b)->id, 32);
}

/* Build a REAL chain block committing `ids` (strictly ascending) under
 * `epoch`, attest it with `signer_priv` (Ed25519 over the block hash — the
 * exact reputation/chain finality message), and return the canonical block
 * bytes + the attestation. Also pins block_hash == BLAKE3(block bytes), the
 * equivalence crdt.c's verifier recomputes from the evidence side. */
static void build_attested_block(const uint8_t (*ids)[32],
                                 size_t n_ids,
                                 uint64_t epoch,
                                 bool degraded,
                                 int with_finding,
                                 const uint8_t signer_priv[32],
                                 uint8_t *block,
                                 size_t block_cap,
                                 size_t *block_len,
                                 uint8_t sig[64])
{
    ants_chain_block_t b;
    ants_chain_pattern_finding_t f;
    uint8_t bh[32], bh2[32];

    memset(&b, 0, sizeof b);
    b.height = 7;
    memset(b.prev_block_hash, 0xAB, sizeof b.prev_block_hash);
    b.degraded_seed = degraded;
    b.summary.epoch = epoch;
    b.summary.cutoff_time = 1234567;
    CHECK_EQ(ants_chain_confirmed_root(ids, n_ids, b.summary.confirmed_proofs), ANTS_OK);
    if (with_finding) {
        memset(&f, 0, sizeof f);
        memset(f.subject, 0x77, sizeof f.subject);
        f.rule_id = ANTS_CHAIN_RULE_FAULT_COUNT_30D;
        f.window_s = ANTS_CHAIN_PATTERN_WINDOW_S;
        f.count = 3;
        f.severity = ANTS_CHAIN_SEVERITY_MEDIUM;
        b.summary.findings = &f;
        b.summary.n_findings = 1;
    }
    CHECK_EQ(ants_chain_block_encode(&b, block, block_cap, block_len), ANTS_OK);
    CHECK_EQ(ants_chain_block_hash(&b, bh), ANTS_OK);
    CHECK_EQ(ants_blake3_hash(block, *block_len, bh2), ANTS_OK);
    CHECK(memcmp(bh, bh2, sizeof bh) == 0);
    CHECK_EQ(ants_ed25519_sign(signer_priv, bh, sizeof bh, sig), ANTS_OK);
}

/* Assemble a full invalid-transition proof citing `cited` as leaf
 * `cited_idx` of the `ids` set, with the REAL chain inclusion path. */
static size_t make_it_proof(const uint8_t signer_pub[32],
                            uint64_t epoch,
                            const uint8_t *block,
                            size_t block_len,
                            const uint8_t sig[64],
                            const uint8_t (*ids)[32],
                            size_t n_ids,
                            size_t cited_idx,
                            const uint8_t *cited,
                            size_t cited_len,
                            uint8_t *proof,
                            size_t proof_cap)
{
    uint8_t path[8 * 32];
    size_t path_len = 0, plen = 0;

    CHECK_EQ(ants_chain_confirmed_prove(ids, n_ids, cited_idx, path, sizeof path, &path_len),
             ANTS_OK);
    CHECK_EQ(ants_crdt_invalid_transition_encode(signer_pub,
                                                 epoch,
                                                 block,
                                                 block_len,
                                                 sig,
                                                 cited,
                                                 cited_len,
                                                 (uint64_t)cited_idx,
                                                 (uint64_t)n_ids,
                                                 path,
                                                 path_len,
                                                 proof,
                                                 proof_cap,
                                                 &plen),
             ANTS_OK);
    return plen;
}

/* Hand-roll an invalid-transition envelope with full control of the
 * evidence values (the public encoder guards the obviously-invalid ones).
 * `n_elems` truncates the evidence array to its first n elements. */
static ants_error_t build_it_raw(const uint8_t subject[32],
                                 uint64_t epoch,
                                 size_t n_elems,
                                 const uint8_t *block,
                                 size_t block_len,
                                 const uint8_t *sig,
                                 size_t sig_len,
                                 const uint8_t *cited,
                                 size_t cited_len,
                                 uint64_t index,
                                 uint64_t n_leaves,
                                 const uint8_t *path,
                                 size_t path_len,
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
        (rc = ants_cbor_enc_uint(&enc, ANTS_FAULT_INVALID_TRANSITION)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 2)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, epoch)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, 3)) != ANTS_OK ||
        (rc = ants_cbor_enc_array(&enc, n_elems)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 1 && (rc = ants_cbor_enc_bytes(&enc, block, block_len)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 2 && (rc = ants_cbor_enc_bytes(&enc, sig, sig_len)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 3 && (rc = ants_cbor_enc_bytes(&enc, cited, cited_len)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 4 && (rc = ants_cbor_enc_uint(&enc, index)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 5 && (rc = ants_cbor_enc_uint(&enc, n_leaves)) != ANTS_OK) {
        return rc;
    }
    if (n_elems >= 6 && (rc = ants_cbor_enc_bytes(&enc, path, path_len)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* The full fabrication flow: a signer attests a block whose confirmed set
 * commits junk bytes that are not a valid fault proof. The proof verifies,
 * is insertable, and slashes the SIGNER (not the junk's nominal author). */
static void test_invalid_transition_verifies(void)
{
    uint8_t signer_priv[32], signer_pub[32], eq_priv[32], eq_pub[32];
    uint8_t valid_eq[512];
    uint8_t junk[24];
    uint8_t jid[32];
    uint8_t ids[2][32];
    uint8_t block[512], sig[64], proof[1536];
    size_t eq_len, block_len = 0, plen, junk_idx;
    ants_fault_proof_view_t v;
    ants_crdt_t *set = NULL;
    bool inserted = false;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, eq_priv, eq_pub);

    /* The committed set: one REAL equivocation proof + junk bytes. */
    eq_len = make_valid_proof(eq_priv, eq_pub, 100, valid_eq);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(valid_eq, eq_len, ids[0]), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids[1]), ANTS_OK);
    qsort(ids, 2, sizeof ids[0], cmp_content_id);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, jid), ANTS_OK);
    junk_idx = (memcmp(ids[0], jid, 32) == 0) ? 0 : 1;

    build_attested_block(ids, 2, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(signer_pub,
                         500,
                         block,
                         block_len,
                         sig,
                         ids,
                         2,
                         junk_idx,
                         junk,
                         sizeof junk,
                         proof,
                         sizeof proof);

    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);

    /* The decoded view exposes the right envelope fields. */
    CHECK_EQ(ants_crdt_fault_proof_decode(proof, plen, &v), ANTS_OK);
    CHECK(v.fault_type == ANTS_FAULT_INVALID_TRANSITION);
    CHECK(v.epoch == 500);
    CHECK(memcmp(v.subject, signer_pub, 32) == 0);

    /* Insertable into the G-Set; the SIGNER is the slashed subject. */
    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &inserted), ANTS_OK);
    CHECK(inserted == true);
    CHECK(ants_crdt_is_slashed(set, signer_pub) == true);
    CHECK(ants_crdt_is_slashed(set, eq_pub) == false);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &inserted), ANTS_OK);
    CHECK(inserted == false); /* content-id dedupe */
    ants_crdt_destroy(set);

    /* A single-leaf set (empty Merkle path) in a degraded-seed block with a
     * findings entry exercises the remaining wire shapes end-to-end. */
    {
        uint8_t ids1[1][32];
        memcpy(ids1[0], jid, 32);
        build_attested_block(
            ids1, 1, 501, true, 1, signer_priv, block, sizeof block, &block_len, sig);
        plen = make_it_proof(signer_pub,
                             501,
                             block,
                             block_len,
                             sig,
                             ids1,
                             1,
                             0,
                             junk,
                             sizeof junk,
                             proof,
                             sizeof proof);
        CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);
    }
}

/* Citing a leaf whose bytes ARE a valid fault proof is no fabrication —
 * the accusation itself is malformed. */
static void test_invalid_transition_unfounded(void)
{
    uint8_t signer_priv[32], signer_pub[32], eq_priv[32], eq_pub[32];
    uint8_t valid_eq[512];
    uint8_t junk[24];
    uint8_t eqid[32];
    uint8_t ids[2][32];
    uint8_t block[512], sig[64], proof[1536];
    size_t eq_len, block_len = 0, plen, eq_idx;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, eq_priv, eq_pub);

    eq_len = make_valid_proof(eq_priv, eq_pub, 100, valid_eq);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(valid_eq, eq_len, ids[0]), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids[1]), ANTS_OK);
    qsort(ids, 2, sizeof ids[0], cmp_content_id);
    CHECK_EQ(ants_crdt_content_id(valid_eq, eq_len, eqid), ANTS_OK);
    eq_idx = (memcmp(ids[0], eqid, 32) == 0) ? 0 : 1;

    build_attested_block(ids, 2, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(signer_pub,
                         500,
                         block,
                         block_len,
                         sig,
                         ids,
                         2,
                         eq_idx,
                         valid_eq,
                         eq_len,
                         proof,
                         sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

/* The realistic fabrications: a plausible-looking citation whose invalidity
 * is subtle (a correctly-signed same-payload "equivocation") and a
 * non-canonical one. Both are permanent invalidity → the fault stands. */
static void test_invalid_transition_subtle_citations(void)
{
    uint8_t signer_priv[32], signer_pub[32], eq_priv[32], eq_pub[32];
    uint8_t body_a[256], body_b[256], sig_a[64], sig_b[64];
    uint8_t subtle[512];
    uint8_t block[512], sig[64], proof[1536];
    uint8_t ids1[1][32];
    size_t la = 0, lb = 0, slen = 0, block_len = 0, plen;
    const uint8_t same[4] = {0x0F, 0x0E, 0x0D, 0x0C};
    /* Non-shortest uint 23 (0x18 0x17): well-formed but non-canonical. */
    const uint8_t noncanon[2] = {0x18, 0x17};

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, eq_priv, eq_pub);

    /* Correctly signed, canonical, same payload — VERIFY says MALFORMED, so
     * committing it as a "fault proof" is fabrication. */
    sign_statement(9, 100, 3, same, sizeof same, eq_priv, body_a, &la, sig_a);
    sign_statement(9, 100, 3, same, sizeof same, eq_priv, body_b, &lb, sig_b);
    CHECK_EQ(ants_crdt_equivocation_encode(
                 eq_pub, 100, body_a, la, sig_a, body_b, lb, sig_b, subtle, sizeof subtle, &slen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(subtle, slen), ANTS_ERROR_MALFORMED);

    CHECK_EQ(ants_crdt_content_id(subtle, slen, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 600, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(
        signer_pub, 600, block, block_len, sig, ids1, 1, 0, subtle, slen, proof, sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);

    /* A non-canonical citation (NON_CANONICAL is also permanent). */
    CHECK_EQ(ants_crdt_content_id(noncanon, sizeof noncanon, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 601, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(signer_pub,
                         601,
                         block,
                         block_len,
                         sig,
                         ids1,
                         1,
                         0,
                         noncanon,
                         sizeof noncanon,
                         proof,
                         sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);
}

/* The envelope's epoch must equal the block summary's epoch. */
static void test_invalid_transition_wrong_epoch(void)
{
    uint8_t signer_priv[32], signer_pub[32];
    uint8_t junk[24];
    uint8_t ids1[1][32];
    uint8_t block[512], sig[64], proof[1536];
    size_t block_len = 0, plen;

    make_key(0x21, signer_priv, signer_pub);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids1[0]), ANTS_OK);

    build_attested_block(ids1, 1, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    /* Envelope says 501, the attested summary says 500. */
    plen = make_it_proof(
        signer_pub, 501, block, block_len, sig, ids1, 1, 0, junk, sizeof junk, proof, sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

/* The attestation must be the subject's signature over THIS block's hash. */
static void test_invalid_transition_bad_signature(void)
{
    uint8_t signer_priv[32], signer_pub[32], other_priv[32], other_pub[32];
    uint8_t junk[24];
    uint8_t ids1[1][32];
    uint8_t block[512], sig[64], proof[1536];
    size_t block_len = 0, plen;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x66, other_priv, other_pub);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids1[0]), ANTS_OK);

    /* Signed by OTHER, blamed on signer_pub → not the subject's act. */
    build_attested_block(ids1, 1, 500, false, 0, other_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(
        signer_pub, 500, block, block_len, sig, ids1, 1, 0, junk, sizeof junk, proof, sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* A flipped signature byte. */
    build_attested_block(ids1, 1, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    sig[0] ^= 0x01u;
    plen = make_it_proof(
        signer_pub, 500, block, block_len, sig, ids1, 1, 0, junk, sizeof junk, proof, sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

/* The inclusion fold must reproduce the committed root. */
static void test_invalid_transition_wrong_path(void)
{
    uint8_t signer_priv[32], signer_pub[32], eq_priv[32], eq_pub[32];
    uint8_t valid_eq[512];
    uint8_t junk[24];
    uint8_t jid[32];
    uint8_t ids[2][32];
    uint8_t block[512], sig[64], proof[1536];
    uint8_t path[8 * 32];
    size_t eq_len, block_len = 0, plen = 0, path_len = 0, junk_idx;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, eq_priv, eq_pub);
    eq_len = make_valid_proof(eq_priv, eq_pub, 100, valid_eq);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(valid_eq, eq_len, ids[0]), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids[1]), ANTS_OK);
    qsort(ids, 2, sizeof ids[0], cmp_content_id);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, jid), ANTS_OK);
    junk_idx = (memcmp(ids[0], jid, 32) == 0) ? 0 : 1;

    build_attested_block(ids, 2, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);

    /* A REAL path with one flipped byte no longer folds to the root. */
    CHECK_EQ(ants_chain_confirmed_prove(ids, 2, junk_idx, path, sizeof path, &path_len), ANTS_OK);
    path[0] ^= 0x01u;
    CHECK_EQ(ants_crdt_invalid_transition_encode(signer_pub,
                                                 500,
                                                 block,
                                                 block_len,
                                                 sig,
                                                 junk,
                                                 sizeof junk,
                                                 (uint64_t)junk_idx,
                                                 2,
                                                 path,
                                                 path_len,
                                                 proof,
                                                 sizeof proof,
                                                 &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* The junk bytes presented at the OTHER leaf's position. */
    plen = make_it_proof(signer_pub,
                         500,
                         block,
                         block_len,
                         sig,
                         ids,
                         2,
                         1 - junk_idx,
                         junk,
                         sizeof junk,
                         proof,
                         sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
}

/* No nesting: a cited proof of class INVALID_TRANSITION is malformed
 * evidence regardless of its own validity — the structural recursion
 * bound. (Its cost, stated honestly: committing an invalid
 * invalid-transition proof is real fabrication this class cannot cite;
 * that case stays detectable-but-not-attributable, like omission.) */
static void test_invalid_transition_no_nesting(void)
{
    uint8_t signer_priv[32], signer_pub[32], eq_priv[32], eq_pub[32];
    uint8_t valid_eq[512];
    uint8_t junk[24];
    uint8_t jid[32];
    uint8_t ids[2][32];
    uint8_t ids1[1][32];
    uint8_t block[512], sig[64];
    uint8_t inner[1536], outer[2560];
    uint8_t bad_it[128];
    size_t eq_len, block_len = 0, inner_len, outer_len, bad_len = 0, junk_idx;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, eq_priv, eq_pub);

    /* A VALID invalid-transition proof (same flow as the happy test). */
    eq_len = make_valid_proof(eq_priv, eq_pub, 100, valid_eq);
    memset(junk, 0xD7, sizeof junk);
    CHECK_EQ(ants_crdt_content_id(valid_eq, eq_len, ids[0]), ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids[1]), ANTS_OK);
    qsort(ids, 2, sizeof ids[0], cmp_content_id);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, jid), ANTS_OK);
    junk_idx = (memcmp(ids[0], jid, 32) == 0) ? 0 : 1;
    build_attested_block(ids, 2, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    inner_len = make_it_proof(signer_pub,
                              500,
                              block,
                              block_len,
                              sig,
                              ids,
                              2,
                              junk_idx,
                              junk,
                              sizeof junk,
                              inner,
                              sizeof inner);
    CHECK_EQ(ants_crdt_verify(inner, inner_len), ANTS_OK);

    /* A second block commits the (valid) inner proof; citing it is
     * MALFORMED by the nesting bound, not an admission. */
    CHECK_EQ(ants_crdt_content_id(inner, inner_len, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 700, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    outer_len = make_it_proof(
        signer_pub, 700, block, block_len, sig, ids1, 1, 0, inner, inner_len, outer, sizeof outer);
    CHECK_EQ(ants_crdt_verify(outer, outer_len), ANTS_ERROR_MALFORMED);

    /* Same bound when the cited invalid-transition proof is INVALID (an
     * empty-evidence envelope): still MALFORMED, decided before any
     * recursive verdict. */
    CHECK_EQ(build_envelope_ftype(
                 eq_pub, ANTS_FAULT_INVALID_TRANSITION, 700, bad_it, sizeof bad_it, &bad_len),
             ANTS_OK);
    CHECK_EQ(ants_crdt_content_id(bad_it, bad_len, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 700, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    outer_len = make_it_proof(
        signer_pub, 700, block, block_len, sig, ids1, 1, 0, bad_it, bad_len, outer, sizeof outer);
    CHECK_EQ(ants_crdt_verify(outer, outer_len), ANTS_ERROR_MALFORMED);
}

/* A cited class this build cannot judge is a typed "don't know" — never a
 * slash, and the G-Set refuses the proof with the same verdict. */
static void test_invalid_transition_unknown_cited_class(void)
{
    uint8_t signer_priv[32], signer_pub[32], some_pub[32], some_priv[32];
    uint8_t future[128];
    uint8_t ids1[1][32];
    uint8_t block[512], sig[64], proof[1536];
    size_t future_len = 0, block_len = 0, plen;
    ants_crdt_t *set = NULL;
    bool inserted = true;

    make_key(0x21, signer_priv, signer_pub);
    make_key(0x42, some_priv, some_pub);

    /* A canonical envelope of unassigned class 7 — valid to a future build,
     * unknowable to this one. */
    CHECK_EQ(build_envelope_ftype(some_pub, 7, 800, future, sizeof future, &future_len), ANTS_OK);
    CHECK_EQ(ants_crdt_verify(future, future_len), ANTS_ERROR_UNSUPPORTED_TYPE);

    CHECK_EQ(ants_crdt_content_id(future, future_len, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 800, false, 0, signer_priv, block, sizeof block, &block_len, sig);
    plen = make_it_proof(signer_pub,
                         800,
                         block,
                         block_len,
                         sig,
                         ids1,
                         1,
                         0,
                         future,
                         future_len,
                         proof,
                         sizeof proof);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_NOT_IMPLEMENTED);

    CHECK_EQ(ants_crdt_init(&set), ANTS_OK);
    CHECK_EQ(ants_crdt_insert(set, proof, plen, &inserted), ANTS_ERROR_NOT_IMPLEMENTED);
    CHECK(inserted == false);
    CHECK(ants_crdt_size(set) == 0);
    ants_crdt_destroy(set);
}

/* Evidence shape violations are MALFORMED (each via the raw builder, with
 * an otherwise-genuine block + attestation so only the probed field is
 * wrong). */
static void test_invalid_transition_evidence_shapes(void)
{
    uint8_t signer_priv[32], signer_pub[32];
    uint8_t junk[24];
    uint8_t ids1[1][32];
    uint8_t block[512], sig[64], proof[1536];
    uint8_t path32[32];
    size_t block_len = 0, plen = 0;

    make_key(0x21, signer_priv, signer_pub);
    memset(junk, 0xD7, sizeof junk);
    memset(path32, 0x11, sizeof path32);
    CHECK_EQ(ants_crdt_content_id(junk, sizeof junk, ids1[0]), ANTS_OK);
    build_attested_block(ids1, 1, 500, false, 0, signer_priv, block, sizeof block, &block_len, sig);

    /* Five evidence elements instead of six. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          5,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          0,
                          1,
                          NULL,
                          0,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* A 63-byte signature. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          63,
                          junk,
                          sizeof junk,
                          0,
                          1,
                          NULL,
                          0,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* Empty cited bytes. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          0,
                          0,
                          1,
                          NULL,
                          0,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* n_leaves == 0. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          0,
                          0,
                          NULL,
                          0,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* index >= n_leaves. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          2,
                          2,
                          path32,
                          sizeof path32,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* n_leaves beyond the chain's max Merkle depth (2^32 + 1). */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          0,
                          ((uint64_t)1 << 32) + 1,
                          path32,
                          sizeof path32,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* A path where (index 0, n 1) requires none. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          block,
                          block_len,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          0,
                          1,
                          path32,
                          sizeof path32,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* Bytes that are not a chain block at all. */
    CHECK_EQ(build_it_raw(signer_pub,
                          500,
                          6,
                          junk,
                          sizeof junk,
                          sig,
                          64,
                          junk,
                          sizeof junk,
                          0,
                          1,
                          NULL,
                          0,
                          proof,
                          sizeof proof,
                          &plen),
             ANTS_OK);
    CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);

    /* Wrong element types: six uints. */
    {
        ants_cbor_enc_t enc;
        size_t i;
        CHECK_EQ(ants_cbor_enc_init(&enc, proof, sizeof proof), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_map(&enc, 4), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 0), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_bytes(&enc, signer_pub, 32), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 1), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, ANTS_FAULT_INVALID_TRANSITION), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 2), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 500), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_uint(&enc, 3), ANTS_OK);
        CHECK_EQ(ants_cbor_enc_array(&enc, 6), ANTS_OK);
        for (i = 0; i < 6; i++) {
            CHECK_EQ(ants_cbor_enc_uint(&enc, 0), ANTS_OK);
        }
        CHECK_EQ(ants_cbor_enc_finalise(&enc), ANTS_OK);
        plen = ants_cbor_enc_size(&enc);
        CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_ERROR_MALFORMED);
    }
}

/* Encoder argument guards. */
static void test_invalid_transition_encoder_guards(void)
{
    uint8_t subject[32], block[8], sig[64], cited[8], path[32], buf[256];
    uint8_t small[16];
    size_t out_len = 0;

    memset(subject, 0x01, sizeof subject);
    memset(block, 0x02, sizeof block);
    memset(sig, 0x03, sizeof sig);
    memset(cited, 0x04, sizeof cited);
    memset(path, 0x05, sizeof path);

    CHECK_EQ(ants_crdt_invalid_transition_encode(NULL,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 NULL,
                                                 0,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 NULL,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 NULL,
                                                 0,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 32,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 0,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 1,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 NULL,
                                                 sizeof buf,
                                                 &out_len),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 buf,
                                                 sizeof buf,
                                                 NULL),
             ANTS_ERROR_INVALID_ARG);
    CHECK_EQ(ants_crdt_invalid_transition_encode(subject,
                                                 1,
                                                 block,
                                                 sizeof block,
                                                 sig,
                                                 cited,
                                                 sizeof cited,
                                                 0,
                                                 1,
                                                 NULL,
                                                 0,
                                                 small,
                                                 sizeof small,
                                                 &out_len),
             ANTS_ERROR_BUFFER_TOO_SMALL);
}

/* Every small tree shape (incl. odd counts → promote-lone levels), every
 * leaf position: a proof built with the REAL chain prover must verify
 * against crdt.c's restated fold. This is the bit-for-bit pin between the
 * two Merkle constructions. */
static void test_invalid_transition_merkle_cross_check(void)
{
    uint8_t signer_priv[32], signer_pub[32];
    uint8_t block[512], sig[64], proof[1536];
    uint8_t ids[8][32];
    it_leaf_t leaves[8];
    size_t block_len = 0, n, i;

    make_key(0x33, signer_priv, signer_pub);

    for (n = 1; n <= 8; n++) {
        for (i = 0; i < n; i++) {
            memset(leaves[i].bytes, (int)(0x40u + i), sizeof leaves[i].bytes);
            leaves[i].bytes[0] = (uint8_t)n; /* distinct across set sizes too */
            CHECK_EQ(ants_crdt_content_id(leaves[i].bytes, sizeof leaves[i].bytes, leaves[i].id),
                     ANTS_OK);
        }
        qsort(leaves, n, sizeof leaves[0], cmp_it_leaf);
        for (i = 0; i < n; i++) {
            memcpy(ids[i], leaves[i].id, 32);
        }
        build_attested_block(
            ids, n, 900 + n, false, 0, signer_priv, block, sizeof block, &block_len, sig);
        for (i = 0; i < n; i++) {
            size_t plen = make_it_proof(signer_pub,
                                        900 + n,
                                        block,
                                        block_len,
                                        sig,
                                        ids,
                                        n,
                                        i,
                                        leaves[i].bytes,
                                        sizeof leaves[i].bytes,
                                        proof,
                                        sizeof proof);
            CHECK_EQ(ants_crdt_verify(proof, plen), ANTS_OK);
        }
    }
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

    test_invalid_transition_verifies();
    test_invalid_transition_unfounded();
    test_invalid_transition_subtle_citations();
    test_invalid_transition_wrong_epoch();
    test_invalid_transition_bad_signature();
    test_invalid_transition_wrong_path();
    test_invalid_transition_no_nesting();
    test_invalid_transition_unknown_cited_class();
    test_invalid_transition_evidence_shapes();
    test_invalid_transition_encoder_guards();
    test_invalid_transition_merkle_cross_check();

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
