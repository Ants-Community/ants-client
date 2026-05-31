/*
 * crdt.c — Layer 1: the consensus-free fault G-Set (Component #7,
 * RFC-0004 v0.6 §"Layer 1 — the consensus-free fault G-Set").
 *
 * PR1: the self-authenticating fault proof. The canonical-CBOR wire
 * format (envelope + equivocation evidence), VERIFY(π) for the
 * equivocation fault class, and the BLAKE3 content-address.
 *
 * The whole proof is ONE canonical CBOR document — the equivocation
 * evidence is a native nested array, not a byte-string wrapping a
 * sub-document — so encode is a single pass and the module needs no
 * scratch buffer and no malloc (the G-Set container, a later PR, is the
 * first allocator). The two statement BODIES carried inside the evidence
 * are themselves canonical-CBOR byte-strings: opaque at the envelope
 * level (so they are reproduced verbatim as the Ed25519 message), then
 * re-decoded as statements to read (domain, epoch, slot, payload).
 *
 * VERIFY is pure, deterministic, context-free: given only the bytes it
 * returns the same verdict on every honest peer, with no external state.
 *
 * No floats, no malloc, no threads, no hidden global state.
 * Spec: RFC-0004 v0.6; RFC-0008 v0.5 §1.1 (canonical CBOR), §2.1
 * (BLAKE3), §3.1 (Ed25519).
 */

#include "ants_crdt.h"

#include "ants_cbor.h"
#include "ants_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Canonical CBOR schema (DRAFT, defined by this module — see header)        */
/*                                                                          */
/* Fault-proof envelope: map(4), integer keys ascending                     */
/*   0 subject(bytes32) 1 fault_type(uint) 2 epoch(uint) 3 evidence(array)  */
/* Equivocation evidence: array(2) of array(2) [ body(bytes), sig(bytes64) ] */
/* Statement body: map(4), integer keys ascending                           */
/*   0 domain(uint) 1 epoch(uint) 2 slot(uint) 3 payload(bytes)             */
/* ------------------------------------------------------------------------ */

enum { ENV_KEY_SUBJECT = 0, ENV_KEY_FAULT_TYPE = 1, ENV_KEY_EPOCH = 2, ENV_KEY_EVIDENCE = 3 };
#define ENV_PAIRS 4

enum { STMT_KEY_DOMAIN = 0, STMT_KEY_EPOCH = 1, STMT_KEY_SLOT = 2, STMT_KEY_PAYLOAD = 3 };
#define STMT_PAIRS  4
#define EQUIV_STMTS 2 /* an equivocation is exactly two statements */
#define EQUIV_ELEMS 2 /* each statement element is [body, sig]     */

/* ------------------------------------------------------------------------ */
/* Encode: statement body                                                   */
/* ------------------------------------------------------------------------ */

ants_error_t ants_crdt_statement_encode(uint64_t domain,
                                        uint64_t epoch,
                                        uint64_t slot,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (payload == NULL && payload_len != 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, STMT_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, STMT_KEY_DOMAIN)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, domain)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, STMT_KEY_EPOCH)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, epoch)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, STMT_KEY_SLOT)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, slot)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, STMT_KEY_PAYLOAD)) != ANTS_OK ||
        (rc = ants_cbor_enc_bytes(&enc, payload, payload_len)) != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Encode: equivocation fault proof                                         */
/* ------------------------------------------------------------------------ */

/* Emit one evidence element: array(2) [ body(bytes), sig(bytes 64) ]. */
static ants_error_t enc_stmt_element(ants_cbor_enc_t *enc,
                                     const uint8_t *body,
                                     size_t body_len,
                                     const uint8_t sig[ANTS_CRDT_SIG_SIZE])
{
    ants_error_t rc = ants_cbor_enc_array(enc, EQUIV_ELEMS);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_bytes(enc, body, body_len);
    if (rc != ANTS_OK) {
        return rc;
    }
    return ants_cbor_enc_bytes(enc, sig, ANTS_CRDT_SIG_SIZE);
}

ants_error_t ants_crdt_equivocation_encode(const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE],
                                           uint64_t epoch,
                                           const uint8_t *body_a,
                                           size_t body_a_len,
                                           const uint8_t sig_a[ANTS_CRDT_SIG_SIZE],
                                           const uint8_t *body_b,
                                           size_t body_b_len,
                                           const uint8_t sig_b[ANTS_CRDT_SIG_SIZE],
                                           uint8_t *buf,
                                           size_t cap,
                                           size_t *out_len)
{
    ants_cbor_enc_t enc;
    ants_error_t rc;

    if (subject == NULL || body_a == NULL || sig_a == NULL || body_b == NULL || sig_b == NULL ||
        buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (body_a_len == 0 || body_b_len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    rc = ants_cbor_enc_init(&enc, buf, cap);
    if (rc != ANTS_OK) {
        return rc;
    }
    rc = ants_cbor_enc_map(&enc, ENV_PAIRS);
    if (rc != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, ENV_KEY_SUBJECT)) != ANTS_OK ||
        (rc = ants_cbor_enc_bytes(&enc, subject, ANTS_CRDT_PEER_ID_SIZE)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, ENV_KEY_FAULT_TYPE)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, ANTS_FAULT_EQUIVOCATION)) != ANTS_OK) {
        return rc;
    }
    if ((rc = ants_cbor_enc_uint(&enc, ENV_KEY_EPOCH)) != ANTS_OK ||
        (rc = ants_cbor_enc_uint(&enc, epoch)) != ANTS_OK) {
        return rc;
    }
    /* key 3: evidence = array(2) of [body, sig]. */
    if ((rc = ants_cbor_enc_uint(&enc, ENV_KEY_EVIDENCE)) != ANTS_OK ||
        (rc = ants_cbor_enc_array(&enc, EQUIV_STMTS)) != ANTS_OK) {
        return rc;
    }
    if ((rc = enc_stmt_element(&enc, body_a, body_a_len, sig_a)) != ANTS_OK) {
        return rc;
    }
    if ((rc = enc_stmt_element(&enc, body_b, body_b_len, sig_b)) != ANTS_OK) {
        return rc;
    }

    rc = ants_cbor_enc_finalise(&enc);
    if (rc != ANTS_OK) {
        return rc;
    }
    *out_len = ants_cbor_enc_size(&enc);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Content address                                                          */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_crdt_content_id(const uint8_t *buf, size_t len, uint8_t out_id[ANTS_CRDT_CONTENT_ID_SIZE])
{
    if (buf == NULL || out_id == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    return ants_blake3_hash(buf, len, out_id);
}

/* ------------------------------------------------------------------------ */
/* Decode helpers                                                           */
/* ------------------------------------------------------------------------ */

/* Read a uint and require it equals `expected` (a map key in canonical
 * order). Maps a structural mismatch to MALFORMED. */
static ants_error_t dec_expect_key(ants_cbor_dec_t *dec, uint64_t expected)
{
    uint64_t k;
    ants_cbor_type_t ty;
    if (ants_cbor_dec_peek_type(dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_uint(dec, &k) != ANTS_OK || k != expected) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* Read a uint value (any value). MALFORMED if the next item is not a uint. */
static ants_error_t dec_uint_val(ants_cbor_dec_t *dec, uint64_t *out)
{
    ants_cbor_type_t ty;
    if (ants_cbor_dec_peek_type(dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_UINT) {
        return ANTS_ERROR_MALFORMED;
    }
    return (ants_cbor_dec_uint(dec, out) == ANTS_OK) ? ANTS_OK : ANTS_ERROR_MALFORMED;
}

/* Read a byte-string value. MALFORMED if the next item is not bytes. */
static ants_error_t dec_bytes_val(ants_cbor_dec_t *dec, const uint8_t **out, size_t *out_len)
{
    ants_cbor_type_t ty;
    if (ants_cbor_dec_peek_type(dec, &ty) != ANTS_OK || ty != ANTS_CBOR_TYPE_BYTES) {
        return ANTS_ERROR_MALFORMED;
    }
    return (ants_cbor_dec_bytes(dec, out, out_len) == ANTS_OK) ? ANTS_OK : ANTS_ERROR_MALFORMED;
}

/* A decoded statement: the (domain, epoch, slot) coordinates plus the
 * payload slice (aliases the source). */
typedef struct {
    uint64_t domain;
    uint64_t epoch;
    uint64_t slot;
    const uint8_t *payload;
    size_t payload_len;
} stmt_t;

/* Decode + canonically validate a statement body (its own CBOR document).
 * MALFORMED on any structural or canonical problem — at the equivocation
 * level a body that is not a well-formed canonical statement simply is not
 * a valid fault. */
static ants_error_t decode_statement(const uint8_t *body, size_t body_len, stmt_t *out)
{
    ants_cbor_dec_t dec;
    size_t n;
    ants_error_t rc;

    if (ants_cbor_is_canonical(body, body_len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_init(&dec, body, body_len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_map(&dec, &n) != ANTS_OK || n != STMT_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    if ((rc = dec_expect_key(&dec, STMT_KEY_DOMAIN)) != ANTS_OK ||
        (rc = dec_uint_val(&dec, &out->domain)) != ANTS_OK) {
        return rc;
    }
    if ((rc = dec_expect_key(&dec, STMT_KEY_EPOCH)) != ANTS_OK ||
        (rc = dec_uint_val(&dec, &out->epoch)) != ANTS_OK) {
        return rc;
    }
    if ((rc = dec_expect_key(&dec, STMT_KEY_SLOT)) != ANTS_OK ||
        (rc = dec_uint_val(&dec, &out->slot)) != ANTS_OK) {
        return rc;
    }
    if ((rc = dec_expect_key(&dec, STMT_KEY_PAYLOAD)) != ANTS_OK ||
        (rc = dec_bytes_val(&dec, &out->payload, &out->payload_len)) != ANTS_OK) {
        return rc;
    }
    if (ants_cbor_dec_finalise(&dec) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Decode: fault-proof envelope (structural, no crypto)                     */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_crdt_fault_proof_decode(const uint8_t *buf, size_t len, ants_fault_proof_view_t *out)
{
    ants_cbor_dec_t dec;
    size_t n, subj_len, ev_start;
    const uint8_t *subj;
    ants_error_t rc;

    if (buf == NULL || out == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Whole-document canonical gate first: cleanly separates "not even
     * well-formed CBOR" (MALFORMED) from "well-formed but non-canonical"
     * (NON_CANONICAL) before the structural walk. */
    rc = ants_cbor_is_canonical(buf, len);
    if (rc != ANTS_OK) {
        return rc; /* MALFORMED or NON_CANONICAL, verbatim */
    }

    if (ants_cbor_dec_init(&dec, buf, len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_cbor_dec_map(&dec, &n) != ANTS_OK || n != ENV_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    if ((rc = dec_expect_key(&dec, ENV_KEY_SUBJECT)) != ANTS_OK ||
        (rc = dec_bytes_val(&dec, &subj, &subj_len)) != ANTS_OK) {
        return rc;
    }
    if (subj_len != ANTS_CRDT_PEER_ID_SIZE) {
        return ANTS_ERROR_MALFORMED;
    }
    if ((rc = dec_expect_key(&dec, ENV_KEY_FAULT_TYPE)) != ANTS_OK ||
        (rc = dec_uint_val(&dec, &out->fault_type)) != ANTS_OK) {
        return rc;
    }
    if ((rc = dec_expect_key(&dec, ENV_KEY_EPOCH)) != ANTS_OK ||
        (rc = dec_uint_val(&dec, &out->epoch)) != ANTS_OK) {
        return rc;
    }
    /* key 3: evidence. Its value is the last field of a canonical document,
     * so it spans from here to the end of the buffer (type-agnostic — we do
     * not interpret its shape; that is the per-fault-type verifier's job). */
    if ((rc = dec_expect_key(&dec, ENV_KEY_EVIDENCE)) != ANTS_OK) {
        return rc;
    }
    ev_start = ants_cbor_dec_pos(&dec);
    if (ev_start >= len) {
        return ANTS_ERROR_MALFORMED;
    }

    out->subject = subj;
    out->evidence = buf + ev_start;
    out->evidence_len = len - ev_start;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* VERIFY(π)                                                                 */
/* ------------------------------------------------------------------------ */

/* Verify the equivocation evidence against `subject` at `env_epoch`. The
 * envelope is already known canonical; this re-walks the evidence with the
 * typed readers (which re-enforce canonical encoding) to extract the two
 * [body, sig] pairs, then applies the fault conditions. */
static ants_error_t
verify_equivocation(const uint8_t *buf, size_t len, const uint8_t *subject, uint64_t env_epoch)
{
    ants_cbor_dec_t dec;
    size_t n, i;
    const uint8_t *body[EQUIV_STMTS];
    size_t body_len[EQUIV_STMTS];
    const uint8_t *sig[EQUIV_STMTS];
    size_t sig_len;
    stmt_t st[EQUIV_STMTS];
    ants_error_t rc;

    if (ants_cbor_dec_init(&dec, buf, len) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    /* Re-walk envelope to position the decoder at the evidence value. */
    if (ants_cbor_dec_map(&dec, &n) != ANTS_OK || n != ENV_PAIRS) {
        return ANTS_ERROR_MALFORMED;
    }
    {
        uint64_t tmp;
        const uint8_t *b;
        size_t bl;
        if ((rc = dec_expect_key(&dec, ENV_KEY_SUBJECT)) != ANTS_OK ||
            (rc = dec_bytes_val(&dec, &b, &bl)) != ANTS_OK) {
            return rc;
        }
        if ((rc = dec_expect_key(&dec, ENV_KEY_FAULT_TYPE)) != ANTS_OK ||
            (rc = dec_uint_val(&dec, &tmp)) != ANTS_OK) {
            return rc;
        }
        if ((rc = dec_expect_key(&dec, ENV_KEY_EPOCH)) != ANTS_OK ||
            (rc = dec_uint_val(&dec, &tmp)) != ANTS_OK) {
            return rc;
        }
        if ((rc = dec_expect_key(&dec, ENV_KEY_EVIDENCE)) != ANTS_OK) {
            return rc;
        }
    }

    /* evidence = array(2) of array(2) [ body(bytes), sig(bytes 64) ]. */
    if (ants_cbor_dec_array(&dec, &n) != ANTS_OK || n != EQUIV_STMTS) {
        return ANTS_ERROR_MALFORMED;
    }
    for (i = 0; i < EQUIV_STMTS; i++) {
        size_t m;
        if (ants_cbor_dec_array(&dec, &m) != ANTS_OK || m != EQUIV_ELEMS) {
            return ANTS_ERROR_MALFORMED;
        }
        if ((rc = dec_bytes_val(&dec, &body[i], &body_len[i])) != ANTS_OK) {
            return rc;
        }
        if ((rc = dec_bytes_val(&dec, &sig[i], &sig_len)) != ANTS_OK) {
            return rc;
        }
        if (sig_len != ANTS_CRDT_SIG_SIZE) {
            return ANTS_ERROR_MALFORMED;
        }
    }
    if (ants_cbor_dec_finalise(&dec) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }

    /* Parse both statement bodies (each its own canonical CBOR document). */
    if ((rc = decode_statement(body[0], body_len[0], &st[0])) != ANTS_OK) {
        return rc;
    }
    if ((rc = decode_statement(body[1], body_len[1], &st[1])) != ANTS_OK) {
        return rc;
    }

    /* The fault conditions (RFC-0004 §Equivocation slashing): both
     * statements bind the SAME (domain, epoch, slot) — and the envelope's
     * epoch — to DIFFERENT payloads. */
    if (st[0].epoch != env_epoch || st[1].epoch != env_epoch) {
        return ANTS_ERROR_MALFORMED;
    }
    if (st[0].domain != st[1].domain || st[0].slot != st[1].slot) {
        return ANTS_ERROR_MALFORMED;
    }
    if (st[0].payload_len == st[1].payload_len &&
        memcmp(st[0].payload, st[1].payload, st[0].payload_len) == 0) {
        return ANTS_ERROR_MALFORMED; /* same commitment — not a fault */
    }

    /* Both statements must be authentic: signed by the subject over their
     * exact body bytes (two Ed25519 checks). */
    if (ants_ed25519_verify(subject, body[0], body_len[0], sig[0]) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    if (ants_ed25519_verify(subject, body[1], body_len[1], sig[1]) != ANTS_OK) {
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

ants_error_t ants_crdt_verify(const uint8_t *buf, size_t len)
{
    ants_fault_proof_view_t view;
    ants_error_t rc;

    if (buf == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Structural + canonical decode of the envelope (this also runs the
     * whole-document canonical gate). */
    rc = ants_crdt_fault_proof_decode(buf, len, &view);
    if (rc != ANTS_OK) {
        return rc; /* INVALID_ARG / MALFORMED / NON_CANONICAL */
    }

    switch (view.fault_type) {
    case ANTS_FAULT_EQUIVOCATION:
        return verify_equivocation(buf, len, view.subject, view.epoch);
    case ANTS_FAULT_INVALID_TRANSITION:
        /* Defined, but verifying it needs the L2 chain (Component #8). */
        return ANTS_ERROR_NOT_IMPLEMENTED;
    default:
        /* Unknown/unassigned class — fail closed, never a valid slash. */
        return ANTS_ERROR_UNSUPPORTED_TYPE;
    }
}

/* ------------------------------------------------------------------------ */
/* The G-Set — grow-only set of verified fault proofs                       */
/*                                                                          */
/* Storage is an open-addressed (linear-probe) hash table keyed by the      */
/* 32-byte content-id. Because the content-id is a BLAKE3 hash it is        */
/* already uniformly distributed, so the first 8 bytes serve directly as    */
/* the bucket hash — no secondary mixing needed. The table is power-of-two  */
/* sized and grows (doubling, full rehash) at a 0.7 load factor, so an      */
/* empty slot always exists and probing terminates. An empty slot is one    */
/* whose `proof` pointer is NULL (calloc-zeroed); the set is grow-only in   */
/* this PR (no tombstones — pruning, which removes, is a later PR that       */
/* rebuilds the table).                                                     */
/* ------------------------------------------------------------------------ */

#define CRDT_INITIAL_CAP 16u

struct crdt_elem {
    uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t subject[ANTS_CRDT_PEER_ID_SIZE];
    uint64_t epoch;
    uint8_t *proof; /* heap-owned copy; NULL marks an empty slot */
    size_t proof_len;
};

struct ants_crdt {
    struct crdt_elem *slots; /* `cap` buckets, power of two */
    size_t cap;
    size_t count; /* live elements */
};

/* First 8 bytes of the (uniformly random) content-id as the bucket hash. */
static uint64_t id_hash(const uint8_t id[ANTS_CRDT_CONTENT_ID_SIZE])
{
    uint64_t h;
    memcpy(&h, id, sizeof h);
    return h;
}

/* Probe for `id` in `slots` (cap a power of two). On return *found tells
 * whether the id is present; the returned index is its slot if found, else
 * the empty slot where it would be inserted. */
static size_t crdt_probe(const struct crdt_elem *slots,
                         size_t cap,
                         const uint8_t id[ANTS_CRDT_CONTENT_ID_SIZE],
                         bool *found)
{
    size_t mask = cap - 1u;
    size_t i = (size_t)(id_hash(id) & mask);
    while (slots[i].proof != NULL) {
        if (memcmp(slots[i].content_id, id, ANTS_CRDT_CONTENT_ID_SIZE) == 0) {
            *found = true;
            return i;
        }
        i = (i + 1u) & mask;
    }
    *found = false;
    return i;
}

/* Double the table and rehash every live element (pointers are moved, not
 * re-copied). */
static ants_error_t crdt_grow(struct ants_crdt *set)
{
    size_t new_cap = set->cap * 2u;
    struct crdt_elem *ns = calloc(new_cap, sizeof *ns);
    size_t i;

    if (ns == NULL) {
        return ANTS_ERROR_MALFORMED; /* OOM (project convention) */
    }
    for (i = 0; i < set->cap; i++) {
        if (set->slots[i].proof != NULL) {
            bool found;
            size_t j = crdt_probe(ns, new_cap, set->slots[i].content_id, &found);
            ns[j] = set->slots[i]; /* move; keep the proof pointer */
        }
    }
    free(set->slots);
    set->slots = ns;
    set->cap = new_cap;
    return ANTS_OK;
}

/* Insert an already-validated element (content-id, subject, epoch + bytes).
 * Dedupes by content-id; copies the proof bytes. No VERIFY — callers that
 * cross the deserialization boundary (ants_crdt_insert) verify first; merge
 * relies on the set invariant. */
static ants_error_t crdt_insert_elem(struct ants_crdt *set,
                                     const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE],
                                     const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE],
                                     uint64_t epoch,
                                     const uint8_t *proof,
                                     size_t len,
                                     bool *out_inserted)
{
    bool found;
    size_t i;
    uint8_t *copy;

    /* Grow BEFORE probing so the slot we settle on is in the final table
     * and an empty slot is guaranteed to exist. */
    if ((set->count + 1u) * 10u >= set->cap * 7u) {
        ants_error_t rc = crdt_grow(set);
        if (rc != ANTS_OK) {
            return rc;
        }
    }
    i = crdt_probe(set->slots, set->cap, content_id, &found);
    if (found) {
        if (out_inserted != NULL) {
            *out_inserted = false;
        }
        return ANTS_OK; /* idempotent */
    }
    copy = malloc(len);
    if (copy == NULL) {
        return ANTS_ERROR_MALFORMED; /* OOM */
    }
    memcpy(copy, proof, len);
    memcpy(set->slots[i].content_id, content_id, ANTS_CRDT_CONTENT_ID_SIZE);
    memcpy(set->slots[i].subject, subject, ANTS_CRDT_PEER_ID_SIZE);
    set->slots[i].epoch = epoch;
    set->slots[i].proof = copy;
    set->slots[i].proof_len = len;
    set->count++;
    if (out_inserted != NULL) {
        *out_inserted = true;
    }
    return ANTS_OK;
}

ants_error_t ants_crdt_init(ants_crdt_t **out_set)
{
    struct ants_crdt *set;

    if (out_set == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    set = malloc(sizeof *set);
    if (set == NULL) {
        return ANTS_ERROR_MALFORMED;
    }
    set->slots = calloc(CRDT_INITIAL_CAP, sizeof *set->slots);
    if (set->slots == NULL) {
        free(set);
        return ANTS_ERROR_MALFORMED;
    }
    set->cap = CRDT_INITIAL_CAP;
    set->count = 0;
    *out_set = set;
    return ANTS_OK;
}

void ants_crdt_destroy(ants_crdt_t *set)
{
    size_t i;

    if (set == NULL) {
        return;
    }
    for (i = 0; i < set->cap; i++) {
        free(set->slots[i].proof); /* free(NULL) is a no-op */
    }
    free(set->slots);
    free(set);
}

ants_error_t
ants_crdt_insert(ants_crdt_t *set, const uint8_t *proof, size_t len, bool *out_inserted)
{
    ants_fault_proof_view_t view;
    uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE];
    uint8_t subject[ANTS_CRDT_PEER_ID_SIZE];
    ants_error_t rc;

    if (out_inserted != NULL) {
        *out_inserted = false;
    }
    if (set == NULL || proof == NULL || len == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* The trust boundary: never admit a proof that does not verify. */
    rc = ants_crdt_verify(proof, len);
    if (rc != ANTS_OK) {
        return rc;
    }
    /* Extract subject + epoch for the index (decode cannot fail after a
     * successful verify, but check defensively). */
    rc = ants_crdt_fault_proof_decode(proof, len, &view);
    if (rc != ANTS_OK) {
        return rc;
    }
    memcpy(subject, view.subject, ANTS_CRDT_PEER_ID_SIZE);

    rc = ants_crdt_content_id(proof, len, content_id);
    if (rc != ANTS_OK) {
        return rc;
    }
    return crdt_insert_elem(set, content_id, subject, view.epoch, proof, len, out_inserted);
}

bool ants_crdt_contains(const ants_crdt_t *set, const uint8_t content_id[ANTS_CRDT_CONTENT_ID_SIZE])
{
    bool found;

    if (set == NULL || content_id == NULL) {
        return false;
    }
    (void)crdt_probe(set->slots, set->cap, content_id, &found);
    return found;
}

bool ants_crdt_is_slashed(const ants_crdt_t *set, const uint8_t subject[ANTS_CRDT_PEER_ID_SIZE])
{
    size_t i;

    if (set == NULL || subject == NULL) {
        return false;
    }
    for (i = 0; i < set->cap; i++) {
        if (set->slots[i].proof != NULL &&
            memcmp(set->slots[i].subject, subject, ANTS_CRDT_PEER_ID_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

size_t ants_crdt_size(const ants_crdt_t *set)
{
    return (set == NULL) ? 0 : set->count;
}

ants_error_t ants_crdt_merge(ants_crdt_t *dst, const ants_crdt_t *src)
{
    size_t i;

    if (dst == NULL || src == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    for (i = 0; i < src->cap; i++) {
        const struct crdt_elem *e = &src->slots[i];
        if (e->proof != NULL) {
            ants_error_t rc = crdt_insert_elem(
                dst, e->content_id, e->subject, e->epoch, e->proof, e->proof_len, NULL);
            if (rc != ANTS_OK) {
                return rc;
            }
        }
    }
    return ANTS_OK;
}

void ants_crdt_enumerate(const ants_crdt_t *set, ants_crdt_visit_fn fn, void *ctx)
{
    size_t i;

    if (set == NULL || fn == NULL) {
        return;
    }
    for (i = 0; i < set->cap; i++) {
        if (set->slots[i].proof != NULL) {
            if (!fn(set->slots[i].content_id, set->slots[i].proof, set->slots[i].proof_len, ctx)) {
                return;
            }
        }
    }
}
