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
