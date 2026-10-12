/*
 * infer_wire.c — INFER_REQ / INFER_RESP codec (RFC-0008 §11.14).
 *
 * Same envelope as the DHT RPCs (§11.2): {0: type, 1: txid, 2: body}, an
 * empty body omitting key 2. Both body maps are closed: a decoder rejects
 * unknown keys, and every decoder finalises (no trailing bytes).
 */

#include "ants_infer.h"

#include "ants_cbor.h"

#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Envelope                                                                 */
/* ------------------------------------------------------------------------ */

static ants_error_t enc_head(ants_cbor_enc_t *enc, uint64_t type, uint32_t txid, bool has_body)
{
    ants_error_t err;
    if ((err = ants_cbor_enc_map(enc, has_body ? 3u : 2u)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(enc, 0)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(enc, type)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(enc, 1)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(enc, txid)) != ANTS_OK) {
        return err;
    }
    if (has_body) {
        return ants_cbor_enc_uint(enc, 2);
    }
    return ANTS_OK;
}

/* Decode map(2|3) → 0: type → 1: txid [→ 2]. */
static ants_error_t
dec_head(ants_cbor_dec_t *dec, uint64_t *out_type, uint32_t *out_txid, bool *out_has_body)
{
    ants_error_t err;
    size_t n;
    uint64_t key;
    uint64_t txid;
    if ((err = ants_cbor_dec_map(dec, &n)) != ANTS_OK) {
        return err;
    }
    if (n != 2 && n != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 0) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = ants_cbor_dec_uint(dec, out_type)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 1) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = ants_cbor_dec_uint(dec, &txid)) != ANTS_OK) {
        return err;
    }
    if (txid > UINT32_MAX) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    *out_txid = (uint32_t)txid;
    *out_has_body = (n == 3);
    if (n == 3) {
        if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
            return err;
        }
        if (key != 2) {
            return ANTS_ERROR_NON_CANONICAL;
        }
    }
    return ANTS_OK;
}

ants_error_t ants_infer_wire_peek_type(const uint8_t *buf, size_t len, uint64_t *out_type)
{
    ants_cbor_dec_t dec;
    uint32_t txid;
    bool has_body;
    ants_error_t err;
    if (buf == NULL || out_type == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((err = ants_cbor_dec_init(&dec, buf, len)) != ANTS_OK) {
        return err;
    }
    return dec_head(&dec, out_type, &txid, &has_body);
}

static ants_error_t expect_key(ants_cbor_dec_t *dec, uint64_t want)
{
    uint64_t key;
    ants_error_t err = ants_cbor_dec_uint(dec, &key);
    if (err != ANTS_OK) {
        return err;
    }
    return key == want ? ANTS_OK : ANTS_ERROR_NON_CANONICAL;
}

/* ------------------------------------------------------------------------ */
/* INFER_REQ                                                                */
/* ------------------------------------------------------------------------ */

static bool request_valid(const ants_infer_request_t *r)
{
    return r->input != NULL && r->input_len > 0 && r->input_len <= ANTS_INFER_MAX_INPUT_BYTES &&
           r->tier <= (uint32_t)INT32_MAX;
}

ants_error_t ants_infer_wire_encode_req(uint8_t *buf,
                                        size_t cap,
                                        size_t *out_len,
                                        uint32_t txid,
                                        const ants_infer_request_t *req)
{
    ants_cbor_enc_t enc;
    ants_error_t err;
    if (buf == NULL || out_len == NULL || req == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (!request_valid(req)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((err = ants_cbor_enc_init(&enc, buf, cap)) != ANTS_OK) {
        return err;
    }
    if ((err = enc_head(&enc, ANTS_INFER_MSG_REQ, txid, true)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_map(&enc, 3)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(&enc, 0)) != ANTS_OK ||
        (err = ants_cbor_enc_bytes(&enc, req->input, req->input_len)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(&enc, 1)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(&enc, req->tier)) != ANTS_OK ||
        (err = ants_cbor_enc_uint(&enc, 2)) != ANTS_OK ||
        (err = ants_cbor_enc_bytes(&enc, req->req_nonce, sizeof req->req_nonce)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_infer_wire_decode_req(const uint8_t *buf,
                                        size_t len,
                                        uint32_t *out_txid,
                                        ants_infer_request_t *out)
{
    ants_cbor_dec_t dec;
    uint64_t type;
    uint64_t tier;
    bool has_body;
    size_t n;
    const uint8_t *nonce;
    size_t nonce_len;
    ants_error_t err;
    if (buf == NULL || out_txid == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);
    if ((err = ants_cbor_dec_init(&dec, buf, len)) != ANTS_OK) {
        return err;
    }
    if ((err = dec_head(&dec, &type, out_txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (type != ANTS_INFER_MSG_REQ || !has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = ants_cbor_dec_map(&dec, &n)) != ANTS_OK) {
        return err;
    }
    if (n != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_key(&dec, 0)) != ANTS_OK ||
        (err = ants_cbor_dec_bytes(&dec, &out->input, &out->input_len)) != ANTS_OK ||
        (err = expect_key(&dec, 1)) != ANTS_OK ||
        (err = ants_cbor_dec_uint(&dec, &tier)) != ANTS_OK ||
        (err = expect_key(&dec, 2)) != ANTS_OK ||
        (err = ants_cbor_dec_bytes(&dec, &nonce, &nonce_len)) != ANTS_OK ||
        (err = ants_cbor_dec_finalise(&dec)) != ANTS_OK) {
        memset(out, 0, sizeof *out);
        return err;
    }
    if (nonce_len != sizeof out->req_nonce || tier > (uint64_t)INT32_MAX) {
        memset(out, 0, sizeof *out);
        return ANTS_ERROR_MALFORMED;
    }
    out->tier = (uint32_t)tier;
    memcpy(out->req_nonce, nonce, nonce_len);
    if (!request_valid(out)) {
        memset(out, 0, sizeof *out);
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* INFER_RESP                                                               */
/* ------------------------------------------------------------------------ */

static bool answer_valid(const ants_infer_answer_t *a)
{
    return a->commit != NULL && a->commit_len > 0 &&
           a->commit_len <= ANTS_INFERENCE_COMMIT_ENCODED_MAX && a->envelope != NULL &&
           a->envelope_len > 0;
}

ants_error_t ants_infer_wire_encode_resp(uint8_t *buf,
                                         size_t cap,
                                         size_t *out_len,
                                         uint32_t txid,
                                         const ants_infer_answer_t *a)
{
    ants_cbor_enc_t enc;
    ants_error_t err;
    bool present = a != NULL && a->present;
    if (buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (present && !answer_valid(a)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((err = ants_cbor_enc_init(&enc, buf, cap)) != ANTS_OK) {
        return err;
    }
    if ((err = enc_head(&enc, ANTS_INFER_MSG_RESP, txid, present)) != ANTS_OK) {
        return err;
    }
    if (present) {
        if ((err = ants_cbor_enc_map(&enc, 3)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 0)) != ANTS_OK ||
            (err = ants_cbor_enc_bytes(&enc, a->commit, a->commit_len)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 1)) != ANTS_OK ||
            (err = ants_cbor_enc_bytes(&enc, a->sig, sizeof a->sig)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 2)) != ANTS_OK ||
            (err = ants_cbor_enc_bytes(&enc, a->envelope, a->envelope_len)) != ANTS_OK) {
            return err;
        }
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_infer_wire_decode_resp(const uint8_t *buf,
                                         size_t len,
                                         uint32_t *out_txid,
                                         ants_infer_answer_t *out)
{
    ants_cbor_dec_t dec;
    uint64_t type;
    bool has_body;
    size_t n;
    const uint8_t *sig;
    size_t sig_len;
    ants_error_t err;
    if (buf == NULL || out_txid == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);
    if (len > ANTS_INFER_MAX_RESP_BYTES) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if ((err = ants_cbor_dec_init(&dec, buf, len)) != ANTS_OK) {
        return err;
    }
    if ((err = dec_head(&dec, &type, out_txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (type != ANTS_INFER_MSG_RESP) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (!has_body) {
        return ants_cbor_dec_finalise(&dec); /* declined */
    }
    if ((err = ants_cbor_dec_map(&dec, &n)) != ANTS_OK) {
        return err;
    }
    if (n != 3) {
        /* An explicit empty body (n == 0) is non-canonical too. */
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_key(&dec, 0)) != ANTS_OK ||
        (err = ants_cbor_dec_bytes(&dec, &out->commit, &out->commit_len)) != ANTS_OK ||
        (err = expect_key(&dec, 1)) != ANTS_OK ||
        (err = ants_cbor_dec_bytes(&dec, &sig, &sig_len)) != ANTS_OK ||
        (err = expect_key(&dec, 2)) != ANTS_OK ||
        (err = ants_cbor_dec_bytes(&dec, &out->envelope, &out->envelope_len)) != ANTS_OK ||
        (err = ants_cbor_dec_finalise(&dec)) != ANTS_OK) {
        memset(out, 0, sizeof *out);
        return err;
    }
    if (sig_len != sizeof out->sig) {
        memset(out, 0, sizeof *out);
        return ANTS_ERROR_MALFORMED;
    }
    memcpy(out->sig, sig, sig_len);
    out->present = true;
    if (!answer_valid(out)) {
        memset(out, 0, sizeof *out);
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
