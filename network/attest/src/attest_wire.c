/*
 * attest_wire.c — ATTEST_REQ / ATTEST_RESP codec (RFC-0008 §11.12).
 *
 * Same envelope as the DHT RPCs (§11.2): {0: type, 1: txid, 2: body}, an
 * empty body omitting key 2. Canonical CBOR in, canonical CBOR out; every
 * decoder finalises (no trailing bytes) and rejects anything an encoder
 * would not have produced.
 */

#include "ants_attest.h"

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

/* Decode map(2|3) → 0: type → 1: txid [→ 2]. *out_has_body says whether the
 * body map follows. */
static ants_error_t
dec_head(ants_cbor_dec_t *dec, uint64_t *out_type, uint32_t *out_txid, bool *out_has_body)
{
    ants_error_t err;
    size_t n;
    if ((err = ants_cbor_dec_map(dec, &n)) != ANTS_OK) {
        return err;
    }
    if (n != 2 && n != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t key;
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
    uint64_t txid;
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

ants_error_t ants_attest_wire_peek_type(const uint8_t *buf, size_t len, uint64_t *out_type)
{
    if (buf == NULL || out_type == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    uint32_t txid;
    bool has_body;
    return dec_head(&dec, out_type, &txid, &has_body);
}

/* ------------------------------------------------------------------------ */
/* ATTEST_REQ                                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_attest_wire_encode_req(uint8_t *buf, size_t cap, size_t *out_len, uint32_t txid)
{
    if (buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = enc_head(&enc, ANTS_ATTEST_MSG_REQ, txid, false)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_attest_wire_decode_req(const uint8_t *buf, size_t len, uint32_t *out_txid)
{
    if (buf == NULL || out_txid == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    uint64_t type;
    bool has_body;
    if ((err = dec_head(&dec, &type, out_txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (type != ANTS_ATTEST_MSG_REQ || has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ants_cbor_dec_finalise(&dec);
}

/* ------------------------------------------------------------------------ */
/* ATTEST_RESP                                                              */
/* ------------------------------------------------------------------------ */

/* A presentation an encoder may emit (and a decoder may accept). */
static bool presentation_valid(const ants_attest_presentation_t *p)
{
    return p->vendor > 0 && p->issued_at_unix >= 0 && p->expires_at_unix >= 0 && p->blob != NULL &&
           p->blob_len > 0 && p->blob_len <= ANTS_ATTEST_MAX_BLOB_BYTES;
}

ants_error_t ants_attest_wire_encode_resp(uint8_t *buf,
                                          size_t cap,
                                          size_t *out_len,
                                          uint32_t txid,
                                          const ants_attest_presentation_t *p)
{
    if (buf == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    bool present = p != NULL && p->present;
    if (present && !presentation_valid(p)) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = enc_head(&enc, ANTS_ATTEST_MSG_RESP, txid, present)) != ANTS_OK) {
        return err;
    }
    if (present) {
        if ((err = ants_cbor_enc_map(&enc, 4)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 0)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, (uint64_t)p->vendor)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 1)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, (uint64_t)p->issued_at_unix)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 2)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, (uint64_t)p->expires_at_unix)) != ANTS_OK ||
            (err = ants_cbor_enc_uint(&enc, 3)) != ANTS_OK ||
            (err = ants_cbor_enc_bytes(&enc, p->blob, p->blob_len)) != ANTS_OK) {
            return err;
        }
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

/* Decode `key: uint` where the uint must fit a non-negative int64. */
static ants_error_t dec_keyed_uint(ants_cbor_dec_t *dec, uint64_t want_key, uint64_t *out)
{
    uint64_t key;
    ants_error_t err;
    if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != want_key) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = ants_cbor_dec_uint(dec, out)) != ANTS_OK) {
        return err;
    }
    return *out > (uint64_t)INT64_MAX ? ANTS_ERROR_MALFORMED : ANTS_OK;
}

ants_error_t ants_attest_wire_decode_resp(const uint8_t *buf,
                                          size_t len,
                                          uint32_t *out_txid,
                                          ants_attest_presentation_t *out)
{
    if (buf == NULL || out_txid == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);
    if (len > ANTS_ATTEST_MAX_RESP_BYTES) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    uint64_t type;
    bool has_body;
    if ((err = dec_head(&dec, &type, out_txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (type != ANTS_ATTEST_MSG_RESP) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if (!has_body) {
        return ants_cbor_dec_finalise(&dec); /* empty body: nothing presented */
    }
    size_t n;
    if ((err = ants_cbor_dec_map(&dec, &n)) != ANTS_OK) {
        return err;
    }
    if (n != 4) {
        /* An explicit empty body (n == 0) is non-canonical too: the empty
         * answer omits key 2. */
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t vendor, issued, expires;
    if ((err = dec_keyed_uint(&dec, 0, &vendor)) != ANTS_OK) {
        return err;
    }
    if ((err = dec_keyed_uint(&dec, 1, &issued)) != ANTS_OK) {
        return err;
    }
    if ((err = dec_keyed_uint(&dec, 2, &expires)) != ANTS_OK) {
        return err;
    }
    uint64_t key;
    if ((err = ants_cbor_dec_uint(&dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    const uint8_t *blob;
    size_t blob_len;
    if ((err = ants_cbor_dec_bytes(&dec, &blob, &blob_len)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_dec_finalise(&dec)) != ANTS_OK) {
        return err;
    }
    if (vendor == 0 || vendor > (uint64_t)INT32_MAX) {
        return ANTS_ERROR_MALFORMED;
    }
    out->present = true;
    out->vendor = (ants_tee_vendor_t)vendor;
    out->issued_at_unix = (int64_t)issued;
    out->expires_at_unix = (int64_t)expires;
    out->blob = blob;
    out->blob_len = blob_len;
    if (!presentation_valid(out)) {
        memset(out, 0, sizeof *out);
        return ANTS_ERROR_MALFORMED;
    }
    return ANTS_OK;
}
