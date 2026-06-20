/*
 * der.c — strict DER TLV reader. See der.h for the rules enforced and why.
 */

#include "der.h"

void ants_der_init(ants_der *r, const uint8_t *buf, size_t len)
{
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

ants_error_t ants_der_peek_tag(const ants_der *r, uint8_t *tag)
{
    if (r == NULL || tag == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (r->pos >= r->len) {
        return ANTS_ERROR_MALFORMED;
    }
    *tag = r->buf[r->pos];
    return ANTS_OK;
}

ants_error_t ants_der_read(ants_der *r, uint8_t expect_tag, ants_der_tlv *out)
{
    if (r == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Reader invariant; defensive against a corrupted cursor. */
    if (r->pos > r->len) {
        return ANTS_ERROR_MALFORMED;
    }

    size_t pos = r->pos;
    /* Need at least the identifier octet and the first length octet. */
    if (r->len - pos < 2) {
        return ANTS_ERROR_MALFORMED;
    }

    uint8_t tag = r->buf[pos];
    /* Low-tag-number form only: a tag number of 0x1F means the identifier
     * continues into further octets (high-tag-number form), which no field of
     * an X.509 certificate uses. Reject rather than parse a form we never
     * expect. */
    if ((tag & 0x1F) == 0x1F) {
        return ANTS_ERROR_MALFORMED;
    }
    if (expect_tag != 0 && tag != expect_tag) {
        return ANTS_ERROR_MALFORMED;
    }
    pos++;

    uint8_t l0 = r->buf[pos];
    pos++;

    size_t length;
    if (l0 < 0x80) {
        /* Short form: the length is the octet itself (0..127). */
        length = l0;
    } else if (l0 == 0x80) {
        /* Indefinite length is BER, not DER. */
        return ANTS_ERROR_MALFORMED;
    } else {
        /* Long form: low 7 bits give the count of subsequent length octets. */
        size_t nbytes = (size_t)(l0 & 0x7F);
        if (nbytes > sizeof(size_t)) {
            return ANTS_ERROR_MALFORMED; /* would not fit in size_t */
        }
        if (r->len - pos < nbytes) {
            return ANTS_ERROR_MALFORMED; /* length octets run past the buffer */
        }
        /* DER minimal encoding: no leading zero octet. */
        if (r->buf[pos] == 0x00) {
            return ANTS_ERROR_MALFORMED;
        }
        length = 0;
        for (size_t i = 0; i < nbytes; i++) {
            length = (length << 8) | (size_t)r->buf[pos];
            pos++;
        }
        /* A value of 0..127 must use the short form. */
        if (length < 0x80) {
            return ANTS_ERROR_MALFORMED;
        }
    }

    /* The value must lie wholly within the buffer. */
    if (r->len - pos < length) {
        return ANTS_ERROR_MALFORMED;
    }

    out->tag = tag;
    out->val = r->buf + pos;
    out->len = length;
    r->pos = pos + length;
    return ANTS_OK;
}

ants_error_t ants_der_enter(ants_der *r, uint8_t expect_tag, ants_der *inner)
{
    if (inner == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Entering only makes sense for a constructed type. */
    if ((expect_tag & 0x20) == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_der_tlv tlv;
    ants_error_t err = ants_der_read(r, expect_tag, &tlv);
    if (err != ANTS_OK) {
        return err;
    }
    ants_der_init(inner, tlv.val, tlv.len);
    return ANTS_OK;
}

ants_error_t ants_der_skip(ants_der *r)
{
    ants_der_tlv tlv;
    return ants_der_read(r, 0, &tlv);
}

bool ants_der_eof(const ants_der *r)
{
    return r != NULL && r->pos == r->len;
}
