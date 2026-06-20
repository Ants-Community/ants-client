/*
 * der.h — strict DER (Distinguished Encoding Rules) TLV reader.
 *
 * A minimal, allocation-free cursor over a DER byte buffer, used by the TEE
 * certificate-chain validator (RFC-0005) to walk vendor X.509 certificates.
 * It implements only the DER subset X.509 actually uses and REJECTS everything
 * else, because the input is attacker-controlled — a quote may embed a hostile
 * certificate chain:
 *
 *   - definite-length only (indefinite length 0x80 is rejected);
 *   - minimal length encoding (long form only when the value will not fit in
 *     short form; no leading-zero length octets) — DER, not BER;
 *   - single-octet identifiers (low-tag-number form, tag number < 31);
 *   - every value fully contained in the enclosing buffer.
 *
 * No heap, no recursion: nesting is walked by deriving a sub-reader over a
 * constructed element's contents. Internal to foundation/tee; exposed via this
 * header (not ants_tee.h) so the reader can be unit-tested in isolation — the
 * hardening that matters most for a hand-written parser lives in those tests.
 */

#ifndef ANTS_TEE_DER_H
#define ANTS_TEE_DER_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Identifier octets for the ASN.1 types X.509 certificates use. The low 5
 * bits are the tag number; bit 0x20 marks a constructed type; the high 2 bits
 * are the class (0x00 universal, 0x80 context-specific). */
#define ANTS_DER_TAG_BOOLEAN          0x01
#define ANTS_DER_TAG_INTEGER          0x02
#define ANTS_DER_TAG_BIT_STRING       0x03
#define ANTS_DER_TAG_OCTET_STRING     0x04
#define ANTS_DER_TAG_NULL             0x05
#define ANTS_DER_TAG_OID              0x06
#define ANTS_DER_TAG_UTF8_STRING      0x0C
#define ANTS_DER_TAG_PRINTABLE_STRING 0x13
#define ANTS_DER_TAG_UTC_TIME         0x17
#define ANTS_DER_TAG_GENERALIZED_TIME 0x18
#define ANTS_DER_TAG_SEQUENCE         0x30 /* constructed */
#define ANTS_DER_TAG_SET              0x31 /* constructed */
/* Context-specific constructed [n]: 0xA0 | n. Used for X.509 version [0],
 * extensions [3], and the like. */
#define ANTS_DER_TAG_CONTEXT(n) ((uint8_t)(0xA0 | (n)))

/* A cursor over a DER buffer. `pos` is the offset of the next element; the
 * invariant pos <= len always holds. Treat the fields as opaque. */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} ants_der;

/* A decoded TLV: the identifier octet and the value octets as a slice into the
 * buffer the reader was initialised over (no copy). */
typedef struct {
    uint8_t tag;
    const uint8_t *val;
    size_t len;
} ants_der_tlv;

/* Initialise a reader over [buf, buf+len). */
void ants_der_init(ants_der *r, const uint8_t *buf, size_t len);

/* Return the identifier octet of the element at the cursor WITHOUT advancing,
 * for choosing among optional fields. ANTS_ERROR_MALFORMED if no byte remains.
 * Does not validate the element — that is ants_der_read's job. */
ants_error_t ants_der_peek_tag(const ants_der *r, uint8_t *tag);

/* Read the next TLV, advancing past it. If `expect_tag` is non-zero the
 * identifier octet must equal it. Enforces the strict-DER rules above; fills
 * `*out` with the value slice on success. Returns ANTS_ERROR_MALFORMED on any
 * violation, ANTS_ERROR_INVALID_ARG on a NULL argument. */
ants_error_t ants_der_read(ants_der *r, uint8_t expect_tag, ants_der_tlv *out);

/* Read a constructed TLV (`expect_tag` must have the 0x20 constructed bit) and
 * initialise `inner` over its contents — the cursor for descending one level. */
ants_error_t ants_der_enter(ants_der *r, uint8_t expect_tag, ants_der *inner);

/* Skip the next TLV regardless of tag. */
ants_error_t ants_der_skip(ants_der *r);

/* True once the cursor has consumed the whole buffer (no trailing data). */
bool ants_der_eof(const ants_der *r);

#endif /* ANTS_TEE_DER_H */
