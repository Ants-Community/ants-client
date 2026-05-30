/*
 * ants_payment.h — Payment-terms advertisement object (Component #14,
 * RFC-0006 Payment Terms & Economic Pluralism).
 *
 * The metadata structure by which a peer declares the economic terms it
 * will transact under. Every service advertisement (server: *offered*
 * terms) and every query (consumer: *acceptable* terms) may carry a
 * `payment_terms` object; a match exists when at least one offered scheme
 * intersects an acceptable scheme (RFC-0006 §"The payment_terms field").
 * The object is ADVERTISED, not negotiated — there is no handshake; a
 * peer publishes its terms (signed by its attested identity, RFC-0006
 * §Adversarial) and the counterparty either transacts or moves on.
 *
 * Scope of THIS module (PR3 of Component #14): the object + its canonical
 * CBOR (de)serialisation + structural validation. Deliberately NOT here:
 * the requester's candidate-ranking / scheme-matching policy (RFC-0006
 * §"How peers discover each other's terms" describes it in prose, not as
 * a pinned algorithm), cross-economy cache settlement, and the fiat-NCS
 * gateway — all of which RFC-0006 v0.1 leaves open and expects to evolve.
 *
 * RFC-0006 is v0.1 (early). The five named schemes and the object shape
 * are modelled faithfully; the scheme sub-fields (Stripe endpoint, rate
 * tables, Lightning invoice addresses) are loosely specified upstream and
 * are carried here as bounded text without imposing semantics the spec
 * has not fixed. The CBOR shape below is DRAFT pending an explicit
 * RFC-0008 §"Payment terms" section; documented in-header for byte-exact
 * interop before peers exchange signed terms.
 *
 * No floats (RFC-0008 §1.3 / §6): the only monetary quantities — Stripe
 * rate-per-unit (in the currency's minor units, e.g. cents) and Lightning
 * sats-per-unit — are u64 integers. No malloc, no threads, no hidden
 * global state; every entry point operates on caller-allocated structs
 * with fixed bounded buffers.
 *
 * Spec: RFC-0006 v0.1 §"The payment_terms field"; RFC-0008 v0.5 §1.1
 * (canonical CBOR). Component README: ants-client/economy/ledger/README.md.
 */

#ifndef ANTS_PAYMENT_H
#define ANTS_PAYMENT_H

#include "ants_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

/* Maximum schemes in one payment_terms object. RFC-0006 has six scheme
 * kinds; a real advertisement lists a handful in preference order. The
 * cap bounds the no-malloc struct; an object with more is rejected as
 * malformed. */
#define ANTS_PAYMENT_MAX_SCHEMES 8u

/* Bounded text-field capacities (including the NUL terminator). The
 * scheme reference fields (rate_table ref, Stripe endpoint, Lightning
 * invoice address, subscription provider/plan, custom schema URI) are
 * free-form upstream; these caps keep the struct fixed-size. A decoded
 * field that does not fit is rejected as malformed. */
#define ANTS_PAYMENT_REF_MAX      128u
#define ANTS_PAYMENT_CURRENCY_MAX 8u /* ISO 4217 codes are 3 chars */
#define ANTS_PAYMENT_NOTES_MAX    256u

/* ------------------------------------------------------------------------ */
/* Scheme + scope enums                                                     */
/* ------------------------------------------------------------------------ */

/*
 * The five named schemes (RFC-0006 §"Standard schemes") plus `custom`.
 * Values are pinned: they appear on the wire as the scheme map's `kind`
 * and in caller switch statements, so renumbering is a protocol break.
 */
typedef enum {
    ANTS_PAYMENT_SCHEME_NONE = 0,           /* gift economy, no settlement   */
    ANTS_PAYMENT_SCHEME_NCS = 1,            /* community barter (RFC-0001)    */
    ANTS_PAYMENT_SCHEME_FIAT_STRIPE = 2,    /* commercial fiat via Stripe    */
    ANTS_PAYMENT_SCHEME_FIAT_LIGHTNING = 3, /* commercial fiat via Lightning */
    ANTS_PAYMENT_SCHEME_SUBSCRIPTION = 4,   /* periodic credential access     */
    ANTS_PAYMENT_SCHEME_CUSTOM = 5          /* externally-specified scheme    */
} ants_payment_scheme_kind_t;

/* Scope of a quoted set of terms (RFC-0006 §"The payment_terms field").
 * Pinned wire values. */
typedef enum {
    ANTS_PAYMENT_SCOPE_PER_QUERY = 0,
    ANTS_PAYMENT_SCOPE_SESSION = 1,
    ANTS_PAYMENT_SCOPE_SUBSCRIPTION = 2
} ants_payment_scope_t;

/* ------------------------------------------------------------------------ */
/* Scheme                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * One payment scheme. Which fields are meaningful depends on `kind`
 * (RFC-0006 §"Standard schemes"); the codec encodes and validates ONLY
 * the fields relevant to the kind, and a decoded scheme has its
 * irrelevant fields zeroed:
 *
 *   NONE           — (no fields)
 *   NCS            — ref_a = rate_table reference
 *   FIAT_STRIPE    — amount = rate per unit (currency minor units),
 *                    currency = ISO 4217 code, ref_a = Stripe endpoint
 *   FIAT_LIGHTNING — amount = sats per unit, ref_a = invoice address
 *   SUBSCRIPTION   — ref_a = provider, ref_b = plan id
 *   CUSTOM         — ref_a = schema URI
 *
 * `amount` is u64 (no float). Text fields are NUL-terminated and bounded;
 * the codec rejects an over-long field on decode.
 */
typedef struct {
    ants_payment_scheme_kind_t kind;
    uint64_t amount; /* rate_per_unit (Stripe) or sats_per_unit (Lightning) */
    char currency[ANTS_PAYMENT_CURRENCY_MAX]; /* Stripe only; else ""        */
    char ref_a[ANTS_PAYMENT_REF_MAX];         /* kind-specific (see above)   */
    char ref_b[ANTS_PAYMENT_REF_MAX];         /* subscription plan id; else "" */
} ants_payment_scheme_t;

/* ------------------------------------------------------------------------ */
/* Payment terms object                                                     */
/* ------------------------------------------------------------------------ */

/*
 * A payment_terms advertisement: an ordered list of accepted/offered
 * schemes (most-preferred first), a validity deadline, scope, and
 * free-form notes. RFC-0006 §"The payment_terms field".
 */
typedef struct {
    ants_payment_scheme_t schemes[ANTS_PAYMENT_MAX_SCHEMES];
    uint32_t n_schemes;

    /* Unix seconds through which these terms are honoured (RFC-0006
     * "validity: timestamp"). 0 means "unset / no stated expiry". u64,
     * not float/time_t — fixed width for the canonical record. */
    uint64_t validity_unix_s;

    ants_payment_scope_t scope;
    char notes[ANTS_PAYMENT_NOTES_MAX]; /* NUL-terminated, may be ""        */
} ants_payment_terms_t;

/* ------------------------------------------------------------------------ */
/* Lifecycle + validation                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Zero-initialise a payment_terms object: no schemes, validity unset
 * (0), scope = PER_QUERY, empty notes.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if terms is NULL.
 */
ants_error_t ants_payment_terms_init(ants_payment_terms_t *terms);

/*
 * Append a scheme to the object's ordered list. Validates the scheme
 * (ants_payment_scheme_valid) and that the list is not full.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG if terms/scheme is NULL or the
 *         scheme is invalid; ANTS_ERROR_BUFFER_TOO_SMALL if the list is
 *         already at ANTS_PAYMENT_MAX_SCHEMES.
 */
ants_error_t ants_payment_terms_add_scheme(ants_payment_terms_t *terms,
                                           const ants_payment_scheme_t *scheme);

/*
 * Structural validity of one scheme: kind in range, every text field
 * NUL-terminated within its buffer, and the kind's required fields
 * present / irrelevant fields empty (e.g. a NONE scheme must carry no
 * amount or text; a FIAT_STRIPE must have a non-empty currency). This is
 * the same check the encoder and decoder apply.
 *
 * @return true iff the scheme is structurally valid.
 */
bool ants_payment_scheme_valid(const ants_payment_scheme_t *scheme);

/*
 * Whether two terms objects share at least one scheme KIND — the
 * RFC-0006 match test ("a match is made when at least one of the
 * consumer's acceptable schemes intersects with the server's offered
 * schemes"). This compares kinds only, not prices; price/endpoint
 * agreement is the caller's policy, deliberately out of scope here.
 *
 * @return ANTS_OK with *out_match set; ANTS_ERROR_INVALID_ARG on NULL.
 */
ants_error_t ants_payment_terms_intersects(const ants_payment_terms_t *a,
                                           const ants_payment_terms_t *b,
                                           bool *out_match);

/* ------------------------------------------------------------------------ */
/* Canonical serialisation (RFC-0008 §1.1)                                  */
/* ------------------------------------------------------------------------ */

/*
 * Worst-case encoded size. Outer map (4 pairs) + notes (~259 B) + up to
 * ANTS_PAYMENT_MAX_SCHEMES schemes, each a small map with two ~130 B text
 * fields. 8 * ~280 + ~300 < 2560.
 */
#define ANTS_PAYMENT_ENCODED_MAX 2560u

/*
 * Encode a payment_terms object as canonical CBOR (RFC-0008 §1.1) into
 * `buf`. Definite-length map of 4 integer-keyed pairs in ascending key
 * order:
 *   1: schemes  (array; each scheme a map of integer-keyed pairs:
 *                1 kind(uint); then only the kind's fields, ascending:
 *                2 amount(uint), 3 currency(text), 4 ref_a(text),
 *                5 ref_b(text))
 *   2: validity (uint, unix seconds; 0 = unset)
 *   3: scope    (uint enum)
 *   4: notes    (text)
 * Float-free by construction.
 *
 * The object must be valid (every scheme passes ants_payment_scheme_valid
 * and n_schemes <= ANTS_PAYMENT_MAX_SCHEMES); otherwise INVALID_ARG.
 *
 * On success *out_len is the number of bytes written.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL/invalid object;
 *         ANTS_ERROR_BUFFER_TOO_SMALL if cap is insufficient.
 */
ants_error_t ants_payment_terms_encode(const ants_payment_terms_t *terms,
                                       uint8_t *buf,
                                       size_t cap,
                                       size_t *out_len);

/*
 * Decode a canonical-CBOR payment_terms object from `buf` into `terms`.
 * STRICT: a §4.2.1 canonical violation (non-shortest int, out-of-order /
 * duplicate keys, indefinite length, trailing bytes) returns
 * ANTS_ERROR_NON_CANONICAL; any other structural problem (wrong shape,
 * wrong type, an over-long text field, too many schemes, a scheme whose
 * present keys do not match its kind) returns ANTS_ERROR_MALFORMED. A
 * permissive decoder would open hash-malleability on signed terms, so it
 * fails closed.
 *
 * @return ANTS_OK; ANTS_ERROR_INVALID_ARG on NULL args;
 *         ANTS_ERROR_NON_CANONICAL / ANTS_ERROR_MALFORMED as above.
 */
ants_error_t ants_payment_terms_decode(const uint8_t *buf, size_t len, ants_payment_terms_t *terms);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_PAYMENT_H */
