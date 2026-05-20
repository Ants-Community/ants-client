/*
 * ants_common.h — types and error codes shared across all ants-client
 * components.
 *
 * Spec references: project-wide; mirrors the discipline declared in
 * CONTRIBUTING.md ("Errors are values. Return codes with ants_error_t
 * enum.").
 *
 * Stability: this header is part of every component's public interface.
 * Additions to ants_error_t must be append-only (existing enum values
 * keep their integer assignment); a deprecated value is reserved, never
 * recycled, so old binaries reading new error codes see UNKNOWN rather
 * than mis-interpret.
 */

#ifndef ANTS_COMMON_H
#define ANTS_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Project-wide return codes.
 *
 * ANTS_OK is the only success value (== 0).
 * Negative values are reserved for future use (none defined yet).
 * Positive values enumerate error conditions; the integer assignment is
 * stable across versions.
 */
typedef enum {
    ANTS_OK = 0,

    /* Caller mistake: argument was NULL, out of range, or otherwise
     * structurally invalid. The library did not even try the operation. */
    ANTS_ERROR_INVALID_ARG = 1,

    /* Caller-provided buffer is too small for the operation. The caller
     * may retry with a larger buffer; no state was mutated. */
    ANTS_ERROR_BUFFER_TOO_SMALL = 2,

    /* The function is part of the API but has not yet been implemented in
     * this build. Used by stubs during incremental development; should
     * never be returned by a release-tagged build. */
    ANTS_ERROR_NOT_IMPLEMENTED = 3,

    /* Input bytes were not well-formed under the relevant encoding (CBOR,
     * attestation blob, fault proof, etc.). Always a protocol-level
     * error — fail closed. */
    ANTS_ERROR_MALFORMED = 4,

    /* Input bytes were well-formed but violated a canonical-encoding rule
     * (e.g. CBOR §4.2.1: non-shortest integer, unsorted map keys,
     * indefinite-length item). Always rejected, never accepted leniently. */
    ANTS_ERROR_NON_CANONICAL = 5,

    /* The encoding identified a major type or tag the library does not
     * support (e.g. CBOR floats in protocol-level objects, or an
     * unreserved tag). */
    ANTS_ERROR_UNSUPPORTED_TYPE = 6,

    /* Numeric overflow during accumulation (e.g. integer parsed from
     * input exceeds u64, or sum of NCS exceeds u64::MAX). */
    ANTS_ERROR_OVERFLOW = 7,

    /* Sentinel — never returned; helpers may use it as a bound when
     * iterating over the enum. Update if new variants are appended. */
    ANTS_ERROR__MAX = 8,
} ants_error_t;

/*
 * Convert an ants_error_t to a short human-readable string. The returned
 * pointer is to a static literal — caller must not free it. Returns
 * "unknown" for values outside the enum.
 */
const char *ants_strerror(ants_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_COMMON_H */
