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
 * ANTS_OK is the only success value (== 0). Positive values enumerate
 * error conditions; the integer assignment is stable across versions.
 * Negative values are reserved for future use.
 *
 * `ants_error_t` is typedef'd to `int32_t` (not an `enum`) so that
 *   - sizeof(ants_error_t) is locked at 4 bytes across compilers and
 *     platforms — adding new error variants never changes the ABI;
 *   - the type pins behavior under C99 (which permits implementations
 *     to choose any integer type wide enough to hold the enumerators).
 * The #define values still allow callers to write `if (err ==
 * ANTS_ERROR_MALFORMED)` exactly as before.
 */
typedef int32_t ants_error_t;

#define ANTS_OK ((ants_error_t)0)

/* Caller mistake: argument was NULL, out of range, or otherwise
 * structurally invalid. The library did not even try the operation. */
#define ANTS_ERROR_INVALID_ARG ((ants_error_t)1)

/* Caller-provided buffer is too small for the operation. The caller
 * may retry with a larger buffer; no state was mutated. */
#define ANTS_ERROR_BUFFER_TOO_SMALL ((ants_error_t)2)

/* The function is part of the API but has not yet been implemented in
 * this build. Used by stubs during incremental development; should
 * never be returned by a release-tagged build. */
#define ANTS_ERROR_NOT_IMPLEMENTED ((ants_error_t)3)

/* Input bytes were not well-formed under the relevant encoding (CBOR,
 * attestation blob, fault proof, etc.). Also returned by cryptographic
 * verify functions when a signature/proof fails to validate. Always a
 * protocol-level error — fail closed.
 *
 * Note: a future minor release may split this into a structural-error
 * code and a verify-failed code; callers that need to distinguish
 * "garbage encoding" (drop the peer) from "the adversary tried to fool
 * me" (slash/log evidence) should already be storing the raw bytes for
 * forensic inspection. */
#define ANTS_ERROR_MALFORMED ((ants_error_t)4)

/* Input bytes were well-formed but violated a canonical-encoding rule
 * (e.g. CBOR §4.2.1: non-shortest integer, unsorted map keys,
 * indefinite-length item). Always rejected, never accepted leniently. */
#define ANTS_ERROR_NON_CANONICAL ((ants_error_t)5)

/* The encoding identified a major type or tag the library does not
 * support (e.g. CBOR floats in protocol-level objects, or an
 * unreserved tag). */
#define ANTS_ERROR_UNSUPPORTED_TYPE ((ants_error_t)6)

/* Numeric overflow during accumulation (e.g. integer parsed from
 * input exceeds u64, or sum of NCS exceeds u64::MAX). */
#define ANTS_ERROR_OVERFLOW ((ants_error_t)7)

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
