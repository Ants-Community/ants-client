/*
 * sodium_stub.c — minimal libsodium plumbing stubs for the vendored
 * ed25519 subset.
 *
 * The libsodium codebase calls into a few global helpers that we don't
 * want to drag in fully:
 *
 *   - sodium_misuse() is invoked on API misuse and is declared noreturn.
 *     We provide an abort() stub: the protocol's reference client must
 *     not exercise misuse paths anyway, and aborting on misuse is the
 *     correct fail-closed posture.
 *
 *   - randombytes_buf() is the platform-level RNG entrypoint. The
 *     deterministic Ed25519 ref10 sign/verify path does not call it,
 *     but a handful of utils.c initialisers reference it transitively.
 *     We provide an abort() stub here too; if any code path in our
 *     subset starts to need randomness, the stub will fail loudly,
 *     surfacing the dependency rather than letting it slip in
 *     silently. Future PRs that need randomness will wire a real
 *     entropy source.
 *
 * Both stubs live outside the vendored libsodium sources so that
 * upstream files remain bit-identical to their pinned 1.0.22 release.
 */

#include <stdlib.h>
#include <stddef.h>

__attribute__((noreturn)) void sodium_misuse(void)
{
    abort();
}

__attribute__((noreturn)) void randombytes_buf(void *buf, size_t size)
{
    (void)buf;
    (void)size;
    abort();
}
