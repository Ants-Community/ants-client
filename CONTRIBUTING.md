# Contributing to ants-client

This repository implements the ANTS protocol specified at
[Ants-Community/ants](https://github.com/Ants-Community/ants).

## Where contributions go

- **Protocol design questions** — changes to RFCs, manifesto,
  governance, the CHANGELOG — go to the **spec repo**,
  [Ants-Community/ants](https://github.com/Ants-Community/ants).
- **Implementation contributions** — component code, build system,
  tests, implementation-side documentation — go to **this repo**.

The two are separate by design. The spec is CC0 and stable across
client implementations (the v1.0 condition is "three independent
client implementations passing the conformance test suite"). This
client is Apache-2.0/MIT and evolves with its build.

## Claiming a component

Per
[IMPLEMENTATION.md §"How to claim a sub-component"](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md#how-to-claim-a-sub-component):

1. Open an issue on the **spec repo** titled
   `[CLAIM] Component #N — <name>`.
2. Describe your background, expected start date, expected
   duration, working hours per week.
3. Wait for the nomination window (currently 2–3 weeks). The BDFL
   (during v0.x) acknowledges the claim. Multiple claims for the
   same component go to the most-qualified-and-available;
   parallelisable sub-tasks within a component may be shared.
4. Once acknowledged, the claim is recorded in `CONTRIBUTORS.md`
   here, and you become the primary contributor for that
   component.

A primary contributor who falls silent for > 2 months without
communication may have the claim reassigned per
IMPLEMENTATION.md §"How to claim a sub-component" step 5.

## Code style

- **C99 with no compiler extensions.** `-Wpedantic` clean. No GNU
  extensions, no platform-specific intrinsics outside the
  platforms/ subdirs of components that explicitly need them
  (e.g., `inference/kernels/platforms/x86_avx2.c`).
- **Audit-friendliness over cleverness.** Every line does one
  thing. No hidden control flow, no macro magic, no implicit
  conversions on hot paths.
- **No hidden allocations on hot paths.** Arena allocators or
  caller-provided buffers for protocol-message and audit-path
  code. `malloc`/`free` only at well-defined boundaries.
- **Errors are values.** Return codes with `ants_error_t` enum.
  No `errno` on protocol paths (vendor SDK errno is wrapped at
  the boundary). No `longjmp`, no signals as control flow.
- **Naming.** Public symbols `ants_<component>_<verb>()` (e.g.,
  `ants_crypto_blake3_hash()`). Static functions
  `<component>_<verb>()`. Headers are `<component>.h`.

## Testing requirements

- **Every component ships test vectors.** Per RFC-0008 §8 and the
  sibling repo `ants-test-vectors`, every protocol-level primitive
  has at least one fixed-input/fixed-output vector. The component's
  tests must validate against vectors in `ants-test-vectors` as
  part of its CI.
- **AddressSanitizer + UndefinedBehaviorSanitizer in CI** on every
  PR. ThreadSanitizer separately (mutually exclusive with ASan).
- **Fuzzing on protocol-parser surfaces.** Any component that
  parses bytes from the network (CBOR codec, gossip messages,
  attestation blobs, fault proofs) ships with a libFuzzer or
  AFL++ harness. The harness runs in CI.
- **Clang static analysis pass** (`scan-build` or `clang
  --analyze`) clean before merge.

## Commit and PR discipline

- **Atomic commits.** One logical change per commit. Commit
  message subject is imperative mood, ≤ 72 chars; body explains
  *why*, not just *what*.
- **No "WIP" merges to main.** Feature branches merge clean. The
  main branch is always buildable and tests-green on every
  supported platform.
- **PR review.** Component primary's PRs reviewed by the BDFL
  (during v0.x) or by another component primary; cross-component
  changes reviewed by both component primaries.

## Code of Conduct

This project adopts the **Contributor Covenant 2.1**, applied
org-wide via the
[Ants-Community/.github](https://github.com/Ants-Community/.github)
repo's `CODE_OF_CONDUCT.md`.

Routine enforcement is via the **2–3 community moderator panel**
per GOVERNANCE.md in the spec repo. Serious incidents escalate to
the BDFL (during v0.x) or to the TSC (after v1.0).

## License

Dual-licensed under **Apache-2.0 OR MIT**. By submitting a
contribution, you agree to license it under those terms. See
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).
