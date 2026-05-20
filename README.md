# ants-client

The all-in-one reference client for the ANTS protocol.

**Status:** scaffolding. No component code yet. Pending claims on
foundation-layer components (#1 crypto primitives, #2 CBOR codec,
#3 TEE attestation harness) per
[IMPLEMENTATION.md §"How to claim a sub-component"](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md#how-to-claim-a-sub-component).

## What this is

The reference implementation of the ANTS protocol — the open
peer-to-peer protocol for distributed/sovereign AI specified at
[Ants-Community/ants](https://github.com/Ants-Community/ants).

Written in C (C99/C11), built with CMake, cross-platform. Targets
every server, every Apple Silicon, every Android NDK target, every
embedded ARM chip with a TEE. The canonical inference kernels
leverage [`ggml`](https://github.com/ggerganov/ggml) as the
computational foundation.

The choice of C reflects two priorities the project declared when
the design corpus closed and the conversation pivoted to code:
maximum performance on the audited path, and total cross-platform
reach. The trade-off (no compile-time memory safety) is accepted
explicitly per Manifesto Thesis 18, mitigated through static
analysis (`-Wpedantic` clean, Clang `-Weverything` review),
AddressSanitizer + UBSan + ThreadSanitizer in CI, fuzzing on every
protocol-parser surface, and external security audit at Phase F
per IMPLEMENTATION.md.

## Layout

The client decomposes into 15 sub-components across 6 layers, per
IMPLEMENTATION.md. The directory tree mirrors that decomposition;
each layer subdirectory contains its own `CMakeLists.txt` and a
`README.md`, and each component subdirectory contains a
`README.md` with the spec reference, claim status, and intended
interface.

| Layer | Components | Effort (EM) |
|---|---|---|
| `foundation/` | crypto primitives, CBOR codec, TEE attestation harness | ~9 |
| `network/` | P2P transport, Kademlia DHT (shard-key variant), gossip overlay | ~9 |
| `reputation/` | L1 CRDT (G-Set), L2 PoUH chain, identity & reputation service | ~13 |
| `cache/` | semantic cache (DHT-routed), canonical embedding service | ~6 |
| `inference/` | `ants-canonical-kernels`, inference orchestration | ~10–18 |
| `economy/` | local economic ledger, bond accounting service | ~4 |

Total: ~51–62 engineer-months of component work, plus ~15–20 EM
integration testing and ~6–10 EM security audit. Realistic
wall-clock: 24–36 months with a team of 4–6 engineers.

## Build (when there is something to build)

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest
```

Requirements:

- CMake ≥ 3.20
- C99 compiler: GCC ≥ 9, Clang ≥ 10, or MSVC 2019+
- Platform-dependent: TEE SDK for the target vendor (Intel SGX/TDX,
  AMD SEV-SNP, ARM CCA, Apple SE, Qualcomm QSEE)

Optional / per-component dependencies (declared per the
component's `README.md` as it arrives):

- [`ggml`](https://github.com/ggerganov/ggml) — vendored or git
  submodule, foundation for `inference/kernels/`
- [`blst`](https://github.com/supranational/blst) — BLS12-381
- [`BLAKE3`](https://github.com/BLAKE3-team/BLAKE3) C reference
- [`tinycbor`](https://github.com/intel/tinycbor) or
  [`nanocbor`](https://github.com/bergzand/NanoCBOR) — CBOR codec
  candidate baseline

## How to claim a component

Per the spec repo's IMPLEMENTATION.md:

1. Open an issue on
   [Ants-Community/ants](https://github.com/Ants-Community/ants)
   titled `[CLAIM] Component #N — <name>`.
2. Describe: your background, why you're suited, expected start
   date, expected duration, working hours per week.
3. Wait for the nomination window (currently 2–3 weeks). The BDFL
   (during v0.x) reviews; multiple claims for the same component
   go to the most-qualified-and-available.
4. Once acknowledged, the claim is recorded in `CONTRIBUTORS.md`
   (in this repo) and you become the primary contributor for
   that component.

The same process applies whether you intend to contribute one
component or several. A first contribution naturally starts with
the smaller-scope components — #2 (CBOR codec, ~1 EM), #11
(embedding service, ~1 EM), #15 (bond accounting, ~2 EM) — per
IMPLEMENTATION.md §"Parallelisable vs critical-path work."

## License

Dual-licensed under **Apache-2.0 OR MIT**. See
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).
Choose whichever fits your downstream needs.

The dual-license is the modern standard for systems code: the
Apache-2.0 path provides explicit patent grant (non-negotiable for
crypto/TEE-touching code), the MIT path maximises permissiveness
for downstream forks. The spec repo (`Ants-Community/ants`) is
CC0; this client repo is dual-licensed because code requires
patent grant protection that CC0 does not provide.

## Protocol specification

The protocol itself — RFCs, manifesto, governance, CHANGELOG —
lives at [Ants-Community/ants](https://github.com/Ants-Community/ants).
This repository **implements** that specification; it does **not**
modify it. Protocol-level questions, RFC amendments, and design
discussions go to the spec repo.

The bytes on the wire are the spec, not the source. Any conforming
reimplementation of ANTS in any other systems language is equally
valid; the v1.0 condition of "at least three independent client
implementations" anticipates this explicitly (GOVERNANCE.md §"When
BDFL ends: the sunset for v1.0").

## Code of Conduct

This project adopts the Contributor Covenant 2.1, applied org-wide
via the [Ants-Community/.github](https://github.com/Ants-Community/.github)
repo. Routine enforcement is via the 2–3 community moderator
panel per GOVERNANCE.md (in the spec repo).
