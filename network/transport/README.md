# transport — Component #4

P2P transport. Network layer.

**Status:** in progress — picoquic vendoring + ANTS-native protocol design.
**Effort:** 5 EM total (~3 EM picoquic wrapping + ~2 EM application protocol).
**Spec:** [RFC-0002 §DHT routing](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0002-verifiability.md), [RFC-0010 §First peer's flow](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0010-bootstrap.md), [RFC-0005 §Anti-eclipse](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md).
**Dependencies:** `foundation/crypto` (Ed25519 peer identity), `foundation/cbor` (frame encoding). External: `deps/picoquic` (to be vendored).

## Scope

The base P2P transport: peer dialing, TLS 1.3 encrypted channels via
QUIC, multiplexed streams for parallel DHT queries and gossip frames,
Ed25519 peer identity bound to QUIC TLS handshake via RFC 7250
raw-public-key, NAT-friendly UDP, anti-eclipse peer selection per
RFC-0005.

Sits below the DHT (#5) and the gossip overlay (#6); exposes a
caller-driven event loop and a stream-oriented API that those
components use.

## Architectural decision (2026-05-21)

Three paths were considered (per the earlier open-question text and
[IMPLEMENTATION.md](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)):

1. ~~Custom minimal C transport on raw UDP/TCP~~ — too much surface
   to write+audit from scratch (~6 EM just for transport-level
   correctness); IETF has already solved most of these problems in
   QUIC.
2. ~~`libp2p-c`~~ — the C++ binding is half-maintained and pulls
   a C++ runtime, violating the project's C99 pure stack.
3. ~~External daemon via IPC (go-libp2p sidecar)~~ — drags in a Go
   runtime as a hard dependency for the C client.

**Path chosen: vendor [`picoquic`](https://github.com/private-octopus/picoquic)
(IETF QUIC reference, pure C99, BSD-3-licensed) and write the ANTS-
native application protocol on top of QUIC streams.**

Picoquic gives us:

- TLS 1.3 handshake (with raw-public-key support per RFC 7250)
- Stream multiplexing within a connection (one stream per DHT query,
  separate streams for gossip frames)
- Congestion control + HOL-blocking elimination
- Connection migration (good for mobile / NAT rebinding)
- 0-RTT establishment for repeat connections

What we write on top:

- Ed25519 peer identity binding to TLS handshake (RFC 7250 raw key
  extension; bypasses X.509+CA complexity)
- DHT query / response framing (CBOR-encoded per RFC-0002)
- Gossip frame discipline (rate limits, anti-flood per RFC-0004 §L1)
- Anti-eclipse peer selection (RFC-0005)
- Bootstrap protocol (RFC-0010 first-peer flow)

The decision is documented in [IMPLEMENTATION.md component #4](https://github.com/Ants-Community/ants/blob/main/IMPLEMENTATION.md)
and the corresponding [CHANGELOG entry](https://github.com/Ants-Community/ants/blob/main/spec/CHANGELOG.md).

## v1.0 scaffold sequence

1. **API design** — in progress. The public surface (`ants_transport.h`)
   needs concrete decisions on sync/async style, opaque ctx sizing,
   error model, TLS identity binding, stream lifetime.
2. **Scaffolding PR** — stubs for all transport functions returning
   `ANTS_ERROR_NOT_IMPLEMENTED`, following the foundation/tee pattern.
3. **Vendor picoquic** under `deps/picoquic/` with the same snapshot
   discipline as `deps/{blake3,ed25519,blst}`.
4. **Wire transport wrapper** against picoquic. Tests + an in-tree
   loopback round-trip.

## Good-first-contribution flag

**No.** Touches peer-lifecycle, identity-binding cryptography, and
the network's anti-eclipse posture (RFC-0005). Claims from
contributors with prior P2P networking experience (QUIC, libp2p,
Tor, IPFS) or confidential-compute attestation background welcome
once the foundation transport API stabilises.
