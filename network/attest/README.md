# network/attest

How a peer presents its TEE attestation over a live connection, and how the receiver judges it: the v1 handshake gate.

**Spec:** [RFC-0008 §11.12](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md) (bytes) · [RFC-0005 §v1 admission posture](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0005-identity.md) (policy).

## What it does

- **Exchange.** After the handshake, each side sends `ATTEST_REQ` (type 9) on a new bidirectional stream. The peer answers on that same stream with `ATTEST_RESP` (type 10). The answer is either empty ("nothing to present") or `{vendor, issued_at, expires_at, blob}`.
- **Shared envelope.** Both messages use the DHT's envelope and stream discipline. This module and the DHT server both see every inbound bidi stream. Each one claims only its own envelope types and releases the rest silently.
- **Verdict.** The receiver verifies the presentation with `foundation/tee` and caches one verdict per connection. Verification is `ants_attestation_verify` (chain to the pinned vendor root, signature, `report_data` bound to the connection's authenticated peer-id and `issued_at`) plus `ants_attestation_is_fresh`. The bound key always comes from `ants_transport_conn_peer_id` and is never taken from the wire.

| verdict | when |
|---|---|
| `UNATTESTED` | empty answer; a vendor this build cannot verify yet (fail closed); genuine evidence that is no longer fresh |
| `ATTESTED` | evidence verifies and is fresh |
| `REJECTED` | evidence fails verification, or the answer is malformed |

The module reports verdicts. **Policy belongs to the caller.** The daemon (`cmd/antsd`) runs RFC-0005's v1 **verify-and-tag** posture:
- it admits unattested peers;
- it tags attested ones;
- it disconnects rejected ones, because presenting false evidence is worse than presenting none.

## Status

Every v1 node answers with the empty body, because producing evidence needs `ants_attestation_generate` on real confidential-compute hardware. A live network therefore produces `UNATTESTED` and, for forged or relayed evidence, `REJECTED`.

The `ATTESTED` path is covered only up to the evidence half:
- `foundation/tee` verifies genuine Intel TDX and AMD SEV-SNP evidence;
- the end-to-end positive test arrives with `generate` on real hardware.

## Tests

`tests/test_attest.c`:
- **Codec:** hand-written canonical bytes and the strict-decoder rejections.
- **Engine:** runs over two real loopback QUIC transports and covers empty answers both ways, a **genuine** TDX quote presented by a peer it is not bound to (→ `REJECTED`), an unverifiable vendor (→ `UNATTESTED`), malformed answers (→ `REJECTED`) and a silent peer (no verdict, nothing leaks under ASan).

`cmd/antsd/tests/test_antsd_run.c` runs the gate in the real daemon, alongside DHT bootstrap on the same connection. It includes the disconnect on false evidence.
