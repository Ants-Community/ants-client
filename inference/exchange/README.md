# inference/exchange

How a requester asks a node for an inference answer over a live connection, and how it checks what comes back.

**Spec:** [RFC-0008 §11.14](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md) (bytes) · [RFC-0003](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0003-verification.md) (what the commit is for).

## What it does

- **Exchange.** The requester sends `INFER_REQ` (type 11) `{input, tier, req_nonce}` on a new bidirectional stream. The producer answers on that stream with `INFER_RESP` (type 12): either empty (declined) or `{commit, sig, envelope}`, the §11.8 commit and the full answer envelope.
- **Shared envelope.** Both messages use the DHT's envelope and stream discipline. The DHT server, `network/attest` and this module all see every inbound bidi stream. This module classifies a stream from its first bytes (the envelope head) and releases anything that is not an `INFER_REQ` straight away, so a peer's concurrent DHT RPCs never occupy its slots. Release is silent: the stream may be a sibling's.
- **Producer.** A callback. The engine decodes the request and hands it to `serve_fn`, which answers or declines. `ants_infer_serve_reference` is the bridge to `ants_inference_serve` for the reference model.
- **Requester check.** `ants_inference_answer_check` runs under the peer-id the transport authenticated for this connection, never a key from the wire, so a relayed answer fails.

| verdict | when |
|---|---|
| `ANSWERED` | the signature, the match with the request, the envelope shape and the §11.8 integrity gate all hold |
| `DECLINED` | empty answer |
| `REJECTED` | any check fails, or the answer is malformed, oversized or echoes the wrong txid |
| `NO_ANSWER` | stream reset, connection closed, or `ants_infer_tick` timed the request out |

An answered response is the input to an audit, not the audit. The audit (`ants_inference_audit`) needs `B_{r+1}`, and v1 pins no beacon for it yet (RFC-0008 §10).

## Status

The daemon (`cmd/antsd`) serves every tier 1–3 request with the pinned v1 reference model (`ants_inference_ref_model_v1_build`), so every reference node has the same `model_hash` and can audit any other. `antsd ask` is the one-shot requester.

Not yet here: receipts (RFC-0008 §11.9) and their countersignature round-trip, which come in the next PR, and audit dispatch.

## Tests

`tests/test_infer.c`:
- **Codec:** hand-written canonical bytes and the strict-decoder rejections, including the pinned input and response caps.
- **Engine:** runs over two real loopback QUIC transports. Cases:
  - an honest answer, which the requester then audits with nothing but the pinned model;
  - a decline;
  - a tampered envelope;
  - an answer signed by a key other than the connection's peer-id;
  - malformed, wrong-txid and oversized replies;
  - a silent producer, which times out;
  - two non-INFER bidi streams held open, which must not block the INFER_REQ. Holding them until FIN instead makes this test fail.

`cmd/antsd/tests/test_antsd_run.c` runs the real `antsd ask` against the spawned daemon.
