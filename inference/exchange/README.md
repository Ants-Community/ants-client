# inference/exchange

How a requester asks a node for an inference answer over a live connection, and how it checks what comes back.

**Spec:** [RFC-0008 §11.14–§11.15](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0008-wire-formats.md) (bytes) · [RFC-0003](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0003-verification.md) (what the commit is for) · [RFC-0004 §Computing A](https://github.com/Ants-Community/ants/blob/main/spec/RFC-0004-reputation-pouh.md) (what a receipt is for).

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

**Receipts (§11.15).** After an answered exchange the requester pays with a receipt. `ants_infer_receipt_prepare` builds the §11.9 body (`server` = the connection's peer-id, `nonce` = `BLAKE3(commit)[0:16]`, `ncs_value` = 1000 μNCS × positions) and signs it. `ants_infer_offer_receipt` sends it as `RECEIPT_OFFER` (type 13). The producer countersigns in `RECEIPT_ACK` (type 14) iff all of these hold:
- the body is canonical and names this producer as server and this connection's peer as client;
- the client signature verifies;
- the nonce names an answer the producer served to this client within `RECEIPT_WINDOW` (600 s, inclusive), and the producer has never filed a receipt for it. The second half is checked through `receipt_paid_fn` against its whole history, because a replayed request reproduces the same commit and nonce. The result is at most one receipt per answer, ever;
- the value is at least the reference rate;
- the timestamp is within `RECEIPT_CLOCK_SKEW` (300 s) of the producer's clock.

Otherwise it refuses with the empty body. Filing the receipt is the caller's job (`receipt_fn`); the daemon appends it to its bag on disk. The producer remembers the last `ANTS_INFER_MAX_SERVED` (256) answers, one entry per nonce for the first requester, and forgets paid ones first.

| receipt verdict | when |
|---|---|
| `ACKED` | the countersignature makes the receipt whole: both signatures verify, under the connection's peer-id |
| `REFUSED` | empty ACK |
| `REJECTED` | malformed ACK, wrong txid, or a countersignature that does not verify |
| `NO_ANSWER` | stream reset, connection closed, or timeout |

An answered response is the input to an audit, not the audit. The audit (`ants_inference_audit`) needs `B_{r+1}`, and v1 pins no beacon for it yet (RFC-0008 §10).

## Status

The daemon (`cmd/antsd`) serves every tier 1–3 request with the pinned v1 reference model (`ants_inference_ref_model_v1_build`), so every reference node has the same `model_hash` and can audit any other. `antsd ask` is the one-shot requester.

`antsd ask` pays for every answer with a receipt, and `antsd receipts <config>` shows the node's bag with its A and T.

Not yet here: bonds over A (§11.10, the next PR) and audit dispatch.

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

- **Receipts:**
  - the codec, with hand-written bytes and caps;
  - an acked receipt, which both sides then hold whole;
  - one case per producer rule: once per nonce, rate, skew and window each at the edge and one past it, a request replayed after its window, foreign client, wrong nonce, bad client signature, no signer.
  - Removing the once-per-nonce, paid-history, skew or window rule makes its own test fail.

`cmd/antsd/tests/test_antsd_run.c` runs the real `antsd ask` against the spawned daemon. The answer is paid for and filed, and a restart reloads the bag: it skips a record with a corrupted signature and cuts a torn tail, so a receipt filed afterwards stays readable.
