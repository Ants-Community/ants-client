# inference/

The economic engine of the network: canonical kernel library and the
orchestration that does inference, commits at send, and dispatches
audits.

**Effort:** ~10–18 engineer-months total (CPU baseline); GPU canonical
kernels add 6–18 EM per platform as v0.2+ deliverables.

| Component | Effort | Spec | Status |
|---|---|---|---|
| [`kernels/`](./kernels) — `ants-canonical-kernels` (#12) | 6–12 EM (CPU) | RFC-0009 v0.5 | pending claim |
| [`orchestration/`](./orchestration) — Inference orchestration (#13) | 4 EM | RFC-0003 v0.2, RFC-0009 v0.5 | pending claim |

The kernel library (#12) is **the largest engineering risk in the
entire corpus** per IMPLEMENTATION.md. The strategy: leverage
[`ggml`](https://github.com/ggerganov/ggml) as the computational
foundation (vendored or git-submoduled under `deps/ggml/`) with the
*discipline layer* of RFC-0009 §§ 1–5 above it — the left-biased
binary tree max reduction (§2.1), the divide-not-reciprocal scale
arithmetic (§2.1), the q24 conversion (§5), the INT8-GPTQ-128 pinning
(§1). The `cpu_scalar.c` path is the bit-exact reference; every SIMD
implementation must produce byte-identical output against it on every
supported architecture for every test vector.

The orchestration (#13) is on the critical path. It depends on #11
(embedding service), #12 (kernels), #7 (L1 CRDT), #9 (identity), and
#10 (cache), so it sequences last among the integration-heavy
components.
