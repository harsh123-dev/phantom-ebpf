# Phase 1 — Source Blocker Resolution

**Status (updated 2026-10-25):** Follow-up source fixes and focused tests have now run in an isolated Python 3.11.13 environment. This report's original environment limitations below are historical. Full runtime and Kubernetes validation remains unavailable on the shared SQL Server controller.

## Changes

| Blocker | Resolution | Evidence and remaining limit |
|---|---|---|
| Causal exporter routing | Declared container/Service port 9090 for metrics and changed Prometheus target to that port; health stays on 8080. Corrected the cAdvisor path replacement. | Parsed manifest and embedded Prometheus YAML; cross-checked target port statically. Prometheus scrape health is unverified. |
| Agent event lag absent | Added `phantom_event_delivery_lag_seconds` histogram and bounded invalid-timestamp counter. The BPF timestamp is `bpf_ktime_get_ns()`; callback entry is captured with `time.monotonic_ns()`. Zero and negative deltas are excluded. Added `/metrics` on port 9101, a ClusterIP Service, scrape job, and optional NetworkPolicy ingress. | AST/YAML checks passed. Unit test added but could not run. Runtime same-clock assumption, fresh buckets, and timestamp validity require the dedicated single-node lab. |
| Event metric semantics | Histogram measures **kernel event to userspace ring-buffer callback entry**, in seconds. The runner's p95 is `histogram_quantile` over a 5-minute rate and is represented in milliseconds. It is not API ingestion latency, detection latency, or end-to-end latency. | Kernel and userspace clocks must share the node monotonic domain without a time-namespace offset. Invalid values increment a reason-labeled counter; no zero is substituted. |
| Benign no-ops | Added controls: run-tagged Deployment annotation rollout with unchanged image refs; finite 200-request burst to the internal paired service, requiring request-token access-log evidence; and pod deletion with new Ready UID verification. | A mocked local control check and Python payload compilation passed. No cluster was available, so actual service receipts and telemetry activity are not verified. `benign-update-001` is now explicitly a metadata rollout, not a dependency update. |
| Config mismatch | Added validated YAML loader. The config drives pilot/extended scenario membership, workload pairing, repetitions, timing, namespace, and output root. CLI supports `--config`; explicit values remain overrides. | Config and scenario counts checked locally (18/27 planned); runner/import tests could not run due to missing `httpx` and pytest. |
| Nullable metrics | Evaluator filters absent samples per metric, distinguishes a measured zero from missing data, rejects non-finite/negative Prometheus samples, and reports unknown overhead as `None`. | AST and source checks passed; pytest could not run. |
| Historical output/oracle protection | Batch output defaults to a unique UTC timestamp path; existing paths and descendants of `raw/` or `raw3/` are refused. Oracle, run JSON, failed-run JSON, and index files use exclusive creation. Per-batch oracles live under that batch's `oracles/`. Run IDs include microseconds and a random suffix. | Output resolution and refusal tests added, not executed because pytest is unavailable. Existing data was not modified. |
| Ground-truth honesty | Run records mark contract outcome `unknown_contract_state` until an independent contract oracle exists. The evaluator excludes those records from TP/FP/FN/TN counts. Intervention verification is recorded separately from PHANTOM alerts. | Source-level only. No independent contract-state source is currently wired, so live detection metrics will remain inconclusive until one is implemented and validated. |

## Validation actually performed

- `ast.parse` on changed Python source/test files: **PASS**.
- PyYAML parsing of the experiment config, four Kubernetes manifests, and embedded Prometheus config: **PASS**.
- Matrix, target, and output-root assertions: **PASS** (6 pilot scenarios × 3 repetitions = 18; 9 extended scenarios × 3 = 27).
- Static exporter/scrape route assertions: **PASS** (causal 9090, agent 9101).
- Mocked benign-load subprocess receipt, command argument boundary, and payload compilation: **PASS**; this is synthetic validation, not a live activity observation.
- `python3 -m unittest tests.test_event_lag -v` from `services/ebpf-agent/`: **3 passed** for valid delta, zero source timestamp, and future timestamp rejection. This pure unit test runs without the agent's external dependencies.
- `python3 -m unittest research.evaluation.tests.test_config_unittest -v` from the repository root: **2 passed** for the 18/27 configured profiles, target pairings, and existing/historical output refusal.
- `git diff --check`: **PASS**.
- Focused pytest command: **NOT RUN**; Python reported `No module named pytest`. Project dependencies and supported Python 3.11 are unavailable. No unit test pass is claimed.

## Protocol implication

The new controls exercise bounded operational activity, but the dependency-update research treatment/control pairing has changed. The paper and protocol must describe the update control as a metadata rollout. Until an independent source verifies actual contract conformance/drift, do not calculate detection confusion-matrix metrics from expected scenario IDs or absent alerts.

## Follow-up pipeline repair (2026-10-25 15:33 UTC)

- Canonical Redis contract `1.0` and stream `phantom:drift-events` now live in `phantom-core`. API publisher and causal consumer use it; k3s-lab gateway/causal Redis URLs now use DB 0. Fake-Redis tests verify publish → schema validation → causal mutation invocation → acknowledgement and malformed payload remains pending.
- The consumer validates required workload/process/runtime evidence and timezone/digest shape, preserves unbound status with zero confidence, and does not ACK on processing or DLQ write failure. This is not a live Redis/PostgreSQL result.
- Agent stops emitting fabricated generic violations, placeholder all-zero digest, constant sequence, zero pod UID, default service account, and zero image digest. It hashes the parsed event and requires exact container identity plus runtime `image_id` immutable digest before forwarding. The agent's image digest helper has two focused tests. Runtime behavior remains unverified.
- Latest follow-up totals: phantom-core **47 passed**; evaluation **222 passed**; causal Redis/integration **69 passed**; SBOM mapper/domain **125 passed**; API outbox-retry/endpoint **8 passed**; agent lag/digest **5 passed**. **476 passed, 0 failed.** Terraform fmt/init/validate, `compileall`, YAML parse, and `git diff --check` passed. The earlier 422-test total above is superseded by this count.
- Remaining blockers: resolver serialization is not wired into ingestion; there is no independent contract oracle or run-correlated durable sink receipt. Accordingly no lab plan/apply or experiment proceeded.

## Follow-up implementation update (2026-10-25)

The SBOM resolver is now wired into gateway drift-event ingestion through the SBOM service's tenant-scoped runtime-binding endpoint. Exact CycloneDX SHA-256 component hashes can support positive attribution; path-only evidence and unresolved cases abstain. Gateway tests verify the mapping handoff and explicit unknown result when the service is unavailable. SBOM endpoint and resolver fixtures cover exact binding, ambiguous evidence, missing SBOM/provenance, and digest mismatch. These results are synthetic/local; the agent currently does not provide executable hashes, and no live attribution has been observed.

The blocking ground-truth gap remains: the sink has no durable run-correlated receipt store, and no independent contract-state oracle is wired to scenario outcomes. The end-to-end readiness gate is therefore still failed; no Terraform plan, deployment, or pilot execution was started.

## Independent oracle and receipt follow-up (2026-10-25)

Added a fail-closed deterministic contract evaluator in `research/evaluation/oracle.py` and a durable SQLite receipt store in `research/evaluation/evidence_store.py`. The evaluator rejects detector-derived sources, checks a supplied active/verified contract snapshot and workload selector, and emits confirmed violation, confirmed compliance (only with complete coverage), or unknown. The scenario runner now writes one versioned receipt per attempt in the unique batch directory; absent independent evidence is recorded as unknown. The store uses durable SQLite commits, deterministic receipt IDs, retry idempotency, conflict rejection, retrieval, and canonical-hash verification.

Tests prove oracle/store behavior and an oracle-to-file-store composition with controlled fixtures. They do not authenticate the claimed contract signature or the producer of an `independent_sink` observation. There is no live contract snapshot adapter or independent evidence collector in this checkout. The existing in-cluster TCP `phantom-sink` still only accepts/closes connections and does not produce durable run-correlated connection receipts. The composed runtime-to-oracle-to-sink pipeline is therefore not verified and AWS/pilot readiness remains blocked. Agent executable hashes also remain unavailable: the eBPF event ABI exposes executable path and argv digest, not executable-byte SHA-256; hashing via `/proc` would require a new race/overhead design.

Final relevant tests: **494 passed, 0 failed**; compileall, 15-file YAML parse, and `git diff --check` passed. No Terraform plan, deployment, AWS changes, or scenario executions were performed.
