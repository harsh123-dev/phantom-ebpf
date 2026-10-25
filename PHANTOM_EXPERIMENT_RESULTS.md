# PHANTOM Experiment Results

**Status: controlled pilot withheld at the telemetry and ground-truth gate.** No attack or benign-control scenario was attempted. The only runtime actions were infrastructure validation and harmless smoke tests in the dedicated lab.

## Run accounting

| Measure | Result |
|---|---:|
| Planned pilot profile | 18 (3 attacks × 3 repetitions; 3 controls × 3 repetitions) |
| Attempted scenarios | 0 |
| Injection successes / failures | 0 / 0 |
| Behaviorally verified attack/control runs | 0 / 0 |
| Independently verified contract outcomes | 0 |
| PHANTOM alert outcomes | 0 |
| Complete / partial / missing experiment telemetry | 0 / 0 / 0 runs |
| Extended profile | Not run |

These counts describe experiment runs, not smoke-test events. The config-driven dry-run printed the 18-scenario matrix and performed no cluster mutation or experiment writes.

## Harmless deployment smoke evidence (not pilot data)

At `2026-10-25T15:08:26Z`, the runner retrieved actual Prometheus measurements: eBPF-agent CPU rate `0.00942` cores, RSS `69.73 MiB`, and kernel-to-agent-callback p95 `32.96 ms`. A preceding Prometheus sample showed `phantom_event_delivery_lag_seconds_count=2877`. These values are point-in-time smoke measurements from host orchestration activity and must not be described as attack overhead or scenario latency.

A harmless in-cluster emailservice HTTP request returned 200. The event stream sample included 21 resolved `phantom-eval` records and 29 ambiguous host/runtime records in a 50-row query. Even the resolved event had no PURL, SBOM ID, or binding status; its reported violation was generic. The causal Redis consumer remained at stream ID `0-0` because publisher/consumer stream names and payloads disagree. Event payloads also carry the incorrect hard-coded cluster name `phantom-eks` instead of the deployed `phantom-k3s-lab`.

## Supported conclusions

- The eBPF agent can load programs on this kernel, export its event-lag histogram, and deliver events that the API gateway durably accepts.
- Prometheus reached the actual API, causal-engine, agent, and cAdvisor targets.
- The evaluation namespace has an active egress policy; an evaluation Pod reached the internal sink and was refused when connecting to an unauthorized cross-namespace monitoring endpoint.
- Runtime-to-SBOM binding, causal-engine event consumption, and independent contract verification were **not** demonstrated.

No precision, recall, F1, false-positive rate, confidence interval, detection latency, causal effect, or experimental overhead estimate is reported. These quantities are unavailable, not zero. No attack/control replacement run was attempted. The 27-run extension is not justified until the event pipeline and independent oracle gates pass.

Raw smoke artifacts: `research/datasets/smoke_batch/20261025T150659Z/`. Deployment and blocker details: `PHANTOM_DEPLOYMENT_VERIFICATION.md`.

## Current execution update (2026-10-25)

No new experiment was started after repairing the Redis event contract and removing fabricated agent identity/violation placeholders. The source-level fake-Redis test now processes a valid versioned event and acknowledges it; malformed schema remains pending. This does not constitute live lab telemetry or independent contract ground truth. SBOM resolution is still not wired into ingestion, and no durable sink/oracle receipt is available. Thus the current run counts remain the historical **18 planned, 0 attempted in the latest valid pilot**, with no detection, latency, overhead, or causal metric supported by these code tests. The previously deployed smoke events are not reclassified as pilot results.

Latest local suites total **476 passed, 0 failed**. They include synthetic fake-Redis consumer/BDG and resolver serialization checks, not a live experiment; the pilot counts above remain unchanged.
