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

## Live deployment smoke update — 2026-10-25

The new EC2/k3s deployment was exercised with harmless `kubectl exec` workload activity only. The eBPF agent captured live runtime events; the gateway persisted them; 12 corresponding outbox entries reached the canonical Redis stream and were processed by the causal consumer (`success=12`, pending 0, lag 0). These events are deployment smoke evidence and are not included in any pilot denominator.

The SBOM service now responds successfully after adding its missing schema migrations. It reports `unbound` because no SBOM is indexed for the observed immutable workload image digest. A smoke-only sink receipt survived a pod restart and verified its canonical integrity hash, but the receipt's oracle outcome is `unknown`, authenticity and independence are `unverified`, and storage remains on a same-node local-path PVC.

The experiment counts remain **18 planned, 0 attempted**. No attacks or benign-control scenarios were run. The independent observer/trust-anchor, executable-hash attribution, actual SBOM binding, off-node backup/recovery, and complete isolation gates remain unresolved. No detection, causal, latency, or overhead result is supported. Details and raw artifacts: `research/datasets/live_smoke_20261025T193500Z/`.


## Live SBOM and evidence follow-up — 2026-10-25 19:56 UTC

No pilot scenarios were run; planned and attempted counts remain **18 planned / 0 attempted**. The latest activity was a harmless runtime file-read smoke and sink persistence check, not an attack/control run. It produced identifiable API/outbox/Redis records, but the events had null run/scenario IDs, no executable hash, and `unbound` SBOM status. Causal consumer group state was `entries-read=22`, `pending=0`, `lag=0`; the live success metric sample was 28 cumulative messages and is not an experimental denominator.

A Syft SBOM for the exact evaluation platform manifest was generated and hashed. Its file inventory includes `/usr/local/bin/python3.11`, whose file hash matched a direct hash of that path in the running target. The agent still did not provide per-event executable bytes/hash; the interpreter file has no PURL/package occurrence, and the SBOM service database remains empty. Therefore no component-level binding is reported.

A real unknown sink receipt survived a pod restart and its integrity hash verified. A manual actual-S3 backup/restore recovered 2 receipts into a fresh database with matching canonical receipt hashes. The receipt oracle outcome remains `unknown`, and authenticity/independence remain unverified.

The production trust store has no keys and no live independent observer source exists. The evaluation cross-namespace Redis probe was denied (`connect_ex=111`), but public egress was not directly probed. Accordingly the 18-run profile remains invalid to launch. No precision, recall, F1, false-positive rate, detection latency, overhead, or causal-effect estimate is supported. Evidence: `research/datasets/live_attribution_20261025T194226Z/`.

Receipt timestamp clarification (2026-10-25): receipt `0956698a-668c-55e8-9033-e61de20f677c` was created at `2026-10-25T19:46:14.185107+00:00`. Its run ID's embedded `194800Z` is only an operator smoke label, not an observation timestamp. The manual project backup client used the controller AWS identity `arn:aws:iam::253490771520:user/harsh2`; the SBOM artifact upload used the lab instance role.

## Final live readiness check — 2026-10-25 20:08–20:12 UTC

No experiment run was attempted. The latest evidence is a harmless file-read smoke event only. It was persisted by the API/outbox and published as Redis ID `1792958994132-0`; the consumer group advanced past it with no pending message. Event `7893c151-30ff-4c78-b1d2-38c695c658ec` has no run/scenario identifiers, no executable hash, and returns `unbound` at the live SBOM binding endpoint. The service database still has 0 SBOM rows.

The image artifact remains complete and tied to the exact evaluation platform manifest (raw SBOM SHA-256 `sha256:c5b3a412b3534cfb0647b639cbc3e2993bbd2b09797aff9b34ce5a3904e04c80`). Indexing is blocked by missing SBOM pod object-store configuration/credential path and an IAM/key-prefix mismatch. The oracle ConfigMap remains empty, with no independent live observer. Sink receipt integrity and prior actual S3 restore are verified, but authenticity/independence remain unknown and backups are not automated. Public egress was not probed.

**Pilot: 18 planned / 0 attempted / 0 valid.** No confusion-matrix, detection latency, resource overhead, or causal-effect metric is calculable. Smoke telemetry and cumulative service counters are not pilot outcomes. Detailed captured evidence: `research/datasets/live_finalization_20261025T200807Z/`.


## SBOM ingestion smoke update — 2026-10-25

The exact evaluation-image SBOM is now indexed by the deployed SBOM service. One harmless non-pilot workload smoke event reached the API/outbox and canonical Redis stream; the consumer group had progressed through the event (entries-read 49, pending 0, lag 0). The event had no run/scenario IDs and represented `runc` initialization. SBOM binding returned `insufficient_evidence` because the SBOM remains pending signature verification and executable hash is unavailable. No event is counted as an attack/control result.

The production oracle trust store remains empty, no independent live observer is configured, and no trusted signed receipt was created. Pilot counts remain **18 planned / 0 attempted / 0 valid**. Confusion-matrix metrics, latency, overhead, and causal effects remain unavailable.

## Trust and direct application probe — 2026-10-25 21:04 UTC

The running recommendationservice returned HTTP 200 to a direct internal request, confirmed by its own access log. The sampled eBPF agent log showed identity-insufficient events and no attributable application event for that request. The prior `runc:[2:INIT]` record arose during `kubectl exec` and remains unsuitable for application component attribution. No executable hash, PURL, trusted SBOM signature, or run/scenario correlation was demonstrated. The deployed oracle public-key store still contains zero keys and no independent live observer produced ground truth. The pilot remains **18 planned / 0 attempted / 0 valid**; TP/FP/TN/FN and all performance and causal metrics are unavailable. Raw command responses: `research/datasets/trust_attribution_20261025T2104Z/`.
## 2026-10-25 live readiness update

The existing lab remains running. A harmless event (`f344d15a-5260-478c-9025-022ebe955f56`) reached API persistence, Redis stream ID `1792964344284-0`, and the causal consumer (pending 0, lag 0), but was a `runc:[2:INIT]` transition with no event-time executable hash or supported component binding. The exact-image indexed SBOM has 22,823 components and status `pending`; the live verifier rejects an unconfigured signer with HTTP 503. The deployed oracle trust store has zero keys and no independent live contract observer supplies run-level ground truth. **Pilot: 18 planned, 0 attempted, 0 valid.** TP/FP/TN/FN, precision, recall, F1, false-positive rate, detection latency, overhead, and causal effects are unavailable. These smoke observations are not experiment results. Evidence: `research/datasets/attribution_probe_20261025T2132Z/` and `research/datasets/trust_integration_20261025T2150Z/`.
