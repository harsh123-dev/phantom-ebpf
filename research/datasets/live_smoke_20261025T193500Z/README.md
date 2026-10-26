# Live smoke evidence — 2026-10-25

This directory contains live, non-experimental deployment validation only. The activity was harmless `kubectl exec`/shell sleep and service probes. No attack/control scenario or pilot run was executed.

## Verified path

Six sampled recommendationservice events are recorded in `runtime_smoke_events.csv`. The eBPF agent observed real kernel events, resolved them to the live Kubernetes pod and image digest, the API committed the event and an outbox row, Redis published to `phantom:drift-events`, and the causal consumer processed events. At the latest captured check, the consumer success counter was 12, the Redis consumer group had `entries-read=12`, `pending=0`, and `lag=0`.

The SBOM service initially returned HTTP 500 because the `sboms` table had never been migrated. A dedicated `phantom_sbom` schema and startup migrations were added. After the fix, runtime binding calls returned HTTP 200 and yielded `unbound`/`insufficient_evidence`: the SBOM schema contained zero SBOM documents for the actual target image digest. No PURL or SBOM ID is asserted. The API database stores the normalized binding status `missing`.

An explicit unknown smoke receipt was POSTed to the actual FastAPI sink, retrieved, and integrity-verified. After restarting the sink Deployment, the same receipt ID remained retrievable and its integrity hash remained valid. Receipt ID: `5ce90608-0117-5836-95dc-01f37543ab38`. Oracle outcome is `unknown`; authenticity and independence are `unverified`. This is not an experiment oracle result. SQLite is on a single-node `local-path` PVC; node-loss or instance-termination recovery and off-node backup have not been tested.

## Limits

- Event `run_id` and `scenario_id` from the agent were null. The receipt's smoke run/scenario labels were assigned only to the validation request; do not count it as a runner-generated experiment.
- Oracle trusted-key ConfigMap is empty; no production trust anchor or live independent workload/contract observer exists.
- Executable hash is unavailable; runtime-to-component attribution remains unbound.
- The lab's SG has no ingress and the EC2 instance has no public IP. Host egress allows TCP 80/443 via NAT. An evaluation Pod's TCP connect to Redis in another namespace was refused while the API gateway could connect to that Redis service; this is a cross-namespace isolation check. Public egress was not directly probed.
- Event lag is kernel timestamp to ring-buffer callback, not ingestion, detection, or end-to-end latency. Resource CPU values are one-minute point-in-time usage samples, not overhead estimates.
- No attack/control experiment, precision/recall, detection latency, causal-effect estimate, or overhead experiment was run.

Raw command results are retained as JSON files in this directory, together with `aws_inventory.json` and Terraform state addresses.
