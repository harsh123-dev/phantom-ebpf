# Pilot Batch 01 Analysis

## Decision

**Do not analyze a pilot confusion matrix or extend the profile.** The controlled run loop was not entered because the pre-run end-to-end checks found missing causal delivery and missing independent SBOM/contract ground truth.

## Profile and outcomes

The active YAML and runner define 3 configured attack scenarios and 3 benign controls, each repeated 3 times: **18 planned; 0 attempted**. No injections succeeded or failed because no injection was started. No run-level behavior, contract, alert, or latency label exists.

The actual 18-run dry-run matrix was printed at 2026-10-25 15:04 UTC. It did not mutate the cluster or write experiment records. The historical status-only directory `research/datasets/pilot_batch01/20261025T123839Z/` remains untouched.

## Preflight evidence and reasons for withholding

The agent generated live kernel-event samples and successfully posted events to the API gateway. Prometheus targets for the API, causal engine, agent, and cAdvisor were UP. A harmless workload request and an internal sink connection were observed. However:

- The agent-resolved event had no SBOM PURL, SBOM ID, binding status, or provenance.
- Generic violation objects were emitted without a verified behavioral contract.
- API publisher writes to `phantom:bdg:mutations`, while the causal consumer listens on `phantom:drift-events`; the consumer group showed no delivered message.
- The sink does not persist independent receipts.
- Agent event payloads hard-code cluster name `phantom-eks`, which is not the deployed cluster identity.

These are preconditions for the stated causal attribution study, not ordinary statistical missingness. Counting any alert absence as a negative would be invalid.

## Metrics

Detection precision/recall/F1, false-positive rate, confidence intervals, injection success rates, detection latency, causal estimates, and pilot overhead are all **not estimable** because no scenarios were attempted. Smoke-only measurements are in `research/datasets/smoke_batch/20261025T150659Z/preflight-metrics.json` and must not be mixed into experimental analysis.

## Extension

The 27-run profile is not justified. First align the Redis stream name and payload schema, implement or connect workload-image SBOM binding with provenance, and independently verify contract state and sink receipts. Then rerun harmless integration checks and start a new uniquely named pilot only after those checks pass.

## Live finalization check — 2026-10-25 20:08–20:12 UTC

This later check supersedes the earlier smoke conclusions above where noted: API-to-Redis stream alignment and sink persistence have since been demonstrated with live harmless events/receipts. The current lab showed event `7893c151-30ff-4c78-b1d2-38c695c658ec` persisted and published to Redis ID `1792958994132-0`; the causal consumer group advanced through the message. The live SBOM binding endpoint still returned `unbound` for the exact evaluation image digest, the SBOM database had 0 rows, the oracle trust keys are empty, and no independent live contract observer exists. The event had no run/scenario IDs or executable hash, and its process was `runc:[1:CHILD]`.

The planned pilot remains **18 planned, 0 attempted, 0 valid**. No confusion matrix, precision, recall, F1, false-positive rate, latency, overhead, or causal estimate is supported. Current raw evidence: `research/datasets/live_finalization_20261025T200807Z/`.


## Latest pre-pilot gate — SBOM indexing verified, other gates closed

The real SBOM service indexed Syft's CycloneDX artifact for config digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7` (manifest `sha256:ec4370b0af44b4ba2ffe0247f1b1339c4f4debdba319d025d5753140ccec4184`). It returned 22,823 components; subsequent retrieval matched the canonical document hash. A wrong raw-artifact hash was rejected before DB persistence, and an identical retry after deployment returned the same SBOM ID without adding rows.

No pilot was run. The live observer/trust store is unavailable (zero production keys); the runtime smoke event had no run/scenario identity or executable hash, and binding remained `insufficient_evidence` because the SBOM is `pending` verification. Accordingly the valid experimental denominator is still zero and performance or causal metrics cannot be calculated.

### 2026-10-25 21:04 UTC gate check

Direct internal application HTTP activity succeeded, but the sampled agent output did not contain an attributable application-process event. The deployed trust store still has zero keys; no independent live contract assertion or signed receipt exists. A source-level Cosign predicate/subject check passed synthetic tests but has not been deployed or exercised against a real signed attestation. **Pilot: 18 planned, 0 attempted, 0 valid.** See `research/datasets/trust_attribution_20261025T2104Z/`; no research estimates are calculated.
## Readiness decision — 2026-10-25

Do not start the 18-run pilot. The indexed SBOM has not passed independent signature verification; the latest event lacks application executable/hash attribution; no independently operated, signed contract observer or production oracle trust anchor is configured. Live API → Redis → causal processing and SQLite/S3 smoke evidence do not close those gates. Planned 18; attempted 0; valid 0. No detection or causal estimate is defensible. See the timestamped trust and attribution evidence directories cited in `PHANTOM_EXECUTION_LOG.md`.
