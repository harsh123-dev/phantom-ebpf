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
