# Paper Evidence Matrix

| Claim / section | Current evidence | Status / permitted wording |
|---|---|---|
| Dedicated environment | AWS identity, tagged EC2, Terraform plan/apply record, k3s and BTF evidence | Dedicated disposable lab provisioned and deployed; see execution log and deployment verification. |
| eBPF capture | Agent Running, real Prometheus histogram count, persisted API event samples | Runtime events were captured and accepted by the API. |
| Workload identity | Harmless emailservice smoke event with resolved namespace, pod, and container | Workload-level attribution occurred for sample events; some events remained ambiguous. |
| SBOM/component attribution | Resolved event fields `purl`, `sbom_id`, and binding status are null | Not demonstrated. No component attribution or provenance claim is supported. |
| Causal-engine path | Redis group at `0-0`; publisher and consumer stream/schema mismatch | Causal engine processing of agent observations is not demonstrated. |
| Cluster identity | Agent event payload hard-codes `phantom-eks`; actual cluster is `phantom-k3s-lab` | Event cluster identity is inaccurate and must be fixed before another run.
| Contract drift | Generic violation payloads; no independent registered contract oracle | Contract-drift labels are unknown; no contract detection claim is supported. |
| Prometheus | Four real targets UP; SBOM scrape target removed after verified 404 | Core exporter and cAdvisor scraping works. SBOM service has no scrape endpoint. |
| Event lag | Live smoke p95 query based on BPF monotonic timestamp and agent callback monotonic timestamp | Smoke-only kernel-to-callback estimate; do not conflate with API ingestion, detection, or end-to-end latency. |
| Resource overhead | Live cAdvisor CPU/RSS smoke queries | Point-in-time smoke measurements only; no attack-vs-baseline overhead result. |
| Pilot detection performance | 18 planned, 0 attempted | No precision, recall, F1, FPR, MTTD, or confidence interval. |
| Causal effect | No valid intervention dataset and no demonstrated graph/diagnostics | No causal estimate. |
| Extended profile | Not run | Not justified before pipeline/oracle blockers are resolved. |
| Related work | NTIA official SBOM report, Kubernetes NetworkPolicy docs, Linux kernel BPF docs | Background only; not an exhaustive literature review and no novelty claim. |

All runtime evidence is separate from historical raw datasets. Smoke artifacts are at `research/datasets/smoke_batch/20261025T150659Z/`.

## Source-level follow-up (2026-10-25)

| Claim area | New evidence | Supported conclusion |
|---|---|---|
| Redis publisher/consumer | Fake-Redis tests: valid schema event processed and acknowledged; malformed schema remains pending (2 tests) | Contract shape and local adapter flow pass; live Redis/DB pipeline is not established. |
| Workload digest | Two tests for immutable `image_id` digest extraction; agent now declines to forward fabricated/unknown workload identity | Helper behavior is unit-tested; actual Kubernetes attribution is not verified. |
| SBOM component mapping | Existing standalone mapper/domain suite: 121 passing tests | Resolver behavior is tested in isolation; runtime ingestion mapping is not connected. |
| Experimental validity | Evaluation suite: 222 passing tests | Runner/config and metric accounting tests pass; no new experiment was executed. |
| Deployment / pilot | No plan/apply or live run; AWS read-only queries show no PHANTOM lab resources | No current deployment, detection metrics, or causal finding. |

Latest focused local suite count: **476 passed, 0 failed** across core, evaluation, SBOM resolver, causal-engine, gateway, and agent tests. Synthetic event-to-BDG and binding payload tests are implementation evidence only. The SBOM resolver is not connected to persisted ingestion; the independent contract oracle and durable sink evidence are not present. No empirical claim is supported by these tests.


## Current live evidence update — 2026-10-25 19:56 UTC

This section supersedes earlier deployment-status rows where they said no lab existed; it adds only checks verified in the current running lab.

| Claim area | New evidence | Supported conclusion |
|---|---|---|
| Exact evaluation image | Pod imageID `sha256:149440…`; containerd links it to `linux/amd64` manifest `sha256:ec4370…`; Syft 1.55.0 scanned that immutable manifest. | Image identity and SBOM generation input are tied by containerd metadata. |
| SBOM file evidence | CycloneDX 1.7 artifact SHA `sha256:c5b3…`; 22,823 components including 22,268 file entries; running `/usr/local/bin/python3.11` hash matched file entry `46d05c…`. | A live image file matches a file inventory record. The interpreter has no package PURL/occurrence; this does not establish application-package attribution. |
| SBOM indexing and binding | Live `phantom_sbom.sboms` row count 0; runtime event shows `binding_status=unbound`, SBOM ID/PURL null, executable hash null. Service S3 storage configuration does not match the existing role's allowed prefix. | Component-level SBOM binding remains unsupported. SBOM was stored as an evidence artifact, not indexed. |
| Redis/causal processing | API/outbox and canonical Redis records match event IDs; group `entries-read=22`, pending 0, lag 0; live counter reported 28 cumulative successes. | The smoke event path is operational. Counts are cumulative smoke telemetry, not experiment results or per-event causal attribution claims. |
| Sink integrity and recovery | Receipt `0956698a-668c-55e8-9033-e61de20f677c` retrieved after pod restart; actual S3 backup restored 2 receipts with matching canonical hashes. | Same-node restart persistence and one manual off-node restore are demonstrated. Automated backup scheduling is not. |
| Independent ground truth | Trust ConfigMap has `keys:[]`; scenario observer source has no live collector; receipt remains outcome unknown. | No authenticated independent contract ground truth is available. |
| Network boundary | Evaluation policy is applied; cross-namespace Redis TCP probe returned `connect_ex=111`; node allows 80/443 egress through NAT; public egress was not directly probed. | That tested cross-namespace attempt was denied. Do not claim an external egress test or full public boundary validation. |
| Pilot | 18 planned, 0 attempted; no attack/control scenarios were run. | No detection-performance, latency, resource-overhead, or causal-effect metric is supported. |

Raw artifact bundle with checksums: `research/datasets/live_attribution_20261025T194226Z/`.

## Live finalization evidence — 2026-10-25 20:12 UTC

| Claim | Fresh evidence | Supported conclusion |
|---|---|---|
| Runtime to API/Redis | Exact event/outbox identifiers and published Redis ID `1792958994132-0`; consumer group advanced through it, pending 0. | Harmless smoke event traversed capture, API persistence, outbox, Redis, and was acknowledged by group progress. No run/scenario IDs. |
| SBOM availability | Exact-image SBOM artifact present in S3; `phantom_sbom.sboms` count 0; live binding endpoint says unbound. | Artifact generation/retention is supported, service indexing and component mapping are not. |
| Executable attribution | Current event is `runc:[1:CHILD]`, `executable_hash=null`, despite workload image digest populated. | No event-level executable-to-component attribution; do not map host runtime hash to container package. |
| Independent ground truth | `phantom-eval/phantom-oracle-trust` has empty key/revocation data; no live direct assertion collector. | No authentic independent contract label; event is smoke only. |
| Receipt integrity and recovery | Current sink verification returned integrity valid; prior actual S3 restore matched 2 receipts. | Receipt integrity and manual restore are demonstrated; authenticity/independence and automated backup are not. |
| Pilot metrics | 18 planned, 0 attempted, 0 valid. | No precision, recall, F1, false-positive rate, latency, overhead, or causal effect is supported. |

Raw data and hashes: `research/datasets/live_finalization_20261025T200807Z/`.


## Live SBOM ingestion evidence — 2026-10-25

| Claim area | New live evidence | Supported conclusion |
|---|---|---|
| SBOM ingestion | Exact existing S3 object/version checked by real service; HTTP 201; DB 1 row/22,823 components; retrieval digest matches | Artifact is indexed for exact image identity, but signature status remains `pending`. |
| Safe failure and retry | Wrong content hash returns 503 with unchanged DB count; identical retry returns same SBOM ID | Invalid artifact is not indexed and identical retry is idempotent. |
| Runtime binding | Real API returns `insufficient_evidence`, null SBOM/PURL/confidence for hashless `runc` event against pending SBOM | No executable-to-component attribution is supported. |
| Observer/trust | Live trust ConfigMap reports no trusted keys; independent observer not connected | Ground-truth authenticity and independence are not verified. |
| Pilot metrics | 18 planned, 0 attempted, 0 valid | No detection, latency, overhead, or causal metric is estimable. |

Raw SSM responses and source/image build hashes are retained in `research/datasets/sbom_ingestion_20261025T202953Z/`.

### 2026-10-25 21:04 UTC follow-up

| Claim | Evidence | Supported conclusion |
| --- | --- | --- |
| Application request | Direct internal HTTP 200 and recommendationservice access log in `research/datasets/trust_attribution_20261025T2104Z/` | The application handled a harmless request; this does not establish eBPF process attribution. |
| Runtime identity | Same batch's agent logs show `identity_insufficient` and no sampled attributable `dispatcher.success` entry | Executable hash and application-component binding remain unverified. |
| SBOM signature trust | Existing DB status `pending`; S3 source-prefix listing has no attestation there; local strict-binding verifier tests 4/4 pass; deployed container has no Cosign binary | No trusted live SBOM attestation has been demonstrated. Source-only test results cannot promote the deployed SBOM to verified. |
| Independent oracle | Deployed trust ConfigMap has zero public keys; no live harness assertion | No independent signed contract label or valid pilot denominator. |
## Evidence boundary — 2026-10-25 continuation

| Claim | Current evidence | Status |
| --- | --- | --- |
| Exact-image SBOM is indexed | Live GET: ID `f6ffce2a-50c1-4284-91f4-5d515e43da9e`, 22,823 components, digest `sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb` | Supported, signature pending |
| SBOM attestation is independently trusted | Live verification request HTTP 503 because signer identity and issuer are unconfigured; no matching lab-image attestation found | Unsupported |
| Runtime event reaches causal consumer | Harmless event `f344d15a-5260-478c-9025-022ebe955f56`, Redis ID `1792964344284-0`, group pending 0/lag 0 | Supported for transport only |
| Application executable maps to SBOM component | Event `runc:[2:INIT]`, executable path unknown, hash null, binding missing | Unsupported |
| Independent contract ground truth | Oracle trust ConfigMap has zero keys; no live independent assertion collector | Unsupported |
| Pilot accuracy, latency, overhead, causal effect | 0/18 runs attempted | Unavailable |

Source artifacts: `research/datasets/attribution_probe_20261025T2132Z/` and `research/datasets/trust_integration_20261025T2150Z/`.
