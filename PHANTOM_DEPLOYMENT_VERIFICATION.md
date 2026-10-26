# PHANTOM Deployment Verification

**Execution date:** 2026-10-25 UTC  
**Overall status:** Deployment and basic telemetry smoke passed; experiment-readiness gate **FAILED** because causal stream delivery and SBOM/contract attribution were not verified.

## Environment and cloud lab

| Check | Status | Actual evidence |
|---|---|---|
| Controller isolation | PASS | Controller is the existing SQL Server host; no k3s installed there. |
| AWS identity | PASS | Account `253490771520`, IAM user `harsh2`, region `ap-south-1`. Sanitized identity output is in `research/datasets/smoke_batch/20261025T150659Z/aws-identity.json`. |
| Dedicated EC2 | PASS | `i-003c65aeee29735f0`, `m7i.xlarge`, Ubuntu 22.04.5, AZ `ap-south-1c`, private IP `172.31.109.121`, public IP `13.203.64.74`; PHANTOM project tags. EC2 system and instance checks both `ok`; SSM `Online`. |
| Network ingress | PASS | Dedicated SG `sg-0c4ba611357357e03` has no ingress rules; SSM is the management path. |
| Storage | PASS | Encrypted 80 GB gp3 volume `vol-036bac9c0dc4f31bf`. |
| Kernel / BTF | PASS | Linux `6.8.0-1066-aws`, amd64, `/sys/kernel/btf/vmlinux` present. |
| Cluster | PASS | k3s `v1.36.5+k3s1`, one node Ready; cluster API reached through the SSM tunnel and explicit `phantom-lab` context. |
| Terraform | PASS | The reviewed plan had five creates, zero changes, zero destroys. Applied only the dedicated `infra/terraform/environments/k3s-lab/` stack. |

## Deployment and monitoring

| Component / check | Status | Evidence |
|---|---|---|
| PostgreSQL, Redis | PASS | Pods Ready. |
| API gateway | PASS | Pod Ready; `/healthz` and `/metrics` returned HTTP 200. |
| Causal engine | PASS | Pod Ready; health endpoint responds; exporter bound on 9090. |
| SBOM service | PASS | Pod Ready. It does not expose Prometheus metrics at the configured service path; the 404 scrape target was removed. |
| eBPF agent | PASS | DaemonSet Ready after correcting a kernel BTF `kernel_cap_t` CO-RE mismatch. Agent metrics endpoint on 9101 is scraped. |
| Evaluation targets / sink | PASS | Recommendation, email, cart workloads and sink Pods Ready; all are ClusterIP services. |
| Prometheus | PASS | Active targets `cadvisor`, `phantom-api-gateway`, `phantom-causal-engine`, and `phantom-ebpf-agent` all reported `up`. Actual target data: `research/datasets/smoke_batch/20261025T150659Z/prometheus-targets.json`. |
| Harmless workload activity | PASS | In-cluster emailservice GET returned 200. A target-process event was attributed to the emailservice Pod. Exact receipt: `resolved-workload-event.json`. |
| Event ingestion | PASS | Agent dispatcher logs contain successful HTTP event ingestion; API GET returned persisted events with `ingestion_status=accepted`. Logs and response samples are saved in the smoke evidence directory. |
| Kernel-to-callback lag | PASS, smoke only | Prometheus histogram had live observations. A runner query at 15:08:26 UTC returned p95 `32.96 ms`; this is kernel timestamp to ring-buffer callback, not ingestion, detection, or end-to-end latency. |
| Agent CPU / RSS | PASS, smoke only | Same preflight snapshot: CPU rate `0.00942` cores and RSS `69.73 MiB`. These are point-in-time smoke values, not experimental overhead estimates. |
| Internal sink | PASS | Evaluation Pod connected to the allowlisted sink at port 4445. |
| Egress restriction | PARTIAL PASS | Active namespace egress policy allows DNS, listed workload peers, mirror, and sink only. A connection from evaluation workload to Prometheus in another namespace was refused (`connect_ex=111`); a reserved TEST-NET probe was also refused. The TEST-NET response alone is not treated as proof. Raw outputs and policy are saved. |

## Experiment-readiness blockers

1. **No causal-engine observations:** API gateway publishes to Redis stream `phantom:bdg:mutations`; the causal consumer is configured for `phantom:drift-events` and expects a different message schema. `XINFO GROUPS phantom:drift-events` showed the group at `last-delivered-id=0-0`, `pending=0`, `lag=0`. Thus event persistence does not prove the causal engine received events.
2. **No SBOM/component binding:** A resolved emailservice runtime event has `purl=null`, `sbom_id=null`, `binding_status=null`, and no binding provenance. Image digest is a zero placeholder in the event record.
3. **No independent contract oracle:** Agent payload currently attaches a generic `unexpected_process_relation` violation to every event. There is no verified registered contract comparison to establish contract drift.
4. **Incorrect cluster identity:** Agent event payloads hard-code `cluster_name=phantom-eks`; the deployed cluster is k3s `phantom-k3s-lab`. This weakens traceability and must be corrected before a campaign.
5. **No independent sink receipt:** The sink only accepts and closes sockets; it does not persist request receipts. Scenario verifiers can establish some local intervention state, but there is not yet a durable sink oracle.

No attacks or pilot controls were executed. These failures prevent a defensible PHANTOM contract-drift evaluation even though the cluster and telemetry smoke path are alive.

## Evidence directory

`research/datasets/smoke_batch/20261025T150659Z/` contains current cluster state, Prometheus targets and samples, event records, logs, network-policy check, AWS identity, and a README describing limitations. Smoke evidence is separate from pilot records. No historical `raw/` or `raw3/` dataset was modified.

## Cost and resources

The dedicated lab was stopped and then destroyed after all local reports and smoke artifacts passed SHA-256 verification. An inspected destroy plan contained five project-resource deletes, zero adds/changes; applying it destroyed the EC2, encrypted gp3 root volume, project security group, IAM role, and profile. Read-only verification found zero PHANTOM-tagged volumes/security groups and no lab role; the instance appears only as a terminated historical record. No PHANTOM-created cloud resources remain. Accrued charges may still post; no ongoing project-resource charges remain. Lifecycle evidence: `research/datasets/smoke_batch/20261025T150659Z/resource-lifecycle.json`.

## Current checkout verification (2026-10-25 15:33 UTC)

The preceding deployment is historical. The latest read-only AWS checks authenticated account `253490771520` in `ap-south-1`; tagged PHANTOM lab instance/security-group queries and the lab-role query returned no rows. Terraform state is empty. No new Terraform plan or apply was run. The current controller is `ip-172-31-67-19` (Ubuntu 22.04.5, kernel `6.8.0-1066-aws`) with active SQL Server; it has no Docker/Podman, kubectl, or k3s executable and was not modified for cluster installation.

Latest source tests establish the fake-Redis contract path only. **Current deployment status: NOT DEPLOYED.** Component-level SBOM mapping is not connected to ingestion, and independent contract verification plus durable run-correlated sink receipts remain absent. These are explicit no-go conditions for any new deployment smoke or live pilot. Details and exact test results are in `PHANTOM_EXECUTION_LOG.md`.

The latest local suites total **476 passed, 0 failed** across core, evaluation, SBOM mapping, causal integration fixtures, API, and agent tests. The causal test now exercises the real BDG update use case and a provenance-backed PURL graph node using synthetic events. These tests do not establish live event transport, runtime SBOM resolution, or independent contract evidence.

## Latest live deployment update — 2026-10-25

This section supersedes the earlier “NOT DEPLOYED” status above; those statements describe the prior checkout/time and remain historical.

### Current lab

- **AWS:** account `253490771520`, region `ap-south-1`. EC2 `i-06bb29d253668fa5f` (`t3.xlarge`) is running in private VPC `vpc-08127443fa071e39a`, private IP `10.89.2.125`, no public IP. SG `sg-0dd69eccac1594f6f` has zero ingress rules. Root volume `vol-059e997e6d7909b5f` is encrypted gp3, 50 GB, delete-on-termination. SSM access is Online.
- **Network:** private lab subnet routes outbound via NAT gateway `nat-001088ed60b94cb8a` / EIP `13.206.14.201`. Three SSM interface endpoints and an S3 gateway endpoint are present. Host egress allows TCP 80/443 to `0.0.0.0/0` through NAT. Evaluation NetworkPolicy was exercised with a denied cross-namespace TCP attempt to Redis while an API-gateway control connection reached Redis; no public egress probe was made. Thus this is private ingress with controlled-port NAT egress, not a claim that all public egress is blocked.
- **Kubernetes:** k3s `v1.36.5+k3s1`, Ubuntu 22.04.5, kernel `6.8.0-1066-aws`, BTF present, one Ready node. All app, eBPF, Redis, PostgreSQL, SBOM, sink, evaluation, and Prometheus pods were Ready at the final inventory. All application services are ClusterIP.

### Live harmless smoke path

A harmless shell process launched by `kubectl exec` in `recommendationservice` produced real eBPF kernel events. Six sampled events with actual event IDs, times, workload/image identity, and outbox IDs are in [runtime_smoke_events.csv](research/datasets/live_smoke_20261025T193500Z/runtime_smoke_events.csv). The gateway persisted the events; API outbox entries were published to `phantom:drift-events`; the causal worker consumed them and called the BDG update use case. At the final query: 12 outbox rows were published, Prometheus consumer success count was 12, Redis `entries-read=12`, pending 0, lag 0.

The SBOM service initially returned 500 because its tables had not been migrated. It now runs migrations in a dedicated `phantom_sbom` schema and answers mapping requests with HTTP 200. The live database has no SBOM documents for the evaluation image. The resolver returned `unbound` with an explicit reason; no SBOM ID or PURL is asserted.

Prometheus currently scrapes cAdvisor, API gateway, causal engine (9090), and agent (9101); all were up. Agent kernel-to-ring-callback lag histogram count reached 5,348. A 5-minute histogram p95 sample was 40.05 ms. This is not ingestion, detection, or end-to-end latency. One-minute CPU samples are in [metrics_observed.csv](research/datasets/live_smoke_20261025T193500Z/metrics_observed.csv); these are point-in-time resource usage, not overhead deltas.

The sink accepted an explicitly unknown smoke receipt, and it remained retrievable and hash-valid after a sink pod restart. Receipt ID: `5ce90608-0117-5836-95dc-01f37543ab38`. Authenticity and independence are unverified. SQLite is on a single-node 2 GiB local-path RWO PVC; this does not prove node-loss durability.

### Remaining readiness blockers

- The oracle trust ConfigMap has no public keys. There is no separately operated independent live contract observer; no confirmed contract ground truth exists.
- Runtime executable hash is unavailable. No live executable-to-component binding exists; the actual workload image has no SBOM indexed, so the resolver abstained.
- Sink persistence after pod restart is verified, but no S3 receipt backup or restore from node loss has been performed.
- Cross-namespace connectivity was checked; public egress was not directly probed. Host TCP 80/443 egress via NAT remains configured.
- No attack/control scenarios were run. The 18-run pilot remains **18 planned / 0 attempted**. Research gate remains **CLOSED**.

Raw SSM, AWS, Redis, database, metrics, and image evidence with checksums: [live smoke evidence directory](research/datasets/live_smoke_20261025T193500Z/).


## Live attribution and recovery follow-up — 2026-10-25 19:56 UTC

The existing lab remained healthy. EC2 `i-06bb29d253668fa5f` was running, the k3s node was Ready, and the listed services were Ready. The sink was restarted; the smoke receipt remained retrievable and passed HTTP integrity verification. Fresh command output is in `research/datasets/live_attribution_20261025T194226Z/`.

A Syft 1.55.0 CycloneDX SBOM was generated from the exact `linux/amd64` manifest `sha256:ec4370b0af44b4ba2ffe0247f1b1339c4f4debdba319d025d5753140ccec4184`, which containerd maps to the evaluation pod imageID/config digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`. Artifact SHA-256 is `sha256:c5b3a412b3534cfb0647b639cbc3e2993bbd2b09797aff9b34ce5a3904e04c80`; the running target file `/usr/local/bin/python3.11` hashes to `46d05ca7094b029959f0218e990a7f2737dbc87d5b2e783ecfc44e978937922a`, matching the SBOM file entry. The live agent still emits no executable hash. Since this is an interpreter file with no package PURL/provenance, package attribution remains unsupported.

**SBOM indexing: BLOCKED.** The SBOM database is empty. The deployed service lacks configured artifact bucket/region and credentials; its default bucket is `phantom-sbom-artifacts`, and its key path is outside the lab role's scoped evidence prefix. The SBOM was preserved in the existing encrypted/versioned evidence bucket, but not indexed. We avoided a POST that would persist rows before the failing artifact upload.

**Sink off-node recovery: MANUAL TEST PASS.** A live SQLite snapshot was uploaded with the project S3 backup client to the existing versioned AES256 bucket, restored to a new database, and integrity-checked. Both receipt IDs and canonical hashes matched. This does not provide automatic backup scheduling; local-path volume durability remains node-bound.

**Live event path: SMOKE PASS WITH UNBOUND SBOM.** API and outbox records appeared in Redis with matching event IDs. The consumer group had `entries-read=22`, `pending=0`, `lag=0`; a metrics scrape returned 28 cumulative success counter samples for the configured stream. Events lacked run/scenario IDs and executable hashes; binding remained `unbound`. A cross-namespace eval-to-Redis TCP attempt returned `connect_ex=111`, consistent with the applied NetworkPolicy. Host egress via NAT remains allowed on TCP 80/443; no public destination was contacted, so no direct public-egress test is claimed.

### Readiness gate

**CLOSED.** No production oracle public keys are configured, no live independent contract observer emitted a signed observation, the SBOM is not indexed and component attribution is still unbound, and public egress was not directly probed. The manual sink S3 restore passed, but an automated schedule and deployment-role recovery operation are not configured. No pilot scenario was run.

S3 provenance clarification (2026-10-25): the manual restore used the existing `S3EvidenceBackupClient` with the controller's configured AWS identity; it was an actual versioned, encrypted S3 bucket operation, not an in-memory double. The source snapshot came from the live sink after restart. The upload/restore process is not yet wired to an automated pod or scheduled backup identity.

Receipt timestamp clarification (2026-10-25): receipt `0956698a-668c-55e8-9033-e61de20f677c` was created at `2026-10-25T19:46:14.185107+00:00`. Its run ID's embedded `194800Z` is only an operator smoke label, not an observation timestamp. The manual project backup client used the controller AWS identity `arn:aws:iam::253490771520:user/harsh2`; the SBOM artifact upload used the lab instance role.

## Live finalization status — 2026-10-25 20:12 UTC

| Gate | Latest verified status | Evidence |
|---|---|---|
| EC2/k3s/apps | PASS: existing instance running, SSM Online; node and application/evaluation pods Ready | `research/datasets/live_finalization_20261025T200807Z/ssm/live_cluster_inventory.json`, `ec2_status.json` |
| Runtime event persistence and Redis publication | PASS for harmless smoke: event `7893c151-30ff-4c78-b1d2-38c695c658ec` persisted in Postgres/outbox as `published`; stream ID `1792958994132-0` | `ssm/api_database_outbox_confirmation.json`, `ssm/harmless_event_trace.json` |
| Causal consumer progress | PASS for stream progress: group advanced through the smoke message, pending 0, lag 0. Counter 35 is cumulative; no event-specific causal effect established. | `ssm/live_cluster_inventory.json`, see README in evidence directory |
| Exact-image SBOM indexed | FAIL: DB row count 0; live binding endpoint returned `unbound` for the exact image digest | `ssm/sbom_sink_trust_verification.json`, `runtime_binding_result.json` |
| SBOM artifact store access | BLOCKED: bucket/region unset in pod; host role cannot be reached from pod; key prefix and IAM grant do not match; NetworkPolicy has no S3 egress. No unsafe credential exposure or ingestion attempted. | `sbom_s3_head.json`; previous IAM evidence at `research/datasets/live_attribution_20261025T194226Z/lab_backup_role_policy.json` |
| Executable-to-component attribution | FAIL: event has no executable hash and process is `runc:[1:CHILD]`; matching interpreter file record has no supported package PURL. | `ssm/harmless_event_trace.json`, `evaluation-image.cdx.json` |
| Independent oracle | FAIL: trust ConfigMap key lists empty; no live independent collector or signed observation. | `ssm/sbom_sink_trust_verification.json`; source `research/evaluation/scenario_observer.py` |
| Sink current retrieval/integrity | PASS for prior unknown smoke receipt after restart: integrity valid; authenticity/independence unverified. | `sink_current_verification.json` |
| Off-node recovery | PASS as prior manual actual S3 restore only; no automated schedule or new recovery test this turn. | `prior_verified_s3_restore.json`, `prior_receipt_compare.json` |
| Network isolation | PARTIAL: prior cross-namespace Redis denial; public egress not tested. | Earlier `live_attribution_20261025T194226Z` evidence |
| Research pilot | CLOSED: 18 planned, 0 attempted, 0 valid | `README.md` in latest evidence directory |


## SBOM ingestion follow-up — 2026-10-25 20:32–20:47 UTC

| Check | Result | Evidence |
|---|---|---|
| SBOM service configuration | PASS: bucket, region, write prefix, and allowed artifact prefix configured in its Deployment/ConfigMap | `research/datasets/sbom_ingestion_20261025T202953Z/sbom_service_rollout_ssm.json` |
| Restricted S3 egress | PASS for tested policy: DNS/Postgres/S3 CIDRs only; SBOM pod fetched the versioned artifact; IMDS and reserved TEST-NET probes blocked | `sbom_restricted_egress_live_apply.json`, `sbom_live_final_cluster_state.json` |
| Exact-image SBOM indexed | PASS: HTTP 201; exact config digest; 22,823 components; DB row count 1 | `sbom_ingest_first_live_response.json`, `sbom_live_final_cluster_state.json` |
| Retrieval and content integrity | PASS: GET returned HTTP 200 and canonical digest `sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb`, matching source document | `sbom_duplicate_and_bad_digest_checks.json` |
| Invalid artifact checksum | PASS fail-closed: HTTP 503; DB remained 1 SBOM / 22,823 components | `sbom_duplicate_and_bad_digest_checks.json` |
| Identical retry | PASS after service update: HTTP 201 returned the same SBOM ID; DB remained 1 / 22,823 | `sbom_idempotent_retry_live_response.json` |
| Runtime attribution | UNKNOWN/ABSTAIN: event was `runc:[2:INIT]`, hash null, SBOM status pending; response `insufficient_evidence` with no component | `sbom_live_runtime_binding_result.json` |
| Independent oracle/trust | BLOCKED: 0 trusted and 0 revoked keys; no independent live observer | `sbom_live_final_cluster_state.json` |
| Pilot | NOT RUN: 18 planned / 0 attempted / 0 valid | Execution log and experiment report |

The SBOM endpoint was tested against real Kubernetes, Postgres, and S3 (the existing short-lived presigned URL was generated using the EC2 role outside the pod). The pod itself did not receive node-role credentials. Ordinary SDK-based S3 uploads from inside the SBOM pod and a production signing trust anchor remain unverified. The restricted policy probes establish tested denials only; they are not a comprehensive public-egress audit.

### EXEC collection follow-up

Added event-stage counters and deployed `phantom/ebpf-agent:schedexec-20261025T2215Z` (1/1 Ready), with the executable-change hook attached at `sched_process_exec`. A harmless `kubectl exec ... /bin/echo PHANTOM_EXEC_PROBE_2215` succeeded. Before and after metrics showed namespace and privilege records but no `exec` event series. This build change therefore did **not** verify executable event delivery; its reason remains unresolved. See `research/datasets/exec_telemetry_20261025T2209Z/`. No executable hash or SBOM component attribution is supported.
## 2026-10-25 continuation: current live status

EC2 `i-06bb29d253668fa5f` is `running` in `ap-south-1` (`10.89.2.125`, `t3.xlarge`). The rebuilt SBOM deployment `phantom/sbom-service:trustfix-20261025T2150Z` rolled out successfully and has Cosign v3.1.4. Its live indexed SBOM remains `pending`; a verification request without server-configured signer identity/issuer returned HTTP 503. The corrected eBPF agent DaemonSet rolled out Ready 1/1. A harmless event reached API persistence, Redis, and the causal consumer, but its process was `runc:[2:INIT]`, with unknown event-time executable path/hash and no component binding. The oracle trust ConfigMap has zero keys. Therefore deployment is suitable for engineering smoke checks but **not** the 18-run research pilot. Evidence: `research/datasets/attribution_probe_20261025T2132Z/` and `research/datasets/trust_integration_20261025T2150Z/`.


### Live EXEC recheck (2026-10-25)

The current DaemonSet is `phantom/ebpf-agent:cgroupattr-20261025T2306Z`, 1/1 ready. A harmless `/bin/sleep 5` in the evaluation pod generated the persisted EXEC event recorded in `research/datasets/live_exec_attribution_20261025T230924Z/persisted_api_events.json`; it retained the target pod, container ID, and image digest. The event path was unknown and SBOM binding remained missing. This verifies event delivery and workload/image identity through the API only. It does not verify executable hashing, SBOM component binding, independent oracle output, Redis/causal processing for this exact smoke event, or research-pilot readiness.
