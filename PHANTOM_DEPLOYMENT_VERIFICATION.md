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
