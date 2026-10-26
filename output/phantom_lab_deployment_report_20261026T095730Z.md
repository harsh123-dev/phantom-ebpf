# PHANTOM lab deployment and verification report

**Verified:** 2026-10-26 UTC  
**Repository:** `/root/phantom-ebpf`, branch `main`, commit `664441fb93b08fbad33fcce9bf1b6d92d02d6a71`  
**Working tree:** pre-existing dirty changes and untracked evidence preserved; no source files were changed in this deployment/finalization pass. No commit or push was made.

## Status

A dedicated single-node k3s lab is provisioned and left running. The PHANTOM services, Prometheus, evaluation workloads, and internal sink are currently Ready. The lab is available for further **non-attack integration work** and later operator access. This is not a research-pilot readiness declaration: the exact evaluation image has no indexed SBOM in the live SBOM service, the production oracle trust store is empty, independent contract ground truth is unavailable, and off-node receipt recovery has not been verified in this deployed environment. No attack scenarios were executed.

## Terraform and AWS

AWS identity check succeeded for account `253490771520`, region `ap-south-1`. Current Terraform state identifies the dedicated PHANTOM resources and the running instance; it does not include the shared SQL Server administration host.

The previously reviewed no-NAT plan was applied successfully: **17 added, 0 changed, 0 destroyed**. Current read-only AWS inventory confirms the dedicated PHANTOM instance, encrypted volume, VPC, SSM endpoints, and associated lab resources.

A fresh plan with Terraform's **default** `enable_nat_gateway=true` was not applied. It proposed **3 creates, 3 in-place changes, and 1 destroy/replacement**: including a NAT Gateway, EIP, moving the EC2 node to the private subnet, changing the private default route, and replacing the running instance. This is inconsistent with the requested no-NAT design and would replace the lab. It was rejected.

The fresh plan with `-var='enable_nat_gateway=false'`, matching the live no-NAT deployment, returned **No changes** (detailed plan exit code 0). The configuration currently defaults the variable to `true`, while `terraform.tfvars.example` sets it to `false`; always pass the explicit false variable or create a reviewed local tfvars file before future plans. No Terraform apply was run during this finalization pass.

Terraform checks: `terraform fmt -check -recursive` passed; `terraform init -input=false -backend=false` passed; `terraform validate` passed; corrected no-NAT plan passed with no changes. The unqualified default plan is a known hazardous drift and must not be applied.

### Live instance and resources

- EC2 `i-071309f235077647e`, `t3.xlarge`, `running`, Ubuntu 22.04.5.
- Private IP `10.89.1.98`, public IPv4 `35.154.215.122`; VPC `vpc-01df6bcd62aa7a73e`, subnet `subnet-0d8fb3679e0931ddb`.
- Encrypted root volume `vol-00b487033c973d1d8`, 50 GB gp3.
- SSM instance profile `phantom-k3s-lab-instance-profile`; SSM reports Online.
- No NAT Gateway, allocated EIP, evidence-backup S3 bucket, or public application load balancer was created.
- Security group `sg-0717df3a8b373f320` has **no ingress rules**. Egress is limited to TCP 80/443 to `0.0.0.0/0`, VPC DNS on UDP/TCP 53, and Amazon Time Sync UDP 123. The node therefore has controlled-port public outbound connectivity; this is not a host-level public-egress deny.

### Estimated recurring cost

Using the regional Price List API rates and assumptions documented in [`phantom_lab_cost_options.md`](phantom_lab_cost_options.md), the current no-NAT fixed-cost estimate is approximately **$1.8363 for 8 hours**, **$5.5088 for 24 hours**, or **$165.264 for 30 days**. This includes the running `t3.xlarge`, 50 GB gp3, one public IPv4 while running, and three SSM interface endpoints. It excludes variable data transfer/endpoint processing, T3 surplus CPU credits, taxes, and price changes; it is not a cap or guaranteed total. No NAT or backup-bucket charges apply because those resources were not created. Charges continue while the lab remains provisioned; stopping the instance does not stop EBS or SSM endpoint charges. The linked cost-options file was prepared before provisioning; any statement there that resources had not yet been created describes that earlier planning point. This deployment report records the later applied state.

## Source snapshot and image build

The deployment used the explicit working-tree snapshot, including intended uncommitted application changes, rather than relying on GitHub `main` or user-data to copy source. Snapshot archive: `output/phantom_lab_deployment_evidence_20261026T092647Z/phantom-source-snapshot.tar.gz`; SHA-256 `18f0ac9b88534e2879409037d8cabf0028fa63384c183f58b1f5a7800a44e70d`; 721,943 bytes / 366 listed files. The destination-side checksum matched before extraction. The snapshot excluded `.git`, virtual environments, credentials, caches, historical datasets, and prior `output/` reports.

Five service images were built from that snapshot and imported into k3s containerd. Image IDs:

- API gateway: `sha256:f65e55be900e516ba241daf5f438b352d83f1c181d12b4489ef11ba46a8c037b`
- Causal engine: `sha256:63ef7316b9129c991f4df86871a7e8a638cd61e11727c0ac9f9a0e157847b5fc`
- SBOM service: `sha256:64c943c62f49e36c7fc04cf407a32a07b3d6e4bd4dadb6860b4dec358cabc47c`
- eBPF agent: `sha256:5f4bdbe0e3464d535d8db7fb01d596b3a6c292833cb8f9c172729407bc131cdf`
- Evidence sink: `sha256:923d49fec37246b061f912dda7d8d266834183a6ba05fd554cf9b4ae9fa402c7`

The first image-build invocation as the unprivileged `ubuntu` account could not access the k3s containerd socket. Re-running the repository build/import script with the required root access succeeded. This was an invocation permission issue, not an image build failure.

## Kubernetes, services, and telemetry

A read-only final SSM check at 2026-10-26 09:57 UTC confirmed k3s active and node `ip-10-89-1-98` Ready on Kubernetes `v1.36.5+k3s1`, kernel `6.8.0-1066-aws`, containerd `2.3.4-k3s1.36`. BTF is present. `bpftool` reports ring-buffer map support and an attached `sched_process_exec` tracepoint program. This proves the agent program is attached; the harmless event below also confirms records were observed and delivered. It does not establish attribution for every event.

The final pod check showed all **14 displayed pods** Running and Ready, with zero restarts in the displayed list: 3 system pods (CoreDNS, local-path provisioner, metrics-server), Prometheus, 4 `phantom-eval` pods (recommendationservice, emailservice, cartservice, phantom-sink), and 6 `phantom` pods (API gateway, causal engine, eBPF agent, PostgreSQL, Redis, SBOM service). Service health checks returned API, causal, SBOM, and sink health/readiness 200; PostgreSQL accepted connections; Redis returned PONG. Prometheus targets for cAdvisor, API, causal engine, and agent were UP.

### NetworkPolicy verification

The evaluation namespace has an egress policy and the k3s NetworkPolicy controller is active. A harmless allowed eval-to-emailservice request returned HTTP 200. A control request from the PHANTOM namespace to the API returned HTTP 200. From `phantom-eval`, a request to that unauthorized API service was denied; the policy NFLOG/drop counter changed from `0 0` to `1 60`, with the policy drop recorded. A separate TCP connection attempt to the RFC 5737 documentation address `203.0.113.1:443` also failed, and the policy drop counter increased from `0 0` to `1 60` (one packet, 60 bytes). No public service or third-party host was contacted. These checks verify the tested internal allow/deny behavior and a default-denied public-destination path; the host itself retains outbound TCP 80/443 for bootstrap and image retrieval.

## Harmless live event smoke check

No attack scenario or attack-runner `--execute` command was used. One harmless `kubectl exec ... /bin/ls -ld /tmp` was used to verify real runtime event capture. The actual evaluation workload manifest digest was `sha256:50a337a6c7f43a609feaa56e826e4b5085db9f95447f3232edbe47302c7b0ad7`.

Observed event:

- Event ID `0000012e-1404-2112-0000-000000000001`, type `exec`, `comm=ls`.
- Workload `phantom-eval/recommendationservice-5dc98bbcb9-4mml4`, container `server`, container ID `containerd://8a4183c3080e4f2e5c8d57163781531e1cbbcbac99e4038b2e85975443c6306b`.
- Image digest matched the workload digest above.
- `executable_path` was unknown, executable hash unavailable, SBOM ID and PURL null, binding status `missing` in the API record.
- The canonical Redis stream `phantom:drift-events` contained exactly one matching event (`stream_id=1793008132290-0`, schema `1.0`) with binding status `unbound`, reason: no SBOM indexed for the image digest.
- At the check, the stream had 16 entries, consumer group `causal-engine-bdg-updater` had read all 16 with pending 0 and lag 0; Prometheus `phantom_redis_stream_messages_total{stream="phantom:drift-events",result="success"}` was 22. The exact event was observed in Redis and the consumer was caught up, but no event-specific causal mutation/result was returned in the correlation output; this is not claimed as proof of a causal effect.
- Agent exec counters changed across the harmless check: received/queued 552→568, identity_missing 467→481, namespace_filtered 82→83, dispatched 3→4. The delivery-lag histogram count changed 2515→2572; it reflects kernel-event-to-agent-callback lag and background activity, not end-to-end latency or research performance.

The live SBOM database contained **0 records** for this exact image digest. The observed event cannot support component-level attribution. The production oracle trust ConfigMap is empty; no independent contract observer, verified ground truth, or verified live receipt/backup-recovery path was exercised. These gates remain closed. No SBOM, trust key, ground-truth label, receipt, or attack result was fabricated.

## Automated test and validation results

Tests ran in the project's isolated Python 3.11 virtual environments with `PYTHONHOME=/root/.local/share/uv/python/cpython-3.11.13-linux-x86_64-gnu` set for the relocated venvs. Each suite was launched as a separate process with the commands below; detailed output and exit codes are in `output/phantom_lab_deployment_evidence_20261026T092647Z/tests/attempt2/results.tsv` and its per-suite logs.

```bash
export PYTHONHOME=/root/.local/share/uv/python/cpython-3.11.13-linux-x86_64-gnu
.venv-causal/bin/python -m pytest libs/phantom-core/tests -q -rs
.venv-causal/bin/python -m pytest services/causal-engine/tests -q -rs
.venv-services/bin/python -m pytest services/api-gateway/tests -q -rs
.venv-services/bin/python -m pytest services/sbom-service/tests -q -rs
.venv-services/bin/python -m pytest services/report-generator/tests -q -rs
.venv-agent/bin/python -m pytest services/ebpf-agent/tests -q -rs
.venv-evaluation/bin/python -m pytest research/evaluation/tests -q -rs
.venv-causal/bin/python -m pytest tests/e2e -q -rs
.venv-causal/bin/python -m pytest tests/verify_m4_adversarial.py -q -rs
```

| Suite | Result |
|---|---:|
| `libs/phantom-core/tests` | 48 passed |
| `services/causal-engine/tests` | 376 passed, 1 skipped |
| `services/api-gateway/tests` | 63 passed |
| `services/sbom-service/tests` | 211 passed |
| `services/report-generator/tests` | 36 passed |
| `services/ebpf-agent/tests` | 174 passed |
| `research/evaluation/tests` | 267 passed |
| `tests/e2e` | 387 passed, 1 skipped |
| `tests/verify_m4_adversarial.py` | 27 passed, 2 skipped |
| **Total** | **1,589 passed, 4 skipped, 0 failed** |

The skips are explicit evidence-preserving skips: the causal composition test requires a local `redis-server` not installed in this controller environment (fake Redis coverage remains separate); E2E preserves a historical raw archive with 69 files rather than synthesizing the legacy minimum 108; two M4 checks leave FP/hour values unverified because exposure-duration denominators are absent. Suites target distinct directories/files; the totals above count each once.

Additional final checks: Python AST parse passed for 285 repository `.py` files; YAML parse passed for 33 `.yaml`/`.yml` files; `git diff --check` passed. Terraform formatting, initialization, validation, and corrected no-NAT no-change planning passed. Docker builds/imports passed as listed above. The safe scenario `--dry-run` printed a plan for 18 planned runs and exited 0; source inspection confirmed the dry-run branch precedes cluster I/O and output-directory creation. The requested output directory was confirmed absent afterward. **No live scenarios were executed.**

## Preserved evidence

- Snapshot and deployment evidence: [`phantom_lab_deployment_evidence_20261026T092647Z`](phantom_lab_deployment_evidence_20261026T092647Z/)
- Final AWS inventory and selected SSM outputs: [`finalization_20261026T095730Z`](phantom_lab_deployment_evidence_20261026T092647Z/finalization_20261026T095730Z/)
- Full suite logs and counts: [`tests/attempt2`](phantom_lab_deployment_evidence_20261026T092647Z/tests/attempt2/)
- Earlier infrastructure reports and historical datasets were not modified.

## Access and later cleanup

Start an SSM session (no inbound SSH/Kubernetes/API port is exposed):

```bash
aws ssm start-session --target i-071309f235077647e --region ap-south-1
# On the lab:
sudo k3s kubectl get nodes,pods -A -o wide
```

To stop the instance after preserving any desired data (EBS and the SSM endpoints continue to incur charges):

```bash
aws ec2 stop-instances --instance-ids i-071309f235077647e --region ap-south-1
```

For eventual infrastructure removal, first inspect the destroy plan from the dedicated Terraform directory with the matching no-NAT variable; do not use the default variable value:

```bash
cd infra/terraform/environments/k3s-lab
terraform plan -destroy -var='enable_nat_gateway=false' -out=/tmp/phantom-k3s-lab-destroy.tfplan
terraform show /tmp/phantom-k3s-lab-destroy.tfplan
# Only after confirming every address is exclusively PHANTOM lab state:
terraform destroy -var='enable_nat_gateway=false'
```

The lab was intentionally left running. No destroy or stop command was executed.
