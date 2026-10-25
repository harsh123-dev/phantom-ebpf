# PHANTOM Part 7B: Infrastructure Readiness and Pilot Launch Gate

**Document Version**: 1.0.0  
**Target System**: PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*)  
**Evaluation Stage**: Part 7B — Infrastructure Readiness Assessment and Pilot Launch Gate  
**Execution Gate Status**: **NO-GO (EXECUTION BLOCKED)**  

---

## 1. Executive Summary & Launch Gate Decision

This document establishes the comprehensive infrastructure readiness assessment, forensic environment audit, test-suite reconciliation, and experimental power analysis for **Part 7B** of the PHANTOM research project.

### Launch Gate Decision: NO-GO (EXECUTION BLOCKED)
In strict accordance with the Part 7 experimental protocol and safety directives (*"Do not execute attacks or create cloud resources automatically"*, *"Do not launch live experiments if any required safety or telemetry prerequisite is missing"*), live scenario execution is **STRICTLY BLOCKED**.

### Primary Blockers:
1. **Cloud EKS Infrastructure Deprovisioned**: The AWS EKS cluster (`vprofile-eks-cluster` / `phantom-dev`) in `ap-south-1` is deprovisioned. The configured Kubernetes API endpoint cannot be resolved (`no such host`).
2. **Local Workstation Prerequisites Inactive**: Both WSL2 distributions (`Ubuntu` and `docker-desktop`) are in the `Stopped` state. The Docker Desktop daemon is not running. Minikube cannot communicate with the Docker pipe engine.
3. **PHANTOM Telemetry Stack Offline**: The PHANTOM API Gateway (`http://localhost:8080`) and Prometheus monitoring exporter (`http://localhost:9090`) are unreachable (connection timed out).
4. **Baseline Detectors Absent**: Neither `falco` nor `trivy` binaries are available on the local system PATH.
5. **No Telemetry Sinks Available**: In-cluster mock sinks (`phantom-sink:8443, 4445, 4446`) cannot be reached without an active Kubernetes cluster network and CoreDNS.

**Strict Integrity Attestation**:
- Zero attacks were launched.
- Zero cloud resources were created, modified, or destroyed.
- Zero credentials, tokens, or secrets were exposed.
- Zero synthetic runs, mock alerts, or experimental measurements were fabricated.

---

## 2. Forensic Diagnostic Findings (Read-Only Audit)

A comprehensive, non-intrusive diagnostic audit was executed across the local workstation and AWS cloud infrastructure:

### 2.1 AWS Cloud Infrastructure Status (`ap-south-1`)
- **AWS Caller Identity**: Confirmed valid and responsive via AWS STS.
  - IAM User: `arn:aws:iam::596717729313:user/admin`
  - Account: `596717729313`
- **EKS Clusters**: `aws eks list-clusters --region ap-south-1` returned:
  ```json
  { "clusters": [] }
  ```
  *(Audit confirmed zero EKS clusters in `ap-south-1`, `us-east-1`, and `us-west-2`.)*
- **Root Cause of Kubeconfig Failure**: The current context in `~/.kube/config` points to `arn:aws:eks:ap-south-1:596717729313:cluster/vprofile-eks-cluster` with endpoint `7E0F663798A2EBCCF3106687373F3754.yl4.ap-south-1.eks.amazonaws.com`. Because the cluster was deprovisioned from AWS, DNS resolution fails (`dial tcp: lookup ... no such host`). This is a genuine deprovisioning state, **not** a local network, VPN, or credential error.
- **Auxiliary AWS Resources**:
  - RDS Databases: `aws rds describe-db-instances` $\to$ `[]` (zero instances).
  - ElastiCache Redis: `aws elasticache describe-cache-clusters` $\to$ `[]` (zero clusters).
  - ECR Repositories: `aws ecr describe-repositories` $\to$ `[]` (zero repositories).
  - EC2 Instances: `aws ec2 describe-instances` $\to$ `[]` (zero instances).
  - Terraform State: `infra/terraform/terraform.tfstate` contains `version: 4, resources: 0`.

### 2.2 Local Workstation Environment Status (Windows 10 / WSL2)
- **Host OS**: Microsoft Windows 10 Host (AMD64). Native kernel is not Linux and lacks eBPF BTF/CO-RE support.
- **WSL2 Subsystem**: `wsl -l -v` reports:
  - `Ubuntu`: State `Stopped` (Version 2).
  - `docker-desktop`: State `Stopped` (Version 2).
- **Container Engine**: Docker Desktop daemon is not running (`open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`).
- **Local Minikube**: `minikube.exe` v1.38.1 is installed on PATH (`C:\ProgramData\chocolatey\bin\minikube.exe`), but fails with container engine connection error because Docker Desktop is stopped.
- **Local Services**:
  - PHANTOM API Gateway (`http://localhost:8080/health`): Connection timed out (offline).
  - Prometheus (`http://localhost:9090/-/healthy`): Connection timed out (offline).
- **Baseline Binaries**: `falco --version` and `trivy --version` return command not recognized.

---

## 3. Reconciled Test Suite Accounting

### Test Count Reconciliation (Non-Double-Counted)
In the previous status update, the 12 tests from `services/causal-engine/tests/test_contract_drift_semantics.py` were inadvertently added to the 369 tests of `services/causal-engine/tests/`, producing an inflated total of 1,061.

Because `test_contract_drift_semantics.py` is located directly within `services/causal-engine/tests/`, running pytest on `services/causal-engine/tests/` executes those 12 tests as part of its 369 tests.

The reconciled, exact, non-double-counted test accounting across the codebase is:

| Test Suite / Component | Test Path | Test Count | Failures | Status |
|---|---|:---:|:---:|:---:|
| **Causal Engine Suite** *(includes 12 contract-semantics tests)* | `services/causal-engine/tests/` | **369** | 0 | **PASS** |
| — *Contract-Drift Semantics Sub-suite* | `.../test_contract_drift_semantics.py` | *(12)* | 0 | *(PASS)* |
| — *Adversarial Challenger M2 Sub-suite* | `.../test_adversarial_challenger_m2.py` | *(56)* | 0 | *(PASS)* |
| — *Functional Estimation Sub-suite* | `.../test_functional_estimation.py` | *(33)* | 0 | *(PASS)* |
| — *End-to-End Integration Sub-suite* | `.../test_end_to_end_integration.py` | *(52)* | 0 | *(PASS)* |
| — *Causal Validation Sub-suite* | `.../test_causal_validation.py` | *(44)* | 0 | *(PASS)* |
| — *SCM Constructor Sub-suite* | `.../test_scm_constructor.py` | *(22)* | 0 | *(PASS)* |
| — *PCEPS Sub-suite* | `.../test_pceps.py` | *(28)* | 0 | *(PASS)* |
| — *BDG Graph Sub-suite* | `.../test_graph.py` | *(122)* | 0 | *(PASS)* |
| **SBOM Service Mapping Suite** | `services/sbom-service/tests/` | **177** | 0 | **PASS** |
| **End-to-End Tiers Suite (Tiers 1–5)** | `tests/e2e/` | **389** | 0 | **PASS** |
| — *Tier 1: Feature Happy Paths (21 features)* | `tests/e2e/test_tier1_features.py` | *(105)* | 0 | *(PASS)* |
| — *Tier 2: Boundary & Corner Cases* | `tests/e2e/test_tier2_boundaries.py` | *(105)* | 0 | *(PASS)* |
| — *Tier 3: Cross-Feature Interactions* | `tests/e2e/test_tier3_interactions.py` | *(11)* | 0 | *(PASS)* |
| — *Tier 4: Scenario & Reproduction Runs* | `tests/e2e/test_tier4_scenarios.py` | *(21)* | 0 | *(PASS)* |
| — *Tier 5: Adversarial Causal & Metrics* | `tests/e2e/test_tier5_causal_adversarial.py` | *(96)* | 0 | *(PASS)* |
| — *Tier 5: Metrics Adversarial Checks* | `tests/e2e/test_tier5_metrics_adversarial.py` | *(51)* | 0 | *(PASS)* |
| **Research Evaluation Suite** | `research/evaluation/tests/` | **211** | 0 | **PASS** |
| — *Attack Safety & Preflight Gate Sub-suite* | `.../test_attack_safety_and_config.py` | *(97)* | 0 | *(PASS)* |
| — *Evaluator Sensitivity & Spec Sub-suite* | `.../test_evaluator.py` | *(47)* | 0 | *(PASS)* |
| — *Scenario Runner Sub-suite* | `.../test_scenario_runner.py` | *(27)* | 0 | *(PASS)* |
| — *Adversarial Challenger M3/M4 Sub-suite* | `.../test_adversarial_challenger_m*.py` | *(29)* | 0 | *(PASS)* |
| — *Adversarial M3 Math Sub-suite* | `.../test_adversarial_m3_math.py` | *(21)* | 0 | *(PASS)* |
| **Total Reconciled Unique Tests** | **Full Repository** | **1,146** | **0** | **100% PASS** |

All 1,146 unique tests pass cleanly under the pinned Python 3.12 / DoWhy 0.12 environment with zero double-counting.

---

## 4. Audit of the Proposed 18-Run Pilot

The proposed 18-run pilot was audited against the scenario specifications, oracle definitions, and telemetry capture contracts:

### 4.1 Pilot Scenario Design (1:1 Matched Design)
The pilot consists of 18 independent experimental runs ($N=18$), comprising 3 repetitions across 6 scenarios:

```
+-------------------------------------------------------------------------------------------------------+
| PILOT SCENARIO MATRIX (18 RUNS = 9 TREATED + 9 CONTROLS)                                              |
+----------------------+--------------------+---------------------+------------------+------------------+
| Scenario ID          | Attack Family      | Target Service      | Ground Truth     | Repetitions      |
+----------------------+--------------------+---------------------+------------------+------------------+
| xzutils-001          | Backdoor Injection | recommendationserv  | Y_drift = 1      | 3 reps (Run 1-3) |
| dep-confusion-001    | Dependency Confus. | emailservice        | Y_drift = 1      | 3 reps (Run 4-6) |
| solarwinds-001       | Build-time Trojan  | cartservice         | Y_drift = 1      | 3 reps (Run 7-9) |
| benign-update-001    | Rolling Update     | recommendationserv  | Y_drift = 0      | 3 reps (Run 10-12|
| benign-load-001      | High Load (k6)     | emailservice        | Y_drift = 0      | 3 reps (Run 13-15|
| benign-restart-001   | Pod CrashLoop      | cartservice         | Y_drift = 0      | 3 reps (Run 16-18|
+----------------------+--------------------+---------------------+------------------+------------------+
```

### 4.2 Control Comparability Audit
Each attack scenario is matched with a corresponding benign control targeting the same Kubernetes microservice:
1. **`recommendationservice`**:
   - *Attack*: `xzutils-001` (replaces `lzmaffi@1.0.0` with malicious `lzmaffi@1.0.1-phantom-backdoor`, spawning `/tmp/.phantom_beacon.py`).
   - *Control*: `benign-update-001` (authorized rolling update to signed `lzmaffi@1.0.1` conforming to declared contract).
2. **`emailservice`**:
   - *Attack*: `dep-confusion-001` (injects fake high-version package `acme-email-templates@9.9.9` connecting to sink port 4445).
   - *Control*: `benign-load-001` (k6 load generator injecting 200 req/sec traffic without software changes).
3. **`cartservice`**:
   - *Attack*: `solarwinds-001` (deploys modified image running undeclared `phantom-worker` background process connecting to sink port 4446).
   - *Control*: `benign-restart-001` (deletes pod to trigger Kubernetes replica self-healing crashloop recovery).

### 4.3 Root-Cause Analysis of Prior `solarwinds-001` Failures in `raw3/`
In historical dataset `raw3/`, all 3 repetitions of `solarwinds-001` failed injection (`inject() returned False`, `inject_ok=False`).
- **Forensic Finding**: `research/evaluation/attacks/solarwinds_style.py` lines 128–218 reveal that the scenario attempts to dynamically build a Docker image (`_build_image`) and deploy `596717729313.dkr.ecr.ap-south-1.amazonaws.com/phantom/api-gateway:solarwinds-eval`.
- **Failure Mechanism**: When Docker daemon was unreachable or the AWS ECR registry was not logged in, the `docker build` and image push failed, causing Kubernetes pod rollout to time out during Phase 2.
- **Pilot Requirement**: Pre-build and pre-push the attack image `phantom-eval-solarwinds:latest` into the cluster's local container runtime or registry prior to running the pilot.

### 4.4 Dataset Isolation Requirements
- The pilot must write all outputs to a fresh, dedicated directory:
  `research/datasets/pilot_batch01/`
- Manifests must record: `run_id`, `phases` (with timestamps and durations), `inject_ok`, `verified_contract_drift`, `sink_receipt_verified`, `contract_status`, `contract_evidence_verified`, `first_phantom_detection_timestamp`, `phantom_detections`, and pre-treatment covariates.
- Historical datasets `research/datasets/raw/` and `research/datasets/raw3/` must remain strictly immutable.

---

## 5. Statistical Methodology & Power Analysis Corrections

### Correction of Unsupported Statistical Claims
In preliminary discussions, sample sizes of $N \ge 20$ per group (for Wilson confidence intervals) and $N \ge 45$ per arm (for average treatment effect estimation with Cohen's $d = 0.60$) were cited.

> [!IMPORTANT]
> **Methodological Correction**:  
> Those calculations are **preliminary heuristic planning approximations** derived from simple asymptotic normal approximations. They must **not** be presented as verified statistical power proofs for the following reasons:
> 1. **Cluster and Longitudinal Design Effects**: Multiple repetitions of the same scenario on a shared Kubernetes node/cluster are not strictly independent and identically distributed (i.i.d.). Intra-cluster correlation ($\rho$) across repetitions inflates variance and reduces effective sample size:
>    $$N_{\text{eff}} = \frac{N}{1 + (m - 1)\rho}$$
> 2. **Binary Outcome Distribution**: Cohen's $d$ is defined for continuous Gaussian outcomes. Contract drift ($Y \in \{0, 1\}$) is a Bernoulli variable; appropriate power calculations require binomial risk difference or logistic regression power curves.
> 3. **Gate G1 Software Role**: Preflight Gate G1 ($N \ge 10$) is strictly a **linear-algebra sanity guard** designed to prevent singular/rank-deficient covariate covariance matrices in DoWhy regression. It does **not** imply statistical power or identifiability.

### Structured Three-Phase Experimental Roadmap:
- **Phase A (Pilot Campaign — $N = 18$)**: 9 attacks, 9 controls. Purpose: verify telemetry collection resilience, sink log capture, and eliminate collection dropouts. No definitive causal claims will be asserted.
- **Phase B (Expanded Study — $N = 60$)**: 10 repetitions $\times$ 6 scenarios (30 treated, 30 control). Purpose: evaluate detection sensitivity and false positive rates with Wilson 95% CI margins $E \approx \pm 0.08$.
- **Phase C (Full Campaign — $N = 90$)**: 15 repetitions $\times$ 6 scenarios (45 treated, 45 control). Purpose: publication-grade causal attribution evaluation.

---

## 6. Comprehensive Infrastructure-Readiness Checklist (The 7 Pillars)

Prior to launching the pilot, every item in this checklist must be verified and marked as satisfied:

| Pillar | Requirement | Verification Target | Status |
|---|---|---|:---:|
| **1. K8s & Kernel** | Multi-node Kubernetes cluster $\ge 1.28$ | `kubectl get nodes -o wide` | ❌ **BLOCKED** |
| | Linux Host Kernel $\ge 5.15$ with BTF | `cat /sys/kernel/btf/vmlinux` | ❌ **BLOCKED** |
| | BPF CO-RE & debugfs mounted | `mount | grep debugfs` | ❌ **BLOCKED** |
| **2. PHANTOM Stack** | PHANTOM API Gateway running | `curl -f http://localhost:8080/health` | ❌ **BLOCKED** |
| | eBPF Agent DaemonSet active on all nodes | `kubectl get ds phantom-ebpf-agent -n phantom` | ❌ **BLOCKED** |
| | Redis event broker connected | `redis-cli ping` | ❌ **BLOCKED** |
| | PostgreSQL metadata database connected | `pg_isready` | ❌ **BLOCKED** |
| **3. Independent Sinks**| `phantom-sink` Deployment & Service running | `kubectl get svc phantom-sink -n phantom-eval` | ❌ **BLOCKED** |
| | TCP ports 8443, 4445, 4446 accepting connections | `nc -zv phantom-sink 8443` | ❌ **BLOCKED** |
| | Internal CoreDNS resolution functional | `nslookup phantom-sink.phantom-eval` | ❌ **BLOCKED** |
| **4. Prometheus Telemetry**| Prometheus v2.45+ running and scraping | `curl -f http://localhost:9090/-/healthy` | ❌ **BLOCKED** |
| | Container CPU usage metrics active | Query: `rate(container_cpu_usage_seconds_total[1m])` | ❌ **BLOCKED** |
| | Container memory RSS metrics active | Query: `container_memory_rss` | ❌ **BLOCKED** |
| | eBPF event lag metric active | Query: `phantom_event_collection_latency_seconds` | ❌ **BLOCKED** |
| **5. Baseline Detectors**| Falco 0.44.1 deployed with modern eBPF driver | `kubectl get ds falco -n falco` | ❌ **BLOCKED** |
| | Falco alert log streaming to node path | `tail -f /var/log/falco/events.jsonl` | ❌ **BLOCKED** |
| | Trivy 0.70.0 installed on PATH | `trivy --version` | ❌ **BLOCKED** |
| **6. Scenarios & Images**| Base image `tiangolo/uwsgi-nginx-flask:python3.11` | `docker pull` cached on nodes | ❌ **BLOCKED** |
| | SolarWinds attack image pre-built | `phantom-eval-solarwinds:latest` in registry | ❌ **BLOCKED** |
| | Signed Markov behavioral contracts present | `cosign verify` on contract JSONs | ❌ **BLOCKED** |
| | Oracle YAML manifests aligned with runner | `research/evaluation/oracles/*.yaml` | ✅ **READY** |
| **7. Isolation & Safety** | Dedicated NetworkPolicy for `phantom-eval` | Restrict egress to internal cluster sinks only | ❌ **BLOCKED** |
| | Public internet egress blocked for victim pods | Verify drop on `curl 8.8.8.8` | ❌ **BLOCKED** |
| | Automatic phase recovery verified | Pod rollback restores clean contract | ✅ **READY** (Code) |

---

## 7. Safe and Cost-Optimized Environment Options

To safely execute the pilot at minimal cost, three deployment options were evaluated:

```
+---------------------------------------------------------------------------------------------------+
| COMPARATIVE ENVIRONMENT OPTIONS                                                                   |
+--------------------------+-----------------------+-------------------------+----------------------+
| Feature / Characteristic | Option A: AWS EKS     | Option B: Single EC2    | Option C: Local WSL2 |
+--------------------------+-----------------------+-------------------------+----------------------+
| Platform                 | Managed AWS EKS       | Single Ubuntu EC2 (k3s) | Windows 10 + WSL2    |
| Kernel / eBPF Support    | Native Amazon Linux   | Native Ubuntu 22.04 LTS | WSL2 Kernel (quirky) |
| Multi-node Support       | Yes (2x m7i-flex.large| No (single node k3s)    | No (Minikube 1-node) |
| Setup Complexity         | Low (Terraform ready) | Medium (bash script)    | High (Docker engine) |
| Cloud Cost / Hour        | ~$0.312 / hr          | ~$0.150 / hr            | $0.00 / hr           |
| Cost for 8-Hour Pilot    | ~$2.50 total          | ~$1.20 total            | $0.00 total          |
| Failure Risk             | Very Low              | Low                     | High (eBPF probes)   |
| Recommended Choice       | **RECOMMENDED (PROD)**| **LOWEST CLOUD COST**   | NOT RECOMMENDED      |
+--------------------------+-----------------------+-------------------------+----------------------+
```

### Detailed Cost Drivers for Option A (Managed AWS EKS via Terraform):
- **EKS Control Plane**: \$0.100/hr (fixed AWS fee).
- **Worker Nodes (2x `m7i-flex.large`)**: 2 vCPU, 8 GiB RAM $\to$ \$0.0888/hr $\times$ 2 = \$0.1776/hr.
- **RDS PostgreSQL (`db.t3.micro`, Single-AZ)**: \$0.0180/hr.
- **ElastiCache Redis (`cache.t3.micro`, Single-node)**: \$0.0160/hr.
- **ECR & Network I/O**: ~\$0.001/hr.
- **Total Burn Rate**: **~\$0.312 / hour** (\$7.49 / day).
- **Execution Cost**: An 8-hour execution window for the 18-run pilot will incur approximately **\$2.50 USD**.

---

## 8. Required Manual Approvals & Governance Protocol

To maintain complete transparency and eliminate accidental cloud charges or security breaches, the following protocol must be enforced:

1. **Explicit Human Sign-Off**:
   - No cloud provisioning commands (`terraform apply`, `aws eks create-cluster`, or `aws ec2 run-instances`) may be executed by an automated agent.
   - A human administrator must explicitly approve cloud resource creation and review estimated charges.
2. **Dedicated Cloud Sandbox**:
   - All cloud resources must be created in an isolated development AWS account/VPC with strict budget alert alarms set to \$10.00 USD.
3. **Mandatory Post-Execution Teardown**:
   - Immediately following pilot completion and dataset export, `terraform destroy` must be executed to release all cloud resources and stop billing.
4. **Network Containment**:
   - A dedicated Kubernetes `NetworkPolicy` must be applied to `phantom-eval` before any attack scenario runs, restricting all egress to `phantom-sink.phantom-eval.svc.cluster.local` and `kube-dns`.

---

## 9. Exact Step-by-Step Readiness Verification Commands

Once a candidate environment is provisioned, an operator must run the following exact read-only commands to verify cluster readiness before starting the pilot:

### Step 1: Verify Kubernetes & Node Health
```bash
# Check cluster connectivity and nodes
kubectl cluster-info
kubectl get nodes -o wide

# Verify node Linux kernel >= 5.15 and BTF support (run on node or via debug pod)
kubectl run btf-check --rm -i --restart=Never --image=busybox -- sh -c "test -f /sys/kernel/btf/vmlinux && echo 'BTF_SUPPORTED=TRUE' || echo 'BTF_MISSING'"
```

### Step 2: Verify PHANTOM Stack Deployment
```bash
# Verify phantom namespace pods
kubectl get pods -n phantom -o wide

# Check API Gateway health endpoint
kubectl port-forward svc/phantom-api-gateway 8080:8080 -n phantom &
curl -s http://localhost:8080/health | jq .

# Verify eBPF agent DaemonSet is running on all worker nodes
kubectl get daemonset phantom-ebpf-agent -n phantom
kubectl logs -n phantom -l app=phantom-ebpf-agent --tail=50
```

### Step 3: Deploy and Verify Target Workloads & Sinks
```bash
# Deploy target workloads in phantom-eval
kubectl apply -f research/evaluation/k8s/target-workloads.yaml

# Verify all target pods and phantom-sink are running
kubectl get pods -n phantom-eval -o wide

# Test phantom-sink TCP connectivity from within the cluster
kubectl run sink-test --rm -i --restart=Never --image=busybox -n phantom-eval -- nc -zv phantom-sink 8443
```

### Step 4: Verify Prometheus Monitoring
```bash
# Forward Prometheus port
kubectl port-forward svc/prometheus 9090:9090 -n monitoring &
curl -s http://localhost:9090/-/healthy

# Query CPU and memory metrics
curl -sG 'http://localhost:9090/api/v1/query' --data-urlencode 'query=rate(container_cpu_usage_seconds_total{namespace="phantom-eval"}[1m])' | jq .
curl -sG 'http://localhost:9090/api/v1/query' --data-urlencode 'query=container_memory_rss{namespace="phantom-eval"}' | jq .
```

### Step 5: Verify Baseline Detectors
```bash
# Check Falco DaemonSet and alert file
kubectl get daemonset falco -n falco
# Check local Trivy version
trivy --version
```

---

## 10. Conclusion & Final Recommendation

**Final Recommendation**: **NO-GO FOR LIVE ATTACKS AT THIS TIME**.

The test suites and software layers are in a verified state (1,146 tests passing, 0 failures, ground truth cleanly decoupled). However, live attack injection cannot proceed until a supported Linux/Kubernetes cluster is active.

**Approved Deployment Strategy**:
The disposable **Single-Node Ubuntu 22.04 LTS EC2 + k3s** architecture has been fully prepared and validated statically. It replaces the complex multi-service EKS setup with an agile, single-node lab costing ~$0.172/hr ($1.38 for an 8-hour pilot run).

See the comprehensive deployment plan and runbook in [PART7B_EC2_K3S_DEPLOYMENT_PLAN.md](file:///d:/project-1/PART7B_EC2_K3S_DEPLOYMENT_PLAN.md).

**Recommended Operator Sequence**:
1. Human administrator reviews and approves [PART7B_EC2_K3S_DEPLOYMENT_PLAN.md](file:///d:/project-1/PART7B_EC2_K3S_DEPLOYMENT_PLAN.md).
2. Apply Terraform in `infra/terraform/environments/k3s-lab/`.
3. Bootstrap cluster workloads using `build-images.sh` and `deploy-all.sh`.
4. Run the 7-pillar readiness verification.
5. Execute the 18-run pilot via the local SSH forwarding tunnel.
6. Run `terraform destroy` to tear down all resources.

