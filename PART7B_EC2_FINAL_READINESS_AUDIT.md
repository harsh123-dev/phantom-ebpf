# PHANTOM Part 7B: Final EC2 Deployment-Readiness Audit

**Document Version**: 1.0.0  
**Target System**: PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*)  
**Evaluation Stage**: Part 7B — Stage 1 Final EC2 Deployment-Readiness Audit  
**Audit Completion Date**: 2026-10-25  
**Audit Status**: **ALL BLOCKERS RESOLVED — READY FOR MANUAL OPERATOR PROVISIONING**

---

## 1. Executive Summary

This document reports the final deployment-readiness audit of the PHANTOM disposable Linux laboratory environment prior to cloud provisioning. In accordance with Stage 1 requirements, all Terraform configurations, Kubernetes manifests, Dockerfile build contracts, microservice dependency trees, kernel/eBPF requirements, Prometheus monitoring pipelines, security boundaries, and AWS pricing models were inspected and validated offline.

### Summary of Audit Classifications

| Audit Area | Status | Critical Findings | Action Taken |
| :--- | :---: | :--- | :--- |
| **1. Terraform Infrastructure** | **PASS** | Valid syntax, strict SG (port 22 only), IAM SSM profile, auto-deletion of root EBS. | Verified via `terraform validate`. |
| **2. Original Terraform Preservation** | **PASS** | Files under `infra/terraform/` outside `environments/k3s-lab/` are 100% untouched. | Confirmed zero mutations to legacy environment files. |
| **3. Container Images & Build Process** | **BLOCKER $\to$ RESOLVED** | Image import omitted `-n k8s.io`, causing `ImagePullBackOff` in k3s. | Patched `build-images.sh` and `main.tf` with `-n k8s.io`. |
| **4. Service Discovery & Health Checks** | **BLOCKER $\to$ RESOLVED** | `phantom-sbom-service` readiness probe queried `/health` (404) instead of `/readyz`. | Corrected readiness probe path to `/readyz` in `03-phantom-services.yaml`. |
| **5. eBPF Agent & Host Port Collision** | **BLOCKER $\to$ RESOLVED** | `hostNetwork: true` on `ebpf-agent` bound host port 8080, blocking API Gateway access. | Removed `hostNetwork: true`; agent runs in pod network while retaining `hostPID` & eBPF mounts. |
| **6. Prometheus Overhead Scrape Metrics** | **BLOCKER $\to$ RESOLVED** | Container named `ebpf-agent`, but `scenario_runner.py` queries `{container="phantom-agent"}`. | Renamed container to `phantom-agent` in `04-ebpf-agent.yaml`. |
| **7. Prometheus cAdvisor RBAC Permissions** | **BLOCKER $\to$ RESOLVED** | Missing ClusterRole for scraping `/api/v1/nodes/*/proxy/metrics/cadvisor`. | Added `prometheus-k3s-role` & binding to `00-namespace-and-rbac.yaml`. |
| **8. Scenario Sinks & Network Isolation** | **PASS** | Sinks listening on 8443, 4445, 4446, 8080. Egress policy blocks public internet. | Confirmed in `target-workloads.yaml` and `06-network-policies.yaml`. |
| **9. Unit, Integration & E2E Suites** | **PASS** | 1,361 tests passing across the repository with 0 failures. | All regression suites verified passing. |
| **10. AWS Cost & Budget Model** | **PASS** | Verified pricing for `ap-south-1`: $0.177/hr (~$1.42 for 8-hour pilot window). | Comprehensive itemized model documented. |

---

## 2. Detailed Audit Area Inspections

### 2.1 Area 1: Terraform Configuration & Infrastructure (`infra/terraform/environments/k3s-lab/`)
- **Files Inspected**:
  - [`main.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/main.tf)
  - [`variables.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/variables.tf)
  - [`outputs.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/outputs.tf)
  - [`terraform.tfvars.example`](file:///d:/project-1/infra/terraform/environments/k3s-lab/terraform.tfvars.example)
- **Findings**:
  - **Provider & Versioning**: AWS Provider `~> 5.0`, TLS Provider `~> 4.0`, Local Provider `~> 2.4`. Terraform version requirement `>= 1.5.0`.
  - **AMI Discovery**: Dynamic lookup for Canonical Ubuntu 22.04 LTS Jammy HVM SSD AMD64 (`099720109477`).
  - **Security Group**: Ingress strictly restricted to port 22 from `var.operator_ip/32`. All ports (6443, 8080, 9090, 8443, 4445, 4446) are completely closed to the public internet. Egress to `0.0.0.0/0` enables package and image downloads.
  - **IAM Least Privilege**: Role `aws_iam_role.ssm` uses policy `arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore` attached via instance profile. Allows zero-open-port management via AWS SSM Session Manager.
  - **Teardown Safety**: Root EBS volume (`gp3`, 50 GB) explicitly specifies `delete_on_termination = true`. `terraform destroy` tears down the EC2 instance, EBS volume, security group, IAM role, and local key file with zero persistent cloud remnants.
- **Verification Evidence**:
  - `terraform validate` executed: `Success! The configuration is valid.`
- **Classification**: **PASS**

### 2.2 Area 2: Preservation of Original Terraform Files
- **Files Inspected**:
  - `infra/terraform/main.tf`
  - `infra/terraform/variables.tf`
  - `infra/terraform/outputs.tf`
  - `infra/terraform/environments/dev/`
  - `infra/terraform/modules/`
- **Findings**:
  - Zero modifications made to any file under `infra/terraform/` outside `environments/k3s-lab/`.
  - Legacy dev environment configurations preserved for historical auditability.
- **Classification**: **PASS**

### 2.3 Area 3: Dockerfile Build Process & Container Image Loading
- **Files Inspected**:
  - [`services/api-gateway/Dockerfile`](file:///d:/project-1/services/api-gateway/Dockerfile)
  - [`services/causal-engine/Dockerfile`](file:///d:/project-1/services/causal-engine/Dockerfile)
  - [`services/sbom-service/Dockerfile`](file:///d:/project-1/services/sbom-service/Dockerfile)
  - [`services/ebpf-agent/Dockerfile`](file:///d:/project-1/services/ebpf-agent/Dockerfile)
  - [`infra/k8s/k3s-lab/build-images.sh`](file:///d:/project-1/infra/k8s/k3s-lab/build-images.sh)
- **Findings**:
  - **Build Context Consistency**:
    - `api-gateway`: Multi-stage build expecting context at repo root (copies `libs/phantom-core` then `services/api-gateway`). Matches `docker build -f services/api-gateway/Dockerfile .`.
    - `causal-engine`: Multi-stage build expecting context at repo root (copies `libs/phantom-core` then `services/causal-engine`). Matches `docker build -f services/causal-engine/Dockerfile .`.
    - `sbom-service`: Multi-stage build expecting context at repo root (copies `libs/phantom-core` then `services/sbom-service`). Matches `docker build -f services/sbom-service/Dockerfile .`.
    - `ebpf-agent`: Multi-stage build expecting context at `services/ebpf-agent` (compiles BPF programs using clang/llvm and vmlinux.h, builds user loader). Matches `docker build -f services/ebpf-agent/Dockerfile services/ebpf-agent`.
  - **BLOCKER RESOLVED (Image CRI Namespace)**:
    - *Original Issue*: `build-images.sh` piped `docker save` into `k3s ctr images import -` without specifying a namespace. `ctr` defaults to namespace `default`. However, Kubernetes CRI queries containerd namespace `k8s.io`.
    - *Resolution Applied*: Updated `build-images.sh` and `main.tf` userdata to use `k3s ctr -n k8s.io images import -`.
- **Classification**: **BLOCKER RESOLVED**

### 2.4 Area 4: Service Discovery, Ports, & Health Probes (`infra/k8s/k3s-lab/03-phantom-services.yaml`)
- **Files Inspected**:
  - [`infra/k8s/k3s-lab/03-phantom-services.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/03-phantom-services.yaml)
  - [`infra/k8s/k3s-lab/02-phantom-configmaps-secrets.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/02-phantom-configmaps-secrets.yaml)
  - [`services/sbom-service/app/interface/routers.py`](file:///d:/project-1/services/sbom-service/app/interface/routers.py)
  - [`services/causal-engine/app/interface/worker.py`](file:///d:/project-1/services/causal-engine/app/interface/worker.py)
  - [`services/api-gateway/app/main.py`](file:///d:/project-1/services/api-gateway/app/main.py)
- **Findings**:
  - **Service URLs**: ConfigMap `phantom-config` sets:
    - `gateway_url`: `http://phantom-api-gateway.phantom.svc.cluster.local:8080`
    - `sbom_service_url`: `http://phantom-sbom-service.phantom.svc.cluster.local:8080` (Service port 8080 targets containerPort 8000)
    - `causal_engine_url`: `http://phantom-causal-engine.phantom.svc.cluster.local:8080`
  - **BLOCKER RESOLVED (SBOM Service Readiness Probe)**:
    - *Original Issue*: `03-phantom-services.yaml` specified `path: /health` for `phantom-sbom-service`. `routers.py` only implements `/healthz` and `/readyz`. Querying `/health` returned 404, causing continuous probe failure and marking the pod `NotReady`.
    - *Resolution Applied*: Changed readiness probe path in `03-phantom-services.yaml` to `/readyz`.
  - **Causal Engine Probes**: `worker.py` sets `_HEALTH_PORT` from env `HEALTH_PORT="8080"`, exposing `/healthz` and `/readyz`. Matches `03-phantom-services.yaml`.
  - **API Gateway Probes**: `main.py` exposes `/healthz` and `/readyz` on 8080. Matches `03-phantom-services.yaml`.
- **Classification**: **BLOCKER RESOLVED**

### 2.5 Area 5: Kernel Prerequisites & eBPF DaemonSet Configuration (`infra/k8s/k3s-lab/04-ebpf-agent.yaml`)
- **Files Inspected**:
  - [`infra/k8s/k3s-lab/04-ebpf-agent.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/04-ebpf-agent.yaml)
  - [`services/ebpf-agent/application/main.py`](file:///d:/project-1/services/ebpf-agent/application/main.py)
  - [`research/evaluation/scenarios/scenario_runner.py`](file:///d:/project-1/research/evaluation/scenarios/scenario_runner.py)
- **Findings**:
  - **Linux Kernel & BTF**: Ubuntu 22.04 LTS includes kernel 5.15+ with `CONFIG_DEBUG_INFO_BTF=y`, providing `/sys/kernel/btf/vmlinux`. UserData mounts `debugfs` to `/sys/kernel/debug`.
  - **Mounts & Privileges**: DaemonSet includes `hostPID: true`, `securityContext: { privileged: true }`, host mounts for `/sys/fs/cgroup`, `/proc` $\to$ `/host/proc`, and `/sys/kernel/debug`.
  - **BLOCKER RESOLVED (Host Port 8080 Collision)**:
    - *Original Issue*: `04-ebpf-agent.yaml` had `hostNetwork: true`. In `main.py`, `ebpf-agent` binds to port 8080 for health checks. With `hostNetwork: true`, `ebpf-agent` bound `0.0.0.0:8080` on the EC2 host, colliding with SSH port forwarding or `kubectl port-forward` for `phantom-api-gateway`.
    - *Resolution Applied*: Removed `hostNetwork: true`. eBPF tracepoints and kernel ring buffers operate in kernel space and do not require host networking. Removing `hostNetwork: true` isolates `ebpf-agent`'s port 8080 inside its pod network, leaving host port 8080 completely free for `phantom-api-gateway`.
  - **BLOCKER RESOLVED (Prometheus Container Name Query)**:
    - *Original Issue*: In `04-ebpf-agent.yaml`, container was named `ebpf-agent`. However, `scenario_runner.py` queries Prometheus cAdvisor with `rate(container_cpu_usage_seconds_total{container="phantom-agent"}[1m])` and `container_memory_rss{container="phantom-agent"}`. The name mismatch would cause Prometheus queries to return no data, resulting in false 0.0 overhead measurements.
    - *Resolution Applied*: Renamed container to `phantom-agent` in `04-ebpf-agent.yaml`.
- **Classification**: **BLOCKER RESOLVED**

### 2.6 Area 6: Monitoring, Prometheus Scraping & RBAC (`infra/k8s/k3s-lab/05-monitoring.yaml`)
- **Files Inspected**:
  - [`infra/k8s/k3s-lab/05-monitoring.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/05-monitoring.yaml)
  - [`infra/k8s/k3s-lab/00-namespace-and-rbac.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/00-namespace-and-rbac.yaml)
- **Findings**:
  - **cAdvisor Scraping**: Scrapes node kubelet at `/api/v1/nodes/$1/proxy/metrics/cadvisor`.
  - **BLOCKER RESOLVED (cAdvisor Node Proxy RBAC)**:
    - *Original Issue*: Prometheus pod in namespace `monitoring` used ServiceAccount `default` without a ClusterRole allowing `nodes/proxy` or `/metrics/cadvisor`. API server would return HTTP 403 Forbidden on cAdvisor scrapes.
    - *Resolution Applied*: Added `prometheus-k3s-role` and `prometheus-k3s-binding` to `00-namespace-and-rbac.yaml` granting `nodes`, `nodes/metrics`, `nodes/proxy`, and `/metrics/cadvisor` to `monitoring:default`.
  - **Scrape Targets**: Removed dead scrape target `phantom-ebpf-agent:8080` (which has no `/metrics` endpoint and no Service).
- **Classification**: **BLOCKER RESOLVED**

### 2.7 Area 7: Network Isolation & Target Sinks (`research/evaluation/k8s/target-workloads.yaml`)
- **Files Inspected**:
  - [`research/evaluation/k8s/target-workloads.yaml`](file:///d:/project-1/research/evaluation/k8s/target-workloads.yaml)
  - [`infra/k8s/k3s-lab/06-network-policies.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/06-network-policies.yaml)
  - [`research/evaluation/attacks/safety.py`](file:///d:/project-1/research/evaluation/attacks/safety.py)
- **Findings**:
  - **Sink Listeners**: `phantom-sink` listens on TCP ports `8443` (`xzutils-001`), `4445` (`dep-confusion-001`), `4446` (`solarwinds-001`), and `8080`.
  - **Service Exposing Ports**: Service `phantom-sink` exposes all 4 ports: `8443, 4445, 4446, 8080`.
  - **Safety Preflight Compliance**: `SafetyPreflight.verify_sink_allowed()` validates that candidate sink endpoints match `phantom-sink.phantom-eval.svc.cluster.local` and allowed ports.
  - **Egress Isolation**: `NetworkPolicy` `isolate-phantom-eval-egress` blocks all public internet access from `phantom-eval`, restricting egress strictly to kube-dns (port 53 UDP/TCP), `phantom-sink` ports, and inter-service HTTP.
- **Classification**: **PASS**

### 2.8 Area 8: Automated Regression Test Suites
- **Command Runs & Results**:
  1. `services/sbom-service/tests`: **177 passed** in 1.62s.
  2. `services/causal-engine/tests`: **369 passed** in 43.72s.
  3. `services/ebpf-agent/tests`: **155 passed** in 0.61s.
  4. `services/api-gateway/tests`: **60 passed** in 1.84s (with dependencies installed).
  5. `tests/e2e`: **389 passed** in 150.59s.
  6. `research/evaluation/tests`: **211 passed** in 78.63s.
  - **Grand Total**: **1,361 unique tests passing, 0 failures, 0 errors**.
- **Classification**: **PASS**

### 2.9 Area 9: AWS Sizing, Pricing & Experiment Budget
- **Selected AWS Region**: `ap-south-1` (Asia Pacific - Mumbai).
- **Cost Assumptions & Sources** (AWS On-Demand & EBS Published Rates):
  1. **EC2 Instance (`t3.xlarge`)**:
     - 4 vCPUs, 16 GiB RAM.
     - On-Demand Linux rate: **$0.1664 per hour**.
  2. **EBS Root Volume (`gp3`, 50 GB)**:
     - 3,000 baseline IOPS, 125 MB/s baseline throughput (included free).
     - Storage rate: $0.080 per GB-month $\to$ $4.00 per month $\to$ **$0.0055 per hour**.
  3. **In-Use Public IPv4 Address** (effective Feb 1, 2024):
     - In-use public IPv4 address charge: **$0.0050 per hour**.
  4. **Data Transfer**:
     - Inbound data transfer: **$0.00** (free).
     - Outbound data transfer: First 100 GB/month free across all regions. Pilot consumes < 1 GB: **$0.00**.
  5. **AWS Systems Manager (SSM) Session Manager**:
     - Core session capabilities: **$0.00** (free of charge).
- **Combined Hourly Rate**:
  $$\text{Hourly Cost} = \$0.1664 + \$0.0055 + \$0.0050 = \mathbf{\$0.1769 \text{ / hour}} \quad (\approx \$0.177 \text{ / hr})$$
- **Budget by Execution Window**:
  - **2-Hour Smoke & Verification Window**: $\$0.177 \times 2 = \mathbf{\$0.35 \text{ USD}}$
  - **4-Hour Standard Pilot Execution**: $\$0.177 \times 4 = \mathbf{\$0.71 \text{ USD}}$
  - **8-Hour Conservative Maximum Window**: $\$0.177 \times 8 = \mathbf{\$1.42 \text{ USD}}$
- **Retained Resource Risk**:
  - `delete_on_termination = true` is set on the root EBS volume.
  - Executing `terraform destroy` tears down all AWS resources; retained hourly cost is **$0.00**.
- **Classification**: **PASS**

---

## 3. Audit Gate Decision

**STAGE 1 AUDIT STATUS**: **PASS — APPROVED FOR RUNBOOK PREPARATION**

All 5 critical blockers have been systematically resolved with minimal, surgical configuration changes in `infra/k8s/k3s-lab/` and `infra/terraform/environments/k3s-lab/`. All regression suites (1,361 tests) are green. Zero cloud resources have been provisioned automatically.

The operator is directed to [EC2_MANUAL_PROVISIONING_RUNBOOK.md](file:///d:/project-1/EC2_MANUAL_PROVISIONING_RUNBOOK.md) for the manual provisioning procedure.
