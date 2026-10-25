# PHANTOM Part 7B: Disposable Linux Lab Deployment Plan (Ubuntu EC2 + k3s)

**Document Version**: 1.0.0  
**Target System**: PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*)  
**Evaluation Stage**: Part 7B — Controlled 18-Run Pilot Lab Environment Preparation  
**Execution Gate Status**: **PLANNING READY (AWAITING HUMAN APPROVAL BEFORE CLOUD PROVISIONING)**

---

## 1. Executive Summary & Selected Architecture

### 1.1 Architecture Decision: Single-Node Ubuntu 22.04 EC2 + k3s
Following the forensic audit in `PART7B_INFRASTRUCTURE_READINESS.md`, the previously configured AWS EKS cluster (`vprofile-eks-cluster`) was confirmed deprovisioned, and the local Windows workstation lacks native Linux kernel eBPF BTF capabilities.

To execute the 18-run pilot safely, rapidly, and at minimal cost, the **Single-Node Ubuntu 22.04 LTS EC2 Instance running k3s** architecture is selected over a multi-service AWS EKS deployment.

```
+-------------------------------------------------------------------------------------------------------+
| PHANTOM DISPOSABLE LAB ARCHITECTURE (UBUNTU 22.04 LTS EC2 + k3s)                                     |
+-------------------------------------------------------------------------------------------------------+
| [Operator Workstation (Windows 10)]                                                                   |
|   |                                                                                                   |
|   |  SSH Local Port Forwarding Tunnel (Port 22 only, restricted to <OPERATOR_IP>/32)                   |
|   +---------------------------------------+----------------------------------+                        |
|                                           |                                  |                        |
|                                     (Port 6443)                        (Port 8080)                    |
|                                           |                                  |                        |
|                                           v                                  v                        |
| [Single AWS EC2 Instance: t3.xlarge (4 vCPU, 16 GiB RAM, 50 GB gp3 root disk) — Ubuntu 22.04 LTS]    |
|   +-------------------------------------------------------------------------------------------------+ |
|   | Linux Host OS: Kernel 5.15+ with /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y) & debugfs   | |
|   | Container Runtime: Docker Engine 24.0+ & k3s containerd (local image cache, zero ECR dependency)| |
|   +-------------------------------------------------------------------------------------------------+ |
|   | k3s Kubernetes Cluster (Control Plane + Worker on single node)                                  | |
|   |                                                                                                 | |
|   | [Namespace: phantom]                                                                            | |
|   |   • phantom-api-gateway (FastAPI HTTP Gateway :8080)                                            | |
|   |   • phantom-causal-engine (DoWhy 0.12 Causal Attribution Service :8080)                         | |
|   |   • phantom-sbom-service (CycloneDX 1.5 SBOM Mapping Service :8080)                            | |
|   |   • phantom-ebpf-agent (Privileged DaemonSet: hostPID, hostNetwork, /sys/kernel/debug)          | |
|   |   • phantom-postgres (In-cluster PostgreSQL 15 pod — replaces AWS RDS)                         | |
|   |   • phantom-redis (In-cluster Redis 7 pod — replaces AWS ElastiCache)                           | |
|   |                                                                                                 | |
|   | [Namespace: phantom-eval (Victim Workloads & Mock Sinks)]                                       | |
|   |   • recommendationservice (Python 3.11 — target of xzutils-001 & benign-update-001)             | |
|   |   • emailservice (Python 3.11 — target of dep-confusion-001 & benign-load-001)                  | |
|   |   • cartservice (C#/.NET — target of solarwinds-001 & benign-restart-001)                       | |
|   |   • phantom-sink (In-cluster ClusterIP TCP sink :8443, :4445, :4446, :8080)                     | |
|   |   • NetworkPolicy: Egress strictly locked to phantom-sink & CoreDNS; public internet DENIED     | |
|   |                                                                                                 | |
|   | [Namespace: monitoring]                                                                         | |
|   |   • prometheus (Prometheus v2.45 scraping cAdvisor metrics and PHANTOM services :9090)          | |
|   +-------------------------------------------------------------------------------------------------+ |
+-------------------------------------------------------------------------------------------------------+
```

### 1.2 Justification & Comparison Matrix

| Architectural Factor | Managed AWS EKS (Option A) | Single Ubuntu EC2 + k3s (Selected) | Local WSL2 / Minikube (Option C) |
| :--- | :--- | :--- | :--- |
| **Hourly Burn Rate** | ~$0.312 / hr ($7.49 / day) | **~$0.172 / hr ($4.13 / day)** | $0.00 / hr |
| **8-Hour Pilot Cost** | ~$2.50 USD + EKS hourly | **~$1.38 USD total** | $0.00 USD |
| **Control Plane Fee** | $0.100 / hr ($73 / mo fixed) | **$0.00 (embedded k3s)** | $0.00 |
| **Backing Services** | AWS RDS + ElastiCache ($0.034/hr) | **$0.00 (in-cluster pods)** | $0.00 |
| **Kernel / eBPF BTF** | Amazon Linux 2 / AL2023 | **Native Ubuntu 22.04 LTS (5.15+)** | WSL2 custom kernel (unstable BTF) |
| **Provisioning Time** | 15–20 minutes | **90–120 seconds** | N/A (Docker daemon stopped) |
| **Teardown Friction** | High (VPC, NAT, EKS, RDS, ECR) | **Instant (single instance delete)**| N/A |
| **Risk of Lingering Cost** | High (forgotten NAT / EKS) | **Zero (single EC2 instance)** | None |

---

## 2. Infrastructure Configuration Files Created & Updated

All configuration files have been prepared and statically validated in the repository:

| File Path | Description / Role | Status |
| :--- | :--- | :---: |
| [`infra/terraform/environments/k3s-lab/main.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/main.tf) | Terraform configuration: Ubuntu 22.04 AMI, `t3.xlarge` EC2, 50 GB gp3 EBS, strict Security Group, UserData bootstrap script | ✅ **Created & Validated** |
| [`infra/terraform/environments/k3s-lab/variables.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/variables.tf) | Input variables (`aws_region`, `instance_type`, `operator_ip`, `root_volume_size`, `enable_ssm`) | ✅ **Created** |
| [`infra/terraform/environments/k3s-lab/outputs.tf`](file:///d:/project-1/infra/terraform/environments/k3s-lab/outputs.tf) | Outputs (`instance_id`, `public_ip`, `ssh_command`, `ssh_tunnel_command`, `ssm_session_command`) | ✅ **Created** |
| [`infra/terraform/environments/k3s-lab/terraform.tfvars.example`](file:///d:/project-1/infra/terraform/environments/k3s-lab/terraform.tfvars.example) | Example configuration template for the operator | ✅ **Created** |
| [`infra/k8s/k3s-lab/00-namespace-and-rbac.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/00-namespace-and-rbac.yaml) | Namespaces (`phantom`, `phantom-eval`, `monitoring`), ServiceAccounts, ClusterRole and Binding | ✅ **Created** |
| [`infra/k8s/k3s-lab/01-in-cluster-backing-services.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/01-in-cluster-backing-services.yaml) | Lightweight in-cluster PostgreSQL 15 & Redis 7 deployments and ClusterIP Services | ✅ **Created** |
| [`infra/k8s/k3s-lab/02-phantom-configmaps-secrets.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/02-phantom-configmaps-secrets.yaml) | ConfigMaps and Secrets pointing PHANTOM services to in-cluster Postgres & Redis | ✅ **Created** |
| [`infra/k8s/k3s-lab/03-phantom-services.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/03-phantom-services.yaml) | Deployments & ClusterIP Services for API Gateway, Causal Engine, and SBOM Service | ✅ **Created** |
| [`infra/k8s/k3s-lab/04-ebpf-agent.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/04-ebpf-agent.yaml) | Privileged DaemonSet for PHANTOM eBPF agent with `/sys/fs/cgroup`, `/proc`, `/sys/kernel/debug` | ✅ **Created** |
| [`infra/k8s/k3s-lab/05-monitoring.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/05-monitoring.yaml) | Prometheus deployment & configuration scraping cAdvisor and PHANTOM services | ✅ **Created** |
| [`infra/k8s/k3s-lab/06-network-policies.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/06-network-policies.yaml) | Kubernetes NetworkPolicy strictly isolating `phantom-eval` and blocking internet egress | ✅ **Created** |
| [`infra/k8s/k3s-lab/deploy-all.sh`](file:///d:/project-1/infra/k8s/k3s-lab/deploy-all.sh) | Automated in-cluster deployment and health rollout script | ✅ **Created** |
| [`infra/k8s/k3s-lab/build-images.sh`](file:///d:/project-1/infra/k8s/k3s-lab/build-images.sh) | Docker build & k3s containerd import script for local service images | ✅ **Created** |
| [`research/evaluation/k8s/target-workloads.yaml`](file:///d:/project-1/research/evaluation/k8s/target-workloads.yaml) | Target victim microservices and `phantom-sink` (patched with port 4445) | ✅ **Updated** |

---

## 3. Sizing & Resource Requirements

### 3.1 Hardware & Compute Capacity
| Component / Layer | Minimum Required | Allocated (`t3.xlarge`) | Headroom / Safety Margin |
| :--- | :--- | :--- | :--- |
| **CPU Cores** | 2 vCPUs | **4 vCPUs** | 100% compute buffer for DoWhy refutations & k6 load |
| **Memory (RAM)** | 8 GiB | **16 GiB** | 8 GiB headroom; prevents OOM-kill during causal estimation |
| **Root Disk** | 30 GB | **50 GB gp3** | 3,000 IOPS / 125 MB/s; caches all Docker layers & Prometheus |
| **Kernel Version** | Linux $\ge 5.15$ | **Ubuntu 22.04 LTS (5.15+)** | Full native BTF support (`/sys/kernel/btf/vmlinux`) |
| **Privileged Containers** | Required for eBPF | **Supported (containerd)** | `privileged: true`, `hostPID: true`, `hostNetwork: true` |

### 3.2 Detailed Workload Resource Budget (Peak Concurrent Usage)
- **k3s Server & containerd overhead**: ~1.0 vCPU, ~1.0 GiB RAM
- **PHANTOM Core Services**:
  - `phantom-api-gateway`: 0.1 vCPU request (0.5 limit), 128 MiB request (512 MiB limit)
  - `phantom-causal-engine`: 0.1 vCPU request (1.0 limit), 256 MiB request (2048 MiB limit)
  - `phantom-sbom-service`: 0.1 vCPU request (0.5 limit), 128 MiB request (512 MiB limit)
  - `phantom-ebpf-agent`: 0.1 vCPU request (0.5 limit), 128 MiB request (512 MiB limit)
  - `phantom-postgres` & `phantom-redis`: 0.15 vCPU request (0.7 limit), 192 MiB request (768 MiB limit)
- **Victim Microservices (`phantom-eval`)**:
  - `recommendationservice`: 0.1 vCPU request (0.2 limit), 128 MiB request (256 MiB limit)
  - `emailservice`: 0.1 vCPU request (0.2 limit), 128 MiB request (256 MiB limit)
  - `cartservice`: 0.1 vCPU request (0.2 limit), 128 MiB request (256 MiB limit)
  - `phantom-sink`: 0.01 vCPU request (0.1 limit), 32 MiB request (64 MiB limit)
- **Monitoring (`monitoring`)**:
  - `prometheus`: 0.1 vCPU request (0.5 limit), 256 MiB request (1024 MiB limit)
- **Total Peak Requested**: ~2.0 vCPU, ~2.7 GiB RAM (well within `t3.xlarge` 4 vCPU / 16 GiB capacity).

---

## 4. Security Controls & Traffic Isolation

### 4.1 Inbound Perimeter Protection
> [!IMPORTANT]
> **Strict Inbound Firewall Policy:**
> - The EC2 Security Group allows **only port 22 (SSH)** inbound, and **strictly restricted** to the operator's public IPv4 address (`<OPERATOR_IP>/32`).
> - If `operator_ip` is left blank, **all inbound ports are closed (0 inbound rules)**, and access is conducted exclusively through AWS Systems Manager (SSM) Session Manager.
> - **Zero public exposure**:
>   - Kubernetes API (port 6443): **CLOSED TO INTERNET**
>   - PHANTOM API Gateway (port 8080): **CLOSED TO INTERNET**
>   - Prometheus (port 9090): **CLOSED TO INTERNET**
>   - Test Sinks (ports 8443, 4445, 4446, 8080): **CLOSED TO INTERNET**

### 4.2 Secure Access via SSH Local Port Forwarding
All management and API traffic flows through an encrypted SSH tunnel bound to `127.0.0.1`:
```bash
ssh -i ~/.ssh/phantom-lab-key.pem -N \
    -L 6443:127.0.0.1:6443 \
    -L 8080:127.0.0.1:8080 \
    -L 9090:127.0.0.1:9090 \
    ubuntu@<EC2_PUBLIC_IP>
```
Once the tunnel is active:
- Workstation `kubectl` connects securely to `https://127.0.0.1:6443` (satisfies `APPROVED_CLUSTER_ENDPOINT_PATTERNS`).
- Workstation PHANTOM scenario runner queries `http://localhost:8080` (API Gateway) and `http://localhost:9090` (Prometheus).

### 4.3 In-Cluster Egress Isolation (NetworkPolicy)
The [`06-network-policies.yaml`](file:///d:/project-1/infra/k8s/k3s-lab/06-network-policies.yaml) manifest enforces strict egress rules in `phantom-eval`:
1. **Permitted**: UDP/TCP port 53 to `kube-dns` in `kube-system`.
2. **Permitted**: TCP ports 8443, 4445, 4446, 8080 to `phantom-sink.phantom-eval.svc.cluster.local`.
3. **Permitted**: Internal HTTP RPC between victim pods (`recommendationservice`, `emailservice`, `cartservice`).
4. **BLOCKED**: All public internet IP ranges (e.g. `8.8.8.8`, external sinks, C2 servers).
5. **BLOCKED**: AWS instance metadata endpoint (`169.254.169.254`).

---

## 5. Itemized Cost Estimate & Billable Resource Breakdown

### 5.1 Itemized Hourly Cost Breakdown (AWS `ap-south-1` Mumbai)

| Resource | Quantity / Specification | Unit Pricing | Hourly Cost (USD) | 8-Hour Pilot Cost (USD) |
| :--- | :--- | :--- | :--- | :--- |
| **EC2 Compute** | 1x `t3.xlarge` (4 vCPU, 16 GiB) | $0.1664 / hour (On-Demand) | $0.1664 / hr | $1.331 USD |
| **EBS Storage** | 50 GB gp3 Root Volume | $0.08 / GB-month | $0.0055 / hr | $0.044 USD |
| **Public IPv4** | 1 In-use Public IPv4 Address | $0.005 / hour (AWS standard) | $0.0050 / hr | $0.040 USD |
| **Kubernetes Control Plane** | k3s (embedded on EC2) | Free / Open Source | $0.0000 / hr | $0.000 USD |
| **PostgreSQL Database** | In-cluster container pod | Free / Open Source | $0.0000 / hr | $0.000 USD |
| **Redis Cache** | In-cluster container pod | Free / Open Source | $0.0000 / hr | $0.000 USD |
| **Data Transfer** | Outbound < 1 GB (setup/apt) | ~$0.09 / GB | < $0.0010 / hr | ~$0.010 USD |
| **Total Billable Burn Rate** | | | **~$0.177 / hour** | **~$1.425 USD** |

### 5.2 Cost Control Safeguards
- **Budget Alert**: Set a \$5.00 USD AWS Budget alert on the AWS account before provisioning.
- **Teardown Discipline**: Running `terraform destroy` immediately after dataset extraction releases 100% of billable resources.
- **No Lingering Assets**: No Elastic IPs, no ECR private repos, no KMS keys, and no NAT gateways are created.

---

## 6. Manual Provisioning Commands (Operator Instructions)

> [!CAUTION]
> **Human Approval Gate:**  
> These commands must be executed manually by the human operator. The automated agent is strictly bounded and will **not** execute `terraform apply` or create cloud resources.

### Step 1: Discover Your Workstation Public IP
```powershell
$MY_IP = (Invoke-RestMethod -Uri "https://ifconfig.me/ip").Trim()
Write-Host "Operator IP: $MY_IP"
```

### Step 2: Initialize and Review Terraform Plan
```powershell
cd D:\project-1\infra\terraform\environments\k3s-lab

# Create terraform.tfvars with your IP
@"
aws_region       = "ap-south-1"
instance_type    = "t3.xlarge"
root_volume_size = 50
operator_ip      = "$MY_IP"
enable_ssm       = true
"@ | Out-File -FilePath terraform.tfvars -Encoding utf8

# Review planned resources
terraform plan
```

### Step 3: Provision the EC2 Instance
```powershell
terraform apply -auto-approve
```
*Wait ~90 seconds for instance creation and UserData bootstrap to finish.*

### Step 4: Extract Connection Details
```powershell
$LAB_IP = (terraform output -raw public_ip)
$SSH_CMD = (terraform output -raw ssh_command)
$TUNNEL_CMD = (terraform output -raw ssh_tunnel_command)

Write-Host "Lab Node IP: $LAB_IP"
Write-Host "SSH Connect: $SSH_CMD"
```

---

## 7. Step-by-Step Readiness Verification (The 7 Pillars)

Once the EC2 instance is running and the UserData bootstrap completes (`/var/log/phantom-bootstrap.done` exists), verify the 7 pillars:

### Pillar 1: Kubernetes & Kernel BTF
SSH into the node:
```bash
ssh -i .ssh/phantom-lab-key.pem ubuntu@<LAB_IP>
```
Run host verification:
```bash
# Verify k3s node status
kubectl get nodes -o wide

# Verify Linux kernel >= 5.15
uname -r

# Verify BTF is present and non-empty
test -s /sys/kernel/btf/vmlinux && echo "PILLAR_1_BTF: PASS" || echo "PILLAR_1_BTF: FAIL"

# Verify debugfs is mounted
mount | grep debugfs && echo "PILLAR_1_DEBUGFS: PASS"
```

### Pillar 2: Deploy PHANTOM Stack & Verify Services
On the EC2 node:
```bash
# Clone or copy repository to /home/ubuntu/phantom
git clone https://github.com/<YOUR_FORK>/phantom.git /home/ubuntu/phantom
cd /home/ubuntu/phantom

# Build service images locally into k3s containerd
bash infra/k8s/k3s-lab/build-images.sh

# Deploy backing services, PHANTOM services, and eBPF DaemonSet
bash infra/k8s/k3s-lab/deploy-all.sh

# Verify all pods are Running
kubectl get pods -n phantom
kubectl get pods -n phantom-eval
kubectl get pods -n monitoring
```

### Pillar 3: Independent Test Sinks
```bash
# Verify phantom-sink Service exposes ports 8443, 4445, 4446, 8080
kubectl get svc phantom-sink -n phantom-eval -o jsonpath='{range .spec.ports[*]}{.port}{" "}{end}'
# Expected output: 8443 4445 4446 8080

# Test TCP socket connect from within the cluster
kubectl run sink-probe --rm -i --restart=Never --image=busybox -n phantom-eval -- nc -zv phantom-sink 8443
kubectl run sink-probe --rm -i --restart=Never --image=busybox -n phantom-eval -- nc -zv phantom-sink 4445
```

### Pillar 4: Prometheus Telemetry Scrapers
```bash
# Verify Prometheus is healthy
curl -s http://prometheus.monitoring.svc.cluster.local:9090/-/healthy
# Expected: Prometheus Server is Healthy.

# Verify container metrics are actively ingested
curl -sG 'http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query' \
    --data-urlencode 'query=rate(container_cpu_usage_seconds_total{namespace="phantom-eval"}[1m])' | jq .data.result
```

### Pillar 5: Baseline Detectors
```bash
# Verify Falco or baseline JSONL log location
ls -la /var/log/falco/events.jsonl || touch /var/log/falco/events.jsonl
```

### Pillar 6: Scenario Images & Workload Alignment
```bash
# Verify victim workloads are 1/1 Running in phantom-eval
kubectl get deployment -n phantom-eval
# recommendationservice (1/1), emailservice (1/1), cartservice (1/1), phantom-sink (1/1)
```

### Pillar 7: Network Isolation & Safety Policies
```bash
# Test that in-cluster victim pod CAN reach internal sink:
kubectl exec -n phantom-eval deployment/recommendationservice -- nc -zv phantom-sink 8443

# Test that in-cluster victim pod CANNOT reach the public internet (NetworkPolicy test):
kubectl exec -n phantom-eval deployment/recommendationservice -- timeout 3 nc -zv 8.8.8.8 53 || echo "EGRESS_BLOCKED: PASS"
```

---

## 8. Executing the 18-Run Pilot via Secure Tunnel

### Step 1: Open the Secure SSH Tunnel on Operator Workstation
In a dedicated PowerShell window on your local machine:
```powershell
cd D:\project-1\infra\terraform\environments\k3s-lab
terraform output -raw ssh_tunnel_command | Invoke-Expression
```
*Keep this PowerShell window open during the evaluation.*

### Step 2: Configure Workstation Local Kubeconfig
Fetch the cluster kubeconfig from the instance:
```powershell
# Copy k3s config to local evaluation config
scp -i infra/terraform/environments/k3s-lab/.ssh/phantom-lab-key.pem ubuntu@<LAB_IP>:/etc/rancher/k3s/k3s.yaml D:\project-1\.kube-phantom-lab.yaml

# Modify server endpoint from 127.0.0.1:6443 (already points to local tunnel!)
$env:KUBECONFIG="D:\project-1\.kube-phantom-lab.yaml"
kubectl get nodes
```

### Step 3: Run Pilot Scenario Orchestration
In your local Python 3.12 environment (`.venv-causal`):
```powershell
$env:PYTHONPATH="."
$env:KUBECONFIG="D:\project-1\.kube-phantom-lab.yaml"

# 1. First run dry-run to confirm clean plan:
.venv-causal\Scripts\python research/evaluation/scenarios/run_all_scenarios.py `
    --campaign pilot `
    --namespace phantom-eval `
    --kubectl-context default

# 2. Execute the 18-run pilot against the verified lab:
.venv-causal\Scripts\python research/evaluation/scenarios/run_all_scenarios.py `
    --campaign pilot `
    --namespace phantom-eval `
    --kubectl-context default `
    --output-dir research/datasets/pilot_batch01 `
    --repetitions 3 `
    --execute
```

---

## 9. Teardown Commands & Cleanup Verification

Immediately upon pilot completion:

### Step 1: Copy Dataset Artifacts Locally (if run remotely)
All run manifests and JSON records are written directly to `research/datasets/pilot_batch01/`.

### Step 2: Destroy Cloud Resources
In your workstation PowerShell:
```powershell
cd D:\project-1\infra\terraform\environments\k3s-lab
terraform destroy -auto-approve
```

### Step 3: Verify Zero Lingering Cloud Resources
```powershell
aws ec2 describe-instances --region ap-south-1 `
    --filters "Name=tag:Project,Values=PHANTOM" "Name=instance-state-name,Values=running,pending" `
    --query "Reservations[*].Instances[*].[InstanceId,State.Name]" --output table
```
*Output must be empty, confirming 0 billable resources remain.*

---

## 10. Explicit GO/NO-GO Criteria for Live Pilot Execution

| Gate / Condition | Threshold / Requirement | Status Today | Status Post-Provisioning |
| :--- | :--- | :---: | :---: |
| **G-1: Tooling & Regressions** | 1,146 unit/integration tests passing (0 failures) | ✅ **PASS** | ✅ **PASS** |
| **G-2: Dry-run Verification** | Exactly 18 planned runs; 0 target mutations; 0 writes | ✅ **PASS** | ✅ **PASS** |
| **G-3: Workload Pairing** | `xzutils` $\leftrightarrow$ `update`, `dep-conf` $\leftrightarrow$ `load`, `solarwinds` $\leftrightarrow$ `restart` | ✅ **PASS** | ✅ **PASS** |
| **G-4: Live Cluster Endpoint** | Accessible, responsive, non-cloud domain via tunnel | ❌ **NO-GO** | **Awaiting Provisioning** |
| **G-5: Kernel BTF & eBPF** | `/sys/kernel/btf/vmlinux` present; debugfs mounted | ❌ **NO-GO** | **Awaiting Provisioning** |
| **G-6: PHANTOM Services** | Gateway, Causal Engine, SBOM, Agent active | ❌ **NO-GO** | **Awaiting Provisioning** |
| **G-7: Mock Sinks & NetworkPolicy**| `phantom-sink` (8443, 4445, 4446, 8080) active; egress blocked | ❌ **NO-GO** | **Awaiting Provisioning** |

**Current Status**: **NO-GO (INFRASTRUCTURE NOT YET PROVISIONED)**.  
The plan, manifests, and Terraform files are ready for manual operator deployment.

---

<!-- GOAL_COMPLETE -->
