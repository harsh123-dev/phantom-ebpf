# PHANTOM Execution Log

**Research Title**: PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes  
**Working Directory**: `D:\project-1`  
**Log Start Date**: 2026-10-25  

---

## Stage 1: Final EC2 Deployment-Readiness Audit
- **Status**: **COMPLETED**
- **Date**: 2026-10-25T15:54:00+05:30
- **Summary**: Comprehensive inspection and offline validation of Terraform configurations, Kubernetes lab manifests, Dockerfiles, service health probes, kernel/eBPF requirements, Prometheus monitoring, and AWS cost assumptions.
- **Commands Executed**:
  - `terraform -chdir=infra\terraform\environments\k3s-lab validate` $\to$ `Success! The configuration is valid.`
  - `.venv-causal\Scripts\pytest services/sbom-service/tests` $\to$ `177 passed in 1.62s`
  - `.venv-causal\Scripts\pytest services/causal-engine/tests` $\to$ `369 passed, 927 warnings in 43.72s`
  - `.venv-causal\Scripts\pytest services/ebpf-agent/tests` $\to$ `155 passed in 0.61s`
  - `.venv-causal\Scripts\pytest services/api-gateway/tests` $\to$ `60 passed in 1.84s`
  - `.venv-causal\Scripts\pytest tests/e2e` $\to$ `389 passed in 150.59s`
  - `.venv-causal\Scripts\pytest research/evaluation/tests` $\to$ `211 passed in 78.63s`
  - Total tests verified passing: **1,361 passed, 0 failures, 0 errors**.
- **Blockers Identified & Resolved**:
  1. *k3s containerd namespace*: Added `-n k8s.io` to `build-images.sh` and `main.tf` userdata so imported images are visible to Kubernetes CRI.
  2. *SBOM Service Readiness Probe*: Fixed probe in `03-phantom-services.yaml` from `/health` (404) to `/readyz` (implemented).
  3. *eBPF Agent Host Port Collision*: Removed `hostNetwork: true` in `04-ebpf-agent.yaml` to prevent health check from binding host port 8080.
  4. *Prometheus Container Name Query Mismatch*: Renamed container to `phantom-agent` in `04-ebpf-agent.yaml` to match `scenario_runner.py`'s query `{container="phantom-agent"}`.
  5. *Prometheus cAdvisor RBAC Permissions*: Added `prometheus-k3s-role` & ClusterRoleBinding to `00-namespace-and-rbac.yaml` to allow node proxy cAdvisor scraping.
- **Files Created / Modified**:
  - `PART7B_EC2_FINAL_READINESS_AUDIT.md` (created)
  - `EC2_MANUAL_PROVISIONING_RUNBOOK.md` (created)
  - `PHANTOM_EXECUTION_LOG.md` (created)
  - `infra/k8s/k3s-lab/build-images.sh` (modified: added `-n k8s.io`)
  - `infra/terraform/environments/k3s-lab/main.tf` (modified: added `-n k8s.io`)
  - `infra/k8s/k3s-lab/03-phantom-services.yaml` (modified: fixed probe path to `/readyz`)
  - `infra/k8s/k3s-lab/04-ebpf-agent.yaml` (modified: container name `phantom-agent`, isolated networking)
  - `infra/k8s/k3s-lab/05-monitoring.yaml` (modified: removed invalid ebpf-agent scrape target)
  - `infra/k8s/k3s-lab/00-namespace-and-rbac.yaml` (modified: added Prometheus RBAC for cAdvisor)
- **Gate Decision**: **PASS**. Infrastructure is fully prepared. Proceeding to Stage 2 requires human operator manual execution of `terraform apply`.

---

## Stage 2: Manual EC2 Provisioning
- **Status**: **AWAITING OPERATOR CONFIRMATION**
- **Action Required**: Human operator to review [EC2_MANUAL_PROVISIONING_RUNBOOK.md](file:///d:/project-1/EC2_MANUAL_PROVISIONING_RUNBOOK.md) and execute `terraform apply` in `infra/terraform/environments/k3s-lab`.
