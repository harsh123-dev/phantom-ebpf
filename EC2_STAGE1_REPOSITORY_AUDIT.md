# PHANTOM Stage 1: Repository Audit

**Observed:** 2026-10-25  
**Repository:** `/root/phantom-ebpf`, branch `main`, initial baseline `4798396` (clean).

This is a static audit of the current checkout. Prior readiness documents contain historical claims and are not evidence of the current host or a running deployment.

## Findings

| Severity | Component / evidence | Finding and recommendation |
|---|---|---|
| **Blocker** | Environment; `EC2_STAGE0_ENVIRONMENT_REPORT.md` | Requested `/home/ubuntu/phantom` is absent; current checkout is `/root/phantom-ebpf`. Docker, kubectl, and k3s are absent. Do not deploy until the operator confirms this is the intended lab and the cluster is installed and positively identified. |
| **High** | `research/evaluation/scenarios/scenario_runner.py`, `MetricsSnapshot` and `collect_metrics_snapshot` | Missing Prometheus results and query failures were serialized as `0.0`, and dry-run snapshots also used zero. This could turn unavailable telemetry into a false zero-overhead result. Changed this code to represent unavailable/dry-run measurements as `None`; see Stage 2 changelog. |
| **High** | `infra/k8s/k3s-lab/05-monitoring.yaml`; `services/causal-engine/app/interface/worker.py`; `research/evaluation/scenarios/scenario_runner.py` | The causal engine starts its Prometheus exporter on port 9090, but the Service exposes port 8080 and the Prometheus scrape target uses `:8080`; no metrics endpoint is configured for that app target. The scenario runner asks for `phantom_event_collection_latency_seconds`, which was not found in the agent source. Reconcile exporter ports/metrics and verify real, fresh samples before collecting overhead results. |
| **High** | `research/evaluation/experiment_config.yaml` vs `research/evaluation/scenarios/run_all_scenarios.py` | The config lists only two attack scenarios and sets `dry_run: false`; the runner hard-codes a three-attack pilot plus three controls, and does not expose a `--config` argument. Use the runner's `--campaign pilot` profile for the 18 planned runs only after verifying its live interface; update or retire the misleading config through a separately reviewed change. |
| **High** | `infra/k8s/k3s-lab/02-phantom-configmaps-secrets.yaml`, `03-phantom-services.yaml` | The lab manifests embed development passwords and agent/JWT bypass tokens; API gateway sets `AUTH_BYPASS_ENABLED=true`, a bypass token, and wildcard CORS. They are unsuitable for any exposure beyond the isolated disposable lab. Keep ClusterIP-only and review these settings before any deployment. |
| **High** | `infra/k8s/k3s-lab/04-ebpf-agent.yaml`, `services/ebpf-agent/Dockerfile`, `services/ebpf-agent/application/main.py` | Agent requires privileged execution, host PID, `/proc`, cgroup and debugfs mounts. The current host BTF exists, but no pod/runtime verification is possible. The Dockerfile comment says `hostNetwork` is required while the manifest deliberately disables it; validate runtime functionality rather than relying on either comment. The agent's Python health endpoint is not proof of kernel event capture. |
| **Medium** | `infra/k8s/k3s-lab/05-monitoring.yaml` | Prometheus uses `emptyDir` storage with 24-hour retention. This is ephemeral; export experiment evidence outside the pod immediately and ensure Prometheus is ready before a run. |
| **Medium** | `research/evaluation/k8s/target-workloads.yaml`, `infra/k8s/k3s-lab/deploy-all.sh` | Sink and target workloads use mutable public tags (`python:3.11-slim`, `tiangolo/uwsgi-nginx-flask:python3.11`) with default pull behavior. Pin digests or record image IDs in the pilot metadata and verify the egress policy is enforced by the installed CNI. |
| **Medium** | `research/evaluation/scenarios/scenario_runner.py` | Scenario runner reads Falco log at `/var/log/falco/events.jsonl`; the k3s deployment set does not deploy Falco or configure that host log. Falco evidence will be absent unless independently provisioned and verified. Missing Falco evidence must remain unknown. |
| **Medium** | Dockerfiles and `infra/k8s/k3s-lab/build-images.sh` | Build contexts are repository root for API, causal, and SBOM images and `services/ebpf-agent` for the agent. Script imports PHANTOM images into containerd namespace `k8s.io`; manifests use matching `phantom/*:latest` and `IfNotPresent`. The pipeline also assumes Docker and k3s exist, which they do not here. Builds were not attempted. |
| **Low** | `infra/k8s/k3s-lab/03-phantom-services.yaml`, `05-monitoring.yaml` | PHANTOM and Prometheus Services are `ClusterIP`; no public service type is present in these files. This static check does not establish cluster ingress, host firewall, or cloud security-group state. |
| **Unknown** | Service/database/runtime integration | PostgreSQL and Redis are configured as in-cluster deployments with fixed lab credentials. No cluster exists here to validate endpoints, probes, migrations, readiness, or application health. |
| **Unknown** | Historical evidence | Existing `research/datasets/raw` and `raw3` directories were preserved. `research/datasets/pilot_batch01` did not exist at inspection. No historical result was treated as current-host evidence. |

## Dependency and test environment

Project metadata exists in service `pyproject.toml` files and `requirements-causal-runtime.txt`; no Python environment, `pip`, `pytest`, `build`, or `uv` is installed in this host. A repository-wide test suite could not start. No dependencies or system packages were installed. `gh auth status` indicated no GitHub CLI authentication; no credential values were read.

## Previous audit reconciliation

`PART7B_EC2_FINAL_READINESS_AUDIT.md` reports a completed prior audit and 1,361 passing tests, but its paths and Windows commands refer to another environment. Those results are historical claims only. Current checks show no Docker/k3s/kubectl and no Python test dependencies. The current tree does contain `infra/k8s/k3s-lab/build-images.sh` with `-n k8s.io`, the SBOM `/readyz` probe, an isolated eBPF pod network, the Prometheus RBAC, and the `phantom-agent` container name described in that audit.
