# PHANTOM Stage 3: Deployment Verification

**Status:** **NOT DEPLOYED — environment and deployment gate not satisfied.** No Kubernetes mutation was performed.

The requested repository path is absent, and the located host has no kubectl or k3s. Its cluster context, endpoint, namespace state, node, and disposable-lab identity are **UNKNOWN**. As required, manifests were not applied to any context.

| Check | Command/evidence | Status | Remediation |
|---|---|---|---|
| k3s running | `command -v k3s`; `systemctl is-active k3s` → command absent / `inactive` | FAIL | Operator must establish the intended lab host and k3s installation. |
| Cluster context/endpoint | `kubectl config current-context` cannot run; kubectl absent | UNKNOWN | Positively identify designated disposable cluster and endpoint before approval/apply. |
| Node Ready, kernel/architecture | Host reports x86_64 and kernel `6.5.0-1020-aws`; no cluster node available | UNKNOWN | Verify node with read-only `kubectl get nodes -o wide` after cluster setup. |
| Namespaces/service accounts | No API server access | UNKNOWN | Verify target namespaces/RBAC from the designated context. |
| Images/build/import | Docker and k3s absent; no images built/imported | FAIL | Build from documented contexts, import into `k8s.io`, compare tags and image refs. |
| PHANTOM app pods, services, probes, health | No cluster | UNKNOWN | Deploy only after reviewing and approving intended manifest changes; verify source-defined endpoints. |
| eBPF agent/kernel event telemetry | Host BTF readable and required config options set; no k3s runtime/pod | UNKNOWN | Verify BTF mount, privileges, attach/load status, and correlated harmless event through API. A healthy endpoint alone is insufficient. |
| Prometheus and current metrics | No cluster; static audit found causal exporter on 9090 but scrape/service on 8080 and no source for requested event-lag metric | FAIL (static configuration) | Reconcile scrape ports and metric instrumentation; prove fresh samples before measurements. |
| Sink and isolation | Static manifests put sink and workloads in `phantom-eval`, with a same-namespace selector policy. Runtime CNI enforcement unverified. | UNKNOWN | Verify policy enforcement and internal sink connectivity after approved deployment. |
| Independent ground truth | Runner has separate injection/behavior fields, but none can be exercised here. Falco log source is not deployed by the lab manifests. | UNKNOWN | Verify independent injection and behavior evidence sources and capture paths before pilot. |

No deployment change is proposed for immediate application: the target cluster cannot be identified from this host. Any later apply requires review of the exact target context and changes first.
