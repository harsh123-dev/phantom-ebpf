#!/usr/bin/env bash
# infra/k8s/k3s-lab/deploy-all.sh
# Deploys the complete self-contained PHANTOM evaluation lab on k3s.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

echo "=== [1/5] Applying Namespaces and RBAC ==="
kubectl apply -f "${SCRIPT_DIR}/00-namespace-and-rbac.yaml"

echo "=== [2/5] Applying Backing Services (PostgreSQL & Redis) ==="
kubectl apply -f "${SCRIPT_DIR}/01-in-cluster-backing-services.yaml"
kubectl apply -f "${SCRIPT_DIR}/02-phantom-configmaps-secrets.yaml"

echo "Waiting for PostgreSQL & Redis readiness..."
kubectl rollout status deployment/phantom-postgres -n phantom --timeout=60s
kubectl rollout status deployment/phantom-redis -n phantom --timeout=60s

echo "=== [3/5] Applying Target Workloads & Sinks ==="
kubectl apply -f "${REPO_ROOT}/research/evaluation/k8s/target-workloads.yaml"
kubectl apply -f "${SCRIPT_DIR}/06-network-policies.yaml"

echo "Waiting for target workloads & phantom-sink..."
kubectl rollout status deployment/phantom-sink -n phantom-eval --timeout=60s
kubectl rollout status deployment/recommendationservice -n phantom-eval --timeout=60s
kubectl rollout status deployment/emailservice -n phantom-eval --timeout=60s
kubectl rollout status deployment/cartservice -n phantom-eval --timeout=60s

echo "=== [4/5] Applying PHANTOM Services & eBPF DaemonSet ==="
kubectl apply -f "${SCRIPT_DIR}/03-phantom-services.yaml"
kubectl apply -f "${SCRIPT_DIR}/04-ebpf-agent.yaml"

echo "Waiting for PHANTOM core services..."
kubectl rollout status deployment/phantom-api-gateway -n phantom --timeout=60s
kubectl rollout status deployment/phantom-causal-engine -n phantom --timeout=60s
kubectl rollout status deployment/phantom-sbom-service -n phantom --timeout=60s
kubectl rollout status daemonset/phantom-ebpf-agent -n phantom --timeout=60s

echo "=== [5/5] Applying Monitoring Stack (Prometheus) ==="
kubectl apply -f "${SCRIPT_DIR}/05-monitoring.yaml"
kubectl rollout status deployment/prometheus -n monitoring --timeout=60s

echo ""
echo "=========================================================================="
echo "PHANTOM k3s Lab Deployment Complete!"
echo "=========================================================================="
kubectl get pods -A -l 'app in (phantom-api-gateway,phantom-causal-engine,phantom-sbom-service,phantom-ebpf-agent,recommendationservice,emailservice,cartservice,phantom-sink,prometheus)'
