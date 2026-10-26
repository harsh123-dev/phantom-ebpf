#!/usr/bin/env bash
# infra/k8s/k3s-lab/build-images.sh
# Builds PHANTOM core service images on the Ubuntu EC2 node and imports them into k3s containerd.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cd "${REPO_ROOT}"

echo "=== [1/4] Building API Gateway ==="
docker build -f services/api-gateway/Dockerfile -t phantom/api-gateway:latest .
docker save phantom/api-gateway:latest | k3s ctr -n k8s.io images import -

echo "=== [2/4] Building Causal Engine ==="
docker build -f services/causal-engine/Dockerfile -t phantom/causal-engine:latest .
docker save phantom/causal-engine:latest | k3s ctr -n k8s.io images import -

echo "=== [3/4] Building SBOM Service ==="
docker build -f services/sbom-service/Dockerfile -t phantom/sbom-service:latest .
docker save phantom/sbom-service:latest | k3s ctr -n k8s.io images import -

echo "=== [4/5] Building eBPF Agent ==="
docker build -f services/ebpf-agent/Dockerfile -t phantom/ebpf-agent:latest services/ebpf-agent
docker save phantom/ebpf-agent:latest | k3s ctr -n k8s.io images import -

echo "=== [5/5] Building Persistent Evidence Sink ==="
docker build -f research/evaluation/Dockerfile.evidence-sink -t phantom/evidence-sink:latest .
docker save phantom/evidence-sink:latest | k3s ctr -n k8s.io images import -

echo ""
echo "=== All PHANTOM service images built and imported into k3s containerd (k8s.io namespace)! ==="
k3s ctr -n k8s.io images list | grep phantom/
