# PHANTOM Stage 4 Remaining Blockers

1. The expected checkout `/home/ubuntu/phantom` is absent; current repository is `/root/phantom-ebpf`.
2. Docker, k3s, kubectl, Python 3.11, pip, pytest, httpx, and project test dependencies are unavailable.
3. No cluster context or disposable-lab endpoint can be confirmed; deployment approval cannot yet be attached to a concrete change set and target.
4. Prometheus causal-engine scrape port does not match the exporter (9090 vs 8080), and the requested event-lag metric was not found in agent source. Overhead evidence is not ready.
5. Falco log collection is configured in the scenario runner, but Falco is not included in the k3s lab manifests.
6. Embedded development credentials, auth bypass, and wildcard CORS require isolated ClusterIP-only lab handling and review before deployment.
7. The supported dry-run command cannot import because `httpx` is missing. No pilot has run.
