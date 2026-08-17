# PHANTOM

**Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes**

## Overview

PHANTOM is a research-grade Kubernetes security platform that instruments workloads via eBPF,
correlates runtime observations against signed Software Bills of Materials (SBOMs) and
behavioral contracts, constructs a Behavioral Dependency Graph (BDG), and applies causal
inference to attribute runtime drift to specific software components.

## Repository Structure

```
phantom/
├── services/         # Independently deployable PHANTOM microservices
│   ├── sbom-service/       # SBOM ingestion, CycloneDX validation, cosign verification
│   ├── ebpf-agent/         # Privileged eBPF node collector and event transport
│   ├── causal-engine/      # BDG maintenance, SCM, DoWhy causal inference, PCEPS scoring
│   ├── api-gateway/        # Public REST/WebSocket API and authorization boundary
│   ├── report-generator/   # Incident evidence assembly and report rendering
│   └── contracts/          # Versioned JSON Schema API and event artifacts
├── frontend/         # React + TypeScript analyst application
├── infra/            # Terraform, Helm, and raw Kubernetes manifests
├── research/         # Reproducible experiment drivers and evaluation notebooks
└── docs/             # Immutable Codex task handoffs and design records
```

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Node.js 20+ (frontend)
- Linux kernel ≥ 5.8 with BTF/CO-RE (eBPF agent)
- `make` (GNU Make)

## Quick Start

```bash
# 1. Copy environment template and fill in secrets
cp .env.example .env

# 2. Start local infrastructure (PostgreSQL, Redis, Prometheus, Grafana)
make docker-up

# 3. Install all Python service dependencies
make install

# 4. Run all linters and type checks
make lint typecheck

# 5. Run all tests
make test
```



## License

See `LICENSE`.
