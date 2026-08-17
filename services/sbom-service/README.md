# PHANTOM — sbom-service

## Purpose

Ingests CycloneDX JSON SBOMs associated with immutable container image digests,
validates their structure, orchestrates cosign/Sigstore signature verification,
and exposes an internal REST API consumed exclusively by the `api-gateway`.

This service is **not internet-facing**. All public traffic is routed through
`services/api-gateway`.

## Clean Architecture Layers

| Layer | Path | Rule |
|---|---|---|
| Domain | `app/domain/` | No framework imports; pure Python + stdlib |
| Application | `app/application/` | Imports domain ports only |
| Infrastructure | `app/infrastructure/` | asyncpg, S3, cosign CLI, object store |
| Interface | `app/interface/` | FastAPI routers, Pydantic DTOs, DI |

## Local Development

### Prerequisites

- Python 3.11+
- Docker (for PostgreSQL and S3-compatible object store)
- `cosign` CLI on `PATH`

### Setup

```bash
# From repo root — start infrastructure
make docker-up

# Install in editable mode
cd services/sbom-service
pip install -e ".[dev]" -e "../../libs/phantom-core"

# Copy and populate environment
cp ../../.env.example ../../.env
# Edit .env with local values

# Run service locally
uvicorn app.main:app --reload --port 8000
```

### Run Tests

```bash
pytest tests/ -v
```

### Lint and Type-check

```bash
ruff check app/ tests/
mypy --strict app/
```

## Environment Variables

See `.env.example` at the repo root for the full list of required variables.
Key variables for this service:

| Variable | Description |
|---|---|
| `SBOM_SERVICE_DB_URL` | asyncpg DSN for PostgreSQL |
| `SBOM_SERVICE_S3_BUCKET` | S3 bucket for SBOM artifact storage |
| `SBOM_SERVICE_S3_ENDPOINT_URL` | S3 endpoint (empty = AWS; set for local MinIO) |
| `COSIGN_PATH` | Absolute path to cosign binary (default: `cosign`) |

## API

Internal endpoints (not publicly routable):

| Method | Path | Description |
|---|---|---|
| `POST` | `/sboms` | Ingest CycloneDX SBOM |
| `GET` | `/sboms/{sbom_id}` | Retrieve SBOM metadata and document |
| `POST` | `/sboms/{sbom_id}/verification` | Enqueue cosign verification |
| `GET` | `/sboms/{sbom_id}/verification` | Get verification status |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |
