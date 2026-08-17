# PHANTOM — api-gateway

## Purpose

The **only internet-facing** PHANTOM service. Provides:

- All public REST endpoints under `/api/v1`
- WebSocket drift-event stream at `GET /api/v1/streams/drift`
- `/healthz` and `/readyz` probes
- JWT/JWKS-based authorization enforcing five gateway roles
- Transactional outbox for durable drift event acceptance before Redis publication
- Routing and forwarding to internal services (sbom-service, causal-engine, report-generator)

## Clean Architecture Layers

| Layer | Path | Rule |
|---|---|---|
| Domain | `app/domain/` | Roles, tenant scope, error taxonomy; no framework imports |
| Application | `app/application/` | Command/query use cases using domain ports only |
| Infrastructure | `app/infrastructure/` | asyncpg outbox, aioredis, JWKS auth, httpx service clients |
| Interface | `app/interface/` | FastAPI routers (per resource), WebSocket endpoint, DI |

## Local Development

### Prerequisites

- Python 3.11+
- Docker (for PostgreSQL and Redis)

### Setup

```bash
# From repo root — start infrastructure
make docker-up

# Install in editable mode
cd services/api-gateway
pip install -e ".[dev]" -e "../../libs/phantom-core"

# Copy and populate environment
cp ../../.env.example ../../.env

# Run gateway locally
uvicorn app.main:app --reload --port 8080
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

| Variable | Description |
|---|---|
| `API_GATEWAY_DB_URL` | asyncpg DSN for PostgreSQL (transactional outbox) |
| `API_GATEWAY_REDIS_URL` | Redis URL for stream publication and WS fan-out |
| `API_GATEWAY_JWKS_URI` | JWKS endpoint for JWT validation |
| `API_GATEWAY_JWT_AUDIENCE` | Expected JWT audience claim |
| `SBOM_SERVICE_BASE_URL` | Internal URL for sbom-service |
| `CAUSAL_ENGINE_BASE_URL` | Internal URL for causal-engine |
| `REPORT_GENERATOR_BASE_URL` | Internal URL for report-generator |

## Public API

Base path: `/api/v1`. See `services/contracts/http/` for canonical JSON Schemas.
