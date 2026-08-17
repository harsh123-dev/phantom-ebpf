# PHANTOM — causal-engine

## Purpose

Maintains the versioned Behavioral Dependency Graph (BDG), constructs
Structural Causal Models (SCMs), runs DoWhy causal inference to produce
attribution records, and scores completed attributions with an XGBoost
PCEPS priority model.

> **Important**: XGBoost is used for priority **ranking** only.
> It is not evidence of causation. Causal and predictive results are
> reported and evaluated separately.

This service is **not internet-facing**. It communicates via Redis Streams
and internal HTTP only.

## Clean Architecture Layers

| Layer | Path | Rule |
|---|---|---|
| Domain | `app/domain/` | BDG, SCM, attribution, PCEPS entities; no framework imports |
| Application | `app/application/` | Graph-update, SCM build, attribution, scoring use cases |
| Infrastructure | `app/infrastructure/` | asyncpg, Redis Streams, NetworkX, DoWhy, XGBoost |
| Interface | `app/interface/` | Worker consumer loop, health probe routes |

## Local Development

### Prerequisites

- Python 3.11+
- Docker (for PostgreSQL and Redis)

### Setup

```bash
# From repo root — start infrastructure
make docker-up

# Install in editable mode
cd services/causal-engine
pip install -e ".[dev]" -e "../../libs/phantom-core"

# Copy and populate environment
cp ../../.env.example ../../.env

# Run worker locally
python -m app.interface.worker
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
| `CAUSAL_ENGINE_DB_URL` | asyncpg DSN for PostgreSQL |
| `CAUSAL_ENGINE_REDIS_URL` | Redis URL for stream consumption |
| `CAUSAL_ENGINE_STREAM_NAME` | Redis stream name for drift events |
| `CAUSAL_ENGINE_CONSUMER_GROUP` | Redis consumer group name |
| `PCEPS_MODEL_PATH` | Filesystem path to serialized XGBoost model |
