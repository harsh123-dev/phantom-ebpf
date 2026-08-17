# PHANTOM — report-generator

## Purpose

Assembles immutable forensic evidence from drift events, causal attributions,
and PCEPS scores into structured incident reports, renders them as Markdown +
JSON evidence bundles, and persists them to S3-compatible object storage.

This service is **not internet-facing**. It communicates via Redis Streams
and internal HTTP only.

## Clean Architecture Layers

| Layer | Path | Rule |
|---|---|---|
| Domain | `app/domain/` | IncidentReport, EvidenceReference, immutability rules; no framework imports |
| Application | `app/application/` | CRUD and generation use cases using domain ports only |
| Infrastructure | `app/infrastructure/` | asyncpg, object store, renderer adapter |
| Interface | `app/interface/` | Worker consumer loop, health probe routes |

## Immutability Rule

Forensic evidence IDs (`drift_event_ids`, `attribution_ids`, `score_ids`, `snapshot_id`)
are **never mutated** after report creation. Only analyst-controlled fields may be revised
(title, summary, classification, status, tags, resolution_notes), and each revision
increments the revision counter.

## Local Development

### Prerequisites

- Python 3.11+
- Docker (for PostgreSQL, Redis, and MinIO)

### Setup

```bash
# From repo root — start infrastructure
make docker-up

# Install in editable mode
cd services/report-generator
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
| `REPORT_GENERATOR_DB_URL` | asyncpg DSN for PostgreSQL |
| `REPORT_GENERATOR_REDIS_URL` | Redis URL for task stream |
| `REPORT_GENERATOR_STREAM_NAME` | Redis stream name for report tasks |
| `REPORT_GENERATOR_S3_BUCKET` | S3 bucket for rendered report storage |
| `REPORT_GENERATOR_S3_ENDPOINT_URL` | S3 endpoint (empty = AWS; set for local MinIO) |
