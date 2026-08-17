# phantom-core

## Purpose

Shared Python library consumed by all PHANTOM Python services. Contains:

- **Pydantic models**: All shared request/response models from the API contracts (Part B)
- **Typed exceptions**: Common exception base classes shared across services
- **Constants**: Central configuration constants (never magic numbers in service code)
- **structlog configuration**: Canonical log setup used by all services

## Design Rules

1. `phantom-core` has **zero service-specific dependencies** — only `pydantic` and `structlog`.
2. Service packages (`phantom-sbom-service`, etc.) depend on `phantom-core`, never the reverse.
3. Adding a new model here requires updating the corresponding JSON Schema in `services/contracts/`.

## Local Development

```bash
cd libs/phantom-core
pip install -e ".[dev]"
pytest tests/ -v
ruff check phantom_core/ tests/
mypy --strict phantom_core/
```

## Package Structure

```
phantom_core/
├── models/          # All shared Pydantic models (API contracts Part B)
│   ├── common.py    # ErrorResponse, HealthResponse, ReadinessResponse
│   ├── sbom.py      # SbomIngestRequest, SbomRecord, SbomDetailResponse, etc.
│   ├── contracts.py # BehavioralContractRegisterRequest, WorkloadSelector, etc.
│   ├── drift.py     # DriftEventIngestRequest, all nested models
│   ├── bdg.py       # BdgNode, BdgEdge, SubgraphQueryRequest, etc.
│   ├── attribution.py # AttributionRequest, AttributionResultResponse, etc.
│   ├── pceps.py     # PcepsScoreRequest, PcepsScoreResponse
│   ├── incidents.py # IncidentCreateRequest, IncidentReport, etc.
│   └── websocket.py # DriftStreamSubscribe, LiveDriftEvent
├── exceptions.py    # Typed exception base classes
├── constants.py     # Central constants (schema version, limits, etc.)
└── logging.py       # structlog configuration factory
```
