"""
api-gateway drift-event ingestion router.

Implements:
  POST /api/v1/drift-events  (transactional outbox + idempotency)
"""

from __future__ import annotations

from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends

from app.application.commands import IngestDriftEventCommand
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.interface.dependencies import require_role

from datetime import datetime

router = fastapi.APIRouter(tags=["Drift Events"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


@router.get("/drift-events", status_code=200)
async def list_drift_events(
    request: fastapi.Request,
    since: datetime,
    limit: int = 200,
) -> dict[str, Any]:
    from app.infrastructure.postgres_repository import DriftEventRepository
    pool = request.app.state.db_pool
    repo = DriftEventRepository(pool)
    events = await repo.list_events(since, limit)
    return {"items": events}

@router.post(
    "/drift-events",
    status_code=202,
    summary="Ingest a runtime drift event",
    description=(
        "Accepts a single RuntimeDriftEvent from an eBPF agent. "
        "Implements the transactional outbox pattern for durable ingestion "
        "and BDG mutation queue publication. Idempotent on event_id."
    ),
)
async def ingest_drift_event(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.AGENT, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/drift-events — transactional outbox ingestion.

    Args:
        request: FastAPI request (for app.state access).
        body: DriftEventIngestRequest payload.
        principal: Verified JWT principal with phantom.agent role.

    Returns:
        DriftEventRecord dict with drift_event_id, bdg_update_id, ingestion_status.
    """
    # Validate tenant_id in body matches principal.
    from phantom_core.models.drift import DriftEventIngestRequest
    validated = DriftEventIngestRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        from app.domain.exceptions import TenantMismatchError
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    pool = request.app.state.db_pool
    redis = request.app.state.redis

    command = IngestDriftEventCommand(pool, redis)
    result = await command.execute(validated.model_dump(), principal.tenant_id)

    log.info(
        "drift_router.ingested",
        drift_event_id=str(result.get("drift_event_id")),
        ingestion_status=result.get("ingestion_status"),
    )
    return result
