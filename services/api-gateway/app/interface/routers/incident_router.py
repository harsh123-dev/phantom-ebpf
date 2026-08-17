"""
api-gateway incident report endpoints router.

Implements:
  POST    /api/v1/incidents
  GET     /api/v1/incidents/{incident_id}
  GET     /api/v1/incidents
  PATCH   /api/v1/incidents/{incident_id}
  DELETE  /api/v1/incidents/{incident_id}  (soft archive)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends, Query

from app.application.commands import (
    ArchiveIncidentCommand,
    CreateIncidentCommand,
    UpdateIncidentCommand,
)
from app.application.queries import GetIncidentQuery, ListIncidentsQuery
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import TenantMismatchError
from app.interface.dependencies import require_role

router = fastapi.APIRouter(tags=["Incidents"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


@router.post(
    "/incidents",
    status_code=201,
    summary="Create an incident report",
)
async def create_incident(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/incidents — create a draft incident report.

    Args:
        request: FastAPI request (for app.state).
        body: IncidentCreateRequest payload.
        principal: Verified JWT principal with phantom.analyst role.

    Returns:
        IncidentReport dict.
    """
    from phantom_core.models.incidents import IncidentCreateRequest
    validated = IncidentCreateRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    pool = request.app.state.db_pool
    cmd = CreateIncidentCommand(pool)
    result = await cmd.execute(
        validated.model_dump(), principal.user_id, principal.tenant_id
    )
    log.info(
        "incident_router.created",
        incident_id=str(result.get("incident_id")),
    )
    return result


@router.get(
    "/incidents/{incident_id}",
    summary="Get incident detail",
)
async def get_incident(
    incident_id: uuid.UUID,
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/incidents/{incident_id} — fetch full incident detail.

    Args:
        incident_id: UUID of the incident.
        request: FastAPI request.
        principal: Verified JWT principal.

    Returns:
        IncidentDetailResponse-compatible dict.
    """
    pool = request.app.state.db_pool
    query = GetIncidentQuery(pool)
    return await query.execute(incident_id, principal.tenant_id)


@router.get(
    "/incidents",
    summary="List incidents",
)
async def list_incidents(
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
    status: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    created_after: datetime | None = Query(default=None),
    created_before: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> dict[str, Any]:
    """GET /api/v1/incidents — paginated incident list with optional filters.

    Args:
        request: FastAPI request.
        principal: Verified JWT principal.
        status: Optional lifecycle status filter.
        classification: Optional classification filter.
        created_after: Optional lower bound on created_at.
        created_before: Optional upper bound on created_at.
        limit: Maximum items to return.
        cursor: Opaque pagination cursor.

    Returns:
        IncidentListResponse-compatible dict.
    """
    pool = request.app.state.db_pool
    query = ListIncidentsQuery(pool)
    items, next_cursor = await query.execute(
        principal.tenant_id,
        status=status,
        classification=classification,
        created_after=created_after,
        created_before=created_before,
        limit=limit,
        cursor=cursor,
    )
    return {"items": items, "next_cursor": next_cursor}


@router.patch(
    "/incidents/{incident_id}",
    summary="Update an incident report",
)
async def update_incident(
    incident_id: uuid.UUID,
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """PATCH /api/v1/incidents/{incident_id} — apply analyst revision.

    Args:
        incident_id: UUID of the incident.
        request: FastAPI request.
        body: IncidentUpdateRequest payload.
        principal: Verified JWT principal with phantom.analyst role.

    Returns:
        Updated IncidentReport dict.
    """
    from phantom_core.models.incidents import IncidentUpdateRequest
    validated = IncidentUpdateRequest.model_validate(body)

    pool = request.app.state.db_pool
    cmd = UpdateIncidentCommand(pool)
    return await cmd.execute(incident_id, principal.tenant_id, validated.model_dump())


@router.delete(
    "/incidents/{incident_id}",
    summary="Archive an incident report",
)
async def archive_incident(
    incident_id: uuid.UUID,
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """DELETE /api/v1/incidents/{incident_id} — soft-archive the incident.

    Forensic evidence is never deleted. Status is changed to 'archived'.

    Args:
        incident_id: UUID of the incident.
        request: FastAPI request.
        principal: Verified JWT principal with phantom.analyst role.

    Returns:
        IncidentArchiveResponse dict.
    """
    pool = request.app.state.db_pool
    cmd = ArchiveIncidentCommand(pool)
    result = await cmd.execute(incident_id, principal.tenant_id)
    log.info(
        "incident_router.archived",
        incident_id=str(incident_id),
    )
    return result
