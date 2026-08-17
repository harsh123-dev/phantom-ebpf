"""
api-gateway causal attribution endpoints router.

Implements:
  POST   /api/v1/attributions
  GET    /api/v1/attributions/{attribution_id}
  POST   /api/v1/pceps:scores
  GET    /api/v1/pceps:scores/{score_id}
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends

from app.application.commands import SubmitAttributionCommand, SubmitPCEPSCommand
from app.application.queries import GetAttributionQuery, GetPCEPSScoreQuery
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import TenantMismatchError
from app.infrastructure.service_clients import CausalEngineClient
from app.interface.dependencies import require_role

router = fastapi.APIRouter(tags=["Attributions"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


@router.post(
    "/attributions",
    status_code=202,
    summary="Submit a causal attribution job",
)
async def submit_attribution(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/attributions — submit a causal attribution job.

    Args:
        request: FastAPI request (for app.state access).
        body: AttributionRequest payload.
        principal: Verified JWT principal with phantom.analyst role.

    Returns:
        AttributionJobResponse dict.
    """
    from phantom_core.models.attribution import AttributionRequest
    validated = AttributionRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    pool = request.app.state.db_pool
    redis = request.app.state.redis

    async with CausalEngineClient() as causal:
        cmd = SubmitAttributionCommand(pool, redis, causal)
        result = await cmd.execute(validated.model_dump(), principal.tenant_id)

    log.info(
        "attribution_router.submitted",
        attribution_id=str(result.get("attribution_id")),
    )
    return result


@router.get(
    "/attributions/{attribution_id}",
    summary="Poll attribution job status",
)
async def get_attribution(
    attribution_id: uuid.UUID,
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.VIEWER, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/attributions/{attribution_id} — poll attribution status.

    Args:
        attribution_id: UUID of the attribution job.
        request: FastAPI request.
        principal: Verified JWT principal.

    Returns:
        AttributionResultResponse dict.
    """
    pool = request.app.state.db_pool
    query = GetAttributionQuery(pool)
    return await query.execute(attribution_id, principal.tenant_id)


@router.post(
    "/pceps:scores",
    status_code=202,
    summary="Submit a PCEPS scoring request",
)
async def submit_pceps_score(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/pceps:scores — request PCEPS priority scoring.

    Args:
        request: FastAPI request.
        body: PcepsScoreRequest payload.
        principal: Verified JWT principal with phantom.analyst role.

    Returns:
        PcepsScoreResponse dict.
    """
    from phantom_core.models.attribution import PcepsScoreRequest
    validated = PcepsScoreRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    pool = request.app.state.db_pool

    async with CausalEngineClient() as causal:
        cmd = SubmitPCEPSCommand(causal, pool)
        return await cmd.execute(validated.model_dump(), principal.tenant_id)


@router.get(
    "/pceps:scores/{score_id}",
    summary="Get a PCEPS score",
)
async def get_pceps_score(
    score_id: uuid.UUID,
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.ANALYST, PhantomRole.VIEWER, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/pceps:scores/{score_id} — fetch a PCEPS score.

    Args:
        score_id: UUID of the score.
        request: FastAPI request.
        principal: Verified JWT principal.

    Returns:
        PcepsScoreResponse dict.
    """
    pool = request.app.state.db_pool
    query = GetPCEPSScoreQuery(pool)
    return await query.execute(score_id, principal.tenant_id)
