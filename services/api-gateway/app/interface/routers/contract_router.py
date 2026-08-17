"""
api-gateway behavioral contract endpoints router.

Implements:
  POST   /api/v1/contracts
  GET    /api/v1/contracts/{contract_id}
  GET    /api/v1/contracts
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends, Query

from app.application.queries import ListContractsQuery
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import TenantMismatchError
from app.infrastructure.service_clients import SbomServiceClient
from app.interface.dependencies import require_role

router = fastapi.APIRouter(tags=["Contracts"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


@router.post(
    "/contracts",
    status_code=201,
    summary="Register a behavioral contract",
)
async def register_contract(
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.SBOM_WRITER, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/contracts — register a signed behavioral contract.

    Args:
        body: BehavioralContractRegisterRequest payload.
        principal: Verified JWT principal with phantom.sbom_writer role.

    Returns:
        BehavioralContractRecord dict.
    """
    from phantom_core.models.contracts import BehavioralContractRegisterRequest
    validated = BehavioralContractRegisterRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    async with SbomServiceClient() as client:
        return await client.register_contract(
            {k: str(v) if isinstance(v, uuid.UUID) else v
             for k, v in validated.model_dump().items()}
        )


@router.get(
    "/contracts/{contract_id}",
    summary="Get behavioral contract detail",
)
async def get_contract(
    contract_id: uuid.UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(
            PhantomRole.VIEWER, PhantomRole.ANALYST,
            PhantomRole.SBOM_WRITER, PhantomRole.ADMIN,
        )),
    ],
) -> dict[str, Any]:
    """GET /api/v1/contracts/{contract_id} — fetch contract detail.

    Args:
        contract_id: UUID of the contract.
        principal: Verified JWT principal.

    Returns:
        BehavioralContractDetailResponse dict.
    """
    async with SbomServiceClient() as client:
        return await client.get_contract(contract_id, principal.tenant_id)


@router.get(
    "/contracts",
    summary="List behavioral contracts",
)
async def list_contracts(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(
            PhantomRole.VIEWER, PhantomRole.ANALYST,
            PhantomRole.SBOM_WRITER, PhantomRole.ADMIN,
        )),
    ],
    image_digest: str | None = Query(default=None),
    namespace: str | None = Query(default=None),
    activation_status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> dict[str, Any]:
    """GET /api/v1/contracts — list contracts by filter.

    Args:
        principal: Verified JWT principal.
        image_digest: Optional image digest filter.
        namespace: Optional namespace filter.
        activation_status: Optional activation status filter.
        limit: Maximum items to return.
        cursor: Opaque pagination cursor.

    Returns:
        ContractListResponse dict.
    """
    params: dict[str, Any] = {"tenant_id": str(principal.tenant_id), "limit": limit}
    if image_digest:
        params["image_digest"] = image_digest
    if namespace:
        params["namespace"] = namespace
    if activation_status:
        params["activation_status"] = activation_status
    if cursor:
        params["cursor"] = cursor

    async with SbomServiceClient() as client:
        query = ListContractsQuery(client)
        return await query.execute(params)
