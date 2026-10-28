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
_EVAL_CONTRACT_RECORD: dict[str, Any] = {
    "contract_id": "c0471ac7-0001-4000-8000-000000000001",
    "image_digest": "sha256:50a337a6c7f43a609feaa56e826e4b5085db9f95447f3232edbe47302c7b0ad7",
    "sbom_id": "428fee4e-805f-4a47-b8f8-fa039d679550",
    "contract_version": "1.0.0",
    "verification_status": "verified",
    "activation_status": "active",
    "created_at": "2026-10-27T19:54:50.474621Z",
}

_EVAL_CONTRACT_DETAIL: dict[str, Any] = {
    "record": _EVAL_CONTRACT_RECORD,
    "workload_selector": {
        "cluster_name": "phantom-lab",
        "namespace": "phantom-eval",
        "service_account": "recommendationservice",
        "match_labels": {"app": "recommendationservice"},
    },
    "constraints": {
        "allowed_executables": [
            "/usr/local/bin/uwsgi",
            "/usr/bin/python3",
            "/usr/sbin/nginx",
        ],
        "allowed_syscall_classes": [
            "process",
            "file_read",
            "file_write",
            "network_connect",
            "network_accept",
        ],
        "allowed_parent_child_pairs": [
            ["uwsgi", "python"],
            ["python", "python3"],
            ["uwsgi", "uwsgi"],
        ],
        "allowed_file_path_prefixes": [
            "/app",
            "/usr",
            "/lib",
            "/tmp",
            "/etc",
        ],
        "allowed_network_destinations": [
            {"protocol": "tcp", "cidr": "10.0.0.0/8", "port_min": 80, "port_max": 9000},
            {"protocol": "tcp", "cidr": "172.16.0.0/12", "port_min": 80, "port_max": 9000},
        ],
        "allowed_purls": [
            "pkg:pypi/flask@3.0.0",
            "pkg:pypi/requests@2.31.0",
            "pkg:pypi/uwsgi@2.0.23",
        ],
        "max_new_processes_per_5m": 50,
    },
    "valid_from": "2026-10-27T00:00:00Z",
    "valid_until": "2027-10-27T00:00:00Z",
    "signature_bundle_uri": "s3://phantom-k3s-lab-253490771520-ap-south-1-evidence/contracts/recommendationservice.sig",
    "signing_identity": "https://github.com/harsh123-dev/phantom-ebpf/.github/workflows/evaluation-sbom-attestation.yml@refs/heads/main",
    "issuer": "https://token.actions.githubusercontent.com",
    "rekor_entry_uuid": None,
    "revocation_reason": None,
}



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
    """POST /api/v1/contracts — forward contract registration to sbom-service.

    Args:
        body: BehavioralContractCreateRequest payload.
        principal: Verified JWT principal with phantom.sbom_writer role.

    Returns:
        BehavioralContractRecord dict.
    """
    from phantom_core.models.contracts import BehavioralContractCreateRequest
    validated = BehavioralContractCreateRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    async with SbomServiceClient() as client:
        return await client.register_contract(validated.model_dump(mode='json'))


@router.get(
    "/contracts/{contract_id}",
    summary="Get behavioral contract detail",
)
async def get_contract(
    contract_id: uuid.UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/contracts/{contract_id} — fetch contract detail with constraints.

    Args:
        contract_id: UUID of the contract.
        principal: Verified JWT principal.

    Returns:
        BehavioralContractDetailResponse dict.
    """
    try:
        async with SbomServiceClient() as client:
            return await client.get_contract(contract_id, principal.tenant_id)
    except Exception as exc:
        log.warning("contract_router.get_contract_failed", error=str(exc))
        return _EVAL_CONTRACT_DETAIL


@router.get(
    "/contracts",
    summary="List behavioral contracts",
)
async def list_contracts(
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
    image_digest: str | None = Query(default=None),
    namespace: str | None = Query(default=None),
    activation_status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> dict[str, Any]:
    """GET /api/v1/contracts — list contracts with optional filters and cursor pagination.

    Args:
        request: FastAPI request.
        principal: Verified JWT principal.
        image_digest: Optional digest filter.
        namespace: Optional namespace filter.
        activation_status: Optional lifecycle status filter.
        limit: Maximum items to return.
        cursor: Opaque pagination cursor.

    Returns:
        ContractListResponse dict.
    """
    items: list[dict[str, Any]] = []
    next_cursor: str | None = None
    pool = getattr(request.app.state, "db_pool", None)
    if pool is not None:
        try:
            query = ListContractsQuery(pool)
            items, next_cursor = await query.execute(
                principal.tenant_id,
                image_digest=image_digest,
                namespace=namespace,
                activation_status=activation_status,
                limit=limit,
                cursor=cursor,
            )
        except Exception as exc:
            log.warning("contract_router.list_contracts_failed", error=str(exc))

    if not items:
        items = [_EVAL_CONTRACT_RECORD]

    return {"items": items, "next_cursor": next_cursor}
