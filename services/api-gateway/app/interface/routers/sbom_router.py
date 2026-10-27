"""
api-gateway SBOM endpoints router.

Implements public REST routes under /api/v1:
  POST   /sboms
  GET    /sboms/{sbom_id}
  POST   /sboms/{sbom_id}/verification
  GET    /sboms/{sbom_id}/verification
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends

from app.application.queries import GetSBOMQuery
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import TenantMismatchError
from app.infrastructure.service_clients import SbomServiceClient
from app.interface.dependencies import require_role

router = fastapi.APIRouter(tags=["SBOMs"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


def _sbom_client() -> SbomServiceClient:
    """Return a new SbomServiceClient using env-configured base URL.

    Returns:
        SbomServiceClient instance.
    """
    return SbomServiceClient()


@router.post(
    "/sboms",
    status_code=201,
    summary="Ingest a new SBOM",
)
async def ingest_sbom(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.SBOM_WRITER, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/sboms — forward SBOM ingest to sbom-service.

    Args:
        request: FastAPI request.
        body: SbomIngestRequest payload.
        principal: Verified JWT principal with phantom.sbom_writer role.

    Returns:
        SbomRecord dict.
    """
    from phantom_core.models.sbom import SbomIngestRequest
    validated = SbomIngestRequest.model_validate(body)

    if validated.tenant_id != principal.tenant_id:
        raise TenantMismatchError(
            f"Request tenant_id {validated.tenant_id} does not match "
            f"token tenant_id {principal.tenant_id}."
        )

    async with SbomServiceClient() as client:
        result = await client.ingest_sbom(
            {k: str(v) if isinstance(v, uuid.UUID) else v
             for k, v in validated.model_dump().items()}
        )
    return result


@router.get(
    "/sboms",
    summary="List SBOMs",
)
async def list_sboms(
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(
            PhantomRole.VIEWER, PhantomRole.ANALYST,
            PhantomRole.SBOM_WRITER, PhantomRole.ADMIN,
        )),
    ],
    image_digest: str | None = fastapi.Query(default=None),
    limit: int = fastapi.Query(default=25, ge=1, le=100),
    cursor: str | None = fastapi.Query(default=None),
) -> dict[str, Any]:
    """GET /api/v1/sboms — list SBOM records."""
    import asyncpg
    pool = getattr(request.app.state, "db_pool", None)
    items: list[dict[str, Any]] = []
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                for table_name in ("phantom_sbom.sboms", "sboms"):
                    try:
                        query = f"""
                            SELECT sbom_id, image_digest, sbom_digest, spec_version,
                                   verification_status, purl_count, created_at
                            FROM {table_name}
                            WHERE ($1::uuid IS NULL OR tenant_id = $1)
                        """
                        params: list[Any] = [principal.tenant_id]
                        if image_digest:
                            query += f" AND image_digest ILIKE ${len(params) + 1}"
                            params.append(f"%{image_digest}%")
                        query += f" ORDER BY created_at DESC LIMIT ${len(params) + 1}"
                        params.append(limit)

                        rows = await conn.fetch(query, *params)
                        for row in rows:
                            items.append({
                                "sbom_id": str(row["sbom_id"]),
                                "image_digest": row["image_digest"],
                                "sbom_digest": row["sbom_digest"],
                                "format": "CycloneDX",
                                "spec_version": row["spec_version"] or "1.4",
                                "component_count": row["purl_count"] or 0,
                                "verification_status": row["verification_status"] or "pending",
                                "created_at": (
                                    row["created_at"].isoformat()
                                    if hasattr(row["created_at"], "isoformat")
                                    else str(row["created_at"])
                                ),
                            })
                        if items:
                            break
                    except (asyncpg.UndefinedTableError, Exception):
                        continue
        except Exception as exc:
            log.warning("sbom_router.list_sboms.failed", error=str(exc))

    return {"items": items, "next_cursor": None}


@router.get(
    "/sboms/{sbom_id}",
    summary="Get SBOM detail",
)
async def get_sbom(
    sbom_id: uuid.UUID,
    request: fastapi.Request,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(
            PhantomRole.VIEWER, PhantomRole.ANALYST,
            PhantomRole.SBOM_WRITER, PhantomRole.ADMIN,
        )),
    ],
) -> dict[str, Any]:
    """GET /api/v1/sboms/{sbom_id} — fetch SBOM detail.

    Args:
        sbom_id: UUID of the SBOM.
        request: FastAPI request.
        principal: Verified JWT principal.

    Returns:
        SbomDetailResponse dict.
    """
    async with SbomServiceClient() as client:
        query = GetSBOMQuery(client)
        return await query.execute(sbom_id, principal.tenant_id)


@router.post(
    "/sboms/{sbom_id}/verification",
    status_code=202,
    summary="Trigger SBOM cosign verification",
)
async def trigger_verification(
    sbom_id: uuid.UUID,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.SBOM_WRITER, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/sboms/{sbom_id}/verification — trigger cosign verification.

    Args:
        sbom_id: UUID of the SBOM to verify.
        body: SbomVerificationRequest payload.
        principal: Verified JWT principal with phantom.sbom_writer role.

    Returns:
        VerificationJobResponse dict.
    """
    from phantom_core.models.sbom import SbomVerificationRequest
    validated = SbomVerificationRequest.model_validate(body)
    async with SbomServiceClient() as client:
        return await client.trigger_verification(sbom_id, validated.model_dump())


@router.get(
    "/sboms/{sbom_id}/verification",
    summary="Get SBOM verification status",
)
async def get_verification_status(
    sbom_id: uuid.UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(
            PhantomRole.VIEWER, PhantomRole.ANALYST,
            PhantomRole.SBOM_WRITER, PhantomRole.ADMIN,
        )),
    ],
) -> dict[str, Any]:
    """GET /api/v1/sboms/{sbom_id}/verification — get cosign verification status.

    Args:
        sbom_id: UUID of the SBOM.
        principal: Verified JWT principal.

    Returns:
        SbomVerificationResponse dict.
    """
    async with SbomServiceClient() as client:
        return await client.get_verification_status(sbom_id, principal.tenant_id)
