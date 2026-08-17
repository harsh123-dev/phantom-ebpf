"""
services/sbom-service/app/interface/routers.py

FastAPI router implementing all SBOM API endpoints from the contract (B.2):

  POST   /api/v1/sboms                             → ingest SBOM
  GET    /api/v1/sboms/{sbom_id}                   → retrieve SBOM detail
  POST   /api/v1/sboms/{sbom_id}/verification      → enqueue verification
  GET    /api/v1/sboms/{sbom_id}/verification      → get verification result
  GET    /healthz                                   → liveness probe
  GET    /readyz                                    → readiness probe

Error mapping follows the handoff contract:
  400 → InvalidSbomError, DigestMismatchError, SyftParseError
  404 → SbomNotFoundError, VerificationJobNotFoundError
  409 → DuplicateSbomError, VerificationAlreadyInProgressError
  503 → SbomStorageError, VerificationServiceUnavailableError
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import AnyUrl, BaseModel, Field

from app.application.use_cases.get_sbom import GetSbomQuery
from app.application.use_cases.ingest_sbom import IngestSbomCommand
from app.application.use_cases.verify_sbom_signature import (
    EnqueueVerificationCommand,
    GetVerificationResultQuery,
)
from app.domain.exceptions import (
    DigestMismatchError,
    DuplicateSbomError,
    InvalidSbomError,
    SbomNotFoundError,
    SbomStorageError,
    VerificationAlreadyInProgressError,
    VerificationJobNotFoundError,
)
from app.interface.dependencies import (
    EnqueueVerifyDep,
    GetSbomDep,
    GetVerifyDep,
    IngestSbomDep,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pydantic request/response schemas (interface layer only)
# ---------------------------------------------------------------------------


class SbomIngestRequestSchema(BaseModel):
    """Request body for ``POST /api/v1/sboms``."""

    schema_version: Literal["v1"] = "v1"
    image_digest: str
    artifact_uri: AnyUrl
    cyclonedx_document: dict[str, Any] = Field(..., min_length=1)
    declared_sbom_digest: str
    source: Literal["syft", "external"]
    generated_at: datetime
    signature_bundle_uri: AnyUrl | None = None
    tenant_id: uuid.UUID

    model_config = {"extra": "forbid"}


class SbomRecordSchema(BaseModel):
    """Response record for SBOM endpoints."""

    sbom_id: uuid.UUID
    image_digest: str
    sbom_digest: str
    format: str
    spec_version: str
    component_count: int
    verification_status: str
    created_at: datetime

    model_config = {"extra": "forbid"}


class SbomDetailResponseSchema(BaseModel):
    """Response body for ``GET /api/v1/sboms/{sbom_id}``."""

    record: SbomRecordSchema
    cyclonedx_document: dict[str, Any]
    purl_count: int
    signature_bundle_uri: str | None
    verified_at: datetime | None
    verification_error: str | None

    model_config = {"extra": "forbid"}


class SbomVerificationRequestSchema(BaseModel):
    """Request body for ``POST /api/v1/sboms/{sbom_id}/verification``."""

    expected_identity: str = Field(..., min_length=1, max_length=512)
    expected_issuer: AnyUrl
    rekor_required: bool = True

    model_config = {"extra": "forbid"}


class VerificationJobResponseSchema(BaseModel):
    """Response body for enqueue-verification endpoint."""

    verification_job_id: uuid.UUID
    sbom_id: uuid.UUID
    status: str
    submitted_at: datetime

    model_config = {"extra": "forbid"}


class SbomVerificationResponseSchema(BaseModel):
    """Response body for get-verification-result endpoint."""

    verification_job_id: uuid.UUID
    sbom_id: uuid.UUID
    status: str
    signing_identity: str | None
    issuer: str | None
    rekor_entry_uuid: uuid.UUID | None
    verified_at: datetime | None
    failure_reason: str | None

    model_config = {"extra": "forbid"}


class HealthResponseSchema(BaseModel):
    """Liveness probe response."""

    status: Literal["ok"]
    service: str
    timestamp: datetime


class ReadinessResponseSchema(BaseModel):
    """Readiness probe response."""

    status: Literal["ready", "not_ready"]
    service: str
    checks: dict[str, str]
    timestamp: datetime


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter()

# ---------------------------------------------------------------------------
# Probe endpoints (no auth required; cluster-internal only)
# ---------------------------------------------------------------------------


@router.get("/healthz", response_model=HealthResponseSchema, tags=["probes"])
async def healthz() -> HealthResponseSchema:
    """Liveness probe — confirms the event loop is alive.

    Returns:
        HealthResponseSchema with status ``"ok"``.
    """
    return HealthResponseSchema(
        status="ok",
        service="sbom-service",
        timestamp=datetime.now(tz=UTC),
    )


@router.get("/readyz", response_model=ReadinessResponseSchema, tags=["probes"])
async def readyz(request: Request) -> ReadinessResponseSchema:
    """Readiness probe — confirms the database pool is available.

    Args:
        request: FastAPI request (used to access app.state.db_pool).

    Returns:
        ReadinessResponseSchema; 503 if postgres is unavailable.
    """
    checks: dict[str, str] = {}
    overall_ready = True

    try:
        pool = request.app.state.db_pool
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["postgres"] = "pass"
    except Exception:  # noqa: BLE001
        checks["postgres"] = "fail"
        overall_ready = False

    schema = ReadinessResponseSchema(
        status="ready" if overall_ready else "not_ready",
        service="sbom-service",
        checks=checks,
        timestamp=datetime.now(tz=UTC),
    )
    if not overall_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=schema.model_dump(),
        )
    return schema


# ---------------------------------------------------------------------------
# SBOM endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/sboms",
    response_model=SbomRecordSchema,
    status_code=status.HTTP_201_CREATED,
    tags=["sboms"],
)
async def ingest_sbom(
    body: SbomIngestRequestSchema,
    use_case: IngestSbomDep,
) -> SbomRecordSchema:
    """Ingest a CycloneDX SBOM (``POST /api/v1/sboms``).

    Args:
        body: Validated request body.
        use_case: Injected IngestSbomUseCase.

    Returns:
        SbomRecordSchema with the new SBOM metadata.

    Raises:
        HTTPException 400: Invalid document or digest mismatch.
        HTTPException 409: SBOM digest already bound to a different image.
        HTTPException 503: Storage unavailable.
    """
    command = IngestSbomCommand(
        tenant_id=body.tenant_id,
        image_digest=body.image_digest,
        artifact_uri=str(body.artifact_uri),
        cyclonedx_document=body.cyclonedx_document,
        declared_sbom_digest=body.declared_sbom_digest,
        source=body.source,
        generated_at=body.generated_at,
        signature_bundle_uri=str(body.signature_bundle_uri) if body.signature_bundle_uri else None,
    )
    try:
        result = await use_case.execute(command)
    except (InvalidSbomError, DigestMismatchError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DuplicateSbomError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except SbomStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return SbomRecordSchema(
        sbom_id=result.sbom_id,
        image_digest=result.image_digest,
        sbom_digest=result.sbom_digest,
        format=result.format,
        spec_version=result.spec_version,
        component_count=result.component_count,
        verification_status=result.verification_status,
        created_at=result.created_at,
    )


@router.get(
    "/api/v1/sboms/{sbom_id}",
    response_model=SbomDetailResponseSchema,
    tags=["sboms"],
)
async def get_sbom(
    sbom_id: uuid.UUID,
    tenant_id: uuid.UUID,
    use_case: GetSbomDep,
) -> SbomDetailResponseSchema:
    """Retrieve SBOM metadata and document (``GET /api/v1/sboms/{sbom_id}``).

    Args:
        sbom_id: UUID path parameter.
        tenant_id: Tenant scope (passed as a query param for the internal service).
        use_case: Injected GetSbomUseCase.

    Returns:
        SbomDetailResponseSchema.

    Raises:
        HTTPException 404: SBOM not found.
    """
    try:
        result = await use_case.execute(GetSbomQuery(sbom_id=sbom_id, tenant_id=tenant_id))
    except SbomNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    record = SbomRecordSchema(
        sbom_id=result.sbom_id,
        image_digest=result.image_digest,
        sbom_digest=result.sbom_digest,
        format=result.format,
        spec_version=result.spec_version,
        component_count=result.component_count,
        verification_status=result.verification_status,
        created_at=result.created_at,
    )
    return SbomDetailResponseSchema(
        record=record,
        cyclonedx_document=result.cyclonedx_document,
        purl_count=result.purl_count,
        signature_bundle_uri=result.signature_bundle_uri,
        verified_at=result.verified_at,
        verification_error=result.verification_error,
    )


@router.post(
    "/api/v1/sboms/{sbom_id}/verification",
    response_model=VerificationJobResponseSchema,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["sboms"],
)
async def enqueue_verification(
    sbom_id: uuid.UUID,
    body: SbomVerificationRequestSchema,
    tenant_id: uuid.UUID,
    use_case: EnqueueVerifyDep,
) -> VerificationJobResponseSchema:
    """Enqueue cosign verification (``POST /api/v1/sboms/{sbom_id}/verification``).

    Args:
        sbom_id: UUID path parameter.
        body: Validated verification request body.
        tenant_id: Tenant scope.
        use_case: Injected EnqueueVerificationUseCase.

    Returns:
        VerificationJobResponseSchema with the queued job details.

    Raises:
        HTTPException 404: SBOM not found.
        HTTPException 409: Verification already in progress.
    """
    command = EnqueueVerificationCommand(
        sbom_id=sbom_id,
        tenant_id=tenant_id,
        expected_identity=body.expected_identity,
        expected_issuer=str(body.expected_issuer),
        rekor_required=body.rekor_required,
    )
    try:
        result = await use_case.execute(command)
    except SbomNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except VerificationAlreadyInProgressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return VerificationJobResponseSchema(
        verification_job_id=result.verification_job_id,
        sbom_id=result.sbom_id,
        status=result.status,
        submitted_at=result.submitted_at,
    )


@router.get(
    "/api/v1/sboms/{sbom_id}/verification",
    response_model=SbomVerificationResponseSchema,
    tags=["sboms"],
)
async def get_verification_result(
    sbom_id: uuid.UUID,
    tenant_id: uuid.UUID,
    use_case: GetVerifyDep,
) -> SbomVerificationResponseSchema:
    """Retrieve the verification result (``GET /api/v1/sboms/{sbom_id}/verification``).

    Args:
        sbom_id: UUID path parameter.
        tenant_id: Tenant scope.
        use_case: Injected GetVerificationResultUseCase.

    Returns:
        SbomVerificationResponseSchema.

    Raises:
        HTTPException 404: SBOM or job not found.
    """
    query = GetVerificationResultQuery(sbom_id=sbom_id, tenant_id=tenant_id)
    try:
        result = await use_case.execute(query)
    except (SbomNotFoundError, VerificationJobNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return SbomVerificationResponseSchema(
        verification_job_id=result.verification_job_id,
        sbom_id=result.sbom_id,
        status=result.status,
        signing_identity=result.signing_identity,
        issuer=result.issuer,
        rekor_entry_uuid=result.rekor_entry_uuid,
        verified_at=result.verified_at,
        failure_reason=result.failure_reason,
    )
