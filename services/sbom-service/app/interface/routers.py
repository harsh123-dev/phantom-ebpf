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

import re
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from pydantic import AnyUrl, BaseModel, Field, ValidationInfo, field_validator, model_validator

from app.application.use_cases.get_sbom import GetSbomQuery
from app.application.use_cases.ingest_sbom import IngestSbomCommand
from app.application.use_cases.verify_sbom_signature import (
    EnqueueVerificationCommand,
    GetVerificationResultQuery,
    RunVerificationCommand,
)
from app.domain.entities import VerificationStatus
from app.domain.exceptions import (
    DigestMismatchError,
    DuplicateSbomError,
    InvalidSbomError,
    SbomNotFoundError,
    SbomStorageError,
    SignatureVerificationError,
    VerificationAlreadyInProgressError,
    VerificationJobNotFoundError,
    VerificationServiceUnavailableError,
)
from app.domain.mapping import (
    ContainerIdentity,
    ProcessIdentity,
    RuntimeEventRecord,
    RuntimeToSbomMapper,
    SbomIndex,
)
from app.interface.dependencies import (
    ComponentRepoDep,
    CosignClientDep,
    EnqueueVerifyDep,
    GetSbomDep,
    GetVerifyDep,
    IngestSbomDep,
    RunVerifyDep,
    SbomRepoDep,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pydantic request/response schemas (interface layer only)
# ---------------------------------------------------------------------------


class SbomIngestRequestSchema(BaseModel):
    """Request body for ``POST /api/v1/sboms``."""

    schema_version: Literal["v1"] = "v1"
    image_digest: str
    image_reference: str | None = None
    artifact_uri: AnyUrl
    artifact_download_url: AnyUrl | None = None
    artifact_version_id: str | None = None
    artifact_content_sha256: str | None = None
    artifact_manifest_digest: str | None = None
    cyclonedx_document: dict[str, Any] = Field(..., min_length=1)
    declared_sbom_digest: str
    source: Literal["syft", "external"]
    generated_at: datetime
    signature_bundle_uri: AnyUrl | None = None
    tenant_id: uuid.UUID

    model_config = {"extra": "forbid"}

    @field_validator("image_digest", "artifact_manifest_digest")
    @classmethod
    def _valid_image_digests(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError(f"{info.field_name} must be sha256:<lowercase hex>")
        return value

    @field_validator("image_reference")
    @classmethod
    def _immutable_image_reference(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        digest = info.data.get("image_digest")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}", value)
            or not value.endswith(f"@{digest}")
        ):
            raise ValueError("image_reference must be an immutable registry/repository@image_digest reference")
        return value

    @field_validator("artifact_content_sha256")
    @classmethod
    def _valid_artifact_sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("artifact_content_sha256 must be sha256:<lowercase hex>")
        return value

    @model_validator(mode="after")
    def _external_artifact_fields_pair(self) -> SbomIngestRequestSchema:
        external_fields = (
            self.artifact_download_url,
            self.artifact_version_id,
            self.artifact_content_sha256,
            self.artifact_manifest_digest,
        )
        if any(value is not None for value in external_fields) and any(
            value is None for value in external_fields
        ):
            raise ValueError(
                "external artifact URL, version, digest, and manifest digest "
                "must be supplied together"
            )
        return self


class SbomRecordSchema(BaseModel):
    """Response record for SBOM endpoints."""

    sbom_id: uuid.UUID
    image_digest: str
    image_reference: str | None = None
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
    expected_issuer: str = Field(..., min_length=1, max_length=512)
    rekor_required: bool = True

    model_config = {"extra": "forbid"}

    @field_validator("expected_issuer")
    @classmethod
    def _exact_https_issuer(cls, value: str) -> str:
        """Validate the issuer without rewriting its certificate-bound bytes."""
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or value.strip() != value
        ):
            raise ValueError("expected_issuer must be an exact HTTPS issuer URI")
        return value


class RuntimeBindingRequestSchema(BaseModel):
    """Evidence required to resolve a runtime event against a verified SBOM."""

    event_id: uuid.UUID
    run_id: str = ""
    tenant_id: uuid.UUID
    event_type: str = Field(..., min_length=1, max_length=128)
    observed_at: datetime
    container_id: str = Field(..., min_length=1, max_length=256)
    image_digest: str
    pod_uid: str | None = None
    namespace: str | None = None
    workload_name: str | None = None
    tgid: int = Field(..., ge=0)
    pid_start_time_ns: int = Field(..., ge=0)
    executable_path: str | None = None
    executable_hash: str | None = None
    comm: str | None = None
    uid: int | None = None
    resource_path: str | None = None
    resource_hash: str | None = None

    model_config = {"extra": "forbid"}

    @field_validator("image_digest")
    @classmethod
    def _valid_image_digest(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("image_digest must be an immutable sha256 digest")
        return value

    @field_validator("observed_at")
    @classmethod
    def _aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value

    @field_validator("executable_hash")
    @classmethod
    def _valid_executable_hash(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", value):
            raise ValueError("executable_hash must be a SHA-256 digest")
        return value


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


def _cyclonedx_file_inventory(document: dict[str, Any]) -> dict[str, list[str]]:
    """Extract only explicit CycloneDX occurrence paths keyed by component ref."""
    result: dict[str, list[str]] = {}
    components = document.get("components", [])
    if not isinstance(components, list):
        return result
    for component in components:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        evidence = component.get("evidence")
        occurrences = evidence.get("occurrences") if isinstance(evidence, dict) else None
        if not isinstance(purl, str) or not isinstance(occurrences, list):
            continue
        for occurrence in occurrences:
            location = occurrence.get("location") if isinstance(occurrence, dict) else None
            path = location.get("path") if isinstance(location, dict) else location
            if isinstance(path, str) and path.startswith("/") and ".." not in path.split("/"):
                result.setdefault(purl, []).append(path)
    return result


@router.post("/internal/v1/runtime-bindings", tags=["internal"])
async def map_runtime_binding(
    body: RuntimeBindingRequestSchema,
    sbom_repo: SbomRepoDep,
    component_repo: ComponentRepoDep,
) -> dict[str, Any]:
    """Map runtime evidence using only a verified SBOM for the exact digest.

    Multiple verified SBOM documents for one tenant and image are treated as
    insufficient evidence: the service does not choose one arbitrarily.
    """
    records = await sbom_repo.get_by_image_digest(body.image_digest, body.tenant_id)
    verified = [item for item in records if item.verification_status == VerificationStatus.VERIFIED]
    indices: dict[str, SbomIndex] = {}
    if len(verified) == 1:
        sbom = verified[0]
        components = await component_repo.get_by_sbom_id(sbom.sbom_id, body.tenant_id)
        index = SbomIndex.build(
            sbom,
            components,
            file_inventory=_cyclonedx_file_inventory(sbom.cyclonedx_document),
        )
        indices[body.image_digest] = index

    runtime = RuntimeEventRecord(
        event_id=body.event_id,
        event_type=body.event_type,
        event_time=body.observed_at,
        process=ProcessIdentity(
            tgid=body.tgid,
            pid_start_time_ns=body.pid_start_time_ns,
            container_id=body.container_id,
            executable_path=body.executable_path,
            executable_hash=body.executable_hash,
            comm=body.comm,
            uid=body.uid,
        ),
        container=ContainerIdentity(
            container_id=body.container_id,
            image_digest=body.image_digest,
            pod_uid=body.pod_uid,
            namespace=body.namespace,
            workload_name=body.workload_name,
        ),
        resource_path=body.resource_path,
        resource_hash=body.resource_hash,
        tenant_id=str(body.tenant_id),
        run_id=body.run_id,
    )
    result = RuntimeToSbomMapper(indices).map(runtime)
    payload = result.to_causal_binding_payload()
    if len(verified) > 1:
        payload.update({
            "binding_status": "insufficient_evidence",
            "sbom_id": None,
            "purl": None,
            "confidence": None,
            "candidate_purls": [],
            "reason": "multiple verified SBOM documents match the image digest",
        })
    elif records and not verified:
        payload.update({
            "binding_status": "insufficient_evidence",
            "sbom_id": None,
            "purl": None,
            "confidence": None,
            "reason": "matching SBOM exists but has not passed verification",
        })
    return payload

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
        artifact_download_url=(
            str(body.artifact_download_url) if body.artifact_download_url else None
        ),
        artifact_version_id=body.artifact_version_id,
        artifact_content_sha256=body.artifact_content_sha256,
        artifact_manifest_digest=body.artifact_manifest_digest,
        image_reference=body.image_reference,
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
        image_reference=result.image_reference,
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
        image_reference=result.image_reference,
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
    runner: RunVerifyDep,
    verifier: CosignClientDep,
    background_tasks: BackgroundTasks,
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
    try:
        verifier.validate_trust_request(
            body.expected_identity, str(body.expected_issuer), body.rekor_required
        )
    except VerificationServiceUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except SignatureVerificationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

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

    background_tasks.add_task(
        runner.execute,
        RunVerificationCommand(
            verification_job_id=result.verification_job_id,
            tenant_id=tenant_id,
        ),
    )

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
