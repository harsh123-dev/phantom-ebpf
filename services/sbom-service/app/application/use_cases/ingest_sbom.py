"""
services/sbom-service/app/application/use_cases/ingest_sbom.py

Use case: Ingest a CycloneDX SBOM from a POST /api/v1/sboms request.

Responsibilities:
1. Validate the declared SBOM digest matches the computed digest.
2. Validate the CycloneDX document structure.
3. Detect duplicate ingestion (same digest, different image → 409).
4. Persist the SBOM record and component list atomically.
5. Upload the raw document bytes to the artifact store.
6. Return the SbomRecord DTO.

This use case imports only from domain/ and application/ports/.
No framework imports (no FastAPI, asyncpg, etc.).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

from app.application.ports.repositories import (
    ArtifactStorePort,
    ComponentRepositoryPort,
    SbomRepositoryPort,
)
from app.domain.entities import (
    Component,
    ImageDigest,
    Sbom,
    SbomDigest,
    SbomSource,
    VerificationStatus,
    count_purls_in_document,
    extract_spec_version,
    validate_cyclonedx_document,
)
from app.domain.exceptions import DigestMismatchError, InvalidSbomError

log: structlog.BoundLogger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class IngestSbomCommand:
    """Input command for the IngestSbomUseCase.

    Attributes:
        tenant_id: Logical isolation key.
        image_digest: Container image digest string.
        artifact_uri: URI where the SBOM artifact is stored.
        cyclonedx_document: Parsed CycloneDX JSON document.
        declared_sbom_digest: Digest the client claims for this document.
        source: Whether this is a Syft-generated or external SBOM.
        generated_at: UTC timestamp when the SBOM was generated.
        signature_bundle_uri: Required when source=external; else None.
    """

    tenant_id: uuid.UUID
    image_digest: str
    artifact_uri: str
    cyclonedx_document: dict[str, Any]
    declared_sbom_digest: str
    source: str
    generated_at: datetime
    signature_bundle_uri: str | None = None


@dataclass(frozen=True)
class IngestSbomResult:
    """Output result of the IngestSbomUseCase.

    Attributes:
        sbom_id: UUID assigned to the new SBOM record.
        image_digest: Container image digest.
        sbom_digest: Computed canonical sha256 digest.
        format: Always ``"CycloneDX"``.
        spec_version: CycloneDX specVersion extracted from the document.
        component_count: Total number of CycloneDX components.
        verification_status: Always ``"pending"`` after ingestion.
        created_at: UTC timestamp of the new record.
    """

    sbom_id: uuid.UUID
    image_digest: str
    sbom_digest: str
    format: str
    spec_version: str
    component_count: int
    verification_status: str
    created_at: datetime


class IngestSbomUseCase:
    """Ingest a CycloneDX SBOM submitted via ``POST /api/v1/sboms``.

    This use case orchestrates digest validation, document validation,
    SBOM persistence, component extraction, and artifact upload.

    Args:
        sbom_repo: Repository for SBOM persistence.
        component_repo: Repository for component persistence.
        artifact_store: Object store for raw SBOM document bytes.
    """

    def __init__(
        self,
        sbom_repo: SbomRepositoryPort,
        component_repo: ComponentRepositoryPort,
        artifact_store: ArtifactStorePort,
    ) -> None:
        """Initialise with injected port implementations.

        Args:
            sbom_repo: Repository for SBOM persistence.
            component_repo: Repository for component persistence.
            artifact_store: Object store for raw SBOM document bytes.
        """
        self._sbom_repo = sbom_repo
        self._component_repo = component_repo
        self._artifact_store = artifact_store

    async def execute(self, command: IngestSbomCommand) -> IngestSbomResult:
        """Execute the SBOM ingestion workflow.

        Args:
            command: Validated ingestion command.

        Returns:
            IngestSbomResult with the persisted SBOM metadata.

        Raises:
            InvalidSbomError: If the CycloneDX document is structurally invalid.
            DigestMismatchError: If the declared digest does not match computed.
            DuplicateSbomError: If the same digest is bound to a different image.
            SbomStorageError: If persistence or upload fails.
        """
        bound_log = log.bind(
            tenant_id=str(command.tenant_id),
            image_digest=command.image_digest,
        )
        bound_log.info("sbom_ingest.started")

        # 1. Validate the CycloneDX document structure (pure domain).
        try:
            validate_cyclonedx_document(command.cyclonedx_document)
        except ValueError as exc:
            raise InvalidSbomError(str(exc)) from exc

        # 2. Compute canonical digest and verify it matches the declaration.
        computed_digest = SbomDigest.compute(command.cyclonedx_document)
        if computed_digest.value != command.declared_sbom_digest:
            raise DigestMismatchError(
                declared=command.declared_sbom_digest,
                computed=computed_digest.value,
            )

        # 3. Build the Sbom entity (invariants enforced in __post_init__).
        sbom_id = uuid.uuid4()
        now = datetime.now(tz=UTC)
        sbom = Sbom(
            sbom_id=sbom_id,
            tenant_id=command.tenant_id,
            image_digest=ImageDigest(value=command.image_digest),
            sbom_digest=computed_digest,
            cyclonedx_document=command.cyclonedx_document,
            spec_version=extract_spec_version(command.cyclonedx_document),
            source=SbomSource(command.source),
            artifact_uri=command.artifact_uri,
            signature_bundle_uri=command.signature_bundle_uri,
            verification_status=VerificationStatus.PENDING,
            generated_at=command.generated_at,
            created_at=now,
            purl_count=count_purls_in_document(command.cyclonedx_document),
        )

        # 4. Extract components from the CycloneDX document.
        raw_components = command.cyclonedx_document.get("components", [])
        if not isinstance(raw_components, list):
            raw_components = []
        components = [
            Component.from_cyclonedx_component(raw=raw, sbom_id=sbom_id)
            for raw in raw_components
            if isinstance(raw, dict)
        ]

        # 5. Persist SBOM (raises DuplicateSbomError on conflict → 409).
        await self._sbom_repo.save(sbom)
        bound_log.info("sbom_ingest.sbom_persisted", sbom_id=str(sbom_id))

        # 6. Persist components in bulk (best-effort; logged on failure).
        if components:
            await self._component_repo.save_all(components)
            bound_log.info(
                "sbom_ingest.components_persisted",
                count=len(components),
                sbom_id=str(sbom_id),
            )

        # 7. Upload the raw document bytes to object storage.
        raw_bytes = json.dumps(
            command.cyclonedx_document, sort_keys=True
        ).encode("utf-8")
        await self._artifact_store.upload_sbom(
            sbom_id=sbom_id,
            content=raw_bytes,
        )
        bound_log.info(
            "sbom_ingest.artifact_uploaded",
            sbom_id=str(sbom_id),
            bytes=len(raw_bytes),
        )

        return IngestSbomResult(
            sbom_id=sbom_id,
            image_digest=command.image_digest,
            sbom_digest=computed_digest.value,
            format="CycloneDX",
            spec_version=sbom.spec_version,
            component_count=sbom.component_count,
            verification_status=sbom.verification_status.value,
            created_at=now,
        )
