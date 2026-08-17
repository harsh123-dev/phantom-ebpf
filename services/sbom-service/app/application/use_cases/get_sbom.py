"""
services/sbom-service/app/application/use_cases/get_sbom.py

Use case: Retrieve SBOM metadata and document via ``GET /api/v1/sboms/{sbom_id}``.

Responsibilities:
1. Fetch the Sbom entity from the repository (tenant-scoped).
2. Return a rich detail DTO including the CycloneDX document.

Imports only from domain/ and application/ports/.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog

from app.application.ports.repositories import (
    SbomRepositoryPort,
)
from app.domain.entities import Sbom

log: structlog.BoundLogger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class GetSbomQuery:
    """Input query for the GetSbomUseCase.

    Attributes:
        sbom_id: UUID of the SBOM to retrieve.
        tenant_id: Tenant scope for authorization.
    """

    sbom_id: uuid.UUID
    tenant_id: uuid.UUID


@dataclass(frozen=True)
class GetSbomResult:
    """Output result for the GetSbomUseCase.

    Attributes:
        sbom_id: UUID of the SBOM record.
        image_digest: Container image digest.
        sbom_digest: Canonical sha256 digest of the document.
        format: Always ``"CycloneDX"``.
        spec_version: CycloneDX spec version string.
        component_count: Total CycloneDX components in the document.
        verification_status: Current cosign verification state.
        created_at: UTC creation timestamp.
        cyclonedx_document: Full parsed CycloneDX document.
        purl_count: Number of components with a resolvable PURL.
        signature_bundle_uri: URI of the cosign signature bundle; None if absent.
        verified_at: UTC timestamp of successful verification; None if pending.
        verification_error: Failure reason; None if not failed.
    """

    sbom_id: uuid.UUID
    image_digest: str
    sbom_digest: str
    format: str
    spec_version: str
    component_count: int
    verification_status: str
    created_at: datetime
    cyclonedx_document: dict[str, Any]
    purl_count: int
    signature_bundle_uri: str | None
    verified_at: datetime | None
    verification_error: str | None

    @classmethod
    def from_entity(cls, sbom: Sbom) -> GetSbomResult:
        """Build the result DTO from a domain entity.

        Args:
            sbom: The Sbom domain entity.

        Returns:
            GetSbomResult populated from the entity.
        """
        return cls(
            sbom_id=sbom.sbom_id,
            image_digest=sbom.image_digest.value,
            sbom_digest=sbom.sbom_digest.value,
            format="CycloneDX",
            spec_version=sbom.spec_version,
            component_count=sbom.component_count,
            verification_status=sbom.verification_status.value,
            created_at=sbom.created_at,
            cyclonedx_document=sbom.cyclonedx_document,
            purl_count=sbom.purl_count,
            signature_bundle_uri=sbom.signature_bundle_uri,
            verified_at=sbom.verified_at,
            verification_error=sbom.verification_error,
        )


class GetSbomUseCase:
    """Retrieve one SBOM record for ``GET /api/v1/sboms/{sbom_id}``.

    Args:
        sbom_repo: Repository for SBOM reads.
    """

    def __init__(self, sbom_repo: SbomRepositoryPort) -> None:
        """Initialise with the SBOM repository port.

        Args:
            sbom_repo: Repository for SBOM reads.
        """
        self._sbom_repo = sbom_repo

    async def execute(self, query: GetSbomQuery) -> GetSbomResult:
        """Execute the SBOM retrieval query.

        Args:
            query: The retrieval query with sbom_id and tenant_id.

        Returns:
            GetSbomResult with the SBOM metadata and document.

        Raises:
            SbomNotFoundError: If no SBOM with that ID exists in this tenant.
        """
        log.info(
            "get_sbom.started",
            sbom_id=str(query.sbom_id),
            tenant_id=str(query.tenant_id),
        )
        sbom = await self._sbom_repo.get_by_id(
            sbom_id=query.sbom_id,
            tenant_id=query.tenant_id,
        )
        log.info("get_sbom.found", sbom_id=str(query.sbom_id))
        return GetSbomResult.from_entity(sbom)
