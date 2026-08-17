"""
services/sbom-service/app/domain/ports.py

Domain port definitions (abstract interfaces) for the SBOM service.

These are the abstract contracts that the domain and application layers
depend on. Concrete implementations live in infrastructure/.

Rules:
- NO imports from infrastructure/, interface/, or application/.
- Uses only stdlib abc and domain entities.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.domain.entities import Component, Sbom, VerificationJob


class SbomRepositoryPort(ABC):
    """Abstract repository port for SBOM persistence operations.

    The application layer depends on this interface only.
    The infrastructure PostgreSQL adapter implements it.
    """

    @abstractmethod
    async def save(self, sbom: Sbom) -> None:
        """Persist a new SBOM record.

        Args:
            sbom: The Sbom entity to persist.

        Raises:
            DuplicateSbomError: If the same SBOM digest is already bound
                to a different image digest.
            SbomStorageError: If persistence fails due to a storage error.
        """

    @abstractmethod
    async def get_by_id(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> Sbom:
        """Retrieve one SBOM by its UUID within a tenant scope.

        Args:
            sbom_id: The UUID of the SBOM to retrieve.
            tenant_id: Tenant scope for isolation.

        Returns:
            The matching Sbom entity.

        Raises:
            SbomNotFoundError: If no SBOM with that ID exists in this tenant.
        """

    @abstractmethod
    async def update_verification(self, sbom: Sbom) -> None:
        """Persist updated verification state for an existing SBOM.

        Args:
            sbom: The Sbom entity with updated verification fields.

        Raises:
            SbomNotFoundError: If the SBOM no longer exists.
            SbomStorageError: If persistence fails.
        """


class VerificationJobRepositoryPort(ABC):
    """Abstract repository port for verification job persistence."""

    @abstractmethod
    async def save(self, job: VerificationJob) -> None:
        """Persist a new verification job.

        Args:
            job: The VerificationJob entity to persist.
        """

    @abstractmethod
    async def get_by_sbom_id(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> VerificationJob:
        """Retrieve the most recent verification job for an SBOM.

        Args:
            sbom_id: The UUID of the SBOM.
            tenant_id: Tenant scope for isolation.

        Returns:
            The most recent VerificationJob for this SBOM.

        Raises:
            VerificationJobNotFoundError: If no job exists.
        """

    @abstractmethod
    async def update(self, job: VerificationJob) -> None:
        """Persist updated state for an existing verification job.

        Args:
            job: The VerificationJob entity with updated state.
        """


class ComponentRepositoryPort(ABC):
    """Abstract repository port for SBOM component records."""

    @abstractmethod
    async def save_all(self, components: list[Component]) -> None:
        """Bulk-persist a list of Component records.

        Args:
            components: The Component entities to persist.

        Raises:
            SbomStorageError: If persistence fails.
        """

    @abstractmethod
    async def get_by_sbom_id(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[Component]:
        """Retrieve all components belonging to an SBOM.

        Args:
            sbom_id: The UUID of the parent SBOM.
            tenant_id: Tenant scope for isolation.

        Returns:
            List of Component entities; may be empty.
        """


class SbomVerifierPort(ABC):
    """Abstract port for cosign/Sigstore signature verification."""

    @abstractmethod
    async def verify(
        self,
        sbom: Sbom,
        expected_identity: str,
        expected_issuer: str,
        rekor_required: bool,
    ) -> Sbom:
        """Verify the cosign signature of an SBOM and return updated entity.

        Args:
            sbom: The Sbom entity to verify.
            expected_identity: Expected Fulcio signing identity.
            expected_issuer: Expected OIDC issuer URI.
            rekor_required: Whether a Rekor transparency log entry is mandatory.

        Returns:
            The Sbom entity with updated verification fields (VERIFIED or FAILED).

        Raises:
            SignatureVerificationError: If verification fails definitively.
            VerificationServiceUnavailableError: If cosign/Sigstore is unreachable.
        """


class ArtifactStorePort(ABC):
    """Abstract port for object-store artifact upload/download."""

    @abstractmethod
    async def upload_sbom(
        self,
        sbom_id: uuid.UUID,
        content: bytes,
        content_type: str = "application/json",
    ) -> str:
        """Upload a SBOM document to object storage.

        Args:
            sbom_id: The SBOM UUID used to derive the object key.
            content: Raw bytes of the serialized CycloneDX document.
            content_type: MIME type of the content.

        Returns:
            The URI where the artifact was stored.

        Raises:
            SbomStorageError: If the upload fails.
        """

    @abstractmethod
    async def download_sbom(self, sbom_id: uuid.UUID) -> bytes:
        """Download a SBOM document from object storage.

        Args:
            sbom_id: The SBOM UUID used to locate the object.

        Returns:
            Raw bytes of the serialized CycloneDX document.

        Raises:
            SbomNotFoundError: If the object does not exist.
            SbomStorageError: If the download fails.
        """
