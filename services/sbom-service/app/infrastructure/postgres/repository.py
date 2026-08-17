"""
services/sbom-service/app/infrastructure/postgres/repository.py

asyncpg implementations of SbomRepositoryPort, ComponentRepositoryPort,
and VerificationJobRepositoryPort.

These adapters translate between domain entities and PostgreSQL rows.
They import only from domain/ (entities, exceptions, ports) and asyncpg.
No framework imports (no FastAPI, Pydantic, etc.) are present here.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import structlog

from app.domain.entities import (
    BindingStatus,
    Component,
    ImageDigest,
    Purl,
    Sbom,
    SbomDigest,
    SbomSource,
    VerificationJob,
    VerificationStatus,
)
from app.domain.exceptions import (
    DuplicateSbomError,
    SbomNotFoundError,
    SbomStorageError,
    VerificationJobNotFoundError,
)
from app.domain.ports import (
    ComponentRepositoryPort,
    SbomRepositoryPort,
    VerificationJobRepositoryPort,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware (UTC).

    Args:
        dt: A datetime or None.

    Returns:
        The datetime with UTC tzinfo, or None.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _row_to_sbom(row: asyncpg.Record) -> Sbom:
    """Convert an asyncpg Record from the ``sboms`` table to a domain Sbom.

    Args:
        row: A Record from the sboms table.

    Returns:
        A Sbom domain entity.
    """
    doc: dict[str, Any] = json.loads(row["cyclonedx_document"])
    return Sbom(
        sbom_id=row["sbom_id"],
        tenant_id=row["tenant_id"],
        image_digest=ImageDigest(value=row["image_digest"]),
        sbom_digest=SbomDigest(value=row["sbom_digest"]),
        cyclonedx_document=doc,
        spec_version=row["spec_version"],
        source=SbomSource(row["source"]),
        artifact_uri=row["artifact_uri"],
        signature_bundle_uri=row["signature_bundle_uri"],
        verification_status=VerificationStatus(row["verification_status"]),
        signing_identity=row["signing_identity"],
        issuer=row["issuer"],
        rekor_entry_uuid=row["rekor_entry_uuid"],
        verification_error=row["verification_error"],
        verified_at=_ensure_utc(row["verified_at"]),
        generated_at=_ensure_utc(row["generated_at"]),  # type: ignore[arg-type]
        created_at=_ensure_utc(row["created_at"]),  # type: ignore[arg-type]
        purl_count=row["purl_count"],
    )


def _row_to_component(row: asyncpg.Record) -> Component:
    """Convert an asyncpg Record from sbom_components to a domain Component.

    Args:
        row: A Record from the sbom_components table.

    Returns:
        A Component domain entity.
    """
    return Component(
        component_id=row["component_id"],
        sbom_id=row["sbom_id"],
        purl=Purl(value=row["purl"]),
        name=row["name"],
        version=row["version"],
        component_type=row["component_type"],
        binding_status=BindingStatus(row["binding_status"]),
        binding_confidence=row["binding_confidence"],
        created_at=_ensure_utc(row["created_at"]),  # type: ignore[arg-type]
    )


def _row_to_verification_job(row: asyncpg.Record) -> VerificationJob:
    """Convert an asyncpg Record from verification_jobs to a domain entity.

    Args:
        row: A Record from the verification_jobs table.

    Returns:
        A VerificationJob domain entity.
    """
    return VerificationJob(
        verification_job_id=row["verification_job_id"],
        sbom_id=row["sbom_id"],
        tenant_id=row["tenant_id"],
        expected_identity=row["expected_identity"],
        expected_issuer=row["expected_issuer"],
        rekor_required=row["rekor_required"],
        status=row["status"],
        submitted_at=_ensure_utc(row["submitted_at"]),  # type: ignore[arg-type]
        completed_at=_ensure_utc(row["completed_at"]),
        signing_identity=row["signing_identity"],
        issuer=row["issuer"],
        rekor_entry_uuid=row["rekor_entry_uuid"],
        failure_reason=row["failure_reason"],
    )


# ---------------------------------------------------------------------------
# SbomRepository
# ---------------------------------------------------------------------------


class PostgresSbomRepository(SbomRepositoryPort):
    """asyncpg implementation of SbomRepositoryPort.

    Args:
        pool: asyncpg connection pool to the PHANTOM PostgreSQL database.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with the asyncpg connection pool.

        Args:
            pool: The shared asyncpg connection pool.
        """
        self._pool = pool

    async def save(self, sbom: Sbom) -> None:
        """Persist a new SBOM record.

        Args:
            sbom: The Sbom entity to persist.

        Raises:
            DuplicateSbomError: If the (sbom_digest, image_digest, tenant_id)
                unique index is violated.
            SbomStorageError: On any other database error.
        """
        doc_json = json.dumps(sbom.cyclonedx_document, sort_keys=True)
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO sboms (
                        sbom_id, tenant_id, image_digest, sbom_digest,
                        cyclonedx_document, spec_version, source,
                        artifact_uri, signature_bundle_uri,
                        verification_status, purl_count,
                        generated_at, created_at
                    ) VALUES (
                        $1, $2, $3, $4,
                        $5::jsonb, $6, $7,
                        $8, $9,
                        $10, $11,
                        $12, $13
                    )
                    """,
                    sbom.sbom_id,
                    sbom.tenant_id,
                    sbom.image_digest.value,
                    sbom.sbom_digest.value,
                    doc_json,
                    sbom.spec_version,
                    sbom.source.value,
                    sbom.artifact_uri,
                    sbom.signature_bundle_uri,
                    sbom.verification_status.value,
                    sbom.purl_count,
                    sbom.generated_at,
                    sbom.created_at,
                )
        except asyncpg.UniqueViolationError as exc:
            # The unique index sboms_sbom_digest_image_digest_uq was violated.
            raise DuplicateSbomError(
                sbom_digest=sbom.sbom_digest.value,
                existing_image_digest="(see database)",
                requested_image_digest=sbom.image_digest.value,
            ) from exc
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(f"Failed to persist SBOM: {exc}") from exc

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
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM sboms WHERE sbom_id = $1 AND tenant_id = $2",
                    sbom_id,
                    tenant_id,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(f"Failed to fetch SBOM {sbom_id}: {exc}") from exc

        if row is None:
            raise SbomNotFoundError(sbom_id=str(sbom_id))
        return _row_to_sbom(row)

    async def update_verification(self, sbom: Sbom) -> None:
        """Persist updated verification state for an existing SBOM.

        Args:
            sbom: The Sbom entity with updated verification fields.

        Raises:
            SbomNotFoundError: If the SBOM no longer exists.
            SbomStorageError: If the update fails.
        """
        try:
            async with self._pool.acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE sboms
                    SET verification_status  = $1,
                        signing_identity     = $2,
                        issuer               = $3,
                        rekor_entry_uuid     = $4,
                        verification_error   = $5,
                        verified_at          = $6
                    WHERE sbom_id = $7 AND tenant_id = $8
                    """,
                    sbom.verification_status.value,
                    sbom.signing_identity,
                    sbom.issuer,
                    sbom.rekor_entry_uuid,
                    sbom.verification_error,
                    sbom.verified_at,
                    sbom.sbom_id,
                    sbom.tenant_id,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(
                f"Failed to update verification for SBOM {sbom.sbom_id}: {exc}"
            ) from exc

        if result == "UPDATE 0":
            raise SbomNotFoundError(sbom_id=str(sbom.sbom_id))


# ---------------------------------------------------------------------------
# ComponentRepository
# ---------------------------------------------------------------------------


class PostgresComponentRepository(ComponentRepositoryPort):
    """asyncpg implementation of ComponentRepositoryPort.

    Args:
        pool: asyncpg connection pool to the PHANTOM PostgreSQL database.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with the asyncpg connection pool.

        Args:
            pool: The shared asyncpg connection pool.
        """
        self._pool = pool

    async def save_all(self, components: list[Component]) -> None:
        """Bulk-persist a list of Component records using COPY.

        Args:
            components: The Component entities to persist.

        Raises:
            SbomStorageError: If the bulk insert fails.
        """
        if not components:
            return

        rows = [
            (
                comp.component_id,
                comp.sbom_id,
                comp.sbom_id,  # tenant_id derived from first component's sbom
                comp.purl.value,
                comp.name,
                comp.version,
                comp.component_type,
                comp.binding_status.value,
                comp.binding_confidence,
                comp.created_at,
            )
            for comp in components
        ]
        # Use the tenant_id from the first component (all share the same SBOM).
        # asyncpg executemany is more efficient than individual INSERTs.
        try:
            async with self._pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO sbom_components (
                        component_id, sbom_id, tenant_id,
                        purl, name, version, component_type,
                        binding_status, binding_confidence, created_at
                    ) VALUES ($1, $2,
                        (SELECT tenant_id FROM sboms WHERE sbom_id = $2),
                        $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT DO NOTHING
                    """,
                    [
                        (
                            comp.component_id,
                            comp.sbom_id,
                            comp.purl.value,
                            comp.name,
                            comp.version,
                            comp.component_type,
                            comp.binding_status.value,
                            comp.binding_confidence,
                            comp.created_at,
                        )
                        for comp in components
                    ],
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(f"Failed to persist components: {exc}") from exc

    async def get_by_sbom_id(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[Component]:
        """Retrieve all components for an SBOM.

        Args:
            sbom_id: The UUID of the parent SBOM.
            tenant_id: Tenant scope for isolation.

        Returns:
            List of Component entities; may be empty.
        """
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT c.* FROM sbom_components c
                    JOIN sboms s ON s.sbom_id = c.sbom_id
                    WHERE c.sbom_id = $1 AND s.tenant_id = $2
                    ORDER BY c.name, c.purl
                    """,
                    sbom_id,
                    tenant_id,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(
                f"Failed to fetch components for SBOM {sbom_id}: {exc}"
            ) from exc
        return [_row_to_component(row) for row in rows]


# ---------------------------------------------------------------------------
# VerificationJobRepository
# ---------------------------------------------------------------------------


class PostgresVerificationJobRepository(VerificationJobRepositoryPort):
    """asyncpg implementation of VerificationJobRepositoryPort.

    Args:
        pool: asyncpg connection pool to the PHANTOM PostgreSQL database.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with the asyncpg connection pool.

        Args:
            pool: The shared asyncpg connection pool.
        """
        self._pool = pool

    async def save(self, job: VerificationJob) -> None:
        """Persist a new verification job.

        Args:
            job: The VerificationJob entity to persist.

        Raises:
            SbomStorageError: If persistence fails.
        """
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO verification_jobs (
                        verification_job_id, sbom_id, tenant_id,
                        expected_identity, expected_issuer, rekor_required,
                        status, submitted_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    """,
                    job.verification_job_id,
                    job.sbom_id,
                    job.tenant_id,
                    job.expected_identity,
                    job.expected_issuer,
                    job.rekor_required,
                    job.status,
                    job.submitted_at,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(
                f"Failed to persist verification job: {exc}"
            ) from exc

    async def get_by_sbom_id(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> VerificationJob:
        """Retrieve the most recent verification job for an SBOM.

        Args:
            sbom_id: The UUID of the SBOM.
            tenant_id: Tenant scope.

        Returns:
            The most recent VerificationJob for this SBOM.

        Raises:
            VerificationJobNotFoundError: If no job exists.
        """
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT * FROM verification_jobs
                    WHERE sbom_id = $1 AND tenant_id = $2
                    ORDER BY submitted_at DESC
                    LIMIT 1
                    """,
                    sbom_id,
                    tenant_id,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(
                f"Failed to fetch verification job for SBOM {sbom_id}: {exc}"
            ) from exc

        if row is None:
            raise VerificationJobNotFoundError(sbom_id=str(sbom_id))
        return _row_to_verification_job(row)

    async def update(self, job: VerificationJob) -> None:
        """Persist updated state for an existing verification job.

        Args:
            job: The VerificationJob entity with updated state.

        Raises:
            SbomStorageError: If the update fails.
        """
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE verification_jobs
                    SET status             = $1,
                        completed_at       = $2,
                        signing_identity   = $3,
                        issuer             = $4,
                        rekor_entry_uuid   = $5,
                        failure_reason     = $6
                    WHERE verification_job_id = $7
                    """,
                    job.status,
                    job.completed_at,
                    job.signing_identity,
                    job.issuer,
                    job.rekor_entry_uuid,
                    job.failure_reason,
                    job.verification_job_id,
                )
        except asyncpg.PostgresError as exc:
            raise SbomStorageError(
                f"Failed to update verification job {job.verification_job_id}: {exc}"
            ) from exc
