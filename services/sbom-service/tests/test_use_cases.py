"""
tests/sbom-service/test_use_cases.py

Use-case tests with mocked repositories and ports.

Uses unittest.mock.AsyncMock to satisfy all async port methods without I/O.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.application.use_cases.get_sbom import GetSbomQuery, GetSbomUseCase
from app.application.use_cases.ingest_sbom import (
    IngestSbomCommand,
    IngestSbomUseCase,
)
from app.application.use_cases.verify_sbom_signature import (
    EnqueueVerificationCommand,
    EnqueueVerificationUseCase,
    GetVerificationResultQuery,
    GetVerificationResultUseCase,
)
from app.domain.entities import (
    ImageDigest,
    Sbom,
    SbomDigest,
    SbomSource,
    VerificationJob,
    VerificationStatus,
)
from app.domain.exceptions import (
    DuplicateSbomError,
    InvalidSbomError,
    SbomNotFoundError,
    VerificationAlreadyInProgressError,
    VerificationJobNotFoundError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)
_UUID = uuid.uuid4()
_DIGEST = "sha256:" + "a" * 64
_DOC = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _make_sbom_entity(sbom_id: uuid.UUID | None = None) -> Sbom:
    """Build a minimal Sbom entity for mock returns."""
    return Sbom(
        sbom_id=sbom_id or uuid.uuid4(),
        tenant_id=_UUID,
        image_digest=ImageDigest(value=_DIGEST),
        sbom_digest=SbomDigest(value=_DIGEST),
        cyclonedx_document=_DOC,
        spec_version="1.5",
        source=SbomSource.SYFT,
        artifact_uri="https://example.com/sbom.json",
        signature_bundle_uri=None,
        verification_status=VerificationStatus.PENDING,
        generated_at=_NOW,
        created_at=_NOW,
        purl_count=0,
    )


def _make_job(sbom_id: uuid.UUID, status: str = "queued") -> VerificationJob:
    """Build a minimal VerificationJob for mock returns."""
    return VerificationJob(
        verification_job_id=uuid.uuid4(),
        sbom_id=sbom_id,
        tenant_id=_UUID,
        expected_identity="user@example.com",
        expected_issuer="https://accounts.google.com",
        rekor_required=True,
        status=status,
        submitted_at=_NOW,
    )


# ---------------------------------------------------------------------------
# IngestSbomUseCase
# ---------------------------------------------------------------------------


class TestIngestSbomUseCase:
    """Tests for IngestSbomUseCase."""

    def _make_command(self, **overrides) -> IngestSbomCommand:
        defaults = dict(
            tenant_id=_UUID,
            image_digest=_DIGEST,
            artifact_uri="https://example.com/sbom.json",
            cyclonedx_document=_DOC,
            declared_sbom_digest=SbomDigest.compute(_DOC).value,
            source="syft",
            generated_at=_NOW,
        )
        defaults.update(overrides)
        return IngestSbomCommand(**defaults)

    @pytest.mark.asyncio
    async def test_successful_ingest(self) -> None:
        """Happy path: valid document persisted and artifact uploaded."""
        sbom_repo = AsyncMock()
        component_repo = AsyncMock()
        artifact_store = AsyncMock()
        artifact_store.upload_sbom.return_value = "s3://bucket/key"

        use_case = IngestSbomUseCase(
            sbom_repo=sbom_repo,
            component_repo=component_repo,
            artifact_store=artifact_store,
        )
        result = await use_case.execute(self._make_command())

        assert result.format == "CycloneDX"
        assert result.verification_status == "pending"
        sbom_repo.save.assert_awaited_once()
        artifact_store.upload_sbom.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_cyclonedx_document_raises(self) -> None:
        """Non-CycloneDX document raises InvalidSbomError."""
        sbom_repo = AsyncMock()
        component_repo = AsyncMock()
        artifact_store = AsyncMock()

        use_case = IngestSbomUseCase(
            sbom_repo=sbom_repo,
            component_repo=component_repo,
            artifact_store=artifact_store,
        )
        with pytest.raises(InvalidSbomError):
            await use_case.execute(
                self._make_command(
                    cyclonedx_document={"bomFormat": "SPDX"},
                    declared_sbom_digest=SbomDigest.compute({"bomFormat": "SPDX"}).value,
                )
            )

    @pytest.mark.asyncio
    async def test_digest_mismatch_raises(self) -> None:
        """Wrong declared_sbom_digest raises DigestMismatchError."""
        from app.domain.exceptions import DigestMismatchError

        sbom_repo = AsyncMock()
        component_repo = AsyncMock()
        artifact_store = AsyncMock()

        use_case = IngestSbomUseCase(
            sbom_repo=sbom_repo,
            component_repo=component_repo,
            artifact_store=artifact_store,
        )
        with pytest.raises(DigestMismatchError):
            await use_case.execute(
                self._make_command(declared_sbom_digest="sha256:" + "b" * 64)
            )

    @pytest.mark.asyncio
    async def test_duplicate_sbom_propagates(self) -> None:
        """DuplicateSbomError from repo propagates out of the use case."""
        sbom_repo = AsyncMock()
        sbom_repo.save.side_effect = DuplicateSbomError(
            _DIGEST, "sha256:" + "b" * 64, _DIGEST
        )
        component_repo = AsyncMock()
        artifact_store = AsyncMock()

        use_case = IngestSbomUseCase(
            sbom_repo=sbom_repo,
            component_repo=component_repo,
            artifact_store=artifact_store,
        )
        with pytest.raises(DuplicateSbomError):
            await use_case.execute(self._make_command())


# ---------------------------------------------------------------------------
# GetSbomUseCase
# ---------------------------------------------------------------------------


class TestGetSbomUseCase:
    """Tests for GetSbomUseCase."""

    @pytest.mark.asyncio
    async def test_get_existing_sbom(self) -> None:
        """Returns result DTO for an existing SBOM."""
        sbom_id = uuid.uuid4()
        entity = _make_sbom_entity(sbom_id=sbom_id)
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.return_value = entity

        use_case = GetSbomUseCase(sbom_repo=sbom_repo)
        result = await use_case.execute(
            GetSbomQuery(sbom_id=sbom_id, tenant_id=_UUID)
        )
        assert result.sbom_id == sbom_id
        assert result.format == "CycloneDX"

    @pytest.mark.asyncio
    async def test_sbom_not_found_propagates(self) -> None:
        """SbomNotFoundError from repo propagates out."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.side_effect = SbomNotFoundError("missing")

        use_case = GetSbomUseCase(sbom_repo=sbom_repo)
        with pytest.raises(SbomNotFoundError):
            await use_case.execute(GetSbomQuery(sbom_id=_UUID, tenant_id=_UUID))


# ---------------------------------------------------------------------------
# EnqueueVerificationUseCase
# ---------------------------------------------------------------------------


class TestEnqueueVerificationUseCase:
    """Tests for EnqueueVerificationUseCase."""

    def _make_command(self) -> EnqueueVerificationCommand:
        return EnqueueVerificationCommand(
            sbom_id=_UUID,
            tenant_id=_UUID,
            expected_identity="user@example.com",
            expected_issuer="https://accounts.google.com",
            rekor_required=True,
        )

    @pytest.mark.asyncio
    async def test_enqueue_new_job(self) -> None:
        """Creates a new queued job when no existing job is present."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.return_value = _make_sbom_entity()
        job_repo = AsyncMock()
        # Simulate no existing job.
        job_repo.get_by_sbom_id.side_effect = VerificationJobNotFoundError(str(_UUID))

        use_case = EnqueueVerificationUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        result = await use_case.execute(self._make_command())
        assert result.status == "queued"
        job_repo.save.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_enqueue_rejects_if_in_progress(self) -> None:
        """Raises VerificationAlreadyInProgressError if a job is running."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.return_value = _make_sbom_entity()
        job_repo = AsyncMock()
        job_repo.get_by_sbom_id.return_value = _make_job(_UUID, status="running")

        use_case = EnqueueVerificationUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        with pytest.raises(VerificationAlreadyInProgressError):
            await use_case.execute(self._make_command())

    @pytest.mark.asyncio
    async def test_enqueue_sbom_not_found(self) -> None:
        """Raises SbomNotFoundError when the SBOM does not exist."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.side_effect = SbomNotFoundError(str(_UUID))
        job_repo = AsyncMock()

        use_case = EnqueueVerificationUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        with pytest.raises(SbomNotFoundError):
            await use_case.execute(self._make_command())

    @pytest.mark.asyncio
    async def test_enqueue_ok_after_previous_failure(self) -> None:
        """Re-enqueue is allowed when the previous job status is 'failed'."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.return_value = _make_sbom_entity()
        job_repo = AsyncMock()
        job_repo.get_by_sbom_id.return_value = _make_job(_UUID, status="failed")

        use_case = EnqueueVerificationUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        result = await use_case.execute(self._make_command())
        assert result.status == "queued"


# ---------------------------------------------------------------------------
# GetVerificationResultUseCase
# ---------------------------------------------------------------------------


class TestGetVerificationResultUseCase:
    """Tests for GetVerificationResultUseCase."""

    @pytest.mark.asyncio
    async def test_get_queued_result(self) -> None:
        """Returns the queued job state."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.return_value = _make_sbom_entity()
        job_repo = AsyncMock()
        job_repo.get_by_sbom_id.return_value = _make_job(_UUID, status="queued")

        use_case = GetVerificationResultUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        result = await use_case.execute(
            GetVerificationResultQuery(sbom_id=_UUID, tenant_id=_UUID)
        )
        assert result.status == "queued"

    @pytest.mark.asyncio
    async def test_get_result_sbom_not_found(self) -> None:
        """SbomNotFoundError propagates when SBOM is absent."""
        sbom_repo = AsyncMock()
        sbom_repo.get_by_id.side_effect = SbomNotFoundError(str(_UUID))
        job_repo = AsyncMock()

        use_case = GetVerificationResultUseCase(
            sbom_repo=sbom_repo, job_repo=job_repo
        )
        with pytest.raises(SbomNotFoundError):
            await use_case.execute(
                GetVerificationResultQuery(sbom_id=_UUID, tenant_id=_UUID)
            )
