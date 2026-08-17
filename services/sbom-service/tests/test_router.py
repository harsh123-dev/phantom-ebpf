"""
tests/sbom-service/test_router.py

FastAPI router tests using httpx AsyncClient.

Uses dependency_overrides to inject fake in-memory implementations
of all repositories so no database is required.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.domain.entities import (
    ImageDigest,
    Sbom,
    SbomSource,
    VerificationStatus,
)
from app.domain.exceptions import (
    DuplicateSbomError,
    SbomNotFoundError,
    VerificationAlreadyInProgressError,
    VerificationJobNotFoundError,
)
from app.interface.dependencies import (
    get_enqueue_verification_use_case,
    get_get_sbom_use_case,
    get_get_verification_result_use_case,
    get_ingest_sbom_use_case,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)
_UUID = uuid.uuid4()
_DIGEST = "sha256:" + "a" * 64
_DOC: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.5"}


def _make_sbom_entity(sbom_id: uuid.UUID | None = None) -> Sbom:
    """Build a minimal Sbom entity."""
    from app.domain.entities import SbomDigest

    sid = sbom_id or uuid.uuid4()
    return Sbom(
        sbom_id=sid,
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


# ---------------------------------------------------------------------------
# App fixture with overridden dependencies
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_ingest_use_case() -> AsyncMock:
    """Mock IngestSbomUseCase."""
    return AsyncMock()


@pytest.fixture()
def mock_get_sbom_use_case() -> AsyncMock:
    """Mock GetSbomUseCase."""
    return AsyncMock()


@pytest.fixture()
def mock_enqueue_verify_use_case() -> AsyncMock:
    """Mock EnqueueVerificationUseCase."""
    return AsyncMock()


@pytest.fixture()
def mock_get_verify_use_case() -> AsyncMock:
    """Mock GetVerificationResultUseCase."""
    return AsyncMock()


@pytest_asyncio.fixture()
async def client(
    mock_ingest_use_case: AsyncMock,
    mock_get_sbom_use_case: AsyncMock,
    mock_enqueue_verify_use_case: AsyncMock,
    mock_get_verify_use_case: AsyncMock,
) -> AsyncClient:
    """Build an httpx AsyncClient with overridden use-case dependencies."""
    # Import app here to avoid module-level side effects.
    from app.main import app

    app.dependency_overrides[get_ingest_sbom_use_case] = lambda: mock_ingest_use_case
    app.dependency_overrides[get_get_sbom_use_case] = lambda: mock_get_sbom_use_case
    app.dependency_overrides[
        get_enqueue_verification_use_case
    ] = lambda: mock_enqueue_verify_use_case
    app.dependency_overrides[
        get_get_verification_result_use_case
    ] = lambda: mock_get_verify_use_case

    # Stub lifespan so we don't need a real database.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _noop_lifespan(app):  # type: ignore[misc]
        app.state.db_pool = None
        yield

    app.router.lifespan_context = _noop_lifespan

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Probe tests
# ---------------------------------------------------------------------------


class TestProbes:
    """Tests for /healthz and /readyz probes."""

    @pytest.mark.asyncio
    async def test_healthz_returns_ok(self, client: AsyncClient) -> None:
        """GET /healthz returns 200 with status='ok'."""
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["service"] == "sbom-service"


# ---------------------------------------------------------------------------
# POST /api/v1/sboms
# ---------------------------------------------------------------------------


class TestIngestSbomEndpoint:
    """Tests for POST /api/v1/sboms."""

    def _valid_body(self) -> dict[str, Any]:
        from app.domain.entities import SbomDigest

        doc = _DOC
        return {
            "schema_version": "v1",
            "image_digest": _DIGEST,
            "artifact_uri": "https://example.com/sbom.json",
            "cyclonedx_document": doc,
            "declared_sbom_digest": SbomDigest.compute(doc).value,
            "source": "syft",
            "generated_at": _NOW.isoformat(),
            "tenant_id": str(_UUID),
        }

    @pytest.mark.asyncio
    async def test_successful_ingest_returns_201(
        self,
        client: AsyncClient,
        mock_ingest_use_case: AsyncMock,
    ) -> None:
        """Successful ingest returns 201 with a SbomRecord."""
        from app.application.use_cases.ingest_sbom import IngestSbomResult

        sbom_id = uuid.uuid4()
        mock_ingest_use_case.execute.return_value = IngestSbomResult(
            sbom_id=sbom_id,
            image_digest=_DIGEST,
            sbom_digest=_DIGEST,
            format="CycloneDX",
            spec_version="1.5",
            component_count=0,
            verification_status="pending",
            created_at=_NOW,
        )
        response = await client.post("/api/v1/sboms", json=self._valid_body())
        assert response.status_code == 201
        body = response.json()
        assert body["sbom_id"] == str(sbom_id)
        assert body["verification_status"] == "pending"

    @pytest.mark.asyncio
    async def test_duplicate_returns_409(
        self,
        client: AsyncClient,
        mock_ingest_use_case: AsyncMock,
    ) -> None:
        """DuplicateSbomError from use case → 409."""
        mock_ingest_use_case.execute.side_effect = DuplicateSbomError(
            _DIGEST, "sha256:" + "b" * 64, _DIGEST
        )
        response = await client.post("/api/v1/sboms", json=self._valid_body())
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_invalid_sbom_returns_400(
        self,
        client: AsyncClient,
        mock_ingest_use_case: AsyncMock,
    ) -> None:
        """InvalidSbomError from use case → 400."""
        from app.domain.exceptions import InvalidSbomError

        mock_ingest_use_case.execute.side_effect = InvalidSbomError("bad doc")
        response = await client.post("/api/v1/sboms", json=self._valid_body())
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/v1/sboms/{sbom_id}
# ---------------------------------------------------------------------------


class TestGetSbomEndpoint:
    """Tests for GET /api/v1/sboms/{sbom_id}."""

    @pytest.mark.asyncio
    async def test_get_existing_sbom(
        self,
        client: AsyncClient,
        mock_get_sbom_use_case: AsyncMock,
    ) -> None:
        """Returns 200 with the SBOM detail for an existing record."""
        from app.application.use_cases.get_sbom import GetSbomResult

        sbom_id = uuid.uuid4()
        mock_get_sbom_use_case.execute.return_value = GetSbomResult(
            sbom_id=sbom_id,
            image_digest=_DIGEST,
            sbom_digest=_DIGEST,
            format="CycloneDX",
            spec_version="1.5",
            component_count=0,
            verification_status="pending",
            created_at=_NOW,
            cyclonedx_document=_DOC,
            purl_count=0,
            signature_bundle_uri=None,
            verified_at=None,
            verification_error=None,
        )
        response = await client.get(
            f"/api/v1/sboms/{sbom_id}", params={"tenant_id": str(_UUID)}
        )
        assert response.status_code == 200
        assert response.json()["record"]["sbom_id"] == str(sbom_id)

    @pytest.mark.asyncio
    async def test_sbom_not_found_returns_404(
        self,
        client: AsyncClient,
        mock_get_sbom_use_case: AsyncMock,
    ) -> None:
        """SbomNotFoundError from use case → 404."""
        mock_get_sbom_use_case.execute.side_effect = SbomNotFoundError("missing")
        response = await client.get(
            f"/api/v1/sboms/{uuid.uuid4()}", params={"tenant_id": str(_UUID)}
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/v1/sboms/{sbom_id}/verification
# ---------------------------------------------------------------------------


class TestEnqueueVerificationEndpoint:
    """Tests for POST /api/v1/sboms/{sbom_id}/verification."""

    @pytest.mark.asyncio
    async def test_enqueue_returns_202(
        self,
        client: AsyncClient,
        mock_enqueue_verify_use_case: AsyncMock,
    ) -> None:
        """Successful enqueue returns 202 with job details."""
        from app.application.use_cases.verify_sbom_signature import (
            EnqueueVerificationResult,
        )

        mock_enqueue_verify_use_case.execute.return_value = EnqueueVerificationResult(
            verification_job_id=uuid.uuid4(),
            sbom_id=_UUID,
            status="queued",
            submitted_at=_NOW,
        )
        sbom_id = uuid.uuid4()
        response = await client.post(
            f"/api/v1/sboms/{sbom_id}/verification",
            json={
                "expected_identity": "user@example.com",
                "expected_issuer": "https://accounts.google.com",
                "rekor_required": True,
            },
            params={"tenant_id": str(_UUID)},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "queued"

    @pytest.mark.asyncio
    async def test_already_in_progress_returns_409(
        self,
        client: AsyncClient,
        mock_enqueue_verify_use_case: AsyncMock,
    ) -> None:
        """VerificationAlreadyInProgressError → 409."""
        mock_enqueue_verify_use_case.execute.side_effect = (
            VerificationAlreadyInProgressError(str(_UUID))
        )
        response = await client.post(
            f"/api/v1/sboms/{uuid.uuid4()}/verification",
            json={
                "expected_identity": "user@example.com",
                "expected_issuer": "https://accounts.google.com",
            },
            params={"tenant_id": str(_UUID)},
        )
        assert response.status_code == 409


# ---------------------------------------------------------------------------
# GET /api/v1/sboms/{sbom_id}/verification
# ---------------------------------------------------------------------------


class TestGetVerificationResultEndpoint:
    """Tests for GET /api/v1/sboms/{sbom_id}/verification."""

    @pytest.mark.asyncio
    async def test_get_queued_result(
        self,
        client: AsyncClient,
        mock_get_verify_use_case: AsyncMock,
    ) -> None:
        """Returns 200 with current job state."""
        from app.application.use_cases.verify_sbom_signature import (
            GetVerificationResultResult,
        )

        mock_get_verify_use_case.execute.return_value = GetVerificationResultResult(
            verification_job_id=uuid.uuid4(),
            sbom_id=_UUID,
            status="queued",
            signing_identity=None,
            issuer=None,
            rekor_entry_uuid=None,
            verified_at=None,
            failure_reason=None,
        )
        response = await client.get(
            f"/api/v1/sboms/{_UUID}/verification",
            params={"tenant_id": str(_UUID)},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    @pytest.mark.asyncio
    async def test_job_not_found_returns_404(
        self,
        client: AsyncClient,
        mock_get_verify_use_case: AsyncMock,
    ) -> None:
        """VerificationJobNotFoundError → 404."""
        mock_get_verify_use_case.execute.side_effect = VerificationJobNotFoundError(
            str(_UUID)
        )
        response = await client.get(
            f"/api/v1/sboms/{_UUID}/verification",
            params={"tenant_id": str(_UUID)},
        )
        assert response.status_code == 404
