"""
Integration tests for api-gateway endpoint contracts.

Tests use httpx.AsyncClient with the ASGI transport (no live server needed).
Database and Redis are mocked via unittest.mock.patch so no real infrastructure
is required to run this suite.

Covered cases:
1. POST /drift-events happy path → 202, outbox record created
2. POST /drift-events duplicate event_id → ingestion_status='duplicate'
3. POST /drift-events missing auth → 401
4. GET /sboms/{id} not found → 404
5. GET /healthz → 200
6. GET /readyz when redis down → 503
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.domain.entities import AuthenticatedPrincipal

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_TENANT_ID = uuid.uuid4()
_USER_ID = "test-agent-001"
_JTI = str(uuid.uuid4())

# ---------------------------------------------------------------------------
# Mock principal helpers
# ---------------------------------------------------------------------------


def _agent_principal() -> AuthenticatedPrincipal:
    """Return a mock AuthenticatedPrincipal with phantom.agent role."""
    from app.domain.entities import AuthenticatedPrincipal, PhantomRole

    return AuthenticatedPrincipal(
        tenant_id=_TENANT_ID,
        user_id=_USER_ID,
        roles=frozenset({PhantomRole.AGENT}),
        token_jti=_JTI,
    )


def _analyst_principal() -> AuthenticatedPrincipal:
    """Return a mock AuthenticatedPrincipal with phantom.analyst role."""
    from app.domain.entities import AuthenticatedPrincipal, PhantomRole

    return AuthenticatedPrincipal(
        tenant_id=_TENANT_ID,
        user_id=_USER_ID,
        roles=frozenset({PhantomRole.ANALYST}),
        token_jti=_JTI,
    )


def _viewer_principal() -> AuthenticatedPrincipal:
    """Return a mock AuthenticatedPrincipal with phantom.viewer role."""
    from app.domain.entities import AuthenticatedPrincipal, PhantomRole

    return AuthenticatedPrincipal(
        tenant_id=_TENANT_ID,
        user_id=_USER_ID,
        roles=frozenset({PhantomRole.VIEWER}),
        token_jti=_JTI,
    )


# ---------------------------------------------------------------------------
# Minimal valid DriftEventIngestRequest payload
# ---------------------------------------------------------------------------


def _drift_payload(event_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Build a minimal valid DriftEventIngestRequest dict.

    Args:
        event_id: Use a specific event_id for idempotency testing.

    Returns:
        Dict compatible with DriftEventIngestRequest.
    """
    eid = event_id or uuid.uuid4()
    return {
        "schema_version": "v1",
        "event_id": str(eid),
        "observed_at": datetime.now(tz=UTC).isoformat(),
        "node_name": "node-01",
        "event_type": "exec",
        "process": {
            "pid": 1234,
            "tgid": 1234,
            "ppid": 1,
            "uid": 1000,
            "gid": 1000,
            "comm": "python3",
            "executable_path": "/usr/bin/python3",
            "start_time_ns": 12345678,
        },
        "workload": {
            "cluster_name": "prod-cluster",
            "namespace": "default",
            "pod_name": "app-pod-001",
            "pod_uid": str(uuid.uuid4()),
            "container_name": "app",
            "container_id": "abc" * 20,
            "image_digest": "sha256:" + "a" * 64,
            "cgroup_id": 42,
        },
        "identity_status": "resolved",
        "violations": [
            {
                "violation_type": "unexpected_executable",
                "observed": "/usr/bin/python3",
                "severity": "high",
                "confidence": 0.95,
            }
        ],
        "evidence": {
            "kernel_timestamp_ns": 9876543210,
            "cpu": 0,
            "architecture": "x86_64",
            "event_loss_observed": False,
            "raw_event_digest": "sha256:" + "b" * 64,
        },
        "agent_sequence": 1,
        "tenant_id": str(_TENANT_ID),
    }


# ---------------------------------------------------------------------------
# App fixture with mocked state
# ---------------------------------------------------------------------------


def _get_test_app_with_mocked_state() -> Any:  # noqa: ANN401
    """Build the FastAPI app and inject mocked db_pool and redis into app.state."""
    from app.main import create_app

    app = create_app()

    # Mock asyncpg pool.
    mock_pool = MagicMock()
    mock_pool.acquire = MagicMock()

    # Mock redis.
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)
    mock_redis.xadd = AsyncMock(return_value="1700000000000-0")
    mock_redis.publish = AsyncMock(return_value=1)

    # Inject into state (bypassing lifespan).
    app.state.db_pool = mock_pool
    app.state.redis = mock_redis

    return app, mock_pool, mock_redis


# ---------------------------------------------------------------------------
# Test: GET /healthz → 200
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Verify /healthz returns 200 regardless of infrastructure state."""

    @pytest.mark.asyncio
    async def test_healthz_returns_200(self) -> None:
        """GET /healthz always returns 200 with {status: ok}."""
        from app.main import create_app

        app = create_app()
        app.state.db_pool = MagicMock()
        app.state.redis = AsyncMock()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Test: GET /readyz — happy path and redis-down
# ---------------------------------------------------------------------------


class TestReadyzEndpoint:
    """Verify /readyz reflects real infrastructure health."""

    @pytest.mark.asyncio
    async def test_readyz_ok_when_both_healthy(self) -> None:
        """GET /readyz returns 200 when DB and Redis are reachable."""
        from app.main import create_app

        app = create_app()

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)

        app.state.db_pool = mock_pool
        app.state.redis = mock_redis

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["db"] == "ok"
        assert response.json()["redis"] == "ok"

    @pytest.mark.asyncio
    async def test_readyz_503_when_redis_down(self) -> None:
        """GET /readyz returns 503 when Redis is unreachable."""
        from app.main import create_app

        app = create_app()

        # DB healthy.
        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_pool.acquire = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

        # Redis down.
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("redis down"))

        app.state.db_pool = mock_pool
        app.state.redis = mock_redis

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/readyz")
        assert response.status_code == 503
        assert "error" in response.json()["redis"]


# ---------------------------------------------------------------------------
# Test: POST /api/v1/drift-events — missing auth → 401
# ---------------------------------------------------------------------------


class TestDriftEventsMissingAuth:
    """Verify unauthenticated drift event POST returns 401."""

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self) -> None:
        """POST /drift-events without Authorization header returns 401."""
        from app.main import create_app

        app = create_app()
        app.state.db_pool = MagicMock()
        app.state.redis = AsyncMock()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/v1/drift-events",
                json=_drift_payload(),
            )
        assert response.status_code == 401
        body = response.json()
        assert "error_code" in body
        assert "UNAUTHENTICATED" in body["error_code"] or "TOKEN" in body["error_code"]


# ---------------------------------------------------------------------------
# Test: POST /api/v1/drift-events — happy path
# ---------------------------------------------------------------------------


class TestDriftEventsHappyPath:
    """Verify successful drift event ingestion with outbox creation."""

    @pytest.mark.asyncio
    async def test_accepted_drift_event(self) -> None:
        """POST /drift-events with valid agent token → 202, ingestion_status=accepted."""
        from app.interface.dependencies import get_current_principal
        from app.main import create_app

        drift_event_id = uuid.uuid4()
        bdg_update_id = uuid.uuid4()
        now = datetime.now(tz=UTC)

        expected_result = {
            "drift_event_id": drift_event_id,
            "event_id": uuid.uuid4(),
            "bdg_update_id": bdg_update_id,
            "ingestion_status": "accepted",
            "received_at": now,
        }

        app = create_app()
        app.state.db_pool = MagicMock()
        app.state.redis = AsyncMock()
        app.state.redis.xadd = AsyncMock(return_value="1700000000000-0")
        app.state.redis.publish = AsyncMock(return_value=1)

        principal = _agent_principal()
        app.dependency_overrides[get_current_principal] = lambda: principal

        with patch(
            "app.application.commands.IngestDriftEventCommand.execute",
            new=AsyncMock(return_value=expected_result),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/api/v1/drift-events",
                    json=_drift_payload(),
                )

        assert response.status_code == 202
        body = response.json()
        assert body["ingestion_status"] == "accepted"
        assert "drift_event_id" in body
        assert "bdg_update_id" in body


# ---------------------------------------------------------------------------
# Test: POST /api/v1/drift-events — duplicate
# ---------------------------------------------------------------------------


class TestDriftEventsDuplicate:
    """Verify duplicate drift event returns duplicate status, not 500."""

    @pytest.mark.asyncio
    async def test_duplicate_returns_duplicate_status(self) -> None:
        """POST /drift-events with known event_id → ingestion_status=duplicate, not 409."""
        from app.interface.dependencies import get_current_principal
        from app.main import create_app

        eid = uuid.uuid4()
        now = datetime.now(tz=UTC)

        duplicate_result = {
            "drift_event_id": uuid.uuid4(),
            "event_id": eid,
            "bdg_update_id": uuid.uuid4(),
            "ingestion_status": "duplicate",
            "received_at": now,
        }

        app = create_app()
        app.state.db_pool = MagicMock()
        app.state.redis = AsyncMock()

        principal = _agent_principal()
        app.dependency_overrides[get_current_principal] = lambda: principal

        with patch(
            "app.application.commands.IngestDriftEventCommand.execute",
            new=AsyncMock(return_value=duplicate_result),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/api/v1/drift-events",
                    json=_drift_payload(event_id=eid),
                )

        assert response.status_code == 202
        body = response.json()
        # Must be duplicate, NOT a 409/500 error.
        assert body["ingestion_status"] == "duplicate"


# ---------------------------------------------------------------------------
# Test: GET /api/v1/sboms/{id} — not found → 404
# ---------------------------------------------------------------------------


class TestSBOMNotFound:
    """Verify SBOM lookup returns 404 when the resource does not exist."""

    @pytest.mark.asyncio
    async def test_sbom_not_found_returns_404(self) -> None:
        """GET /sboms/{id} for a nonexistent SBOM returns 404 with NOT_FOUND code."""
        from app.domain.exceptions import ResourceNotFoundError
        from app.interface.dependencies import get_current_principal
        from app.main import create_app

        app = create_app()
        app.state.db_pool = MagicMock()
        app.state.redis = AsyncMock()

        principal = _viewer_principal()
        app.dependency_overrides[get_current_principal] = lambda: principal

        sbom_id = uuid.uuid4()

        with patch(
            "app.interface.routers.sbom_router.SbomServiceClient",
            autospec=True,
        ) as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get_sbom = AsyncMock(
                side_effect=ResourceNotFoundError(f"SBOM {sbom_id} not found.")
            )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get(f"/api/v1/sboms/{sbom_id}")

        assert response.status_code == 404
        body = response.json()
        assert body.get("error_code") == "NOT_FOUND"
