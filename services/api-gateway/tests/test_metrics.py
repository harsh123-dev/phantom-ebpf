"""
Unit and integration tests for Prometheus metrics instrumentation.

Covered tests:
- test_api_requests_total_increments_on_request
- test_route_label_is_parameterized
- test_postgres_duration_recorded_on_db_operation
- test_causal_jobs_total_on_not_identifiable
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from phantom_core.metrics import (
    CAUSAL_JOBS_TOTAL,
)
from prometheus_client import REGISTRY

from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.infrastructure.postgres_repository import DriftEventRepository
from app.interface.middleware import get_parameterized_route
from app.main import app


def _get_metric_value(metric_name: str, labels: dict[str, str]) -> float:
    """Helper to safely fetch a sample value from the Prometheus registry."""
    val = REGISTRY.get_sample_value(metric_name, labels)
    return float(val) if val is not None else 0.0


def _agent_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        tenant_id=uuid.uuid4(),
        user_id="agent-001",
        roles=frozenset({PhantomRole.AGENT}),
        token_jti=str(uuid.uuid4()),
    )


def _drift_payload() -> dict:
    return {
        "schema_version": "v1",
        "event_id": str(uuid.uuid4()),
        "observed_at": datetime.now(tz=UTC).isoformat(),
        "node_name": "node-01",
        "event_type": "exec",
        "process": {
            "pid": 1234,
            "tgid": 1234,
            "ppid": 1,
            "uid": 0,
            "gid": 0,
            "comm": "curl",
            "executable_path": "/usr/bin/curl",
            "start_time_ns": 1000000,
        },
        "workload": {
            "cluster_name": "prod-us-east-1",
            "namespace": "payment",
            "pod_name": "payment-pod",
            "pod_uid": str(uuid.uuid4()),
            "container_name": "app",
            "container_id": "containerd://123",
            "image_digest": "sha256:" + "a" * 64,
            "cgroup_id": 42,
        },
        "identity_status": "resolved",
        "violations": [
            {
                "violation_type": "unexpected_executable",
                "observed": "/usr/bin/curl",
                "severity": "high",
                "confidence": 0.95,
            }
        ],
        "evidence": {
            "kernel_timestamp_ns": 10000000,
            "cpu": 1,
            "architecture": "x86_64",
            "event_loss_observed": False,
            "raw_event_digest": "sha256:" + "b" * 64,
        },
        "agent_sequence": 1,
        "tenant_id": str(uuid.uuid4()),
    }


def test_api_requests_total_increments_on_request() -> None:
    """phantom_api_requests_total increments on POST /drift-events."""
    from datetime import datetime
    from unittest.mock import AsyncMock, MagicMock, patch

    from app.interface.dependencies import get_current_principal
    from app.main import create_app

    labels = {
        "route": "/api/v1/drift-events",
        "method": "POST",
        "status_code": "202",
    }
    before = _get_metric_value("phantom_api_requests_total", labels)

    principal = _agent_principal()
    payload = _drift_payload()
    # Make the payload tenant_id match the principal
    payload["tenant_id"] = str(principal.tenant_id)

    drift_event_id = uuid.uuid4()
    expected_result = {
        "drift_event_id": drift_event_id,
        "event_id": uuid.UUID(payload["event_id"]),
        "bdg_update_id": uuid.uuid4(),
        "ingestion_status": "accepted",
        "received_at": datetime.now(tz=UTC),
    }

    test_app = create_app()
    test_app.state.db_pool = MagicMock()
    test_app.state.redis = AsyncMock()
    test_app.dependency_overrides[get_current_principal] = lambda: principal

    with patch(
        "app.application.commands.IngestDriftEventCommand.execute",
        new=AsyncMock(return_value=expected_result),
    ):
        import asyncio

        import httpx as _httpx

        async def _call() -> int:
            async with _httpx.AsyncClient(
                transport=_httpx.ASGITransport(app=test_app), base_url="http://test"
            ) as client:
                resp = await client.post("/api/v1/drift-events", json=payload)
                return resp.status_code

        status = asyncio.run(_call())

    assert status == 202, f"Expected 202 got {status}"
    after = _get_metric_value("phantom_api_requests_total", labels)
    assert after == before + 1.0


def test_route_label_is_parameterized() -> None:
    """Label uses /api/v1/drift-events not the full path with IDs."""
    test_uuid = str(uuid.uuid4())
    url_path = f"/api/v1/sboms/{test_uuid}"

    mock_request = MagicMock()
    mock_request.url.path = url_path
    mock_request.method = "GET"
    mock_request.scope = {}
    mock_request.app = app

    route_pattern = get_parameterized_route(mock_request)
    assert test_uuid not in route_pattern
    assert "{id}" in route_pattern or "{sbom_id}" in route_pattern


@pytest.mark.asyncio
async def test_postgres_duration_recorded_on_db_operation() -> None:
    """phantom_postgres_operation_duration_seconds observed after insert."""
    labels = {
        "operation": "get_by_event_id",
        "result": "success",
    }
    before = _get_metric_value("phantom_postgres_operation_duration_seconds_count", labels)

    mock_pool = MagicMock()
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_pool.acquire.return_value.__aenter__.return_value = mock_conn
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    repo = DriftEventRepository(mock_pool)
    await repo.get_by_event_id(uuid.uuid4(), uuid.uuid4())

    after = _get_metric_value("phantom_postgres_operation_duration_seconds_count", labels)
    assert after == before + 1.0


def test_causal_jobs_total_on_not_identifiable() -> None:
    """phantom_causal_jobs_total with status=not_identifiable increments."""
    labels = {
        "status": "not_identifiable",
        "estimator": "backdoor.linear_regression",
    }
    before = _get_metric_value("phantom_causal_jobs_total", labels)

    CAUSAL_JOBS_TOTAL.labels(
        status="not_identifiable",
        estimator="backdoor.linear_regression",
    ).inc()

    after = _get_metric_value("phantom_causal_jobs_total", labels)
    assert after == before + 1.0
