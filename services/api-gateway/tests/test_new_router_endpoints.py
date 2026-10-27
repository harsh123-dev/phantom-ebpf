"""
Test suite for newly added / enhanced api-gateway endpoints:
- GET /api/v1/sboms
- GET /api/v1/contracts (fallback handling)
- GET /api/v1/contracts/{contract_id} (fallback handling)
- POST /api/v1/bdg/subgraphs:query (fallback handling)
- GET /api/v1/incidents (safe date parsing and fallback handling)
- GET /api/v1/incidents/{incident_id} (fallback handling)
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.interface.dependencies import get_current_principal
from app.interface.routers.contract_router import _EVAL_CONTRACT_RECORD
from app.interface.routers.incident_router import _EVAL_INCIDENT

_TENANT_ID = uuid.uuid4()
_USER_ID = "analyst-001"
_JTI = str(uuid.uuid4())


def _analyst_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        tenant_id=_TENANT_ID,
        user_id=_USER_ID,
        roles=frozenset({PhantomRole.ANALYST, PhantomRole.VIEWER, PhantomRole.ADMIN}),
        token_jti=_JTI,
    )


@pytest.mark.asyncio
async def test_get_sboms_returns_paginated_list() -> None:
    from app.main import create_app

    app = create_app()
    app.state.db_pool = None
    app.dependency_overrides[get_current_principal] = lambda: _analyst_principal()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/sboms")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "next_cursor" in data


@pytest.mark.asyncio
async def test_list_contracts_fallback() -> None:
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_current_principal] = lambda: _analyst_principal()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/contracts")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 1
        assert data["items"][0]["contract_id"] == _EVAL_CONTRACT_RECORD["contract_id"]


@pytest.mark.asyncio
async def test_get_contract_fallback() -> None:
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_current_principal] = lambda: _analyst_principal()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            f"/api/v1/contracts/{_EVAL_CONTRACT_RECORD['contract_id']}"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "record" in data
        assert "workload_selector" in data
        assert "constraints" in data


@pytest.mark.asyncio
async def test_bdg_subgraphs_query_fallback() -> None:
    from app.main import create_app

    app = create_app()
    app.state.db_pool = None
    app.dependency_overrides[get_current_principal] = lambda: _analyst_principal()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/v1/bdg/subgraphs:query",
            json={"snapshot_id": None, "root_node_ids": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0


@pytest.mark.asyncio
async def test_list_incidents_invalid_date_graceful() -> None:
    from app.main import create_app

    app = create_app()
    app.state.db_pool = None
    app.dependency_overrides[get_current_principal] = lambda: _analyst_principal()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/incidents?created_after=28-10-20206")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert data["items"][0]["incident_id"] == _EVAL_INCIDENT["incident_id"]
