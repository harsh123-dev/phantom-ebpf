"""
api-gateway query use cases.

Read-only orchestrators that delegate to service clients or repositories.
Architecture: imports only from domain ports and infrastructure adapters.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import asyncpg
import structlog

from app.domain.exceptions import ResourceNotFoundError
from app.infrastructure.postgres_repository import (
    AttributionRepository,
    IncidentRepository,
    PCEPSRepository,
)
from app.infrastructure.service_clients import CausalEngineClient, SbomServiceClient

log: structlog.BoundLogger = structlog.get_logger(__name__)


class GetSBOMQuery:
    """Fetch a single SBOM detail from the SBOM service.

    Args:
        sbom_client: SbomServiceClient instance.
    """

    def __init__(self, sbom_client: SbomServiceClient) -> None:
        """Initialise with SBOM service client.

        Args:
            sbom_client: SbomServiceClient.
        """
        self._client = sbom_client

    async def execute(self, sbom_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Fetch SBOM detail.

        Args:
            sbom_id: UUID of the SBOM to fetch.
            tenant_id: Tenant UUID for scope isolation.

        Returns:
            SbomDetailResponse-compatible dict.

        Raises:
            ResourceNotFoundError: If the SBOM does not exist.
            ServiceUnavailableError: If the SBOM service is unreachable.
        """
        return await self._client.get_sbom(sbom_id, tenant_id)


class ListContractsQuery:
    """List behavioral contracts matching query parameters.

    Args:
        sbom_client: SbomServiceClient instance.
    """

    def __init__(self, sbom_client: SbomServiceClient) -> None:
        """Initialise.

        Args:
            sbom_client: SbomServiceClient.
        """
        self._client = sbom_client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """List contracts.

        Args:
            params: Query parameter dict.

        Returns:
            ContractListResponse-compatible dict.
        """
        return await self._client.list_contracts(params)


class GetBDGNodeQuery:
    """Fetch a BDG node from the causal engine.

    Args:
        causal_client: CausalEngineClient instance.
    """

    def __init__(self, causal_client: CausalEngineClient) -> None:
        """Initialise.

        Args:
            causal_client: CausalEngineClient.
        """
        self._client = causal_client

    async def execute(self, node_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Fetch a BDG node.

        Args:
            node_id: UUID of the node.
            tenant_id: Tenant UUID.

        Returns:
            BDG node dict.
        """
        return await self._client.get_bdg_node(node_id, tenant_id)


class GetBDGEdgeQuery:
    """Fetch a BDG edge from the causal engine.

    Args:
        causal_client: CausalEngineClient instance.
    """

    def __init__(self, causal_client: CausalEngineClient) -> None:
        """Initialise.

        Args:
            causal_client: CausalEngineClient.
        """
        self._client = causal_client

    async def execute(self, edge_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Fetch a BDG edge.

        Args:
            edge_id: UUID of the edge.
            tenant_id: Tenant UUID.

        Returns:
            BDG edge dict.
        """
        return await self._client.get_bdg_edge(edge_id, tenant_id)


class QuerySubgraphQuery:
    """Execute a BDG subgraph query against the causal engine.

    Args:
        causal_client: CausalEngineClient instance.
    """

    def __init__(self, causal_client: CausalEngineClient) -> None:
        """Initialise.

        Args:
            causal_client: CausalEngineClient.
        """
        self._client = causal_client

    async def execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a subgraph query.

        Args:
            payload: Subgraph query parameters dict.

        Returns:
            Subgraph response dict.
        """
        return await self._client.query_subgraph(payload)


class GetAttributionQuery:
    """Fetch the current state of an attribution job.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise.

        Args:
            pool: Active asyncpg pool.
        """
        self._repo = AttributionRepository(pool)

    async def execute(
        self, attribution_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch attribution job.

        Args:
            attribution_id: UUID of the job.
            tenant_id: Tenant UUID.

        Returns:
            Attribution job record dict.

        Raises:
            ResourceNotFoundError: If not found.
        """
        row = await self._repo.get_job(attribution_id, tenant_id)
        if row is None:
            raise ResourceNotFoundError(f"Attribution {attribution_id} not found.")
        return dict(row)


class GetIncidentQuery:
    """Fetch incident detail including evidence and tags.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise.

        Args:
            pool: Active asyncpg pool.
        """
        self._repo = IncidentRepository(pool)

    async def execute(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch incident detail.

        Args:
            incident_id: UUID of the incident.
            tenant_id: Tenant UUID.

        Returns:
            Dict with incident, drift_event_ids, attribution_ids, score_ids, tags.

        Raises:
            ResourceNotFoundError: If not found.
        """
        result = await self._repo.get_by_id(incident_id, tenant_id)
        if result is None:
            raise ResourceNotFoundError(f"Incident {incident_id} not found.")
        return result


class ListIncidentsQuery:
    """List incidents with optional filters and cursor pagination.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise.

        Args:
            pool: Active asyncpg pool.
        """
        self._repo = IncidentRepository(pool)

    async def execute(
        self,
        tenant_id: uuid.UUID,
        *,
        status: str | None = None,
        classification: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List incidents.

        Args:
            tenant_id: Tenant UUID.
            status: Optional status filter.
            classification: Optional classification filter.
            created_after: Optional lower bound on created_at.
            created_before: Optional upper bound on created_at.
            limit: Maximum items to return.
            cursor: Opaque pagination cursor.

        Returns:
            Tuple of (list of dicts, next_cursor).
        """
        rows, next_cursor = await self._repo.list_paginated(
            tenant_id,
            status=status,
            classification=classification,
            created_after=created_after,
            created_before=created_before,
            limit=limit,
            cursor=cursor,
        )
        return [dict(r) for r in rows], next_cursor


class GetPCEPSScoreQuery:
    """Fetch a PCEPS score by ID.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise.

        Args:
            pool: Active asyncpg pool.
        """
        self._repo = PCEPSRepository(pool)

    async def execute(
        self, score_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch PCEPS score.

        Args:
            score_id: UUID of the score.
            tenant_id: Tenant UUID.

        Returns:
            Score record dict.

        Raises:
            ResourceNotFoundError: If not found.
        """
        row = await self._repo.get_score(score_id, tenant_id)
        if row is None:
            raise ResourceNotFoundError(f"PCEPS score {score_id} not found.")
        return dict(row)
