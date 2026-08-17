"""
api-gateway BDG query endpoints router.

Implements:
  GET    /api/v1/bdg/nodes/{node_id}
  GET    /api/v1/bdg/edges/{edge_id}
  POST   /api/v1/bdg/subgraphs:query
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import fastapi
import structlog
from fastapi import Depends

from app.application.queries import GetBDGEdgeQuery, GetBDGNodeQuery, QuerySubgraphQuery
from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.infrastructure.service_clients import CausalEngineClient
from app.interface.dependencies import require_role

router = fastapi.APIRouter(tags=["BDG"])
log: structlog.BoundLogger = structlog.get_logger(__name__)


@router.get(
    "/bdg/nodes/{node_id}",
    summary="Get a BDG node",
)
async def get_bdg_node(
    node_id: uuid.UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/bdg/nodes/{node_id} — fetch a single BDG node.

    Args:
        node_id: UUID of the node.
        principal: Verified JWT principal.

    Returns:
        BDG node dict from the causal engine.
    """
    async with CausalEngineClient() as client:
        query = GetBDGNodeQuery(client)
        return await query.execute(node_id, principal.tenant_id)


@router.get(
    "/bdg/edges/{edge_id}",
    summary="Get a BDG edge",
)
async def get_bdg_edge(
    edge_id: uuid.UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """GET /api/v1/bdg/edges/{edge_id} — fetch a single BDG edge.

    Args:
        edge_id: UUID of the edge.
        principal: Verified JWT principal.

    Returns:
        BDG edge dict from the causal engine.
    """
    async with CausalEngineClient() as client:
        query = GetBDGEdgeQuery(client)
        return await query.execute(edge_id, principal.tenant_id)


@router.post(
    "/bdg/subgraphs:query",
    summary="Query BDG subgraph",
)
async def query_subgraph(
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/bdg/subgraphs:query — execute a BDG subgraph query.

    Args:
        body: Subgraph query parameters dict.
        principal: Verified JWT principal.

    Returns:
        Subgraph response dict from the causal engine.
    """
    payload = {**body, "tenant_id": str(principal.tenant_id)}
    async with CausalEngineClient() as client:
        query = QuerySubgraphQuery(client)
        return await query.execute(payload)
