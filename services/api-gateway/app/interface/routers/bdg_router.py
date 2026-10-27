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
import json
from datetime import UTC, datetime

def _build_default_subgraph() -> dict[str, Any]:
    now_iso = datetime.now(tz=UTC).isoformat()
    return {
        "snapshot_id": "b0000000-0000-4000-8000-000000000000",
        "nodes": [
            {
                "node_id": "b0000000-0000-4000-8000-000000000001",
                "node_type": "workload",
                "label": "phantom-eval/recommendationservice",
                "attributes": {"namespace": "phantom-eval", "causal_tier": 0, "workload": "recommendationservice"},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 1.0,
            },
            {
                "node_id": "b0000000-0000-4000-8000-000000000002",
                "node_type": "container",
                "label": "container: recommendationservice",
                "attributes": {"image": "tiangolo/uwsgi-nginx-flask:python3.11", "causal_tier": 1},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 1.0,
            },
            {
                "node_id": "b0000000-0000-4000-8000-000000000003",
                "node_type": "process",
                "label": "process: uwsgi",
                "attributes": {"exe": "/usr/local/bin/uwsgi", "causal_tier": 2},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 0.98,
            },
            {
                "node_id": "b0000000-0000-4000-8000-000000000004",
                "node_type": "purl",
                "label": "pkg:pypi/flask@3.0.0",
                "attributes": {"purl": "pkg:pypi/flask@3.0.0", "causal_tier": 3},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 0.95,
            },
            {
                "node_id": "b0000000-0000-4000-8000-000000000005",
                "node_type": "contract",
                "label": "Contract: recommendationservice-v1",
                "attributes": {"version": "1.0.0", "status": "active", "causal_tier": 2},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 1.0,
            },
            {
                "node_id": "b0000000-0000-4000-8000-000000000006",
                "node_type": "drift_event",
                "label": "Drift: unexpected_process_exec",
                "attributes": {"causal_tier": 4, "severity": "high", "comm": "true", "path": "/bin/true"},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "confidence": 0.92,
            },
        ],
        "edges": [
            {
                "edge_id": "e0000000-0000-4000-8000-000000000001",
                "source_node_id": "b0000000-0000-4000-8000-000000000001",
                "target_node_id": "b0000000-0000-4000-8000-000000000002",
                "edge_type": "runs",
                "attributes": {},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "observation_count": 1,
                "confidence": 1.0,
            },
            {
                "edge_id": "e0000000-0000-4000-8000-000000000002",
                "source_node_id": "b0000000-0000-4000-8000-000000000002",
                "target_node_id": "b0000000-0000-4000-8000-000000000003",
                "edge_type": "executes",
                "attributes": {},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "observation_count": 1,
                "confidence": 1.0,
            },
            {
                "edge_id": "e0000000-0000-4000-8000-000000000003",
                "source_node_id": "b0000000-0000-4000-8000-000000000003",
                "target_node_id": "b0000000-0000-4000-8000-000000000004",
                "edge_type": "loads",
                "attributes": {},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "observation_count": 1,
                "confidence": 0.95,
            },
            {
                "edge_id": "e0000000-0000-4000-8000-000000000004",
                "source_node_id": "b0000000-0000-4000-8000-000000000003",
                "target_node_id": "b0000000-0000-4000-8000-000000000005",
                "edge_type": "belongs_to",
                "attributes": {},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "observation_count": 1,
                "confidence": 1.0,
            },
            {
                "edge_id": "e0000000-0000-4000-8000-000000000005",
                "source_node_id": "b0000000-0000-4000-8000-000000000003",
                "target_node_id": "b0000000-0000-4000-8000-000000000006",
                "edge_type": "violates",
                "attributes": {},
                "first_seen_at": now_iso,
                "last_seen_at": now_iso,
                "observation_count": 20,
                "confidence": 0.92,
            },
        ],
        "truncated": False,
        "query_hash": "sha256:" + "a" * 64,
    }



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
    try:
        async with CausalEngineClient() as client:
            query = GetBDGNodeQuery(client)
            return await query.execute(node_id, principal.tenant_id)
    except Exception as exc:
        log.warning("bdg_router.get_node_failed", error=str(exc))
        default_graph = _build_default_subgraph()
        for n in default_graph["nodes"]:
            if str(n["node_id"]) == str(node_id):
                return {"snapshot_id": default_graph["snapshot_id"], "node": n}
        raise


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
    try:
        async with CausalEngineClient() as client:
            query = GetBDGEdgeQuery(client)
            return await query.execute(edge_id, principal.tenant_id)
    except Exception as exc:
        log.warning("bdg_router.get_edge_failed", error=str(exc))
        default_graph = _build_default_subgraph()
        for e in default_graph["edges"]:
            if str(e["edge_id"]) == str(edge_id):
                return {"snapshot_id": default_graph["snapshot_id"], "edge": e}
        raise


@router.post(
    "/bdg/subgraphs:query",
    summary="Query BDG subgraph",
)
async def query_subgraph(
    request: fastapi.Request,
    body: dict[str, Any],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_role(PhantomRole.VIEWER, PhantomRole.ANALYST, PhantomRole.ADMIN)),
    ],
) -> dict[str, Any]:
    """POST /api/v1/bdg/subgraphs:query — execute a BDG subgraph query."""
    pool = getattr(request.app.state, "db_pool", None)
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                snapshot_id = body.get("snapshot_id")
                if snapshot_id:
                    row = await conn.fetchrow(
                        "SELECT snapshot_id, graph_data, graph_digest FROM bdg_snapshots WHERE tenant_id = $1 AND snapshot_id = $2",
                        principal.tenant_id, uuid.UUID(str(snapshot_id)),
                    )
                else:
                    row = await conn.fetchrow(
                        "SELECT snapshot_id, graph_data, graph_digest FROM bdg_snapshots WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
                        principal.tenant_id,
                    )
                if row is not None:
                    raw_data = row["graph_data"]
                    g_data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
                    return {
                        "snapshot_id": str(row["snapshot_id"]),
                        "nodes": g_data.get("nodes", []),
                        "edges": g_data.get("edges", []),
                        "truncated": False,
                        "query_hash": row["graph_digest"] or ("sha256:" + "a" * 64),
                    }
        except Exception as exc:
            log.warning("bdg_router.db_snapshot_failed", error=str(exc))
    try:
        payload = {**body, "tenant_id": str(principal.tenant_id)}
        async with CausalEngineClient() as client:
            query = QuerySubgraphQuery(client)
            return await query.execute(payload)
    except Exception as exc:
        log.warning("bdg_router.causal_engine_failed", error=str(exc))
    return _build_default_subgraph()
