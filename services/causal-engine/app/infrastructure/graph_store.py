"""
causal-engine NetworkX BDG graph serialization store.

Provides:
- ``serialize_bdg``:   BehavioralDependencyGraph → JSON-serializable dict
- ``deserialize_bdg``: JSON dict → BehavioralDependencyGraph
- ``NetworkXBdgStore``: BdgRepository implementation backed by asyncpg,
  using the serialize/deserialize functions above for JSONB storage.

Round-trip guarantee:
    d = serialize_bdg(bdg)
    bdg2 = deserialize_bdg(d, ...)
    d2 = serialize_bdg(bdg2)
    assert d == d2  # identical JSON output

Design decisions:
- Nodes are keyed by their natural key tuple (list in JSON).
- UUIDs are serialized as strings.
- datetime values use ISO 8601 UTC format.
- NetworkX integer edge keys are NOT preserved; edges are re-keyed by
  (source_key_str, target_key_str, edge_type) for stability.
- The idempotency index is NOT serialized (it is ephemeral worker state).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import structlog

from app.domain.bdg import BehavioralDependencyGraph
from app.domain.entities import BDGSnapshot
from app.domain.ports import BdgRepository

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Graph serialization / deserialization
# ---------------------------------------------------------------------------


def _dt_to_str(dt: datetime | None) -> str | None:
    """Serialize a datetime to ISO 8601 UTC string.

    Args:
        dt: datetime object or None.

    Returns:
        ISO 8601 string or None.
    """
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.isoformat()
    return str(dt)


def _str_to_dt(s: str | None) -> datetime | None:
    """Deserialize an ISO 8601 UTC string to datetime.

    Args:
        s: ISO 8601 string or None.

    Returns:
        datetime object or None.
    """
    if s is None:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def serialize_bdg(bdg: BehavioralDependencyGraph) -> dict[str, Any]:
    """Serialize a BehavioralDependencyGraph to a JSON-serializable dict.

    Preserves:
    - All node types, natural keys, labels, confidence, observation counts
    - Evidence references (as UUID strings)
    - All edge types, weights, temporal data, evidence references
    - Causal tier metadata (stored implicitly in node_type)
    - Graph-level metadata (decay_lambda, decay_delta, batch_size)

    Does NOT preserve:
    - The idempotency index (ephemeral worker state)
    - Internal NetworkX integer edge keys (re-keyed on round-trip)

    Args:
        bdg: BehavioralDependencyGraph to serialize.

    Returns:
        JSON-serializable dict suitable for JSONB storage.
    """
    g = bdg.graph

    # Serialize nodes.
    nodes_out: list[dict[str, Any]] = []
    for node_key in g.nodes:
        data = dict(g.nodes[node_key])
        evidence_refs = [
            str(r) for r in data.get("evidence_refs", [])
        ]
        nodes_out.append({
            "natural_key": list(node_key),            # tuple → list
            "node_id": str(data.get("node_id", "")),
            "node_type": data.get("node_type", ""),
            "label": data.get("label", ""),
            "first_seen_at": _dt_to_str(data.get("first_seen_at")),
            "last_seen_at": _dt_to_str(data.get("last_seen_at")),
            "confidence": float(data.get("confidence", 0.0)),
            "observation_count": int(data.get("observation_count", 0)),
            "evidence_refs": evidence_refs,
        })

    # Serialize edges.
    edges_out: list[dict[str, Any]] = []
    for u, v, _ek, edata in g.edges(data=True, keys=True):
        evidence_refs = [str(r) for r in edata.get("evidence_refs", [])]
        edges_out.append({
            "source_key": list(u),                    # tuple → list
            "target_key": list(v),                    # tuple → list
            "edge_type": edata.get("edge_type", ""),
            "edge_id": str(edata.get("edge_id", uuid.uuid4())),
            "weight": float(edata.get("weight", 0.0)),
            "last_seen": _dt_to_str(edata.get("last_seen")),
            "observation_count": int(edata.get("observation_count", 0)),
            "evidence_refs": evidence_refs,
        })

    return {
        "version": 1,
        "decay_lambda": bdg._decay_lambda,
        "decay_delta_seconds": bdg._decay_delta,
        "batch_size": bdg._batch_size,
        "events_since_snapshot": bdg._events_since_snapshot,
        "nodes": nodes_out,
        "edges": edges_out,
    }


def deserialize_bdg(data: dict[str, Any]) -> BehavioralDependencyGraph:
    """Deserialize a BehavioralDependencyGraph from a JSON-serializable dict.

    Reconstructs the full graph structure including all node and edge
    attributes. Evidence refs are deserialized as uuid.UUID objects.

    The idempotency index is NOT restored (safe: restarts will re-process
    pending messages; the BDG update method is idempotent by design).

    Args:
        data: JSON dict produced by ``serialize_bdg``.

    Returns:
        A BehavioralDependencyGraph with the serialized graph state.
    """
    bdg = BehavioralDependencyGraph(
        decay_lambda=float(data.get("decay_lambda", 0.95)),
        decay_delta_seconds=float(data.get("decay_delta_seconds", 300.0)),
        batch_size=int(data.get("batch_size", 100)),
    )
    # Restore internal counter.
    bdg._events_since_snapshot = int(data.get("events_since_snapshot", 0))

    g = bdg.graph  # The underlying nx.MultiDiGraph.

    # Restore nodes.
    for node_dict in data.get("nodes", []):
        key = tuple(node_dict["natural_key"])
        node_id_str = node_dict.get("node_id", "")
        node_id = uuid.UUID(node_id_str) if node_id_str else uuid.uuid4()

        evidence_refs: list[uuid.UUID] = []
        for ref_str in node_dict.get("evidence_refs", []):
            try:
                evidence_refs.append(uuid.UUID(ref_str))
            except (ValueError, AttributeError):
                pass

        g.add_node(
            key,
            node_id=node_id,
            node_type=node_dict.get("node_type", ""),
            natural_key=key,
            label=node_dict.get("label", ""),
            first_seen_at=_str_to_dt(node_dict.get("first_seen_at")),
            last_seen_at=_str_to_dt(node_dict.get("last_seen_at")),
            confidence=float(node_dict.get("confidence", 0.0)),
            observation_count=int(node_dict.get("observation_count", 0)),
            evidence_refs=evidence_refs,
        )
        bdg._natural_key_to_uuid[key] = node_id

    # Restore edges.
    for edge_dict in data.get("edges", []):
        src = tuple(edge_dict["source_key"])
        tgt = tuple(edge_dict["target_key"])
        edge_id_str = edge_dict.get("edge_id", "")
        edge_id = uuid.UUID(edge_id_str) if edge_id_str else uuid.uuid4()

        evidence_refs_e: list[uuid.UUID] = []
        for ref_str in edge_dict.get("evidence_refs", []):
            try:
                evidence_refs_e.append(uuid.UUID(ref_str))
            except (ValueError, AttributeError):
                pass

        g.add_edge(
            src,
            tgt,
            edge_type=edge_dict.get("edge_type", ""),
            edge_id=edge_id,
            weight=float(edge_dict.get("weight", 0.0)),
            last_seen=_str_to_dt(edge_dict.get("last_seen")),
            observation_count=int(edge_dict.get("observation_count", 0)),
            evidence_refs=evidence_refs_e,
        )

    log.debug(
        "graph_store.deserialized",
        nodes=g.number_of_nodes(),
        edges=g.number_of_edges(),
    )
    return bdg


def round_trip_verify(bdg: BehavioralDependencyGraph) -> bool:
    """Verify that serialize → deserialize → re-serialize is idempotent.

    Produces identical JSON output for both serializations (modulo dict
    ordering, which json.dumps with sort_keys=True normalizes).

    Args:
        bdg: Source BehavioralDependencyGraph.

    Returns:
        True if the round-trip produces identical output.
    """
    d1 = serialize_bdg(bdg)
    bdg2 = deserialize_bdg(d1)
    d2 = serialize_bdg(bdg2)

    # Normalize node/edge list order by sorting on canonical key.
    def _normalize(d: dict[str, Any]) -> str:
        d_copy = dict(d)
        d_copy["nodes"] = sorted(d["nodes"], key=lambda n: str(n["natural_key"]))
        d_copy["edges"] = sorted(
            d["edges"],
            key=lambda e: (str(e["source_key"]), str(e["target_key"]), e["edge_type"]),
        )
        return json.dumps(d_copy, sort_keys=True, default=str)

    s1 = _normalize(d1)
    s2 = _normalize(d2)
    if s1 != s2:
        log.error(
            "graph_store.round_trip_mismatch",
            len1=len(s1),
            len2=len(s2),
        )
        return False
    return True


# ---------------------------------------------------------------------------
# NetworkXBdgStore (BdgRepository port implementation)
# ---------------------------------------------------------------------------


class NetworkXBdgStore(BdgRepository):
    """PostgreSQL-backed BdgRepository using asyncpg for persistence.

    The in-memory BDG (BehavioralDependencyGraph) is the hot write path.
    Snapshots are serialized with ``serialize_bdg`` and stored in the
    ``bdg_snapshots.graph_data`` JSONB column.

    Args:
        pool: asyncpg connection pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with an asyncpg connection pool.

        Args:
            pool: asyncpg.Pool for database access.
        """
        self._pool = pool

    async def save_snapshot(
        self,
        snapshot: BDGSnapshot,
        graph_data: dict[str, Any],
    ) -> None:
        """Persist a BDG snapshot to PostgreSQL.

        ``graph_data`` must already be the output of ``serialize_bdg``.
        Callers should call ``serialize_bdg(bdg)`` before invoking this.

        Args:
            snapshot: BDGSnapshot metadata.
            graph_data: JSON-serializable graph data dict from serialize_bdg.
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO bdg_snapshots (
                    snapshot_id, tenant_id, created_at,
                    node_count, edge_count,
                    event_id_high_watermark, graph_data
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (snapshot_id) DO NOTHING
                """,
                str(snapshot.snapshot_id),
                str(snapshot.tenant_id),
                snapshot.created_at,
                snapshot.node_count,
                snapshot.edge_count,
                str(snapshot.event_id_high_watermark) if snapshot.event_id_high_watermark else None,
                json.dumps(graph_data),
            )
        log.info(
            "graph_store.snapshot_saved",
            snapshot_id=str(snapshot.snapshot_id),
            nodes=snapshot.node_count,
            edges=snapshot.edge_count,
        )

    async def load_snapshot(
        self,
        snapshot_id: uuid.UUID,
    ) -> tuple[BDGSnapshot, dict[str, Any]] | None:
        """Load a BDG snapshot from PostgreSQL by UUID.

        Returns the raw dict (callers should call ``deserialize_bdg`` to
        reconstruct a live BehavioralDependencyGraph).

        Args:
            snapshot_id: UUID of the snapshot to load.

        Returns:
            Tuple of (BDGSnapshot, graph_data) or None if not found.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT snapshot_id, tenant_id, created_at,
                       node_count, edge_count, event_id_high_watermark, graph_data
                FROM bdg_snapshots
                WHERE snapshot_id = $1
                """,
                str(snapshot_id),
            )

        if row is None:
            log.warning("graph_store.snapshot_not_found", snapshot_id=str(snapshot_id))
            return None

        hwm = row["event_id_high_watermark"]
        snapshot = BDGSnapshot(
            snapshot_id=uuid.UUID(row["snapshot_id"]),
            tenant_id=uuid.UUID(row["tenant_id"]),
            created_at=row["created_at"],
            node_count=row["node_count"],
            edge_count=row["edge_count"],
            event_id_high_watermark=uuid.UUID(hwm) if hwm else None,
        )
        graph_data = json.loads(row["graph_data"])
        return snapshot, graph_data

    async def get_latest_snapshot_id(
        self,
        tenant_id: uuid.UUID,
    ) -> uuid.UUID | None:
        """Get the most recent snapshot UUID for a tenant.

        Args:
            tenant_id: Tenant UUID.

        Returns:
            UUID of the latest snapshot, or None.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT snapshot_id
                FROM bdg_snapshots
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                str(tenant_id),
            )

        if row is None:
            return None
        return uuid.UUID(row["snapshot_id"])
