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


from app.domain.serialization import (
    _dt_to_str,
    _str_to_dt,
    deserialize_bdg,
    round_trip_verify,
    serialize_bdg,
)

__all__ = [
    "_dt_to_str",
    "_str_to_dt",
    "deserialize_bdg",
    "round_trip_verify",
    "serialize_bdg",
    "NetworkXBdgStore",
]


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
                json.dumps(graph_data, default=str),
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
