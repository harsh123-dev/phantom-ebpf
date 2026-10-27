"""
causal-engine BDG graph domain serialization store.

Provides domain-level JSON-serializable representations and reconstruction
of BehavioralDependencyGraph instances, adhering to Clean Architecture
by eliminating dependencies from domain/application to infrastructure.

Schema:
- Version 1 (canonical):
    version: int
    decay_lambda: float
    decay_delta_seconds: float
    batch_size: int
    events_since_snapshot: int
    nodes: list[dict[natural_key, node_id, node_type, label, ...]]
    edges: list[dict[source_key, target_key, edge_type, edge_id, ...]]
- Backwards compatible with legacy snapshot format:
    nodes: list[dict[key, data]]
    edges: list[dict[source, target, data]]
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from app.domain.bdg import BehavioralDependencyGraph

log: structlog.BoundLogger = structlog.get_logger(__name__)


def _dt_to_str(dt: datetime | str | None) -> str | None:
    """Serialize a datetime to ISO 8601 UTC string.

    Args:
        dt: datetime object, existing ISO string, or None.

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


def _str_to_dt(s: datetime | str | None) -> datetime | None:
    """Deserialize an ISO 8601 UTC string to datetime.

    Args:
        s: ISO 8601 string, datetime object, or None.

    Returns:
        datetime object or None.
    """
    if s is None:
        return None
    if isinstance(s, datetime):
        if s.tzinfo is None:
            return s.replace(tzinfo=UTC)
        return s
    dt = datetime.fromisoformat(str(s))
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
    attributes. Supports both Version 1 canonical schema and legacy
    unversioned snapshot formats.

    Args:
        data: JSON dict produced by ``serialize_bdg`` or legacy snapshot.

    Returns:
        A BehavioralDependencyGraph with the serialized graph state.
    """
    from app.domain.bdg import BehavioralDependencyGraph

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
        if "natural_key" in node_dict:
            key = tuple(node_dict["natural_key"])
            node_id_str = node_dict.get("node_id", "")
            node_type = node_dict.get("node_type", "")
            label = node_dict.get("label", "")
            first_seen_at = _str_to_dt(node_dict.get("first_seen_at"))
            last_seen_at = _str_to_dt(node_dict.get("last_seen_at"))
            confidence = float(node_dict.get("confidence", 0.0))
            observation_count = int(node_dict.get("observation_count", 0))
            raw_evidence = node_dict.get("evidence_refs", [])
        else:
            # Legacy format support: {"key": [...], "data": {...}}
            key = tuple(node_dict.get("key", ()))
            ndata = node_dict.get("data", {})
            node_id_str = str(ndata.get("node_id", ""))
            node_type = ndata.get("node_type", "")
            label = ndata.get("label", "")
            first_seen_at = _str_to_dt(ndata.get("first_seen_at"))
            last_seen_at = _str_to_dt(ndata.get("last_seen_at"))
            confidence = float(ndata.get("confidence", 0.0))
            observation_count = int(ndata.get("observation_count", 0))
            raw_evidence = ndata.get("evidence_refs", [])

        node_id = uuid.UUID(node_id_str) if node_id_str else uuid.uuid4()

        evidence_refs: list[uuid.UUID] = []
        for ref_str in raw_evidence:
            try:
                evidence_refs.append(
                    ref_str if isinstance(ref_str, uuid.UUID) else uuid.UUID(str(ref_str))
                )
            except (ValueError, AttributeError):
                pass

        g.add_node(
            key,
            node_id=node_id,
            node_type=node_type,
            natural_key=key,
            label=label,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            confidence=confidence,
            observation_count=observation_count,
            evidence_refs=evidence_refs,
        )
        bdg._natural_key_to_uuid[key] = node_id

    # Restore edges.
    for edge_dict in data.get("edges", []):
        if "source_key" in edge_dict:
            src = tuple(edge_dict["source_key"])
            tgt = tuple(edge_dict["target_key"])
            edge_type = edge_dict.get("edge_type", "")
            edge_id_str = edge_dict.get("edge_id", "")
            weight = float(edge_dict.get("weight", 0.0))
            last_seen = _str_to_dt(edge_dict.get("last_seen"))
            observation_count = int(edge_dict.get("observation_count", 0))
            raw_evidence_e = edge_dict.get("evidence_refs", [])
        else:
            # Legacy format support: {"source": [...], "target": [...], "data": {...}}
            src = tuple(edge_dict.get("source", ()))
            tgt = tuple(edge_dict.get("target", ()))
            edata = edge_dict.get("data", {})
            edge_type = edata.get("edge_type", "")
            edge_id_str = str(edata.get("edge_id", ""))
            weight = float(edata.get("weight", 0.0))
            last_seen = _str_to_dt(edata.get("last_seen"))
            observation_count = int(edata.get("observation_count", 0))
            raw_evidence_e = edata.get("evidence_refs", [])

        edge_id = uuid.UUID(edge_id_str) if edge_id_str else uuid.uuid4()

        evidence_refs_e: list[uuid.UUID] = []
        for ref_str in raw_evidence_e:
            try:
                evidence_refs_e.append(
                    ref_str if isinstance(ref_str, uuid.UUID) else uuid.UUID(str(ref_str))
                )
            except (ValueError, AttributeError):
                pass

        g.add_edge(
            src,
            tgt,
            edge_type=edge_type,
            edge_id=edge_id,
            weight=weight,
            last_seen=last_seen,
            observation_count=observation_count,
            evidence_refs=evidence_refs_e,
        )

    log.debug(
        "bdg.deserialized",
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
        d_copy["nodes"] = sorted(d["nodes"], key=lambda n: str(n.get("natural_key", n.get("key"))))
        d_copy["edges"] = sorted(
            d["edges"],
            key=lambda e: (
                str(e.get("source_key", e.get("source"))),
                str(e.get("target_key", e.get("target"))),
                e.get("edge_type", e.get("data", {}).get("edge_type", "")),
            ),
        )
        return json.dumps(d_copy, sort_keys=True, default=str)

    s1 = _normalize(d1)
    s2 = _normalize(d2)
    if s1 != s2:
        log.error(
            "bdg.round_trip_mismatch",
            len1=len(s1),
            len2=len(s2),
        )
        return False
    return True
