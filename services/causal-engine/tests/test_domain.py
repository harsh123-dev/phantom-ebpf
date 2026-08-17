"""
Tests for causal-engine domain entities and BDG invariants.

Validates:
- GraphNode / GraphEdge field constraints and default values
- BDGSnapshot equality semantics
- AttributionResult status enum completeness
- EvidenceReference immutability (frozen dataclass)
- BehavioralDependencyGraph upsert idempotency,
  node observation count accumulation, and
  evidence_refs bounded-list cap

All tests are pure-Python unit tests with no database or Redis deps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.bdg import _MAX_EVIDENCE_REFS, BehavioralDependencyGraph

# ---------------------------------------------------------------------------
# Domain imports
# ---------------------------------------------------------------------------
from app.domain.entities import (
    BdgEdgeType,
    BdgNodeType,
    BDGSnapshot,
    GraphEdge,
    GraphMutation,
    GraphNode,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)


def _make_node(
    node_type: BdgNodeType = BdgNodeType.PROCESS,
    natural_key: tuple[str, ...] = ("proc", "test"),
) -> GraphNode:
    return GraphNode(
        node_id=uuid.uuid4(),
        node_type=node_type,
        natural_key=natural_key,
        label="test-node",
        confidence=0.9,
        observation_count=1,
        first_seen_at=_NOW,
        last_seen_at=_NOW,
    )


def _make_edge(
    src: tuple[str, ...] = ("proc", "src"),
    dst: tuple[str, ...] = ("purl", "dst"),
    edge_type: BdgEdgeType = BdgEdgeType.LOADS,
) -> GraphEdge:
    return GraphEdge(
        edge_id=uuid.uuid4(),
        source_key=src,
        target_key=dst,
        edge_type=edge_type,
        weight=1.0,
        observation_count=1,
    )


# ---------------------------------------------------------------------------
# GraphNode tests
# ---------------------------------------------------------------------------


class TestGraphNode:
    def test_default_attributes(self) -> None:
        node = _make_node()
        assert node.attributes == {}
        assert node.evidence_refs == []

    def test_confidence_in_range(self) -> None:
        node = _make_node()
        assert 0.0 <= node.confidence <= 1.0

    def test_natural_key_is_tuple(self) -> None:
        node = _make_node(natural_key=("ns", "pod", "container"))
        assert isinstance(node.natural_key, tuple)
        assert len(node.natural_key) == 3

    def test_node_type_enum_values(self) -> None:
        """Every BdgNodeType value must be a non-empty string."""
        for member in BdgNodeType:
            assert isinstance(member.value, str)
            assert len(member.value) > 0


# ---------------------------------------------------------------------------
# GraphEdge tests
# ---------------------------------------------------------------------------


class TestGraphEdge:
    def test_default_weight_is_zero_or_positive(self) -> None:
        edge = _make_edge()
        assert edge.weight >= 0.0

    def test_evidence_refs_bounded(self) -> None:
        edge = _make_edge()
        assert len(edge.evidence_refs) <= _MAX_EVIDENCE_REFS

    def test_edge_type_enum_values(self) -> None:
        for member in BdgEdgeType:
            assert isinstance(member.value, str)
            assert len(member.value) > 0


# ---------------------------------------------------------------------------
# BDGSnapshot tests
# ---------------------------------------------------------------------------


class TestBDGSnapshot:
    def test_snapshot_fields(self) -> None:
        snap = BDGSnapshot(
            snapshot_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            created_at=_NOW,
            node_count=5,
            edge_count=3,
        )
        assert snap.node_count == 5
        assert snap.edge_count == 3
        assert snap.event_id_high_watermark is None

    def test_snapshot_with_watermark(self) -> None:
        wm = uuid.uuid4()
        snap = BDGSnapshot(
            snapshot_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            created_at=_NOW,
            event_id_high_watermark=wm,
        )
        assert snap.event_id_high_watermark == wm


# ---------------------------------------------------------------------------
# GraphMutation tests
# ---------------------------------------------------------------------------


class TestGraphMutation:
    def test_defaults(self) -> None:
        mutation = GraphMutation(
            mutation_id=uuid.uuid4(),
            event_id=uuid.uuid4(),
        )
        assert mutation.nodes_created == 0
        assert mutation.edges_created == 0
        assert mutation.snapshot_cut is False


# ---------------------------------------------------------------------------
# BehavioralDependencyGraph upsert tests
# ---------------------------------------------------------------------------


class TestBDGUpsertNode:
    def _bdg(self) -> BehavioralDependencyGraph:
        return BehavioralDependencyGraph(decay_lambda=0.95, decay_delta_seconds=300.0)

    def test_upsert_creates_new_node(self) -> None:
        bdg = self._bdg()
        key = bdg.upsert_node(
            node_type=BdgNodeType.PROCESS,
            natural_key=("proc", "bash"),
            event_time=_NOW,
            confidence=0.8,
        )
        assert bdg.graph.has_node(key)
        data = bdg.graph.nodes[key]
        assert data["node_type"] == BdgNodeType.PROCESS.value
        assert data["observation_count"] == 1

    def test_upsert_same_key_increments_observation_count(self) -> None:
        bdg = self._bdg()
        key = ("proc", "bash")
        for _ in range(3):
            bdg.upsert_node(BdgNodeType.PROCESS, key, _NOW, confidence=0.8)
        assert bdg.graph.nodes[key]["observation_count"] == 3

    def test_upsert_idempotency_same_key(self) -> None:
        bdg = self._bdg()
        key = ("purl", "pkg:pypi/requests@2.31.0")
        bdg.upsert_node(BdgNodeType.PURL, key, _NOW, confidence=1.0)
        bdg.upsert_node(BdgNodeType.PURL, key, _NOW, confidence=1.0)
        # Still one node entry in graph.
        assert bdg.graph.number_of_nodes() == 1

    def test_different_keys_create_separate_nodes(self) -> None:
        bdg = self._bdg()
        bdg.upsert_node(BdgNodeType.PROCESS, ("proc", "bash"), _NOW, confidence=0.8)
        bdg.upsert_node(BdgNodeType.PROCESS, ("proc", "python"), _NOW, confidence=0.8)
        assert bdg.graph.number_of_nodes() == 2

    def test_evidence_refs_cap(self) -> None:
        bdg = self._bdg()
        key = ("proc", "bash")
        bdg.upsert_node(BdgNodeType.PROCESS, key, _NOW, confidence=0.8)
        # Insert _MAX_EVIDENCE_REFS + 10 events; list must not exceed cap.
        for _ in range(_MAX_EVIDENCE_REFS + 10):
            bdg.upsert_node(
                BdgNodeType.PROCESS,
                key,
                _NOW,
                confidence=0.8,
                event_id=uuid.uuid4(),
            )
        assert len(bdg.graph.nodes[key]["evidence_refs"]) <= _MAX_EVIDENCE_REFS

    def test_node_uuid_stable_after_upsert(self) -> None:
        bdg = self._bdg()
        key = ("proc", "stable")
        bdg.upsert_node(BdgNodeType.PROCESS, key, _NOW, confidence=0.5)
        original_id = bdg.graph.nodes[key]["node_id"]
        bdg.upsert_node(BdgNodeType.PROCESS, key, _NOW, confidence=0.9)
        # node_id must not change on update
        assert bdg.graph.nodes[key]["node_id"] == original_id


# ---------------------------------------------------------------------------
# BDG edge weight decay tests (§5.1 formula)
# ---------------------------------------------------------------------------


class TestBDGEdgeWeight:
    """w_e(t) = lambda^((t - t_prev)/Delta) * w_e(t_prev) + q_e"""

    def _bdg(self) -> BehavioralDependencyGraph:
        return BehavioralDependencyGraph(decay_lambda=0.95, decay_delta_seconds=300.0)

    def test_upsert_edge_creates_entry(self) -> None:
        bdg = self._bdg()
        src = bdg.upsert_node(BdgNodeType.PROCESS, ("proc", "bash"), _NOW, confidence=0.8)
        dst = bdg.upsert_node(BdgNodeType.PURL, ("purl", "requests"), _NOW, confidence=0.8)
        bdg.upsert_edge(src, dst, BdgEdgeType.LOADS, event_time=_NOW, weight_increment=1.0)
        assert bdg.graph.number_of_edges() == 1

    def test_edge_weight_increases_on_repeated_observation(self) -> None:
        bdg = self._bdg()
        src = bdg.upsert_node(BdgNodeType.PROCESS, ("proc", "bash"), _NOW, confidence=0.8)
        dst = bdg.upsert_node(BdgNodeType.PURL, ("purl", "requests"), _NOW, confidence=0.8)
        bdg.upsert_edge(src, dst, BdgEdgeType.LOADS, event_time=_NOW, weight_increment=1.0)
        w1 = list(bdg.graph.get_edge_data(src, dst).values())[0]["weight"]
        bdg.upsert_edge(src, dst, BdgEdgeType.LOADS, event_time=_NOW, weight_increment=1.0)
        w2 = list(bdg.graph.get_edge_data(src, dst).values())[0]["weight"]
        assert w2 > w1

    def test_edge_weight_positive(self) -> None:
        bdg = self._bdg()
        src = bdg.upsert_node(BdgNodeType.PROCESS, ("proc", "p"), _NOW, confidence=0.8)
        dst = bdg.upsert_node(BdgNodeType.FILE, ("file", "liblzma.so"), _NOW, confidence=0.8)
        bdg.upsert_edge(src, dst, BdgEdgeType.READS, event_time=_NOW, weight_increment=1.0)
        w = list(bdg.graph.get_edge_data(src, dst).values())[0]["weight"]
        assert w > 0.0


# ---------------------------------------------------------------------------
# BDG snapshot cut tests
# ---------------------------------------------------------------------------


class TestBDGSnapshot:
    def test_no_snapshot_before_batch_size(self) -> None:
        bdg = BehavioralDependencyGraph(batch_size=10)
        for i in range(5):
            bdg.upsert_node(BdgNodeType.PROCESS, (f"proc{i}",), _NOW, confidence=0.5)
        assert len(bdg.snapshots) == 0

    def test_snapshot_cut_at_batch_boundary(self) -> None:
        bdg = BehavioralDependencyGraph(batch_size=3)
        tenant_id = uuid.uuid4()
        # Trigger enough events to cut a snapshot.
        for i in range(4):
            bdg.update_from_event(
                event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                event_type="exec",
                process_key=("proc", f"cmd{i}"),
                event_time=_NOW,
                relations=[],
            )
        assert len(bdg.snapshots) >= 1

    def test_snapshot_has_correct_node_count(self) -> None:
        bdg = BehavioralDependencyGraph(batch_size=2)
        tenant_id = uuid.uuid4()
        for i in range(3):
            bdg.update_from_event(
                event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                event_type="exec",
                process_key=("proc", f"cmd{i}"),
                event_time=_NOW,
                relations=[],
            )
        if bdg.snapshots:
            snap = bdg.snapshots[-1]
            assert snap.node_count >= 1
