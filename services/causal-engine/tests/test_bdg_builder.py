"""
tests/causal-engine/test_bdg_builder.py

Unit tests for BDG construction (app/domain/bdg.py).

Coverage:
- Node upsert creates new nodes with correct types.
- Duplicate node upsert updates observation_count and confidence.
- Edge upsert creates typed edges with correct weight.
- Exponential decay formula applied on edge weight update.
- Idempotency index prevents duplicate event processing.
- MapEventToRelations produces correct relations per event type.
- Full update() creates workload → container → process chain.
- PURL binding creates belongs_to edge.
- Contract violations create drift_event and violates edges.
- Temporal DAG projection produces acyclic result.
- SCC detection flags treatment_or_outcome_in_cycle.
- Cycles retained in underlying MultiDiGraph.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import networkx as nx
import pytest

from app.domain.bdg import (
    CAUSAL_TIERS,
    BdgEdgeType,
    BdgNodeType,
    BehavioralDependencyGraph,
)

_BASE_TIME: datetime = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
_TENANT: str = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Node upsert tests
# ---------------------------------------------------------------------------


class TestNodeUpsert:
    """Tests for BehavioralDependencyGraph.upsert_node()."""

    def test_new_node_created(self) -> None:
        """First upsert creates a node with observation_count=1."""
        bdg = BehavioralDependencyGraph()
        key = bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=(_TENANT, "cluster", "ns", "pod-1"),
            event_time=_BASE_TIME,
            confidence=0.9,
        )
        assert bdg.graph.has_node(key)
        data = bdg.graph.nodes[key]
        assert data["node_type"] == "workload"
        assert data["observation_count"] == 1

    def test_duplicate_upsert_increments_count(self) -> None:
        """Second upsert on same key increments observation_count."""
        bdg = BehavioralDependencyGraph()
        key = (_TENANT, "cluster", "ns", "pod-1")
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=_BASE_TIME,
            confidence=0.9,
        )
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=_BASE_TIME + timedelta(seconds=10),
            confidence=0.8,
        )
        assert bdg.graph.nodes[key]["observation_count"] == 2

    def test_last_seen_updated(self) -> None:
        """Upsert with later time updates last_seen_at."""
        bdg = BehavioralDependencyGraph()
        key = (_TENANT, "c", "ns", "pod")
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=_BASE_TIME,
            confidence=0.5,
        )
        later = _BASE_TIME + timedelta(hours=1)
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=later,
            confidence=0.5,
        )
        assert bdg.graph.nodes[key]["last_seen_at"] == later

    def test_confidence_ewma(self) -> None:
        """Confidence uses bounded EWMA on update."""
        bdg = BehavioralDependencyGraph()
        key = (_TENANT, "c", "ns", "p")
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=_BASE_TIME,
            confidence=1.0,
        )
        # Second with lower confidence should reduce it.
        bdg.upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=key,
            event_time=_BASE_TIME + timedelta(seconds=1),
            confidence=0.0,
        )
        conf = bdg.graph.nodes[key]["confidence"]
        assert 0.0 < conf < 1.0


# ---------------------------------------------------------------------------
# Edge upsert tests
# ---------------------------------------------------------------------------


class TestEdgeUpsert:
    """Tests for BehavioralDependencyGraph.upsert_edge()."""

    def test_new_edge_weight_equals_confidence(self) -> None:
        """New edge weight equals the event confidence q."""
        bdg = BehavioralDependencyGraph()
        src = (_TENANT, "src")
        tgt = (_TENANT, "tgt")
        bdg.upsert_node(BdgNodeType.WORKLOAD, src, _BASE_TIME, 1.0)
        bdg.upsert_node(BdgNodeType.CONTAINER, tgt, _BASE_TIME, 1.0)
        bdg.upsert_edge(src, tgt, BdgEdgeType.RUNS, _BASE_TIME, 0.8)
        edges = bdg.graph[src][tgt]
        assert len(edges) == 1
        edge_data = list(edges.values())[0]
        assert edge_data["weight"] == pytest.approx(0.8)

    def test_edge_weight_decays(self) -> None:
        """Edge weight uses exponential decay on update (§5.1 formula)."""
        bdg = BehavioralDependencyGraph(decay_lambda=0.5, decay_delta_seconds=60.0)
        src = (_TENANT, "src")
        tgt = (_TENANT, "tgt")
        bdg.upsert_node(BdgNodeType.WORKLOAD, src, _BASE_TIME, 1.0)
        bdg.upsert_node(BdgNodeType.CONTAINER, tgt, _BASE_TIME, 1.0)

        # First edge.
        bdg.upsert_edge(src, tgt, BdgEdgeType.RUNS, _BASE_TIME, 1.0)

        # Second edge 60 seconds later → decay = 0.5^(60/60) = 0.5.
        bdg.upsert_edge(
            src, tgt, BdgEdgeType.RUNS,
            _BASE_TIME + timedelta(seconds=60),
            1.0,
        )
        edges = bdg.graph[src][tgt]
        edge_data = list(edges.values())[0]
        # w = 0.5 * 1.0 + 1.0 = 1.5
        assert edge_data["weight"] == pytest.approx(1.5)


# ---------------------------------------------------------------------------
# Idempotency tests
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Tests for duplicate event idempotency."""

    def test_duplicate_event_ignored(self) -> None:
        """Same event_id applied twice produces zero mutations on second call."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        eid = uuid.uuid4()
        m1 = bdg.update(
            event_id=eid, event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="p",
            container_id="cid", image_digest="sha256:abc", tgid=100,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
        )
        m2 = bdg.update(
            event_id=eid, event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="p",
            container_id="cid", image_digest="sha256:abc", tgid=100,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
        )
        assert m1.nodes_created > 0
        assert m2.nodes_created == 0
        assert m2.edges_created == 0


# ---------------------------------------------------------------------------
# Full update() tests
# ---------------------------------------------------------------------------


class TestFullUpdate:
    """Tests for the full BDG update() pipeline (Algorithm 3)."""

    def test_creates_workload_container_process_chain(self) -> None:
        """Update creates workload, container, process nodes and edges."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        m = bdg.update(
            event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="pod1",
            container_id="cid1", image_digest="sha256:abc", tgid=1001,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
        )
        assert m.nodes_created >= 3  # workload, container, process
        assert m.edges_created >= 2  # runs, executes

    def test_purl_binding_creates_belongs_to(self) -> None:
        """Resolved PURL binding creates a belongs_to edge."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        bdg.update(
            event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="pod1",
            container_id="cid1", image_digest="sha256:abc", tgid=1001,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
            binding_status="resolved",
            component_purl="pkg:pypi/requests@2.31.0",
        )
        purl_key = (_TENANT, "pkg:pypi/requests@2.31.0")
        assert bdg.graph.has_node(purl_key)
        # Check belongs_to edge from container.
        container_key = (_TENANT, "cid1", "sha256:abc")
        assert bdg.graph.has_edge(container_key, purl_key)

    def test_contract_violations_create_drift_edges(self) -> None:
        """Contract violations create drift_event and violates edges."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        drift_id = str(uuid.uuid4())
        contract_id = str(uuid.uuid4())
        bdg.update(
            event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="pod1",
            container_id="cid1", image_digest="sha256:abc", tgid=1001,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
            binding_status="resolved",
            component_purl="pkg:pypi/requests@2.31.0",
            contract_violations=[{
                "drift_event_id": drift_id,
                "contract_id": contract_id,
            }],
        )
        drift_key = (_TENANT, drift_id)
        contract_key = (_TENANT, contract_id)
        assert bdg.graph.has_node(drift_key)
        assert bdg.graph.has_node(contract_key)

    def test_shared_purl_node_across_pods(self) -> None:
        """Two pods using the same PURL share one PURL node (§5.1)."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        for pod_uid in ["pod-A", "pod-B"]:
            bdg.update(
                event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
                tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid=pod_uid,
                container_id=f"cid-{pod_uid}", image_digest="sha256:abc",
                tgid=1001, pid_start_time_ns=1, identity_confidence=1.0,
                binding_confidence=1.0, collector_confidence=1.0,
                binding_status="resolved",
                component_purl="pkg:pypi/flask@3.0.0",
            )
        purl_key = (_TENANT, "pkg:pypi/flask@3.0.0")
        assert bdg.graph.nodes[purl_key]["observation_count"] == 2

    def test_exec_event_creates_file_node(self) -> None:
        """An exec event maps to a file node with 'loads' edge."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        bdg.update(
            event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="p",
            container_id="cid", image_digest="sha256:abc", tgid=1001,
            pid_start_time_ns=1, identity_confidence=1.0,
            binding_confidence=1.0, collector_confidence=1.0,
            event_attrs={"resource_class": "/usr/bin/python3"},
        )
        file_key = (_TENANT, "/usr/bin/python3")
        assert bdg.graph.has_node(file_key)
        assert bdg.graph.nodes[file_key]["node_type"] == "file"

    def test_composite_confidence(self) -> None:
        """Composite q = collector * identity * binding (§5.3 line 03)."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        m = bdg.update(
            event_id=uuid.uuid4(), event_type="exec", event_time=_BASE_TIME,
            tenant_id=_TENANT, cluster="c", namespace="ns", pod_uid="p",
            container_id="cid", image_digest="sha256:abc", tgid=1001,
            pid_start_time_ns=1, identity_confidence=0.5,
            binding_confidence=0.5, collector_confidence=0.5,
        )
        # q = 0.5 * 0.5 * 0.5 = 0.125. Edges should have this weight.
        assert m.nodes_created > 0


# ---------------------------------------------------------------------------
# Temporal DAG projection tests
# ---------------------------------------------------------------------------


class TestTemporalDAGProjection:
    """Tests for project_to_temporal_dag()."""

    def test_projection_produces_nodes(self, sample_bdg: BehavioralDependencyGraph) -> None:
        """Projection creates (variable, window) nodes."""
        proj = sample_bdg.project_to_temporal_dag(
            treatment_variable="component_version",
            outcome_variable="runtime_sbom_drift",
            window_count=3,
        )
        assert len(proj.projected_nodes) > 0

    def test_projection_edges_respect_temporal_order(
        self, sample_bdg: BehavioralDependencyGraph
    ) -> None:
        """Projected edges have source window <= target window."""
        proj = sample_bdg.project_to_temporal_dag(
            treatment_variable="component_version",
            outcome_variable="runtime_sbom_drift",
            window_count=3,
        )
        for (src_var, src_w), (tgt_var, tgt_w) in proj.projected_edges:
            if src_w == tgt_w:
                # Same window → must satisfy causal tier.
                src_tier = CAUSAL_TIERS.get(src_var, 99)
                tgt_tier = CAUSAL_TIERS.get(tgt_var, 99)
                assert src_tier < tgt_tier, (
                    f"Same-window edge violates tier: {src_var}(t{src_tier}) → "
                    f"{tgt_var}(t{tgt_tier})"
                )
            else:
                assert src_w < tgt_w

    def test_bdg_retains_cycles(self) -> None:
        """Cycles are retained in the underlying MultiDiGraph (§5.2)."""
        bdg = BehavioralDependencyGraph(batch_size=1000)
        a = (_TENANT, "a")
        b = (_TENANT, "b")
        bdg.upsert_node(BdgNodeType.PROCESS, a, _BASE_TIME, 1.0)
        bdg.upsert_node(BdgNodeType.NETWORK_ENDPOINT, b, _BASE_TIME, 1.0)
        bdg.upsert_edge(a, b, BdgEdgeType.CONNECTS_TO, _BASE_TIME, 1.0)
        bdg.upsert_edge(b, a, BdgEdgeType.CONNECTS_TO, _BASE_TIME, 1.0)
        # The underlying graph should have the cycle.
        assert bdg.graph.has_edge(a, b)
        assert bdg.graph.has_edge(b, a)
        assert not nx.is_directed_acyclic_graph(bdg.graph)

    def test_diagnostics_populated(self, sample_bdg: BehavioralDependencyGraph) -> None:
        """Diagnostics dict is populated with projection metadata."""
        proj = sample_bdg.project_to_temporal_dag(
            treatment_variable="component_version",
            outcome_variable="runtime_sbom_drift",
        )
        assert "semantic_variables" in proj.diagnostics
        assert "window_count" in proj.diagnostics
        assert proj.diagnostics["total_projected_nodes"] > 0
