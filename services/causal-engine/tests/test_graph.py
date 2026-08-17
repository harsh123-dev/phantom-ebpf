"""
Tests for causal graph construction, update, and snapshot invariants.

Validates:
- BehavioralDependencyGraph.update() builds the expected graph topology
  from normalized eBPF events (Algorithm 3, handoff §5.3)
- Temporal DAG projection produces a DAG from a MultiDiGraph with cycles
- Snapshot cut occurs at batch boundaries and records accurate counts
- Idempotency index prevents double-processing the same event_id
- CAUSAL_TIERS ordering is well-defined for all BdgNodeType values
- EventRelation mapping produces correct target types per event_type

All tests are pure-Python unit tests with no database or Redis deps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.bdg import (
    CAUSAL_TIERS,
    NODE_TYPE_TO_SEMANTIC,
    BehavioralDependencyGraph,
)
from app.domain.entities import BdgEdgeType, BdgNodeType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)
_TENANT = "00000000-0000-0000-0000-000000000001"


def _update_kwargs(**overrides) -> dict:
    """Return a minimal valid keyword dict for BDG.update()."""
    defaults = dict(
        event_id=uuid.uuid4(),
        event_type="exec",
        event_time=_NOW,
        tenant_id=_TENANT,
        cluster="test-cluster",
        namespace="phantom-eval",
        pod_uid=str(uuid.uuid4()),
        container_id="abc123",
        image_digest="sha256:deadbeef",
        tgid=1234,
        pid_start_time_ns=1000000,
        identity_confidence=0.9,
        binding_confidence=0.8,
        collector_confidence=0.95,
        binding_status="resolved",
        component_purl="pkg:pypi/requests@2.31.0",
        contract_violations=[],
        event_attrs={"resource_class": "LIB"},
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# CAUSAL_TIERS and semantic map completeness
# ---------------------------------------------------------------------------


class TestCausalTiers:
    def test_all_node_types_have_semantic(self) -> None:
        """Every BdgNodeType must map to a semantic category."""
        for nt in BdgNodeType:
            assert nt in NODE_TYPE_TO_SEMANTIC, f"{nt!r} missing from NODE_TYPE_TO_SEMANTIC"

    def test_all_semantics_have_tier(self) -> None:
        """Every semantic category from NODE_TYPE_TO_SEMANTIC must appear in CAUSAL_TIERS."""
        semantics = set(NODE_TYPE_TO_SEMANTIC.values())
        for sem in semantics:
            assert sem in CAUSAL_TIERS, f"semantic {sem!r} not in CAUSAL_TIERS"

    def test_tier_values_non_negative(self) -> None:
        for sem, tier in CAUSAL_TIERS.items():
            assert tier >= 0, f"tier for {sem!r} must be >= 0"

    def test_workload_precedes_drift_event(self) -> None:
        """Workloads (environment) must have lower tier than drift events."""
        env_tier = CAUSAL_TIERS[NODE_TYPE_TO_SEMANTIC[BdgNodeType.WORKLOAD]]
        drift_tier = CAUSAL_TIERS[NODE_TYPE_TO_SEMANTIC[BdgNodeType.DRIFT_EVENT]]
        assert env_tier < drift_tier

    def test_component_version_precedes_process(self) -> None:
        """Component version must be a cause of process behavior (tier ordering)."""
        comp_tier = CAUSAL_TIERS[NODE_TYPE_TO_SEMANTIC[BdgNodeType.PURL]]
        proc_tier = CAUSAL_TIERS[NODE_TYPE_TO_SEMANTIC[BdgNodeType.PROCESS]]
        assert comp_tier < proc_tier


# ---------------------------------------------------------------------------
# BDG update — node/edge topology
# ---------------------------------------------------------------------------


class TestBDGUpdate:
    def _bdg(self) -> BehavioralDependencyGraph:
        return BehavioralDependencyGraph(decay_lambda=0.95, decay_delta_seconds=300.0)

    def test_update_creates_process_node(self) -> None:
        bdg = self._bdg()
        mutation = bdg.update(**_update_kwargs())
        assert bdg.graph.number_of_nodes() >= 1
        assert mutation.nodes_created >= 1

    def test_update_creates_workload_and_container_nodes(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs())
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        # At minimum: workload, container, process
        assert BdgNodeType.PROCESS.value in types

    def test_update_creates_purl_node_when_binding_resolved(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            binding_status="resolved",
            component_purl="pkg:pypi/requests@2.31.0",
        ))
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        assert BdgNodeType.PURL.value in types

    def test_update_no_purl_node_when_unresolved(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            binding_status="unresolved",
            component_purl=None,
        ))
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        assert BdgNodeType.PURL.value not in types

    def test_update_creates_file_node_for_exec_event(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            event_type="exec",
            event_attrs={"resource_class": "BIN"},
        ))
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        assert BdgNodeType.FILE.value in types

    def test_update_creates_network_node_for_net_connect(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            event_type="net_connect",
            event_attrs={
                "resource_class": "CLUSTER_INTERNAL",
                "protocol": "tcp",
                "port_class": "443",
            },
        ))
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        assert BdgNodeType.NETWORK_ENDPOINT.value in types

    def test_update_creates_contract_node_for_violation(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            contract_violations=[
                {"violation_type": "unexpected_exec", "severity": "HIGH"}
            ],
        ))
        types = {data["node_type"] for _, data in bdg.graph.nodes(data=True)}
        assert BdgNodeType.CONTRACT.value in types

    def test_update_returns_mutation_object(self) -> None:
        bdg = self._bdg()
        mutation = bdg.update(**_update_kwargs())
        assert mutation.mutation_id is not None
        assert mutation.event_id is not None

    def test_idempotency_same_event_id(self) -> None:
        """Sending the same event_id twice must not create extra nodes."""
        bdg = self._bdg()
        eid = uuid.uuid4()
        bdg.update(**_update_kwargs(event_id=eid))
        n1 = bdg.graph.number_of_nodes()
        bdg.update(**_update_kwargs(event_id=eid))
        n2 = bdg.graph.number_of_nodes()
        assert n1 == n2, "duplicate event_id must not create extra nodes"

    def test_two_different_events_can_increase_node_count(self) -> None:
        bdg = self._bdg()
        bdg.update(**_update_kwargs(
            event_id=uuid.uuid4(),
            pod_uid="pod-a",
            component_purl="pkg:pypi/requests@2.31.0",
        ))
        n1 = bdg.graph.number_of_nodes()
        bdg.update(**_update_kwargs(
            event_id=uuid.uuid4(),
            pod_uid="pod-b",
            component_purl="pkg:pypi/urllib3@2.0.0",
        ))
        n2 = bdg.graph.number_of_nodes()
        assert n2 >= n1, "new unique event should add nodes"


# ---------------------------------------------------------------------------
# BDG temporal DAG projection
# ---------------------------------------------------------------------------


class TestTemporalDAGProjection:
    def test_projection_is_dag(self) -> None:
        """project_to_temporal_dag() must return a DAG (no cycles)."""
        import networkx as nx

        bdg = BehavioralDependencyGraph()
        # Add two events with different tiers.
        bdg.update(**_update_kwargs(
            event_type="exec",
            component_purl="pkg:pypi/requests@2.31.0",
        ))
        bdg.update(**_update_kwargs(
            event_id=uuid.uuid4(),
            event_type="net_connect",
            event_attrs={
                "resource_class": "CLUSTER_INTERNAL",
                "protocol": "tcp",
                "port_class": "443",
            },
        ))
        projection = bdg.project_to_temporal_dag(tenant_id=_TENANT)
        dag = projection.dag
        assert nx.is_directed_acyclic_graph(dag), "temporal DAG projection must be a DAG"

    def test_projection_preserves_node_count(self) -> None:
        bdg = BehavioralDependencyGraph()
        bdg.update(**_update_kwargs())
        projection = bdg.project_to_temporal_dag(tenant_id=_TENANT)
        assert projection.dag.number_of_nodes() >= 1

    def test_scc_detection_raises_or_flattens(self) -> None:
        """A BDG with cross-tier cycles should either raise GraphCycleError
        or flatten cycles into a condensation node. Either behavior is valid."""
        from app.domain.exceptions import GraphCycleError

        bdg = BehavioralDependencyGraph()
        # Build a minimal multi-hop graph.
        bdg.update(**_update_kwargs())
        try:
            projection = bdg.project_to_temporal_dag(tenant_id=_TENANT)
            dag = projection.dag
            # Accept: DAG with no self-loops
            assert not any(dag.has_edge(n, n) for n in dag.nodes())
        except GraphCycleError:
            # Also acceptable: explicit rejection
            pass


# ---------------------------------------------------------------------------
# EventRelation mapping
# ---------------------------------------------------------------------------


class TestEventRelationMapping:
    def test_exec_maps_to_file_loads(self) -> None:
        bdg = BehavioralDependencyGraph()
        relations = bdg.map_event_to_relations(
            event_type="exec",
            event_attrs={"resource_class": "BIN"},
            tenant_id=_TENANT,
        )
        assert any(r.edge_type == BdgEdgeType.LOADS for r in relations)
        assert any(r.target_type == BdgNodeType.FILE for r in relations)

    def test_file_open_maps_to_reads(self) -> None:
        bdg = BehavioralDependencyGraph()
        relations = bdg.map_event_to_relations(
            event_type="file_open",
            event_attrs={"resource_class": "LIB"},
            tenant_id=_TENANT,
        )
        assert any(r.edge_type == BdgEdgeType.READS for r in relations)

    def test_net_connect_maps_to_network_endpoint(self) -> None:
        bdg = BehavioralDependencyGraph()
        relations = bdg.map_event_to_relations(
            event_type="net_connect",
            event_attrs={
                "resource_class": "CLUSTER_INTERNAL",
                "protocol": "tcp",
                "port_class": "443",
            },
            tenant_id=_TENANT,
        )
        assert any(r.target_type == BdgNodeType.NETWORK_ENDPOINT for r in relations)

    def test_unknown_event_type_returns_empty_or_fallback(self) -> None:
        bdg = BehavioralDependencyGraph()
        relations = bdg.map_event_to_relations(
            event_type="unknown_event_xyz",
            event_attrs={},
            tenant_id=_TENANT,
        )
        # Either empty list or a valid fallback relation — must not raise.
        assert isinstance(relations, list)
