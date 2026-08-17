"""
causal-engine domain BDG module.

Implements Algorithm 3 (UpdateBDGStreaming) from the handoff document §5.

Design:
- Uses NetworkX MultiDiGraph to retain cycles (handoff §5.2).
- Each node is keyed by its natural key tuple; UUIDs are metadata.
- Edge weight uses the exponentially decayed formula from §5.1:
    w_e(t) = lambda^((t - t_prev)/Delta) * w_e(t_prev) + q_e
- Immutable snapshots are cut at batch boundaries.
- Idempotency index prevents double-counting duplicate events.
- No edge deletion or arbitrary cycle breaking.
"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any

import networkx as nx
import structlog

from app.domain.entities import (
    BdgEdgeType,
    BdgNodeType,
    BDGSnapshot,
    EventRelation,
    GraphEdge,
    GraphMutation,
    TemporalDAGProjection,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_EVIDENCE_REFS: int = 50
"""Maximum evidence references retained per node/edge."""

# Causal tier ordering for intra-window edge orientation (§5.2 rule 2).
# Lower number = earlier in causal order.
CAUSAL_TIERS: dict[str, int] = {
    "environment": 0,
    "rbac": 0,
    "image": 0,
    "component_version": 1,
    "process_behavior": 2,
    "file_behavior": 3,
    "network_behavior": 3,
    "privilege_behavior": 3,
    "contract_deviation": 4,
    "runtime_sbom_drift": 5,
}

# Mapping from BdgNodeType to semantic variable category for SCM projection.
NODE_TYPE_TO_SEMANTIC: dict[BdgNodeType, str] = {
    BdgNodeType.WORKLOAD: "environment",
    BdgNodeType.CONTAINER: "image",
    BdgNodeType.PROCESS: "process_behavior",
    BdgNodeType.PURL: "component_version",
    BdgNodeType.FILE: "file_behavior",
    BdgNodeType.NETWORK_ENDPOINT: "network_behavior",
    BdgNodeType.CONTRACT: "contract_deviation",
    BdgNodeType.DRIFT_EVENT: "runtime_sbom_drift",
}


# ---------------------------------------------------------------------------
# BehavioralDependencyGraph
# ---------------------------------------------------------------------------


class BehavioralDependencyGraph:
    """In-memory BDG implemented as a NetworkX MultiDiGraph.

    Retains cycles per handoff §5.2. Edges are typed via the ``edge_type``
    attribute. Node data is stored as NetworkX node attributes.

    Args:
        decay_lambda: Exponential decay constant λ ∈ (0, 1]. Default 0.95.
        decay_delta_seconds: Decay interval Δ in seconds. Default 300 (5 min).
        batch_size: Number of events between immutable snapshot cuts.
    """

    def __init__(
        self,
        decay_lambda: float = 0.95,
        decay_delta_seconds: float = 300.0,
        batch_size: int = 100,
    ) -> None:
        """Initialise an empty BDG.

        Args:
            decay_lambda: Decay constant λ ∈ (0, 1].
            decay_delta_seconds: Decay interval Δ in seconds.
            batch_size: Events between snapshot cuts.
        """
        self._graph = nx.MultiDiGraph()
        self._decay_lambda = decay_lambda
        self._decay_delta = decay_delta_seconds
        self._batch_size = batch_size
        self._events_since_snapshot: int = 0
        self._idempotency_index: set[uuid.UUID] = set()
        self._snapshots: list[BDGSnapshot] = []
        self._natural_key_to_uuid: dict[tuple[str, ...], uuid.UUID] = {}

    @property
    def graph(self) -> nx.MultiDiGraph:
        """Return the underlying NetworkX MultiDiGraph.

        Returns:
            The graph object.
        """
        return self._graph

    @property
    def snapshots(self) -> list[BDGSnapshot]:
        """Return the list of committed snapshots.

        Returns:
            List of BDGSnapshot objects.
        """
        return list(self._snapshots)

    # -----------------------------------------------------------------
    # UpsertNode (handoff §5.3 lines 04–06, 10, 14, 18, 21)
    # -----------------------------------------------------------------

    def upsert_node(
        self,
        node_type: BdgNodeType,
        natural_key: tuple[str, ...],
        event_time: datetime,
        confidence: float,
        label: str = "",
        event_id: uuid.UUID | None = None,
    ) -> tuple[str, ...]:
        """Insert or update a BDG node by its natural key.

        If the node exists, updates last_seen, confidence (bounded EWMA),
        and observation_count. If absent, creates a new node with a fresh UUID.

        Args:
            node_type: Semantic category of the node.
            natural_key: Unique identity tuple.
            event_time: Observation timestamp.
            confidence: Observation confidence q ∈ [0, 1].
            label: Human-readable label.
            event_id: UUID of the contributing event.

        Returns:
            The natural key tuple (used as the NetworkX node key).
        """
        key = natural_key

        if self._graph.has_node(key):
            data = self._graph.nodes[key]
            data["last_seen_at"] = max(data.get("last_seen_at", event_time), event_time)
            data["observation_count"] = data.get("observation_count", 0) + 1
            # Bounded EWMA for confidence.
            alpha = 0.1
            old_conf = data.get("confidence", 0.0)
            data["confidence"] = min(1.0, old_conf * (1 - alpha) + confidence * alpha)
            if event_id and len(data.get("evidence_refs", [])) < _MAX_EVIDENCE_REFS:
                data["evidence_refs"].append(event_id)
        else:
            node_uuid = uuid.uuid4()
            self._natural_key_to_uuid[key] = node_uuid
            self._graph.add_node(
                key,
                node_id=node_uuid,
                node_type=node_type.value,
                natural_key=key,
                label=label or str(key),
                first_seen_at=event_time,
                last_seen_at=event_time,
                confidence=confidence,
                observation_count=1,
                evidence_refs=[event_id] if event_id else [],
            )

        return key

    # -----------------------------------------------------------------
    # UpsertEdge (handoff §5.1 weight formula + §5.3 lines 07–08, 11, etc.)
    # -----------------------------------------------------------------

    def upsert_edge(
        self,
        source_key: tuple[str, ...],
        target_key: tuple[str, ...],
        edge_type: BdgEdgeType,
        event_time: datetime,
        confidence: float = 1.0,
        event_id: uuid.UUID | None = None,
        weight_increment: float | None = None,
    ) -> GraphEdge:
        """Insert or update a typed directed edge.

        Uses the exponentially decayed weight formula from handoff §5.1:
            w_e(t) = λ^((t - t_prev)/Δ) · w_e(t_prev) + q_e

        A new edge starts with w_e = q_e. If the (source, target, edge_type)
        triple already exists, the matching edge key is updated.

        Args:
            source_key: Natural key of the source node.
            target_key: Natural key of the target node.
            edge_type: Semantic relationship type.
            event_time: Observation timestamp.
            confidence: Event evidence confidence q ∈ [0, 1]. Defaults to 1.0.
            event_id: UUID of the contributing event.
            weight_increment: Amount to add after decay. If None, defaults to
                ``confidence``. Use this to control the increment independently
                from the evidence confidence.

        Returns:
            A GraphEdge domain object representing the upserted edge.
        """
        # weight_increment defaults to confidence for backward compatibility.
        q_e = weight_increment if weight_increment is not None else confidence

        # Find existing edge by type.
        existing_key: int | None = None
        if self._graph.has_node(source_key) and self._graph.has_node(target_key):
            if self._graph.has_edge(source_key, target_key):
                for ek, edata in self._graph[source_key][target_key].items():
                    if edata.get("edge_type") == edge_type.value:
                        existing_key = ek
                        break

        if existing_key is not None:
            data = self._graph[source_key][target_key][existing_key]
            t_prev = data.get("last_seen", event_time)
            w_prev = data.get("weight", 0.0)

            # Exponential decay.
            dt = (event_time - t_prev).total_seconds()
            if dt > 0 and self._decay_delta > 0:
                decay = self._decay_lambda ** (dt / self._decay_delta)
            else:
                decay = 1.0
            data["weight"] = decay * w_prev + q_e
            data["last_seen"] = max(t_prev, event_time)
            data["observation_count"] = data.get("observation_count", 0) + 1
            if event_id and len(data.get("evidence_refs", [])) < _MAX_EVIDENCE_REFS:
                data["evidence_refs"].append(event_id)
            return GraphEdge(
                edge_id=data["edge_id"],
                source_key=source_key,
                target_key=target_key,
                edge_type=edge_type,
                weight=data["weight"],
                observation_count=data["observation_count"],
                evidence_refs=list(data.get("evidence_refs", [])),
            )
        else:
            edge_id = uuid.uuid4()
            self._graph.add_edge(
                source_key,
                target_key,
                edge_type=edge_type.value,
                weight=q_e,
                last_seen=event_time,
                observation_count=1,
                evidence_refs=[event_id] if event_id else [],
                edge_id=edge_id,
            )
            return GraphEdge(
                edge_id=edge_id,
                source_key=source_key,
                target_key=target_key,
                edge_type=edge_type,
                weight=q_e,
                observation_count=1,
                evidence_refs=[event_id] if event_id else [],
            )


    # -----------------------------------------------------------------
    # MapEventToRelations (handoff §5.3 line 13)
    # -----------------------------------------------------------------

    @staticmethod
    def map_event_to_relations(
        event_type: str,
        tenant_id: str,
        event_attrs: dict[str, Any],
    ) -> list[EventRelation]:
        """Map a normalized runtime event to typed BDG relations.

        This is the fixed mapping from Task 2 event types to graph edges.
        Unsupported event types return an empty list (retained in raw
        evidence but do not invent graph semantics per handoff §5.3).

        Args:
            event_type: Normalized event type string.
            tenant_id: Tenant ID for natural key scoping.
            event_attrs: Event-specific attributes.

        Returns:
            List of EventRelation objects describing target nodes and edges.
        """
        relations: list[EventRelation] = []

        if event_type == "exec":
            path_class = event_attrs.get("resource_class", "OTHER_RESOURCE")
            relations.append(EventRelation(
                target_type=BdgNodeType.FILE,
                natural_key=(tenant_id, path_class),
                edge_type=BdgEdgeType.LOADS,
                label=f"exec:{path_class}",
            ))

        elif event_type in ("file_open", "read"):
            path_class = event_attrs.get("resource_class", "OTHER_RESOURCE")
            relations.append(EventRelation(
                target_type=BdgNodeType.FILE,
                natural_key=(tenant_id, path_class),
                edge_type=BdgEdgeType.READS,
                label=f"read:{path_class}",
            ))

        elif event_type in ("file_write", "write"):
            path_class = event_attrs.get("resource_class", "OTHER_RESOURCE")
            relations.append(EventRelation(
                target_type=BdgNodeType.FILE,
                natural_key=(tenant_id, path_class),
                edge_type=BdgEdgeType.WRITES,
                label=f"write:{path_class}",
            ))

        elif event_type in ("net_connect", "connect"):
            endpoint_class = event_attrs.get("resource_class", "OTHER_RESOURCE")
            protocol = event_attrs.get("protocol", "tcp")
            port_class = event_attrs.get("port_class", "other")
            relations.append(EventRelation(
                target_type=BdgNodeType.NETWORK_ENDPOINT,
                natural_key=(tenant_id, protocol, endpoint_class, port_class),
                edge_type=BdgEdgeType.CONNECTS_TO,
                label=f"connect:{endpoint_class}:{port_class}",
            ))

        elif event_type in ("net_accept", "accept"):
            endpoint_class = event_attrs.get("resource_class", "OTHER_RESOURCE")
            protocol = event_attrs.get("protocol", "tcp")
            port_class = event_attrs.get("port_class", "other")
            relations.append(EventRelation(
                target_type=BdgNodeType.NETWORK_ENDPOINT,
                natural_key=(tenant_id, protocol, endpoint_class, port_class),
                edge_type=BdgEdgeType.CONNECTS_TO,
                label=f"accept:{endpoint_class}:{port_class}",
            ))

        return relations

    # -----------------------------------------------------------------
    # Algorithm 3: UpdateBDGStreaming
    # -----------------------------------------------------------------

    def update(
        self,
        event_id: uuid.UUID,
        event_type: str,
        event_time: datetime,
        tenant_id: str,
        cluster: str,
        namespace: str,
        pod_uid: str,
        container_id: str,
        image_digest: str,
        tgid: int,
        pid_start_time_ns: int,
        identity_confidence: float,
        binding_confidence: float,
        collector_confidence: float,
        binding_status: str = "resolved",
        component_purl: str | None = None,
        contract_violations: list[dict[str, Any]] | None = None,
        event_attrs: dict[str, Any] | None = None,
    ) -> GraphMutation:
        """Apply a single normalized event to the BDG per Algorithm 3.

        Args:
            event_id: Unique event UUID.
            event_type: Normalized event type string.
            event_time: Event observation timestamp (UTC).
            tenant_id: Tenant UUID string.
            cluster: Kubernetes cluster name.
            namespace: Kubernetes namespace.
            pod_uid: Pod UID string.
            container_id: Container ID string.
            image_digest: Container image digest string.
            tgid: Thread group ID.
            pid_start_time_ns: Process start time (disambiguates PID reuse).
            identity_confidence: Identity resolution confidence [0, 1].
            binding_confidence: SBOM binding confidence [0, 1].
            collector_confidence: Collector/event quality confidence [0, 1].
            binding_status: "resolved" or other status string.
            component_purl: Canonical PURL if binding is resolved.
            contract_violations: List of violation dicts if any.
            event_attrs: Event-specific attributes for relation mapping.

        Returns:
            A GraphMutation describing the changes made.
        """
        # Idempotency check (§5.3 line 01).
        if event_id in self._idempotency_index:
            log.debug("bdg.duplicate_event", event_id=str(event_id))
            return GraphMutation(
                mutation_id=uuid.uuid4(),
                event_id=event_id,
            )
        self._idempotency_index.add(event_id)

        # Composite confidence (§5.3 line 03).
        q = collector_confidence * identity_confidence * binding_confidence

        nodes_created = 0
        nodes_updated = 0
        edges_created = 0
        edges_updated = 0

        def _count_upsert_node(**kwargs: Any) -> tuple[str, ...]:  # noqa: ANN401
            nonlocal nodes_created, nodes_updated
            key = kwargs["natural_key"]
            existed = self._graph.has_node(key)
            result = self.upsert_node(**kwargs)
            if existed:
                nodes_updated += 1
            else:
                nodes_created += 1
            return result

        def _count_upsert_edge(**kwargs: Any) -> None:  # noqa: ANN401
            nonlocal edges_created, edges_updated
            sk, tk, et = kwargs["source_key"], kwargs["target_key"], kwargs["edge_type"]
            existed = False
            if self._graph.has_edge(sk, tk):
                for _, edata in self._graph[sk][tk].items():
                    if edata.get("edge_type") == et.value:
                        existed = True
                        break
            self.upsert_edge(**kwargs)
            if existed:
                edges_updated += 1
            else:
                edges_created += 1

        # §5.3 lines 04–08: workload → container → process chain.
        workload_key = _count_upsert_node(
            node_type=BdgNodeType.WORKLOAD,
            natural_key=(tenant_id, cluster, namespace, pod_uid),
            event_time=event_time,
            confidence=q,
            label=f"pod:{namespace}/{pod_uid[:8]}",
            event_id=event_id,
        )

        container_key = _count_upsert_node(
            node_type=BdgNodeType.CONTAINER,
            natural_key=(tenant_id, container_id, image_digest),
            event_time=event_time,
            confidence=q,
            label=f"container:{container_id[:12]}",
            event_id=event_id,
        )

        process_key = _count_upsert_node(
            node_type=BdgNodeType.PROCESS,
            natural_key=(tenant_id, container_id, str(tgid), str(pid_start_time_ns)),
            event_time=event_time,
            confidence=q,
            label=f"process:{tgid}",
            event_id=event_id,
        )

        _count_upsert_edge(
            source_key=workload_key,
            target_key=container_key,
            edge_type=BdgEdgeType.RUNS,
            event_time=event_time,
            confidence=q,
            event_id=event_id,
        )
        _count_upsert_edge(
            source_key=container_key,
            target_key=process_key,
            edge_type=BdgEdgeType.EXECUTES,
            event_time=event_time,
            confidence=q,
            event_id=event_id,
        )

        # §5.3 lines 09–12: PURL binding.
        component_key: tuple[str, ...] | None = None
        if binding_status == "resolved" and component_purl:
            component_key = _count_upsert_node(
                node_type=BdgNodeType.PURL,
                natural_key=(tenant_id, component_purl),
                event_time=event_time,
                confidence=q,
                label=f"purl:{component_purl}",
                event_id=event_id,
            )
            _count_upsert_edge(
                source_key=container_key,
                target_key=component_key,
                edge_type=BdgEdgeType.BELONGS_TO,
                event_time=event_time,
                confidence=q,
                event_id=event_id,
            )

        # §5.3 lines 13–16: event-derived target relations.
        attrs = event_attrs or {}
        relations = self.map_event_to_relations(event_type, tenant_id, attrs)
        for rel in relations:
            target_key = _count_upsert_node(
                node_type=rel.target_type,
                natural_key=rel.natural_key,
                event_time=event_time,
                confidence=q,
                label=rel.label,
                event_id=event_id,
            )
            _count_upsert_edge(
                source_key=process_key,
                target_key=target_key,
                edge_type=rel.edge_type,
                event_time=event_time,
                confidence=q,
                event_id=event_id,
            )

        # §5.3 lines 17–23: contract violations → drift events.
        if contract_violations:
            for violation in contract_violations:
                drift_event_id = violation.get("drift_event_id", str(uuid.uuid4()))
                contract_id_str = violation.get("contract_id", "")

                drift_key = _count_upsert_node(
                    node_type=BdgNodeType.DRIFT_EVENT,
                    natural_key=(tenant_id, drift_event_id),
                    event_time=event_time,
                    confidence=q,
                    label=f"drift:{drift_event_id[:8]}",
                    event_id=event_id,
                )
                _count_upsert_edge(
                    source_key=process_key,
                    target_key=drift_key,
                    edge_type=BdgEdgeType.DERIVED_FROM,
                    event_time=event_time,
                    confidence=q,
                    event_id=event_id,
                )

                if component_key:
                    _count_upsert_edge(
                        source_key=component_key,
                        target_key=drift_key,
                        edge_type=BdgEdgeType.VIOLATES,
                        event_time=event_time,
                        confidence=q,
                        event_id=event_id,
                    )

                if contract_id_str:
                    contract_key = _count_upsert_node(
                        node_type=BdgNodeType.CONTRACT,
                        natural_key=(tenant_id, contract_id_str),
                        event_time=event_time,
                        confidence=q,
                        label=f"contract:{contract_id_str[:8]}",
                        event_id=event_id,
                    )
                else:
                    # No explicit contract_id supplied — synthesise a key from
                    # the violation_type so that a CONTRACT node is always
                    # materialised (required per §5.3 and test invariants).
                    violation_type = violation.get("violation_type", "unknown")
                    synthetic_id = f"synthetic:{tenant_id}:{violation_type}"
                    contract_key = _count_upsert_node(
                        node_type=BdgNodeType.CONTRACT,
                        natural_key=(tenant_id, synthetic_id),
                        event_time=event_time,
                        confidence=q,
                        label=f"contract:{violation_type}",
                        event_id=event_id,
                    )
                _count_upsert_edge(
                    source_key=drift_key,
                    target_key=contract_key,
                    edge_type=BdgEdgeType.VIOLATES,
                    event_time=event_time,
                    confidence=q,
                    event_id=event_id,
                )

        # §5.3 lines 24–25: batch boundary → snapshot cut.
        self._events_since_snapshot += 1
        snapshot_cut = False
        if self._events_since_snapshot >= self._batch_size:
            self._commit_snapshot(tenant_id, event_id)
            snapshot_cut = True

        return GraphMutation(
            mutation_id=uuid.uuid4(),
            event_id=event_id,
            nodes_created=nodes_created,
            nodes_updated=nodes_updated,
            edges_created=edges_created,
            edges_updated=edges_updated,
            snapshot_cut=snapshot_cut,
        )

    # -----------------------------------------------------------------
    # update_from_event — high-level convenience wrapper
    # -----------------------------------------------------------------

    def update_from_event(
        self,
        event_id: uuid.UUID,
        tenant_id: uuid.UUID | str,
        event_type: str,
        process_key: tuple[str, ...],
        event_time: datetime,
        relations: list[EventRelation] | None = None,
        confidence: float = 1.0,
    ) -> GraphMutation:
        """High-level convenience wrapper for processing a pre-parsed event.

        This method allows callers to supply already-resolved node keys and
        relations directly, bypassing the full identity-resolution chain used
        in ``update()``. It is intended for testing and for pipeline stages
        where identity has already been resolved upstream.

        Args:
            event_id: Unique event UUID.
            tenant_id: Tenant UUID (or string form) for scoping.
            event_type: Normalized event type string (for logging).
            process_key: Pre-resolved natural key for the process node.
            event_time: Observation timestamp (UTC).
            relations: List of EventRelation objects to materialize as target
                nodes and edges from the process node. Defaults to empty list.
            confidence: Observation confidence q ∈ [0, 1]. Defaults to 1.0.

        Returns:
            A GraphMutation describing the changes made.
        """
        tenant_str = str(tenant_id)

        # Idempotency check.
        if event_id in self._idempotency_index:
            log.debug("bdg.duplicate_event", event_id=str(event_id))
            return GraphMutation(
                mutation_id=uuid.uuid4(),
                event_id=event_id,
            )
        self._idempotency_index.add(event_id)

        nodes_created = 0
        nodes_updated = 0
        edges_created = 0
        edges_updated = 0

        # Upsert the process node.
        existed = self._graph.has_node(process_key)
        self.upsert_node(
            node_type=BdgNodeType.PROCESS,
            natural_key=process_key,
            event_time=event_time,
            confidence=confidence,
            label=f"process:{process_key[-1] if process_key else 'unknown'}",
            event_id=event_id,
        )
        if existed:
            nodes_updated += 1
        else:
            nodes_created += 1

        # Materialize relations.
        for rel in (relations or []):
            rel_existed = self._graph.has_node(rel.natural_key)
            self.upsert_node(
                node_type=rel.target_type,
                natural_key=rel.natural_key,
                event_time=event_time,
                confidence=confidence,
                label=rel.label,
                event_id=event_id,
            )
            if rel_existed:
                nodes_updated += 1
            else:
                nodes_created += 1

            edge_existed = False
            if self._graph.has_edge(process_key, rel.natural_key):
                for _, edata in self._graph[process_key][rel.natural_key].items():
                    if edata.get("edge_type") == rel.edge_type.value:
                        edge_existed = True
                        break
            self.upsert_edge(
                source_key=process_key,
                target_key=rel.natural_key,
                edge_type=rel.edge_type,
                event_time=event_time,
                confidence=confidence,
                event_id=event_id,
            )
            if edge_existed:
                edges_updated += 1
            else:
                edges_created += 1

        # Batch boundary → snapshot cut.
        self._events_since_snapshot += 1
        snapshot_cut = False
        if self._events_since_snapshot >= self._batch_size:
            self._commit_snapshot(tenant_str, event_id)
            snapshot_cut = True

        return GraphMutation(
            mutation_id=uuid.uuid4(),
            event_id=event_id,
            nodes_created=nodes_created,
            nodes_updated=nodes_updated,
            edges_created=edges_created,
            edges_updated=edges_updated,
            snapshot_cut=snapshot_cut,
        )


    def _commit_snapshot(self, tenant_id: str, event_id: uuid.UUID) -> BDGSnapshot:
        """Cut an immutable snapshot of the current graph state.

        Args:
            tenant_id: Tenant UUID string.
            event_id: High-watermark event UUID.

        Returns:
            The newly created BDGSnapshot.
        """
        snapshot = BDGSnapshot(
            snapshot_id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id) if tenant_id else uuid.uuid4(),
            created_at=datetime.now(tz=UTC),
            node_count=self._graph.number_of_nodes(),
            edge_count=self._graph.number_of_edges(),
            event_id_high_watermark=event_id,
        )
        self._snapshots.append(snapshot)
        self._events_since_snapshot = 0
        log.info(
            "bdg.snapshot_committed",
            snapshot_id=str(snapshot.snapshot_id),
            nodes=snapshot.node_count,
            edges=snapshot.edge_count,
        )
        return snapshot

    # -----------------------------------------------------------------
    # Temporal DAG projection (handoff §5.2)
    # -----------------------------------------------------------------

    def project_to_temporal_dag(
        self,
        treatment_variable: str = "component_version",
        outcome_variable: str = "runtime_sbom_drift",
        window_count: int = 10,
        tenant_id: str | None = None,
    ) -> TemporalDAGProjection:
        """Project the BDG into a temporal DAG for SCM construction.

        Per handoff §5.2:
        1. Convert each semantic variable z into (z, w) for window w.
        2. Add edge (z, w) → (z', w') only if w < w' (temporal precedence)
           or w = w' and causal tier order is satisfied.
        3. Detect SCCs; if treatment or outcome is in an SCC, mark
           treatment_or_outcome_in_cycle = True.

        Args:
            treatment_variable: Semantic variable name for treatment.
            outcome_variable: Semantic variable name for outcome.
            window_count: Number of time windows to project.
            tenant_id: Optional tenant UUID string to scope the projection.
                If None, all tenants are included (single-tenant mode).

        Returns:
            A TemporalDAGProjection whose ``.dag`` attribute is the
            projected NetworkX DiGraph.
        """
        projected_dag = nx.DiGraph()
        excluded: list[tuple[str, str, str]] = []

        # Collect unique semantic variable categories from the graph.
        semantic_vars: set[str] = set()
        for node_key in self._graph.nodes:
            # Optionally scope to tenant.
            if tenant_id is not None:
                # node_key is a tuple; first element is typically tenant_id.
                if isinstance(node_key, tuple) and node_key and node_key[0] != tenant_id:
                    continue
            node_data = self._graph.nodes[node_key]
            ntype = node_data.get("node_type", "")
            try:
                semantic = NODE_TYPE_TO_SEMANTIC.get(BdgNodeType(ntype), ntype)
            except ValueError:
                semantic = ntype
            semantic_vars.add(semantic)

        # Create time-windowed variable nodes.
        projected_nodes: list[tuple[str, int]] = []
        for var in sorted(semantic_vars):
            for w in range(window_count):
                node = (var, w)
                projected_dag.add_node(node)
                projected_nodes.append(node)

        # Project edges using temporal precedence and causal tier rules.
        projected_edges: list[tuple[tuple[str, int], tuple[str, int]]] = []

        for u, v, _key, edata in self._graph.edges(data=True, keys=True):
            u_data = self._graph.nodes.get(u, {})
            v_data = self._graph.nodes.get(v, {})
            u_type = u_data.get("node_type", "")
            v_type = v_data.get("node_type", "")

            try:
                u_semantic = NODE_TYPE_TO_SEMANTIC.get(BdgNodeType(u_type), u_type)
            except ValueError:
                u_semantic = u_type
            try:
                v_semantic = NODE_TYPE_TO_SEMANTIC.get(BdgNodeType(v_type), v_type)
            except ValueError:
                v_semantic = v_type

            u_tier = CAUSAL_TIERS.get(u_semantic, 99)
            v_tier = CAUSAL_TIERS.get(v_semantic, 99)

            for w in range(window_count):
                # Rule 1: temporal precedence (w < w').
                for w_prime in range(w + 1, window_count):
                    edge = ((u_semantic, w), (v_semantic, w_prime))
                    if not projected_dag.has_edge(*edge):
                        projected_dag.add_edge(*edge)
                        projected_edges.append(edge)

                # Rule 2: same window, causal tier order.
                if u_tier < v_tier:
                    edge = ((u_semantic, w), (v_semantic, w))
                    if not projected_dag.has_edge(*edge):
                        projected_dag.add_edge(*edge)
                        projected_edges.append(edge)
                elif u_tier >= v_tier and u_semantic != v_semantic:
                    # Violates orientation rules → excluded.
                    excluded.append((str(u), str(v), edata.get("edge_type", "")))

        # SCC detection (§5.2).
        sccs: list[list[tuple[str, int]]] = []
        treatment_in_cycle = False

        for scc in nx.strongly_connected_components(projected_dag):
            if len(scc) > 1:
                scc_list = list(scc)
                sccs.append(scc_list)
                scc_vars = {var for var, _w in scc_list}
                if treatment_variable in scc_vars or outcome_variable in scc_vars:
                    treatment_in_cycle = True

        return TemporalDAGProjection(
            projected_nodes=projected_nodes,
            projected_edges=projected_edges,
            excluded_edges=excluded,
            treatment_or_outcome_in_cycle=treatment_in_cycle,
            sccs=sccs,
            diagnostics={
                "semantic_variables": sorted(semantic_vars),
                "window_count": window_count,
                "total_projected_nodes": len(projected_nodes),
                "total_projected_edges": len(projected_edges),
                "excluded_edge_count": len(excluded),
                "scc_count": len(sccs),
            },
            dag=projected_dag,
        )


    def get_node_count(self) -> int:
        """Return the number of nodes in the graph.

        Returns:
            Integer node count.
        """
        return int(self._graph.number_of_nodes())

    def get_edge_count(self) -> int:
        """Return the number of edges in the graph.

        Returns:
            Integer edge count.
        """
        return int(self._graph.number_of_edges())

    def copy(self) -> nx.MultiDiGraph:
        """Return a deep copy of the underlying graph for snapshot purposes.

        Returns:
            A deep copy of the NetworkX MultiDiGraph.
        """
        return copy.deepcopy(self._graph)
