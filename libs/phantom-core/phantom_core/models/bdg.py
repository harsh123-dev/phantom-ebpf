"""
phantom_core.models.bdg — Pydantic models for BDG query API contracts (B.5).

Covers:
- BdgNodeType / BdgEdgeType: literal type aliases
- BdgNode: graph node value object
- BdgEdge: graph edge value object
- GraphSnapshotQuery: shared snapshot_id query parameter
- BdgNodeResponse: GET /api/v1/bdg/nodes/{node_id}
- BdgEdgeResponse: GET /api/v1/bdg/edges/{edge_id}
- SubgraphQueryRequest: POST /api/v1/bdg/subgraphs:query
- SubgraphResponse
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from phantom_core.constants import (
    BDG_NODE_CONFIDENCE_MAX,
    BDG_NODE_CONFIDENCE_MIN,
    BDG_SUBGRAPH_MAX_HOPS_MAX,
    BDG_SUBGRAPH_MAX_HOPS_MIN,
    BDG_SUBGRAPH_MAX_NODES_MAX,
    BDG_SUBGRAPH_MAX_NODES_MIN,
    BDG_SUBGRAPH_ROOT_NODES_MAX,
    BDG_SUBGRAPH_ROOT_NODES_MIN,
    DIGEST_PATTERN,
)
from phantom_core.models.common import _PhantomBaseModel

# ---------------------------------------------------------------------------
# Literal type aliases
# ---------------------------------------------------------------------------

BdgNodeType = Literal[
    "workload",
    "container",
    "process",
    "purl",
    "file",
    "network_endpoint",
    "contract",
    "drift_event",
]

BdgEdgeType = Literal[
    "runs",
    "executes",
    "loads",
    "reads",
    "writes",
    "connects_to",
    "belongs_to",
    "violates",
    "derived_from",
]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


class BdgNode(_PhantomBaseModel):
    """A node in the Behavioral Dependency Graph snapshot.

    Attributes:
        node_id: Immutable UUID of this node.
        node_type: Semantic category of this node.
        label: Human-readable label for display and triage.
        attributes: Arbitrary key-value metadata; values are JSON primitives.
        first_seen_at: UTC timestamp when this node was first observed.
        last_seen_at: UTC timestamp of the most recent observation.
        confidence: Observation confidence [0, 1].
    """

    node_id: uuid.UUID
    node_type: BdgNodeType
    label: str = Field(..., min_length=1)
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    confidence: float = Field(..., ge=BDG_NODE_CONFIDENCE_MIN, le=BDG_NODE_CONFIDENCE_MAX)


class BdgEdge(_PhantomBaseModel):
    """A directed relationship edge in the Behavioral Dependency Graph snapshot.

    Attributes:
        edge_id: Immutable UUID of this edge.
        source_node_id: UUID of the source node.
        target_node_id: UUID of the target node.
        edge_type: Semantic relationship type.
        attributes: Arbitrary key-value metadata.
        first_seen_at: UTC timestamp when this edge was first observed.
        last_seen_at: UTC timestamp of the most recent observation.
        observation_count: Number of times this edge has been observed; >= 1.
        confidence: Observation confidence [0, 1].
    """

    edge_id: uuid.UUID
    source_node_id: uuid.UUID
    target_node_id: uuid.UUID
    edge_type: BdgEdgeType
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    observation_count: int = Field(..., ge=1)
    confidence: float = Field(..., ge=BDG_NODE_CONFIDENCE_MIN, le=BDG_NODE_CONFIDENCE_MAX)


# ---------------------------------------------------------------------------
# Query parameters
# ---------------------------------------------------------------------------


class GraphSnapshotQuery(_PhantomBaseModel):
    """Shared query parameter for BDG snapshot selection.

    Attributes:
        snapshot_id: UUID of a specific immutable snapshot; None returns the
            latest consistent snapshot.
    """

    snapshot_id: uuid.UUID | None = None


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class BdgNodeResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/bdg/nodes/{node_id}``.

    Attributes:
        snapshot_id: UUID of the snapshot this node was retrieved from.
        node: The BDG node value object.
    """

    snapshot_id: uuid.UUID
    node: BdgNode


class BdgEdgeResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/bdg/edges/{edge_id}``.

    Attributes:
        snapshot_id: UUID of the snapshot this edge was retrieved from.
        edge: The BDG edge value object.
    """

    snapshot_id: uuid.UUID
    edge: BdgEdge


class SubgraphQueryRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/bdg/subgraphs:query``.

    Attributes:
        snapshot_id: UUID of the snapshot to query; None uses the latest.
        root_node_ids: Starting node UUIDs for the traversal; 1..50 items.
        max_hops: Maximum graph traversal depth; 0..6.
        node_types: Optional node-type filter; None returns all types.
        edge_types: Optional edge-type filter; None returns all types.
        observed_after: Optional temporal lower bound.
        observed_before: Optional temporal upper bound; must be after observed_after.
        max_nodes: Maximum nodes in the response; 1..5000.
    """

    snapshot_id: uuid.UUID | None = None
    root_node_ids: list[uuid.UUID] = Field(
        ...,
        min_length=BDG_SUBGRAPH_ROOT_NODES_MIN,
        max_length=BDG_SUBGRAPH_ROOT_NODES_MAX,
    )
    max_hops: int = Field(..., ge=BDG_SUBGRAPH_MAX_HOPS_MIN, le=BDG_SUBGRAPH_MAX_HOPS_MAX)
    node_types: list[BdgNodeType] | None = None
    edge_types: list[BdgEdgeType] | None = None
    observed_after: datetime | None = None
    observed_before: datetime | None = None
    max_nodes: int = Field(
        ..., ge=BDG_SUBGRAPH_MAX_NODES_MIN, le=BDG_SUBGRAPH_MAX_NODES_MAX
    )

    @model_validator(mode="after")
    def _time_bounds_valid(self) -> SubgraphQueryRequest:
        """Validate that observed_before > observed_after if both are provided.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If temporal bounds are inverted.
        """
        if (
            self.observed_after is not None
            and self.observed_before is not None
            and self.observed_before <= self.observed_after
        ):
            raise ValueError("observed_before must be after observed_after")
        return self


class SubgraphResponse(_PhantomBaseModel):
    """Response body for ``POST /api/v1/bdg/subgraphs:query``.

    Attributes:
        snapshot_id: UUID of the snapshot the subgraph was extracted from.
        nodes: Nodes in the bounded subgraph.
        edges: Edges in the bounded subgraph.
        truncated: True if the graph was truncated at max_nodes.
        query_hash: sha256 digest of the canonical query parameters for caching.
    """

    snapshot_id: uuid.UUID
    nodes: list[BdgNode]
    edges: list[BdgEdge]
    truncated: bool
    query_hash: str

    @property
    def is_valid_query_hash(self) -> bool:
        """Check that query_hash matches the expected digest format.

        Returns:
            True if the hash matches the sha256 digest pattern.
        """
        return bool(re.fullmatch(DIGEST_PATTERN, self.query_hash))
