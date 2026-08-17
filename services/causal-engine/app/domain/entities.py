"""
causal-engine domain entities.

Defines core BDG, SCM, and attribution domain entities:
- BdgNode / BdgEdge: versioned graph elements
- TreatmentSpec / OutcomeSpec / CovariateSpec: causal model inputs
- AttributionRecord: immutable causal evidence record
- PcepsScore: PCEPS priority score value object
- BDGSnapshot / TemporalDAGProjection: graph snapshot types
- CausalObservation / CausalModelHandle: SCM construction types

No framework imports allowed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None  # noqa: PGH003


# ---------------------------------------------------------------------------
# BDG node/edge type enums
# ---------------------------------------------------------------------------


class BdgNodeType(str, Enum):
    """Node type discriminant matching the handoff §5.1 natural key table."""

    WORKLOAD = "workload"
    CONTAINER = "container"
    PROCESS = "process"
    PURL = "purl"
    FILE = "file"
    NETWORK_ENDPOINT = "network_endpoint"
    CONTRACT = "contract"
    DRIFT_EVENT = "drift_event"


class BdgEdgeType(str, Enum):
    """Edge type discriminant matching the handoff §5.1 relation types."""

    RUNS = "runs"
    EXECUTES = "executes"
    LOADS = "loads"
    READS = "reads"
    WRITES = "writes"
    CONNECTS_TO = "connects_to"
    BELONGS_TO = "belongs_to"
    VIOLATES = "violates"
    DERIVED_FROM = "derived_from"


# ---------------------------------------------------------------------------
# BDG node and edge domain objects
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    """A node in the Behavioral Dependency Graph.

    Attributes:
        node_id: Immutable UUID.
        node_type: Semantic category.
        natural_key: Tuple of strings forming the unique identity.
        label: Human-readable label for display.
        attributes: Arbitrary key-value metadata.
        first_seen_at: UTC timestamp of first observation.
        last_seen_at: UTC timestamp of most recent observation.
        confidence: Observation confidence in [0, 1].
        observation_count: Number of observations.
        evidence_refs: Bounded list of event IDs contributing evidence.
    """

    node_id: uuid.UUID
    node_type: BdgNodeType
    natural_key: tuple[str, ...]
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    confidence: float = 0.0
    observation_count: int = 0
    evidence_refs: list[uuid.UUID] = field(default_factory=list)


@dataclass
class GraphEdge:
    """A directed relationship edge in the BDG.

    Attributes:
        edge_id: Immutable UUID.
        source_key: Natural key of the source node.
        target_key: Natural key of the target node.
        edge_type: Semantic relationship type.
        weight: Exponentially decayed observation weight (§5.1 formula).
        last_seen: UTC timestamp of most recent observation.
        observation_count: Number of observations.
        evidence_refs: Bounded list of contributing event IDs.
    """

    edge_id: uuid.UUID
    source_key: tuple[str, ...]
    target_key: tuple[str, ...]
    edge_type: BdgEdgeType
    weight: float = 0.0
    last_seen: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    observation_count: int = 0
    evidence_refs: list[uuid.UUID] = field(default_factory=list)


# ---------------------------------------------------------------------------
# BDG snapshot
# ---------------------------------------------------------------------------


@dataclass
class BDGSnapshot:
    """An immutable point-in-time snapshot of the BDG.

    Attributes:
        snapshot_id: UUID of this snapshot.
        tenant_id: Tenant UUID for multi-tenant isolation.
        created_at: UTC timestamp of snapshot creation.
        node_count: Number of nodes at snapshot time.
        edge_count: Number of edges at snapshot time.
        event_id_high_watermark: Highest event_id included.
    """

    snapshot_id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    node_count: int = 0
    edge_count: int = 0
    event_id_high_watermark: uuid.UUID | None = None


# ---------------------------------------------------------------------------
# Graph event relations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRelation:
    """A single event-derived target relation for BDG update.

    Attributes:
        target_type: BDG node type of the target.
        natural_key: Tuple forming the target node's natural key.
        edge_type: Semantic relationship from the process to the target.
        label: Human-readable label for the target node.
    """

    target_type: BdgNodeType
    natural_key: tuple[str, ...]
    edge_type: BdgEdgeType
    label: str


# ---------------------------------------------------------------------------
# Graph mutation result
# ---------------------------------------------------------------------------


@dataclass
class GraphMutation:
    """Result of a single BDG update operation.

    Attributes:
        mutation_id: UUID for lineage tracking.
        event_id: UUID of the triggering event.
        nodes_created: Number of new nodes created.
        nodes_updated: Number of existing nodes updated.
        edges_created: Number of new edges created.
        edges_updated: Number of existing edges updated.
        snapshot_cut: True if an immutable snapshot was committed.
    """

    mutation_id: uuid.UUID
    event_id: uuid.UUID
    nodes_created: int = 0
    nodes_updated: int = 0
    edges_created: int = 0
    edges_updated: int = 0
    snapshot_cut: bool = False


# ---------------------------------------------------------------------------
# Temporal DAG projection
# ---------------------------------------------------------------------------


@dataclass
class TemporalDAGProjection:
    """Result of projecting the BDG into a temporal DAG for SCM construction.

    Attributes:
        projected_nodes: List of (variable_name, window_index) tuples.
        projected_edges: List of (source, target) variable-window tuples.
        excluded_edges: Edges excluded because they violate temporal ordering.
        treatment_or_outcome_in_cycle: True if treatment or outcome is in SCC.
        sccs: List of strongly connected components found.
        diagnostics: Additional diagnostic info for the analyst.
        dag: The NetworkX DiGraph of the projected temporal DAG (None if
            networkx is unavailable).
    """

    projected_nodes: list[tuple[str, int]] = field(default_factory=list)
    projected_edges: list[tuple[tuple[str, int], tuple[str, int]]] = field(
        default_factory=list
    )
    excluded_edges: list[tuple[str, str, str]] = field(default_factory=list)
    treatment_or_outcome_in_cycle: bool = False
    sccs: list[list[tuple[str, int]]] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    dag: Any = field(default=None)


# ---------------------------------------------------------------------------
# Causal specs
# ---------------------------------------------------------------------------


CausalEstimatorName = Literal[
    "backdoor.linear_regression",
    "backdoor.propensity_score_matching",
    "backdoor.generalized_linear_model",
]


@dataclass(frozen=True)
class TreatmentSpec:
    """Specification for the treatment variable in a causal query.

    Attributes:
        variable_name: Column name for the treatment binary variable.
        description: Human-readable description.
    """

    variable_name: str = "component_version_treatment"
    description: str = "1 when component runs the candidate/manipulated version, 0 when approved"


@dataclass(frozen=True)
class OutcomeSpec:
    """Specification for the outcome variable in a causal query.

    Attributes:
        variable_name: Column name for the outcome binary variable.
        description: Human-readable description.
    """

    variable_name: str = "runtime_sbom_drift"
    description: str = "1 when contract deviation occurs within horizon, 0 otherwise"


@dataclass(frozen=True)
class CovariateSpec:
    """Specification for a pre-treatment covariate.

    Attributes:
        variable_name: Column name.
        description: Human-readable description.
        is_binary: Whether the covariate is binary (True) or continuous (False).
    """

    variable_name: str
    description: str = ""
    is_binary: bool = False


# ---------------------------------------------------------------------------
# Causal observation and model handle
# ---------------------------------------------------------------------------


@dataclass
class CausalObservation:
    """One row of the windowed causal data table.

    Attributes:
        window_index: Time window index.
        treatment_value: 0 or 1.
        outcome_value: 0 or 1.
        covariates: Dict of covariate_name → value.
    """

    window_index: int
    treatment_value: int
    outcome_value: int
    covariates: dict[str, float] = field(default_factory=dict)


@dataclass
class CausalModelHandle:
    """Wrapper around a constructed DoWhy CausalModel.

    Attributes:
        model: The DoWhy CausalModel object (Any to avoid domain→infra import).
        graph_gml: GML serialization of the projected DAG.
        treatment_name: Treatment variable name.
        outcome_name: Outcome variable name.
        covariate_names: List of covariate variable names.
    """

    model: Any
    graph_gml: str
    treatment_name: str
    outcome_name: str
    covariate_names: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Attribution result
# ---------------------------------------------------------------------------


class AttributionStatus(str, Enum):
    """Status of a causal attribution attempt."""

    COMPLETED = "completed"
    NOT_IDENTIFIABLE = "not_identifiable"


@dataclass
class RefutationResult:
    """Result of a single causal refutation test.

    Attributes:
        refuter_name: Name of the refutation method.
        estimated_effect: The refuted effect estimate.
        new_effect: The effect estimate after refutation.
        p_value: p-value of the refutation test (if available).
        passed: True if the refutation does not invalidate the estimate.
    """

    refuter_name: str
    estimated_effect: float
    new_effect: float
    p_value: float | None = None
    passed: bool = True


@dataclass
class AttributionResult:
    """Complete result of a causal attribution query.

    Attributes:
        attribution_id: UUID of this attribution run.
        status: completed or not_identifiable.
        reason: Human-readable reason when not_identifiable.
        ate: Average Treatment Effect estimate (None if not identifiable).
        ate_ci_lower: Lower bound of ATE confidence interval.
        ate_ci_upper: Upper bound of ATE confidence interval.
        counterfactual_drift_probability: P(D|do(C=0)) for treated cohort.
        counterfactual_status: available / unavailable.
        refutations: List of refutation results.
        confidence: Attribution confidence score in [0, 1].
        snapshot_id: UUID of the BDG snapshot used.
        estimator_name: The estimator that was used.
        graph_diagnostics: Diagnostic info about the projected DAG.
    """

    attribution_id: uuid.UUID
    status: AttributionStatus
    reason: str = ""
    ate: float | None = None
    ate_ci_lower: float | None = None
    ate_ci_upper: float | None = None
    counterfactual_drift_probability: float | None = None
    counterfactual_status: str = "unavailable"
    refutations: list[RefutationResult] = field(default_factory=list)
    confidence: float = 0.0
    snapshot_id: uuid.UUID | None = None
    estimator_name: str = ""
    graph_diagnostics: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# PCEPS types
# ---------------------------------------------------------------------------


PCEPS_FEATURE_NAMES: list[str] = [
    "f1_causal_effect",
    "f2_attribution_confidence",
    "f3_contract_violation_rate",
    "f4_behavioral_divergence_ratio",
    "f5_new_process_rate",
    "f6_unexpected_network_rate",
    "f7_privilege_transition",
    "f8_sensitive_file_access_rate",
    "f9_component_criticality",
    "f10_image_signature_invalid",
    "f11_namespace_risk_weight",
    "f12_service_account_privilege",
    "f13_event_loss_rate",
    "f14_graph_centrality_delta",
    "f15_prior_drift_frequency",
    "f16_runtime_component_novelty",
]
"""Ordered list of PCEPS feature names matching §7.1 table."""


@dataclass
class PcepsFeatureVector:
    """The 16-feature vector for PCEPS scoring.

    Attributes:
        values: List of 16 float values in [0, 1].
        mask: List of 16 booleans; True if the feature was imputed.
        feature_completeness: Fraction of non-imputed features.
        imputed_feature_names: Names of imputed features.
    """

    values: list[float] = field(default_factory=lambda: [0.0] * 16)
    mask: list[bool] = field(default_factory=lambda: [False] * 16)
    feature_completeness: float = 1.0
    imputed_feature_names: list[str] = field(default_factory=list)


@dataclass
class PcepsCalibration:
    """Platt scaling calibration parameters.

    Attributes:
        a: Slope parameter of the sigmoid calibration.
        b: Intercept parameter of the sigmoid calibration.
        calibration_sample_count: Number of calibration samples used.
        brier_score: Brier score on the calibration set.
        expected_calibration_error: ECE on the calibration set.
    """

    a: float = 1.0
    b: float = 0.0
    calibration_sample_count: int = 0
    brier_score: float = 0.0
    expected_calibration_error: float = 0.0


class PcepsSeverity(str, Enum):
    """Pre-registered severity bands for PCEPS scores."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PcepsScore:
    """PCEPS priority score result.

    Attributes:
        score: Calibrated score in [0, 100].
        severity: Severity band derived from pre-registered operating points.
        raw_probability: Uncalibrated XGBoost probability.
        calibrated_probability: Platt-scaled probability.
        feature_completeness: Fraction of non-imputed features.
        imputed_features: Names of features that were imputed.
        model_version: Version identifier of the XGBoost model used.
        calibration: Platt calibration parameters for provenance.
    """

    score: float = 0.0
    severity: PcepsSeverity = PcepsSeverity.INFO
    raw_probability: float = 0.0
    calibrated_probability: float = 0.0
    feature_completeness: float = 1.0
    imputed_features: list[str] = field(default_factory=list)
    model_version: str = ""
    calibration: PcepsCalibration = field(default_factory=PcepsCalibration)


@dataclass
class PcepsFeatureBaseline:
    """Training-partition statistics used for feature normalization.

    Attributes:
        medians: Per-feature median values (length 16).
        mads: Per-feature MAD values (length 16).
        model_version: Version identifier.
    """

    medians: list[float] = field(default_factory=lambda: [0.0] * 16)
    mads: list[float] = field(default_factory=lambda: [1.0] * 16)
    model_version: str = ""
