"""
phantom_core.models.attribution — Pydantic models for causal attribution and PCEPS (B.6, B.7).

Covers:
- TreatmentSpec, OutcomeSpec, CovariateSpec: SCM variable specifications
- AttributionRequest: POST /api/v1/attributions
- AttributionJobResponse: POST response
- AttributionConfidence: confidence decomposition value object
- RefutationResult: DoWhy refutation result value object
- AttributionResultResponse: GET /api/v1/attributions/{attribution_id}
- PcepsScoreRequest: POST /api/v1/pceps:scores
- PcepsScoreResponse: POST response
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from phantom_core.constants import (
    ATTRIBUTION_CONFIDENCE_EXPLANATION_MAX,
    ATTRIBUTION_COVARIATES_MAX,
    ATTRIBUTION_COVARIATES_MIN,
    ATTRIBUTION_OUTCOME_NODES_MAX,
    ATTRIBUTION_OUTCOME_NODES_MIN,
    ATTRIBUTION_REFUTATION_NOTES_MAX_LENGTH,
    ATTRIBUTION_TREATMENT_NODES_MAX,
    ATTRIBUTION_TREATMENT_NODES_MIN,
    ATTRIBUTION_VARIABLE_PATTERN,
    PCEPS_FEATURE_COMPLETENESS_MAX,
    PCEPS_FEATURE_COMPLETENESS_MIN,
    PCEPS_MODEL_VERSION_MAX_LENGTH,
    PCEPS_SCORE_MAX,
    PCEPS_SCORE_MIN,
    SCHEMA_VERSION,
)
from phantom_core.models.common import _PhantomBaseModel

# ---------------------------------------------------------------------------
# Estimator literal
# ---------------------------------------------------------------------------

EstimatorType = Literal[
    "backdoor.linear_regression",
    "backdoor.propensity_score_matching",
    "backdoor.generalized_linear_model",
]

CovariateSource = Literal[
    "workload",
    "container",
    "process",
    "purl",
    "network",
    "cluster",
    "temporal",
]

AttributionStatus = Literal[
    "queued",
    "running",
    "completed",
    "not_identifiable",
    "failed",
]

RefutationMethod = Literal[
    "random_common_cause",
    "placebo_treatment_refuter",
    "data_subset_refuter",
]

SeverityBand = Literal["informational", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# SCM variable specifications (B.6)
# ---------------------------------------------------------------------------


class TreatmentSpec(_PhantomBaseModel):
    """Causal treatment variable specification.

    Attributes:
        variable: Variable name matching ``^[A-Za-z][A-Za-z0-9_]{0,127}$``.
        observed_value: Binary treatment assignment; 0 or 1.
        source_node_ids: BDG node UUIDs from which this treatment is derived; 1..100.
    """

    variable: str = Field(..., pattern=ATTRIBUTION_VARIABLE_PATTERN)
    observed_value: Literal[0, 1]
    source_node_ids: list[uuid.UUID] = Field(
        ...,
        min_length=ATTRIBUTION_TREATMENT_NODES_MIN,
        max_length=ATTRIBUTION_TREATMENT_NODES_MAX,
    )


class OutcomeSpec(_PhantomBaseModel):
    """Causal outcome variable specification.

    Attributes:
        variable: Always ``"runtime_sbom_drift"`` per the handoff contract.
        observed_value: Binary outcome; 0 or 1.
        target_node_ids: BDG node UUIDs representing this outcome; 1..100.
    """

    variable: Literal["runtime_sbom_drift"]
    observed_value: Literal[0, 1]
    target_node_ids: list[uuid.UUID] = Field(
        ...,
        min_length=ATTRIBUTION_OUTCOME_NODES_MIN,
        max_length=ATTRIBUTION_OUTCOME_NODES_MAX,
    )


class CovariateSpec(_PhantomBaseModel):
    """A single covariate variable for the SCM adjustment set.

    Attributes:
        variable: Variable name matching the variable pattern.
        source: The domain from which this covariate is derived.
        observed_value: Observed scalar value; may be None if missing.
    """

    variable: str = Field(..., pattern=ATTRIBUTION_VARIABLE_PATTERN)
    source: CovariateSource
    observed_value: float | int | str | bool | None = None


# ---------------------------------------------------------------------------
# POST /api/v1/attributions
# ---------------------------------------------------------------------------


class AttributionRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/attributions``.

    Attributes:
        schema_version: Always ``"v1"``.
        snapshot_id: UUID of the immutable BDG snapshot to use.
        drift_event_id: UUID of the drift event being analysed.
        treatment: Treatment variable specification.
        outcome: Outcome variable specification.
        covariates: Adjustment covariate specifications; 1..128 items.
        estimator: DoWhy estimator method to apply.
        counterfactual_treatment_value: Binary counterfactual treatment; 0 or 1.
        tenant_id: Logical isolation key.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    snapshot_id: uuid.UUID
    drift_event_id: uuid.UUID
    treatment: TreatmentSpec
    outcome: OutcomeSpec
    covariates: list[CovariateSpec] = Field(
        ...,
        min_length=ATTRIBUTION_COVARIATES_MIN,
        max_length=ATTRIBUTION_COVARIATES_MAX,
    )
    estimator: EstimatorType
    counterfactual_treatment_value: Literal[0, 1]
    tenant_id: uuid.UUID


class AttributionJobResponse(_PhantomBaseModel):
    """Response body for ``POST /api/v1/attributions``.

    Attributes:
        attribution_id: Gateway-assigned UUID for this attribution job.
        status: Current job status.
        snapshot_id: UUID of the snapshot being analysed.
        submitted_at: UTC timestamp when the job was enqueued.
    """

    attribution_id: uuid.UUID
    status: AttributionStatus
    snapshot_id: uuid.UUID
    submitted_at: datetime


# ---------------------------------------------------------------------------
# GET /api/v1/attributions/{attribution_id}
# ---------------------------------------------------------------------------


class AttributionConfidence(_PhantomBaseModel):
    """Multi-dimensional confidence decomposition for a completed attribution.

    All scores are in [0, 1]. Higher is more confident, except loss_penalty
    where higher means more penalty (less confident).

    Attributes:
        score: Composite confidence score; [0, 1].
        data_coverage: Fraction of relevant observation window covered; [0, 1].
        identity_resolution_confidence: Confidence in workload identity; [0, 1].
        contract_verification_confidence: Confidence in contract trust; [0, 1].
        graph_temporal_consistency: Consistency of BDG snapshot temporally; [0, 1].
        refutation_stability: Fraction of refutation tests that passed; [0, 1].
        loss_penalty: Penalty applied due to ring-buffer observation loss; [0, 1].
        explanation: Ordered list of human-readable confidence factors; max 16.
    """

    score: float = Field(..., ge=0.0, le=1.0)
    data_coverage: float = Field(..., ge=0.0, le=1.0)
    identity_resolution_confidence: float = Field(..., ge=0.0, le=1.0)
    contract_verification_confidence: float = Field(..., ge=0.0, le=1.0)
    graph_temporal_consistency: float = Field(..., ge=0.0, le=1.0)
    refutation_stability: float = Field(..., ge=0.0, le=1.0)
    loss_penalty: float = Field(..., ge=0.0, le=1.0)
    explanation: list[str] = Field(..., max_length=ATTRIBUTION_CONFIDENCE_EXPLANATION_MAX)


class RefutationResult(_PhantomBaseModel):
    """Result of a single DoWhy refutation test.

    Attributes:
        method: The refutation method applied.
        passed: True if the refutation did not invalidate the estimate.
        effect_estimate: Effect estimate from the refutation run; None if unavailable.
        notes: Diagnostic notes; max 2048 characters.
    """

    method: RefutationMethod
    passed: bool
    effect_estimate: float | None = None
    notes: str = Field(..., max_length=ATTRIBUTION_REFUTATION_NOTES_MAX_LENGTH)


class AttributionResultResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/attributions/{attribution_id}``.

    When ``status="not_identifiable"``, ``average_treatment_effect`` MUST be None.
    A numeric effect is never fabricated for unidentifiable causal queries.

    Attributes:
        attribution_id: UUID of this attribution job.
        status: Current or final job status.
        snapshot_id: UUID of the analysed BDG snapshot.
        drift_event_id: UUID of the analysed drift event.
        estimand: DoWhy estimand string; None if not yet identified.
        identified: True if a valid adjustment set was found.
        identification_method: DoWhy identification method used; None if not identified.
        average_treatment_effect: Estimated ATE; None if not_identifiable or pending.
        effect_ci_lower: Lower bound of 95% CI; None if not available.
        effect_ci_upper: Upper bound of 95% CI; None if not available.
        counterfactual_drift_probability: Counterfactual drift probability [0, 1].
        attribution_confidence: Multi-dimensional confidence decomposition; None if pending.
        refutation_results: DoWhy refutation results; empty if not yet run.
        failure_reason: Human-readable failure description; None if not failed.
        completed_at: UTC timestamp of job completion; None if still running.
    """

    attribution_id: uuid.UUID
    status: AttributionStatus
    snapshot_id: uuid.UUID
    drift_event_id: uuid.UUID
    estimand: str | None = None
    identified: bool
    identification_method: str | None = None
    average_treatment_effect: float | None = None
    effect_ci_lower: float | None = None
    effect_ci_upper: float | None = None
    counterfactual_drift_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    attribution_confidence: AttributionConfidence | None = None
    refutation_results: list[RefutationResult] = Field(default_factory=list)
    failure_reason: str | None = None
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# POST /api/v1/pceps:scores
# ---------------------------------------------------------------------------


class PcepsScoreRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/pceps:scores``.

    Attributes:
        schema_version: Always ``"v1"``.
        drift_event_id: UUID of the drift event to score.
        attribution_id: UUID of the completed attribution providing causal evidence.
        model_version: XGBoost model version string; 1..128 characters.
        allow_imputation: Whether missing features may be imputed. Default True.
        tenant_id: Logical isolation key.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    drift_event_id: uuid.UUID
    attribution_id: uuid.UUID
    model_version: str = Field(..., min_length=1, max_length=PCEPS_MODEL_VERSION_MAX_LENGTH)
    allow_imputation: bool = True
    tenant_id: uuid.UUID


class PcepsScoreResponse(_PhantomBaseModel):
    """Response body for ``POST /api/v1/pceps:scores``.

    Attributes:
        score_id: Gateway-assigned UUID for this score record.
        drift_event_id: UUID of the scored drift event.
        attribution_id: UUID of the attribution providing causal evidence.
        model_version: XGBoost model version used.
        score: PCEPS priority score [0, 100]. Higher = higher priority.
        severity: Human-readable severity band derived from the score.
        feature_completeness: Fraction of non-imputed features [0, 1].
        imputed_features: Names of features that were imputed; empty if none.
        scored_at: UTC timestamp when the score was computed.
    """

    score_id: uuid.UUID
    drift_event_id: uuid.UUID
    attribution_id: uuid.UUID
    model_version: str
    score: float = Field(..., ge=PCEPS_SCORE_MIN, le=PCEPS_SCORE_MAX)
    severity: SeverityBand
    feature_completeness: float = Field(
        ...,
        ge=PCEPS_FEATURE_COMPLETENESS_MIN,
        le=PCEPS_FEATURE_COMPLETENESS_MAX,
    )
    imputed_features: list[str] = Field(default_factory=list)
    scored_at: datetime
