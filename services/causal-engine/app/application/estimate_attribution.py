"""
causal-engine application use case: estimate_attribution.

Implements Algorithm 4 (BuildAndEstimateSCM) from handoff §6.4.

Pipeline:
1. Load BDG snapshot, project to temporal DAG.
2. Check treatment/outcome cycle → not_identifiable.
3. Build windowed causal data table.
4. Verify variation and positivity → not_identifiable on failure.
5. Construct DoWhy CausalModel.
6. Identify effect (proceed_when_unidentifiable=False).
7. Estimate effect with selected backdoor estimator.
8. Estimate cohort counterfactual risk under do(C=0).
9. Run required refutations: RandomCommonCause, PlaceboTreatment, DataSubset.
10. Compute attribution confidence.
11. Return AttributionResult.

Clean Architecture: imports from domain/ only; no infrastructure imports.
"""

from __future__ import annotations

import uuid

import structlog

from app.domain.bdg import BehavioralDependencyGraph
from app.domain.causal import construct_causal_model
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalEstimatorName,
    CausalObservation,
    CovariateSpec,
    OutcomeSpec,
    RefutationResult,
    TreatmentSpec,
)
from app.domain.exceptions import (
    CausalModelConstructionError,
    GraphCycleError,
    InsufficientVariationError,
    PositivityFailureError,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Required refuters (§6.4 line 24)
# ---------------------------------------------------------------------------

REQUIRED_REFUTERS: list[str] = [
    "random_common_cause",
    "placebo_treatment_refuter",
    "data_subset_refuter",
]


# ---------------------------------------------------------------------------
# Attribution confidence (§6.4 lines 25–26)
# ---------------------------------------------------------------------------


def compute_attribution_confidence(
    ate: float | None,
    ate_ci_lower: float | None,
    ate_ci_upper: float | None,
    refutations: list[RefutationResult],
    event_loss_rate: float = 0.0,
    identity_resolution_rate: float = 1.0,
    contract_verified: bool = True,
) -> float:
    """Compute a composite attribution confidence score.

    Per handoff §6.4 line 26: ComputeAttributionConfidence uses
    data quality, projection quality, estimate stability, and
    refutation results.

    Args:
        ate: Average Treatment Effect estimate.
        ate_ci_lower: Lower bound of ATE confidence interval.
        ate_ci_upper: Upper bound of ATE confidence interval.
        refutations: List of refutation results.
        event_loss_rate: Fraction of events lost (higher = lower confidence).
        identity_resolution_rate: Fraction of events with resolved identity.
        contract_verified: Whether the contract is cosign-verified.

    Returns:
        Confidence score in [0, 1].
    """
    confidence = 1.0

    # Penalize for event loss.
    confidence *= max(0.0, 1.0 - event_loss_rate)

    # Penalize for identity resolution gaps.
    confidence *= identity_resolution_rate

    # Penalize for unverified contract.
    if not contract_verified:
        confidence *= 0.5

    # Penalize for wide confidence intervals.
    if ate_ci_lower is not None and ate_ci_upper is not None:
        ci_width = ate_ci_upper - ate_ci_lower
        if ci_width > 0.5:
            confidence *= max(0.3, 1.0 - ci_width)

    # Penalize for failed refutations.
    if refutations:
        passed_count = sum(1 for r in refutations if r.passed)
        confidence *= passed_count / len(refutations)

    return max(0.0, min(1.0, confidence))


# ---------------------------------------------------------------------------
# Use case
# ---------------------------------------------------------------------------


async def estimate_causal_attribution(
    bdg: BehavioralDependencyGraph,
    observations: list[CausalObservation],
    treatment_spec: TreatmentSpec,
    outcome_spec: OutcomeSpec,
    covariates: list[CovariateSpec],
    estimator: CausalEstimatorName,
    window_count: int = 10,
    event_loss_rate: float = 0.0,
    identity_resolution_rate: float = 1.0,
    contract_verified: bool = True,
) -> AttributionResult:
    """Execute the full causal attribution pipeline (Algorithm 4).

    Args:
        bdg: The BehavioralDependencyGraph to project.
        observations: Windowed causal observation rows.
        treatment_spec: Treatment variable specification.
        outcome_spec: Outcome variable specification.
        covariates: List of pre-treatment covariate specifications.
        estimator: The backdoor estimator to use.
        window_count: Number of time windows for DAG projection.
        event_loss_rate: Event loss rate for confidence adjustment.
        identity_resolution_rate: Identity resolution rate.
        contract_verified: Whether the contract is cosign-verified.

    Returns:
        An AttributionResult with status=completed or not_identifiable.
    """
    attribution_id = uuid.uuid4()
    bound_log = log.bind(
        attribution_id=str(attribution_id),
        estimator=estimator,
    )

    treatment_name = treatment_spec.variable_name
    outcome_name = outcome_spec.variable_name
    covariate_names = [c.variable_name for c in covariates]

    # ---- Step 1: Project BDG to temporal DAG (§6.4 line 02) ----
    bound_log.info("attribution.projecting_bdg")
    projection = bdg.project_to_temporal_dag(
        treatment_variable=treatment_name,
        outcome_variable=outcome_name,
        window_count=window_count,
    )

    # ---- Step 2: Check for cycles (§6.4 lines 03–04) ----
    if projection.treatment_or_outcome_in_cycle:
        bound_log.warning("attribution.cyclic_treatment_or_outcome")
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason="cyclic_treatment_or_outcome",
            graph_diagnostics=projection.diagnostics,
        )

    # ---- Steps 3–5: Construct CausalModel ----
    try:
        handle = construct_causal_model(
            projection=projection,
            observations=observations,
            treatment_name=treatment_name,
            outcome_name=outcome_name,
            covariate_names=covariate_names,
        )
    except GraphCycleError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"cyclic_treatment_or_outcome: {exc}",
            graph_diagnostics=projection.diagnostics,
        )
    except InsufficientVariationError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"no_empirical_variation: {exc.variable}",
            graph_diagnostics=projection.diagnostics,
        )
    except PositivityFailureError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"positivity_failure: {exc.details}",
            graph_diagnostics=projection.diagnostics,
        )
    except CausalModelConstructionError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"model_construction_error: {exc.reason}",
            graph_diagnostics=projection.diagnostics,
        )

    model = handle.model

    # ---- Step 6: Identify effect (§6.4 lines 13–18) ----
    bound_log.info("attribution.identifying_effect")
    try:
        estimand = model.identify_effect(
            proceed_when_unidentifiable=False,
            optimize_backdoor=False,
        )
    except Exception as exc:
        bound_log.warning("attribution.identification_failed", error=str(exc))
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"unidentified_effect: {exc}",
            graph_diagnostics=projection.diagnostics,
        )

    if estimand is None:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason="unidentified_effect: no valid adjustment set",
            graph_diagnostics=projection.diagnostics,
        )

    # ---- Step 7: Estimate effect (§6.4 lines 19–21) ----
    bound_log.info("attribution.estimating_effect", method=estimator)
    try:
        estimate = model.estimate_effect(
            estimand,
            method_name=estimator,
            control_value=0,
            treatment_value=1,
            target_units="ate",
            confidence_intervals=True,
        )
    except Exception as exc:
        bound_log.error("attribution.estimation_failed", error=str(exc))
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason=f"estimation_failed: {exc}",
            estimator_name=estimator,
            graph_diagnostics=projection.diagnostics,
        )

    ate_value = float(estimate.value) if hasattr(estimate, "value") else None
    ci_lower: float | None = None
    ci_upper: float | None = None

    if hasattr(estimate, "get_confidence_intervals"):
        try:
            ci = estimate.get_confidence_intervals()
            if ci is not None and len(ci) >= 2:
                ci_lower = float(ci[0])
                ci_upper = float(ci[1])
        except Exception:
            pass

    # ---- Step 8: Counterfactual cohort risk (§6.4 lines 22–23) ----
    counterfactual_prob: float | None = None
    counterfactual_status = "unavailable"
    # The counterfactual risk estimation requires the estimator to expose
    # an outcome prediction interface. Per handoff §6.4: "permitted only
    # when the estimator exposes a documented outcome-prediction interface".
    # For GLM-based estimators, we can attempt the prediction.
    try:
        if hasattr(estimate, "estimator") and hasattr(estimate.estimator, "predict"):

            treated_mask = model._data[treatment_name] == 1
            treated_data = model._data[treated_mask].copy()
            treated_data[treatment_name] = 0  # Intervene: set C=0.
            counterfactual_pred = estimate.estimator.predict(treated_data)
            counterfactual_prob = float(counterfactual_pred.mean())
            counterfactual_status = "available"
    except Exception as exc:
        bound_log.debug("attribution.counterfactual_unavailable", error=str(exc))
        counterfactual_status = "unavailable"

    # ---- Step 9: Refutations (§6.4 line 24) ----
    bound_log.info("attribution.running_refutations")
    refutations: list[RefutationResult] = []

    for refuter_name in REQUIRED_REFUTERS:
        try:
            refutation = model.refute_estimate(
                estimand,
                estimate,
                method_name=refuter_name,
            )
            new_effect = float(refutation.new_effect) if hasattr(refutation, "new_effect") else 0.0
            p_value: float | None = None
            if hasattr(refutation, "refutation_result"):
                p_value = getattr(refutation.refutation_result, "p_value", None)
            # Consider refutation passed if new effect is within 50% of original.
            passed = True
            if ate_value is not None and ate_value != 0:
                passed = abs(new_effect - ate_value) / abs(ate_value) < 0.5
            refutations.append(RefutationResult(
                refuter_name=refuter_name,
                estimated_effect=ate_value or 0.0,
                new_effect=new_effect,
                p_value=p_value,
                passed=passed,
            ))
        except Exception as exc:
            bound_log.warning(
                "attribution.refutation_failed",
                refuter=refuter_name,
                error=str(exc),
            )
            refutations.append(RefutationResult(
                refuter_name=refuter_name,
                estimated_effect=ate_value or 0.0,
                new_effect=0.0,
                p_value=None,
                passed=False,
            ))

    # ---- Step 10: Confidence (§6.4 lines 25–26) ----
    confidence = compute_attribution_confidence(
        ate=ate_value,
        ate_ci_lower=ci_lower,
        ate_ci_upper=ci_upper,
        refutations=refutations,
        event_loss_rate=event_loss_rate,
        identity_resolution_rate=identity_resolution_rate,
        contract_verified=contract_verified,
    )

    bound_log.info(
        "attribution.completed",
        ate=ate_value,
        confidence=confidence,
        refutation_count=len(refutations),
    )

    return AttributionResult(
        attribution_id=attribution_id,
        status=AttributionStatus.COMPLETED,
        ate=ate_value,
        ate_ci_lower=ci_lower,
        ate_ci_upper=ci_upper,
        counterfactual_drift_probability=counterfactual_prob,
        counterfactual_status=counterfactual_status,
        refutations=refutations,
        confidence=confidence,
        estimator_name=estimator,
        graph_diagnostics=projection.diagnostics,
    )
