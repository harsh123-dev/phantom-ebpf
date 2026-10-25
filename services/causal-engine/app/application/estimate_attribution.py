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

import math
import uuid

import structlog

from app.domain.bdg import BehavioralDependencyGraph
from app.domain.causal import construct_causal_model
from app.domain.causal_validation import DEFAULT_CAUSAL_ASSUMPTIONS
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
    required_refuter_count: int | None = None,
    event_loss_rate: float = 0.0,
    identity_resolution_rate: float = 1.0,
    contract_verified: bool = True,
) -> float:
    """Compute a composite heuristic diagnostic stability score in [0, 1].

    Note: This is a diagnostic stability and data-quality index, NOT a
    calibrated probability that an attribution is true. Passing sensitivity
    analyses / refutations checks robustness against tested perturbations
    under assumed ignorability; it does not establish empirical truth.

    Args:
        ate: Average Treatment Effect estimate.
        ate_ci_lower: Lower bound of ATE confidence interval.
        ate_ci_upper: Upper bound of ATE confidence interval.
        refutations: List of refutation results.
        required_refuter_count: Expected number of refutations. If refutations
            are missing or skipped, the score is penalized proportionally.
        event_loss_rate: Fraction of events lost (higher = lower confidence).
        identity_resolution_rate: Fraction of events with resolved identity.
        contract_verified: Whether the contract is cosign-verified.

    Returns:
        Diagnostic score in [0, 1]. Returns 0.0 if ATE is None or non-finite.
    """
    if ate is None or not math.isfinite(ate):
        return 0.0

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

    # Penalize for failed or omitted refutations.
    if required_refuter_count is not None and required_refuter_count > 0:
        passed_count = sum(1 for r in refutations if r.passed)
        confidence *= passed_count / max(len(refutations), required_refuter_count)
    elif refutations:
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
    estimator: CausalEstimatorName = "backdoor.linear_regression",
    window_count: int = 10,
    event_loss_rate: float = 0.0,
    identity_resolution_rate: float = 1.0,
    contract_verified: bool = True,
    projection: TemporalDAGProjection | None = None,
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
        projection: Optional pre-constructed TemporalDAGProjection. If None,
            projected from bdg via bdg.project_to_temporal_dag().

    Returns:
        An AttributionResult with status=completed, not_identifiable, or invalid_graph.
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
    if projection is None:
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
            status=AttributionStatus.INVALID_GRAPH,
            reason="cyclic_treatment_or_outcome",
            explanation=(
                "The treatment or outcome variable participates in an "
                "unresolved cycle in the Behavioral Dependency Graph. "
                "A DAG-based estimator cannot be applied to a cyclic graph."
            ),
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
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
            status=AttributionStatus.INVALID_GRAPH,
            reason="invalid_graph_cycle",
            explanation=f"SCM graph contains a cycle: {exc}",
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
        )
    except InsufficientVariationError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.INSUFFICIENT_EVIDENCE,
            reason="no_empirical_variation",
            explanation=(
                f"Variable '{exc.variable}' has no variation across the "
                "observation window. Both treatment=0 and treatment=1 (or "
                "outcome=0 and outcome=1) must be present."
            ),
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
        )
    except PositivityFailureError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.INSUFFICIENT_EVIDENCE,
            reason="positivity_failure",
            explanation=(
                f"Positivity check failed: {exc.details}. "
                "Every covariate stratum must contain both treated and "
                "control observations."
            ),
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
        )
    except CausalModelConstructionError as exc:
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.INVALID_GRAPH,
            reason="model_construction_error",
            explanation=f"DoWhy CausalModel construction failed: {exc.reason}",
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
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
            reason="unidentified_effect",
            explanation=(
                f"DoWhy identify_effect() raised: {exc}. "
                "No valid backdoor adjustment set was found."
            ),
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
            causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
        )

    is_identified = False
    if estimand is not None:
        estimands_dict = getattr(estimand, "estimands", {})
        if estimator.startswith("backdoor"):
            is_identified = estimands_dict.get("backdoor") is not None
        elif estimator.startswith("iv"):
            is_identified = estimands_dict.get("iv") is not None
        elif estimator.startswith("frontdoor"):
            is_identified = estimands_dict.get("frontdoor") is not None
        else:
            is_identified = any(v is not None for v in estimands_dict.values())

    if not is_identified:
        bound_log.warning("attribution.unidentified_effect")
        return AttributionResult(
            attribution_id=attribution_id,
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason="unidentified_backdoor_effect" if estimator.startswith("backdoor") else "unidentified_effect",
            explanation=(
                f"The causal effect is not identifiable via {estimator}: "
                "no valid adjustment set of observed covariates blocks all confounding paths "
                "under the specified causal graph and assumptions."
            ),
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
            causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
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
            status=AttributionStatus.ESTIMATION_FAILED,
            reason="estimation_failed",
            explanation=(
                f"The causal effect was identifiable, but the estimator "
                f"'{estimator}' raised an exception: {exc}. "
                "The ATE is unavailable. This is a numerical/model failure, "
                "not an identification failure."
            ),
            estimator_name=estimator,
            graph_diagnostics=projection.diagnostics,
            observation_count=len(observations),
            causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
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
            # Evaluate refutation pass condition:
            # - For placebo refuters, the treatment is replaced by noise, so the
            #   expected effect is zero (treatment effect vanishes).
            # - For stability refuters (random common cause, data subset), the
            #   new effect should remain stable within 50% of the original estimate.
            passed = True
            if refuter_name == "placebo_treatment_refuter":
                if p_value is not None:
                    passed = p_value > 0.05 or abs(new_effect) < (0.2 * abs(ate_value) if ate_value else 0.1)
                else:
                    passed = abs(new_effect) < (0.2 * abs(ate_value) if ate_value else 0.1)
            elif ate_value is not None and ate_value != 0:
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
        required_refuter_count=len(REQUIRED_REFUTERS),
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
        observation_count=len(observations),
        causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
    )
