"""
causal-engine domain: causal evidence gating and pre-attribution validation.

Implements the evidence-quality gates that must pass before the SCM
construction pipeline is attempted. Separated from ``causal.py`` to keep
each module single-purpose and independently testable.

Gates (in order):
  G1. Minimum observation count (INSUFFICIENT_EVIDENCE)
  G2. Component mapping quality (AMBIGUOUS_COMPONENT)
  G3. Treatment/outcome temporal ordering (INVALID_GRAPH)
  G4. Covariate temporal pre-treatment ordering (INVALID_GRAPH)
  G5. No unresolved component PURLs used as treatment variable (AMBIGUOUS_COMPONENT)

IMPORTANT — what this module does NOT claim:
  - These gates do not prove the causal estimate is correct.
  - Passing all gates does not establish causality.
  - The module records explicit assumptions for each analysis.

All data is caller-supplied (synthetic or real). Gate verdicts are
returned as structured ``GateVerdict`` objects, not raised exceptions,
so the use-case layer controls the error-handling flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Concept vocabulary (maps directly onto the Part 4 contract definitions)
# ---------------------------------------------------------------------------

# These string constants are the machine-readable reason codes used in
# AttributionResult.reason.  Keep them consistent with the audit §2.

REASON_TOO_FEW_OBSERVATIONS    = "too_few_observations"
REASON_UNRESOLVED_COMPONENT    = "unresolved_component_identity"
REASON_AMBIGUOUS_COMPONENT     = "ambiguous_component_identity"
REASON_REVERSED_TEMPORAL_ORDER = "reversed_temporal_order"
REASON_COVARIATE_POST_OUTCOME  = "covariate_observed_after_outcome"
REASON_MISSING_OUTCOME         = "outcome_absent_from_window"
REASON_CYCLIC_TREATMENT        = "cyclic_treatment_or_outcome"
REASON_NO_VARIATION            = "no_empirical_variation"
REASON_NO_TREATMENT_VARIATION  = "no_treatment_variation"
REASON_POSITIVITY_FAILURE      = "positivity_failure"
REASON_MODEL_CONSTRUCTION      = "model_construction_error"
REASON_UNIDENTIFIED_EFFECT     = "unidentified_effect"
REASON_ESTIMATION_FAILED       = "estimation_failed"
REASON_DUPLICATE_OBSERVATIONS  = "duplicate_observations_detected"
REASON_INVALID_GRAPH_CYCLE     = "invalid_graph_cycle"
REASON_WINDOW_SLICING_DETECTED = "window_slicing_detected"
REASON_TOO_FEW_INDEPENDENT_RUNS = "too_few_independent_runs"


# ---------------------------------------------------------------------------
# Gate verdict
# ---------------------------------------------------------------------------


class GateOutcome(str, Enum):
    """Outcome of a pre-attribution evidence gate."""

    PASS   = "pass"
    BLOCK  = "block"


@dataclass(frozen=True)
class GateVerdict:
    """Structured result of a single pre-attribution evidence gate.

    Attributes:
        gate_name: Short identifier for the gate that produced this verdict.
        outcome: PASS or BLOCK.
        reason: Machine-readable reason code (snake_case); empty for PASS.
        explanation: Human-readable explanation; empty for PASS.
        suggested_status: The AttributionStatus the caller should use when
            this gate blocks.  None when outcome is PASS.
    """

    gate_name: str
    outcome: GateOutcome
    reason: str = ""
    explanation: str = ""
    suggested_status: Optional[str] = None  # AttributionStatus value string


def _pass(gate_name: str) -> GateVerdict:
    return GateVerdict(gate_name=gate_name, outcome=GateOutcome.PASS)


def _block(
    gate_name: str,
    reason: str,
    explanation: str,
    status: str,
) -> GateVerdict:
    return GateVerdict(
        gate_name=gate_name,
        outcome=GateOutcome.BLOCK,
        reason=reason,
        explanation=explanation,
        suggested_status=status,
    )


# ---------------------------------------------------------------------------
# Gate functions
# ---------------------------------------------------------------------------

_MINIMUM_OBSERVATIONS = 10


def gate_minimum_observations(
    observation_count: int,
    minimum: int = _MINIMUM_OBSERVATIONS,
) -> GateVerdict:
    """G1: Ensure there are enough causal observations to attempt identification.

    Enforces Preflight Gate G1 (N >= 10) strictly as a minimum technical software
    sanity guard preventing rank-deficient regression matrices and numerical
    singularity in OLS/GLM and DoWhy estimators.

    CRITICAL CAUSAL INTERPRETATION:
    Passing N >= 10 is NOT proof of statistical power, sample adequacy, or causal
    identifiability. It is strictly a software sanity guard against singular covariance
    matrices. Causal estimation requires genuine treatment variation, comparable
    controls, valid labels, and structural exchangeability.

    Args:
        observation_count: Number of ``CausalObservation`` rows supplied.
        minimum: Minimum accepted count (default 10).

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if observation_count >= minimum:
        return _pass("G1_minimum_observations")
    return _block(
        gate_name="G1_minimum_observations",
        reason=REASON_TOO_FEW_OBSERVATIONS,
        explanation=(
            f"Only {observation_count} causal observation(s) available; "
            f"minimum required is {minimum}. "
            "Minimum technical guard: N >= 10 required to prevent rank-deficient "
            "regression matrices. Does not imply statistical power or identifiability."
        ),
        status="insufficient_evidence",
    )


def gate_treatment_variation(
    treatment_values_or_observations: list[Any],
) -> GateVerdict:
    """Ensure treatment variable exhibits empirical variation across observations.

    Requires treatment variation (T in {0, 1}), comparable controls, and valid labels
    before estimation. Blocks when T has 0 controls or 0 treatments with:
        GateVerdict(outcome=BLOCK, reason="no_treatment_variation", suggested_status="not_identifiable")

    Args:
        treatment_values_or_observations: List of integer treatment values (0/1),
            or CausalObservation objects possessing a `treatment_value` attribute,
            or dictionaries with 'treatment_value' or 'treatment' keys.

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if not treatment_values_or_observations:
        return _block(
            gate_name="gate_treatment_variation",
            reason=REASON_NO_TREATMENT_VARIATION,
            explanation=(
                "No treatment observations provided. Treatment variation requires "
                "both treatment (T=1) and control (T=0) observations."
            ),
            status="not_identifiable",
        )

    t_values: list[int] = []
    for item in treatment_values_or_observations:
        if hasattr(item, "treatment_value"):
            t_values.append(int(item.treatment_value))
        elif isinstance(item, dict) and "treatment_value" in item:
            t_values.append(int(item["treatment_value"]))
        elif isinstance(item, dict) and "treatment" in item:
            t_values.append(int(item["treatment"]))
        else:
            t_values.append(int(item))

    unique_vals = set(t_values)
    has_treated = 1 in unique_vals
    has_control = 0 in unique_vals

    if not (has_treated and has_control):
        count_treated = sum(1 for v in t_values if v == 1)
        count_control = sum(1 for v in t_values if v == 0)
        return _block(
            gate_name="gate_treatment_variation",
            reason=REASON_NO_TREATMENT_VARIATION,
            explanation=(
                f"No treatment variation in observations (treated={count_treated}, "
                f"controls={count_control}). Causal identification requires both "
                "T=1 and T=0 units; one-sided batches are not identifiable."
            ),
            status="not_identifiable",
        )

    return _pass("gate_treatment_variation")


def gate_unique_run_ids(
    run_ids_or_observations: list[Any],
    minimum_unique_runs: int = _MINIMUM_OBSERVATIONS,
) -> GateVerdict:
    """Ensure observations represent independent experimental units (one run = one unit).

    Strictly forbids splitting one run into multiple temporal windows to artificially
    satisfy Gate G1. Temporal windows within a single run are longitudinal, autocorrelated
    measurements, NOT independent cross-sectional units.

    Args:
        run_ids_or_observations: List of run_id strings, or objects possessing a
            `run_id` attribute (e.g. WindowProvenance, CausalObservationRecord).
        minimum_unique_runs: Minimum required distinct run IDs (default 10).

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if not run_ids_or_observations:
        return _block(
            gate_name="gate_unique_run_ids",
            reason=REASON_TOO_FEW_OBSERVATIONS,
            explanation="No run IDs provided; cannot verify independent experimental units.",
            status="insufficient_evidence",
        )

    extracted_ids: list[str] = []
    for item in run_ids_or_observations:
        if hasattr(item, "run_id"):
            extracted_ids.append(str(item.run_id))
        elif isinstance(item, dict) and "run_id" in item:
            extracted_ids.append(str(item["run_id"]))
        else:
            extracted_ids.append(str(item))

    unique_runs = set(extracted_ids)
    num_unique = len(unique_runs)
    total_obs = len(extracted_ids)

    # Check if multiple observations come from the same run while unique runs < minimum
    if total_obs > num_unique and num_unique < minimum_unique_runs:
        return _block(
            gate_name="gate_unique_run_ids",
            reason=REASON_WINDOW_SLICING_DETECTED,
            explanation=(
                f"Slicing detected: {total_obs} observation(s) originate from only "
                f"{num_unique} unique run(s). Slicing one run into multiple temporal "
                f"windows to satisfy Gate G1 is strictly forbidden (one run = one independent unit). "
                f"Requires at least {minimum_unique_runs} unique runs."
            ),
            status="insufficient_evidence",
        )

    if num_unique < minimum_unique_runs:
        return _block(
            gate_name="gate_unique_run_ids",
            reason=REASON_TOO_FEW_OBSERVATIONS,
            explanation=(
                f"Only {num_unique} unique run(s) available; minimum required is {minimum_unique_runs}. "
                "Each independent experimental unit must be a distinct scenario run."
            ),
            status="insufficient_evidence",
        )

    return _pass("gate_unique_run_ids")


# Aliases for interface conformity
gate_independent_experimental_units = gate_unique_run_ids


def gate_component_mapping_quality(
    mapping_statuses: list[str],
    allow_inferred: bool = True,
) -> GateVerdict:
    """G2: Ensure the treatment component has defensible identity evidence.

    Per audit C-3 and C-6: UNRESOLVED or INVALID mapping statuses mean the
    treatment variable does not correspond to an identified software component.
    Proceeding would attribute a causal effect to an unknown entity.

    AMBIGUOUS mapping statuses block by default because two candidate
    components cannot both be the treatment.

    INFERRED mapping (single file-inventory match) is allowed by default;
    the confidence penalty in ``compute_attribution_confidence`` accounts for it.

    Args:
        mapping_statuses: List of ``MappingResult.status.value`` strings for
            the events contributing to the treatment column.
        allow_inferred: If True, ``INFERRED`` statuses are accepted (default).

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if not mapping_statuses:
        return _block(
            gate_name="G2_component_mapping_quality",
            reason=REASON_UNRESOLVED_COMPONENT,
            explanation=(
                "No component mapping evidence is available for the treatment "
                "variable. Cannot attribute drift to an unidentified component."
            ),
            status="ambiguous_component",
        )

    blocking_statuses: set[str] = {"UNRESOLVED", "INVALID"}
    if not allow_inferred:
        blocking_statuses.add("INFERRED")

    blocked = [s for s in mapping_statuses if s.upper() in blocking_statuses]
    ambiguous = [s for s in mapping_statuses if s.upper() == "AMBIGUOUS"]

    if blocked:
        return _block(
            gate_name="G2_component_mapping_quality",
            reason=REASON_UNRESOLVED_COMPONENT,
            explanation=(
                f"{len(blocked)} of {len(mapping_statuses)} treatment observations "
                f"have unresolved or invalid component identity "
                f"({', '.join(blocked)}). "
                "Attribution cannot proceed without defensible evidence linking "
                "the runtime event to a specific SBOM component."
            ),
            status="ambiguous_component",
        )

    if ambiguous:
        return _block(
            gate_name="G2_component_mapping_quality",
            reason=REASON_AMBIGUOUS_COMPONENT,
            explanation=(
                f"{len(ambiguous)} of {len(mapping_statuses)} treatment observations "
                "have AMBIGUOUS component identity (multiple candidate components). "
                "Attribution to a single component is not defensible when the "
                "event matches multiple SBOM entries."
            ),
            status="ambiguous_component",
        )

    return _pass("G2_component_mapping_quality")


def gate_temporal_order(
    treatment_first_seen_ns: int,
    outcome_first_seen_ns: int,
) -> GateVerdict:
    """G3: Ensure treatment precedes outcome in wall-clock time.

    A treatment observed after the outcome cannot causally explain that outcome.
    This gate checks the nanosecond timestamps of the first treatment and first
    outcome observation.

    Args:
        treatment_first_seen_ns: Wall-clock timestamp (nanoseconds) of the
            first treatment observation.
        outcome_first_seen_ns: Wall-clock timestamp (nanoseconds) of the
            first outcome observation.

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if treatment_first_seen_ns <= outcome_first_seen_ns:
        return _pass("G3_temporal_order")
    return _block(
        gate_name="G3_temporal_order",
        reason=REASON_REVERSED_TEMPORAL_ORDER,
        explanation=(
            f"Treatment first observed at t={treatment_first_seen_ns} ns, "
            f"which is AFTER the outcome at t={outcome_first_seen_ns} ns. "
            "A cause must precede its effect. "
            "Check observation-window boundaries and clock synchronization."
        ),
        status="not_identifiable",
    )


def gate_covariates_pre_treatment(
    covariate_name_to_first_seen_ns: dict[str, int],
    treatment_first_seen_ns: int,
) -> GateVerdict:
    """G4: Ensure all covariates precede treatment in wall-clock time.

    Per audit C-2: a covariate observed after treatment violates the
    pre-treatment covariate assumption required for valid backdoor adjustment.
    Such a covariate could be a mediator or collider, not a confounder.

    Args:
        covariate_name_to_first_seen_ns: Mapping from covariate name to the
            nanosecond timestamp of its first observation.
        treatment_first_seen_ns: Nanosecond timestamp of first treatment
            observation.

    Returns:
        GateVerdict with outcome PASS or BLOCK (first violation found).
    """
    violations: list[str] = []
    for cov_name, cov_ts in covariate_name_to_first_seen_ns.items():
        if cov_ts > treatment_first_seen_ns:
            violations.append(cov_name)

    if not violations:
        return _pass("G4_covariates_pre_treatment")

    return _block(
        gate_name="G4_covariates_pre_treatment",
        reason=REASON_COVARIATE_POST_OUTCOME,
        explanation=(
            f"Covariate(s) {violations!r} were first observed AFTER the "
            "treatment event. Including post-treatment variables as covariates "
            "violates the pre-treatment assumption; they may be mediators or "
            "colliders. Remove them from the covariate set."
        ),
        status="invalid_graph",
    )


gate_covariates_precede_treatment = gate_covariates_pre_treatment


def gate_outcome_present(
    outcome_observation_count: int,
) -> GateVerdict:
    """G5: Ensure the outcome is present in the observation window.

    An outcome column with no positive cases (all zeros) means the event of
    interest was not observed. This would produce ``InsufficientVariationError``
    inside the pipeline; we surface it with a clearer pre-flight message.

    Args:
        outcome_observation_count: Number of observations where outcome == 1.

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    if outcome_observation_count > 0:
        return _pass("G5_outcome_present")
    return _block(
        gate_name="G5_outcome_present",
        reason=REASON_MISSING_OUTCOME,
        explanation=(
            "No outcome events (drift observations) are recorded in the "
            "current observation window. Causal attribution requires at least "
            "one positive outcome case. Widen the observation window or verify "
            "that the drift detector output is being consumed correctly."
        ),
        status="insufficient_evidence",
    )


def gate_no_duplicate_observations(
    window_indices: list[int],
) -> GateVerdict:
    """G6: Detect duplicate window indices in the observation list.

    Duplicate rows can distort backdoor estimates by artificially inflating
    counts and biasing the positivity check. Each window index must be unique.

    Args:
        window_indices: List of ``CausalObservation.window_index`` values.

    Returns:
        GateVerdict with outcome PASS or BLOCK.
    """
    seen: set[int] = set()
    duplicates: list[int] = []
    for idx in window_indices:
        if idx in seen:
            duplicates.append(idx)
        seen.add(idx)

    if not duplicates:
        return _pass("G6_no_duplicate_observations")

    return _block(
        gate_name="G6_no_duplicate_observations",
        reason=REASON_DUPLICATE_OBSERVATIONS,
        explanation=(
            f"Duplicate window indices detected: {sorted(set(duplicates))}. "
            "Each causal observation must correspond to a unique time window. "
            "Deduplicate before retrying attribution."
        ),
        status="insufficient_evidence",
    )


# ---------------------------------------------------------------------------
# Explicit causal assumption strings (recorded in AttributionResult)
# ---------------------------------------------------------------------------

ASSUMPTION_FORCED_TREATMENT_OUTCOME_EDGE = (
    "treatment→outcome edge was forced into the SCM graph regardless of "
    "whether the BDG contained a path from the treatment component to the "
    "outcome variable. This is a structural modeling assumption, not an "
    "empirically derived relationship."
)

ASSUMPTION_BACKDOOR_SUFFICIENT = (
    "The backdoor adjustment set is assumed to block all back-door paths from "
    "treatment to outcome. Unobserved confounders that are not in the BDG "
    "remain uncontrolled."
)

ASSUMPTION_CAUSAL_DIRECTION_ASSERTED = (
    "Causal direction (treatment causes outcome, not vice-versa) is asserted "
    "by the caller via temporal ordering. The pipeline does not independently "
    "test for reverse causality."
)

ASSUMPTION_INFERRED_IDENTITY = (
    "The treatment component was identified by file-inventory path matching "
    "(INFERRED status). This establishes component identity by path evidence, "
    "not by cryptographic hash. A different component at the same path "
    "would produce the same treatment assignment."
)

DEFAULT_CAUSAL_ASSUMPTIONS: list[str] = [
    ASSUMPTION_FORCED_TREATMENT_OUTCOME_EDGE,
    ASSUMPTION_BACKDOOR_SUFFICIENT,
    ASSUMPTION_CAUSAL_DIRECTION_ASSERTED,
]


# ---------------------------------------------------------------------------
# Composite pre-flight check
# ---------------------------------------------------------------------------


@dataclass
class PreflightReport:
    """Aggregated result of all pre-attribution evidence gates.

    Attributes:
        verdicts: List of all gate verdicts (PASS and BLOCK).
        blocking_verdicts: Subset of verdicts that are BLOCK.
        passed: True if all gates passed.
        first_blocker: The first blocking verdict, or None if all passed.
    """

    verdicts: list[GateVerdict] = field(default_factory=list)
    blocking_verdicts: list[GateVerdict] = field(default_factory=list)
    passed: bool = True
    first_blocker: GateVerdict | None = None


def run_preflight_checks(
    observation_count: int,
    outcome_positive_count: int,
    window_indices: list[int],
    mapping_statuses: list[str],
    treatment_first_seen_ns: int | None = None,
    outcome_first_seen_ns: int | None = None,
    covariate_name_to_first_seen_ns: dict[str, int] | None = None,
    minimum_observations: int = _MINIMUM_OBSERVATIONS,
    run_ids: list[Any] | None = None,
    treatment_values: list[Any] | None = None,
) -> PreflightReport:
    """Run all pre-attribution evidence gates and return a consolidated report.

    Gates are run in a fixed order. The first blocking gate determines the
    ``suggested_status`` of the ``AttributionResult``.

    Args:
        observation_count: Total number of CausalObservation rows.
        outcome_positive_count: Number of rows where outcome == 1.
        window_indices: List of CausalObservation.window_index values.
        mapping_statuses: MappingResult.status.value strings for treatment events.
        treatment_first_seen_ns: Optional ns timestamp of first treatment obs.
        outcome_first_seen_ns: Optional ns timestamp of first outcome obs.
        covariate_name_to_first_seen_ns: Optional {cov_name: ns} mapping.
        minimum_observations: Minimum accepted observation count.
        run_ids: Optional list of run_ids to verify independent experimental units.
        treatment_values: Optional list of treatment values to verify treatment variation.

    Returns:
        PreflightReport with all gate verdicts.
    """
    gates: list[GateVerdict] = []

    gates.append(gate_minimum_observations(observation_count, minimum_observations))

    if run_ids is not None:
        gates.append(gate_unique_run_ids(run_ids, minimum_observations))

    if treatment_values is not None:
        gates.append(gate_treatment_variation(treatment_values))

    gates.append(gate_outcome_present(outcome_positive_count))
    gates.append(gate_no_duplicate_observations(window_indices))
    gates.append(gate_component_mapping_quality(mapping_statuses))

    if treatment_first_seen_ns is not None and outcome_first_seen_ns is not None:
        gates.append(gate_temporal_order(treatment_first_seen_ns, outcome_first_seen_ns))

    if covariate_name_to_first_seen_ns is not None and treatment_first_seen_ns is not None:
        gates.append(
            gate_covariates_pre_treatment(
                covariate_name_to_first_seen_ns, treatment_first_seen_ns
            )
        )

    blocking = [g for g in gates if g.outcome == GateOutcome.BLOCK]
    return PreflightReport(
        verdicts=gates,
        blocking_verdicts=blocking,
        passed=len(blocking) == 0,
        first_blocker=blocking[0] if blocking else None,
    )

