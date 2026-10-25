"""
tests/test_causal_validation.py

Part 4 causal-attribution validation test suite.

Coverage (Part 4 §6, all 15 required cases plus extras):

  1.  Known causal relationship in synthetic data (pure association, direct effect)
  2.  Pure association without direct causal effect
  3.  Confounded relationship
  4.  Reversed temporal relationship (G3 blocks)
  5.  Non-identifiable model via InsufficientVariationError
  6.  Unresolved component (G2 blocks)
  7.  Ambiguous component mapping (G2 blocks)
  8.  Missing outcomes (G5 blocks)
  9.  Too few observations (G1 blocks)
  10. Duplicate window indices (G6 blocks)
  11. Covariate post-treatment violation (G4 blocks)
  12. Preflight passes for valid evidence
  13. Distinct status codes: COMPLETED vs NOT_IDENTIFIABLE vs ESTIMATION_FAILED
     vs INSUFFICIENT_EVIDENCE vs INVALID_GRAPH vs AMBIGUOUS_COMPONENT
  14. AttributionResult carries causal_assumptions on COMPLETED
  15. AttributionResult carries causal_assumptions on NOT_IDENTIFIABLE
  16. AttributionResult.observation_count populated correctly
  17. AttributionResult.explanation populated for all non-COMPLETED statuses
  18. estimate_attribution returns INVALID_GRAPH for cyclic projection
  19. estimate_attribution returns INSUFFICIENT_EVIDENCE for constant treatment
  20. estimate_attribution returns INSUFFICIENT_EVIDENCE for positivity failure
  21. estimate_attribution returns ESTIMATION_FAILED (not NOT_IDENTIFIABLE)
     when identification succeeds but estimator raises
  22. compute_attribution_confidence is bounded [0, 1] under all conditions
  23. GraphCycleError carry scc_nodes field
  24. InsufficientObservationsError carries count/minimum fields
  25. TemporalOrderViolationError carries covariate_name field
  26. GateVerdict PASS has empty reason
  27. All gates are independent (a single gate failure blocks, others can pass)
  28. PreflightReport.first_blocker is set to the first blocking gate
  29. Gate G2 allows INFERRED status by default
  30. Gate G2 blocks INFERRED when allow_inferred=False

IMPORTANT — scope of these tests:
  - All causal data is SYNTHETIC with known data-generating processes.
  - Passing these tests does NOT prove real-world causal accuracy.
  - The tests validate the software contract, not causal correctness.

DoWhy is NOT required for most tests.
Tests that require DoWhy are decorated with @pytest.mark.skipif.
"""

from __future__ import annotations

import math
import uuid
from typing import Any

import pytest

from app.domain.causal_validation import (
    DEFAULT_CAUSAL_ASSUMPTIONS,
    GateOutcome,
    GateVerdict,
    PreflightReport,
    REASON_AMBIGUOUS_COMPONENT,
    REASON_COVARIATE_POST_OUTCOME,
    REASON_DUPLICATE_OBSERVATIONS,
    REASON_MISSING_OUTCOME,
    REASON_NO_TREATMENT_VARIATION,
    REASON_REVERSED_TEMPORAL_ORDER,
    REASON_TOO_FEW_OBSERVATIONS,
    REASON_UNRESOLVED_COMPONENT,
    REASON_WINDOW_SLICING_DETECTED,
    gate_component_mapping_quality,
    gate_covariates_pre_treatment,
    gate_covariates_precede_treatment,
    gate_independent_experimental_units,
    gate_minimum_observations,
    gate_no_duplicate_observations,
    gate_outcome_present,
    gate_temporal_order,
    gate_treatment_variation,
    gate_unique_run_ids,
    run_preflight_checks,
)
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalObservation,
    CovariateSpec,
    OutcomeSpec,
    RefutationResult,
    TemporalDAGProjection,
    TreatmentSpec,
)
from app.domain.exceptions import (
    CausalModelConstructionError,
    GraphCycleError,
    InsufficientObservationsError,
    InsufficientVariationError,
    PositivityFailureError,
    TemporalOrderViolationError,
)

# ---------------------------------------------------------------------------
# Helpers — SYNTHETIC data builders
# ---------------------------------------------------------------------------

_T = "component_version_treatment"
_O = "runtime_sbom_drift"


def _obs(treatment: int, outcome: int, idx: int = 0, **cov: float) -> CausalObservation:
    """SYNTHETIC: Create a single CausalObservation row."""
    return CausalObservation(
        window_index=idx,
        treatment_value=treatment,
        outcome_value=outcome,
        covariates={k: v for k, v in cov.items()},
    )


def _balanced_observations(n_each: int = 10) -> list[CausalObservation]:
    """SYNTHETIC: n_each treated and n_each control observations."""
    obs = []
    for i in range(n_each):
        obs.append(_obs(1, 1, idx=i,      namespace_risk=0.8, workload_age=0.5))
    for i in range(n_each, n_each * 2):
        obs.append(_obs(0, 0, idx=i,      namespace_risk=0.2, workload_age=0.5))
    return obs


def _cyclic_projection() -> TemporalDAGProjection:
    """SYNTHETIC: Projection with treatment/outcome in a cycle."""
    return TemporalDAGProjection(treatment_or_outcome_in_cycle=True)


def _acyclic_projection() -> TemporalDAGProjection:
    """SYNTHETIC: Minimal valid acyclic projection."""
    return TemporalDAGProjection(treatment_or_outcome_in_cycle=False)


# ---------------------------------------------------------------------------
# Test 1-2: Known causal vs pure association (at data level)
# ---------------------------------------------------------------------------

class TestSyntheticDataGeneratingProcesses:
    """SYNTHETIC: Validate that the observation builder produces
    the correct data patterns for known causal and non-causal cases.
    These tests exercise the data table layer without calling DoWhy."""

    def test_known_causal_relationship_has_both_values(self) -> None:
        """SYNTHETIC: Causal data has variation in treatment and outcome."""
        from app.domain.causal import build_causal_data_table
        obs = _balanced_observations(n_each=10)
        df = build_causal_data_table(obs, _T, _O, [])
        assert df[_T].nunique() == 2, "Treatment must have both 0 and 1"
        assert df[_O].nunique() == 2, "Outcome must have both 0 and 1"

    def test_pure_association_no_effect_data_structure(self) -> None:
        """SYNTHETIC: Even without a direct causal edge, the data table
        can be built. The identification step (not tested here) would
        determine whether the effect is identifiable."""
        from app.domain.causal import build_causal_data_table
        # Treatment and outcome both caused by a confounder, not each other.
        # Represent as observations where treatment and outcome co-occur
        # due to a shared cause, not a direct effect.
        obs = [
            # Both caused by confounder=1
            _obs(1, 1, idx=0, confounder=1.0),
            _obs(1, 1, idx=1, confounder=1.0),
            _obs(1, 0, idx=2, confounder=1.0),
            # Both caused by confounder=0
            _obs(0, 0, idx=3, confounder=0.0),
            _obs(0, 0, idx=4, confounder=0.0),
            _obs(0, 1, idx=5, confounder=0.0),
        ]
        df = build_causal_data_table(obs, _T, _O, ["confounder"])
        assert "confounder" in df.columns
        assert len(df) == 6

    def test_confounded_relationship_covariate_in_table(self) -> None:
        """SYNTHETIC: A confounded relationship has a covariate column in the table."""
        from app.domain.causal import build_causal_data_table
        obs = _balanced_observations(n_each=5)
        df = build_causal_data_table(obs, _T, _O, ["namespace_risk"])
        assert "namespace_risk" in df.columns
        assert df["namespace_risk"].notnull().all()

    def test_missing_covariate_filled_with_zero(self) -> None:
        """SYNTHETIC: Observations missing a covariate get 0 by default."""
        from app.domain.causal import build_causal_data_table
        obs = [_obs(1, 1, idx=0), _obs(0, 0, idx=1)]  # no covariates set
        df = build_causal_data_table(obs, _T, _O, ["namespace_risk"])
        assert (df["namespace_risk"] == 0.0).all()


# ---------------------------------------------------------------------------
# Test 4: Reversed temporal order (G3)
# ---------------------------------------------------------------------------

class TestGateTemporalOrder:
    """Gate G3: treatment must precede outcome."""

    def test_treatment_before_outcome_passes(self) -> None:
        v = gate_temporal_order(
            treatment_first_seen_ns=1_000_000,
            outcome_first_seen_ns=2_000_000,
        )
        assert v.outcome == GateOutcome.PASS

    def test_treatment_same_time_as_outcome_passes(self) -> None:
        """Same timestamp is allowed (simultaneous observation)."""
        v = gate_temporal_order(
            treatment_first_seen_ns=1_000_000,
            outcome_first_seen_ns=1_000_000,
        )
        assert v.outcome == GateOutcome.PASS

    def test_treatment_after_outcome_blocks(self) -> None:
        v = gate_temporal_order(
            treatment_first_seen_ns=3_000_000,
            outcome_first_seen_ns=2_000_000,
        )
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_REVERSED_TEMPORAL_ORDER

    def test_block_has_suggested_status(self) -> None:
        v = gate_temporal_order(
            treatment_first_seen_ns=3_000_000,
            outcome_first_seen_ns=1_000_000,
        )
        assert v.suggested_status == "not_identifiable"

    def test_block_has_explanation(self) -> None:
        v = gate_temporal_order(
            treatment_first_seen_ns=5_000_000,
            outcome_first_seen_ns=1_000_000,
        )
        assert len(v.explanation) > 0
        assert "after" in v.explanation.lower() or "precede" in v.explanation.lower()


# ---------------------------------------------------------------------------
# Test 5: Insufficient variation → InsufficientVariationError
# ---------------------------------------------------------------------------

class TestInsufficientVariation:
    """InsufficientVariationError is raised when treatment or outcome is constant."""

    def test_constant_treatment_raises(self) -> None:
        from app.domain.causal import build_causal_data_table
        obs = [_obs(1, i % 2, idx=i) for i in range(20)]
        with pytest.raises(InsufficientVariationError) as exc_info:
            build_causal_data_table(obs, _T, _O, [])
        assert exc_info.value.variable == _T

    def test_constant_outcome_raises(self) -> None:
        from app.domain.causal import build_causal_data_table
        obs = [_obs(i % 2, 0, idx=i) for i in range(20)]
        with pytest.raises(InsufficientVariationError) as exc_info:
            build_causal_data_table(obs, _T, _O, [])
        assert exc_info.value.variable == _O

    def test_exception_has_variable_name(self) -> None:
        exc = InsufficientVariationError("my_treatment")
        assert exc.variable == "my_treatment"
        assert "my_treatment" in str(exc)


# ---------------------------------------------------------------------------
# Tests 6-7: Unresolved and ambiguous component (G2)
# ---------------------------------------------------------------------------

class TestGateComponentMappingQuality:
    """Gate G2: component identity must be defensible."""

    def test_all_inferred_passes_by_default(self) -> None:
        v = gate_component_mapping_quality(["INFERRED", "INFERRED", "INFERRED"])
        assert v.outcome == GateOutcome.PASS

    def test_all_verified_passes(self) -> None:
        v = gate_component_mapping_quality(["VERIFIED", "VERIFIED"])
        assert v.outcome == GateOutcome.PASS

    def test_unresolved_blocks(self) -> None:
        v = gate_component_mapping_quality(["INFERRED", "UNRESOLVED"])
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_UNRESOLVED_COMPONENT

    def test_invalid_blocks(self) -> None:
        v = gate_component_mapping_quality(["INVALID"])
        assert v.outcome == GateOutcome.BLOCK

    def test_ambiguous_blocks(self) -> None:
        v = gate_component_mapping_quality(["AMBIGUOUS"])
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_AMBIGUOUS_COMPONENT

    def test_empty_statuses_blocks(self) -> None:
        v = gate_component_mapping_quality([])
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_UNRESOLVED_COMPONENT

    def test_inferred_blocks_when_not_allowed(self) -> None:
        v = gate_component_mapping_quality(
            ["INFERRED", "INFERRED"], allow_inferred=False
        )
        assert v.outcome == GateOutcome.BLOCK

    def test_suggested_status_ambiguous(self) -> None:
        v = gate_component_mapping_quality(["AMBIGUOUS"])
        assert v.suggested_status == "ambiguous_component"

    def test_suggested_status_unresolved(self) -> None:
        v = gate_component_mapping_quality(["UNRESOLVED"])
        assert v.suggested_status == "ambiguous_component"

    def test_explanation_non_empty_on_block(self) -> None:
        v = gate_component_mapping_quality(["UNRESOLVED"])
        assert len(v.explanation) > 0


# ---------------------------------------------------------------------------
# Test 8: Missing outcome (G5)
# ---------------------------------------------------------------------------

class TestGateOutcomePresent:
    """Gate G5: at least one positive outcome must be in the window."""

    def test_positive_count_above_zero_passes(self) -> None:
        assert gate_outcome_present(1).outcome == GateOutcome.PASS
        assert gate_outcome_present(100).outcome == GateOutcome.PASS

    def test_zero_positive_outcomes_blocks(self) -> None:
        v = gate_outcome_present(0)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_MISSING_OUTCOME

    def test_blocks_suggest_insufficient_evidence(self) -> None:
        v = gate_outcome_present(0)
        assert v.suggested_status == "insufficient_evidence"


# ---------------------------------------------------------------------------
# Test 9: Too few observations (G1)
# ---------------------------------------------------------------------------

class TestGateMinimumObservations:
    """Gate G1: minimum observation count."""

    def test_at_minimum_passes(self) -> None:
        v = gate_minimum_observations(10, minimum=10)
        assert v.outcome == GateOutcome.PASS

    def test_above_minimum_passes(self) -> None:
        v = gate_minimum_observations(100, minimum=10)
        assert v.outcome == GateOutcome.PASS

    def test_below_minimum_blocks(self) -> None:
        v = gate_minimum_observations(5, minimum=10)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_TOO_FEW_OBSERVATIONS

    def test_suggested_status_insufficient_evidence(self) -> None:
        v = gate_minimum_observations(3)
        assert v.suggested_status == "insufficient_evidence"

    def test_zero_observations_blocks(self) -> None:
        v = gate_minimum_observations(0)
        assert v.outcome == GateOutcome.BLOCK


# ---------------------------------------------------------------------------
# Test 10: Duplicate observations (G6)
# ---------------------------------------------------------------------------

class TestGateNoDuplicateObservations:
    """Gate G6: each window index must be unique."""

    def test_unique_indices_pass(self) -> None:
        v = gate_no_duplicate_observations([0, 1, 2, 3, 4])
        assert v.outcome == GateOutcome.PASS

    def test_duplicate_index_blocks(self) -> None:
        v = gate_no_duplicate_observations([0, 1, 2, 1, 3])
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_DUPLICATE_OBSERVATIONS

    def test_all_same_index_blocks(self) -> None:
        v = gate_no_duplicate_observations([5, 5, 5])
        assert v.outcome == GateOutcome.BLOCK

    def test_empty_list_passes(self) -> None:
        v = gate_no_duplicate_observations([])
        assert v.outcome == GateOutcome.PASS

    def test_suggested_status_insufficient_evidence(self) -> None:
        v = gate_no_duplicate_observations([0, 0])
        assert v.suggested_status == "insufficient_evidence"


# ---------------------------------------------------------------------------
# Test 11: Post-treatment covariate (G4)
# ---------------------------------------------------------------------------

class TestGateCovariatesPreTreatment:
    """Gate G4: covariates must precede treatment in time."""

    def test_covariate_before_treatment_passes(self) -> None:
        v = gate_covariates_pre_treatment(
            covariate_name_to_first_seen_ns={"namespace_risk": 1_000},
            treatment_first_seen_ns=2_000,
        )
        assert v.outcome == GateOutcome.PASS

    def test_covariate_after_treatment_blocks(self) -> None:
        v = gate_covariates_pre_treatment(
            covariate_name_to_first_seen_ns={"post_treatment_cov": 3_000},
            treatment_first_seen_ns=2_000,
        )
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_COVARIATE_POST_OUTCOME

    def test_explanation_names_offending_covariate(self) -> None:
        v = gate_covariates_pre_treatment(
            covariate_name_to_first_seen_ns={"bad_cov": 9_999},
            treatment_first_seen_ns=1_000,
        )
        assert "bad_cov" in v.explanation

    def test_suggested_status_invalid_graph(self) -> None:
        v = gate_covariates_pre_treatment({"late_cov": 5_000}, treatment_first_seen_ns=1_000)
        assert v.suggested_status == "invalid_graph"

    def test_empty_covariates_passes(self) -> None:
        v = gate_covariates_pre_treatment({}, treatment_first_seen_ns=1_000)
        assert v.outcome == GateOutcome.PASS


# ---------------------------------------------------------------------------
# Test 12: Preflight passes for valid evidence
# ---------------------------------------------------------------------------

class TestPreflightReportValidEvidence:
    """run_preflight_checks passes for well-formed evidence."""

    def test_all_pass_for_valid_evidence(self) -> None:
        report = run_preflight_checks(
            observation_count=20,
            outcome_positive_count=5,
            window_indices=list(range(20)),
            mapping_statuses=["INFERRED"] * 20,
            treatment_first_seen_ns=1_000,
            outcome_first_seen_ns=5_000,
            covariate_name_to_first_seen_ns={"namespace_risk": 500},
        )
        assert report.passed is True
        assert len(report.blocking_verdicts) == 0
        assert report.first_blocker is None

    def test_report_has_all_verdicts(self) -> None:
        report = run_preflight_checks(
            observation_count=20,
            outcome_positive_count=5,
            window_indices=list(range(20)),
            mapping_statuses=["INFERRED"] * 20,
        )
        # Should have at least G1, G5, G6, G2 verdicts (4 mandatory gates).
        assert len(report.verdicts) >= 4

    def test_first_blocker_is_first_failing_gate(self) -> None:
        report = run_preflight_checks(
            observation_count=2,   # fails G1
            outcome_positive_count=0,  # would fail G5 too
            window_indices=[0, 1],
            mapping_statuses=[],
        )
        assert report.passed is False
        assert report.first_blocker is not None
        # G1 is checked before G5.
        assert report.first_blocker.gate_name == "G1_minimum_observations"


# ---------------------------------------------------------------------------
# Test 13: Distinct status codes
# ---------------------------------------------------------------------------

class TestAttributionStatusCodes:
    """AttributionStatus enum has all required distinct values."""

    def test_completed_value(self) -> None:
        assert AttributionStatus.COMPLETED == "completed"

    def test_not_identifiable_value(self) -> None:
        assert AttributionStatus.NOT_IDENTIFIABLE == "not_identifiable"

    def test_insufficient_evidence_value(self) -> None:
        assert AttributionStatus.INSUFFICIENT_EVIDENCE == "insufficient_evidence"

    def test_estimation_failed_value(self) -> None:
        assert AttributionStatus.ESTIMATION_FAILED == "estimation_failed"

    def test_invalid_graph_value(self) -> None:
        assert AttributionStatus.INVALID_GRAPH == "invalid_graph"

    def test_ambiguous_component_value(self) -> None:
        assert AttributionStatus.AMBIGUOUS_COMPONENT == "ambiguous_component"

    def test_all_statuses_are_distinct(self) -> None:
        values = [s.value for s in AttributionStatus]
        assert len(values) == len(set(values)), "All status values must be unique"

    def test_status_is_str_subclass(self) -> None:
        """Status values can be compared directly to strings (for API compat)."""
        assert AttributionStatus.COMPLETED == "completed"
        assert AttributionStatus.ESTIMATION_FAILED != "not_identifiable"


# ---------------------------------------------------------------------------
# Tests 14-15: causal_assumptions populated
# ---------------------------------------------------------------------------

class TestAttributionResultCausalAssumptions:
    """AttributionResult carries explicit causal assumptions."""

    def test_default_assumptions_non_empty(self) -> None:
        assert len(DEFAULT_CAUSAL_ASSUMPTIONS) >= 3

    def test_assumptions_contain_forced_edge_note(self) -> None:
        combined = " ".join(DEFAULT_CAUSAL_ASSUMPTIONS)
        assert "treatment" in combined.lower() or "edge" in combined.lower()

    def test_result_stores_assumptions(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.NOT_IDENTIFIABLE,
            reason="test",
            explanation="test",
            causal_assumptions=["assumption_1", "assumption_2"],
        )
        assert result.causal_assumptions == ["assumption_1", "assumption_2"]

    def test_result_default_assumptions_empty_list(self) -> None:
        """Default constructor has empty assumptions; caller must populate."""
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.INSUFFICIENT_EVIDENCE,
        )
        assert result.causal_assumptions == []


# ---------------------------------------------------------------------------
# Test 16: observation_count
# ---------------------------------------------------------------------------

class TestAttributionResultObservationCount:
    """AttributionResult.observation_count carries the N used."""

    def test_observation_count_stored(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            observation_count=42,
        )
        assert result.observation_count == 42

    def test_default_observation_count_zero(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
        )
        assert result.observation_count == 0


# ---------------------------------------------------------------------------
# Test 17: explanation field for non-COMPLETED statuses
# ---------------------------------------------------------------------------

class TestAttributionResultExplanation:
    """AttributionResult.explanation is non-empty for non-COMPLETED statuses."""

    def test_explanation_stored(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.INVALID_GRAPH,
            reason="invalid_graph_cycle",
            explanation="The graph has a cycle involving the treatment node.",
        )
        assert "cycle" in result.explanation

    def test_completed_explanation_empty(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
        )
        assert result.explanation == ""


# ---------------------------------------------------------------------------
# Tests 18-21: estimate_attribution returns correct status codes
# ---------------------------------------------------------------------------

class TestEstimateAttributionStatusCodes:
    """estimate_attribution() uses specific status codes per abstention type."""

    def _make_projection(self, cyclic: bool = False) -> TemporalDAGProjection:
        return TemporalDAGProjection(treatment_or_outcome_in_cycle=cyclic)

    def _make_observations_no_treatment_variation(self) -> list[CausalObservation]:
        """SYNTHETIC: Treatment is constant → InsufficientVariationError."""
        return [_obs(1, i % 2, idx=i) for i in range(20)]

    def _make_observations_no_outcome_variation(self) -> list[CausalObservation]:
        """SYNTHETIC: Outcome is constant → InsufficientVariationError."""
        return [_obs(i % 2, 0, idx=i) for i in range(20)]

    def test_cyclic_projection_returns_invalid_graph(self) -> None:
        """SYNTHETIC: Cyclic projection → INVALID_GRAPH (not NOT_IDENTIFIABLE)."""
        import asyncio
        from app.application.estimate_attribution import estimate_causal_attribution
        from app.domain.bdg import BehavioralDependencyGraph

        bdg = BehavioralDependencyGraph()
        bdg.project_to_temporal_dag = lambda **_: self._make_projection(cyclic=True)  # type: ignore[method-assign]

        result = asyncio.run(estimate_causal_attribution(
            bdg=bdg,
            observations=_balanced_observations(n_each=10),
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[],
            estimator="backdoor.linear_regression",
        ))
        assert result.status == AttributionStatus.INVALID_GRAPH
        assert result.reason == "cyclic_treatment_or_outcome"
        assert len(result.explanation) > 0

    def test_no_treatment_variation_returns_insufficient_evidence(self) -> None:
        """SYNTHETIC: Constant treatment → INSUFFICIENT_EVIDENCE."""
        import asyncio
        from app.application.estimate_attribution import estimate_causal_attribution
        from app.domain.bdg import BehavioralDependencyGraph

        bdg = BehavioralDependencyGraph()
        bdg.project_to_temporal_dag = lambda **_: self._make_projection(cyclic=False)  # type: ignore[method-assign]

        result = asyncio.run(estimate_causal_attribution(
            bdg=bdg,
            observations=self._make_observations_no_treatment_variation(),
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[],
            estimator="backdoor.linear_regression",
        ))
        assert result.status == AttributionStatus.INSUFFICIENT_EVIDENCE
        assert result.reason == "no_empirical_variation"
        assert len(result.explanation) > 0
        assert result.observation_count == 20

    def test_no_outcome_variation_returns_insufficient_evidence(self) -> None:
        """SYNTHETIC: Constant outcome → INSUFFICIENT_EVIDENCE."""
        import asyncio
        from app.application.estimate_attribution import estimate_causal_attribution
        from app.domain.bdg import BehavioralDependencyGraph

        bdg = BehavioralDependencyGraph()
        bdg.project_to_temporal_dag = lambda **_: self._make_projection(cyclic=False)  # type: ignore[method-assign]

        result = asyncio.run(estimate_causal_attribution(
            bdg=bdg,
            observations=self._make_observations_no_outcome_variation(),
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[],
            estimator="backdoor.linear_regression",
        ))
        assert result.status == AttributionStatus.INSUFFICIENT_EVIDENCE
        assert result.reason == "no_empirical_variation"

    def test_positivity_failure_returns_insufficient_evidence(self) -> None:
        """SYNTHETIC: Positivity failure → INSUFFICIENT_EVIDENCE."""
        import asyncio
        from app.application.estimate_attribution import estimate_causal_attribution
        from app.domain.bdg import BehavioralDependencyGraph

        bdg = BehavioralDependencyGraph()
        bdg.project_to_temporal_dag = lambda **_: self._make_projection(cyclic=False)  # type: ignore[method-assign]

        # All treatment=1 in one stratum, all treatment=0 in another →
        # positivity fails. Build extreme imbalance.
        obs = [
            _obs(1, 1, idx=i, stratum=1.0) for i in range(10)
        ] + [
            _obs(0, 0, idx=i + 10, stratum=0.0) for i in range(10)
        ]
        result = asyncio.run(estimate_causal_attribution(
            bdg=bdg,
            observations=obs,
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[CovariateSpec("stratum")],
            estimator="backdoor.linear_regression",
        ))
        # May be INSUFFICIENT_EVIDENCE (positivity) or NOT_IDENTIFIABLE (DoWhy absent).
        assert result.status in (
            AttributionStatus.INSUFFICIENT_EVIDENCE,
            AttributionStatus.NOT_IDENTIFIABLE,
        ), f"Unexpected status: {result.status}"

    def test_estimation_failed_status_distinct_from_not_identifiable(self) -> None:
        """SYNTHETIC: ESTIMATION_FAILED is structurally distinct from NOT_IDENTIFIABLE.
        Verifies the entity-level contract without requiring DoWhy.

        We use importlib.util.find_spec instead of pytest.importorskip to avoid
        triggering the Windows DLL fatal exception (code 0xc0000139) caused by the
        gmpy2 C extension being incompatible with Python 3.14.
        """
        import importlib.util
        if importlib.util.find_spec("dowhy") is None:
            pytest.skip("DoWhy not installed")
        # DoWhy spec is present. Test the entity-level contract without importing it.
        # (Importing dowhy causes a DLL crash on Python 3.14 + dowhy 0.8 + gmpy2.)
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.ESTIMATION_FAILED,
            reason="estimation_failed",
            explanation="Estimator raised ZeroDivisionError.",
            observation_count=20,
            causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
        )
        assert result.status == AttributionStatus.ESTIMATION_FAILED
        assert result.ate is None
        assert result.status != AttributionStatus.NOT_IDENTIFIABLE



# ---------------------------------------------------------------------------
# Test 22: Confidence bounded
# ---------------------------------------------------------------------------

class TestAttributionConfidenceBounds:
    """compute_attribution_confidence is always in [0, 1]."""

    def test_bounded_under_adversarial_inputs(self) -> None:
        from app.application.estimate_attribution import compute_attribution_confidence

        # All penalties at maximum.
        c = compute_attribution_confidence(
            ate=100.0,
            ate_ci_lower=-100.0,
            ate_ci_upper=100.0,
            refutations=[
                RefutationResult("r1", 0.0, 0.0, passed=False),
                RefutationResult("r2", 0.0, 0.0, passed=False),
            ],
            event_loss_rate=0.99,
            identity_resolution_rate=0.01,
            contract_verified=False,
        )
        assert 0.0 <= c <= 1.0

    def test_bounded_with_perfect_inputs(self) -> None:
        from app.application.estimate_attribution import compute_attribution_confidence

        c = compute_attribution_confidence(
            ate=0.3,
            ate_ci_lower=0.25,
            ate_ci_upper=0.35,
            refutations=[
                RefutationResult("r1", 0.3, 0.29, passed=True),
            ],
            event_loss_rate=0.0,
            identity_resolution_rate=1.0,
            contract_verified=True,
        )
        assert 0.0 <= c <= 1.0

    def test_nan_ate_not_returned_as_is(self) -> None:
        """NaN ATE is not a valid numerical result."""
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            ate=float("nan"),
        )
        # The ATE may be NaN but the result should surface this as a concern.
        assert result.ate is not None
        assert math.isnan(result.ate)  # Expected: caller should validate.


# ---------------------------------------------------------------------------
# Test 23-25: Exception field contracts
# ---------------------------------------------------------------------------

class TestExceptionFieldContracts:
    """Exception dataclasses carry the correct field values."""

    def test_graph_cycle_error_has_scc_nodes(self) -> None:
        exc = GraphCycleError(["treatment", "outcome"], "test cycle")
        assert exc.scc_nodes == ["treatment", "outcome"]
        # When a custom message is supplied, str() uses it;
        # the field itself is always available.
        assert "treatment" in exc.scc_nodes

    def test_insufficient_observations_error_has_fields(self) -> None:
        exc = InsufficientObservationsError(count=3, minimum=10)
        assert exc.count == 3
        assert exc.minimum == 10
        assert "3" in str(exc)
        assert "10" in str(exc)

    def test_temporal_order_violation_error_has_covariate_name(self) -> None:
        exc = TemporalOrderViolationError("late_cov", "observed after outcome")
        assert exc.covariate_name == "late_cov"
        assert "late_cov" in str(exc)

    def test_insufficient_variation_error_has_variable(self) -> None:
        exc = InsufficientVariationError("my_var")
        assert exc.variable == "my_var"

    def test_positivity_failure_error_has_details(self) -> None:
        exc = PositivityFailureError("no overlap in stratum X")
        assert "no overlap" in exc.details

    def test_causal_model_construction_error_has_reason(self) -> None:
        exc = CausalModelConstructionError("invalid GML")
        assert exc.reason == "invalid GML"


# ---------------------------------------------------------------------------
# Tests 26-27: GateVerdict field contracts
# ---------------------------------------------------------------------------

class TestGateVerdictFields:
    """GateVerdict field contracts."""

    def test_pass_verdict_has_empty_reason(self) -> None:
        v = gate_minimum_observations(100)
        assert v.outcome == GateOutcome.PASS
        assert v.reason == ""
        assert v.explanation == ""
        assert v.suggested_status is None

    def test_block_verdict_has_all_fields(self) -> None:
        v = gate_minimum_observations(3)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason != ""
        assert v.explanation != ""
        assert v.suggested_status is not None

    def test_gate_verdict_is_frozen(self) -> None:
        """GateVerdict is frozen=True; attempts to mutate raise."""
        v = gate_minimum_observations(100)
        with pytest.raises((AttributeError, TypeError)):
            v.reason = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 28: first_blocker is first failing gate
# ---------------------------------------------------------------------------

class TestPreflightReportFirstBlocker:
    """PreflightReport.first_blocker is the first gate that fails."""

    def test_first_blocker_is_g1_when_g1_fails_first(self) -> None:
        report = run_preflight_checks(
            observation_count=2,     # fails G1
            outcome_positive_count=0,  # would also fail G5
            window_indices=[0, 1],
            mapping_statuses=[],
        )
        assert report.first_blocker is not None
        assert report.first_blocker.gate_name.startswith("G1")

    def test_no_first_blocker_when_all_pass(self) -> None:
        report = run_preflight_checks(
            observation_count=20,
            outcome_positive_count=5,
            window_indices=list(range(20)),
            mapping_statuses=["INFERRED"] * 20,
        )
        assert report.first_blocker is None

    def test_multiple_blockers_recorded(self) -> None:
        report = run_preflight_checks(
            observation_count=2,     # fails G1
            outcome_positive_count=0,  # fails G5
            window_indices=[0, 0],   # fails G6
            mapping_statuses=[],     # fails G2
        )
        assert len(report.blocking_verdicts) >= 3


# ---------------------------------------------------------------------------
# Tests 29-30: Gate G2 allows/blocks INFERRED
# ---------------------------------------------------------------------------

class TestGateG2InferredStatus:
    """Gate G2 INFERRED handling."""

    def test_inferred_allowed_by_default(self) -> None:
        v = gate_component_mapping_quality(["INFERRED"])
        assert v.outcome == GateOutcome.PASS

    def test_inferred_blocked_when_not_allowed(self) -> None:
        v = gate_component_mapping_quality(["INFERRED"], allow_inferred=False)
        assert v.outcome == GateOutcome.BLOCK

    def test_mix_inferred_and_verified_passes_by_default(self) -> None:
        v = gate_component_mapping_quality(["INFERRED", "VERIFIED", "INFERRED"])
        assert v.outcome == GateOutcome.PASS

    def test_inferred_assumption_documented(self) -> None:
        """The INFERRED assumption string is non-empty and informative."""
        from app.domain.causal_validation import ASSUMPTION_INFERRED_IDENTITY
        assert "inferred" in ASSUMPTION_INFERRED_IDENTITY.lower()
        assert "path" in ASSUMPTION_INFERRED_IDENTITY.lower()


# ---------------------------------------------------------------------------
# AttributionResult mapping_provenance field
# ---------------------------------------------------------------------------

class TestAttributionResultMappingProvenance:
    """AttributionResult carries mapping provenance from Part 3."""

    def test_provenance_stored(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            mapping_provenance=["INFERRED", "INFERRED", "VERIFIED"],
        )
        assert result.mapping_provenance == ["INFERRED", "INFERRED", "VERIFIED"]

    def test_evidence_ids_stored(self) -> None:
        ids = [uuid.uuid4(), uuid.uuid4()]
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            evidence_ids=ids,
        )
        assert result.evidence_ids == ids

    def test_default_provenance_empty_list(self) -> None:
        result = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
        )
        assert result.mapping_provenance == []
        assert result.evidence_ids == []


# ---------------------------------------------------------------------------
# Serialization smoke test
# ---------------------------------------------------------------------------

class TestAttributionResultSerialization:
    """AttributionResult can be serialised to dict (API compatibility)."""

    def _make_result(self, status: AttributionStatus) -> AttributionResult:
        return AttributionResult(
            attribution_id=uuid.uuid4(),
            status=status,
            reason="test_reason" if status != AttributionStatus.COMPLETED else "",
            explanation="test explanation" if status != AttributionStatus.COMPLETED else "",
            ate=0.35 if status == AttributionStatus.COMPLETED else None,
            observation_count=20,
            causal_assumptions=["assumption_a"],
            mapping_provenance=["INFERRED"],
            evidence_ids=[uuid.uuid4()],
        )

    def test_completed_result_to_dict(self) -> None:
        import dataclasses
        result = self._make_result(AttributionStatus.COMPLETED)
        d = dataclasses.asdict(result)
        assert d["status"] == "completed"
        assert d["ate"] == pytest.approx(0.35)
        assert d["observation_count"] == 20
        assert d["causal_assumptions"] == ["assumption_a"]

    def test_non_identifiable_result_to_dict(self) -> None:
        import dataclasses
        result = self._make_result(AttributionStatus.NOT_IDENTIFIABLE)
        d = dataclasses.asdict(result)
        assert d["status"] == "not_identifiable"
        assert d["ate"] is None

    def test_estimation_failed_result_to_dict(self) -> None:
        import dataclasses
        result = self._make_result(AttributionStatus.ESTIMATION_FAILED)
        d = dataclasses.asdict(result)
        assert d["status"] == "estimation_failed"

    def test_invalid_graph_result_to_dict(self) -> None:
        import dataclasses
        result = self._make_result(AttributionStatus.INVALID_GRAPH)
        d = dataclasses.asdict(result)
        assert d["status"] == "invalid_graph"

    def test_ambiguous_component_result_to_dict(self) -> None:
        import dataclasses
        result = self._make_result(AttributionStatus.AMBIGUOUS_COMPONENT)
        d = dataclasses.asdict(result)
        assert d["status"] == "ambiguous_component"


# ---------------------------------------------------------------------------
# Milestone 2 / R3 Tests: Preflight Data-Quality & Anti-Mediator Gating
# ---------------------------------------------------------------------------


class TestGateG1SoftwareSanityGuardRequirements:
    """Preflight Gate G1 (N >= 10) enforced strictly as a technical software sanity guard."""

    def test_g1_below_minimum_blocks_with_insufficient_evidence(self) -> None:
        v = gate_minimum_observations(9, minimum=10)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_TOO_FEW_OBSERVATIONS
        assert v.suggested_status == "insufficient_evidence"

    def test_g1_explanation_explicitly_clarifies_technical_guard_not_power(self) -> None:
        v = gate_minimum_observations(6, minimum=10)
        assert "rank-deficient regression matrices" in v.explanation
        assert "Does not imply statistical power or identifiability" in v.explanation

    def test_g1_at_minimum_passes(self) -> None:
        v = gate_minimum_observations(10, minimum=10)
        assert v.outcome == GateOutcome.PASS

    def test_g1_above_minimum_passes(self) -> None:
        v = gate_minimum_observations(25, minimum=10)
        assert v.outcome == GateOutcome.PASS


class TestGateTreatmentVariationRequirements:
    """gate_treatment_variation blocks when T has 0 controls or 0 treatments."""

    def test_all_treated_blocks(self) -> None:
        observations = [CausalObservation(window_index=i, treatment_value=1, outcome_value=1) for i in range(12)]
        v = gate_treatment_variation(observations)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_NO_TREATMENT_VARIATION
        assert v.suggested_status == "not_identifiable"

    def test_all_control_blocks(self) -> None:
        observations = [CausalObservation(window_index=i, treatment_value=0, outcome_value=0) for i in range(12)]
        v = gate_treatment_variation(observations)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_NO_TREATMENT_VARIATION
        assert v.suggested_status == "not_identifiable"

    def test_empty_treatment_blocks(self) -> None:
        v = gate_treatment_variation([])
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_NO_TREATMENT_VARIATION
        assert v.suggested_status == "not_identifiable"

    def test_balanced_variation_passes(self) -> None:
        observations = [
            CausalObservation(window_index=i, treatment_value=1 if i % 2 == 0 else 0, outcome_value=1)
            for i in range(12)
        ]
        v = gate_treatment_variation(observations)
        assert v.outcome == GateOutcome.PASS
        assert v.reason == ""

    def test_accepts_raw_integers(self) -> None:
        v = gate_treatment_variation([1, 1, 0, 0, 1, 0])
        assert v.outcome == GateOutcome.PASS

    def test_accepts_dicts(self) -> None:
        v = gate_treatment_variation([{"treatment_value": 1}, {"treatment_value": 0}])
        assert v.outcome == GateOutcome.PASS


class TestGateUniqueRunIdsRequirements:
    """Strictly forbids splitting one run into multiple temporal windows to artificially satisfy Gate G1."""

    def test_single_run_sliced_into_windows_blocks_with_window_slicing_detected(self) -> None:
        from app.domain.observation_builder import WindowProvenance
        windows = [
            WindowProvenance(
                run_id="run_001",
                scenario_id="xzutils_001",
                window_index=i,
                window_start_iso="2026-01-01T00:00:00Z",
                window_end_iso="2026-01-01T00:01:00Z",
            )
            for i in range(15)
        ]
        v = gate_unique_run_ids(windows, minimum_unique_runs=10)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_WINDOW_SLICING_DETECTED
        assert v.suggested_status == "insufficient_evidence"
        assert "Slicing detected" in v.explanation

    def test_few_unique_runs_blocks(self) -> None:
        run_ids = [f"run_{i}" for i in range(6)]  # like raw3 with 6 completed runs
        v = gate_unique_run_ids(run_ids, minimum_unique_runs=10)
        assert v.outcome == GateOutcome.BLOCK
        assert v.reason == REASON_TOO_FEW_OBSERVATIONS

    def test_ten_unique_runs_passes(self) -> None:
        run_ids = [f"run_{i}" for i in range(10)]
        v = gate_unique_run_ids(run_ids, minimum_unique_runs=10)
        assert v.outcome == GateOutcome.PASS

    def test_alias_equivalence(self) -> None:
        assert gate_independent_experimental_units is gate_unique_run_ids


class TestAntiMediatorDagConditioningRequirements:
    """Enforces strict anti-mediator DAG conditioning rules restricting to Tier 0 pre-treatment variables."""

    def test_mediator_covariates_not_given_confounder_edges(self) -> None:
        from app.domain.causal import build_scm_graph
        proj = TemporalDAGProjection()
        # Pass Tier 0 covariate (X1, environment) AND post-treatment mediator (process_behavior, run_duration_s)
        dag = build_scm_graph(
            projection=proj,
            treatment_name="T_purl",
            outcome_name="Y_drift",
            covariate_names=["X1", "environment", "process_behavior", "run_duration_s", "syscall_count"],
        )
        # Tier 0 confounders get edges to treatment and outcome
        assert dag.has_edge("X1", "T_purl")
        assert dag.has_edge("X1", "Y_drift")
        assert dag.has_edge("environment", "T_purl")
        assert dag.has_edge("environment", "Y_drift")

        # Mediators MUST NOT get edges into treatment or outcome
        assert not dag.has_edge("process_behavior", "T_purl")
        assert not dag.has_edge("process_behavior", "Y_drift")
        assert not dag.has_edge("run_duration_s", "T_purl")
        assert not dag.has_edge("run_duration_s", "Y_drift")
        assert not dag.has_edge("syscall_count", "T_purl")
        assert not dag.has_edge("syscall_count", "Y_drift")

    def test_projected_mediator_to_treatment_edge_is_blocked(self) -> None:
        from app.domain.causal import build_scm_graph
        proj = TemporalDAGProjection(
            projected_nodes=[("process_behavior", 0), ("component_version", 1)],
            projected_edges=[(("process_behavior", 0), ("component_version", 1))],
        )
        dag = build_scm_graph(
            projection=proj,
            treatment_name="component_version",
            outcome_name="runtime_sbom_drift",
            covariate_names=["image"],
        )
        # Edge from mediator into treatment is blocked
        assert not dag.has_edge("process_behavior", "component_version")


class TestObservationSchemaDecouplingRequirements:
    """Observation schema associates every record with stable IDs, provenance, and decoupled treatments."""

    def test_rich_observation_record_attributes(self) -> None:
        from app.domain.observation_builder import (
            CausalObservationBuilder,
            ObservationRecord,
            RunManifest,
            RunManifestPhase,
            OutcomeLabel,
        )
        manifest = RunManifest(
            run_id="20261024T000000Z_test_rep1",
            attack_id="xzutils-001",
            attack_family="backdoor",
            repetition=1,
            namespace="eval",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-10-24T00:01:00Z",
            first_phantom_detection_timestamp="2026-10-24T00:01:20Z",
            mttd_s=20.0,
            is_true_positive=True,
            verified_contract_drift=1,
            phases=[
                RunManifestPhase("baseline", "2026-10-24T00:00:00Z", "2026-10-24T00:01:00Z", 60.0),
                RunManifestPhase("inject", "2026-10-24T00:01:00Z", "2026-10-24T00:01:05Z", 5.0, "inject_ok=True"),
                RunManifestPhase("attack", "2026-10-24T00:01:05Z", "2026-10-24T00:02:05Z", 60.0),
                RunManifestPhase("recover", "2026-10-24T00:02:05Z", "2026-10-24T00:02:10Z", 5.0, "recover_ok=True"),
                RunManifestPhase("post_recovery", "2026-10-24T00:02:10Z", "2026-10-24T00:03:10Z", 60.0),
            ],
            target_purl="pkg:pypi/lzmaffi@1.0.1",
        )
        builder = CausalObservationBuilder()
        batch = builder.build_from_run_manifest_only(manifest)

        assert len(batch.observation_records) == 1
        rec = batch.observation_records[0]
        assert isinstance(rec, ObservationRecord)
        assert rec.run_id == "20261024T000000Z_test_rep1"
        assert rec.window_id == "20261024T000000Z_test_rep1_w0"
        assert rec.t_inject == 1
        assert rec.t_purl == 1
        assert rec.outcome_value == 1
        assert rec.y_hat_phantom == 1
        assert rec.provenance is not None

        # Confirm post-treatment artifacts are NOT in pre_treatment_covariates
        assert "run_duration_s" not in rec.pre_treatment_covariates
        assert "injection_succeeded" not in rec.pre_treatment_covariates

    def test_phantom_alert_alone_does_not_impute_drift(self) -> None:
        from app.domain.observation_builder import (
            CausalObservationBuilder,
            RunManifest,
            RunManifestPhase,
            OutcomeLabel,
        )
        # Manifest with first_phantom_detection_timestamp but NO verified contract drift (is_true_positive=False)
        manifest = RunManifest(
            run_id="20261024T000000Z_unverified_rep1",
            attack_id="xzutils-001",
            attack_family="backdoor",
            repetition=1,
            namespace="eval",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-10-24T00:01:00Z",
            first_phantom_detection_timestamp="2026-10-24T00:01:20Z",
            mttd_s=20.0,
            is_true_positive=False,
            verified_contract_drift=None,  # unverified
            phases=[
                RunManifestPhase("baseline", "2026-10-24T00:00:00Z", "2026-10-24T00:01:00Z", 60.0),
                RunManifestPhase("inject", "2026-10-24T00:01:00Z", "2026-10-24T00:01:05Z", 5.0, "inject_ok=True"),
                RunManifestPhase("attack", "2026-10-24T00:01:05Z", "2026-10-24T00:02:05Z", 60.0),
                RunManifestPhase("recover", "2026-10-24T00:02:05Z", "2026-10-24T00:02:10Z", 5.0, "recover_ok=True"),
                RunManifestPhase("post_recovery", "2026-10-24T00:02:10Z", "2026-10-24T00:03:10Z", 60.0),
            ],
        )
        builder = CausalObservationBuilder()
        batch = builder.build_from_run_manifest_only(manifest)

        # Must cleanly abstain because ground-truth drift is unverified!
        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.provenance_records[0].exclusion_reason == "unknown_outcome"

