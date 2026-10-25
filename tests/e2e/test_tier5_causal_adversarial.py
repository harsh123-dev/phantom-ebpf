"""Tier 5: Adversarial Coverage Hardening for PHANTOM Causal Engine & Preflight Guards.

White-box adversarial tests stress-testing:
1. Preflight Gate G1 software sanity guard (N < 10, N == 10, N > 10, custom minimum, wording).
2. Treatment variation validation (all T=0, all T=1, non-binary, polymorphic types, empty).
3. Anti-window slicing & independent experimental units (single run sliced, partial slicing, duplicate runs).
4. Timestamp monotonicity & observation windows (reverse causality, sub-ns boundaries, post-treatment covariates).
5. Anti-mediator DAG conditioning enforcement (mediator classification, edge filtering, confounder exclusion).
6. Decoupled 4-dimensional ground-truth & ObservationBuilder hardening (inject_ok=False, unverified drift, estimands).
7. Composite preflight gating priority & defense-in-depth verification.
"""

from __future__ import annotations

import networkx as nx
import pandas as pd
import pytest

from app.domain.causal import (
    POST_TREATMENT_MEDIATOR_NAMES,
    build_causal_data_table,
    build_scm_graph,
    check_positivity,
    construct_causal_model,
    is_post_treatment_mediator,
)
from app.domain.causal_validation import (
    REASON_AMBIGUOUS_COMPONENT,
    REASON_COVARIATE_POST_OUTCOME,
    REASON_DUPLICATE_OBSERVATIONS,
    REASON_MISSING_OUTCOME,
    REASON_NO_TREATMENT_VARIATION,
    REASON_REVERSED_TEMPORAL_ORDER,
    REASON_TOO_FEW_OBSERVATIONS,
    REASON_UNRESOLVED_COMPONENT,
    REASON_WINDOW_SLICING_DETECTED,
    GateOutcome,
    GateVerdict,
    PreflightReport,
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
    CausalObservation,
    TemporalDAGProjection,
)
from app.domain.exceptions import (
    GraphCycleError,
    InsufficientVariationError,
    PositivityFailureError,
)
from app.domain.observation_builder import (
    BuilderInsufficiency,
    CausalObservationBuilder,
    ObservationBatch,
    ObservationRecord,
    OutcomeLabel,
    RunManifest,
    RunManifestPhase,
    WindowProvenance,
)


# ===========================================================================
# 1. Preflight Gate G1 Software Sanity Guard Adversarial Stress Suite
# ===========================================================================

class TestTier5GateG1SoftwareSanityGuardAdversarial:
    """Adversarial stress tests for Preflight Gate G1 (N >= 10) technical guard."""

    @pytest.mark.parametrize("n", [-100, -1, 0, 1, 2, 5, 8, 9])
    def test_g1_strictly_blocks_below_threshold(self, n: int):
        """Gate G1 strictly blocks any sample size N < 10 with status 'insufficient_evidence'."""
        verdict = gate_minimum_observations(n, minimum=10)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_TOO_FEW_OBSERVATIONS
        assert verdict.suggested_status == "insufficient_evidence"
        assert f"Only {n} causal observation(s) available; minimum required is 10." in verdict.explanation

    def test_g1_exact_pass_at_boundary_10(self):
        """Gate G1 passes at exact boundary N == 10."""
        verdict = gate_minimum_observations(10, minimum=10)
        assert verdict.outcome == GateOutcome.PASS
        assert verdict.reason == ""
        assert verdict.suggested_status is None

    @pytest.mark.parametrize("n", [11, 15, 50, 100, 10000])
    def test_g1_passes_above_threshold(self, n: int):
        """Gate G1 passes cleanly for all N > 10."""
        verdict = gate_minimum_observations(n, minimum=10)
        assert verdict.outcome == GateOutcome.PASS

    def test_g1_custom_minimum_threshold(self):
        """Gate G1 respects caller-specified custom minimum values."""
        # Custom minimum = 5
        assert gate_minimum_observations(4, minimum=5).outcome == GateOutcome.BLOCK
        assert gate_minimum_observations(5, minimum=5).outcome == GateOutcome.PASS

        # Custom minimum = 25
        assert gate_minimum_observations(24, minimum=25).outcome == GateOutcome.BLOCK
        assert gate_minimum_observations(25, minimum=25).outcome == GateOutcome.PASS

    def test_g1_explanation_contains_mandatory_disclaimer_text(self):
        """Gate G1 explanation contains the exact disclaimer mandated by EXPERIMENT_PROTOCOL.md §6.1."""
        verdict = gate_minimum_observations(6, minimum=10)
        expected_phrase = (
            "Minimum technical guard: N >= 10 required to prevent rank-deficient "
            "regression matrices. Does not imply statistical power or identifiability."
        )
        assert expected_phrase in verdict.explanation

    def test_g1_pass_does_not_permit_causal_claim_if_variation_fails(self):
        """Adversarial scenario: N=100 observations, but all treated (T=1). G1 passes, but estimation is blocked."""
        g1_verdict = gate_minimum_observations(100)
        assert g1_verdict.outcome == GateOutcome.PASS

        # Treatment variation must catch the flaw
        t_verdict = gate_treatment_variation([1] * 100)
        assert t_verdict.outcome == GateOutcome.BLOCK
        assert t_verdict.reason == REASON_NO_TREATMENT_VARIATION


# ===========================================================================
# 2. Treatment Variation & Empirical Overlap Adversarial Suite
# ===========================================================================

class TestTier5TreatmentVariationAdversarial:
    """Adversarial stress tests for empirical treatment variation requirement."""

    def test_treatment_variation_all_ones_blocks(self):
        """All treated units (T=1, 0 controls, as in raw3/ completed runs) is strictly blocked."""
        verdict = gate_treatment_variation([1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_NO_TREATMENT_VARIATION
        assert verdict.suggested_status == "not_identifiable"
        assert "treated=10, controls=0" in verdict.explanation

    def test_treatment_variation_all_zeros_blocks(self):
        """All control units (T=0, 0 treated) is strictly blocked."""
        verdict = gate_treatment_variation([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_NO_TREATMENT_VARIATION
        assert verdict.suggested_status == "not_identifiable"
        assert "treated=0, controls=10" in verdict.explanation

    def test_treatment_variation_empty_list_blocks(self):
        """Empty observation list blocks with not_identifiable status."""
        verdict = gate_treatment_variation([])
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_NO_TREATMENT_VARIATION
        assert verdict.suggested_status == "not_identifiable"

    def test_treatment_variation_single_element_blocks(self):
        """Single treatment element cannot exhibit variation."""
        assert gate_treatment_variation([0]).outcome == GateOutcome.BLOCK
        assert gate_treatment_variation([1]).outcome == GateOutcome.BLOCK

    def test_treatment_variation_invalid_non_binary_values_blocks(self):
        """Treatments outside {0, 1} fail the requirement for treated and control units."""
        # Only values 2 and 3: neither 0 nor 1 exists
        verdict = gate_treatment_variation([2, 3, 2, 3])
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_NO_TREATMENT_VARIATION

        # Contains 0 but not 1
        verdict_no_1 = gate_treatment_variation([0, 2, 0, 2])
        assert verdict_no_1.outcome == GateOutcome.BLOCK

        # Contains 1 but not 0
        verdict_no_0 = gate_treatment_variation([1, 2, 1, 2])
        assert verdict_no_0.outcome == GateOutcome.BLOCK

    def test_treatment_variation_valid_mixed_binary(self):
        """Mixed treatments containing at least one 0 and one 1 pass."""
        verdict = gate_treatment_variation([0, 1])
        assert verdict.outcome == GateOutcome.PASS

        verdict_asymmetric = gate_treatment_variation([0] * 9 + [1])
        assert verdict_asymmetric.outcome == GateOutcome.PASS

    def test_treatment_variation_polymorphic_causal_observation_objects(self):
        """gate_treatment_variation accepts CausalObservation objects directly."""
        obs_treated = [CausalObservation(window_index=i, treatment_value=1, outcome_value=1) for i in range(5)]
        obs_control = [CausalObservation(window_index=i + 5, treatment_value=0, outcome_value=0) for i in range(5)]

        # Mixed passes
        assert gate_treatment_variation(obs_treated + obs_control).outcome == GateOutcome.PASS
        # Only treated blocks
        assert gate_treatment_variation(obs_treated).outcome == GateOutcome.BLOCK

    def test_treatment_variation_polymorphic_dict_inputs(self):
        """gate_treatment_variation accepts dictionaries with 'treatment_value' or 'treatment' keys."""
        dicts_mixed = [{"treatment_value": 0}, {"treatment_value": 1}]
        assert gate_treatment_variation(dicts_mixed).outcome == GateOutcome.PASS

        dicts_legacy = [{"treatment": 0}, {"treatment": 1}]
        assert gate_treatment_variation(dicts_legacy).outcome == GateOutcome.PASS

        dicts_all_treated = [{"treatment_value": 1}, {"treatment_value": 1}]
        assert gate_treatment_variation(dicts_all_treated).outcome == GateOutcome.BLOCK


# ===========================================================================
# 3. Anti-Window Slicing & Independent Experimental Units Adversarial Suite
# ===========================================================================

class TestTier5AntiWindowSlicingAdversarial:
    """Adversarial stress tests enforcing One Run = One Independent Experimental Unit."""

    def test_slicing_attack_single_run_sliced_into_ten_windows_blocked(self):
        """Adversarial Attack: Slicing 1 run into 10 windows to spoof Gate G1 is detected and blocked."""
        # 10 observations all bearing the same run_id
        run_ids = ["run_attack_001"] * 10
        verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)

        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_WINDOW_SLICING_DETECTED
        assert verdict.suggested_status == "insufficient_evidence"
        assert "Slicing detected: 10 observation(s) originate from only 1 unique run(s)" in verdict.explanation
        assert "Slicing one run into multiple temporal windows to satisfy Gate G1 is strictly forbidden" in verdict.explanation

    def test_slicing_attack_partial_multirun_slicing_blocked(self):
        """Adversarial Attack: 2 runs sliced into 5 windows each (total=10 obs, unique=2) is blocked."""
        run_ids = ["run_001"] * 5 + ["run_002"] * 5
        verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)

        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_WINDOW_SLICING_DETECTED
        assert "originate from only 2 unique run(s)" in verdict.explanation

    def test_slicing_attack_near_miss_nine_runs_duplicated_to_ten(self):
        """Adversarial Attack: 9 distinct runs with 1 duplicated run (total=10 obs, unique=9) is blocked."""
        run_ids = [f"run_{i:02d}" for i in range(9)] + ["run_00"]  # duplicate run_00
        assert len(run_ids) == 10
        assert len(set(run_ids)) == 9

        verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_WINDOW_SLICING_DETECTED
        assert "originate from only 9 unique run(s)" in verdict.explanation

    def test_insufficient_independent_runs_without_slicing(self):
        """8 unique runs with 8 observations (no slicing, but N < 10) blocks with too_few_observations."""
        run_ids = [f"run_{i:02d}" for i in range(8)]
        verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)

        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_TOO_FEW_OBSERVATIONS
        assert "Only 8 unique run(s) available; minimum required is 10." in verdict.explanation

    def test_ten_distinct_runs_passes(self):
        """10 distinct runs with 10 observations cleanly passes."""
        run_ids = [f"run_{i:02d}" for i in range(10)]
        verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)
        assert verdict.outcome == GateOutcome.PASS

    def test_gate_alias_independent_experimental_units_identical(self):
        """Verify gate_independent_experimental_units is an exact alias for gate_unique_run_ids."""
        assert gate_independent_experimental_units is gate_unique_run_ids

    def test_unique_run_ids_polymorphic_inputs(self):
        """gate_unique_run_ids extracts run_id from objects with .run_id and dicts."""
        # Objects with .run_id attribute (WindowProvenance)
        provs = [
            WindowProvenance(
                run_id=f"run_{i}",
                scenario_id="sc",
                window_index=0,
                window_start_iso="",
                window_end_iso="",
            )
            for i in range(10)
        ]
        assert gate_unique_run_ids(provs).outcome == GateOutcome.PASS

        # Sliced objects
        sliced_provs = [
            WindowProvenance(
                run_id="run_same",
                scenario_id="sc",
                window_index=i,
                window_start_iso="",
                window_end_iso="",
            )
            for i in range(10)
        ]
        assert gate_unique_run_ids(sliced_provs).reason == REASON_WINDOW_SLICING_DETECTED

        # Dictionaries with 'run_id'
        dicts = [{"run_id": f"run_{i}"} for i in range(10)]
        assert gate_unique_run_ids(dicts).outcome == GateOutcome.PASS

    def test_gate_no_duplicate_observations_detects_within_run_index_dups(self):
        """Duplicate window indices within observation sequence are detected and blocked."""
        # Duplicates [0, 1, 2, 2, 3]
        verdict_dup = gate_no_duplicate_observations([0, 1, 2, 2, 3])
        assert verdict_dup.outcome == GateOutcome.BLOCK
        assert verdict_dup.reason == REASON_DUPLICATE_OBSERVATIONS
        assert verdict_dup.suggested_status == "insufficient_evidence"
        assert "[2]" in verdict_dup.explanation

        # Unique passes
        assert gate_no_duplicate_observations([0, 1, 2, 3, 4]).outcome == GateOutcome.PASS


# ===========================================================================
# 4. Timestamp Monotonicity, Temporal Ordering & Observation Windows Suite
# ===========================================================================

class TestTier5TemporalPrecedenceAndObservationWindowsAdversarial:
    """Adversarial stress tests for temporal precedence (G3, G4) and window boundaries."""

    def test_temporal_order_reverse_causality_blocked(self):
        """Treatment observed after outcome (t_T > t_Y) blocks with reversed_temporal_order."""
        verdict = gate_temporal_order(treatment_first_seen_ns=1000, outcome_first_seen_ns=900)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_REVERSED_TEMPORAL_ORDER
        assert verdict.suggested_status == "not_identifiable"
        assert "A cause must precede its effect." in verdict.explanation

    def test_temporal_order_exact_simultaneous_boundary_passes(self):
        """Simultaneous treatment and outcome timestamps (t_T == t_Y) passes boundary check."""
        verdict = gate_temporal_order(treatment_first_seen_ns=5000, outcome_first_seen_ns=5000)
        assert verdict.outcome == GateOutcome.PASS

    def test_temporal_order_sub_nanosecond_boundary(self):
        """1 nanosecond reversal is strictly detected and blocked."""
        verdict = gate_temporal_order(treatment_first_seen_ns=1000000001, outcome_first_seen_ns=1000000000)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_REVERSED_TEMPORAL_ORDER

    def test_temporal_order_extreme_unix_epoch_nanoseconds(self):
        """Handles 64-bit integer nanosecond timestamps without overflow or float precision degradation."""
        # 2026-10-24 timestamp in ns (~1.792e18 ns)
        t_treat = 1792840000000000000
        t_out = 1792840000000000050

        assert gate_temporal_order(t_treat, t_out).outcome == GateOutcome.PASS
        assert gate_temporal_order(t_out, t_treat).outcome == GateOutcome.BLOCK

    def test_covariates_pre_treatment_strict_precedence(self):
        """Covariates observed strictly before treatment pass."""
        covs = {"baseline_rps": 1000, "base_memory_mb": 1500}
        assert gate_covariates_pre_treatment(covs, treatment_first_seen_ns=2000).outcome == GateOutcome.PASS

    def test_covariates_at_treatment_timestamp_pass(self):
        """Covariates observed at exact treatment timestamp (t_cov == t_T) pass."""
        covs = {"baseline_rps": 2000}
        assert gate_covariates_pre_treatment(covs, treatment_first_seen_ns=2000).outcome == GateOutcome.PASS

    def test_covariate_one_ns_after_treatment_blocked(self):
        """Post-treatment covariate observed 1 ns after treatment blocks with covariate_observed_after_outcome."""
        covs = {"post_metric": 2001}
        verdict = gate_covariates_pre_treatment(covs, treatment_first_seen_ns=2000)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_COVARIATE_POST_OUTCOME
        assert verdict.suggested_status == "invalid_graph"
        assert "post_metric" in verdict.explanation

    def test_multiple_covariates_with_single_bad_actor(self):
        """When 5 covariates are valid and 1 is post-treatment, the gate isolates and blocks the bad actor."""
        covs = {
            "valid_cov_1": 100,
            "valid_cov_2": 200,
            "valid_cov_3": 300,
            "valid_cov_4": 400,
            "valid_cov_5": 500,
            "sneaky_post_treatment_leak": 601,
        }
        verdict = gate_covariates_pre_treatment(covs, treatment_first_seen_ns=600)
        assert verdict.outcome == GateOutcome.BLOCK
        assert "sneaky_post_treatment_leak" in verdict.explanation
        assert "valid_cov_1" not in verdict.explanation

    def test_gate_covariates_precede_treatment_alias(self):
        """gate_covariates_precede_treatment is an alias for gate_covariates_pre_treatment."""
        assert gate_covariates_precede_treatment is gate_covariates_pre_treatment

    def test_outcome_present_gate_zero_positives_blocks(self):
        """Absence of positive drift cases in window (outcome count == 0) blocks with outcome_absent_from_window."""
        verdict = gate_outcome_present(0)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == REASON_MISSING_OUTCOME
        assert verdict.suggested_status == "insufficient_evidence"

    def test_outcome_present_gate_positive_count_passes(self):
        """At least one positive drift outcome passes Gate G5."""
        assert gate_outcome_present(1).outcome == GateOutcome.PASS
        assert gate_outcome_present(100).outcome == GateOutcome.PASS


# ===========================================================================
# 5. Anti-Mediator DAG Conditioning & SCM Graph Enforcement Suite
# ===========================================================================

class TestTier5AntiMediatorDAGConditioningAdversarial:
    """Adversarial stress tests enforcing anti-mediator DAG conditioning rules."""

    @pytest.mark.parametrize("mediator_name", list(POST_TREATMENT_MEDIATOR_NAMES))
    def test_all_canonical_mediators_identified(self, mediator_name: str):
        """Oracle correctly classifies every canonical post-treatment execution artifact as mediator."""
        assert is_post_treatment_mediator(mediator_name) is True

    @pytest.mark.parametrize("mediator_name", [
        "PROCESS_BEHAVIOR",
        "Syscall_Count",
        "Network_Packets",
        "Run_Duration_S",
        "SPAWNED_PIDS",
    ])
    def test_mediator_detection_case_insensitivity(self, mediator_name: str):
        """Mediator detection is case-insensitive."""
        assert is_post_treatment_mediator(mediator_name) is True

    @pytest.mark.parametrize("mediator_name", [
        "container_process_behavior_rate",
        "container_network_behavior_count",
        "intermediate_process_spawns_v2",
        "host_spawned_pid_count",
    ])
    def test_mediator_detection_substring_matching(self, mediator_name: str):
        """Mediator detection flags variables containing mediator substrings."""
        assert is_post_treatment_mediator(mediator_name) is True

    def test_mediator_detection_exact_name_vs_unlisted_compound_prefix(self):
        """Exact canonical names 'network_packets' and 'syscall_count' match, but unlisted compound prefixes do not."""
        # Exact canonical names match
        assert is_post_treatment_mediator("network_packets") is True
        assert is_post_treatment_mediator("syscall_count") is True
        # Compound names containing 'network_behavior' match via substring
        assert is_post_treatment_mediator("custom_network_behavior_metric") is True
        # But compound names with 'network_packets' without 'network_behavior' are not in SUBSTRINGS
        assert is_post_treatment_mediator("custom_network_packets_metric") is False

    def test_positivity_diagnostic_empirical_boundaries(self):
        """check_positivity returns False on strata with len >= 2 lacking overlap."""
        # Single treatment value within a stratum of size >= 2
        df_single_stratum = pd.DataFrame({"T": [1, 1, 1, 1], "cov": [1.0, 1.0, 1.0, 1.0]})
        assert check_positivity(df_single_stratum, "T", ["cov"]) is False

        # Two strata: stratum A has T=1 only, stratum B has T=0 only (complete separation)
        df_separated = pd.DataFrame({
            "T": [1, 1, 1, 1, 0, 0, 0, 0],
            "cov": [1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0],
        })
        assert check_positivity(df_separated, "T", ["cov"]) is False

        # Well-overlapped strata
        df_overlapped = pd.DataFrame({
            "T": [1, 0, 1, 0, 1, 0, 1, 0],
            "cov": [1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0],
        })
        assert check_positivity(df_overlapped, "T", ["cov"]) is True

        # When covariate is empty, checks global treatment variation
        df_no_cov = pd.DataFrame({"T": [1, 0, 1, 0]})
        assert check_positivity(df_no_cov, "T", []) is True
        df_no_cov_single = pd.DataFrame({"T": [1, 1, 1]})
        assert check_positivity(df_no_cov_single, "T", []) is False

    @pytest.mark.parametrize("pre_var", [
        "baseline_rps",
        "pre_injection_memory_mb",
        "node_os_version",
        "cpu_limit",
        "replica_count",
        "repetition",
    ])
    def test_pre_treatment_covariates_not_flagged_as_mediators(self, pre_var: str):
        """Legitimate Tier 0 pre-treatment confounders are never classified as mediators."""
        assert is_post_treatment_mediator(pre_var) is False

    def test_scm_builder_blocks_mediator_to_treatment_edges(self):
        """SCM builder explicitly blocks edges from post-treatment mediators into treatment."""
        proj = TemporalDAGProjection(
            projected_nodes=[("process_behavior", 0), ("treatment", 0), ("outcome", 0)],
            projected_edges=[
                (("process_behavior", 0), ("treatment", 0)),  # Illegal mediator -> treatment edge
                (("treatment", 0), ("outcome", 0)),
            ],
        )
        dag = build_scm_graph(
            projection=proj,
            treatment_name="treatment",
            outcome_name="outcome",
            covariate_names=[],
        )
        # Verify edge was blocked
        assert not dag.has_edge("process_behavior", "treatment")
        assert dag.has_edge("treatment", "outcome")

    def test_scm_builder_excludes_mediators_passed_in_covariates(self):
        """SCM builder excludes mediator variables mistakenly passed in covariate_names."""
        proj = TemporalDAGProjection(
            projected_nodes=[("treatment", 0), ("outcome", 0)],
            projected_edges=[(("treatment", 0), ("outcome", 0))],
        )
        # Caller attempts to condition on post-treatment mediator 'syscall_count' alongside 'baseline_rps'
        covariates = ["baseline_rps", "syscall_count", "network_packets"]
        dag = build_scm_graph(
            projection=proj,
            treatment_name="treatment",
            outcome_name="outcome",
            covariate_names=covariates,
        )

        # Baseline RPS is pre-treatment -> gets confounder edges to both treatment and outcome
        assert dag.has_edge("baseline_rps", "treatment")
        assert dag.has_edge("baseline_rps", "outcome")

        # Mediators MUST NOT receive confounder edges
        assert not dag.has_edge("syscall_count", "treatment")
        assert not dag.has_edge("syscall_count", "outcome")
        assert not dag.has_edge("network_packets", "treatment")
        assert not dag.has_edge("network_packets", "outcome")

    def test_scm_builder_ensures_dag_acyclicity(self):
        """SCM graph construction produces a valid Directed Acyclic Graph."""
        proj = TemporalDAGProjection(
            projected_nodes=[("cov1", 0), ("treatment", 0), ("outcome", 0)],
            projected_edges=[
                (("cov1", 0), ("treatment", 0)),
                (("treatment", 0), ("outcome", 0)),
            ],
        )
        dag = build_scm_graph(proj, "treatment", "outcome", ["cov1"])
        assert nx.is_directed_acyclic_graph(dag)

    def test_scm_construction_raises_on_unresolved_cycle(self):
        """construct_causal_model raises GraphCycleError when treatment/outcome in cycle."""
        proj = TemporalDAGProjection(
            projected_nodes=[("T", 0), ("Y", 0)],
            projected_edges=[],
            treatment_or_outcome_in_cycle=True,
        )
        obs = [CausalObservation(window_index=i, treatment_value=i % 2, outcome_value=i % 2) for i in range(10)]
        with pytest.raises(GraphCycleError):
            construct_causal_model(proj, obs, "T", "Y", [])

    def test_scm_construction_raises_on_insufficient_variation(self):
        """construct_causal_model raises InsufficientVariationError when treatment lacks variation."""
        proj = TemporalDAGProjection(
            projected_nodes=[("T", 0), ("Y", 0)],
            projected_edges=[(("T", 0), ("Y", 0))],
        )
        # All treatment values = 1
        obs = [CausalObservation(window_index=i, treatment_value=1, outcome_value=i % 2) for i in range(10)]
        with pytest.raises(InsufficientVariationError):
            construct_causal_model(proj, obs, "T", "Y", [])

    def test_scm_construction_raises_on_positivity_failure(self):
        """construct_causal_model raises PositivityFailureError when stratum lacks overlap."""
        proj = TemporalDAGProjection(
            projected_nodes=[("T", 0), ("Y", 0), ("stratum", 0)],
            projected_edges=[(("T", 0), ("Y", 0))],
        )
        # Stratum 1.0 has only treated (1), stratum 2.0 has only control (0)
        obs = (
            [CausalObservation(window_index=i, treatment_value=1, outcome_value=1, covariates={"stratum": 1.0}) for i in range(5)]
            + [CausalObservation(window_index=i + 5, treatment_value=0, outcome_value=0, covariates={"stratum": 2.0}) for i in range(5)]
        )
        with pytest.raises(PositivityFailureError):
            construct_causal_model(proj, obs, "T", "Y", ["stratum"])


# ===========================================================================
# 6. Decoupled 4-Dimensional Ground-Truth & ObservationBuilder Hardening Suite
# ===========================================================================

class TestTier5ObservationBuilderDecouplingAdversarial:
    """Adversarial stress tests for 4-dimensional ground-truth decoupling in ObservationBuilder."""

    def test_failed_injection_excluded_with_insufficiency(self):
        """Run with inject_ok=False is classified as FAILED_INJECTION and excluded without creating observations."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifest = RunManifest(
            run_id="run_failed_inj",
            attack_id="solarwinds-001",
            attack_family="build_pipeline_tampering",
            repetition=1,
            namespace="default",
            pod_name="cartservice",
            ground_truth_label=1,
            injection_timestamp="2026-09-05T23:11:39Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=False rollout timed out"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
            error="inject() returned False",
        )

        batch = builder.build_from_run_manifest_only(manifest)
        assert len(batch.observations) == 0
        assert batch.excluded_count == 1
        assert batch.can_proceed_to_estimation is False
        assert len(batch.insufficiencies) == 1
        assert batch.insufficiencies[0].reason_code == "failed_injection"

    def test_incomplete_run_excluded_with_insufficiency(self):
        """Run that crashed mid-experiment is excluded with incomplete_run."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifest = RunManifest(
            run_id="run_crashed",
            attack_id="xzutils-001",
            attack_family="supply_chain_backdoor",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=1,
            injection_timestamp=None,
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
            ],
            error="Node crashed during baseline phase",
        )

        batch = builder.build_from_run_manifest_only(manifest)
        assert len(batch.observations) == 0
        assert batch.excluded_count == 1
        assert batch.insufficiencies[0].reason_code == "incomplete_run"

    def test_attack_run_without_verified_drift_label_remains_unknown(self):
        """Attack run without verified contract drift label is classified as UNKNOWN and never imputed."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifest = RunManifest(
            run_id="run_unverified_telemetry",
            attack_id="xzutils-001",
            attack_family="supply_chain_backdoor",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=1,
            injection_timestamp="2026-09-05T22:31:01Z",
            first_phantom_detection_timestamp="2026-09-05T22:32:00Z",  # Detector alerted!
            mttd_s=59.0,
            is_true_positive=False,  # But ground truth drift is unverified!
            verified_contract_drift=None,  # Missing verification
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
        )

        batch = builder.build_from_run_manifest_only(manifest)
        # Even though detector fired, Y_drift != Y_hat; missing ground truth drift means unknown
        assert len(batch.observations) == 0
        assert batch.excluded_count == 1
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN

    def test_verified_contract_drift_oracle_labels(self):
        """Independent oracle verified_contract_drift=1 produces POSITIVE, 0 produces NEGATIVE."""
        builder = CausalObservationBuilder(minimum_observations=10)

        # Attack with verified contract drift
        manifest_drift_1 = RunManifest(
            run_id="run_verified_1",
            attack_id="xzutils-001",
            attack_family="supply_chain_backdoor",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=1,
            injection_timestamp="2026-09-05T22:31:01Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            verified_contract_drift=1,  # Verified drift = 1
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
        )
        batch_1 = builder.build_from_run_manifest_only(manifest_drift_1)
        assert len(batch_1.observations) == 1
        assert batch_1.observations[0].outcome_value == 1

        # Verified contract drift = 0 (e.g. benign scenario)
        manifest_drift_0 = RunManifest(
            run_id="run_verified_0",
            attack_id="benign-update-001",
            attack_family="benign_update",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=0,
            injection_timestamp=None,
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            verified_contract_drift=0,  # Verified drift = 0
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
        )
        batch_0 = builder.build_from_run_manifest_only(manifest_drift_0)
        assert len(batch_0.observations) == 1
        assert batch_0.observations[0].outcome_value == 0

    def test_treatment_target_switching_inject_vs_purl(self):
        """Builder correctly selects T_inject vs T_purl according to treatment_target parameter."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifest = RunManifest(
            run_id="run_switch",
            attack_id="xzutils-001",
            attack_family="supply_chain_backdoor",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=1,
            injection_timestamp="2026-09-05T22:31:01Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=True,
            verified_contract_drift=1,
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
        )

        batch_purl = builder.build_from_run_manifest_only(manifest, treatment_target="purl")
        assert batch_purl.observations[0].treatment_value == 1

        batch_inject = builder.build_from_run_manifest_only(manifest, treatment_target="inject")
        assert batch_inject.observations[0].treatment_value == 1

    def test_single_run_cannot_proceed_to_estimation(self):
        """A single experiment run produces at most 1 observation, always failing can_proceed_to_estimation."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifest = RunManifest(
            run_id="run_single",
            attack_id="xzutils-001",
            attack_family="supply_chain_backdoor",
            repetition=1,
            namespace="default",
            pod_name="recommendation",
            ground_truth_label=1,
            injection_timestamp="2026-09-05T22:31:01Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=True,
            verified_contract_drift=1,
            phases=[
                RunManifestPhase("baseline", "t0", "t1", 30.0),
                RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                RunManifestPhase("attack", "t2", "t3", 60.0),
                RunManifestPhase("recover", "t3", "t4", 30.0),
            ],
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 1
        assert batch.can_proceed_to_estimation is False
        assert any(ins.reason_code == "too_few_observations" for ins in batch.insufficiencies)

    def test_multi_run_batch_aggregation(self):
        """Aggregating 10 distinct runs with 5 treated and 5 controls satisfies can_proceed_to_estimation."""
        builder = CausalObservationBuilder(minimum_observations=10)
        manifests = []
        for i in range(5):
            manifests.append(RunManifest(
                run_id=f"run_attack_{i}",
                attack_id="xzutils-001",
                attack_family="supply_chain_backdoor",
                repetition=i,
                namespace="default",
                pod_name="recommendation",
                ground_truth_label=1,
                injection_timestamp="2026-09-05T22:31:01Z",
                first_phantom_detection_timestamp=None,
                mttd_s=None,
                is_true_positive=True,
                verified_contract_drift=1,
                phases=[
                    RunManifestPhase("baseline", "t0", "t1", 30.0),
                    RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                    RunManifestPhase("attack", "t2", "t3", 60.0),
                    RunManifestPhase("recover", "t3", "t4", 30.0),
                ],
            ))
            manifests.append(RunManifest(
                run_id=f"run_benign_{i}",
                attack_id="benign-update-001",
                attack_family="benign_update",
                repetition=i,
                namespace="default",
                pod_name="recommendation",
                ground_truth_label=0,
                injection_timestamp=None,
                first_phantom_detection_timestamp=None,
                mttd_s=None,
                is_true_positive=False,
                verified_contract_drift=0,
                phases=[
                    RunManifestPhase("baseline", "t0", "t1", 30.0),
                    RunManifestPhase("inject", "t1", "t2", 10.0, notes="inject_ok=True"),
                    RunManifestPhase("attack", "t2", "t3", 60.0),
                    RunManifestPhase("recover", "t3", "t4", 30.0),
                ],
            ))

        combined = builder.build_from_run_batch(manifests)
        assert combined.included_count == 10
        assert combined.can_proceed_to_estimation is True
        assert combined.has_valid_outcome_labels is True


# ===========================================================================
# 7. Composite Preflight Report & Defense-in-Depth Integration Suite
# ===========================================================================

class TestTier5PreflightCompositeDefenseInDepthAdversarial:
    """Adversarial stress tests for multi-gate interaction in run_preflight_checks."""

    def test_composite_preflight_all_valid_passes(self):
        """Consolidated preflight passes when all gates are satisfied."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            treatment_first_seen_ns=1000,
            outcome_first_seen_ns=2000,
            covariate_name_to_first_seen_ns={"baseline_rps": 500},
            minimum_observations=10,
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report.passed is True
        assert len(report.blocking_verdicts) == 0
        assert report.first_blocker is None

    def test_composite_preflight_priority_g1_blocks_first(self):
        """When N < 10, Gate G1 blocks first even if other parameters fail."""
        report = run_preflight_checks(
            observation_count=5,  # Too few!
            outcome_positive_count=0,  # Also bad!
            window_indices=[0, 0, 1, 1, 2],  # Duplicate indices!
            mapping_statuses=["UNRESOLVED"],  # Unresolved!
            minimum_observations=10,
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "G1_minimum_observations"
        assert report.first_blocker.reason == REASON_TOO_FEW_OBSERVATIONS

    def test_composite_preflight_priority_slicing_blocks_second(self):
        """When N >= 10 but slicing is used, gate_unique_run_ids blocks second."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            minimum_observations=10,
            run_ids=["run_single"] * 10,  # Slicing!
            treatment_values=[0, 1] * 5,
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "gate_unique_run_ids"
        assert report.first_blocker.reason == REASON_WINDOW_SLICING_DETECTED

    def test_composite_preflight_priority_treatment_variation_blocks_third(self):
        """When N >= 10 and unique runs, but all T=1, gate_treatment_variation blocks third."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            minimum_observations=10,
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[1] * 10,  # No variation!
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "gate_treatment_variation"
        assert report.first_blocker.reason == REASON_NO_TREATMENT_VARIATION

    def test_composite_preflight_priority_outcome_present_blocks_fourth(self):
        """When T varies but outcome has 0 positives, G5_outcome_present blocks."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=0,  # Zero positive outcomes!
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            minimum_observations=10,
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "G5_outcome_present"
        assert report.first_blocker.reason == REASON_MISSING_OUTCOME

    def test_composite_preflight_component_mapping_quality_blocks(self):
        """Unresolved or ambiguous component mapping blocks in composite preflight."""
        # Unresolved
        report_unres = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED", "UNRESOLVED"],
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report_unres.passed is False
        assert report_unres.first_blocker.gate_name == "G2_component_mapping_quality"
        assert report_unres.first_blocker.reason == REASON_UNRESOLVED_COMPONENT

        # Ambiguous
        report_amb = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED", "AMBIGUOUS"],
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report_amb.passed is False
        assert report_amb.first_blocker.gate_name == "G2_component_mapping_quality"
        assert report_amb.first_blocker.reason == REASON_AMBIGUOUS_COMPONENT

    def test_composite_preflight_temporal_precedence_blocks(self):
        """Reverse causality blocks in composite preflight."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            treatment_first_seen_ns=5000,
            outcome_first_seen_ns=4000,  # Reversed!
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "G3_temporal_order"
        assert report.first_blocker.reason == REASON_REVERSED_TEMPORAL_ORDER

    def test_composite_preflight_covariate_post_treatment_blocks(self):
        """Post-treatment covariate blocks in composite preflight."""
        report = run_preflight_checks(
            observation_count=10,
            outcome_positive_count=5,
            window_indices=list(range(10)),
            mapping_statuses=["VERIFIED"] * 10,
            treatment_first_seen_ns=5000,
            outcome_first_seen_ns=6000,
            covariate_name_to_first_seen_ns={"bad_cov": 5001},  # After treatment!
            run_ids=[f"run_{i}" for i in range(10)],
            treatment_values=[0, 1] * 5,
        )
        assert report.passed is False
        assert report.first_blocker.gate_name == "G4_covariates_pre_treatment"
        assert report.first_blocker.reason == REASON_COVARIATE_POST_OUTCOME
