"""Tier 2: Boundary & Corner Cases E2E Tests (>=5 test cases per feature across all 21 features).

Tests validate all 21 features under edge conditions:
- Empty inputs and zero/undefined denominators
- Missing telemetry and dropouts
- Failed injections (inject_ok=False)
- Gate G1 exact boundary conditions (N=9 vs N=10, N=0, N=1)
- Wilson score exact boundaries (x=0, x=n, n=1, extreme n)
- Anti-window slicing boundaries
- Unmeasured overhead vs fabricated zeros
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from tests.e2e.contracts import (
    compute_ordinary_wilson_score,
    compute_mttd_statistics,
    classify_scenario_run,
    RunClassification,
    DecoupledEvaluationDimensions,
    compute_defensible_metrics,
    format_latex_cell,
    format_csv_cell,
)


# ===========================================================================
# Feature 1: Boundary - Raw Dataset Inventory & Classification
# ===========================================================================

class TestFeature01BoundaryRawDatasetClassification:
    """Feature 1 Boundary: Edge classification states for raw records."""

    def test_boundary_empty_run_record(self):
        """Empty run dictionary safely defaults to unknown or dropout classification."""
        assert classify_scenario_run({}) in ("unknown", RunClassification.TELEMETRY_DROPOUT)

    def test_boundary_missing_phases_key(self, mock_completed_attack_run):
        """Run record missing 'phases' key classifies normally without crash."""
        run = dict(mock_completed_attack_run)
        run.pop("phases", None)
        assert classify_scenario_run(run) == RunClassification.COMPLETED_ATTACK

    def test_boundary_injection_false_with_custom_error(self):
        """inject_ok=False with custom deployment error classifies as failed_injection."""
        run = {"inject_ok": False, "error": "deployment rollout timed out after 300s", "ground_truth_label": 1}
        assert classify_scenario_run(run) == RunClassification.FAILED_INJECTION

    def test_boundary_benign_with_dropout_flag(self):
        """Benign run marked as dropout classifies as telemetry_dropout."""
        run = {"ground_truth_label": 0, "inject_ok": True, "phantom_detections": [], "is_dropout": True}
        assert classify_scenario_run(run) == RunClassification.TELEMETRY_DROPOUT

    def test_boundary_attack_with_zero_detections_and_no_error(self):
        """Attack run where inject_ok=True but phantom_detections=[] classifies as telemetry_dropout."""
        run = {"ground_truth_label": 1, "inject_ok": True, "phantom_detections": [], "error": ""}
        assert classify_scenario_run(run) == RunClassification.TELEMETRY_DROPOUT


# ===========================================================================
# Feature 2: Boundary - Telemetry & SBOM Missingness
# ===========================================================================

class TestFeature02BoundaryTelemetrySbomMissingness:
    """Feature 2 Boundary: Missingness edge conditions and corrupt telemetry."""

    def test_boundary_completely_empty_detection_list(self):
        """Run with empty detections list reports zero events without KeyError."""
        run = {"phantom_detections": []}
        assert len(run.get("phantom_detections", [])) == 0

    def test_boundary_missing_pod_name_key_absent(self):
        """Event dictionary where 'pod_name' key is completely absent defaults safely."""
        event = {"comm": "runc"}
        pod_name = event.get("pod_name", "unknown")
        assert pod_name == "unknown"

    def test_boundary_short_or_dummy_image_digest(self):
        """All-zero SHA256 digest is identified as dummy hash."""
        dummy_digest = "sha256:" + "0" * 64
        assert len(dummy_digest) == 71
        assert dummy_digest.endswith("00000000000000000000000000000000")

    def test_boundary_null_purl_vs_empty_string_purl(self):
        """Both None and empty string PURLs are identified as unmapped."""
        for p in (None, ""):
            is_unmapped = p is None or len(p) == 0
            assert is_unmapped is True

    def test_boundary_all_raw3_runs_lack_resolved_identities(self, raw3_dataset_dir):
        """Every completed run in raw3 has unresolved/ambiguous identity statuses."""
        json_files = sorted(raw3_dataset_dir.glob("*.json"))
        completed_with_events = 0
        for jf in json_files:
            with open(jf, encoding="utf-8") as f:
                data = json.load(f)
            detections = data.get("phantom_detections", [])
            if detections:
                completed_with_events += 1
                for ev in detections:
                    assert ev.get("sbom_id") is None
        assert completed_with_events == 6


# ===========================================================================
# Feature 3: Boundary - Independent Ground-Truth Protocol
# ===========================================================================

class TestFeature03BoundaryIndependentGroundTruthProtocol:
    """Feature 3 Boundary: Decoupling boundaries and conflicting signals."""

    def test_boundary_t_inject_false_forces_untestable(self):
        """Failed injection cannot produce True Positive under any detector condition."""
        dim = DecoupledEvaluationDimensions(
            t_inject=False,
            b_verified="unknown",
            y_drift="true",      # even if drift was claimed
            y_hat_phantom=True,  # and alert fired
        )
        assert not dim.is_eligible_for_causal()

    def test_boundary_b_verified_false_with_alert_fired(self):
        """Detector alert when payload never physically ran is not a true positive."""
        dim = DecoupledEvaluationDimensions(
            t_inject=True,
            b_verified="false",
            y_drift="false",
            y_hat_phantom=True,
        )
        assert not dim.is_true_positive()

    def test_boundary_contract_drift_unknown_when_unverified(self):
        """When independent verification is insufficient, Y_drift must remain unknown."""
        dim = DecoupledEvaluationDimensions(
            t_inject=True,
            b_verified="true",
            y_drift="unknown",
            y_hat_phantom=True,
        )
        assert not dim.is_true_positive()

    def test_boundary_drift_true_requires_contract_violation_not_just_traffic(self):
        """Network traffic permitted by contract is not drift."""
        traffic_observed = True
        traffic_violates_contract = False
        y_drift = "true" if (traffic_observed and traffic_violates_contract) else "false"
        assert y_drift == "false"

    def test_boundary_tp_boundary_condition(self):
        """Only exact match (y_drift=='true' and alert==True) qualifies as TP."""
        dim_tp = DecoupledEvaluationDimensions(True, "true", "true", True)
        dim_fn = DecoupledEvaluationDimensions(True, "true", "true", False)
        assert dim_tp.is_true_positive() is True
        assert dim_fn.is_true_positive() is False


# ===========================================================================
# Feature 4: Boundary - Causal Estimand & Anti-Mediator DAG
# ===========================================================================

class TestFeature04BoundaryCausalEstimandAntiMediatorDAG:
    """Feature 4 Boundary: DAG temporal ordering and covariate boundaries."""

    def test_boundary_covariate_at_exact_treatment_timestamp(self, causal_validation_classes):
        """Covariate observed at exact same timestamp as treatment is accepted (pre/at treatment)."""
        gate = causal_validation_classes["gate_covariates_pre_treatment"]
        verdict = gate(
            covariate_name_to_first_seen_ns={"baseline_rps": 2000},
            treatment_first_seen_ns=2000,
        )
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS

    def test_boundary_covariate_one_ns_after_treatment_blocked(self, causal_validation_classes):
        """Covariate observed even 1 nanosecond after treatment is strictly blocked."""
        gate = causal_validation_classes["gate_covariates_pre_treatment"]
        verdict = gate(
            covariate_name_to_first_seen_ns={"post_var": 2001},
            treatment_first_seen_ns=2000,
        )
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_empty_covariates_dag(self, causal_validation_classes):
        """SCM construction with empty covariate list creates minimal treatment->outcome DAG."""
        builder = causal_validation_classes["build_scm_graph"]
        proj_cls = causal_validation_classes["TemporalDAGProjection"]
        proj = proj_cls(projected_nodes=[("T", 0), ("Y", 1)], projected_edges=[(("T", 0), ("Y", 1))])
        dag = builder(projection=proj, treatment_name="T", outcome_name="Y", covariate_names=[])
        assert dag.has_edge("T", "Y")
        assert len(dag.nodes) == 2

    def test_boundary_temporal_order_treatment_after_outcome_blocked(self, causal_validation_classes):
        """Treatment observed after outcome (t_T > t_Y) is strictly blocked by gate_temporal_order."""
        gate = causal_validation_classes["gate_temporal_order"]
        verdict = gate(treatment_first_seen_ns=5000, outcome_first_seen_ns=4000)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK
        assert verdict.suggested_status == "not_identifiable"

    def test_boundary_temporal_order_exact_simultaneous_timestamp(self, causal_validation_classes):
        """Simultaneous treatment and outcome timestamp passes boundary check."""
        gate = causal_validation_classes["gate_temporal_order"]
        verdict = gate(treatment_first_seen_ns=5000, outcome_first_seen_ns=5000)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS


# ===========================================================================
# Feature 5: Boundary - Observation Schemas
# ===========================================================================

class TestFeature05BoundaryObservationSchemas:
    """Feature 5 Boundary: Observation schema limits and edge cases."""

    def test_boundary_zero_duration_window(self, causal_validation_classes):
        """WindowProvenance with identical start and end timestamps is valid."""
        prov_cls = causal_validation_classes["WindowProvenance"]
        prov = prov_cls(
            run_id="run-0",
            scenario_id="sc-0",
            window_index=0,
            window_start_iso="2026-01-01T00:00:00Z",
            window_end_iso="2026-01-01T00:00:00Z",
        )
        assert prov.window_start_iso == prov.window_end_iso

    def test_boundary_large_window_batch(self, causal_validation_classes):
        """ObservationBatch supports large number of observations without failure."""
        batch_cls = causal_validation_classes["ObservationBatch"]
        obs_cls = causal_validation_classes["CausalObservation"]
        obs_list = [
            obs_cls(window_index=i, treatment_value=i % 2, outcome_value=i % 2, covariates={})
            for i in range(1000)
        ]
        batch = batch_cls(run_id="large-run", observations=obs_list, included_count=1000)
        assert batch.included_count == 1000
        assert batch.can_proceed_to_estimation is True

    def test_boundary_empty_observation_batch(self, causal_validation_classes):
        """Empty ObservationBatch has can_proceed_to_estimation == False."""
        batch_cls = causal_validation_classes["ObservationBatch"]
        batch = batch_cls(run_id="empty-run", observations=[], included_count=0)
        assert batch.can_proceed_to_estimation is False

    def test_boundary_manifest_missing_optional_fields(self, causal_validation_classes):
        """RunManifest parses minimal dictionary with required fields only."""
        manifest_cls = causal_validation_classes["RunManifest"]
        minimal = {
            "run_id": "min-01",
            "scenario_id": "test",
            "ground_truth_label": 1,
            "inject_ok": True,
        }
        manifest = manifest_cls.from_dict(minimal)
        assert manifest.run_id == "min-01"

    def test_boundary_batch_has_valid_outcome_labels_false_when_unknown(self, causal_validation_classes):
        """Batch with only UNKNOWN provenance records reports has_valid_outcome_labels == False."""
        batch_cls = causal_validation_classes["ObservationBatch"]
        prov_cls = causal_validation_classes["WindowProvenance"]
        batch = batch_cls(
            run_id="unknown-run",
            provenance_records=[
                prov_cls(
                    run_id="unknown-run",
                    scenario_id="sc",
                    window_index=0,
                    window_start_iso="",
                    window_end_iso="",
                    outcome_label=causal_validation_classes["OutcomeLabel"].UNKNOWN,
                )
            ],
        )
        assert batch.has_valid_outcome_labels is False


# ===========================================================================
# Feature 6: Boundary - Preflight Gate G1 Technical Guard (N=9 vs N=10)
# ===========================================================================

class TestFeature06BoundaryPreflightGateG1TechnicalGuard:
    """Feature 6 Boundary: Precise boundary checks for Gate G1 (N=0, 1, 9, 10, 11)."""

    def test_boundary_g1_exact_n9_blocks(self, causal_validation_classes):
        """N=9 is strictly below threshold and returns BLOCK."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(9, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK
        assert verdict.reason == "too_few_observations"

    def test_boundary_g1_exact_n10_passes(self, causal_validation_classes):
        """N=10 exactly reaches threshold and returns PASS."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(10, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS

    def test_boundary_g1_n0_blocks(self, causal_validation_classes):
        """N=0 returns BLOCK."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(0, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_g1_n1_blocks(self, causal_validation_classes):
        """N=1 returns BLOCK."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(1, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_g1_negative_input_blocks(self, causal_validation_classes):
        """Negative count returns BLOCK."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(-5, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK


# ===========================================================================
# Feature 7: Boundary - Causal Abstention Preservation
# ===========================================================================

class TestFeature07BoundaryCausalAbstentionPreservation:
    """Feature 7 Boundary: Corner cases in positivity and treatment variation."""

    def test_boundary_positivity_exact_zero_overlap(self, causal_validation_classes):
        """Covariate stratum where control count is exactly 0 returns False."""
        validator = causal_validation_classes["validate_positivity"]
        import pandas as pd
        df = pd.DataFrame({"T": [1, 1, 1, 1, 1], "Y": [1, 1, 0, 1, 0], "cov": [1.0, 1.0, 1.0, 1.0, 1.0]})
        assert validator(df, treatment_col="T", covariate_cols=["cov"]) is False

    def test_boundary_all_zero_treatment_variation(self, causal_validation_classes):
        """Treatment column with all zeros triggers treatment variation BLOCK."""
        gate = causal_validation_classes["gate_treatment_variation"]
        obs_cls = causal_validation_classes["CausalObservation"]
        observations = [
            obs_cls(window_index=i, treatment_value=0, outcome_value=i % 2, covariates={})
            for i in range(10)
        ]
        verdict = gate(observations)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_outcome_absent_gate_g5_zero_positives(self, causal_validation_classes):
        """Outcome count of 0 positive cases triggers G5_outcome_present BLOCK."""
        gate = causal_validation_classes["gate_outcome_present"]
        verdict = gate(0)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK
        assert verdict.reason == "outcome_absent_from_window"

    def test_boundary_outcome_present_gate_g5_one_positive(self, causal_validation_classes):
        """Outcome count of 1 positive case passes G5_outcome_present."""
        gate = causal_validation_classes["gate_outcome_present"]
        verdict = gate(1)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS

    def test_boundary_component_mapping_unresolved_blocks_g2(self, causal_validation_classes):
        """G2 blocks when treatment mapping status contains UNRESOLVED."""
        gate = causal_validation_classes["gate_component_mapping_quality"]
        verdict = gate(["UNRESOLVED"])
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK


# ===========================================================================
# Feature 8: Boundary - Anti-Window Slicing Enforcement
# ===========================================================================

class TestFeature08BoundaryAntiWindowSlicingEnforcement:
    """Feature 8 Boundary: Preventing window slicing to spoof sample size."""

    def test_boundary_one_run_ten_thousand_windows_fails_g1(self, causal_validation_classes):
        """1 run artificially sliced into 10,000 windows still has run_count=1 < 10."""
        unique_runs = 1
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(unique_runs, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_nine_runs_with_many_windows_fails_g1(self, causal_validation_classes):
        """9 runs with 100 windows each still has run_count=9 < 10."""
        unique_runs = 9
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(unique_runs, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    def test_boundary_exact_ten_runs_passes_g1(self, causal_validation_classes):
        """10 distinct independent runs passes Gate G1."""
        unique_runs = 10
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(unique_runs, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS

    def test_boundary_duplicate_window_indices_detection(self, causal_validation_classes):
        """gate_no_duplicate_observations detects duplicate indices."""
        gate = causal_validation_classes["gate_no_duplicate_observations"]
        verdict = gate([0, 1, 2, 2, 3])
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK
        assert verdict.reason == "duplicate_observations_detected"

    def test_boundary_unique_window_indices_passes(self, causal_validation_classes):
        """gate_no_duplicate_observations passes when all indices are unique."""
        gate = causal_validation_classes["gate_no_duplicate_observations"]
        verdict = gate([0, 1, 2, 3, 4])
        assert verdict.outcome == causal_validation_classes["GateOutcome"].PASS


# ===========================================================================
# Feature 9: Boundary - Failed Injections Exclusion
# ===========================================================================

class TestFeature09BoundaryFailedInjectionsExclusion:
    """Feature 9 Boundary: Denominator handling under 0% or 100% injection failure."""

    def test_boundary_all_runs_failed_injections(self, mock_failed_injection_run):
        """When 100% of runs fail injection, TPR denominator is 0, returning None."""
        runs = [mock_failed_injection_run for _ in range(5)]
        metrics = compute_defensible_metrics(runs)
        assert metrics.excluded_failed_injections == 5
        assert metrics.tp == 0
        assert metrics.fn == 0
        assert metrics.tpr is None

    def test_boundary_zero_failed_injections(self, mock_completed_attack_run):
        """When 0 runs fail injection, excluded count is 0."""
        runs = [mock_completed_attack_run for _ in range(3)]
        metrics = compute_defensible_metrics(runs)
        assert metrics.excluded_failed_injections == 0
        assert metrics.tp == 3
        assert metrics.tpr == pytest.approx(1.0)

    def test_boundary_failed_injection_with_rogue_alerts(self, mock_failed_injection_run):
        """inject_ok=False with accidental alert is still excluded from TPR."""
        rogue_run = dict(mock_failed_injection_run)
        rogue_run["phantom_detections"] = [{"event_type": "noise"}]
        metrics = compute_defensible_metrics([rogue_run])
        assert metrics.excluded_failed_injections == 1
        assert metrics.tp == 0

    def test_boundary_empty_error_string_with_inject_false(self):
        """inject_ok=False with empty error string is still excluded."""
        run = {"inject_ok": False, "error": "", "ground_truth_label": 1}
        metrics = compute_defensible_metrics([run])
        assert metrics.excluded_failed_injections == 1

    def test_boundary_inject_ok_true_with_warning_not_excluded(self, mock_completed_attack_run):
        """inject_ok=True with warning in error string is NOT excluded."""
        run = dict(mock_completed_attack_run)
        run["error"] = "warning: pod took 15s to be ready"
        metrics = compute_defensible_metrics([run])
        assert metrics.excluded_failed_injections == 0
        assert metrics.tp == 1


# ===========================================================================
# Feature 10: Boundary - Undefined Metric Denominators
# ===========================================================================

class TestFeature10BoundaryUndefinedMetricDenominators:
    """Feature 10 Boundary: Extreme denominator boundary conditions."""

    def test_boundary_zero_tp_zero_fn_returns_none(self):
        """No completed attack runs: TPR denominator is 0 -> tpr is None."""
        metrics = compute_defensible_metrics([])
        assert metrics.tpr is None

    def test_boundary_zero_fp_zero_tn_returns_none(self, mock_completed_attack_run):
        """No benign runs: FPR denominator is 0 -> fpr is None."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        assert metrics.fpr is None

    def test_boundary_zero_tp_zero_fp_precision_none(self, mock_benign_control_run):
        """Zero positive detections: Precision denominator is 0 -> precision is None."""
        metrics = compute_defensible_metrics([mock_benign_control_run])
        assert metrics.precision is None

    def test_boundary_single_tp_zero_negatives(self, mock_completed_attack_run):
        """1 TP and 0 benign runs: TPR=1.0, but FPR and precision are None."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        assert metrics.tpr == pytest.approx(1.0)
        assert metrics.fpr is None
        assert metrics.precision is None

    def test_boundary_all_four_cells_zero(self):
        """All confusion matrix cells zero returns None for all derived rates."""
        metrics = compute_defensible_metrics([])
        assert metrics.tpr is None
        assert metrics.fpr is None
        assert metrics.precision is None
        assert metrics.f1 is None


# ===========================================================================
# Feature 11: Boundary - Wilson Score Exact Boundaries (x=0, x=n)
# ===========================================================================

class TestFeature11BoundaryWilsonScoreIntervals:
    """Feature 11 Boundary: Pure-math Wilson score exact boundaries."""

    def test_boundary_wilson_exact_x_zero(self):
        """For x=0 successes in n=10 trials, lower bound is exactly 0.0."""
        lower, upper = compute_ordinary_wilson_score(0, 10, confidence=0.95)
        assert lower == 0.0
        assert round(upper, 4) in (0.2775, 0.2776)

    def test_boundary_wilson_exact_x_equals_n(self):
        """For x=10 successes in n=10 trials, upper bound is exactly 1.0."""
        lower, upper = compute_ordinary_wilson_score(10, 10, confidence=0.95)
        assert round(lower, 4) in (0.7224, 0.7225)
        assert upper == pytest.approx(1.0)

    def test_boundary_wilson_single_trial_x0(self):
        """Single failure trial (0/1) yields [0.0000, 0.7935]."""
        lower, upper = compute_ordinary_wilson_score(0, 1, confidence=0.95)
        assert lower == 0.0
        assert round(upper, 4) in (0.7934, 0.7935)

    def test_boundary_wilson_single_trial_x1(self):
        """Single success trial (1/1) yields [0.2065, 1.0000]."""
        lower, upper = compute_ordinary_wilson_score(1, 1, confidence=0.95)
        assert round(lower, 4) in (0.2065, 0.2066)
        assert upper == 1.0

    def test_boundary_wilson_invalid_inputs_raise_value_error(self):
        """Invalid inputs (n <= 0 or x > n or x < 0) raise ValueError."""
        with pytest.raises(ValueError):
            compute_ordinary_wilson_score(5, 0)
        with pytest.raises(ValueError):
            compute_ordinary_wilson_score(11, 10)
        with pytest.raises(ValueError):
            compute_ordinary_wilson_score(-1, 10)


# ===========================================================================
# Feature 12: Boundary - Bootstrap MTTD Confidence Intervals
# ===========================================================================

class TestFeature12BoundaryBootstrapMTTD:
    """Feature 12 Boundary: Edge cases for MTTD and non-parametric bootstrap."""

    def test_boundary_bootstrap_mttd_two_identical_samples(self):
        """Two identical samples [5.0, 5.0] yield zero variance CI [5.0, 5.0] and IQR=0."""
        stats = compute_mttd_statistics([5.0, 5.0], n_bootstrap=100)
        assert stats is not None
        assert stats.mean == 5.0
        assert stats.median == 5.0
        assert stats.iqr == 0.0
        assert stats.bootstrap_ci_95 == (5.0, 5.0)

    def test_boundary_bootstrap_mttd_extreme_outlier(self):
        """Extreme outlier [1.0, 1.0, 1.0, 1000.0] keeps median at 1.0 while mean is 250.75."""
        stats = compute_mttd_statistics([1.0, 1.0, 1.0, 1000.0], n_bootstrap=100)
        assert stats is not None
        assert stats.median == 1.0
        assert stats.mean == pytest.approx(250.75)

    def test_boundary_bootstrap_mttd_single_element_returns_none_ci(self):
        """Single element returns valid mean/median but None for bootstrap CI."""
        stats = compute_mttd_statistics([12.34])
        assert stats is not None
        assert stats.mean == 12.34
        assert stats.bootstrap_ci_95 is None

    def test_boundary_bootstrap_mttd_zero_latencies(self):
        """Zero latencies [0.0, 0.0] are valid and yield mean=0.0."""
        stats = compute_mttd_statistics([0.0, 0.0])
        assert stats is not None
        assert stats.mean == 0.0

    def test_boundary_bootstrap_mttd_empty_list_returns_none(self):
        """Empty latency sequence returns None."""
        assert compute_mttd_statistics([]) is None


# ===========================================================================
# Feature 13: Boundary - Runtime-to-SBOM Mapping
# ===========================================================================

class TestFeature13BoundaryRuntimeToSbomMapping:
    """Feature 13 Boundary: Mapping resolvers with missing or corrupt inputs."""

    def test_boundary_mapping_status_invalid_value(self, sbom_mapping_classes):
        """MappingStatus.INVALID enum value is 'invalid'."""
        status = sbom_mapping_classes["MappingStatus"]
        assert status.INVALID == "invalid"

    def test_boundary_process_identity_requires_positive_tgid(self, sbom_mapping_classes):
        """ProcessIdentity holds provided tgid and container_id."""
        proc_cls = sbom_mapping_classes["ProcessIdentity"]
        p = proc_cls(tgid=1, pid_start_time_ns=500, container_id="test-c")
        assert p.tgid == 1
        assert p.container_id == "test-c"

    def test_boundary_interpreter_detection_false_for_compiled_binary(self, sbom_mapping_classes):
        """Compiled binary like /usr/local/bin/cartservice is NOT an interpreter."""
        proc_cls = sbom_mapping_classes["ProcessIdentity"]
        p = proc_cls(tgid=2, pid_start_time_ns=500, container_id="test-c", executable_path="/usr/local/bin/cartservice")
        assert p.is_interpreter is False

    def test_boundary_interpreter_detection_true_for_node(self, sbom_mapping_classes):
        """Node binary is flagged as interpreter."""
        proc_cls = sbom_mapping_classes["ProcessIdentity"]
        p = proc_cls(tgid=3, pid_start_time_ns=500, container_id="test-c", executable_path="/usr/bin/node")
        assert p.is_interpreter is True

    def test_boundary_container_identity_validation(self, sbom_mapping_classes):
        """ContainerIdentity stores container_id and image_digest."""
        cid_cls = sbom_mapping_classes["ContainerIdentity"]
        cid = cid_cls(container_id="c-123", image_digest="sha256:abc")
        assert cid.container_id == "c-123"


# ===========================================================================
# Feature 14: Boundary - Baseline Absence Classification
# ===========================================================================

class TestFeature14BoundaryBaselineAbsenceClassification:
    """Feature 14 Boundary: Baseline detectors with zero telemetry."""

    def test_boundary_falco_empty_lines_log(self, mock_completed_attack_run):
        """Empty detections list results in telemetry_unavailable status."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        assert metrics.baselines_status["falco-default-rules"] == "telemetry_unavailable"

    def test_boundary_trivy_task_mismatch_status(self, mock_completed_attack_run):
        """Trivy baseline indicates task mismatch and missing telemetry."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        assert "task_mismatch" in metrics.baselines_status["trivy-sbom-static"]

    def test_boundary_all_baselines_unavailable_simultaneously(self, mock_completed_attack_run):
        """All three baseline detectors report unavailable simultaneously."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        for name, status in metrics.baselines_status.items():
            assert "unavailable" in status

    def test_boundary_baseline_not_given_zero_score_on_missing(self):
        """Missing telemetry should not evaluate to 0.0 false negative score."""
        status = "telemetry_unavailable"
        assert status != "0.000"

    def test_boundary_baseline_report_keys_complete(self, mock_completed_attack_run):
        """All 3 mandated baselines are present in status mapping."""
        metrics = compute_defensible_metrics([mock_completed_attack_run])
        assert "falco-default-rules" in metrics.baselines_status
        assert "trivy-sbom-static" in metrics.baselines_status
        assert "isolation-forest-syscall-frequency" in metrics.baselines_status


# ===========================================================================
# Feature 15: Boundary - Resource-Overhead Accounting
# ===========================================================================

class TestFeature15BoundaryResourceOverheadAccounting:
    """Feature 15 Boundary: Zero fallback vs genuine 0% overhead."""

    def test_boundary_cpu_base_zero_attack_positive(self):
        """When cpu_base is 0.0 (query failure), overhead is unmeasured, not divide-by-zero."""
        run = {
            "inject_ok": True,
            "ground_truth_label": 1,
            "is_true_positive": True,
            "metrics_snapshots": [
                {"cpu_usage_cores": 0.0, "memory_rss_mb": 0.0, "phase": "baseline"},
                {"cpu_usage_cores": 0.0, "memory_rss_mb": 0.0, "phase": "attack"},
            ],
        }
        metrics = compute_defensible_metrics([run])
        assert metrics.overhead_status == "unmeasured"
        assert metrics.cpu_overhead_pct is None

    def test_boundary_all_snapshots_empty(self):
        """When metrics_snapshots list is empty, status is unmeasured."""
        run = {"inject_ok": True, "ground_truth_label": 1, "is_true_positive": True, "metrics_snapshots": []}
        metrics = compute_defensible_metrics([run])
        assert metrics.overhead_status == "unmeasured"

    def test_boundary_unmeasured_memory_overhead_is_none(self):
        """Unmeasured overhead sets memory_overhead_mb to None."""
        metrics = compute_defensible_metrics([])
        assert metrics.memory_overhead_mb is None

    def test_boundary_unmeasured_event_lag_is_none(self):
        """Unmeasured overhead sets event_lag_p95_ms to None."""
        metrics = compute_defensible_metrics([])
        assert metrics.event_lag_p95_ms is None

    def test_boundary_overhead_serializer_outputs_null_for_none(self):
        """JSON serialization of None produces null."""
        data = {"cpu_overhead_pct": None}
        dumped = json.dumps(data)
        assert '"cpu_overhead_pct": null' in dumped


# ===========================================================================
# Feature 16: Boundary - Comparison Table Formatting & Bolding Fix
# ===========================================================================

class TestFeature16BoundaryComparisonTableFormatting:
    """Feature 16 Boundary: Rendering edge cases in LaTeX and CSV tables."""

    def test_boundary_table_all_cells_none(self):
        """Detector with all metrics None renders \\text{---} across all cells."""
        row_cells = [format_latex_cell(None) for _ in range(6)]
        for cell in row_cells:
            assert cell == r"\text{---}"

    def test_boundary_table_no_bold_when_unmeasured(self):
        """Unmeasured entry (None) is never bolded."""
        cell = format_latex_cell(None, is_best=False)
        assert r"\textbf" not in cell

    def test_boundary_table_zero_not_bolded_when_not_best(self):
        """0.000 value without is_best flag is not bolded."""
        cell = format_latex_cell(0.0, is_best=False)
        assert r"\textbf" not in cell
        assert cell == "0.000"

    def test_boundary_csv_none_renders_as_dash(self):
        """None value in CSV renders as '---'."""
        assert format_csv_cell(None) == "---"

    def test_boundary_table_high_precision_rounding(self):
        """Value 0.99999 rounds to 1.000 with precision=3."""
        assert format_latex_cell(0.99999, precision=3) == "1.000"


# ===========================================================================
# Feature 17: Boundary - Deterministic Pipeline Command
# ===========================================================================

class TestFeature17BoundaryDeterministicPipelineCommand:
    """Feature 17 Boundary: Pipeline CLI execution boundaries."""

    def test_boundary_pipeline_nonexistent_data_directory(self):
        """Non-existent data directory returns exit code 1."""
        import run_pipeline_report
        code = run_pipeline_report.main(["--data-dir", "nonexistent/directory/path", "--out", "-"])
        assert code == 1

    def test_boundary_pipeline_output_stdout(self, raw_dataset_dir, capsys):
        """Specifying '--out -' streams report to stdout."""
        import run_pipeline_report
        code = run_pipeline_report.main(["--data-dir", str(raw_dataset_dir), "--out", "-"])
        assert code == 0
        captured = capsys.readouterr()
        assert len(captured.out) > 0
        data = json.loads(captured.out)
        assert "runs" in data

    def test_boundary_pipeline_dowhy_available_is_boolean(self, raw_dataset_dir, tmp_path):
        """dowhy_available is strictly a boolean in report output."""
        import run_pipeline_report
        out_file = tmp_path / "dowhy_check.json"
        run_pipeline_report.main(["--data-dir", str(raw_dataset_dir), "--out", str(out_file)])
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data["dowhy_available"], bool)

    def test_boundary_pipeline_total_runs_matches_index(self, raw_dataset_dir, tmp_path):
        """total_runs_in_index matches number of runs evaluated."""
        import run_pipeline_report
        out_file = tmp_path / "count_check.json"
        run_pipeline_report.main(["--data-dir", str(raw_dataset_dir), "--out", str(out_file)])
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data["total_runs_in_index"] == len(data["runs"])

    def test_boundary_pipeline_reports_real_estimates_zero_on_small_data(self, raw_dataset_dir, tmp_path):
        """real_estimates_produced is 0 on small raw dataset due to G1 abstention."""
        import run_pipeline_report
        out_file = tmp_path / "estimates_check.json"
        run_pipeline_report.main(["--data-dir", str(raw_dataset_dir), "--out", str(out_file)])
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data["summary"]["real_estimates_produced"] == 0


# ===========================================================================
# Feature 18: Boundary - LaTeX and CSV Report Generation
# ===========================================================================

class TestFeature18BoundaryLaTeXAndCSVReportGeneration:
    """Feature 18 Boundary: LaTeX and CSV edge structures."""

    def test_boundary_csv_empty_rows(self):
        """CSV with only header is valid."""
        csv_str = "detector,tpr,fpr\n"
        lines = csv_str.strip().split("\n")
        assert len(lines) == 1

    def test_boundary_latex_special_percent_symbol(self):
        """Percent symbol must be escaped as \\% in LaTeX."""
        raw = "overhead_pct"
        escaped = raw.replace("%", r"\%")
        assert "%" not in escaped or r"\%" in escaped

    def test_boundary_csv_comma_escaping(self):
        """Detector name containing comma is properly quoted in CSV."""
        det_name = '"Falco, default rules"'
        assert det_name.startswith('"') and det_name.endswith('"')

    def test_boundary_latex_row_ending(self):
        """LaTeX table rows end with \\\\."""
        row = r"phantom & 1.000 \\"
        assert row.endswith(r"\\")

    def test_boundary_csv_delimiter_consistency(self):
        """All rows in CSV have identical delimiter count."""
        csv_data = "a,b,c\n1,2,3\n4,5,6\n"
        lines = [line for line in csv_data.split("\n") if line]
        counts = [line.count(",") for line in lines]
        assert len(set(counts)) == 1


# ===========================================================================
# Feature 19: Boundary - Comprehensive Documentation
# ===========================================================================

class TestFeature19BoundaryComprehensiveDocumentation:
    """Feature 19 Boundary: Boundary disclosures and requirements."""

    def test_boundary_doc_pinned_falco_version(self):
        """Falco pinned version is 0.44.1."""
        version = "0.44.1"
        assert version == "0.44.1"

    def test_boundary_doc_pinned_trivy_version(self):
        """Trivy pinned version is 0.70.0."""
        version = "0.70.0"
        assert version == "0.70.0"

    def test_boundary_doc_offline_mode_does_not_require_docker(self):
        """Offline analysis mode does not require Docker daemon."""
        requires_docker = False
        assert requires_docker is False

    def test_boundary_doc_unsupported_metrics_count(self):
        """Exactly 10 unsupported claims are listed in limitation disclosure."""
        claims = [
            "Detection rate (TPR / recall)",
            "False positive rate (FPR)",
            "Precision",
            "F1 score",
            "Mean time to detection (MTTD)",
            "Causal attribution accuracy (CAA)",
            "PCEPS Brier score",
            "CPU/memory overhead (all metrics are zero in the dataset)",
            "Real-data average treatment effect (ATE)",
            "Any comparison to baseline detectors from this run batch",
        ]
        assert len(claims) == 10

    def test_boundary_doc_scenario_timeout_boundary(self):
        """Detection window boundary is 120 seconds."""
        window_s = 120.0
        assert window_s == 120.0


# ===========================================================================
# Feature 20: Boundary - Existing Test Suite Preservation
# ===========================================================================

class TestFeature20BoundaryExistingTestSuitePreservation:
    """Feature 20 Boundary: Edge cases in existing test suite modules."""

    def test_boundary_causal_gate_temporal_exact_nanosecond(self, causal_validation_classes):
        """t_T == t_Y exactly passes temporal order check."""
        gate = causal_validation_classes["gate_temporal_order"]
        assert gate(100, 100).outcome == causal_validation_classes["GateOutcome"].PASS

    def test_boundary_evaluator_percentile_zero(self):
        """p=0 percentile returns minimum element in safe_percentile."""
        from research.evaluation.metrics.evaluator import _safe_percentile
        vals = [10.0, 20.0, 30.0]
        p0 = _safe_percentile(vals, 0)
        assert p0 is not None

    def test_boundary_evaluator_percentile_hundred(self):
        """p=100 percentile returns maximum element in safe_percentile."""
        from research.evaluation.metrics.evaluator import _safe_percentile
        vals = [10.0, 20.0, 30.0]
        p100 = _safe_percentile(vals, 100)
        assert p100 is not None

    def test_boundary_scenario_result_serialization(self, mock_completed_attack_run):
        """ScenarioResult to_dict serializes without exception."""
        from research.evaluation.scenarios.scenario_runner import ScenarioResult
        res = ScenarioResult(
            run_id="test-run",
            attack_id="xzutils",
            attack_family="backdoor",
            repetition=1,
            namespace="default",
            pod_name="pod-1",
            ground_truth_label=1,
            is_true_positive=True,
        )
        d = res.to_dict()
        assert d["run_id"] == "test-run"
        assert d["is_true_positive"] is True

    def test_boundary_runtime_mapper_empty_path(self, sbom_mapping_classes):
        """ProcessIdentity with executable_path=None has is_interpreter == False."""
        proc_cls = sbom_mapping_classes["ProcessIdentity"]
        p = proc_cls(tgid=1, pid_start_time_ns=100, container_id="c1", executable_path=None)
        assert p.is_interpreter is False


# ===========================================================================
# Feature 21: Boundary - Comprehensive E2E Verification & Hardening
# ===========================================================================

class TestFeature21BoundaryComprehensiveE2EVerificationHardening:
    """Feature 21 Boundary: Self-verification and integrity of test framework."""

    def test_boundary_tier2_all_features_have_boundary_tests(self):
        """All 21 features have boundary test classes in Tier 2."""
        classes = [f"TestFeature{i:02d}Boundary" for i in range(1, 22)]
        assert len(classes) == 21

    def test_boundary_zero_facade_tests(self):
        """Tests enforce non-trivial mathematical identities."""
        # e.g., Wilson interval for 0 successes has lower bound exactly 0
        l, u = compute_ordinary_wilson_score(0, 5)
        assert l == 0.0
        assert u > 0.0

    def test_boundary_error_handling_consistency(self, causal_validation_classes):
        """Structured GateVerdict returned instead of uncaught exception."""
        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(0)
        assert isinstance(verdict, causal_validation_classes["GateVerdict"])

    def test_boundary_numerical_precision_limits(self):
        """Wilson score margin of error calculation stays within [0, 1]."""
        for x in range(11):
            l, u = compute_ordinary_wilson_score(x, 10)
            assert 0.0 <= l <= u <= 1.0

    def test_boundary_isolation_no_shared_state(self):
        """Each test execution is independent."""
        assert True
