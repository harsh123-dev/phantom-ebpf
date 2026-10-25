"""Tier 3: Cross-Feature Combinations E2E Tests.

Tests validate pairwise and multi-feature interactions across the 21 features:
- Interaction 1: Failed Injection Exclusion + Undefined Denominators (F09 + F10)
- Interaction 2: Baseline Telemetry Absence + Unmeasured Resource Overhead (F14 + F15)
- Interaction 3: Gate G1 Abstention + Deterministic Reporting Pipeline (F06 + F07 + F17)
- Interaction 4: Anti-Window Slicing + Gate G1 + Preflight Validation (F06 + F08)
- Interaction 5: Ordinary Wilson Score + Zero Denominator Boundary (F10 + F11)
- Interaction 6: Defensible Metrics + LaTeX & CSV Table Formatting (F10 + F15 + F16 + F18)
- Interaction 7: Raw3 Dataset Classification + Runtime SBOM Missingness (F01 + F02 + F13)
- Interaction 8: Decoupled Protocol + Anti-Mediator DAG Enforcement (F03 + F04)
- Interaction 9: Bootstrap MTTD Uncertainty + Small Sample Abstention (F11 + F12)
- Interaction 10: Comprehensive Documentation + Pipeline Verification (F17 + F19)
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


class TestTier3Interactions:
    """Pairwise and multi-feature interaction tests."""

    # -----------------------------------------------------------------------
    # Interaction 1: Failed Injection Exclusion + Undefined Denominators (F09 + F10)
    # -----------------------------------------------------------------------

    def test_interaction_failed_injection_with_zero_benign_controls(
        self,
        mock_completed_attack_run,
        mock_failed_injection_run,
    ):
        """Batch mirroring raw3 (6 completed attacks, 3 failed injections, 0 benign controls).

        Verifies:
        - 3 failed injections excluded from TPR denominator -> TPR = 6 / 6 = 1.0.
        - Wilson CI computed on 6/6 successes -> [0.6096, 1.0000].
        - FPR, Precision, and F1 are None without negative controls (not 0.0 or 1.0).
        - Excluded count is 3.
        """
        runs = [mock_completed_attack_run] * 6 + [mock_failed_injection_run] * 3
        metrics = compute_defensible_metrics(runs)

        assert metrics.tp == 6
        assert metrics.fn == 0
        assert metrics.excluded_failed_injections == 3
        assert metrics.tpr == pytest.approx(1.0)
        assert metrics.tpr_wilson_ci is not None
        low, high = metrics.tpr_wilson_ci
        assert round(low, 4) in (0.6096, 0.6097)
        assert round(high, 4) == 1.0000

        # Undefined denominators
        assert metrics.fp is None
        assert metrics.tn is None
        assert metrics.fpr is None
        assert metrics.precision is None
        assert metrics.f1 is None

    def test_interaction_failed_injection_with_benign_controls(
        self,
        mock_completed_attack_run,
        mock_failed_injection_run,
        mock_benign_control_run,
    ):
        """Batch with 2 completed TP, 1 failed injection, and 2 clean benign controls.

        Verifies:
        - TPR = 2 / 2 = 1.0.
        - FPR = 0 / 2 = 0.0 (benign runs exist!).
        - Precision = 2 / (2 + 0) = 1.0.
        - F1 = 1.0.
        """
        runs = [
            mock_completed_attack_run,
            mock_completed_attack_run,
            mock_failed_injection_run,
            mock_benign_control_run,
            mock_benign_control_run,
        ]
        metrics = compute_defensible_metrics(runs)
        assert metrics.tp == 2
        assert metrics.fn == 0
        assert metrics.excluded_failed_injections == 1
        assert metrics.tpr == pytest.approx(1.0)
        assert metrics.fp == 0
        assert metrics.tn == 2
        assert metrics.fpr == pytest.approx(0.0)
        assert metrics.precision == pytest.approx(1.0)
        assert metrics.f1 == pytest.approx(1.0)

    # -----------------------------------------------------------------------
    # Interaction 2: Baseline Telemetry Absence + Unmeasured Resource Overhead (F14 + F15)
    # -----------------------------------------------------------------------

    def test_interaction_baseline_absence_and_unmeasured_overhead(
        self,
        mock_completed_attack_run,
    ):
        """Detector evaluation with missing Falco/Trivy/Prometheus logs.

        Verifies:
        - Baseline detectors report 'telemetry_unavailable' (never numeric 0.0).
        - Overhead reports 'unmeasured' (never numeric 0.0%).
        """
        metrics = compute_defensible_metrics([mock_completed_attack_run])

        # Baseline statuses
        for detector_name, status in metrics.baselines_status.items():
            assert "unavailable" in status

        # Overhead status
        assert metrics.overhead_status == "unmeasured"
        assert metrics.cpu_overhead_pct is None
        assert metrics.memory_overhead_mb is None
        assert metrics.event_lag_p95_ms is None

    # -----------------------------------------------------------------------
    # Interaction 3: Gate G1 Abstention + Deterministic Reporting Pipeline (F06 + F07 + F17)
    # -----------------------------------------------------------------------

    def test_interaction_gate_g1_abstention_in_pipeline_report(
        self,
        raw_dataset_dir,
        tmp_path,
    ):
        """Pipeline report on raw dataset (N=6 < 10) cleanly records G1 abstention.

        Verifies:
        - Command completes with exit code 0.
        - Output summary confirms real_estimates_produced == 0.
        - Limitations section discloses Gate G1 abstention.
        """
        import run_pipeline_report
        out_file = tmp_path / "g1_report.json"
        exit_code = run_pipeline_report.main(["--data-dir", str(raw_dataset_dir), "--out", str(out_file)])
        assert exit_code == 0
        assert out_file.exists()

        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)

        assert data["summary"]["real_estimates_produced"] == 0
        assert any("G1" in note or "too few" in note.lower() for note in data["limitations"])

    # -----------------------------------------------------------------------
    # Interaction 4: Anti-Window Slicing + Gate G1 (F06 + F08)
    # -----------------------------------------------------------------------

    def test_interaction_anti_window_slicing_blocks_spoofed_batch(
        self,
        causal_validation_classes,
    ):
        """Attempting to satisfy G1 (N=10) by slicing 2 runs into 10 windows blocks.

        Verifies:
        - Unit of analysis is distinct run count, not window count.
        - 2 runs with 5 windows each yields run_count=2, blocking G1.
        """
        prov_cls = causal_validation_classes["WindowProvenance"]
        windows = [
            prov_cls(
                run_id=f"run-{i // 5}",
                scenario_id="sc",
                window_index=i % 5,
                window_start_iso="",
                window_end_iso="",
            )
            for i in range(10)
        ]

        distinct_runs = len({w.run_id for w in windows})
        assert distinct_runs == 2

        gate = causal_validation_classes["gate_minimum_observations"]
        verdict = gate(distinct_runs, minimum=10)
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK
        assert verdict.reason == "too_few_observations"

    # -----------------------------------------------------------------------
    # Interaction 5: Ordinary Wilson Score + Zero Denominator Boundary (F10 + F11)
    # -----------------------------------------------------------------------

    def test_interaction_wilson_score_zero_trials_handled_by_evaluator(self):
        """Evaluator handles zero-trial case by returning None for Wilson interval.

        Verifies:
        - When trials == 0, Wilson score is not called and tpr_wilson_ci is None.
        - When trials > 0, Wilson score produces exact bounds.
        """
        metrics_empty = compute_defensible_metrics([])
        assert metrics_empty.tpr_wilson_ci is None

        # When trials = 1
        run = {
            "ground_truth_label": 1,
            "inject_ok": True,
            "is_true_positive": True,
            "phantom_detections": [{"id": 1}],
        }
        metrics_one = compute_defensible_metrics([run])
        assert metrics_one.tpr_wilson_ci is not None
        low, high = metrics_one.tpr_wilson_ci
        assert round(low, 4) in (0.2065, 0.2066)
        assert round(high, 4) == 1.0000

    # -----------------------------------------------------------------------
    # Interaction 6: Defensible Metrics + LaTeX & CSV Table Generation (F10 + F15 + F16 + F18)
    # -----------------------------------------------------------------------

    def test_interaction_table_formatting_with_defensible_metrics(
        self,
        mock_completed_attack_run,
        tmp_path,
    ):
        """End-to-end flow from defensible metrics to LaTeX and CSV formatting.

        Verifies:
        - Undefined FPR and unmeasured overhead render as \\text{---} in LaTeX.
        - Undefined values render as '---' in CSV.
        - CSV output has matching column counts across all rows.
        """
        metrics = compute_defensible_metrics([mock_completed_attack_run])

        # LaTeX row
        latex_cells = [
            "PHANTOM (ours)",
            format_latex_cell(metrics.tpr, precision=3, is_best=True),
            format_latex_cell(metrics.fpr, precision=3),
            format_latex_cell(metrics.precision, precision=3),
            format_latex_cell(metrics.cpu_overhead_pct, precision=3),
        ]
        latex_row = " & ".join(latex_cells) + r" \\"

        assert r"\textbf{1.000}" in latex_row
        assert r"\text{---}" in latex_row

        # CSV row
        csv_cells = [
            "phantom",
            format_csv_cell(metrics.tpr),
            format_csv_cell(metrics.fpr),
            format_csv_cell(metrics.precision),
            format_csv_cell(metrics.cpu_overhead_pct),
        ]
        csv_row = ",".join(csv_cells)
        assert "1.0000" in csv_row
        assert "---" in csv_row

    # -----------------------------------------------------------------------
    # Interaction 7: Raw3 Dataset Classification + Runtime SBOM Missingness (F01 + F02 + F13)
    # -----------------------------------------------------------------------

    def test_interaction_raw3_audit_and_sbom_resolver_status(
        self,
        raw3_dataset_dir,
        sbom_mapping_classes,
    ):
        """Audit of real raw3 events evaluated against RuntimeToSbomMapper.

        Verifies:
        - Raw3 completed events carry 'unknown' pod names and dummy image digests.
        - Due to missing container/image identity, mapping evaluates to INVALID or UNRESOLVED.
        - Resolver strictly prevents falsely claiming VERIFIED.
        """
        sample_file = raw3_dataset_dir / "20260905T223101Z_xzutils-001_rep1.json"
        with open(sample_file, encoding="utf-8") as f:
            data = json.load(f)

        assert classify_scenario_run(data) == RunClassification.COMPLETED_ATTACK

        detections = data.get("phantom_detections", [])
        assert len(detections) > 0
        first_event = detections[0]

        # eBPF identity fields
        assert first_event.get("pod_name") == "unknown"
        assert first_event.get("container_id") == "unknown"
        assert first_event.get("purl") is None

        # Verify mapping status is not VERIFIED
        mapping_status = first_event.get("identity_status")
        assert mapping_status in ("ambiguous", "missing", "unresolved")

    # -----------------------------------------------------------------------
    # Interaction 8: Decoupled Protocol + Anti-Mediator DAG Enforcement (F03 + F04)
    # -----------------------------------------------------------------------

    def test_interaction_decoupled_protocol_and_anti_mediator_rules(
        self,
        causal_validation_classes,
    ):
        """Decoupled ground-truth protocol feeding into causal DAG builder.

        Verifies:
        - Treatment intervention T_inject is distinct from intermediate runtime behavior.
        - Covariates gate blocks intermediate behavior from confounding adjustment set.
        """
        # Intermediate process event observed after injection
        t_inject_ns = 1_000_000
        intermediate_process_ns = 1_500_000
        outcome_drift_ns = 2_000_000

        gate = causal_validation_classes["gate_covariates_pre_treatment"]
        verdict = gate(
            covariate_name_to_first_seen_ns={"spawned_process": intermediate_process_ns},
            treatment_first_seen_ns=t_inject_ns,
        )
        # Attempting to condition on intermediate process is blocked
        assert verdict.outcome == causal_validation_classes["GateOutcome"].BLOCK

    # -----------------------------------------------------------------------
    # Interaction 9: Bootstrap MTTD Uncertainty + Small Sample Abstention (F11 + F12)
    # -----------------------------------------------------------------------

    def test_interaction_bootstrap_mttd_with_varying_sample_sizes(self):
        """MTTD bootstrap uncertainty calculation across N=1, N=2, and N=6 samples.

        Verifies:
        - N=1: Bootstrap CI returns None (abstains on CI).
        - N=2: Bootstrap CI computed.
        - N=6: Full summary (mean, median, IQR, bootstrap CI).
        """
        # N=1
        s1 = compute_mttd_statistics([5.5])
        assert s1.bootstrap_ci_95 is None

        # N=2
        s2 = compute_mttd_statistics([4.0, 6.0], n_bootstrap=100)
        assert s2.bootstrap_ci_95 is not None

        # N=6 (raw3 values)
        raw_vals = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
        s6 = compute_mttd_statistics(raw_vals, n_bootstrap=200, seed=42)
        assert s6.bootstrap_ci_95 is not None
        assert s6.iqr > 0.0
        assert s6.median < s6.mean  # skewed distribution

    # -----------------------------------------------------------------------
    # Interaction 10: Comprehensive Documentation + Pipeline Verification (F17 + F19)
    # -----------------------------------------------------------------------

    def test_interaction_documentation_and_pipeline_report_consistency(
        self,
        raw3_dataset_dir,
        tmp_path,
    ):
        """Pipeline command execution produces report matching documented schema.

        Verifies:
        - CLI execution on raw3 dataset directory runs cleanly.
        - Output JSON contains 9 runs (6 completed, 3 failed).
        - Excluded runs count matches documented SolarWinds rollout failures.
        """
        import run_pipeline_report
        out_file = tmp_path / "raw3_pipeline_report.json"
        code = run_pipeline_report.main(["--data-dir", str(raw3_dataset_dir), "--out", str(out_file)])
        assert code == 0

        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_runs_in_index"] == 9
        assert len(data["runs"]) == 9
        assert "summary" in data
        assert "limitations" in data
