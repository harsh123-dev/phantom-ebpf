"""
tests/e2e/test_tier5_metrics_adversarial.py

PHANTOM Tier 5 Adversarial Coverage Hardening:
Evaluation, Metrics, Table Generation, and Reporting CLI.

White-box adversarial test suite covering:
1. Wilson score exact boundary conditions (k=0/n=1, k=1/n=1, k=0/n=1000, k=1000/n=1000,
   invalid k>n, n<=0, exact 6/6 formula verification [0.6096, 1.0000], symmetry, monotonicity).
2. Bootstrap MTTD boundary conditions (empty list, single value, identical values zero-variance,
   extreme outliers, small n=2, determinism seed).
3. Evaluator denominator preservation (zero negatives -> FPR None, zero positive predictions ->
   Precision None, zero recall -> F1 None, zero benign duration -> FP/hr None, failed injection exclusions).
4. Table generation adversarial formatting (mixed available/unavailable metrics, unmeasured overhead,
   ensuring no bolding of unmeasured zeros or None cells, LaTeX escaping).
5. Pipeline CLI robustness (corrupt JSON files, missing mandatory fields, synthetic all-failed
   injections, all-dropout datasets, non-existent directories, deep output path creation).
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from research.evaluation.baselines.base_baseline import Detection
from research.evaluation.metrics.comparison_table import (
    _find_best,
    _sort_reports,
    format_csv_cell,
    format_latex_cell,
    generate_comparison_table,
    generate_csv,
    write_tables,
)
from research.evaluation.metrics.evaluator import (
    EvaluationReport,
    ScenarioEvaluator,
    _build_report,
    _compute_mttd_stats,
    _safe_mean,
    _safe_percentile,
    is_failed_injection,
)
from research.evaluation.metrics.wilson_score import (
    _get_z,
    compute_ordinary_wilson_score,
    wilson_score,
    wilson_score_interval,
)
from research.evaluation.scenarios.scenario_runner import (
    MetricsSnapshot,
    PhaseRecord,
    ScenarioResult,
)
import run_pipeline_report


# ==============================================================================
# Test Helper: ScenarioResult factory
# ==============================================================================


def make_sr(
    run_id: str = "test_run",
    attack_id: str = "xzutils",
    attack_family: str = "supply_chain",
    repetition: int = 1,
    namespace: str = "default",
    pod_name: str = "target-pod",
    ground_truth_label: int = 1,
    is_true_positive: bool = False,
    inject_ok: bool = True,
    mttd_s: float | None = None,
    error: str = "",
    phases: list[PhaseRecord] | None = None,
    phantom_detections: list[dict[str, Any]] | None = None,
    falco_detections: list[dict[str, Any]] | None = None,
    metrics_snapshots: list[MetricsSnapshot] | None = None,
    scenario_label: dict[str, Any] | None = None,
    injection_timestamp: datetime | None = None,
) -> ScenarioResult:
    """Helper to construct ScenarioResult and attach inject_ok property cleanly."""
    sr = ScenarioResult(
        run_id=run_id,
        attack_id=attack_id,
        attack_family=attack_family,
        repetition=repetition,
        namespace=namespace,
        pod_name=pod_name,
        ground_truth_label=ground_truth_label,
        injection_timestamp=injection_timestamp,
        mttd_s=mttd_s,
        is_true_positive=is_true_positive,
        phases=phases or [],
        phantom_detections=phantom_detections or [],
        falco_detections=falco_detections or [],
        metrics_snapshots=metrics_snapshots or [],
        scenario_label=scenario_label or {},
        error=error,
    )
    sr.inject_ok = inject_ok
    return sr


# ==============================================================================
# 1. Wilson Score Adversarial & Boundary Hardening
# ==============================================================================


class TestTier5WilsonScoreAdversarial:
    """Adversarial stress-testing of pure-math ordinary Wilson score calculation."""

    def test_wilson_boundary_k0_n1(self):
        """Boundary k=0, n=1: lower bound must be exactly 0.0, upper bound z^2/(1+z^2)."""
        lower, upper = compute_ordinary_wilson_score(0, 1, confidence=0.95)
        assert lower == 0.0
        # z for 95% = 1.959963984540054; z^2 ≈ 3.84145882; upper = 3.84145882 / 4.84145882 ≈ 0.79346
        expected_upper = (1.959963984540054 ** 2) / (1.0 + 1.959963984540054 ** 2)
        assert math.isclose(upper, expected_upper, rel_tol=1e-7)
        assert round(upper, 4) == 0.7935

    def test_wilson_boundary_k1_n1(self):
        """Boundary k=1, n=1: upper bound must be exactly 1.0, lower bound 1 - z^2/(1+z^2)."""
        lower, upper = compute_ordinary_wilson_score(1, 1, confidence=0.95)
        assert upper == 1.0
        expected_lower = 1.0 - ((1.959963984540054 ** 2) / (1.0 + 1.959963984540054 ** 2))
        assert math.isclose(lower, expected_lower, rel_tol=1e-7)
        assert round(lower, 4) == 0.2065

    def test_wilson_boundary_k0_n1000(self):
        """Boundary k=0, n=1000: lower must be 0.0 (within float precision epsilon), upper strictly tiny."""
        lower, upper = compute_ordinary_wilson_score(0, 1000, confidence=0.95)
        assert math.isclose(lower, 0.0, abs_tol=1e-9)
        assert 0.003 < upper < 0.004
        assert round(upper, 5) == 0.00383

    def test_wilson_boundary_k1000_n1000(self):
        """Boundary k=1000, n=1000: upper must be 1.0, lower strictly near 1.0."""
        lower, upper = compute_ordinary_wilson_score(1000, 1000, confidence=0.95)
        assert upper == 1.0
        assert 0.996 < lower < 0.997
        assert round(lower, 5) == 0.99617

    def test_wilson_invalid_inputs_trials_zero(self):
        """trials=0 must gracefully return (None, None) without crashing."""
        assert compute_ordinary_wilson_score(0, 0) == (None, None)

    def test_wilson_invalid_inputs_negative_trials(self):
        """trials < 0 must raise ValueError."""
        with pytest.raises(ValueError, match="trials must be non-negative"):
            compute_ordinary_wilson_score(0, -5)

    def test_wilson_invalid_inputs_negative_successes(self):
        """successes < 0 must raise ValueError."""
        with pytest.raises(ValueError, match="successes must be between 0 and 10"):
            compute_ordinary_wilson_score(-1, 10)

    def test_wilson_invalid_inputs_successes_exceed_trials(self):
        """successes > trials must raise ValueError."""
        with pytest.raises(ValueError, match="successes must be between 0 and 5"):
            compute_ordinary_wilson_score(6, 5)

    def test_wilson_pure_ordinary_formula_six_of_six(self):
        """R4 & Feature 11 contract: 6/6 at 95% CI yields [0.6096, 1.0000] without continuity correction."""
        lower, upper = compute_ordinary_wilson_score(6, 6, confidence=0.95)
        assert upper == 1.0
        # Exact lower bound is 0.609665712...
        assert 0.6096 <= lower <= 0.6097
        assert round(lower, 4) in (0.6096, 0.6097)

    @pytest.mark.parametrize(
        ("k", "n"),
        [
            (2, 7),
            (10, 50),
            (1, 100),
            (25, 25),
            (0, 15),
            (33, 40),
        ],
    )
    def test_wilson_symmetry_invariant(self, k: int, n: int):
        """Mathematical invariant: interval for k/n is symmetric to interval for (n-k)/n."""
        l1, u1 = compute_ordinary_wilson_score(k, n, confidence=0.95)
        l2, u2 = compute_ordinary_wilson_score(n - k, n, confidence=0.95)
        assert math.isclose(l1, 1.0 - u2, abs_tol=1e-7)
        assert math.isclose(u1, 1.0 - l2, abs_tol=1e-7)

    def test_wilson_confidence_level_monotonicity(self):
        """Higher confidence level must produce strictly wider uncertainty interval."""
        levels = [0.90, 0.95, 0.98, 0.99]
        intervals = [compute_ordinary_wilson_score(5, 10, confidence=c) for c in levels]
        for i in range(len(intervals) - 1):
            low_curr, up_curr = intervals[i]
            low_next, up_next = intervals[i + 1]
            assert low_next < low_curr
            assert up_next > up_curr

    def test_wilson_extreme_sample_sizes_no_overflow(self):
        """Massive sample sizes (e.g. 10^8) must not suffer float overflow or NaN."""
        lower, upper = compute_ordinary_wilson_score(50_000_000, 100_000_000, confidence=0.95)
        assert not math.isnan(lower)
        assert not math.isnan(upper)
        assert math.isclose(lower, 0.5, abs_tol=1e-3)
        assert math.isclose(upper, 0.5, abs_tol=1e-3)
        assert 0.0 <= lower <= upper <= 1.0

    def test_wilson_aliases_identical(self):
        """Interface aliases wilson_score and wilson_score_interval behave identically."""
        res1 = compute_ordinary_wilson_score(3, 4)
        res2 = wilson_score_interval(3, 4)
        res3 = wilson_score(3, 4)
        assert res1 == res2 == res3


# ==============================================================================
# 2. Bootstrap MTTD Adversarial & Boundary Hardening
# ==============================================================================


class TestTier5BootstrapMTTDAdversarial:
    """Adversarial stress-testing of MTTD statistics and bootstrap confidence intervals."""

    def test_mttd_empty_list_returns_none(self):
        """Empty MTTD latency list returns all None values without ZeroDivisionError."""
        mean, med, iqr, p95, ci = _compute_mttd_stats([])
        assert mean is None
        assert med is None
        assert iqr is None
        assert p95 is None
        assert ci is None

    def test_mttd_single_value_boundary(self):
        """Single MTTD value: mean=median=p95=val, iqr=0.0, bootstrap CI is None (n < 2)."""
        mean, med, iqr, p95, ci = _compute_mttd_stats([17.42])
        assert mean == 17.42
        assert med == 17.42
        assert iqr == 0.0
        assert p95 == 17.42
        assert ci is None

    def test_mttd_identical_values_zero_variance(self):
        """Identical values: variance is zero; bootstrap CI collapses cleanly to (val, val)."""
        mean, med, iqr, p95, ci = _compute_mttd_stats([8.5, 8.5, 8.5, 8.5, 8.5, 8.5])
        assert mean == 8.5
        assert med == 8.5
        assert iqr == 0.0
        assert p95 == 8.5
        assert ci == (8.5, 8.5)

    def test_mttd_high_variance_heavy_tail(self):
        """Extreme outlier latency must not crash bootstrap or invert bounds."""
        latencies = [1.2, 1.4, 1.1, 1.3, 1.5, 9500.0]
        mean, med, iqr, p95, ci = _compute_mttd_stats(latencies, n_bootstrap=1000, seed=42)
        assert mean is not None and mean > 1000.0
        assert med is not None and med < 2.0
        assert iqr is not None and iqr < 2.0
        assert p95 is not None
        assert ci is not None
        low, high = ci
        assert low <= high
        assert low <= mean <= high

    def test_mttd_n2_minimum_sample_size_for_bootstrap(self):
        """n=2 is the exact boundary where bootstrap CI activates."""
        mean, med, iqr, p95, ci = _compute_mttd_stats([10.0, 30.0], n_bootstrap=500, seed=42)
        assert mean == 20.0
        assert med == 20.0
        assert ci is not None
        low, high = ci
        assert 10.0 <= low <= high <= 30.0

    def test_mttd_bootstrap_determinism_with_fixed_seed(self):
        """Bootstrap CI must be bitwise reproducible given the same input and seed."""
        latencies = [4.5, 7.8, 12.1, 6.3, 9.9, 15.2]
        r1 = _compute_mttd_stats(latencies, n_bootstrap=1000, seed=42)
        r2 = _compute_mttd_stats(latencies, n_bootstrap=1000, seed=42)
        assert r1 == r2

    def test_safe_mean_and_percentile_empty_inputs(self):
        """_safe_mean and _safe_percentile return 0.0 on empty inputs without exception."""
        assert _safe_mean([]) == 0.0
        assert _safe_percentile([], 50.0) == 0.0
        assert _safe_percentile([10.0, 20.0, 30.0], 0.0) == 10.0
        assert _safe_percentile([10.0, 20.0, 30.0], 100.0) == 30.0


# ==============================================================================
# 3. Denominator Preservation & Evaluator Adversarial Hardening
# ==============================================================================


class TestTier5DenominatorPreservationAdversarial:
    """Stress-testing denominator preservation in ScenarioEvaluator."""

    def test_zero_negatives_preserves_none(self):
        """When benign runs are absent (N_benign=0), FPR, Precision, and F1 must be None."""
        evaluator = ScenarioEvaluator()
        sr = make_sr(
            run_id="attack_1",
            attack_id="xzutils",
            repetition=1,
            ground_truth_label=1,
            is_true_positive=True,
            inject_ok=True,
        )
        reports = evaluator.evaluate([sr], {})
        phantom = reports[0]
        assert phantom.tpr == 1.0
        assert phantom.recall == 1.0
        assert phantom.fpr is None
        assert phantom.precision is None
        assert phantom.f1 is None
        assert phantom.fp is None
        assert phantom.tn is None

    def test_zero_positive_predictions_precision_none(self):
        """When detector never fires (TP=0, FP=0), Precision must be None, not 0.0 or 1.0."""
        evaluator = ScenarioEvaluator()
        sr_attack = make_sr(
            run_id="attack_1",
            attack_id="xzutils",
            repetition=1,
            ground_truth_label=1,
            is_true_positive=False,
            inject_ok=True,
        )
        sr_benign = make_sr(
            run_id="benign_1",
            attack_id="benign",
            repetition=1,
            ground_truth_label=0,
            phantom_detections=[],
            inject_ok=True,
        )
        reports = evaluator.evaluate([sr_attack, sr_benign], {})
        phantom = reports[0]
        assert phantom.tp == 0
        assert phantom.fn == 1
        assert phantom.fp == 0
        assert phantom.tn == 1
        assert phantom.tpr == 0.0
        assert phantom.recall == 0.0
        assert phantom.fpr == 0.0
        assert phantom.precision is None
        assert phantom.f1 is None

    def test_zero_recall_f1_none_without_zerodivision(self):
        """When TP=0 and FN=1 but FP=1: Precision=0.0, Recall=0.0 -> F1 must be None."""
        rep = _build_report(
            detector_name="test_det",
            tp=0,
            fp=1,
            fn=1,
            tn=1,
            n_attack=1,
            n_benign=2,
            mttd_values=[],
            total_benign_s=100.0,
        )
        assert rep.recall == 0.0
        assert rep.precision == 0.0
        assert rep.f1 is None

    def test_zero_benign_duration_fp_per_hour_none(self):
        """When total benign duration is zero, false_positives_per_hour must be None."""
        rep = _build_report(
            detector_name="test_det",
            tp=1,
            fp=2,
            fn=0,
            tn=1,
            n_attack=1,
            n_benign=3,
            mttd_values=[10.0],
            total_benign_s=0.0,
        )
        assert rep.false_positives_per_hour is None

    def test_failed_injections_strictly_excluded_from_tpr_denominator(self):
        """Failed injection runs (inject_ok=False) must NEVER enter TPR denominator."""
        evaluator = ScenarioEvaluator()
        runs: list[ScenarioResult] = []
        # 3 completed attacks with TP
        for i in range(3):
            runs.append(
                make_sr(
                    run_id=f"run_valid_{i}",
                    attack_id="xzutils",
                    repetition=i + 1,
                    ground_truth_label=1,
                    is_true_positive=True,
                    inject_ok=True,
                )
            )
        # 2 failed injection runs
        for i in range(2):
            runs.append(
                make_sr(
                    run_id=f"run_failed_{i}",
                    attack_id="solarwinds",
                    repetition=i + 1,
                    ground_truth_label=1,
                    is_true_positive=False,
                    inject_ok=False,
                    error="inject() returned False",
                )
            )
        reports = evaluator.evaluate(runs, {})
        phantom = reports[0]
        assert phantom.n_attack_scenarios == 3
        assert phantom.excluded_failed_injections == 2
        assert phantom.tp == 3
        assert phantom.fn == 0
        assert phantom.tpr == 1.0
        assert phantom.tpr_ci_wilson is not None
        # Wilson CI computed on 3/3, not 3/5
        assert phantom.tpr_ci_wilson[0] > 0.40

    @pytest.mark.parametrize(
        ("kwargs", "expected_failed"),
        [
            ({"inject_ok": False}, True),
            ({"error": "inject() returned False"}, True),
            ({"error": "Phase 2 inject() raised ConnectionResetError"}, True),
            ({"error": "inject_ok=False detected in preflight"}, True),
            ({"phases": [PhaseRecord(name="inject", start_time=datetime.now(timezone.utc), notes="inject_ok=False")]}, True),
            ({"scenario_label": {"inject_ok": False}}, True),
            ({"inject_ok": True, "error": ""}, False),
            ({"inject_ok": True, "phases": [PhaseRecord(name="inject", start_time=datetime.now(timezone.utc), notes="all ok")]}, False),
        ],
    )
    def test_is_failed_injection_variants(self, kwargs: dict[str, Any], expected_failed: bool):
        """Exhaustive check of all failure signatures recognized by is_failed_injection."""
        sr = make_sr(
            run_id="test_run",
            attack_id="test_attack",
            repetition=1,
            ground_truth_label=1,
            **kwargs,
        )
        assert is_failed_injection(sr) is expected_failed

    def test_telemetry_collection_dropouts_counted_as_fn(self):
        """If injection was delivered (inject_ok=True) but collector dropped telemetry, count as FN."""
        evaluator = ScenarioEvaluator()
        sr = make_sr(
            run_id="dropout_run",
            attack_id="xzutils",
            repetition=1,
            ground_truth_label=1,
            inject_ok=True,
            is_true_positive=False,
            phantom_detections=[],
        )
        reports = evaluator.evaluate([sr], {})
        phantom = reports[0]
        assert phantom.n_attack_scenarios == 1
        assert phantom.excluded_failed_injections == 0
        assert phantom.tp == 0
        assert phantom.fn == 1
        assert phantom.tpr == 0.0

    def test_baseline_evaluator_empty_telemetry_classified_unavailable(self):
        """Baselines without telemetry must be classified as telemetry_unavailable with None counts."""
        evaluator = ScenarioEvaluator()
        sr = make_sr(
            run_id="attack_1",
            attack_id="xzutils",
            repetition=1,
            ground_truth_label=1,
            is_true_positive=True,
            inject_ok=True,
        )
        baselines = {
            "falco-default-rules": [],
            "trivy-sbom-static": [],
            "isolation-forest-syscall-frequency": [],
        }
        reports = evaluator.evaluate([sr], baselines)
        rep_map = {r.detector_name: r for r in reports}

        falco = rep_map["falco-default-rules"]
        assert falco.status == "telemetry_unavailable"
        assert falco.tp is None
        assert falco.fn is None
        assert falco.tpr is None

        trivy = rep_map["trivy-sbom-static"]
        assert trivy.status == "task_mismatch_and_telemetry_unavailable"
        assert trivy.tp is None
        assert trivy.tpr is None

    def test_baseline_evaluator_window_filtering(self):
        """Detections occurring outside detection window or after attack phase are not TPs."""
        evaluator = ScenarioEvaluator(detection_window_s=60.0)
        t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
        sr = make_sr(
            run_id="attack_win",
            attack_id="xzutils",
            repetition=1,
            ground_truth_label=1,
            inject_ok=True,
            injection_timestamp=t0,
            phases=[
                PhaseRecord(
                    name="attack",
                    start_time=t0,
                    end_time=t0 + timedelta(seconds=120),
                    duration_s=120.0,
                )
            ],
            scenario_label={"detection_window_s": 60.0},
        )
        # Late detection at t0 + 80s (outside 60s window)
        late_det = Detection(
            detected_at=t0 + timedelta(seconds=80),
            scenario_id="attack_win",
            detector_name="falco-default-rules",
            confidence=1.0,
            raw_alert={},
        )
        reports = evaluator.evaluate([sr], {"falco-default-rules": [late_det]})
        falco = next(r for r in reports if r.detector_name == "falco-default-rules")
        assert falco.tp == 0
        assert falco.fn == 1
        assert falco.tpr == 0.0


# ==============================================================================
# 4. Table Generation Adversarial Formatting & Bolding Hardening
# ==============================================================================


class TestTier5TableGenerationAdversarial:
    """Stress-testing comparison table formatting and bolding rules."""

    def test_unmeasured_overhead_zeros_never_bolded(self):
        """Feature 16: Zero CPU overhead from unmeasured telemetry must NEVER be bolded in CPU column."""
        reports = [
            EvaluationReport(
                detector_name="phantom",
                cpu_overhead_pct=0.0,
                overhead_status="unmeasured",
                tpr=1.0,
                fpr=0.0,
                f1=1.0,
            ),
            EvaluationReport(
                detector_name="falco-default-rules",
                cpu_overhead_pct=3.5,
                overhead_status="measured",
                tpr=0.8,
                fpr=0.1,
                f1=0.85,
            ),
        ]
        latex = generate_comparison_table(reports)
        lines = latex.splitlines()
        phantom_line = next(l for l in lines if "PHANTOM" in l)
        falco_line = next(l for l in lines if "Falco" in l)

        # Columns in TABLE_1: Detector & TPR & FPR & F1 & MTTD & CPU & FP/hr
        phantom_cells = [c.strip() for c in phantom_line.split("&")]
        falco_cells = [c.strip() for c in falco_line.split("&")]

        # CPU cell is index 5
        phantom_cpu_cell = phantom_cells[5]
        falco_cpu_cell = falco_cells[5]

        # Phantom CPU is unmeasured 0.0 -> must NOT be bolded
        assert r"\textbf" not in phantom_cpu_cell
        assert "0.000" in phantom_cpu_cell

        # Falco CPU is measured 3.5 -> is the only valid measured value -> must be bolded
        assert r"\textbf{3.500}" in falco_cpu_cell

    def test_telemetry_unavailable_cells_render_dashes_never_bolded(self):
        """Detectors with telemetry_unavailable must render \\text{---} and never be bolded."""
        reports = [
            EvaluationReport(
                detector_name="phantom",
                tpr=1.0,
                fpr=None,
                f1=None,
                status="evaluated",
            ),
            EvaluationReport(
                detector_name="falco-default-rules",
                tpr=None,
                fpr=None,
                f1=None,
                status="telemetry_unavailable",
            ),
        ]
        latex = generate_comparison_table(reports)
        assert r"\text{---}" in latex
        lines = latex.splitlines()
        falco_line = next(l for l in lines if "Falco" in l)
        assert r"\textbf" not in falco_line

    def test_all_none_column_produces_no_bolding(self):
        """When an entire column has None (e.g. FPR across all detectors), no cells are bolded."""
        reports = [
            EvaluationReport(detector_name="phantom", tpr=1.0, fpr=None, f1=None),
            EvaluationReport(detector_name="falco-default-rules", tpr=0.5, fpr=None, f1=None),
        ]
        latex = generate_comparison_table(reports)
        assert r"\textbf{\text{---}}" not in latex

    def test_format_cells_helper_contracts(self):
        """Format helpers format_latex_cell and format_csv_cell adhere strictly to contract."""
        assert format_latex_cell(None) == r"\text{---}"
        assert format_latex_cell(0.85, precision=2, is_best=False) == "0.85"
        assert format_latex_cell(0.85, precision=2, is_best=True) == r"\textbf{0.85}"
        assert format_csv_cell(None) == "---"
        assert format_csv_cell(0.12345, precision=4) == "0.1235"

    def test_csv_generation_clean_parsability(self):
        """generate_csv generates a valid CSV string with all expected columns."""
        reports = [
            EvaluationReport(detector_name="phantom", tpr=1.0, fpr=None, tp=6, n_attack_scenarios=6),
            EvaluationReport(detector_name="falco-default-rules", tpr=None, status="telemetry_unavailable"),
        ]
        csv_str = generate_csv(reports)
        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["detector_name"] == "phantom"
        assert rows[0]["tpr"] == "1.0000"
        assert rows[0]["fpr"] == ""
        assert rows[1]["detector_name"] == "falco-default-rules"
        assert rows[1]["tpr"] == ""

    def test_write_tables_emits_valid_artifacts(self, tmp_path: Path):
        """write_tables writes main table, extended table, and CSV to disk cleanly."""
        reports = [EvaluationReport(detector_name="phantom", tpr=1.0)]
        out_paths = write_tables(reports, tmp_path, prefix="test_tbl")
        assert out_paths["latex_main"].exists()
        assert out_paths["latex_extended"].exists()
        assert out_paths["csv"].exists()


# ==============================================================================
# 5. Pipeline CLI Adversarial Hardening
# ==============================================================================


class TestTier5PipelineCLIAdversarial:
    """Stress-testing run_pipeline_report CLI against adversarial data states."""

    def test_cli_handles_corrupt_json_record_gracefully(self, tmp_path: Path):
        """Dataset with corrupted JSON record must log run failure without aborting execution."""
        data_dir = tmp_path / "corrupt_dataset"
        data_dir.mkdir()
        # Write valid index
        (data_dir / "index.json").write_text(json.dumps({"results": ["corrupt_run", "valid_run"]}))
        # Write corrupt file
        (data_dir / "corrupt_run.json").write_text("{ unclosed json record ...")
        # Write valid file
        valid_run = {
            "run_id": "valid_run",
            "attack_id": "xzutils",
            "repetition": 1,
            "ground_truth_label": 1,
            "is_true_positive": True,
            "inject_ok": True,
            "phases": [],
            "metrics_snapshots": [],
        }
        (data_dir / "valid_run.json").write_text(json.dumps(valid_run))

        out_json = tmp_path / "out.json"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(data_dir),
            "--out",
            str(out_json),
        ]
        res = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[2]), capture_output=True, text=True, env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"})
        assert res.returncode == 0, f"CLI crashed: {res.stderr}"
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["total_runs_in_index"] == 2
        corrupt_entry = next(r for r in report["runs"] if r["run_id"] == "corrupt_run")
        assert "Processing failed" in corrupt_entry["error"]
        assert corrupt_entry["estimation_attempted"] is False

    def test_cli_missing_mandatory_fields_in_scenario_dict(self):
        """_dict_to_scenario_result handles dictionaries with entirely missing fields."""
        minimal_dict: dict[str, Any] = {"run_id": "sparse_run"}
        sr = run_pipeline_report._dict_to_scenario_result(minimal_dict)
        assert sr.run_id == "sparse_run"
        assert sr.phases == []
        assert sr.metrics_snapshots == []
        assert sr.is_true_positive is False
        assert sr.inject_ok is True
        assert sr.ground_truth_label == 0

    def test_cli_all_failed_injections_synthetic_dataset(self, tmp_path: Path):
        """Dataset with 100% failed injections produces valid report with TPR=None and exclusions."""
        data_dir = tmp_path / "all_failed_dataset"
        data_dir.mkdir()
        run_ids = [f"failed_{i}" for i in range(4)]
        (data_dir / "index.json").write_text(json.dumps({"results": run_ids}))
        for r_id in run_ids:
            run_data = {
                "run_id": r_id,
                "attack_id": "solarwinds",
                "repetition": 1,
                "ground_truth_label": 1,
                "inject_ok": False,
                "error": "inject() returned False",
                "phases": [],
                "metrics_snapshots": [],
            }
            (data_dir / f"{r_id}.json").write_text(json.dumps(run_data))

        out_json = tmp_path / "report_failed.json"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(data_dir),
            "--out",
            str(out_json),
        ]
        res = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[2]), capture_output=True, text=True, env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"})
        assert res.returncode == 0
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["data_quality"]["failed_injections"] == 4
        assert report["data_quality"]["completed_attacks"] == 0
        assert len(report["exclusions"]) == 4
        assert report["metrics"]["tpr"] is None
        assert report["metrics"]["excluded_failed_injections"] == 4

    def test_cli_all_telemetry_dropouts_synthetic_dataset(self, tmp_path: Path):
        """Dataset with 100% telemetry dropouts produces TPR=0.0 and Wilson CI [0.0, upper]."""
        data_dir = tmp_path / "all_dropouts"
        data_dir.mkdir()
        run_ids = [f"dropout_{i}" for i in range(3)]
        (data_dir / "index.json").write_text(json.dumps({"results": run_ids}))
        for r_id in run_ids:
            run_data = {
                "run_id": r_id,
                "attack_id": "xzutils",
                "repetition": 1,
                "ground_truth_label": 1,
                "inject_ok": True,
                "is_true_positive": False,
                "phantom_detections": [],
                "phases": [],
                "metrics_snapshots": [],
            }
            (data_dir / f"{r_id}.json").write_text(json.dumps(run_data))

        out_json = tmp_path / "report_dropouts.json"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(data_dir),
            "--out",
            str(out_json),
        ]
        res = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[2]), capture_output=True, text=True, env={**os.environ, "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"})
        assert res.returncode == 0
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["data_quality"]["collection_dropouts"] == 3
        assert report["metrics"]["tpr"] == 0.0
        assert report["metrics"]["tpr_ci_wilson"][0] == 0.0
        assert report["metrics"]["tpr_ci_wilson"][1] > 0.50
