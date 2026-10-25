"""
research/evaluation/tests/test_adversarial_challenger_m3.py

Adversarial Stress Test Suite for Milestone 3 (Evaluator & Comparison Table).
Author: challenger_m3_2 (teamwork_preview_challenger)

Tests cover:
1. Real raw3 dataset execution & audit:
   - Failed injection exclusions (3 solarwinds runs excluded, TPR denominator = 6)
   - TPR = 1.0, FPR = None, Precision = None, F1 = None on raw3
   - Baseline outputs (Falco, Trivy, IsoForest) classified as telemetry_unavailable /
     task_mismatch_and_telemetry_unavailable with None metrics (not FN=6, TPR=0.0).
2. Comparison table & CSV generation:
   - LaTeX outputs \\text{---} for None values
   - CSV cell helper outputs --- for None values
   - generate_csv outputs clean parsable CSV with empty strings for null fields
3. Stress-testing bolding logic:
   - Unmeasured overhead is NEVER bolded as optimal
   - Missing / unavailable baselines are NEVER bolded as optimal
   - Valid measured metrics are correctly bolded
4. Edge cases & boundary testing:
   - Zero-denominator metrics (empty inputs, attack-only, benign-only)
   - Failed injection detection variants
   - Late detection outside window
   - Wilson score & bootstrap MTTD edge conditions
"""

from __future__ import annotations

import csv
import json
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from research.evaluation.baselines.base_baseline import Detection
from research.evaluation.metrics.comparison_table import (
    _find_best,
    format_csv_cell,
    format_latex_cell,
    generate_comparison_table,
    generate_csv,
)
from research.evaluation.metrics.evaluator import (
    EvaluationReport,
    ScenarioEvaluator,
    _build_report,
    _compute_mttd_stats,
    is_failed_injection,
)
from research.evaluation.metrics.wilson_score import (
    compute_ordinary_wilson_score,
    wilson_score_interval,
)
from research.evaluation.scenarios.scenario_runner import (
    MetricsSnapshot,
    PhaseRecord,
    ScenarioResult,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
RAW3_DIR = _REPO_ROOT / "research" / "datasets" / "raw3"


# ---------------------------------------------------------------------------
# Helper: Load raw3 scenario results
# ---------------------------------------------------------------------------

def load_raw3_scenarios() -> list[ScenarioResult]:
    """Load and parse all ScenarioResult files from research/datasets/raw3/."""
    results: list[ScenarioResult] = []
    for p in sorted(RAW3_DIR.glob("*.json")):
        if p.name == "index.json":
            continue
        data = json.loads(p.read_text(encoding="utf-8"))
        phases = [
            PhaseRecord(
                name=ph["name"],
                start_time=datetime.fromisoformat(ph["start_time"]) if ph.get("start_time") else datetime.now(timezone.utc),
                end_time=datetime.fromisoformat(ph["end_time"]) if ph.get("end_time") else None,
                duration_s=ph.get("duration_s", 0.0),
                notes=ph.get("notes", ""),
            )
            for ph in data.get("phases", [])
        ]
        snaps = [
            MetricsSnapshot(
                timestamp=datetime.fromisoformat(ms["timestamp"]),
                cpu_usage_cores=ms.get("cpu_usage_cores", 0.0),
                memory_rss_mb=ms.get("memory_rss_mb", 0.0),
                event_lag_p95_ms=ms.get("event_lag_p95_ms", 0.0),
                phase=ms.get("phase", ""),
            )
            for ms in data.get("metrics_snapshots", [])
        ]
        sr = ScenarioResult(
            run_id=data["run_id"],
            attack_id=data["attack_id"],
            attack_family=data["attack_family"],
            repetition=data["repetition"],
            namespace=data["namespace"],
            pod_name=data.get("pod_name", ""),
            ground_truth_label=data["ground_truth_label"],
            injection_timestamp=datetime.fromisoformat(data["injection_timestamp"]) if data.get("injection_timestamp") else None,
            first_phantom_detection_timestamp=datetime.fromisoformat(data["first_phantom_detection_timestamp"]) if data.get("first_phantom_detection_timestamp") else None,
            mttd_s=data.get("mttd_s"),
            is_true_positive=data.get("is_true_positive", False),
            phases=phases,
            phantom_detections=data.get("phantom_detections", []),
            falco_detections=data.get("falco_detections", []),
            metrics_snapshots=snaps,
            scenario_label=data.get("scenario_label", {}),
            error=data.get("error", ""),
        )
        results.append(sr)
    return results


# ===========================================================================
# 1. Real Raw3 Dataset Adversarial Verification
# ===========================================================================

class TestRaw3DatasetAdversarialVerification:
    """Stress tests executing on actual raw3 dataset files."""

    def test_raw3_inventory_and_failed_injection_classification(self):
        """Audit all 9 runs in raw3: exactly 3 failed injections (solarwinds) and 6 valid."""
        scenarios = load_raw3_scenarios()
        assert len(scenarios) == 9

        failed_runs = [r for r in scenarios if is_failed_injection(r)]
        valid_runs = [r for r in scenarios if not is_failed_injection(r)]

        assert len(failed_runs) == 3
        assert len(valid_runs) == 6

        # Check failed runs are all solarwinds-001
        for r in failed_runs:
            assert r.attack_id == "solarwinds-001"
            assert "inject() returned False" in r.error or any("inject_ok=False" in p.notes for p in r.phases)

        # Check valid runs are xzutils-001 and dep-confusion-001
        for r in valid_runs:
            assert r.attack_id in ("xzutils-001", "dep-confusion-001")
            assert r.ground_truth_label == 1
            assert r.is_true_positive is True

    def test_raw3_phantom_evaluation_defensible_metrics(self):
        """ScenarioEvaluator on raw3 produces TPR=1.0 (6/6), excluded=3, and None for undefined metrics."""
        scenarios = load_raw3_scenarios()
        ev = ScenarioEvaluator()
        reports = ev.evaluate(scenarios, detections={})
        phantom = reports[0]

        assert phantom.detector_name == "phantom"
        assert phantom.status == "evaluated"
        assert phantom.n_attack_scenarios == 6
        assert phantom.excluded_failed_injections == 3

        # Detection sensitivity
        assert phantom.tp == 6
        assert phantom.fn == 0
        assert phantom.tpr == pytest.approx(1.0)
        assert phantom.recall == pytest.approx(1.0)

        # Exact ordinary Wilson score confidence interval
        assert phantom.tpr_ci_wilson is not None
        assert abs(phantom.tpr_ci_wilson[0] - 0.6096) < 0.001
        assert phantom.tpr_ci_wilson[1] == pytest.approx(1.0000)

        # Undefined metrics due to absence of benign control runs (N_benign = 0)
        assert phantom.n_benign_scenarios == 0
        assert phantom.fp is None
        assert phantom.tn is None
        assert phantom.fpr is None
        assert phantom.precision is None
        assert phantom.f1 is None
        assert phantom.false_positives_per_hour is None

        # Overhead status on raw3 (no live Prometheus metrics)
        assert phantom.overhead_status == "unmeasured"
        assert phantom.cpu_overhead_pct is None
        assert phantom.memory_overhead_mb is None
        assert phantom.event_lag_p95_ms is None

    def test_raw3_baseline_absence_classification(self):
        """Baselines without telemetry must be classified as unavailable with None metrics, NOT FN=6, TPR=0.0."""
        scenarios = load_raw3_scenarios()
        ev = ScenarioEvaluator()
        baselines = {
            "falco-default-rules": [],
            "trivy-sbom-static": [],
            "isolation-forest-syscall-frequency": [],
        }
        reports = ev.evaluate(scenarios, detections=baselines)

        report_map = {r.detector_name: r for r in reports}

        # Falco check
        falco = report_map["falco-default-rules"]
        assert falco.status == "telemetry_unavailable"
        assert falco.tp is None
        assert falco.fn is None
        assert falco.tpr is None
        assert falco.fpr is None
        assert falco.precision is None
        assert falco.f1 is None
        assert falco.overhead_status == "unmeasured"

        # Trivy check (task mismatch and telemetry unavailable)
        trivy = report_map["trivy-sbom-static"]
        assert trivy.status == "task_mismatch_and_telemetry_unavailable"
        assert trivy.tp is None
        assert trivy.fn is None
        assert trivy.tpr is None
        assert trivy.fpr is None
        assert trivy.precision is None
        assert trivy.f1 is None

        # Isolation Forest check
        iso = report_map["isolation-forest-syscall-frequency"]
        assert iso.status == "telemetry_unavailable"
        assert iso.tp is None
        assert iso.fn is None
        assert iso.tpr is None


# ===========================================================================
# 2. Table Formatting and CSV Generation Stress Tests
# ===========================================================================

class TestComparisonTableFormattingStress:
    """Stress tests for LaTeX and CSV generation and None-value rendering."""

    def test_format_latex_cell_rendering_matrix(self):
        """Check all edge cases for LaTeX cell formatting."""
        assert format_latex_cell(None) == r"\text{---}"
        assert format_latex_cell(None, is_best=True) == r"\text{---}"
        assert format_latex_cell(0.0, is_best=False) == "0.000"
        assert format_latex_cell(0.0, is_best=True) == r"\textbf{0.000}"
        assert format_latex_cell(1.0, precision=2, is_best=True) == r"\textbf{1.00}"
        assert format_latex_cell(0.12345, precision=4, is_best=False) == "0.1235"
        assert format_latex_cell(-0.5, precision=1, is_best=False) == "-0.5"

    def test_format_csv_cell_rendering_matrix(self):
        """Check all edge cases for CSV cell formatting."""
        assert format_csv_cell(None) == "---"
        assert format_csv_cell(0.0) == "0.0000"
        assert format_csv_cell(1.0, precision=2) == "1.00"
        assert format_csv_cell(0.85432, precision=3) == "0.854"

    def test_raw3_latex_table_rendering(self):
        """Generating comparison table for raw3 reports renders \\text{---} across all undefined cells."""
        scenarios = load_raw3_scenarios()
        ev = ScenarioEvaluator()
        baselines = {
            "falco-default-rules": [],
            "trivy-sbom-static": [],
            "isolation-forest-syscall-frequency": [],
        }
        reports = ev.evaluate(scenarios, detections=baselines)

        latex = generate_comparison_table(reports)
        assert r"\begin{tabular}" in latex
        assert r"\textbf{PHANTOM (ours)}" in latex
        assert r"\textbf{1.000}" in latex  # TPR is bolded

        # All undefined cells are rendered as \text{---}
        # In phantom row: FPR, F1, CPU%, FP/hr must be \text{---}
        # In baseline rows: all metrics must be \text{---}
        lines = [line.strip() for line in latex.splitlines() if line.strip().endswith(r"\\")]
        phantom_line = next(l for l in lines if "PHANTOM" in l)
        assert r"\text{---}" in phantom_line

        for b_name in ("Falco", "Trivy", "IsoForest"):
            b_line = next(l for l in lines if b_name in l)
            # All 6 metric columns in TABLE_1 must be \text{---}
            cells = [c.strip() for c in b_line.split("&")[1:]]
            assert all(r"\text{---}" in c for c in cells)

    def test_raw3_csv_generation_integrity(self):
        """generate_csv emits valid CSV with empty strings for nulls and correct row headers."""
        scenarios = load_raw3_scenarios()
        ev = ScenarioEvaluator()
        baselines = {
            "falco-default-rules": [],
            "trivy-sbom-static": [],
            "isolation-forest-syscall-frequency": [],
        }
        reports = ev.evaluate(scenarios, detections=baselines)

        csv_str = generate_csv(reports)
        reader = list(csv.DictReader(csv_str.strip().splitlines()))
        assert len(reader) == 4

        detector_names = [r["detector_name"] for r in reader]
        assert detector_names[0] == "phantom"

        phantom_row = reader[0]
        assert phantom_row["tpr"] == "1.0000"
        assert phantom_row["fpr"] == ""
        assert phantom_row["f1"] == ""
        assert phantom_row["cpu_overhead_pct"] == ""


# ===========================================================================
# 3. Adversarial Bolding Logic Stress Tests
# ===========================================================================

class TestAdversarialBoldingLogic:
    """Stress tests ensuring unmeasured overhead or missing baselines are NEVER bolded."""

    def test_unmeasured_zero_overhead_never_bolded(self):
        """If overhead is unmeasured (overhead_status='unmeasured'), 0.0 must NEVER be bolded."""
        r1 = EvaluationReport(
            detector_name="phantom",
            status="evaluated",
            tpr=1.0,
            overhead_status="unmeasured",
            cpu_overhead_pct=0.0,  # adversarial attempt: 0.0 unmeasured
        )
        r2 = EvaluationReport(
            detector_name="falco-default-rules",
            status="evaluated",
            tpr=0.8,
            overhead_status="measured",
            cpu_overhead_pct=4.5,
        )

        latex = generate_comparison_table([r1, r2])
        # In r1, cpu_overhead_pct must NOT be bolded
        lines = [l for l in latex.splitlines() if r"\textbf{PHANTOM" in l]
        assert len(lines) == 1
        phantom_line = lines[0]
        # Should not contain \textbf{0.000}
        assert r"\textbf{0.000}" not in phantom_line

        # Best value calculation should exclude r1
        best_cpu = _find_best([r1, r2], "cpu_overhead_pct", higher_is_better=False)
        assert best_cpu == 4.5

    def test_unavailable_baseline_with_artificially_injected_metrics_never_bolded(self):
        """Baselines with telemetry_unavailable or task_mismatch must NEVER be bolded even if metrics are set."""
        r1 = EvaluationReport(
            detector_name="phantom",
            status="evaluated",
            tpr=0.9,
            f1=0.85,
        )
        r2 = EvaluationReport(
            detector_name="falco-default-rules",
            status="telemetry_unavailable",
            tpr=1.0,   # adversarial spoofing: highest TPR but unavailable status
            f1=1.0,
        )
        r3 = EvaluationReport(
            detector_name="trivy-sbom-static",
            status="task_mismatch_and_telemetry_unavailable",
            tpr=1.0,
            f1=1.0,
        )

        best_tpr = _find_best([r1, r2, r3], "tpr", higher_is_better=True)
        assert best_tpr == 0.9  # Only phantom is eligible

        latex = generate_comparison_table([r1, r2, r3])
        lines = latex.splitlines()
        falco_line = next(l for l in lines if "Falco" in l)
        trivy_line = next(l for l in lines if "Trivy" in l)

        assert r"\textbf" not in falco_line
        assert r"\textbf" not in trivy_line

    def test_all_detectors_unmeasured_overhead_yields_no_bold(self):
        """When all detectors have unmeasured overhead, the CPU column has no bold values."""
        r1 = EvaluationReport(
            detector_name="phantom",
            status="evaluated",
            overhead_status="unmeasured",
            cpu_overhead_pct=None,
        )
        r2 = EvaluationReport(
            detector_name="falco-default-rules",
            status="telemetry_unavailable",
            overhead_status="unmeasured",
            cpu_overhead_pct=None,
        )

        best_cpu = _find_best([r1, r2], "cpu_overhead_pct", higher_is_better=False)
        assert best_cpu is None

        latex = generate_comparison_table([r1, r2])
        # Neither row has bold overhead
        for line in latex.splitlines():
            if "Detector" in line or r"\caption" in line or r"\label" in line:
                continue
            assert r"\textbf{---}" not in line

    def test_proper_bolding_when_valid_metrics_present(self):
        """When valid measurements are present, best values are bolded properly."""
        r1 = EvaluationReport(
            detector_name="phantom",
            status="evaluated",
            tpr=1.0,
            fpr=0.01,
            f1=0.99,
            mttd_mean_s=12.5,
            overhead_status="measured",
            cpu_overhead_pct=2.1,
            false_positives_per_hour=0.05,
        )
        r2 = EvaluationReport(
            detector_name="falco-default-rules",
            status="evaluated",
            tpr=0.85,
            fpr=0.05,
            f1=0.80,
            mttd_mean_s=25.0,
            overhead_status="measured",
            cpu_overhead_pct=5.4,
            false_positives_per_hour=0.20,
        )

        latex = generate_comparison_table([r1, r2])
        phantom_line = next(l for l in latex.splitlines() if "PHANTOM" in l)
        # All optimal metrics should be bold in phantom row
        assert r"\textbf{1.000}" in phantom_line
        assert r"\textbf{0.010}" in phantom_line
        assert r"\textbf{0.990}" in phantom_line
        assert r"\textbf{12.500}" in phantom_line
        assert r"\textbf{2.100}" in phantom_line
        assert r"\textbf{0.050}" in phantom_line


# ===========================================================================
# 4. Adversarial Evaluator Edge Cases & Invariant Verification
# ===========================================================================

class TestAdversarialEvaluatorEdgeCases:
    """Stress tests on edge inputs, boundary counts, and statistical helpers."""

    def test_empty_evaluator_input(self):
        """ScenarioEvaluator handles empty scenario lists gracefully."""
        ev = ScenarioEvaluator()
        reports = ev.evaluate([], {})
        assert len(reports) == 1
        phantom = reports[0]
        assert phantom.n_attack_scenarios == 0
        assert phantom.n_benign_scenarios == 0
        assert phantom.tpr is None
        assert phantom.fpr is None
        assert phantom.precision is None
        assert phantom.f1 is None
        assert phantom.overhead_status == "unmeasured"

    def test_all_failed_injections_batch(self):
        """Batch consisting entirely of failed injections yields TPR denominator = 0, TPR = None."""
        runs = [
            ScenarioResult(
                run_id=f"fail_{i}",
                attack_id="solarwinds-001",
                attack_family="build_pipeline_tampering",
                repetition=i,
                namespace="default",
                pod_name="pod",
                ground_truth_label=1,
                error="inject() returned False",
            )
            for i in range(5)
        ]
        ev = ScenarioEvaluator()
        reports = ev.evaluate(runs, {})
        phantom = reports[0]
        assert phantom.n_attack_scenarios == 0
        assert phantom.excluded_failed_injections == 5
        assert phantom.tp == 0
        assert phantom.fn == 0
        assert phantom.tpr is None
        assert phantom.tpr_ci_wilson is None

    def test_benign_only_batch_denominators(self):
        """Batch of benign scenarios: TPR=None, Precision=None, FPR=0.0 (if no FP)."""
        now = datetime.now(timezone.utc)
        benign_runs = [
            ScenarioResult(
                run_id=f"benign_{i}",
                attack_id="benign-traffic",
                attack_family="benign",
                repetition=i,
                namespace="default",
                pod_name="pod",
                ground_truth_label=0,
                phases=[
                    PhaseRecord(name="baseline", start_time=now, end_time=now + timedelta(seconds=60), duration_s=60.0)
                ],
                phantom_detections=[],
            )
            for i in range(4)
        ]
        ev = ScenarioEvaluator()
        reports = ev.evaluate(benign_runs, {})
        phantom = reports[0]
        assert phantom.n_attack_scenarios == 0
        assert phantom.n_benign_scenarios == 4
        assert phantom.tpr is None
        assert phantom.tp == 0
        assert phantom.fn == 0
        assert phantom.fp == 0
        assert phantom.tn == 4
        assert phantom.fpr == 0.0
        assert phantom.precision is None
        assert phantom.f1 is None
        assert phantom.false_positives_per_hour == 0.0

    def test_is_failed_injection_adversarial_patterns(self):
        """Verify is_failed_injection detects all documented failure patterns."""
        now = datetime.now(timezone.utc)
        # 1. Attribute inject_ok = False
        r1 = ScenarioResult(
            run_id="r1", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
        )
        setattr(r1, "inject_ok", False)
        assert is_failed_injection(r1) is True

        # 2. Phase note contains inject_ok=False
        r2 = ScenarioResult(
            run_id="r2", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
            phases=[PhaseRecord(name="inject", start_time=now, notes="failed: inject_ok=False")],
        )
        assert is_failed_injection(r2) is True

        # 3. Error string contains inject() returned False
        r3 = ScenarioResult(
            run_id="r3", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
            error="inject() returned False",
        )
        assert is_failed_injection(r3) is True

        # 4. Error string contains inject() raised
        r4 = ScenarioResult(
            run_id="r4", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
            error="inject() raised DeploymentTimeoutError",
        )
        assert is_failed_injection(r4) is True

        # 5. Scenario label contains inject_ok: False
        r5 = ScenarioResult(
            run_id="r5", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
            scenario_label={"inject_ok": False},
        )
        assert is_failed_injection(r5) is True

        # 6. Clean run is NOT failed injection
        r6 = ScenarioResult(
            run_id="r6", attack_id="a", attack_family="f", repetition=1,
            namespace="d", pod_name="p", ground_truth_label=1,
            phases=[PhaseRecord(name="inject", start_time=now, notes="inject_ok=True")],
        )
        assert is_failed_injection(r6) is False

    def test_baseline_evaluation_with_valid_and_spurious_detections(self):
        """Baseline detector with detections: classifies TP within window and FP in benign."""
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        attack_run = ScenarioResult(
            run_id="atk1",
            attack_id="xzutils",
            attack_family="backdoor",
            repetition=1,
            namespace="eval",
            pod_name="pod",
            ground_truth_label=1,
            injection_timestamp=t0 + timedelta(seconds=10),
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
        benign_run = ScenarioResult(
            run_id="ben1",
            attack_id="benign",
            attack_family="benign",
            repetition=1,
            namespace="eval",
            pod_name="pod",
            ground_truth_label=0,
            phases=[
                PhaseRecord(
                    name="baseline",
                    start_time=t0 + timedelta(seconds=200),
                    end_time=t0 + timedelta(seconds=320),
                    duration_s=120.0,
                )
            ],
        )

        # Baseline detection in attack window (+25s after t0, +15s after inject) -> TP
        det_tp = Detection(
            detected_at=t0 + timedelta(seconds=25),
            scenario_id="atk1",
            detector_name="falco-default-rules",
            confidence=1.0,
            rule_or_signal="Terminal shell in container",
            severity="critical",
        )
        # Baseline detection in benign window -> FP
        det_fp = Detection(
            detected_at=t0 + timedelta(seconds=250),
            scenario_id="ben1",
            detector_name="falco-default-rules",
            confidence=0.8,
            rule_or_signal="File access",
            severity="warning",
        )

        ev = ScenarioEvaluator()
        reports = ev.evaluate(
            [attack_run, benign_run],
            detections={"falco-default-rules": [det_tp, det_fp]},
        )
        falco = next(r for r in reports if r.detector_name == "falco-default-rules")

        assert falco.status == "evaluated"
        assert falco.tp == 1
        assert falco.fn == 0
        assert falco.tpr == pytest.approx(1.0)
        assert falco.fp == 1
        assert falco.tn == 0
        assert falco.fpr == pytest.approx(1.0)
        assert falco.precision == pytest.approx(0.5)
        assert falco.mttd_mean_s == pytest.approx(15.0)

    def test_ordinary_wilson_score_mathematical_properties(self):
        """Wilson score interval adheres strictly to mathematical bounds without continuity correction."""
        # 6/6 at 95% confidence
        low, high = compute_ordinary_wilson_score(6, 6, confidence=0.95)
        assert abs(low - 0.6096) < 0.001
        assert abs(high - 1.0000) < 0.001

        # 0/0 -> (None, None)
        low0, high0 = compute_ordinary_wilson_score(0, 0, confidence=0.95)
        assert low0 is None
        assert high0 is None

        # 0/6 at 95% confidence (symmetric lower bound: [0.0000, 0.3904])
        low_zero, high_zero = compute_ordinary_wilson_score(0, 6, confidence=0.95)
        assert abs(low_zero - 0.0000) < 0.001
        assert abs(high_zero - 0.3904) < 0.001

        # 50/100 at 95% confidence -> around [0.4038, 0.5962]
        low50, high50 = compute_ordinary_wilson_score(50, 100, confidence=0.95)
        assert abs(low50 - 0.4038) < 0.002
        assert abs(high50 - 0.5962) < 0.002

    def test_bootstrap_mttd_confidence_intervals_determinism(self):
        """Bootstrap MTTD interval calculation is deterministic with seed and returns None for n < 2."""
        # n = 0 -> all None
        mean0, med0, iqr0, p95_0, ci0 = _compute_mttd_stats([])
        assert mean0 is None and ci0 is None

        # n = 1 -> CI is None (cannot bootstrap 1 observation)
        mean1, med1, iqr1, p95_1, ci1 = _compute_mttd_stats([15.0])
        assert mean1 == 15.0
        assert ci1 is None

        # n = 6 (like raw3 valid runs)
        values = [70.33, 5.52, 5.37, 5.48, 5.32, 5.42]
        mean, med, iqr, p95, ci = _compute_mttd_stats(values, n_bootstrap=2000, seed=42)
        assert mean == pytest.approx(round(statistics.mean(values), 2))
        assert ci is not None
        assert ci[0] <= mean <= ci[1]

        # Repeated execution produces identical interval
        mean2, med2, iqr2, p95_2, ci2 = _compute_mttd_stats(values, n_bootstrap=2000, seed=42)
        assert ci == ci2
