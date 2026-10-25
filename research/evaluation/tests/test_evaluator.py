"""
research/evaluation/tests/test_evaluator.py

Unit tests for ScenarioEvaluator and helper functions.

All test data is SYNTHETIC. No real experimental results are used or
modified by this file. See conftest.py for fixture definitions.

Test coverage (matching task requirements 1–10):
  1. Correctly detected attack → TP counted, MTTD measured
  2. Attack not detected → FN counted, MTTD absent
  3. False alert during benign run → FP counted
  4. Benign run without alert → TN counted
  5. Multiple alerts for one incident → only one TP, earliest MTTD used
  6. Missing injection timestamp → run excluded from MTTD, marked FN
  7. Failed / incomplete run → error field non-empty; not counted as TP
  8. Undefined metric denominators → precision/recall/FPR/F1 = 0.0, not NaN
  9. Correct latency calculation from known timestamps
 10. Correct metric aggregation across multiple runs
"""

from __future__ import annotations

import math
import sys
from datetime import timedelta
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.metrics.evaluator import (
    ScenarioEvaluator,
    _build_report,
    _safe_mean,
    _safe_percentile,
)
from research.evaluation.baselines.base_baseline import Detection

from .conftest import (
    _T0,
    _t,
    _make_attack_result,
    _make_benign_result,
    _make_detection,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helper: build an evaluator with default 120s window
# ---------------------------------------------------------------------------

def _evaluator() -> ScenarioEvaluator:
    return ScenarioEvaluator(detection_window_s=120.0)


# ===========================================================================
# Test 1 — Correctly detected attack → TP, MTTD measured
# ===========================================================================


def test_tp_counted(tp_attack_result):
    """PHANTOM TP is counted when is_true_positive=True on a ScenarioResult."""
    ev = _evaluator()
    reports = ev.evaluate([tp_attack_result], {})
    phantom = reports[0]
    assert phantom.tp == 1
    assert phantom.fn == 0
    assert phantom.n_attack_scenarios == 1


def test_mttd_measured(tp_attack_result):
    """MTTD is non-None and positive for a TP run."""
    ev = _evaluator()
    reports = ev.evaluate([tp_attack_result], {})
    phantom = reports[0]
    assert phantom.mttd_mean_s is not None
    assert phantom.mttd_mean_s > 0.0
    # Fixture has mttd_s=30.0
    assert abs(phantom.mttd_mean_s - 30.0) < 0.01


def test_tpr_one_attack_one_tp(tp_attack_result):
    """TPR = 1.0 when 1 attack detected out of 1."""
    ev = _evaluator()
    reports = ev.evaluate([tp_attack_result], {})
    assert reports[0].tpr == pytest.approx(1.0)
    assert reports[0].recall == pytest.approx(1.0)


# ===========================================================================
# Test 2 — Attack not detected → FN, no MTTD
# ===========================================================================


def test_fn_counted(fn_attack_result):
    """FN is counted when is_true_positive=False on an attack run."""
    ev = _evaluator()
    reports = ev.evaluate([fn_attack_result], {})
    phantom = reports[0]
    assert phantom.tp == 0
    assert phantom.fn == 1


def test_no_mttd_for_fn(fn_attack_result):
    """mttd_mean_s is None when there are only FN runs."""
    ev = _evaluator()
    reports = ev.evaluate([fn_attack_result], {})
    assert reports[0].mttd_mean_s is None
    assert reports[0].mttd_p50_s is None
    assert reports[0].mttd_p95_s is None


def test_tpr_zero_fn(fn_attack_result):
    """TPR = 0.0 when no attacks were detected."""
    ev = _evaluator()
    reports = ev.evaluate([fn_attack_result], {})
    assert reports[0].tpr == pytest.approx(0.0)


# ===========================================================================
# Test 3 — False alert during benign run → FP
# ===========================================================================


def test_fp_counted(fp_benign_result):
    """FP is counted when phantom_detections is non-empty on a benign run."""
    ev = _evaluator()
    reports = ev.evaluate([fp_benign_result], {})
    phantom = reports[0]
    assert phantom.fp == 1
    assert phantom.tn == 0


def test_fp_per_hour_positive(fp_benign_result):
    """FP/hr is positive when there is at least one false positive."""
    ev = _evaluator()
    reports = ev.evaluate([fp_benign_result], {})
    assert reports[0].false_positives_per_hour > 0.0


# ===========================================================================
# Test 4 — Benign run without alert → TN
# ===========================================================================


def test_tn_counted(tn_benign_result):
    """TN is counted when no phantom_detections on a benign run."""
    ev = _evaluator()
    reports = ev.evaluate([tn_benign_result], {})
    phantom = reports[0]
    assert phantom.tn == 1
    assert phantom.fp == 0


def test_fpr_zero_for_clean_benign(tn_benign_result):
    """FPR = 0 when the only benign run has no false alarm."""
    ev = _evaluator()
    reports = ev.evaluate([tn_benign_result], {})
    assert reports[0].fpr == pytest.approx(0.0)


# ===========================================================================
# Test 5 — Multiple alerts for one incident → one TP, earliest MTTD
# ===========================================================================


def test_single_tp_despite_multiple_alerts(multi_alert_result):
    """Multiple phantom_detections in one run produce exactly one TP."""
    ev = _evaluator()
    reports = ev.evaluate([multi_alert_result], {})
    phantom = reports[0]
    assert phantom.tp == 1
    assert len(multi_alert_result.phantom_detections) == 3


def test_mttd_uses_earliest_alert(multi_alert_result):
    """MTTD reflects the earliest detection alert (30s), not a later one."""
    ev = _evaluator()
    reports = ev.evaluate([multi_alert_result], {})
    # Fixture: injection T0+300, first alert T0+330 → MTTD = 30s
    assert reports[0].mttd_mean_s == pytest.approx(30.0, abs=0.1)


# ===========================================================================
# Test 6 — Missing injection timestamp → excluded from MTTD
# ===========================================================================


def test_missing_injection_ts_not_counted_as_tp(missing_timestamps_result):
    """A run with injection_timestamp=None is treated as not-detected (FN)."""
    ev = _evaluator()
    reports = ev.evaluate([missing_timestamps_result], {})
    phantom = reports[0]
    # is_true_positive was set to False in the fixture
    assert phantom.tp == 0
    assert phantom.fn == 1


def test_missing_injection_ts_no_mttd(missing_timestamps_result):
    """No MTTD is produced when injection timestamp is absent."""
    ev = _evaluator()
    reports = ev.evaluate([missing_timestamps_result], {})
    assert reports[0].mttd_mean_s is None


# ===========================================================================
# Test 7 — Failed / incomplete run
# ===========================================================================


def test_failed_run_has_error_field(failed_result):
    """A failed run has a non-empty error field."""
    assert failed_result.error != ""


def test_failed_run_not_tp(failed_result):
    """A failed run is not counted as a true positive."""
    assert not failed_result.is_true_positive


def test_failed_run_fn_in_evaluator(failed_result):
    """A failed attack run (inject_ok=False) is excluded from TPR denominators, not counted as FN."""
    ev = _evaluator()
    reports = ev.evaluate([failed_result], {})
    phantom = reports[0]
    assert phantom.tp == 0
    assert phantom.fn == 0
    assert phantom.tpr is None
    assert phantom.excluded_failed_injections == 1
    assert phantom.n_attack_scenarios == 0


# ===========================================================================
# Test 8 — Undefined metric denominators handled correctly
# ===========================================================================


def test_precision_undefined_no_tp_fp():
    """Precision is None (undefined denominator) when TP=0 and FP=0."""
    report = _build_report(
        detector_name="test",
        tp=0, fp=0, fn=3, tn=0,
        n_attack=3, n_benign=0,
        mttd_values=[],
        total_benign_s=3600.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.precision is None


def test_tpr_undefined_no_positives():
    """TPR is None (undefined denominator) when TP=0 and FN=0 (no attack runs at all)."""
    report = _build_report(
        detector_name="test",
        tp=0, fp=0, fn=0, tn=2,
        n_attack=0, n_benign=2,
        mttd_values=[],
        total_benign_s=3600.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.tpr is None


def test_fpr_undefined_no_negatives():
    """FPR is None (undefined denominator) when FP=0 and TN=0 (no benign runs at all)."""
    report = _build_report(
        detector_name="test",
        tp=3, fp=0, fn=0, tn=0,
        n_attack=3, n_benign=0,
        mttd_values=[30.0, 45.0, 60.0],
        total_benign_s=0.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.fpr is None


def test_f1_undefined_all_zero():
    """F1 is None (undefined) when precision or recall is undefined or sum is zero."""
    report = _build_report(
        detector_name="test",
        tp=0, fp=0, fn=5, tn=5,
        n_attack=5, n_benign=5,
        mttd_values=[],
        total_benign_s=3600.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.f1 is None


def test_mttd_none_when_no_tp():
    """mttd_mean_s is None (not 0.0 or NaN) when there are no TP detections."""
    report = _build_report(
        detector_name="test",
        tp=0, fp=0, fn=5, tn=5,
        n_attack=5, n_benign=5,
        mttd_values=[],
        total_benign_s=3600.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.mttd_mean_s is None
    assert report.mttd_p50_s is None
    assert report.mttd_p95_s is None


# ===========================================================================
# Test 9 — Correct latency calculation from known timestamps
# ===========================================================================


def test_mttd_exact_from_known_timestamps():
    """MTTD is exactly the difference between detection and injection timestamps."""
    # Injection at T0+300, detection at T0+330 → MTTD = 30s
    result = _make_attack_result(
        mttd_s=30.0,
        injection_ts_delta_s=300.0,
        detection_ts_delta_s=330.0,
    )
    ev = _evaluator()
    reports = ev.evaluate([result], {})
    assert reports[0].mttd_mean_s == pytest.approx(30.0, abs=0.01)


def test_mttd_zero_edge():
    """MTTD = 0.0 is valid when detection equals injection timestamp."""
    result = _make_attack_result(
        mttd_s=0.0,
        injection_ts_delta_s=300.0,
        detection_ts_delta_s=300.0,  # simultaneous
    )
    result.mttd_s = 0.0
    ev = _evaluator()
    reports = ev.evaluate([result], {})
    assert reports[0].mttd_mean_s == pytest.approx(0.0, abs=0.01)


def test_mttd_excluded_outside_window():
    """
    A detection that arrives after the detection_window_s is NOT a TP.
    mttd_s should reflect only in-window detections.
    """
    # Detection window = 120s, injection at T0+300, detection at T0+600
    # delta = 300s > 120s → should be FN
    result = _make_attack_result(
        mttd_s=None,
        injection_ts_delta_s=300.0,
        detection_ts_delta_s=600.0,  # 300s after injection > 120s window
        is_tp=False,
    )
    result.is_true_positive = False
    result.first_phantom_detection_timestamp = None
    result.mttd_s = None
    ev = _evaluator()
    reports = ev.evaluate([result], {})
    assert reports[0].tp == 0
    assert reports[0].fn == 1
    assert reports[0].mttd_mean_s is None


# ===========================================================================
# Test 10 — Correct metric aggregation across multiple runs
# ===========================================================================


def test_multi_run_aggregation(tp_attack_result, fn_attack_result,
                               tn_benign_result, fp_benign_result):
    """
    Metrics are correctly aggregated across 4 runs:
      1 TP, 1 FN → TPR = 0.5
      1 TN, 1 FP → FPR = 0.5
    """
    results = [
        tp_attack_result,
        fn_attack_result,
        tn_benign_result,
        fp_benign_result,
    ]
    ev = _evaluator()
    reports = ev.evaluate(results, {})
    phantom = reports[0]

    assert phantom.tp == 1
    assert phantom.fn == 1
    assert phantom.tn == 1
    assert phantom.fp == 1
    assert phantom.tpr == pytest.approx(0.5)
    assert phantom.fpr == pytest.approx(0.5)
    assert phantom.n_attack_scenarios == 2
    assert phantom.n_benign_scenarios == 2


def test_multi_run_mttd_mean(tp_attack_result, fn_attack_result):
    """
    MTTD mean is computed only over TP runs (FN excluded).
    With one TP at 30s and one FN, mean = 30.0.
    """
    results = [tp_attack_result, fn_attack_result]
    ev = _evaluator()
    reports = ev.evaluate(results, {})
    assert reports[0].mttd_mean_s == pytest.approx(30.0, abs=0.01)
    assert reports[0].mttd_values_s == pytest.approx([30.0], abs=0.01)


def test_multi_run_mttd_distribution():
    """
    With 3 TP runs at 10s, 30s, 50s:
    - mean = 30.0
    - p50 = 30.0
    - p95 ≈ 48.0 (linear interpolation between 30 and 50)
    """
    mttd_values = [10.0, 30.0, 50.0]
    report = _build_report(
        detector_name="phantom",
        tp=3, fp=0, fn=0, tn=0,
        n_attack=3, n_benign=0,
        mttd_values=mttd_values,
        total_benign_s=0.0,
        cpu_overhead_pct=0.0,
        memory_overhead_mb=0.0,
        event_lag_p95_ms=0.0,
    )
    assert report.mttd_mean_s == pytest.approx(30.0, abs=0.01)
    assert report.mttd_p50_s == pytest.approx(30.0, abs=0.01)
    # p95 linear interpolation: rank = 0.95 * 2 = 1.9 → 30 + 0.9*(50-30) = 48
    assert report.mttd_p95_s == pytest.approx(48.0, abs=0.01)
    assert len(report.mttd_values_s) == 3


# ===========================================================================
# Helper function unit tests
# ===========================================================================


def test_safe_mean_empty():
    """_safe_mean([]) returns 0.0, not an error."""
    assert _safe_mean([]) == pytest.approx(0.0)


def test_safe_mean_values():
    """_safe_mean computes the arithmetic mean correctly."""
    assert _safe_mean([10.0, 20.0, 30.0]) == pytest.approx(20.0)


def test_safe_percentile_empty():
    """_safe_percentile([]) returns 0.0, not an error."""
    assert _safe_percentile([], 95) == pytest.approx(0.0)


def test_safe_percentile_single():
    """_safe_percentile of a single element at any quantile is that element."""
    assert _safe_percentile([42.0], 0) == pytest.approx(42.0)
    assert _safe_percentile([42.0], 50) == pytest.approx(42.0)
    assert _safe_percentile([42.0], 100) == pytest.approx(42.0)


def test_safe_percentile_median():
    """Median of [1, 2, 3] is 2."""
    assert _safe_percentile([1.0, 2.0, 3.0], 50) == pytest.approx(2.0)


# ===========================================================================
# Milestone 3 tests — Wilson Score, Bootstrap MTTD, Baselines & Overhead
# ===========================================================================


def test_evaluator_wilson_score_six_of_six():
    """Wilson score confidence interval for 6/6 TPR matches [0.6096, 1.0000]."""
    report = _build_report(
        detector_name="phantom",
        tp=6, fp=None, fn=0, tn=None,
        n_attack=6, n_benign=0,
        mttd_values=[10.0, 15.0, 20.0, 25.0, 30.0, 35.0],
        total_benign_s=0.0,
    )
    assert report.tpr == pytest.approx(1.0)
    assert report.tpr_ci_wilson is not None
    lower, upper = report.tpr_ci_wilson
    assert lower == pytest.approx(0.6096, abs=0.001)
    assert upper == pytest.approx(1.0, abs=0.001)


def test_evaluator_bootstrap_mttd_statistics():
    """MTTD reports mean, median, IQR, and non-parametric bootstrap CI."""
    latencies = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
    report = _build_report(
        detector_name="phantom",
        tp=6, fp=None, fn=0, tn=None,
        n_attack=6, n_benign=0,
        mttd_values=latencies,
        total_benign_s=0.0,
    )
    assert report.mttd_mean_s == pytest.approx(15.74, abs=0.1)
    assert report.mttd_median_s == pytest.approx(5.52, abs=0.1)
    assert report.mttd_iqr_s is not None
    assert report.mttd_iqr_s > 0.0
    assert report.mttd_ci_bootstrap is not None
    ci_low, ci_high = report.mttd_ci_bootstrap
    assert ci_low <= report.mttd_mean_s <= ci_high


def test_evaluator_baseline_telemetry_unavailable(tp_attack_result):
    """Empty baseline detections list is classified as telemetry_unavailable / NR."""
    ev = _evaluator()
    reports = ev.evaluate(
        scenario_results=[tp_attack_result],
        detections={"falco-default-rules": [], "trivy-sbom-static": []},
    )
    assert len(reports) == 3
    falco = next(r for r in reports if r.detector_name == "falco-default-rules")
    trivy = next(r for r in reports if r.detector_name == "trivy-sbom-static")

    assert falco.status == "telemetry_unavailable"
    assert falco.tpr is None
    assert falco.fn is None

    assert trivy.status == "task_mismatch_and_telemetry_unavailable"
    assert trivy.tpr is None


def test_evaluator_unmeasured_overhead(tp_attack_result):
    """Missing or all-zero Prometheus snapshots result in unmeasured overhead (None)."""
    # tp_attack_result has empty metrics_snapshots
    ev = _evaluator()
    reports = ev.evaluate([tp_attack_result], {})
    phantom = reports[0]
    assert phantom.overhead_status == "unmeasured"
    assert phantom.cpu_overhead_pct is None
    assert phantom.memory_overhead_mb is None
    assert phantom.event_lag_p95_ms is None
