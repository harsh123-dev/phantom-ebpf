"""
research/evaluation/tests/conftest.py

Shared pytest fixtures for PHANTOM evaluation unit tests.

ALL FIXTURES IN THIS FILE ARE SYNTHETIC.
They are constructed to exercise specific code paths and do NOT represent
any real experimental measurement. They must never be mixed with real
results from research/datasets/.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure repo root is on sys.path so `research.*` imports resolve.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.baselines.base_baseline import Detection
from research.evaluation.scenarios.scenario_runner import (
    MetricsSnapshot,
    PhaseRecord,
    ScenarioResult,
)


# ---------------------------------------------------------------------------
# Wall-clock helpers
# ---------------------------------------------------------------------------

def _utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0,
         second: int = 0) -> datetime:
    """Return a timezone-aware UTC datetime (synthetic timestamps only)."""
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


# Synthetic epoch for all fixtures: 2000-01-01T00:00:00Z
_T0 = _utc(2000, 1, 1, 0, 0, 0)


def _t(delta_s: float) -> datetime:
    """Return _T0 + delta_s seconds (used to build synthetic phase windows)."""
    from datetime import timedelta
    return _T0 + timedelta(seconds=delta_s)


# ---------------------------------------------------------------------------
# Synthetic ScenarioResult builders
# ---------------------------------------------------------------------------


def _make_attack_result(
    attack_id: str = "xzutils-001",
    run_id: str = "SYNTHETIC_xzutils-001_rep1",
    repetition: int = 1,
    is_tp: bool = True,
    mttd_s: float | None = 30.0,
    phantom_detections: list | None = None,
    error: str = "",
    injection_ts_delta_s: float = 300.0,   # injection at T0 + 300s
    detection_ts_delta_s: float | None = 330.0,  # detected at T0 + 330s
    scenario_label: dict | None = None,
) -> ScenarioResult:
    """
    Build a SYNTHETIC attack ScenarioResult.

    All timestamps are synthetic (anchored to 2000-01-01).
    Never use these for reporting real experimental results.
    """
    injection_ts = _t(injection_ts_delta_s)
    detect_ts = _t(detection_ts_delta_s) if detection_ts_delta_s is not None else None

    # Baseline phase: T0 → T0+300s
    baseline = PhaseRecord(name="baseline", start_time=_T0, end_time=_t(300))
    baseline.duration_s = 300.0

    # Inject phase: T0+300s → T0+301s
    inject = PhaseRecord(name="inject", start_time=_t(300), end_time=_t(301))
    inject.duration_s = 1.0

    # Attack observation: T0+301s → T0+601s
    attack_phase = PhaseRecord(name="attack", start_time=_t(301), end_time=_t(601))
    attack_phase.duration_s = 300.0

    # Post-recovery: T0+601s → T0+721s
    post = PhaseRecord(name="post_recovery", start_time=_t(601), end_time=_t(721))
    post.duration_s = 120.0

    label = scenario_label or {
        "attack_id": attack_id,
        "attack_family": "supply_chain_backdoor",
        "target_purl": "pkg:pypi/lzmaffi@1.0.1-phantom-backdoor",
        "label": 1,
        "detection_window_s": 120.0,
    }

    dets: list[dict] = phantom_detections if phantom_detections is not None else []
    if is_tp and detect_ts is not None and not dets:
        dets = [{
            "drift_event_id": "aaa00000-0000-0000-0000-000000000001",
            "observed_at": detect_ts.isoformat(),
            "event_type": "unexpected_process_spawn",
        }]

    r = ScenarioResult(
        run_id=run_id,
        attack_id=attack_id,
        attack_family="supply_chain_backdoor",
        repetition=repetition,
        namespace="phantom-eval",
        pod_name="recommendationservice-abc12",
        ground_truth_label=1,
        injection_timestamp=injection_ts,
        first_phantom_detection_timestamp=detect_ts,
        mttd_s=mttd_s if is_tp else None,
        is_true_positive=is_tp,
        phases=[baseline, inject, attack_phase, post],
        phantom_detections=dets,
        scenario_label=label,
        error=error,
    )
    return r


def _make_benign_result(
    attack_id: str = "benign-load-001",
    run_id: str = "SYNTHETIC_benign-load-001_rep1",
    repetition: int = 1,
    phantom_detections: list | None = None,
    error: str = "",
) -> ScenarioResult:
    """
    Build a SYNTHETIC benign ScenarioResult.

    All timestamps are synthetic (anchored to 2000-01-01).
    Never use these for reporting real experimental results.
    """
    baseline = PhaseRecord(name="baseline", start_time=_T0, end_time=_t(300))
    baseline.duration_s = 300.0
    inject = PhaseRecord(name="inject", start_time=_t(300), end_time=_t(301))
    inject.duration_s = 1.0
    attack_phase = PhaseRecord(name="attack", start_time=_t(301), end_time=_t(601))
    attack_phase.duration_s = 300.0
    post = PhaseRecord(name="post_recovery", start_time=_t(601), end_time=_t(721))
    post.duration_s = 120.0

    label = {
        "attack_id": attack_id,
        "attack_family": "high_load",
        "label": 0,
        "detection_window_s": 120.0,
    }

    return ScenarioResult(
        run_id=run_id,
        attack_id=attack_id,
        attack_family="high_load",
        repetition=repetition,
        namespace="phantom-eval",
        pod_name="recommendationservice-abc12",
        ground_truth_label=0,
        injection_timestamp=None,
        first_phantom_detection_timestamp=None,
        mttd_s=None,
        is_true_positive=False,
        phases=[baseline, inject, attack_phase, post],
        phantom_detections=phantom_detections or [],
        scenario_label=label,
        error=error,
    )


def _make_detection(
    detected_at: datetime,
    scenario_id: str = "",
    detector: str = "phantom",
    confidence: float = 0.9,
) -> Detection:
    """Build a SYNTHETIC Detection object."""
    return Detection(
        detected_at=detected_at,
        scenario_id=scenario_id,
        detector_name=detector,
        confidence=confidence,
        raw_alert={},
        rule_name="",
        namespace="phantom-eval",
        pod_name="recommendationservice-abc12",
        service_name="recommendationservice",
    )


def _make_metrics_snapshot(phase: str, cpu: float = 0.01, mem: float = 20.0,
                           lag: float = 5.0) -> MetricsSnapshot:
    """Build a SYNTHETIC MetricsSnapshot."""
    return MetricsSnapshot(
        timestamp=_T0,
        cpu_usage_cores=cpu,
        memory_rss_mb=mem,
        event_lag_p95_ms=lag,
        phase=phase,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tp_attack_result():
    """SYNTHETIC: one attack run that was a true positive (MTTD=30s)."""
    return _make_attack_result(is_tp=True, mttd_s=30.0, detection_ts_delta_s=330.0)


@pytest.fixture
def fn_attack_result():
    """SYNTHETIC: one attack run that was a false negative (not detected)."""
    return _make_attack_result(
        run_id="SYNTHETIC_xzutils-001_rep2",
        repetition=2,
        is_tp=False,
        mttd_s=None,
        detection_ts_delta_s=None,
        phantom_detections=[],
    )


@pytest.fixture
def tn_benign_result():
    """SYNTHETIC: one benign run with no false alarms (true negative)."""
    return _make_benign_result(phantom_detections=[])


@pytest.fixture
def fp_benign_result():
    """SYNTHETIC: one benign run that produced a phantom detection (false positive)."""
    return _make_benign_result(
        run_id="SYNTHETIC_benign-load-001_rep2",
        repetition=2,
        phantom_detections=[{
            "drift_event_id": "bbb00000-0000-0000-0000-000000000001",
            "observed_at": _t(400).isoformat(),
            "event_type": "unexpected_process_spawn",
        }],
    )


@pytest.fixture
def failed_result():
    """SYNTHETIC: one run that failed during injection."""
    r = _make_attack_result(
        run_id="FAILED_xzutils-001_rep1",
        is_tp=False,
        mttd_s=None,
        detection_ts_delta_s=None,
        error="inject() raised RuntimeError: kubectl exec timeout",
    )
    r.injection_timestamp = None
    r.phantom_detections = []
    return r


@pytest.fixture
def multi_alert_result():
    """
    SYNTHETIC: one attack run where PHANTOM fired 3 alerts.
    Only the first alert within the detection window counts as the TP.
    """
    dets = [
        {
            "drift_event_id": f"ccc{i:013d}",
            "observed_at": _t(330 + i * 10).isoformat(),
            "event_type": "unexpected_process_spawn",
        }
        for i in range(3)
    ]
    r = _make_attack_result(
        run_id="SYNTHETIC_xzutils-001_multi",
        is_tp=True,
        mttd_s=30.0,  # first alert at T0+330 → injection at T0+300 → 30s
        detection_ts_delta_s=330.0,
        phantom_detections=dets,
    )
    return r


@pytest.fixture
def missing_timestamps_result():
    """
    SYNTHETIC: one attack run where injection_timestamp is None.
    Models a scenario that aborted before injection (incomplete run).
    """
    r = _make_attack_result(
        run_id="SYNTHETIC_xzutils-001_no_ts",
        is_tp=False,
        mttd_s=None,
        detection_ts_delta_s=None,
    )
    r.injection_timestamp = None
    return r
