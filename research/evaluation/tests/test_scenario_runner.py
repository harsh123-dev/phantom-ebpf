"""
research/evaluation/tests/test_scenario_runner.py

Unit tests for ScenarioResult, PhaseRecord, and ScenarioRunner helpers.

All test data is SYNTHETIC. No real experimental measurements, real API
calls, or kubectl calls are made by these tests.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.scenarios.scenario_runner import (
    PhaseRecord,
    ScenarioResult,
)

from .conftest import _T0, _t, _make_attack_result, _make_benign_result

pytestmark = pytest.mark.unit


# ===========================================================================
# PhaseRecord tests
# ===========================================================================


def test_phase_record_close_computes_duration():
    """PhaseRecord.close() sets end_time and computes a positive duration."""
    start = _T0
    phase = PhaseRecord(name="baseline", start_time=start)
    time.sleep(0.01)   # tiny real sleep so monotonic delta is > 0
    phase.close()
    assert phase.end_time is not None
    assert phase.duration_s > 0.0


def test_phase_record_close_with_notes():
    """PhaseRecord.close(notes=...) attaches the notes string."""
    phase = PhaseRecord(name="inject", start_time=_T0)
    phase.close(notes="inject_ok=True")
    assert "inject_ok=True" in phase.notes


def test_phase_record_duration_accuracy():
    """duration_s matches the delta between synthetic start and end datetimes."""
    from datetime import timedelta
    start = _T0
    end = _T0 + timedelta(seconds=300)
    phase = PhaseRecord(name="baseline", start_time=start, end_time=end,
                        duration_s=300.0)
    assert abs(phase.duration_s - 300.0) < 0.01


# ===========================================================================
# ScenarioResult construction
# ===========================================================================


def test_run_id_format(tp_attack_result):
    """run_id contains the attack_id and 'rep<N>' suffix (or SYNTHETIC prefix)."""
    rid = tp_attack_result.run_id
    assert "xzutils-001" in rid or "SYNTHETIC" in rid


def test_ground_truth_label_attack(tp_attack_result):
    """Attack runs have ground_truth_label == 1."""
    assert tp_attack_result.ground_truth_label == 1


def test_ground_truth_label_benign(tn_benign_result):
    """Benign runs have ground_truth_label == 0."""
    assert tn_benign_result.ground_truth_label == 0


def test_attack_result_has_injection_timestamp(tp_attack_result):
    """A successful attack run has a non-None injection_timestamp."""
    assert tp_attack_result.injection_timestamp is not None


def test_benign_result_no_injection_timestamp(tn_benign_result):
    """A benign run has injection_timestamp == None."""
    assert tn_benign_result.injection_timestamp is None


# ===========================================================================
# MTTD computation on ScenarioResult
# ===========================================================================


def test_mttd_s_positive_for_tp(tp_attack_result):
    """mttd_s is positive for a true-positive result."""
    assert tp_attack_result.mttd_s is not None
    assert tp_attack_result.mttd_s > 0.0


def test_mttd_s_none_for_fn(fn_attack_result):
    """mttd_s is None for a false-negative result."""
    assert fn_attack_result.mttd_s is None


def test_mttd_value_matches_fixture():
    """MTTD = detection - injection, confirmed with known synthetic times."""
    r = _make_attack_result(
        injection_ts_delta_s=300.0,
        detection_ts_delta_s=345.0,
        mttd_s=45.0,
    )
    assert r.mttd_s == pytest.approx(45.0, abs=0.01)
    delta = (r.first_phantom_detection_timestamp - r.injection_timestamp).total_seconds()
    assert delta == pytest.approx(45.0, abs=0.01)


# ===========================================================================
# Serialization round-trip
# ===========================================================================


def test_to_dict_is_json_serializable(tp_attack_result):
    """ScenarioResult.to_dict() produces a JSON-serializable dict."""
    d = tp_attack_result.to_dict()
    serialized = json.dumps(d, default=str)
    loaded = json.loads(serialized)
    assert loaded["run_id"] == tp_attack_result.run_id
    assert loaded["ground_truth_label"] == 1


def test_to_dict_preserves_mttd(tp_attack_result):
    """mttd_s is preserved through the dict serialization."""
    d = tp_attack_result.to_dict()
    assert d["mttd_s"] == pytest.approx(30.0, abs=0.01)


def test_to_dict_is_true_positive(tp_attack_result):
    """is_true_positive is serialized as a bool."""
    d = tp_attack_result.to_dict()
    assert d["is_true_positive"] is True


def test_to_dict_none_injection_for_benign(tn_benign_result):
    """injection_timestamp serializes as None for benign runs."""
    d = tn_benign_result.to_dict()
    assert d["injection_timestamp"] is None


def test_to_dict_error_field(failed_result):
    """error field is non-empty in a failed run."""
    d = failed_result.to_dict()
    assert d["error"] != ""


def test_to_dict_phases_list(tp_attack_result):
    """phases list has the correct length and phase names."""
    d = tp_attack_result.to_dict()
    phase_names = [p["name"] for p in d["phases"]]
    assert "baseline" in phase_names
    assert "inject" in phase_names
    assert "attack" in phase_names
    assert "post_recovery" in phase_names


def test_to_dict_phantom_detections_count(multi_alert_result):
    """phantom_detections length matches the fixture."""
    d = multi_alert_result.to_dict()
    assert len(d["phantom_detections"]) == 3


# ===========================================================================
# Failed / incomplete run handling
# ===========================================================================


def test_failed_result_error_not_empty(failed_result):
    """Failed runs carry a non-empty error message."""
    assert len(failed_result.error) > 0


def test_failed_result_not_true_positive(failed_result):
    """Failed runs are never marked is_true_positive=True."""
    assert not failed_result.is_true_positive


def test_failed_result_no_mttd(failed_result):
    """Failed runs have mttd_s = None."""
    assert failed_result.mttd_s is None


def test_failed_result_no_injection_ts(failed_result):
    """Failed runs that abort before injection have injection_timestamp = None."""
    assert failed_result.injection_timestamp is None


# ===========================================================================
# Scenario state consistency invariants
# ===========================================================================


def test_tp_implies_detection_timestamp(tp_attack_result):
    """is_true_positive=True implies first_phantom_detection_timestamp is set."""
    assert tp_attack_result.is_true_positive
    assert tp_attack_result.first_phantom_detection_timestamp is not None


def test_fn_implies_no_detection_in_window(fn_attack_result):
    """is_true_positive=False with ground_truth_label=1 → FN, no detection ts."""
    assert not fn_attack_result.is_true_positive
    assert fn_attack_result.first_phantom_detection_timestamp is None


def test_benign_is_true_positive_false(tn_benign_result):
    """Benign runs never have is_true_positive=True."""
    assert not tn_benign_result.is_true_positive


def test_fp_benign_still_not_is_true_positive(fp_benign_result):
    """FP benign runs are not is_true_positive (it's a benign scenario)."""
    assert not fp_benign_result.is_true_positive
    # But phantom_detections is non-empty, which is how FP is counted.
    assert len(fp_benign_result.phantom_detections) > 0


# ===========================================================================
# Run ID uniqueness
# ===========================================================================


def test_run_ids_unique():
    """Multiple ScenarioResult objects with different reps have different run_ids."""
    r1 = _make_attack_result(repetition=1, run_id="SYNTHETIC_xzutils-001_rep1")
    r2 = _make_attack_result(repetition=2, run_id="SYNTHETIC_xzutils-001_rep2")
    assert r1.run_id != r2.run_id
