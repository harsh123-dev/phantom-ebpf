"""The live runner must not turn planned labels into observed confusion counts."""

from research.evaluation.scenarios.run_all_scenarios import (
    _direct_behavior_assertion,
    _print_summary,
)
from research.evaluation.scenarios.scenario_runner import ScenarioResult


def _result(label: int, *, alerted: bool, failed: bool = False) -> ScenarioResult:
    return ScenarioResult(
        run_id=f"summary-{label}-{alerted}-{failed}",
        attack_id="attack" if label else "control",
        attack_family="test",
        repetition=1,
        namespace="phantom-eval",
        pod_name="test-pod",
        ground_truth_label=label,
        inject_ok=not failed,
        error="injection failed" if failed else "",
        phantom_detections=[{"id": "alert"}] if alerted else [],
        is_true_positive=alerted and bool(label),
        scenario_label={"ground_truth_status": "unknown_contract_state"},
    )


def test_summary_preserves_unknown_ground_truth_despite_planned_label_and_alert(capsys):
    _print_summary([
        _result(1, alerted=True),
        _result(1, alerted=False),
        _result(0, alerted=False),
        _result(0, alerted=True),
        _result(1, alerted=False, failed=True),
    ])
    output = capsys.readouterr().out
    assert output.count("UNKNOWN") == 4
    assert "FAILED" in output
    assert "ground_truth_unknown=4" in output
    assert "alerted=2" in output
    for unsupported in ("TP=", "FP=", "TN=", "FN=", "mean_MTTD="):
        assert unsupported not in output


def test_direct_harness_assertion_does_not_use_detector_alerts_or_claim_contract_truth():
    with_alert = _result(1, alerted=True)
    without_alert = _result(1, alerted=False)
    with_alert.behavior_verified = True
    without_alert.behavior_verified = True
    assert _direct_behavior_assertion(with_alert) == _direct_behavior_assertion(without_alert)
    observation = _direct_behavior_assertion(with_alert)
    assert observation["behavior_assertion"] == "confirmed"
    assert observation["contract_outcome"] == "unknown"
    assert observation["event_correlation"] == "unavailable"
