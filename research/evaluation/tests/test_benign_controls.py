"""Offline unit tests for benign control command boundaries and receipts."""

import json
import subprocess

from research.evaluation.attacks.base_attack import AttackManifest
from research.evaluation.attacks.benign_controls import BenignLoadControl


def _manifest():
    return AttackManifest(
        attack_id="benign-load-001", attack_family="high_load",
        target_service="emailservice", target_image="", target_component_purl="",
        clean_component_purl="", injection_time_offset_s=0,
        expected_behavioral_changes=[], ground_truth_label=0, control_endpoint="",
        recovery_steps=[],
    )


def test_benign_load_is_bounded_to_internal_target_and_requires_log_receipt(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "exec" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"requests": 200, "successes": 200, "token": control.run_token}), "")
        return subprocess.CompletedProcess(command, 0, f"GET /?phantom_control={control.run_token} 200", "")

    control = BenignLoadControl(_manifest(), kubectl_context="phantom-lab", dry_run=False, allow_live_execution=True)
    monkeypatch.setattr("research.evaluation.attacks.benign_controls.subprocess.run", fake_run)
    assert control.inject("phantom-eval", "emailservice-pod")
    assert control.verify_injection("phantom-eval", "emailservice-pod")
    command = calls[0]
    assert command[:4] == ["kubectl", "--context", "phantom-lab", "exec"]
    script_arg = command.index("-c") + 1
    assert command[script_arg + 1:script_arg + 3] == ["emailservice", "phantom-eval"]
    assert "{host}.{ns}.svc.cluster.local" in command[script_arg]
    assert "200" in command[-1]
    assert control.evidence()["server_access_log_token_seen"] is True
