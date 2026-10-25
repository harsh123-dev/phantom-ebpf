"""
research/evaluation/tests/test_attack_safety_and_config.py

Unit tests for scenario safety preflight gates, dry-run defaults,
oracle manifest schemas, and decoupled ground-truth dimensions.

All tests run in-memory without contacting a live Kubernetes cluster or network sinks.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.file_tamper_style import FileTamperAttack
from research.evaluation.attacks.net_egress_style import NetEgressAttack
from research.evaluation.attacks.proc_spawn_style import ProcSpawnAttack
from research.evaluation.attacks.safety import (
    ALLOWLISTED_NAMESPACES,
    ALLOWLISTED_SERVICES,
    ALLOWLISTED_SINK_HOSTS,
    ALLOWLISTED_SINK_PORTS,
    APPROVED_DISPOSABLE_CONTEXTS,
    DRY_RUN_ALLOWLISTED_SINK_HOSTS,
    LIVE_ALLOWLISTED_SINK_HOSTS,
    SCENARIO_SINK_PORTS,
    SafetyCheckError,
    SafetyPreflight,
)
from research.evaluation.attacks.solarwinds_style import SolarWindsStyleAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack
from research.evaluation.metrics.evaluator import is_failed_injection
from research.evaluation.scenarios.run_all_scenarios import (
    DEFAULT_PILOT_DIR,
    EXTENDED_SCENARIO_IDS,
    PILOT_SCENARIO_IDS,
)
from research.evaluation.scenarios.scenario_runner import ScenarioResult, ScenarioRunner

pytestmark = pytest.mark.unit


# ===========================================================================
# 1. SafetyPreflight Validation Tests
# ===========================================================================


def test_safety_preflight_allowed_namespace():
    """Allowlisted namespace phantom-eval passes safety check."""
    SafetyPreflight.check_namespace("phantom-eval")


@pytest.mark.parametrize("invalid_ns", ["default", "kube-system", "production", "prod", "test"])
def test_safety_preflight_disallowed_namespaces(invalid_ns: str):
    """Non-allowlisted namespaces raise SafetyCheckError."""
    with pytest.raises(SafetyCheckError, match="not allowlisted"):
        SafetyPreflight.check_namespace(invalid_ns)


@pytest.mark.parametrize("svc", ["recommendationservice", "emailservice", "cartservice"])
def test_safety_preflight_allowed_services(svc: str):
    """Allowlisted services pass safety check."""
    SafetyPreflight.check_service(svc)


@pytest.mark.parametrize("invalid_svc", ["authservice", "frontend", "paymentservice", "randomservice"])
def test_safety_preflight_disallowed_services(invalid_svc: str):
    """Non-allowlisted services raise SafetyCheckError."""
    with pytest.raises(SafetyCheckError, match="not allowlisted"):
        SafetyPreflight.check_service(invalid_svc)


@pytest.mark.parametrize(
    "endpoint",
    [
        "phantom-sink.phantom-eval.svc.cluster.local:8443",
        "phantom-sink.phantom-eval.svc.cluster.local:4445",
        "phantom-sink.phantom-eval.svc.cluster.local:4446",
        "phantom-sink.phantom-eval.svc.cluster.local:8080",
        "phantom-sink:8443",
        "127.0.0.1:8080",
        "localhost:8443",
    ],
)
def test_safety_preflight_allowed_control_endpoints(endpoint: str):
    """Cluster-internal allowlisted control endpoints pass safety check."""
    SafetyPreflight.check_control_endpoint(endpoint)


@pytest.mark.parametrize(
    "invalid_endpoint",
    [
        "external-sink.com:8443",
        "192.168.1.1:8443",
        "phantom-sink.phantom-eval.svc.cluster.local:9999",  # disallowed port
        "phantom-sink.phantom-eval.svc.cluster.local",       # missing port
        "evil.attacker.io:4445",
    ],
)
def test_safety_preflight_disallowed_control_endpoints(invalid_endpoint: str):
    """External or unauthorized control endpoints raise SafetyCheckError."""
    with pytest.raises(SafetyCheckError, match="Safety violation"):
        SafetyPreflight.check_control_endpoint(invalid_endpoint)


def test_safety_preflight_empty_endpoint_allowed_for_benign():
    """Empty control endpoint passes safety check (for benign scenarios)."""
    SafetyPreflight.check_control_endpoint("")


def test_safety_preflight_live_mode_rejects_loopback():
    """In live cluster execution mode (dry_run=False), loopback endpoints (127.0.0.1, localhost) must be rejected."""
    with pytest.raises(SafetyCheckError, match="Loopback sink '127.0.0.1' is disallowed in live cluster mode"):
        SafetyPreflight.check_control_endpoint("127.0.0.1:8080", dry_run=False)

    with pytest.raises(SafetyCheckError, match="Loopback sink 'localhost' is disallowed in live cluster mode"):
        SafetyPreflight.check_control_endpoint("localhost:8443", dry_run=False)


def test_safety_preflight_live_mode_allowed_cluster_sink():
    """In live cluster mode, approved cluster-internal sink passes with matched port."""
    SafetyPreflight.check_control_endpoint(
        "phantom-sink.phantom-eval.svc.cluster.local:8443",
        dry_run=False,
        scenario_id="xzutils-001",
    )


@pytest.mark.parametrize(
    "scenario_id,port,valid",
    [
        ("xzutils-001", 8443, True),
        ("xzutils-001", 8080, False),
        ("dep-confusion-001", 4445, True),
        ("dep-confusion-001", 8443, False),
        ("solarwinds-001", 4446, True),
        ("solarwinds-001", 4445, False),
        ("proc-spawn-001", 8080, True),
        ("proc-spawn-001", 8443, False),
        ("net-egress-001", 8080, True),
        ("file-tamper-001", 8080, True),
    ],
)
def test_safety_preflight_scenario_port_enforcement(scenario_id: str, port: int, valid: bool):
    """Live mode strictly enforces scenario-specific sink ports."""
    endpoint = f"phantom-sink.phantom-eval.svc.cluster.local:{port}"
    if valid:
        SafetyPreflight.check_control_endpoint(endpoint, dry_run=False, scenario_id=scenario_id)
    else:
        with pytest.raises(SafetyCheckError, match="does not match the designated scenario sink port"):
            SafetyPreflight.check_control_endpoint(endpoint, dry_run=False, scenario_id=scenario_id)


@pytest.mark.parametrize(
    "live_ctx",
    [
        "minikube",
        "kind-phantom-eval",
        "kind-kind",
        "docker-desktop",
        "phantom-eval-cluster",
        "phantom-lab",
        "disposable-lab",
    ],
)
def test_safety_preflight_live_mode_approved_contexts(live_ctx: str):
    """Positively identified disposable lab contexts pass in live mode."""
    SafetyPreflight.check_context(live_ctx, dry_run=False)


@pytest.mark.parametrize(
    "unapproved_ctx",
    [
        "corp-workload",
        "random-cluster-01",
        "staging-cluster",
        "eks-main",
        "vprofile-eks-cluster",  # Stale deprovisioned context
        "phantom-dev",           # Stale deprovisioned context
    ],
)
def test_safety_preflight_live_mode_unapproved_contexts_rejected(unapproved_ctx: str):
    """Unapproved or stale contexts raise SafetyCheckError in live mode."""
    with pytest.raises(SafetyCheckError):
        SafetyPreflight.check_context(unapproved_ctx, dry_run=False)


@pytest.mark.parametrize(
    "valid_endpoint",
    [
        "https://127.0.0.1:6443",
        "http://localhost:8080",
        "https://192.168.49.2:8443",
        "https://10.96.0.1:443",
        "https://172.20.0.1:6443",
        "https://cluster.phantom.lab:6443",
        "https://kubernetes.default.svc.cluster.local:443",
    ],
)
def test_safety_preflight_cluster_endpoint_valid(valid_endpoint: str):
    """Valid disposable lab cluster endpoints pass validation."""
    SafetyPreflight.check_cluster_endpoint(valid_endpoint)


@pytest.mark.parametrize(
    "invalid_endpoint",
    [
        "https://7E0F663798A2EBCCF3106687373F3754.yl4.ap-south-1.eks.amazonaws.com",
        "https://my-aks-cluster.azmk8s.io:443",
        "https://gke-prod-cluster.container.googleapis.com",
        "https://1.2.3.4:6443",
        "https://external-unknown-cloud.com:6443",
        "",
    ],
)
def test_safety_preflight_cluster_endpoint_rejected(invalid_endpoint: str):
    """Cloud provider or unapproved cluster endpoints raise SafetyCheckError."""
    with pytest.raises(SafetyCheckError):
        SafetyPreflight.check_cluster_endpoint(invalid_endpoint)


def test_safety_preflight_verify_live_cluster_readiness_offline_fails_closed():
    """Live cluster verification must fail closed when cluster is offline or unreachable."""
    with pytest.raises(SafetyCheckError):
        SafetyPreflight.verify_live_cluster_readiness(
            context="non-existent-or-offline-context",
            timeout=1,
        )


def test_safety_preflight_live_mode_missing_context_rejected():
    """Missing context in live execution mode raises SafetyCheckError."""
    with pytest.raises(SafetyCheckError, match="explicit kubectl context must be provided"):
        SafetyPreflight.check_context(None, dry_run=False)


@pytest.mark.parametrize(
    "ctx",
    [
        "arn:aws:eks:ap-south-1:123456789012:cluster/prod-cluster",
        "vprofile-production",
        "my-live-cluster",
    ],
)
def test_safety_preflight_disallowed_contexts(ctx: str):
    """Kubectl context with production keywords raises SafetyCheckError."""
    with pytest.raises(SafetyCheckError, match="forbidden keyword"):
        SafetyPreflight.check_context(ctx)


@pytest.mark.parametrize("safe_ctx", ["minikube", "kind-phantom-eval", "lab-dev-cluster", None])
def test_safety_preflight_safe_contexts(safe_ctx: str | None):
    """Non-production kubectl contexts pass safety check."""
    SafetyPreflight.check_context(safe_ctx)


def test_safety_preflight_execution_permission():
    """Live execution without explicit confirmation raises SafetyCheckError."""
    # dry_run=True is always permitted
    SafetyPreflight.check_execution_permission(dry_run=True, allow_live_execution=False)
    SafetyPreflight.check_execution_permission(dry_run=True, allow_live_execution=True)

    # dry_run=False requires allow_live_execution=True
    SafetyPreflight.check_execution_permission(dry_run=False, allow_live_execution=True)

    with pytest.raises(SafetyCheckError, match="Live execution requested"):
        SafetyPreflight.check_execution_permission(dry_run=False, allow_live_execution=False)


# ===========================================================================
# 2. Attack Class Defaults & Dry-Run Behavior
# ===========================================================================


@pytest.mark.parametrize(
    "attack_cls",
    [
        XZUtilsStyleAttack,
        DependencyConfusionAttack,
        SolarWindsStyleAttack,
        ProcSpawnAttack,
        NetEgressAttack,
        FileTamperAttack,
    ],
)
def test_attack_classes_default_to_dry_run(attack_cls: type[BaseAttack]):
    """All attack classes must instantiate with dry_run=True by default."""
    attack = attack_cls()
    assert attack.dry_run is True
    assert attack.allow_live_execution is False


@pytest.mark.parametrize(
    "attack_cls,ns,pod",
    [
        (XZUtilsStyleAttack, "phantom-eval", "rec-pod-0"),
        (DependencyConfusionAttack, "phantom-eval", "email-pod-0"),
        (SolarWindsStyleAttack, "phantom-eval", "cart-pod-0"),
        (ProcSpawnAttack, "phantom-eval", "rec-pod-0"),
        (NetEgressAttack, "phantom-eval", "cart-pod-0"),
        (FileTamperAttack, "phantom-eval", "rec-pod-0"),
    ],
)
def test_attack_classes_dry_run_execution(attack_cls: type[BaseAttack], ns: str, pod: str):
    """In dry_run mode, inject, verify_injection, and recover execute safely without cluster calls."""
    attack = attack_cls(dry_run=True)
    assert attack.inject(ns, pod) is True
    assert attack.verify_injection(ns, pod) is True
    assert attack.recover(ns, pod) is True


def test_attack_class_enforces_safety_validation():
    """Attack classes reject non-allowlisted target namespaces even in dry-run mode."""
    attack = XZUtilsStyleAttack(dry_run=True)
    with pytest.raises(SafetyCheckError, match="namespace 'kube-system' is not allowlisted"):
        attack.inject("kube-system", "rec-pod-0")


# ===========================================================================
# 3. Oracle Manifest Validation
# ===========================================================================


def test_oracle_manifest_files_exist_and_validate():
    """All oracle YAML files must exist and parse into valid AttackManifest objects."""
    oracle_dir = _REPO_ROOT / "research" / "evaluation" / "oracles"
    assert oracle_dir.exists(), "Oracle directory missing"

    yaml_files = list(oracle_dir.glob("*.yaml")) + list((oracle_dir / "variants").glob("*.yaml"))
    assert len(yaml_files) >= 9, f"Expected at least 9 oracle files, found {len(yaml_files)}"

    for yf in yaml_files:
        with yf.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        # Validate core fields
        assert "attack_id" in data
        assert "attack_family" in data
        assert "target_service" in data
        assert "ground_truth_label" in data
        assert data["ground_truth_label"] in (0, 1)
        assert isinstance(data["expected_behavioral_changes"], list)
        assert "recovery_steps" in data

        # Check endpoint safety for attacks
        if data["ground_truth_label"] == 1:
            SafetyPreflight.check_control_endpoint(data["control_endpoint"])
            SafetyPreflight.check_service(data["target_service"])


# ===========================================================================
# 4. Decoupled Ground-Truth Dimensions
# ===========================================================================


def test_decoupled_ground_truth_labels_in_manifest():
    """Attack.label() emits decoupled ground truth dimension keys."""
    attack = XZUtilsStyleAttack(dry_run=True)
    lbl = attack.label(
        inject_ok=True,
        behavior_verified=True,
        contract_drift_verified=True,
        phantom_alerted=False,
    )

    assert lbl["inject_ok"] is True
    assert lbl["behavior_verified"] is True
    assert lbl["contract_drift_verified"] is True
    assert lbl["phantom_alerted"] is False
    assert lbl["label"] == 1


def test_scenario_result_decoupled_ground_truth_dimensions():
    """ScenarioResult preserves decoupled dimensions across serialization."""
    res = ScenarioResult(
        run_id="TEST_RUN_001",
        attack_id="proc-spawn-001",
        attack_family="unauthorized_process",
        repetition=1,
        namespace="phantom-eval",
        pod_name="dry-run-pod",
        ground_truth_label=1,
        inject_ok=True,
        behavior_verified=True,
        contract_drift_verified=True,
        phantom_alerted=False,
    )

    d = res.to_dict()
    assert d["inject_ok"] is True
    assert d["behavior_verified"] is True
    assert d["contract_drift_verified"] is True
    assert d["phantom_alerted"] is False


def test_failed_injection_exclusion_semantics():
    """When inject_ok is False, is_failed_injection identifies the run for exclusion."""
    res_failed = ScenarioResult(
        run_id="FAILED_RUN_001",
        attack_id="xzutils-001",
        attack_family="supply_chain_backdoor",
        repetition=1,
        namespace="phantom-eval",
        pod_name="dry-run-pod",
        ground_truth_label=1,
        inject_ok=False,
        error="inject() returned False",
    )
    assert is_failed_injection(res_failed) is True

    res_ok = ScenarioResult(
        run_id="OK_RUN_001",
        attack_id="xzutils-001",
        attack_family="supply_chain_backdoor",
        repetition=1,
        namespace="phantom-eval",
        pod_name="dry-run-pod",
        ground_truth_label=1,
        inject_ok=True,
        error="",
    )
    assert is_failed_injection(res_ok) is False


def test_scenario_runner_dry_run_defaults():
    """ScenarioRunner defaults to dry_run=True and passes safety check in dry-run mode."""
    runner = ScenarioRunner()
    assert runner._dry_run is True
    assert runner._allow_live_execution is False

    attack = ProcSpawnAttack(dry_run=True)
    res = runner.run_scenario(
        attack=attack,
        namespace="phantom-eval",
        pod_name="test-pod",
        baseline_duration_s=0,
        attack_duration_s=0,
        recovery_duration_s=0,
    )
    assert res.inject_ok is True
    assert res.attack_id == "proc-spawn-001"


# ===========================================================================
# 5. Campaign Selection and Planned Run Counts
# ===========================================================================


def test_pilot_campaign_scenario_count_and_reconciliation():
    """Pilot campaign specifies exactly 6 scenarios (3 attacks + 3 benign controls = 18 runs with 3 repetitions)."""
    assert len(PILOT_SCENARIO_IDS) == 6
    assert "xzutils-001" in PILOT_SCENARIO_IDS
    assert "dep-confusion-001" in PILOT_SCENARIO_IDS
    assert "solarwinds-001" in PILOT_SCENARIO_IDS
    assert "benign-update-001" in PILOT_SCENARIO_IDS
    assert "benign-load-001" in PILOT_SCENARIO_IDS
    assert "benign-restart-001" in PILOT_SCENARIO_IDS

    # 6 scenarios * 3 repetitions = 18 runs
    total_pilot_runs = len(PILOT_SCENARIO_IDS) * 3
    assert total_pilot_runs == 18


def test_extended_campaign_scenario_count():
    """Extended campaign specifies exactly 9 scenarios (6 attacks + 3 controls = 27 runs with 3 repetitions)."""
    assert len(EXTENDED_SCENARIO_IDS) == 9
    assert "proc-spawn-001" in EXTENDED_SCENARIO_IDS
    assert "net-egress-001" in EXTENDED_SCENARIO_IDS
    assert "file-tamper-001" in EXTENDED_SCENARIO_IDS

    total_extended_runs = len(EXTENDED_SCENARIO_IDS) * 3
    assert total_extended_runs == 27


def test_default_pilot_dir_preserves_historical_datasets():
    """Default pilot output dir points to pilot_batch01 and does not overwrite raw/ or raw3/."""
    assert DEFAULT_PILOT_DIR.name == "pilot_batch01"
    assert DEFAULT_PILOT_DIR.name != "raw"
    assert DEFAULT_PILOT_DIR.name != "raw3"


def test_pilot_workload_pairing_alignment():
    """Verify 1:1 microservice pairing between attack scenarios and benign controls."""
    oracle_dir = _REPO_ROOT / "research" / "evaluation" / "oracles"

    def _get_target_service(attack_id: str) -> str:
        p = oracle_dir / f"{attack_id}.yaml"
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data["target_service"]

    # Pair 1: recommendationservice
    assert _get_target_service("xzutils-001") == "recommendationservice"
    assert _get_target_service("benign-update-001") == "recommendationservice"

    # Pair 2: emailservice
    assert _get_target_service("dep-confusion-001") == "emailservice"
    assert _get_target_service("benign-load-001") == "emailservice"

    # Pair 3: cartservice
    assert _get_target_service("solarwinds-001") == "cartservice"
    assert _get_target_service("benign-restart-001") == "cartservice"


def test_static_manifest_labels_describe_expected_outcomes_only():
    """Static manifest ground_truth_label describes expected scenario outcome only;

    actual ground truth depends on independent runtime verification and remains decoupled.
    """
    attack = XZUtilsStyleAttack(dry_run=True)
    lbl = attack.label()

    # Expected label comes from static specification
    assert lbl["expected_label"] == 1
    assert lbl["label"] == 1

    # Actual runtime verification dimensions default to None (unknown until measured)
    assert lbl["inject_ok"] is None
    assert lbl["behavior_verified"] is None
    assert lbl["contract_drift_verified"] is None
    assert lbl["phantom_alerted"] is None


