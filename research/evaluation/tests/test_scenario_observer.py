"""Synthetic observer tests; no Kubernetes workloads or scenarios are run."""
from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta
import sys
import pytest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml

from research.evaluation.oracle import (
    TrustedOracleKey,
    canonical_payload_bytes,
    verify_signed_observation,
)
from research.evaluation.scenario_observer import (
    HarnessAssertion,
    ScenarioOracleObserver,
    load_observer_private_key,
    load_scenario_policies,
)


IMAGE = "sha256:" + "a" * 64
WORKLOAD = {
    "cluster": "phantom-k3s-lab", "cluster_name": "phantom-k3s-lab",
    "namespace": "phantom-eval", "name": "cartservice-pod", "deployment": "cartservice",
    "image_digest": IMAGE,
}


def _make_observer():
    observation_key = Ed25519PrivateKey.generate()
    contract_key = Ed25519PrivateKey.generate()
    contract_trust = TrustedOracleKey(
        "registry-test-key", "test-contract-registry", "verified_contract_registry",
        contract_key.public_key(), False,
    )
    observer = ScenarioOracleObserver(
        source_id="test-independent-harness", key_id="test-observer-key",
        signing_key=observation_key, trusted_contract_keys={contract_trust.key_id: contract_trust},
        policies=load_scenario_policies("research/evaluation/scenario_oracle_policies.yaml"),
    )
    contract = {
        "contract_id": "cart-contract-v1", "contract_version": "1",
        "image_digest": IMAGE, "status": "active",
        "verification_reference": "test-registry://contracts/cart-v1",
        "workload_selector": {"cluster_name": "phantom-k3s-lab",
                              "namespace": "phantom-eval", "labels": {}},
        "constraints": {
            "allowed_executables": ["/server"], "allowed_file_path_prefixes": ["/etc"],
            "allowed_network_destinations": [{"protocol": "tcp", "cidr": "10.0.0.0/24",
                                               "port_min": 443, "port_max": 443}],
            "allowed_syscall_classes": ["process"], "allowed_purls": [],
            "allowed_parent_child_pairs": [], "max_new_processes_per_5m": 1,
            "allow_privilege_transition": False,
        },
    }
    envelope = {
        "key_id": contract_trust.key_id, "algorithm": "Ed25519",
        "signature": base64.b64encode(contract_key.sign(canonical_payload_bytes(contract))).decode(),
        "payload": contract,
    }
    assertion = HarnessAssertion(
        run_id="observer-run-1", scenario_id="net-egress-001", event_id=str(uuid.uuid4()),
        workload=WORKLOAD, injection_status="succeeded",
        assertion_id="internal_sink_probe_receipt", assertion_passed=True,
        observed_state="violating",
        behavior="network_connect", details={
            "protocol": "tcp", "address": "10.0.0.20", "port": 8080,
        }, evidence_references=("harness://sink-receipts/receipt-1",),
        contract_envelope=envelope, observed_at=datetime.now(UTC).isoformat(),
    )
    return observer, assertion, observation_key, contract_key


def test_observer_emits_canonical_signed_observation_after_direct_assertion_and_contract_verification():
    observer, assertion, private_key, registry_key = _make_observer()
    decision = observer.observe(assertion)
    assert decision.outcome == "violating"
    assert decision.signed_observation is not None
    trusted = TrustedOracleKey(
        "test-observer-key", "test-independent-harness", "independent_runtime_monitor",
        private_key.public_key(), True,
    )
    trusted_registry = TrustedOracleKey(
        "registry-test-key", "test-contract-registry", "verified_contract_registry",
        registry_key.public_key(), False,
    )
    verified = verify_signed_observation(decision.signed_observation, {
        trusted.key_id: trusted, trusted_registry.key_id: trusted_registry,
    })
    assert verified.payload["run_id"] == assertion.run_id
    assert verified.payload["scenario_id"] == assertion.scenario_id
    assert verified.payload["event_id"] == assertion.event_id
    assert verified.payload["workload"] == WORKLOAD
    assert verified.payload["contract_snapshot"]["contract_id"] == "cart-contract-v1"


def test_observer_fails_closed_for_failed_injection_missing_evidence_and_assertion_conflict():
    observer, assertion, *_ = _make_observer()
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "injection_status": "failed",
    })).signed_observation is None
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "evidence_references": (),
    })).outcome == "unknown"
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "assertion_id": "different-assertion",
    })).signed_observation is None
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "observed_state": "conforming",
    })).outcome == "unknown"
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "scenario_id": "unknown-scenario",
    })).outcome == "unknown"


def test_observer_requires_fresh_complete_evidence_and_matching_workload_contract():
    observer, assertion, *_ = _make_observer()
    stale = datetime.now(UTC) - timedelta(minutes=10)
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "observed_at": stale.isoformat(),
    })).outcome == "unknown"
    mismatch = {**WORKLOAD, "image_digest": "sha256:" + "c" * 64}
    assert observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "workload": mismatch,
    })).outcome == "unknown"

    control = HarnessAssertion(**{
        **assertion.__dict__, "scenario_id": "benign-load-001",
        "assertion_id": "correlated_access_log_receipts", "behavior": "network_connect",
        "details": {"protocol": "tcp", "address": "10.0.0.20", "port": 443},
        "interval_complete": False,
    })
    assert observer.observe(control).outcome == "unknown"


def test_observer_rejects_tampered_contract_snapshot_signature():
    observer, assertion, *_ = _make_observer()
    tampered_contract = dict(assertion.contract_envelope)
    tampered_contract["payload"] = {**tampered_contract["payload"], "image_digest": "sha256:" + "d" * 64}
    decision = observer.observe(HarnessAssertion(**{
        **assertion.__dict__, "contract_envelope": tampered_contract,
    }))
    assert decision.outcome == "unknown"
    assert decision.signed_observation is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permission bits not supported on Windows NTFS")
def test_observer_signing_key_file_permissions_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = Path(tmp_path) / "observer-key.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o644)
    try:
        load_observer_private_key(path)
    except PermissionError:
        pass
    else:
        raise AssertionError("world-readable observer key was accepted")
    path.chmod(0o600)
    assert isinstance(load_observer_private_key(path), Ed25519PrivateKey)


def test_oracle_policy_scenario_and_workload_pairings_match_experiment_config():
    policies = load_scenario_policies("research/evaluation/scenario_oracle_policies.yaml")
    config = yaml.safe_load(Path("research/evaluation/experiment_config.yaml").read_text())
    scenarios = config["attack_scenarios"] + config["extended_attack_scenarios"] + config["benign_scenarios"]
    assert set(policies) == {item["id"] for item in scenarios}
    assert all(policies[item["id"]].target_service == item["target_service"] for item in scenarios)
