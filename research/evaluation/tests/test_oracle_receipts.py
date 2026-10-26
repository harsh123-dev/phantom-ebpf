"""Signed-oracle and file-backed evidence-sink tests using ephemeral test keys."""
from __future__ import annotations

import base64
import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.evaluation.evidence_store import (
    DurableEvidenceSink,
    OracleReplayError,
    ReceiptConflictError,
    ReceiptIntegrityError,
    evaluate_and_persist,
    record_attempt_unknown,
    receipt_for_run,
)
from research.evaluation.oracle import (
    InvalidOracleSignatureError,
    OracleVerificationError,
    StaleOracleObservationError,
    TrustedOracleKey,
    TrustedOracleKeySet,
    UnknownOracleKeyError,
    UnsupportedOracleAlgorithmError,
    canonical_payload_bytes,
    evaluate_contract,
    evaluate_signed_observation,
    _classify_contract_observations,
)

RUN = "run-0001"
SCENARIO = "scenario-001"
IMAGE = "sha256:" + "a" * 64
WORKLOAD = {"cluster": "phantom-k3s-lab", "namespace": "phantom-eval",
            "name": "worker", "image_digest": IMAGE}
CONTRACT = {
    "contract_id": "contract-1", "contract_version": "1.0.0", "image_digest": IMAGE,
    "status": "active", "signature_verified": True,
    "verification_reference": "contract-registry://contract-1/1.0.0",
    "workload_selector": {"cluster_name": "phantom-k3s-lab", "namespace": "phantom-eval",
                           "labels": {}},
    "constraints": {
        "allowed_executables": ["/usr/bin/worker"],
        "allowed_file_path_prefixes": ["/etc/worker"],
        "allowed_network_destinations": [{"protocol": "tcp", "cidr": "10.0.0.0/24",
                                           "port_min": 443, "port_max": 443}],
        "allowed_syscall_classes": ["process", "file_read", "network_connect"],
        "allowed_purls": ["pkg:pypi/worker@1.0"],
        "allowed_parent_child_pairs": [], "max_new_processes_per_5m": 50,
        "allow_privilege_transition": False,
    },
}
PRIVATE_KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = PRIVATE_KEY.public_key()
KEY_ID = "test-observer-key"
REGISTRY_PRIVATE_KEY = Ed25519PrivateKey.generate()
REGISTRY_KEY_ID = "test-contract-registry-key"
TRUSTED_KEYS = {
    KEY_ID: TrustedOracleKey(
        key_id=KEY_ID, source_id="independent-test-observer", source_type="independent_sink",
        public_key=PUBLIC_KEY, independent_of_phantom=True,
    ),
    REGISTRY_KEY_ID: TrustedOracleKey(
        key_id=REGISTRY_KEY_ID, source_id="test-contract-registry",
        source_type="verified_contract_registry",
        public_key=REGISTRY_PRIVATE_KEY.public_key(), independent_of_phantom=False,
    )
}


def make_envelope(
    *, port: int = 443, observed_state: str = "conforming",
    evidence_references: list[str] | None = None, run_id: str = RUN,
    scenario_id: str = SCENARIO, event_id: str | None = None,
    observation_id: str | None = None, observed_at: datetime | None = None,
    workload: dict | None = None, behavior: str = "network_connect",
    details: dict | None = None, key: Ed25519PrivateKey = PRIVATE_KEY,
    key_id: str = KEY_ID, algorithm: str = "Ed25519",
) -> dict:
    event_id = event_id or str(uuid.uuid4())
    payload = {
        "schema_version": "1.0",
        "observation_id": observation_id or str(uuid.uuid4()),
        "run_id": run_id,
        "scenario_id": scenario_id,
        "event_id": event_id,
        "observed_at": (observed_at or datetime.now(UTC)).isoformat(),
        "workload": workload or WORKLOAD,
        "image_digest": (workload or WORKLOAD)["image_digest"],
        "source_id": "independent-test-observer",
        "evidence_references": evidence_references if evidence_references is not None else ["sink://connection/abc"],
        "behavior": behavior,
        "details": details or {"protocol": "tcp", "address": "10.0.0.9", "port": port},
        "contract_snapshot": {
            **CONTRACT,
            "registry_attestation": {
                "key_id": REGISTRY_KEY_ID, "algorithm": "Ed25519",
                "signature": base64.b64encode(REGISTRY_PRIVATE_KEY.sign(canonical_payload_bytes({
                    key: value for key, value in CONTRACT.items() if key != "signature_verified"
                }))).decode("ascii"),
            },
        },
        "expected_state": "conforming",
        "observed_state": observed_state,
        "interval_complete": observed_state == "conforming",
    }
    signature = key.sign(canonical_payload_bytes(payload))
    return {"key_id": key_id, "algorithm": algorithm,
            "signature": base64.b64encode(signature).decode("ascii"), "payload": payload}


def test_oracle_confirms_violation_only_after_valid_independent_signature():
    envelope = make_envelope(port=8443, observed_state="violating",)
    result, verified = evaluate_signed_observation(
        envelope, TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
        expected_workload=WORKLOAD,
    )
    assert result.outcome == "confirmed_violation"
    assert result.authenticity_status == "verified"
    assert result.independence_status == "configured_independent"
    assert verified.payload_sha256.startswith("sha256:")
    assert result.run_id == envelope["payload"]["run_id"]
    assert result.observation_ids == (envelope["payload"]["observation_id"],)


def test_compliance_requires_complete_assessable_signed_interval():
    incomplete = make_envelope(port=443, observed_state="unknown")
    incomplete["payload"]["interval_complete"] = False
    incomplete["signature"] = base64.b64encode(
        PRIVATE_KEY.sign(canonical_payload_bytes(incomplete["payload"]))
    ).decode("ascii")
    partial, _ = evaluate_signed_observation(
        incomplete, TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
        expected_workload=WORKLOAD,
    )
    complete, _ = evaluate_signed_observation(
        make_envelope(port=443, observed_state="conforming"), TRUSTED_KEYS,
        expected_run_id=RUN, expected_scenario_id=SCENARIO, expected_workload=WORKLOAD,
    )
    assert partial.outcome == "unknown"
    assert complete.outcome == "confirmed_compliance"


def test_tampered_payload_invalid_signature_unknown_key_and_algorithm_rejected():
    altered = make_envelope(port=8443, observed_state="violating")
    altered["payload"]["details"]["port"] = 443
    with pytest.raises(InvalidOracleSignatureError):
        evaluate_signed_observation(altered, TRUSTED_KEYS, expected_run_id=RUN,
                                    expected_scenario_id=SCENARIO, expected_workload=WORKLOAD)


def test_contract_registry_signature_is_required_and_separately_verified():
    missing = make_envelope(observed_state="violating")
    missing["payload"]["contract_snapshot"].pop("registry_attestation")
    missing["signature"] = base64.b64encode(
        PRIVATE_KEY.sign(canonical_payload_bytes(missing["payload"]))
    ).decode("ascii")
    result, _ = evaluate_signed_observation(
        missing, TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
        expected_workload=WORKLOAD,
    )
    assert result.outcome == "unknown"
    assert result.authenticity_status == "verified"
    assert "registry signature" in result.reasons[0]

    invalid = make_envelope(observed_state="violating")
    invalid["payload"]["contract_snapshot"]["registry_attestation"]["signature"] = \
        base64.b64encode(b"x" * 64).decode("ascii")
    invalid["signature"] = base64.b64encode(
        PRIVATE_KEY.sign(canonical_payload_bytes(invalid["payload"]))
    ).decode("ascii")
    with pytest.raises(InvalidOracleSignatureError, match="registry"):
        evaluate_signed_observation(
            invalid, TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
            expected_workload=WORKLOAD,
        )


def test_unknown_and_revoked_contract_registry_keys_are_rejected():
    unknown = make_envelope(observed_state="violating")
    unknown["payload"]["contract_snapshot"]["registry_attestation"]["key_id"] = "unknown-registry"
    unknown["signature"] = base64.b64encode(
        PRIVATE_KEY.sign(canonical_payload_bytes(unknown["payload"]))
    ).decode("ascii")
    with pytest.raises(UnknownOracleKeyError, match="registry"):
        evaluate_signed_observation(
            unknown, TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
            expected_workload=WORKLOAD,
        )

    revoked = TrustedOracleKeySet(
        trust_store_id="test", generation=2,
        revoked_key_ids=frozenset({REGISTRY_KEY_ID}), config_sha256="sha256:" + "0" * 64,
    )
    revoked.update(TRUSTED_KEYS)
    with pytest.raises(OracleVerificationError, match="revoked"):
        evaluate_signed_observation(
            make_envelope(observed_state="violating"), revoked,
            expected_run_id=RUN, expected_scenario_id=SCENARIO,
            expected_workload=WORKLOAD,
        )

    invalid = make_envelope()
    invalid["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
    with pytest.raises(InvalidOracleSignatureError):
        evaluate_signed_observation(invalid, TRUSTED_KEYS, expected_run_id=RUN,
                                    expected_scenario_id=SCENARIO, expected_workload=WORKLOAD)
    unknown = make_envelope(key_id="not-configured")
    with pytest.raises(UnknownOracleKeyError):
        evaluate_signed_observation(unknown, TRUSTED_KEYS, expected_run_id=RUN,
                                    expected_scenario_id=SCENARIO, expected_workload=WORKLOAD)
    unsupported = make_envelope(algorithm="RS256")
    with pytest.raises(UnsupportedOracleAlgorithmError):
        evaluate_signed_observation(unsupported, TRUSTED_KEYS, expected_run_id=RUN,
                                    expected_scenario_id=SCENARIO, expected_workload=WORKLOAD)


def test_stale_and_identity_mismatched_signed_observations_are_rejected_or_unknown():
    stale = make_envelope(observed_at=datetime.now(UTC) - timedelta(minutes=30))
    with pytest.raises(StaleOracleObservationError):
        evaluate_signed_observation(stale, TRUSTED_KEYS, expected_run_id=RUN,
                                    expected_scenario_id=SCENARIO, expected_workload=WORKLOAD)
    with pytest.raises(OracleVerificationError, match="identity"):
        evaluate_signed_observation(
            make_envelope(), TRUSTED_KEYS, expected_run_id="other-run",
            expected_scenario_id=SCENARIO, expected_workload=WORKLOAD,
        )


def test_missing_evidence_ambiguous_binding_and_untrusted_independence_abstain():
    no_evidence = evaluate_signed_observation(
        make_envelope(observed_state="unknown", evidence_references=[]), TRUSTED_KEYS,
        expected_run_id=RUN, expected_scenario_id=SCENARIO, expected_workload=WORKLOAD,
    )[0]
    assert no_evidence.outcome == "unknown"

    ambiguous = evaluate_signed_observation(
        make_envelope(observed_state="unknown", behavior="component_execution",
                      details={"binding_status": "ambiguous", "purl": None}),
        TRUSTED_KEYS, expected_run_id=RUN, expected_scenario_id=SCENARIO,
        expected_workload=WORKLOAD,
    )[0]
    assert ambiguous.outcome == "unknown"

    non_independent_keys = {
        KEY_ID: TrustedOracleKey(
            KEY_ID, "independent-test-observer", "independent_sink", PUBLIC_KEY, False,
        ),
        REGISTRY_KEY_ID: TRUSTED_KEYS[REGISTRY_KEY_ID],
    }
    result = evaluate_signed_observation(
        make_envelope(port=8443, observed_state="violating"), non_independent_keys,
        expected_run_id=RUN, expected_scenario_id=SCENARIO, expected_workload=WORKLOAD,
    )[0]
    assert result.authenticity_status == "verified"
    assert result.independence_status == "not_established"
    assert result.outcome == "unknown"


def test_signed_observation_conflicting_with_contract_is_unknown():
    contradictory = make_envelope(port=8443, observed_state="conforming")
    result, _ = evaluate_signed_observation(
        contradictory, TRUSTED_KEYS, expected_run_id=RUN,
        expected_scenario_id=SCENARIO, expected_workload=WORKLOAD,
    )
    assert result.authenticity_status == "verified"
    assert result.outcome == "unknown"
    assert "conflicts" in result.reasons[0]


def test_unsigned_raw_observations_are_never_ground_truth():
    result = evaluate_contract(
        run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT, workload=WORKLOAD,
        observations=[{"source": "independent_sink"}], interval_complete=True,
    )
    assert result.outcome == "unknown"
    assert result.authenticity_status == "unverified"


@pytest.mark.parametrize("source", ["phantom_alert", "causal_engine", "scenario_label"])
def test_detector_derived_records_cannot_be_promoted_to_ground_truth(source):
    result = evaluate_contract(
        run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT, workload=WORKLOAD,
        observations=[{"source": source}], interval_complete=True,
    )
    assert result.outcome == "unknown"
    assert result.authenticity_status == "unverified"


def test_contract_classifier_abstains_on_same_event_conflicting_content():
    first = {
        "run_id": RUN, "scenario_id": SCENARIO, "workload": WORKLOAD,
        "event_id": str(uuid.uuid4()), "observed_at": datetime.now(UTC).isoformat(),
        "image_digest": IMAGE, "source": "independent_sink",
        "evidence_reference": "sink://receipt/one", "behavior": "network_connect",
        "details": {"protocol": "tcp", "address": "10.0.0.9", "port": 443},
    }
    second = {**first, "details": {"protocol": "tcp", "address": "10.0.0.9", "port": 8443}}
    result = _classify_contract_observations(
        run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT, workload=WORKLOAD,
        observations=[first, second], interval_complete=True,
    )
    assert result.outcome == "unknown"
    assert "contradictory" in result.reasons[0]


def _receipt(event_id: str | None = None) -> dict:
    oracle = {
        "run_id": RUN, "scenario_id": SCENARIO, "contract_id": None,
        "contract_version": None, "workload": WORKLOAD,
        "expected_state": "contract_state_unavailable", "observed_state": "unknown",
        "outcome": "unknown", "assessed_at": datetime.now(UTC).isoformat(),
        "evidence_references": [], "reasons": ["no independent evidence"],
        "independence_basis": [], "authenticity_status": "unverified",
        "independence_status": "unverified", "observation_ids": [], "signature_key_ids": [],
    }
    return receipt_for_run(
        run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        oracle_result=oracle, processing_outcome="recorded",
        evidence_references=[], provenance={"test": True},
        event_id=event_id or str(uuid.uuid4()), created_at="2026-01-01T00:00:00+00:00",
    )


def test_receipt_survives_reinitialization_is_idempotent_and_retrievable(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = DurableEvidenceSink(path)
    payload = _receipt()
    receipt = store.submit(payload)
    reopened = DurableEvidenceSink(path)
    retry = reopened.submit(payload)
    assert retry["receipt_id"] == receipt["receipt_id"]
    assert retry["integrity_sha256"] == receipt["integrity_sha256"]
    assert reopened.get(receipt["receipt_id"]) == receipt
    assert len(reopened.list_run(RUN)) == 1


def test_conflicting_duplicate_and_malformed_receipts_are_rejected(tmp_path):
    store = DurableEvidenceSink(tmp_path / "evidence.sqlite3")
    event_id = str(uuid.uuid4())
    original = _receipt(event_id)
    store.submit(original)
    changed = _receipt(event_id)
    changed["provenance"] = {"changed": True}
    with pytest.raises(ReceiptConflictError):
        store.submit(changed)
    with pytest.raises(ValueError, match="confirmed outcomes"):
        store.submit({**_receipt(), "oracle_result": {"outcome": "confirmed_violation"}})
    with pytest.raises(ValueError, match="missing required"):
        store.submit({"schema_version": "1.0"})
    wrong_id = _receipt()
    wrong_id["receipt_id"] = str(uuid.uuid4())
    with pytest.raises(ValueError, match="deterministic receipt identity"):
        store.submit(wrong_id)


def test_receipt_hash_detects_payload_tampering(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = DurableEvidenceSink(path)
    receipt = store.submit(_receipt())
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE evidence_receipts SET payload_json=? WHERE receipt_id=?",
                     ("{}", receipt["receipt_id"]))
    with pytest.raises(ReceiptIntegrityError):
        store.get(receipt["receipt_id"])


def test_signed_oracle_and_durable_sink_composed_integration(tmp_path):
    path = tmp_path / "batch" / "evidence.sqlite3"
    sink = DurableEvidenceSink(path)
    event_id = str(uuid.uuid4())
    envelope = make_envelope(port=8443, observed_state="violating", event_id=event_id)
    receipt = sink.submit_signed_observation(
        run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        processing_outcome="event_processed", provenance={"pipeline_event_id": event_id},
        signed_observation=envelope, trusted_keys=TRUSTED_KEYS, expected_event_id=event_id,
    )
    restarted = DurableEvidenceSink(path)
    duplicate = restarted.submit_signed_observation(
        run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        processing_outcome="event_processed", provenance={"pipeline_event_id": event_id},
        signed_observation=envelope, trusted_keys=TRUSTED_KEYS, expected_event_id=event_id,
    )
    retrieved = restarted.get(receipt["receipt_id"])
    assert duplicate["receipt_id"] == receipt["receipt_id"]
    assert retrieved["run_id"] == RUN and retrieved["scenario_id"] == SCENARIO
    assert retrieved["event_id"] == event_id
    assert retrieved["oracle_result"]["outcome"] == "confirmed_violation"
    assert retrieved["oracle_verification"]["authenticity_status"] == "verified"
    assert retrieved["oracle_observation"]["payload"]["event_id"] == event_id
    assert retrieved["integrity_sha256"].startswith("sha256:")


def test_signed_observation_replay_and_conflicting_event_are_rejected(tmp_path):
    sink = DurableEvidenceSink(tmp_path / "evidence.sqlite3")
    event_id = str(uuid.uuid4())
    original = make_envelope(port=8443, observed_state="violating", event_id=event_id)
    sink.submit_signed_observation(
        run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        processing_outcome="event_processed", provenance={}, signed_observation=original,
        trusted_keys=TRUSTED_KEYS,
    )
    replay = make_envelope(port=443, observed_state="conforming", run_id="run-2",
                           scenario_id="scenario-2", event_id=str(uuid.uuid4()),
                           observation_id=original["payload"]["observation_id"])
    with pytest.raises(OracleReplayError):
        sink.submit_signed_observation(
            run_id="run-2", scenario_id="scenario-2", workload=WORKLOAD,
            processing_outcome="event_processed", provenance={}, signed_observation=replay,
            trusted_keys=TRUSTED_KEYS,
        )

    conflicting = make_envelope(port=443, observed_state="conforming", event_id=event_id)
    with pytest.raises(ReceiptConflictError):
        sink.submit_signed_observation(
            run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
            processing_outcome="event_processed", provenance={}, signed_observation=conflicting,
            trusted_keys=TRUSTED_KEYS,
        )


def test_missing_signed_evidence_persists_unknown_only(tmp_path):
    sink = DurableEvidenceSink(tmp_path / "unknown.sqlite3")
    receipt = record_attempt_unknown(
        sink, run_id=RUN, scenario_id=SCENARIO,
        workload={"namespace": "phantom-eval", "image_ref": "worker:tag", "image_digest": None},
        processing_outcome="execution_recorded", provenance={"collector": "unavailable"},
    )
    assert receipt["oracle_result"]["outcome"] == "unknown"
    assert receipt["oracle_result"]["observed_state"] == "unknown"
    assert receipt["oracle_result"]["authenticity_status"] == "unverified"
    assert sink.get(receipt["receipt_id"])["oracle_result"]["outcome"] == "unknown"


def test_evaluate_helper_does_not_promote_unsigned_data(tmp_path):
    sink = DurableEvidenceSink(tmp_path / "unsigned.sqlite3")
    receipt = evaluate_and_persist(
        sink, run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        processing_outcome="recorded", provenance={},
    )
    assert receipt["oracle_result"]["outcome"] == "unknown"
