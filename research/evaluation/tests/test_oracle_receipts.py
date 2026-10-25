"""Unit and local file-backed integration tests for independent oracle receipts."""
from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

import pytest

from research.evaluation.evidence_store import (
    DurableEvidenceSink,
    ReceiptConflictError,
    ReceiptIntegrityError,
    evaluate_and_persist,
    receipt_for_run,
    record_attempt_unknown,
)
from research.evaluation.oracle import evaluate_contract

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


def observation(*, port=443, source="independent_sink", event_id=None, **details):
    return {
        "run_id": RUN, "scenario_id": SCENARIO,
        "workload": WORKLOAD,
        "event_id": event_id or str(uuid.uuid4()),
        "observed_at": datetime.now(UTC).isoformat(), "image_digest": IMAGE,
        "source": source, "evidence_reference": "sink://receipt/abc",
        "behavior": "network_connect",
        "details": {"protocol": "tcp", "address": "10.0.0.9", "port": port, **details},
    }


def test_oracle_confirms_violation_from_independent_observation_not_alert():
    result = evaluate_contract(
        run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT, workload=WORKLOAD,
        observations=[observation(port=8443)], interval_complete=False,
    )
    assert result.outcome == "confirmed_violation"
    assert result.observed_state == "violating"
    assert result.independence_basis == ("independent_sink", "verified_contract_registry")
    assert set(result.evidence_references) == {
        "sink://receipt/abc", "contract-registry://contract-1/1.0.0"
    }


def test_compliance_requires_complete_assessable_independent_interval():
    obs = observation(port=443)
    partial = evaluate_contract(run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
                                workload=WORKLOAD, observations=[obs], interval_complete=False)
    complete = evaluate_contract(run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
                                 workload=WORKLOAD, observations=[obs], interval_complete=True)
    assert partial.outcome == "unknown"
    assert complete.outcome == "confirmed_compliance"


@pytest.mark.parametrize("source", ["phantom_alert", "causal_engine", "scenario_label"])
def test_detector_derived_sources_are_rejected(source):
    result = evaluate_contract(run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
                               workload=WORKLOAD, observations=[observation(source=source)],
                               interval_complete=True)
    assert result.outcome == "unknown"
    assert "non-independent" in result.reasons[0]


def test_missing_component_binding_and_conflicting_event_records_abstain():
    unknown_component = observation(details="unused")
    unknown_component["behavior"] = "component_execution"
    unknown_component["details"] = {"binding_status": "ambiguous", "purl": None}
    result = evaluate_contract(run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
                               workload=WORKLOAD, observations=[unknown_component],
                               interval_complete=True)
    assert result.outcome == "unknown"

    event_id = str(uuid.uuid4())
    first, second = observation(port=443, event_id=event_id), observation(port=8443, event_id=event_id)
    conflict = evaluate_contract(run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
                                 workload=WORKLOAD, observations=[first, second],
                                 interval_complete=True)
    assert conflict.outcome == "unknown"
    assert "contradictory" in conflict.reasons[0]


def _receipt(outcome="unknown", event_id=None):
    oracle = {
        "run_id": RUN, "scenario_id": SCENARIO, "contract_id": None,
        "contract_version": None, "workload": WORKLOAD,
        "expected_state": "contract_state_unavailable", "observed_state": "unknown",
        "outcome": outcome, "assessed_at": datetime.now(UTC).isoformat(),
        "evidence_references": [], "reasons": ["no independent evidence"],
        "independence_basis": [],
    }
    return receipt_for_run(
        run_id=RUN, scenario_id=SCENARIO, workload=WORKLOAD,
        oracle_result=oracle, processing_outcome="recorded",
        evidence_references=[], provenance={"test": True},
        event_id=event_id or str(uuid.uuid4()),
        created_at="2026-01-01T00:00:00+00:00",
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


def test_conflicting_idempotency_key_and_bad_receipt_are_rejected(tmp_path):
    store = DurableEvidenceSink(tmp_path / "evidence.sqlite3")
    event_id = str(uuid.uuid4())
    original = store.submit(_receipt(event_id=event_id))
    changed = _receipt(outcome="confirmed_violation", event_id=event_id)
    changed["oracle_result"]["observed_state"] = "violating"
    changed["oracle_result"].update({
        "contract_id": "contract-1", "contract_version": "1.0.0",
        "expected_state": "conforming", "evidence_references": ["sink://evidence/1"],
        "independence_basis": ["independent_sink"],
    })
    changed["evidence_references"] = ["sink://evidence/1"]
    with pytest.raises(ReceiptConflictError):
        store.submit(changed)
    with pytest.raises(ValueError, match="missing required"):
        store.submit({"schema_version": "1.0"})
    wrong_id = _receipt(event_id=str(uuid.uuid4()))
    wrong_id["receipt_id"] = str(uuid.uuid4())
    with pytest.raises(ValueError, match="deterministic receipt identity"):
        store.submit(wrong_id)
    assert store.get(original["receipt_id"])["oracle_result"]["outcome"] == "unknown"


def test_receipt_hash_detects_payload_tampering(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = DurableEvidenceSink(path)
    receipt = store.submit(_receipt())
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE evidence_receipts SET payload_json=? WHERE receipt_id=?",
                     ('{}', receipt["receipt_id"]))
    with pytest.raises(ReceiptIntegrityError):
        store.get(receipt["receipt_id"])


def test_oracle_and_durable_sink_composed_integration(tmp_path):
    sink = DurableEvidenceSink(tmp_path / "batch" / "evidence.sqlite3")
    event = observation(port=8443)
    event["run_id"], event["scenario_id"] = RUN, SCENARIO
    receipt = evaluate_and_persist(
        sink, run_id=RUN, scenario_id=SCENARIO, contract=CONTRACT,
        workload=WORKLOAD, observations=[event], interval_complete=False,
        processing_outcome="event_processed", provenance={"pipeline_event_id": event["event_id"]},
        event_id=event["event_id"],
    )
    restarted = DurableEvidenceSink(tmp_path / "batch" / "evidence.sqlite3")
    retrieved = restarted.get(receipt["receipt_id"])
    assert retrieved["run_id"] == RUN and retrieved["scenario_id"] == SCENARIO
    assert retrieved["event_id"] == event["event_id"]
    assert retrieved["oracle_result"]["outcome"] == "confirmed_violation"
    assert set(retrieved["evidence_references"]) == {
        event["evidence_reference"], "contract-registry://contract-1/1.0.0"
    }
    assert retrieved["integrity_sha256"].startswith("sha256:")


def test_missing_contract_writes_durable_unknown_not_negative(tmp_path):
    sink = DurableEvidenceSink(tmp_path / "unknown.sqlite3")
    receipt = record_attempt_unknown(
        sink, run_id=RUN, scenario_id=SCENARIO,
        workload={"namespace": "phantom-eval", "image_ref": "worker:tag",
                  "image_digest": None},
        processing_outcome="execution_recorded", provenance={"collector": "unavailable"},
    )
    assert receipt["oracle_result"]["outcome"] == "unknown"
    assert receipt["oracle_result"]["observed_state"] == "unknown"
    assert receipt["oracle_result"]["evidence_references"] == []
    assert sink.get(receipt["receipt_id"])["oracle_result"]["outcome"] == "unknown"
