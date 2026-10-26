"""Local HTTP service integration tests; keys and observations are test fixtures."""
from __future__ import annotations

import base64
import json
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.evaluation.evidence_sink_service import create_app
from research.evaluation.tests.test_oracle_receipts import (
    REGISTRY_KEY_ID, REGISTRY_PRIVATE_KEY, SCENARIO, WORKLOAD, make_envelope,
)


def _trust_file(path, key: Ed25519PrivateKey, *, key_id: str = "local-test-key",
                generation: int = 1, revoked_key_ids: list[str] | None = None) -> None:
    _trust_file_entries(path, [(key_id, key)], generation=generation,
                        revoked_key_ids=revoked_key_ids or [])


def _trust_file_entries(path, entries, *, generation: int, revoked_key_ids: list[str]) -> None:
    keys = []
    for key_id, key in entries:
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        keys.append({
            "key_id": key_id, "source_id": "independent-test-observer",
            "source_type": "independent_sink", "public_key_pem": public_pem,
            "independent_of_phantom": True,
        })
    registry_public_pem = REGISTRY_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    keys.append({
        "key_id": REGISTRY_KEY_ID, "source_id": "test-contract-registry",
        "source_type": "verified_contract_registry", "public_key_pem": registry_public_pem,
        "independent_of_phantom": False,
    })
    path.write_text(json.dumps({
        "schema_version": "1.0", "trust_store_id": "test-oracle-trust",
        "generation": generation, "keys": keys, "revoked_key_ids": revoked_key_ids,
    }), encoding="utf-8")


def test_http_sink_persists_signed_receipt_across_service_reinitialization(tmp_path):
    db = tmp_path / "data" / "evidence.sqlite3"
    trust = tmp_path / "trusted-keys.json"
    key = Ed25519PrivateKey.generate()
    _trust_file(trust, key)
    event_id = str(uuid.uuid4())
    envelope = make_envelope(
        port=8443, observed_state="violating", event_id=event_id, key=key,
        key_id="local-test-key",
    )
    request = {
        "run_id": envelope["payload"]["run_id"], "scenario_id": SCENARIO,
        "event_id": event_id, "workload": WORKLOAD,
        "processing_outcome": "causal_event_processed",
        "provenance": {"binding_status": "insufficient_evidence"},
        "signed_observation": envelope,
    }

    first_app = create_app(db_path=str(db), trust_path=str(trust), tcp_ports=())
    with TestClient(first_app) as client:
        response = client.post("/v1/receipts", json=request)
        assert response.status_code == 201, response.text
        first = response.json()
        assert first["oracle_result"]["outcome"] == "confirmed_violation"
        assert first["event_id"] == event_id
        assert client.get(f"/v1/receipts/{first['receipt_id']}/verify").json()["integrity"] == "valid"
        retry = client.post("/v1/receipts", json=request)
        assert retry.status_code == 201
        assert retry.json()["receipt_id"] == first["receipt_id"]
        conflicting = make_envelope(
            port=443, observed_state="conforming", event_id=event_id, key=key,
            key_id="local-test-key",
        )
        conflict_response = client.post(
            "/v1/receipts", json={**request, "signed_observation": conflicting},
        )
        assert conflict_response.status_code == 409
        assert client.post("/v1/receipts", json={**request, "unexpected": True}).status_code == 422

    second_app = create_app(db_path=str(db), trust_path=str(trust), tcp_ports=())
    with TestClient(second_app) as client:
        retrieved = client.get(f"/v1/receipts/{first['receipt_id']}")
        assert retrieved.status_code == 200
        assert retrieved.json() == first
        assert client.get(f"/v1/runs/{request['run_id']}/receipts").json() == [first]


def test_http_sink_records_unknown_when_no_oracle_and_rejects_tampered_signature(tmp_path):
    db = tmp_path / "evidence.sqlite3"
    trust = tmp_path / "trusted-keys.json"
    _trust_file(trust, Ed25519PrivateKey.generate())
    app = create_app(db_path=str(db), trust_path=str(trust), tcp_ports=())
    with TestClient(app) as client:
        unknown_request = {
            "run_id": "run-without-oracle", "scenario_id": SCENARIO,
            "event_id": str(uuid.uuid4()), "workload": WORKLOAD,
            "processing_outcome": "event_processed", "provenance": {},
        }
        unknown = client.post("/v1/receipts", json=unknown_request)
        assert unknown.status_code == 201
        assert unknown.json()["oracle_result"]["outcome"] == "unknown"
        assert unknown.json()["oracle_result"]["observed_state"] == "unknown"
        retry = client.post("/v1/receipts", json=unknown_request)
        assert retry.status_code == 201
        assert retry.json()["receipt_id"] == unknown.json()["receipt_id"]

        altered = make_envelope(port=8443, observed_state="violating")
        altered["payload"]["details"]["port"] = 443
        bad = {**unknown_request, "run_id": "tampered-run", "signed_observation": altered}
        response = client.post("/v1/receipts", json=bad)
        assert response.status_code == 401
        assert client.post("/v1/receipts", json={
            **unknown_request, "event_id": "not-a-uuid",
        }).status_code == 422


def test_http_retrieval_detects_stored_payload_tampering(tmp_path):
    trust = tmp_path / "trusted-keys.json"
    _trust_file(trust, Ed25519PrivateKey.generate())
    db = tmp_path / "evidence.sqlite3"
    app = create_app(db_path=str(db), trust_path=str(trust), tcp_ports=())
    request = {
        "run_id": "tamper-check", "scenario_id": SCENARIO,
        "event_id": str(uuid.uuid4()), "workload": WORKLOAD,
        "processing_outcome": "recorded", "provenance": {},
    }
    with TestClient(app) as client:
        response = client.post("/v1/receipts", json=request)
        assert response.status_code == 201
        receipt_id = response.json()["receipt_id"]
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE evidence_receipts SET payload_json=? WHERE receipt_id=?",
                         ("{}", receipt_id))
        assert client.get(f"/v1/receipts/{receipt_id}/verify").status_code == 409


def test_sink_storage_failure_returns_server_error_without_success(monkeypatch, tmp_path):
    import sqlite3

    trust = tmp_path / "trusted-keys.json"
    _trust_file(trust, Ed25519PrivateKey.generate())
    app = create_app(db_path=str(tmp_path / "evidence.sqlite3"), trust_path=str(trust), tcp_ports=())

    def fail_persist(_receipt):
        raise sqlite3.OperationalError("simulated storage failure")

    monkeypatch.setattr(app.state.runtime.store, "submit", fail_persist)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/v1/receipts", json={
            "run_id": "storage-failure", "scenario_id": SCENARIO,
            "event_id": str(uuid.uuid4()), "workload": WORKLOAD,
            "processing_outcome": "recorded", "provenance": {},
        })
        assert response.status_code == 500


def test_trust_rotation_is_monotonic_and_revoked_keys_are_rejected(tmp_path):
    trust = tmp_path / "trusted-keys.json"
    database = tmp_path / "evidence.sqlite3"
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    _trust_file(trust, old_key, key_id="observer-v1")
    # Initializing the service pins trust generation 1 in the receipt database.
    app = create_app(db_path=str(database), trust_path=str(trust), tcp_ports=())
    with TestClient(app):
        pass

    _trust_file_entries(
        trust, [("observer-v2", new_key)], generation=2,
        revoked_key_ids=["observer-v1"],
    )
    rotated_app = create_app(db_path=str(database), trust_path=str(trust), tcp_ports=())
    old_event_id = str(uuid.uuid4())
    old_observation = make_envelope(
        port=8443, observed_state="violating", event_id=old_event_id,
        key=old_key, key_id="observer-v1",
    )
    request = {
        "run_id": old_observation["payload"]["run_id"], "scenario_id": SCENARIO,
        "event_id": old_event_id, "workload": WORKLOAD,
        "processing_outcome": "causal_event_processed", "provenance": {},
        "signed_observation": old_observation,
    }
    with TestClient(rotated_app) as client:
        assert client.post("/v1/receipts", json=request).status_code == 401
        new_event_id = str(uuid.uuid4())
        new_observation = make_envelope(
            port=8443, observed_state="violating", event_id=new_event_id,
            key=new_key, key_id="observer-v2",
        )
        accepted = client.post("/v1/receipts", json={
            **request, "run_id": new_observation["payload"]["run_id"],
            "event_id": new_event_id, "signed_observation": new_observation,
        })
        assert accepted.status_code == 201, accepted.text
        assert accepted.json()["oracle_verification"]["key_id"] == "observer-v2"

    _trust_file(trust, old_key, key_id="observer-v1", generation=1)
    with pytest.raises(ValueError, match="rollback"):
        create_app(db_path=str(database), trust_path=str(trust), tcp_ports=())


def test_key_removal_requires_explicit_revocation(tmp_path):
    trust = tmp_path / "trusted-keys.json"
    database = tmp_path / "evidence.sqlite3"
    old_key = Ed25519PrivateKey.generate()
    _trust_file(trust, old_key, key_id="observer-v1")
    with TestClient(create_app(db_path=str(database), trust_path=str(trust), tcp_ports=())):
        pass
    new_key = Ed25519PrivateKey.generate()
    _trust_file_entries(trust, [("observer-v2", new_key)], generation=2, revoked_key_ids=[])
    with pytest.raises(ValueError, match="explicitly listed"):
        create_app(db_path=str(database), trust_path=str(trust), tcp_ports=())


def test_http_sink_persists_tcp_beacon_receipts_without_invented_run_identity(tmp_path):
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    trust = tmp_path / "trusted-keys.json"
    _trust_file(trust, Ed25519PrivateKey.generate())
    app = create_app(db_path=str(tmp_path / "tcp.sqlite3"), trust_path=str(trust), tcp_ports=(port,))
    with TestClient(app):
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        client.sendall(b"bounded-test-beacon")
        client.close()
        # Callback runs on the server event loop. Poll through the service store
        # rather than treating successful connect as a durable receipt.
        runtime = app.state.runtime
        for _ in range(30):
            with runtime.store._connect() as conn:
                rows = conn.execute(
                    "SELECT receipt_id FROM tcp_receipts WHERE local_port=?", (port,),
                ).fetchall()
            if rows:
                break
            import time
            time.sleep(0.02)
        assert rows
        receipt = runtime.store.get_tcp_connection(rows[0]["receipt_id"])
        assert receipt["bytes_received"] == len(b"bounded-test-beacon")
        assert receipt["run_id"] is None and receipt["scenario_id"] is None
        assert receipt["outcome"] == "unknown"
        assert receipt["integrity_sha256"].startswith("sha256:")
        with runtime.store._connect() as conn:
            conn.execute("UPDATE tcp_receipts SET bytes_received=0 WHERE receipt_id=?",
                         (receipt["receipt_id"],))
        from research.evaluation.evidence_store import ReceiptIntegrityError

        with pytest.raises(ReceiptIntegrityError):
            runtime.store.get_tcp_connection(receipt["receipt_id"])
