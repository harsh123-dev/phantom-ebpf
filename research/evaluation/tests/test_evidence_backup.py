from __future__ import annotations

import sqlite3
import uuid

import pytest

from research.evaluation.evidence_backup import (
    backup_database,
    restore_database,
    verify_database,
)
from research.evaluation.evidence_store import (
    DurableEvidenceSink,
    ReceiptIntegrityError,
    record_attempt_unknown,
)


def _seed_database(path):
    store = DurableEvidenceSink(path)
    event_id = str(uuid.uuid4())
    receipt = record_attempt_unknown(
        store, run_id="backup-run", scenario_id="backup-scenario", event_id=event_id,
        workload={"cluster": "k3s-test", "namespace": "phantom-eval", "name": "worker",
                  "image_digest": "sha256:" + "a" * 64},
        processing_outcome="recorded", provenance={"collector": "unavailable"},
    )
    tcp = store.record_tcp_connection(
        local_port=4445, peer_address="10.1.2.3", peer_port=45000, content=b"beacon",
    )
    return receipt, tcp


def test_online_backup_and_restore_retain_receipts_and_verify_integrity(tmp_path):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "off-node" / "evidence-001.sqlite3"
    restore = tmp_path / "restored.sqlite3"
    receipt, tcp_receipt = _seed_database(source)

    backed_up = backup_database(source, backup)
    assert backed_up["sqlite_integrity"] == "ok"
    assert backed_up["evidence_receipts"] == 1
    assert backed_up["tcp_receipts"] == 1
    assert backup.stat().st_mode & 0o777 == 0o600
    assert verify_database(backup)["database_sha256"] == backed_up["database_sha256"]

    recovered = restore_database(backup, restore)
    recovered_store = DurableEvidenceSink(restore)
    assert recovered["evidence_receipts"] == 1
    assert recovered_store.get(receipt["receipt_id"]) == receipt
    assert recovered_store.get_tcp_connection(tcp_receipt["receipt_id"]) == tcp_receipt


def test_backup_and_restore_refuse_to_overwrite_existing_paths(tmp_path):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    restore_path = tmp_path / "restored.sqlite3"
    _seed_database(source)
    backup_database(source, destination)
    original = destination.read_bytes()
    with pytest.raises(FileExistsError):
        backup_database(source, destination)
    assert destination.read_bytes() == original
    restore_database(destination, restore_path)
    with pytest.raises(FileExistsError):
        restore_database(destination, restore_path)


def test_backup_verification_rejects_tampered_receipt_payload(tmp_path):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    receipt, _ = _seed_database(source)
    backup_database(source, backup)
    with sqlite3.connect(backup) as conn:
        conn.execute("UPDATE evidence_receipts SET payload_json='{}' WHERE receipt_id=?",
                     (receipt["receipt_id"],))
    with pytest.raises(ReceiptIntegrityError, match="malformed|hash"):
        verify_database(backup)
