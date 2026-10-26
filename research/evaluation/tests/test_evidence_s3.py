"""S3 backup client tests use an in-memory S3 protocol double, not AWS."""
from __future__ import annotations

import base64
import hashlib
import io
import uuid

import pytest

from research.evaluation.evidence_s3 import EvidenceBackupError, S3EvidenceBackupClient
from research.evaluation.evidence_store import DurableEvidenceSink, record_attempt_unknown


class MemoryS3:
    """Narrow deterministic test double for conditional S3 PUT and versioned GET."""

    def __init__(self):
        self.objects = {}
        self.fail_put = False

    def put_object(self, **kwargs):
        if self.fail_put:
            raise PermissionError("test access denied")
        key = (kwargs["Bucket"], kwargs["Key"])
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise FileExistsError("PreconditionFailed")
        body = kwargs["Body"].read()
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        assert digest == kwargs["ChecksumSHA256"]
        assert kwargs["ContentLength"] == len(body)
        version = str(uuid.uuid4())
        self.objects[key] = {
            "body": body, "metadata": kwargs["Metadata"], "version": version,
            "encryption": kwargs["ServerSideEncryption"],
        }
        return {"VersionId": version}

    def head_object(self, **kwargs):
        obj = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        if kwargs.get("VersionId") and kwargs["VersionId"] != obj["version"]:
            raise KeyError("NoSuchVersion")
        return {
            "Metadata": obj["metadata"], "ContentLength": len(obj["body"]),
            "ServerSideEncryption": obj["encryption"],
        }

    def get_object(self, **kwargs):
        obj = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        if kwargs.get("VersionId") and kwargs["VersionId"] != obj["version"]:
            raise KeyError("NoSuchVersion")
        return {"Body": io.BytesIO(obj["body"])}


def _with_receipt(path):
    sink = DurableEvidenceSink(path)
    receipt = record_attempt_unknown(
        sink, run_id="backup-run", scenario_id="backup-scenario",
        event_id=str(uuid.uuid4()), workload={
            "cluster": "test-k3s", "namespace": "phantom-eval", "name": "worker",
            "image_digest": "sha256:" + "b" * 64,
        }, processing_outcome="recorded", provenance={"test_fixture": True},
    )
    return receipt


def test_receipt_survives_local_database_removal_via_s3_backup_and_restore(tmp_path):
    source = tmp_path / "source.sqlite3"
    receipt = _with_receipt(source)
    s3 = MemoryS3()
    client = S3EvidenceBackupClient(s3, bucket="phantom-test", temp_dir=tmp_path)
    backup = client.backup(source, backup_id="backup-test-001")
    assert backup["evidence_receipts"] == 1
    assert backup["version_id"]

    # Emulate loss of the node-local source database before recovery.
    source.unlink()
    for suffix in ("-wal", "-shm"):
        candidate = source.with_name(source.name + suffix)
        if candidate.exists():
            candidate.unlink()

    restored = tmp_path / "recovered" / "evidence.sqlite3"
    result = client.restore(backup["key"], restored, version_id=backup["version_id"])
    recovered = DurableEvidenceSink(restored).get(receipt["receipt_id"])
    assert result["sqlite_integrity"] == "ok"
    assert result["restored_evidence_receipts"] == 1
    assert recovered["run_id"] == "backup-run"
    assert recovered["scenario_id"] == "backup-scenario"
    assert recovered["integrity_sha256"] == receipt["integrity_sha256"]


def test_s3_backup_refuses_object_overwrite_and_reports_storage_failure(tmp_path):
    source = tmp_path / "source.sqlite3"
    _with_receipt(source)
    s3 = MemoryS3()
    client = S3EvidenceBackupClient(s3, bucket="phantom-test", temp_dir=tmp_path)
    first = client.backup(source, backup_id="stable-id")
    with pytest.raises(EvidenceBackupError, match="S3 backup failed"):
        client.backup(source, backup_id="stable-id")
    assert s3.objects[("phantom-test", first["key"])]

    s3.fail_put = True
    with pytest.raises(EvidenceBackupError, match="S3 backup failed"):
        client.backup(source, backup_id="permission-denied")
    assert ("phantom-test", "phantom/evidence/permission-denied.sqlite3") not in s3.objects


def test_s3_restore_rejects_corrupt_or_unencrypted_objects_and_never_overwrites(tmp_path):
    source = tmp_path / "source.sqlite3"
    _with_receipt(source)
    s3 = MemoryS3()
    client = S3EvidenceBackupClient(s3, bucket="phantom-test", temp_dir=tmp_path)
    backup = client.backup(source, backup_id="restore-validation")
    key_tuple = ("phantom-test", backup["key"])
    obj = s3.objects[key_tuple]

    obj["body"] = obj["body"] + b"tamper"
    with pytest.raises(EvidenceBackupError, match="SHA-256 does not match"):
        client.restore(backup["key"], tmp_path / "bad-size.sqlite3")
    obj["body"] = obj["body"][:-6]
    obj["encryption"] = None
    with pytest.raises(EvidenceBackupError, match="not server-side encrypted"):
        client.restore(backup["key"], tmp_path / "bad-encryption.sqlite3")
    obj["encryption"] = "AES256"

    destination = tmp_path / "recovered.sqlite3"
    client.restore(backup["key"], destination)
    with pytest.raises(EvidenceBackupError):
        client.restore(backup["key"], destination)


def test_s3_restore_missing_object_fails_without_creating_destination(tmp_path):
    client = S3EvidenceBackupClient(MemoryS3(), bucket="phantom-test", temp_dir=tmp_path)
    destination = tmp_path / "never-created.sqlite3"
    with pytest.raises(EvidenceBackupError, match="S3 restore failed"):
        client.restore("phantom/evidence/missing.sqlite3", destination)
    assert not destination.exists()
