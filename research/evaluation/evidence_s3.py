"""Off-node, versioned S3 backup and safe restore for PHANTOM receipts.

The client accepts a boto3-compatible S3 client so tests can inject a narrow
test double. A fake client does not prove AWS IAM, bucket policy, encryption,
versioning, network, or service durability.
"""
from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from research.evaluation.evidence_backup import backup_database, restore_database, verify_database

_MAX_SINGLE_PUT = 5 * 1024**3


class S3Client(Protocol):
    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...
    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...
    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...


class EvidenceBackupError(RuntimeError):
    """An off-node backup could not be safely written, checked, or restored."""


def _service_error(operation: str, exc: Exception) -> EvidenceBackupError:
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code") if isinstance(error, dict) else None
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(response, dict) else None
    detail = ", ".join(str(item) for item in (code, status) if item is not None)
    detail = detail or type(exc).__name__
    return EvidenceBackupError(f"S3 {operation} failed ({detail})")


def _file_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class S3EvidenceBackupClient:
    """Create non-overwriting encrypted objects and restore only verified DBs."""

    def __init__(self, client: S3Client, *, bucket: str, prefix: str = "phantom/evidence",
                 temp_dir: str | Path | None = None):
        if not bucket or bucket.startswith("-"):
            raise ValueError("an explicit S3 bucket is required")
        normalized = prefix.strip("/")
        if not normalized or ".." in normalized.split("/"):
            raise ValueError("backup prefix must be a nonempty safe object prefix")
        self.client = client
        self.bucket = bucket
        self.prefix = normalized
        self.temp_dir = Path(temp_dir) if temp_dir else None

    @classmethod
    def from_environment(cls, *, prefix: str = "phantom/evidence") -> "S3EvidenceBackupClient":
        """Create an SDK client using the standard AWS credential chain."""
        import boto3

        bucket = os.environ.get("PHANTOM_EVIDENCE_BACKUP_BUCKET", "")
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not bucket or not region:
            raise ValueError("PHANTOM_EVIDENCE_BACKUP_BUCKET and AWS_REGION are required")
        configured_prefix = os.environ.get("PHANTOM_EVIDENCE_BACKUP_PREFIX", prefix)
        return cls(boto3.client("s3", region_name=region), bucket=bucket, prefix=configured_prefix)

    def backup(self, source: str | Path, *, backup_id: str | None = None) -> dict[str, Any]:
        """Snapshot a live SQLite DB, verify it, and PUT under a unique key.

        A single S3 PutObject is atomic from readers' perspective. It is capped
        at 5 GiB; larger databases fail explicitly instead of using an
        unconditioned multipart upload. A failed/interrupted PUT leaves no
        readable partial object. Retrying uses a new backup ID unless a caller
        supplies one, in which case S3's If-None-Match condition prevents
        replacement.
        """
        identifier = backup_id or f"{datetime.now(UTC):%Y%m%dT%H%M%S.%fZ}-{uuid.uuid4()}"
        if not identifier or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in identifier):
            raise ValueError("backup_id contains unsupported characters")
        key = f"{self.prefix}/{identifier}.sqlite3"
        try:
            with tempfile.TemporaryDirectory(prefix="phantom-evidence-backup-", dir=self.temp_dir) as temp:
                snapshot = Path(temp) / "snapshot.sqlite3"
                backup_database(source, snapshot)
                verified = verify_database(snapshot)
                file_digest, size = _file_sha256(snapshot)
                if size > _MAX_SINGLE_PUT:
                    raise EvidenceBackupError("SQLite snapshot exceeds S3 single-PUT 5 GiB limit")
                metadata = {
                    "schema": "phantom-sqlite-backup-v1",
                    "sha256": file_digest,
                    "sqlite-integrity": "ok",
                    "evidence-count": str(verified["evidence_receipts"]),
                    "tcp-evidence-count": str(verified["tcp_receipts"]),
                    "created-at": datetime.now(UTC).isoformat(),
                }
                with snapshot.open("rb") as body:
                    response = self.client.put_object(
                        Bucket=self.bucket,
                        Key=key,
                        Body=body,
                        ContentLength=size,
                        ContentType="application/vnd.sqlite3",
                        Metadata=metadata,
                        ServerSideEncryption="AES256",
                        ChecksumAlgorithm="SHA256",
                        ChecksumSHA256=base64.b64encode(bytes.fromhex(file_digest)).decode("ascii"),
                        IfNoneMatch="*",
                    )
            return {
                "bucket": self.bucket, "key": key, "version_id": response.get("VersionId"),
                "sha256": file_digest, "size_bytes": size,
                "evidence_receipts": verified["evidence_receipts"],
                "tcp_receipts": verified["tcp_receipts"],
                "server_side_encryption": "AES256",
            }
        except EvidenceBackupError:
            raise
        except Exception as exc:  # SDK service errors retain cause for operator diagnosis.
            raise _service_error("backup", exc) from exc

    def restore(self, key: str, destination: str | Path, *, version_id: str | None = None) -> dict[str, Any]:
        """Download one object, validate encryption/hash/SQLite receipts, and restore.

        The destination must not exist. `restore_database` enforces this, so a
        restore never silently overwrites prior evidence.
        """
        if not key.startswith(self.prefix + "/") or ".." in key.split("/"):
            raise ValueError("restore key is outside the configured backup prefix")
        request = {"Bucket": self.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        try:
            head = self.client.head_object(**request)
            metadata = {str(k).lower(): str(v) for k, v in head.get("Metadata", {}).items()}
            if metadata.get("schema") != "phantom-sqlite-backup-v1":
                raise EvidenceBackupError("S3 object is not a supported PHANTOM evidence backup")
            if metadata.get("sqlite-integrity") != "ok":
                raise EvidenceBackupError("backup metadata does not assert verified SQLite integrity")
            if head.get("ServerSideEncryption") not in {"AES256", "aws:kms"}:
                raise EvidenceBackupError("backup object is not server-side encrypted")
            expected_size = int(head.get("ContentLength", -1))
            if expected_size < 0 or expected_size > _MAX_SINGLE_PUT:
                raise EvidenceBackupError("S3 backup object size is invalid or exceeds supported limit")
            get_request = dict(request)
            get_request.pop("VersionId", None)
            if version_id is not None:
                get_request["VersionId"] = version_id
            response = self.client.get_object(**get_request)
            body = response["Body"]
            with tempfile.TemporaryDirectory(prefix="phantom-evidence-restore-", dir=self.temp_dir) as temp:
                download = Path(temp) / "download.sqlite3"
                fd = os.open(download, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                digest = hashlib.sha256()
                downloaded_size = 0
                try:
                    with os.fdopen(fd, "wb") as handle:
                        while True:
                            chunk = body.read(1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                            downloaded_size += len(chunk)
                            handle.write(chunk)
                        handle.flush()
                        os.fsync(handle.fileno())
                finally:
                    body.close()
                actual = digest.hexdigest()
                if downloaded_size != expected_size:
                    raise EvidenceBackupError("downloaded backup size does not match S3 object metadata")
                if actual != metadata.get("sha256"):
                    raise EvidenceBackupError("downloaded backup SHA-256 does not match object metadata")
                verification = verify_database(download)
                restored = restore_database(download, destination)
            return {
                "bucket": self.bucket, "key": key, "version_id": version_id,
                "sha256": actual, "source_evidence_receipts": verification["evidence_receipts"],
                "restored_path": str(destination),
                "restored_evidence_receipts": restored["evidence_receipts"],
                "sqlite_integrity": restored["sqlite_integrity"],
            }
        except EvidenceBackupError:
            raise
        except Exception as exc:
            raise _service_error("restore", exc) from exc


def main(argv: list[str] | None = None) -> int:
    """CLI used by the isolated lab backup job; credentials use the AWS chain."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    save = sub.add_parser("backup")
    save.add_argument("database")
    restore = sub.add_parser("restore")
    restore.add_argument("object_key")
    restore.add_argument("destination")
    restore.add_argument("--version-id")
    args = parser.parse_args(argv)
    try:
        client = S3EvidenceBackupClient.from_environment()
        result = (client.backup(args.database) if args.command == "backup" else
                  client.restore(args.object_key, args.destination, version_id=args.version_id))
    except Exception as exc:  # noqa: BLE001
        print(f"S3 evidence operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
