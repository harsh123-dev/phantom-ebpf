"""Append-safe SQLite online backup, verification, and restore CLI.

Destination paths must be on storage protected independently of the source
database (for example an encrypted, separately attached EBS volume). This tool
does not schedule or upload backups.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

from research.evaluation.evidence_store import ReceiptIntegrityError, validate_receipt
from research.evaluation.oracle import canonical_sha256


def _readonly_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(path)
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def verify_database(path: str | Path) -> dict[str, Any]:
    """Verify SQLite integrity and canonical hashes for every stored receipt."""
    source = Path(path)
    conn = _readonly_connection(source)
    try:
        with conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise ReceiptIntegrityError(f"SQLite integrity_check failed: {integrity}")
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "evidence_receipts" not in tables:
                raise ReceiptIntegrityError("database has no evidence receipt table")
            receipt_count = 0
            for receipt_id, payload_json, expected_hash in conn.execute(
                "SELECT receipt_id,payload_json,payload_sha256 FROM evidence_receipts"
            ):
                try:
                    payload = json.loads(payload_json)
                    validate_receipt(payload)
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ReceiptIntegrityError(f"receipt {receipt_id} is malformed") from exc
                if payload.get("receipt_id") != receipt_id or canonical_sha256(payload) != expected_hash:
                    raise ReceiptIntegrityError(f"receipt {receipt_id} hash/identity mismatch")
                receipt_count += 1

            tcp_count = 0
            if "tcp_receipts" in tables:
                for row in conn.execute(
                    "SELECT receipt_id,created_at,local_port,peer_address,peer_port,"
                    "bytes_received,content_sha256,receipt_sha256 FROM tcp_receipts"
                ):
                    receipt_id, created, local_port, address, peer_port, size, content_hash, stored_hash = row
                    body = {
                        "receipt_id": receipt_id, "created_at": created,
                        "local_port": local_port, "peer_address": address,
                        "peer_port": peer_port, "bytes_received": size,
                        "content_sha256": content_hash,
                    }
                    if canonical_sha256(body) != stored_hash:
                        raise ReceiptIntegrityError(f"TCP receipt {receipt_id} hash mismatch")
                    tcp_count += 1
    finally:
        conn.close()
    file_hash = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            file_hash.update(block)
    return {
        "path": str(source), "sqlite_integrity": "ok",
        "evidence_receipts": receipt_count, "tcp_receipts": tcp_count,
        "database_sha256": "sha256:" + file_hash.hexdigest(),
    }


def backup_database(source: str | Path, destination: str | Path) -> dict[str, Any]:
    """Create a consistent SQLite online backup without replacing any file."""
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    if source_path == destination_path:
        raise ValueError("backup destination must differ from source database")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination_path.exists():
        raise FileExistsError(destination_path)
    temporary = destination_path.with_name(
        f".{destination_path.name}.{uuid.uuid4().hex}.partial"
    )
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    try:
        src = _readonly_connection(source_path)
        try:
            dst = sqlite3.connect(temporary)
            try:
                dst.execute("PRAGMA journal_mode=DELETE")
                dst.execute("PRAGMA synchronous=FULL")
                src.backup(dst)
                dst.commit()
            finally:
                dst.close()
        finally:
            src.close()
        os.chmod(temporary, 0o600)
        result = verify_database(temporary)
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        # Hard-link publishes atomically and fails if a competing file appeared.
        os.link(temporary, destination_path)
        temporary.unlink()
        if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(destination_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        result["path"] = str(destination_path)
        return result
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def restore_database(backup: str | Path, destination: str | Path) -> dict[str, Any]:
    """Restore a verified backup to a new path; never overwrite a database."""
    verify_database(backup)
    return backup_database(backup, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("source")
    backup_parser.add_argument("destination")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("database")
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("backup")
    restore_parser.add_argument("destination")
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            result = backup_database(args.source, args.destination)
        elif args.command == "verify":
            result = verify_database(args.database)
        else:
            result = restore_database(args.backup, args.destination)
    except (OSError, ValueError, sqlite3.Error, ReceiptIntegrityError) as exc:
        print(f"backup operation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
