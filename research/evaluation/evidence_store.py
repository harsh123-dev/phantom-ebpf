"""Append-only durable evidence receipt store backed by SQLite.

SQLite FULL synchronous commits provide process-restart persistence. SHA-256
detects accidental payload corruption; it does not establish authenticity or
prove that the submitted oracle evidence was independent.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from research.evaluation.oracle import canonical_sha256, is_approved_independent_source


class ReceiptConflictError(ValueError):
    """An idempotency key was reused for different evidence."""


class ReceiptIntegrityError(ValueError):
    """A stored receipt failed canonical hash verification."""


def _aware_timestamp(value: Any) -> str:  # noqa: ANN401
    if not isinstance(value, str):
        raise ValueError("receipt timestamp must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("receipt timestamp is invalid") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("receipt timestamp must include a timezone")
    return dt.isoformat()


def validate_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema_version", "receipt_id", "run_id", "scenario_id", "event_id",
        "created_at", "workload", "oracle_result", "evidence_references",
        "processing_outcome", "provenance",
    }
    extra = sorted(set(value) - allowed)
    if extra:
        raise ValueError(f"receipt contains unsupported fields: {', '.join(extra)}")
    required = ("schema_version", "run_id", "scenario_id", "created_at", "workload",
                "oracle_result", "evidence_references", "processing_outcome", "provenance")
    missing = [key for key in required if key not in value]
    if missing:
        raise ValueError(f"receipt missing required fields: {', '.join(missing)}")
    if value["schema_version"] != "1.0":
        raise ValueError("unsupported receipt schema_version")
    for field in ("run_id", "scenario_id", "processing_outcome"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ValueError(f"{field} must be a nonempty string")
    event_id = value.get("event_id")
    if event_id is not None:
        try:
            event_id = str(uuid.UUID(str(event_id)))
        except ValueError as exc:
            raise ValueError("event_id must be a UUID when present") from exc
    oracle = value["oracle_result"]
    if not isinstance(oracle, Mapping) or oracle.get("outcome") not in {
        "confirmed_violation", "confirmed_compliance", "unknown"
    }:
        raise ValueError("oracle_result must contain a recognized explicit outcome")
    oracle_required = {
        "contract_id", "contract_version", "workload", "expected_state",
        "observed_state", "outcome", "assessed_at", "evidence_references",
        "reasons", "independence_basis",
    }
    if not oracle_required.issubset(oracle):
        raise ValueError("oracle_result is missing required state, timestamp, or provenance fields")
    if oracle.get("run_id") != value["run_id"] or oracle.get("scenario_id") != value["scenario_id"]:
        raise ValueError("receipt and oracle run/scenario identities must match")
    refs = oracle.get("evidence_references", [])
    if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
        raise ValueError("oracle evidence_references must be a list of nonempty strings")
    receipt_refs = value["evidence_references"]
    if not isinstance(receipt_refs, list) or receipt_refs != refs:
        raise ValueError("receipt references must match the oracle evidence references")
    outcome_state = {
        "confirmed_violation": "violating",
        "confirmed_compliance": "conforming",
        "unknown": "unknown",
    }
    if oracle["observed_state"] != outcome_state[oracle["outcome"]]:
        raise ValueError("oracle outcome and observed_state disagree")
    if not isinstance(oracle["workload"], Mapping):
        raise ValueError("oracle workload identity must be an object")
    if not isinstance(oracle["reasons"], list) or not oracle["reasons"]:
        raise ValueError("oracle result requires an explanation")
    if not isinstance(oracle["independence_basis"], list):
        raise ValueError("oracle independence_basis must be a list")
    if any(not is_approved_independent_source(source) for source in oracle["independence_basis"]):
        raise ValueError("oracle independence basis contains an unapproved or detector-derived source")
    if oracle["outcome"] != "unknown":
        if not refs or not oracle["independence_basis"]:
            raise ValueError("confirmed oracle outcomes require independent evidence references")
        if not isinstance(oracle.get("contract_id"), str) or not isinstance(oracle.get("contract_version"), str):
            raise ValueError("confirmed oracle outcomes require a contract identity")
        if oracle.get("expected_state") != "conforming":
            raise ValueError("confirmed oracle outcome requires a conforming contract expectation")
        if oracle.get("expected_state") != "conforming":
            raise ValueError("confirmed oracle outcome requires a conforming contract expectation")
    _aware_timestamp(oracle["assessed_at"])
    provenance = value["provenance"]
    workload = value.get("workload", {})
    if not isinstance(provenance, Mapping) or not isinstance(workload, Mapping):
        raise ValueError("provenance and workload must be objects")
    receipt_id = value.get("receipt_id")
    if receipt_id is not None:
        try:
            receipt_id = str(uuid.UUID(str(receipt_id)))
        except ValueError as exc:
            raise ValueError("receipt_id must be a UUID when present") from exc
    normalized = dict(value)
    normalized["receipt_id"] = receipt_id
    normalized["event_id"] = event_id
    normalized["created_at"] = _aware_timestamp(value["created_at"])
    normalized["evidence_references"] = list(refs)
    return normalized


class DurableEvidenceSink:
    """Write-once receipts, idempotent on run/scenario/event identity."""

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                os.chmod(candidate, 0o600)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @staticmethod
    def _key(payload: Mapping[str, Any]) -> str:
        identity = {
            "run_id": payload["run_id"], "scenario_id": payload["scenario_id"],
            "event_id": payload.get("event_id"),
        }
        return canonical_sha256(identity)

    def submit(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        payload = validate_receipt(receipt)
        key = self._key(payload)
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
        if payload["receipt_id"] not in (None, expected_id):
            # Caller-specified identifiers remain accepted only when stable for
            # this logical evidence item, preventing retry divergence.
            raise ValueError("receipt_id does not match deterministic receipt identity")
        payload["receipt_id"] = expected_id
        body = {k: v for k, v in payload.items() if k != "integrity_sha256"}
        serialized = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = canonical_sha256(body)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT receipt_id,payload_json,payload_sha256 FROM evidence_receipts WHERE idempotency_key=?",
                (key,),
            ).fetchone()
            if row:
                if row["payload_sha256"] != digest or row["payload_json"] != serialized:
                    conn.rollback()
                    raise ReceiptConflictError("run/scenario/event already has different evidence")
                conn.commit()
                return self.get(row["receipt_id"])
            try:
                conn.execute(
                    "INSERT INTO evidence_receipts VALUES(?,?,?,?,?)",
                    (expected_id, key, serialized, digest, payload["created_at"]),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise ReceiptConflictError("receipt identity conflicts with existing evidence") from exc
        return self.get(expected_id)

    def get(self, receipt_id: str) -> dict[str, Any]:
        normalized_id = str(uuid.UUID(receipt_id))
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json,payload_sha256 FROM evidence_receipts WHERE receipt_id=?",
                (normalized_id,),
            ).fetchone()
        if row is None:
            raise KeyError(normalized_id)
        payload = json.loads(row["payload_json"])
        actual = canonical_sha256(payload)
        if actual != row["payload_sha256"]:
            raise ReceiptIntegrityError("stored receipt payload hash does not match")
        payload["integrity_sha256"] = actual
        return payload

    def list_run(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT receipt_id FROM evidence_receipts WHERE json_extract(payload_json,'$.run_id')=? ORDER BY created_at,receipt_id",
                (run_id,),
            ).fetchall()
        return [self.get(row["receipt_id"]) for row in rows]


def receipt_for_run(
    *, run_id: str, scenario_id: str, workload: Mapping[str, Any],
    oracle_result: Mapping[str, Any], processing_outcome: str,
    evidence_references: list[str], provenance: Mapping[str, Any],
    event_id: str | None = None, created_at: str | None = None,
) -> dict[str, Any]:
    """Build a versioned receipt payload without turning unknown into negative."""
    from datetime import UTC

    return {
        "schema_version": "1.0", "receipt_id": None, "run_id": run_id,
        "scenario_id": scenario_id, "event_id": event_id,
        "created_at": created_at or datetime.now(UTC).isoformat(),
        "workload": dict(workload), "oracle_result": dict(oracle_result),
        "evidence_references": list(evidence_references),
        "processing_outcome": processing_outcome, "provenance": dict(provenance),
    }


def evaluate_and_persist(
    sink: DurableEvidenceSink, *, run_id: str, scenario_id: str,
    contract: Mapping[str, Any] | None, workload: Mapping[str, Any],
    observations: list[Mapping[str, Any]], interval_complete: bool,
    processing_outcome: str, provenance: Mapping[str, Any],
    event_id: str | None = None,
) -> dict[str, Any]:
    """Run the independent contract evaluator and persist its result atomically
    as an append-only receipt. This composes oracle and durable storage only;
    it does not claim the supplied observation source has been authenticated.
    """
    from research.evaluation.oracle import evaluate_contract

    result = evaluate_contract(
        run_id=run_id, scenario_id=scenario_id, contract=contract,
        workload=workload, observations=observations,
        interval_complete=interval_complete,
    )
    refs = list(result.evidence_references)
    receipt = receipt_for_run(
        run_id=run_id, scenario_id=scenario_id, workload=workload,
        oracle_result=result.to_dict(), processing_outcome=processing_outcome,
        evidence_references=refs, provenance=provenance, event_id=event_id,
    )
    return sink.submit(receipt)


def record_attempt_unknown(
    sink: DurableEvidenceSink, *, run_id: str, scenario_id: str,
    workload: Mapping[str, Any], processing_outcome: str,
    provenance: Mapping[str, Any], event_id: str | None = None,
) -> dict[str, Any]:
    """Persist a scenario attempt when no independent contract evidence exists."""
    return evaluate_and_persist(
        sink, run_id=run_id, scenario_id=scenario_id, contract=None,
        workload=workload, observations=[], interval_complete=False,
        processing_outcome=processing_outcome, provenance=provenance,
        event_id=event_id,
    )
