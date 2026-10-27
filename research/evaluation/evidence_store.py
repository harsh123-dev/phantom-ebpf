"""Append-only durable evidence receipt store backed by SQLite.

SQLite FULL synchronous commits provide process-restart persistence. SHA-256
detects accidental payload corruption; it does not establish authenticity or
prove that the submitted oracle evidence was independent.
"""
from __future__ import annotations

import contextlib

import json
import hashlib
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from research.evaluation.oracle import (
    TrustedOracleKey,
    VerifiedOracleObservation,
    canonical_sha256,
    evaluate_signed_observation,
    is_approved_independent_source,
)


class ReceiptConflictError(ValueError):
    """An idempotency key was reused for different evidence."""


class ReceiptIntegrityError(ValueError):
    """A stored receipt failed canonical hash verification."""


class OracleReplayError(ValueError):
    """A signed oracle observation has already been consumed by another receipt."""


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
        "processing_outcome", "provenance", "oracle_observation", "oracle_verification",
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
    if (isinstance(oracle, Mapping)
            and oracle.get("outcome") in {"confirmed_violation", "confirmed_compliance"}
            and (not isinstance(value.get("oracle_verification"), Mapping)
                 or value["oracle_verification"].get("authenticity_status") != "verified")):
        raise ValueError("confirmed outcomes require a verified signed oracle observation")
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
        verification = value.get("oracle_verification")
        if (not isinstance(verification, Mapping)
                or verification.get("authenticity_status") != "verified"
                or verification.get("independence_status") != "configured_independent"
                or not verification.get("key_id") or not verification.get("observation_id")):
            raise ValueError("confirmed oracle receipt requires verified signature and configured independence")
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consumed_oracle_observations (
                    key_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    PRIMARY KEY(key_id, observation_id),
                    FOREIGN KEY(receipt_id) REFERENCES evidence_receipts(receipt_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tcp_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    peer_address TEXT NOT NULL,
                    peer_port INTEGER NOT NULL,
                    bytes_received INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oracle_trust_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    trust_store_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    active_key_ids_json TEXT NOT NULL,
                    revoked_key_ids_json TEXT NOT NULL
                )
            """)
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists() and os.name != "nt":
                os.chmod(candidate, 0o600)

    @contextlib.contextmanager
    def _connect(self):
        previous_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=10000")
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(str(self.path) + suffix)
                if candidate.exists() and os.name != "nt":
                    os.chmod(candidate, 0o600)
            try:
                yield conn
            finally:
                conn.close()
        finally:
            os.umask(previous_umask)

    @staticmethod
    def _key(payload: Mapping[str, Any]) -> str:
        identity = {
            "run_id": payload["run_id"], "scenario_id": payload["scenario_id"],
            "event_id": payload.get("event_id"),
        }
        return canonical_sha256(identity)

    @staticmethod
    def _retry_view(payload: Mapping[str, Any]) -> dict[str, Any]:
        """Exclude server-generated receipt/assessment times from retry identity."""
        result = json.loads(json.dumps(payload))
        result.pop("created_at", None)
        oracle = result.get("oracle_result")
        if isinstance(oracle, dict):
            oracle.pop("assessed_at", None)
        return result

    def apply_trust_configuration(self, trust_configuration: Mapping[str, Any]) -> frozenset[str]:
        """Persist monotonic trust generations and irreversible key revocations."""
        trust_store_id = getattr(trust_configuration, "trust_store_id", None)
        generation = getattr(trust_configuration, "generation", None)
        config_sha256 = getattr(trust_configuration, "config_sha256", None)
        configured_revoked = set(getattr(trust_configuration, "revoked_key_ids", ()))
        active_ids = set(trust_configuration)
        if (not trust_store_id or not isinstance(generation, int)
                or not isinstance(config_sha256, str) or not config_sha256.startswith("sha256:")):
            raise ValueError("oracle trust configuration lacks verified generation metadata")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT trust_store_id,generation,config_sha256,active_key_ids_json,"
                "revoked_key_ids_json FROM oracle_trust_state WHERE singleton=1"
            ).fetchone()
            if row is None:
                if active_ids & configured_revoked:
                    conn.rollback()
                    raise ValueError("revoked oracle key cannot be configured active")
                conn.execute(
                    "INSERT INTO oracle_trust_state VALUES(1,?,?,?,?,?)",
                    (trust_store_id, generation, config_sha256,
                     json.dumps(sorted(active_ids)), json.dumps(sorted(configured_revoked))),
                )
                conn.commit()
                return frozenset(configured_revoked)

            if row["trust_store_id"] != trust_store_id:
                conn.rollback()
                raise ValueError("oracle trust_store_id cannot change for an existing receipt database")
            prior_generation = int(row["generation"])
            prior_active = set(json.loads(row["active_key_ids_json"]))
            prior_revoked = set(json.loads(row["revoked_key_ids_json"]))
            if generation < prior_generation:
                conn.rollback()
                raise ValueError("oracle trust configuration rollback is rejected")
            if generation == prior_generation:
                if config_sha256 != row["config_sha256"]:
                    conn.rollback()
                    raise ValueError("oracle trust configuration changed without a generation increment")
                conn.commit()
                return frozenset(prior_revoked | configured_revoked)

            removed_without_revocation = prior_active - active_ids - configured_revoked
            if removed_without_revocation:
                conn.rollback()
                raise ValueError(
                    "removed oracle keys must be explicitly listed in revoked_key_ids"
                )
            all_revoked = prior_revoked | configured_revoked
            if active_ids & all_revoked:
                conn.rollback()
                raise ValueError("a previously revoked oracle key cannot be reactivated")
            conn.execute(
                "UPDATE oracle_trust_state SET generation=?,config_sha256=?,"
                "active_key_ids_json=?,revoked_key_ids_json=? WHERE singleton=1",
                (generation, config_sha256, json.dumps(sorted(active_ids)),
                 json.dumps(sorted(all_revoked))),
            )
            conn.commit()
            return frozenset(all_revoked)

    def submit(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        payload = validate_receipt(receipt)
        if payload["oracle_result"]["outcome"] != "unknown":
            raise ValueError("confirmed outcomes must be submitted with a verified signed observation")
        return self._persist(payload, verified_observation=None)

    def submit_signed_observation(
        self, *, run_id: str, scenario_id: str, workload: Mapping[str, Any],
        processing_outcome: str, provenance: Mapping[str, Any],
        signed_observation: Mapping[str, Any],
        trusted_keys: Mapping[str, TrustedOracleKey],
        expected_event_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Authenticate, evaluate, replay-protect, and persist one source statement."""
        oracle_result, verified = evaluate_signed_observation(
            signed_observation, trusted_keys,
            expected_run_id=run_id, expected_scenario_id=scenario_id,
            expected_workload=workload, now=now,
        )
        event_id = str(verified.payload["event_id"])
        if expected_event_id is not None and event_id != str(expected_event_id):
            raise ValueError("signed observation event_id does not match receipt event_id")
        oracle_record = oracle_result.to_dict()
        # Bind deterministic receipt timestamps to the signed observation so
        # a byte-identical retry remains idempotent after a service restart.
        oracle_record["assessed_at"] = verified.payload["observed_at"]
        receipt = receipt_for_run(
            run_id=run_id, scenario_id=scenario_id, workload=workload,
            oracle_result=oracle_record, processing_outcome=processing_outcome,
            evidence_references=list(oracle_result.evidence_references), provenance=provenance,
            event_id=event_id, created_at=verified.payload["observed_at"],
        )
        receipt["oracle_observation"] = dict(signed_observation)
        receipt["oracle_verification"] = {
            "authenticity_status": oracle_result.authenticity_status,
            "independence_status": oracle_result.independence_status,
            "key_id": verified.key_id,
            "observation_id": str(verified.payload["observation_id"]),
            "source_id": verified.source_id,
            "source_type": verified.source_type,
            "payload_sha256": verified.payload_sha256,
            "signature_sha256": verified.signature_sha256,
        }
        payload = validate_receipt(receipt)
        return self._persist(payload, verified_observation=verified)

    def _persist(
        self, payload: dict[str, Any],
        verified_observation: VerifiedOracleObservation | None,
    ) -> dict[str, Any]:
        key = self._key(payload)
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
        if payload["receipt_id"] not in (None, expected_id):
            # Caller-specified identifiers remain accepted only when stable for
            # this logical evidence item, preventing retry divergence.
            raise ValueError("receipt_id does not match deterministic receipt identity")
        payload["receipt_id"] = expected_id
        body = {k: v for k, v in payload.items() if k != "integrity_sha256"}
        serialized = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        )
        digest = canonical_sha256(body)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT receipt_id,payload_json,payload_sha256 FROM evidence_receipts WHERE idempotency_key=?",
                (key,),
            ).fetchone()
            if row:
                existing_payload = json.loads(row["payload_json"])
                same_content = self._retry_view(existing_payload) == self._retry_view(payload)
                if not same_content:
                    conn.rollback()
                    raise ReceiptConflictError("run/scenario/event already has different evidence")
                conn.commit()
                return self.get(row["receipt_id"])
            if verified_observation is not None:
                seen = conn.execute(
                    "SELECT payload_sha256 FROM consumed_oracle_observations "
                    "WHERE key_id=? AND observation_id=?",
                    (verified_observation.key_id, verified_observation.payload["observation_id"]),
                ).fetchone()
                if seen is not None:
                    conn.rollback()
                    raise OracleReplayError("signed oracle observation was already consumed")
            try:
                conn.execute(
                    "INSERT INTO evidence_receipts VALUES(?,?,?,?,?)",
                    (expected_id, key, serialized, digest, payload["created_at"]),
                )
                if verified_observation is not None:
                    conn.execute(
                        "INSERT INTO consumed_oracle_observations VALUES(?,?,?,?)",
                        (verified_observation.key_id,
                         verified_observation.payload["observation_id"],
                         verified_observation.payload_sha256, expected_id),
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

    def record_tcp_connection(
        self, *, local_port: int, peer_address: str, peer_port: int,
        content: bytes,
    ) -> dict[str, Any]:
        """Persist a passive TCP receipt; run/scenario identity stays unknown."""
        import ipaddress
        from datetime import UTC

        if not isinstance(local_port, int) or not 1 <= local_port <= 65535:
            raise ValueError("local_port is invalid")
        if not isinstance(peer_port, int) or not 0 <= peer_port <= 65535:
            raise ValueError("peer_port is invalid")
        try:
            peer = str(ipaddress.ip_address(peer_address))
        except ValueError as exc:
            raise ValueError("peer_address must be an IP address") from exc
        if not isinstance(content, bytes):
            raise ValueError("content must be bytes")
        receipt_id = str(uuid.uuid4())
        created = datetime.now(UTC).isoformat()
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        receipt_body = {
            "receipt_id": receipt_id, "created_at": created, "local_port": local_port,
            "peer_address": peer, "peer_port": peer_port,
            "bytes_received": len(content), "content_sha256": digest,
        }
        receipt_hash = canonical_sha256(receipt_body)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tcp_receipts VALUES(?,?,?,?,?,?,?,?)",
                (receipt_id, created, local_port, peer, peer_port, len(content), digest, receipt_hash),
            )
            conn.commit()
        return self.get_tcp_connection(receipt_id)

    def get_tcp_connection(self, receipt_id: str) -> dict[str, Any]:
        normalized_id = str(uuid.UUID(receipt_id))
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tcp_receipts WHERE receipt_id=?", (normalized_id,),
            ).fetchone()
        if row is None:
            raise KeyError(normalized_id)
        result = dict(row)
        receipt_hash = result.pop("receipt_sha256")
        if canonical_sha256(result) != receipt_hash:
            raise ReceiptIntegrityError("stored TCP receipt hash does not match")
        result["integrity_sha256"] = receipt_hash
        result["run_id"] = None
        result["scenario_id"] = None
        result["outcome"] = "unknown"
        return result

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
    workload: Mapping[str, Any],
    processing_outcome: str, provenance: Mapping[str, Any],
    signed_observation: Mapping[str, Any] | None = None,
    trusted_keys: Mapping[str, TrustedOracleKey] | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Persist only authenticated signed results; unsigned/missing input abstains."""
    if signed_observation is not None:
        if trusted_keys is None:
            raise ValueError("explicit trusted oracle keys are required for signed observations")
        return sink.submit_signed_observation(
            run_id=run_id, scenario_id=scenario_id, workload=workload,
            processing_outcome=processing_outcome, provenance=provenance,
            signed_observation=signed_observation, trusted_keys=trusted_keys,
            expected_event_id=event_id,
        )
    from research.evaluation.oracle import abstain

    result = abstain(
        run_id=run_id, scenario_id=scenario_id, workload=workload,
        reason="no authenticated independent signed oracle observation was supplied",
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
        sink, run_id=run_id, scenario_id=scenario_id, workload=workload,
        processing_outcome=processing_outcome, provenance=provenance,
        event_id=event_id,
    )
