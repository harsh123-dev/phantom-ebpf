"""Fail-closed contract oracle over independently collected observations.

This module does not collect observations or authenticate their producers. It
rejects PHANTOM-derived sources and evaluates independently supplied evidence
against an explicit behavioral-contract snapshot. A live oracle remains
unavailable until an independent collector supplies authenticated records.
"""
from __future__ import annotations

import hashlib
import base64
import binascii
import ipaddress
import json
import re
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_FORBIDDEN_SOURCES = {
    "phantom_alert", "phantom_detector", "causal_engine", "pceps",
    "scenario_label", "detector_output", "phantom_api",
}
_ALLOWED_SOURCES = {
    "independent_sink", "kubernetes_audit", "host_audit",
    "independent_runtime_monitor", "external_attestation",
    "verified_contract_registry",
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SIGNED_OBSERVATION_SCHEMA = "1.0"
_SIGNED_PAYLOAD_FIELDS = {
    "schema_version", "observation_id", "run_id", "scenario_id", "event_id",
    "observed_at", "workload", "image_digest", "source_id", "evidence_references",
    "behavior", "details", "contract_snapshot", "expected_state", "observed_state",
    "interval_complete",
}


class OracleVerificationError(ValueError):
    """Base class for rejected signed oracle observations."""


class UnknownOracleKeyError(OracleVerificationError):
    """The signing key is not in the explicitly configured trust store."""


class RevokedOracleKeyError(OracleVerificationError):
    """The signing key was explicitly revoked by the trust administrator."""


class UnsupportedOracleAlgorithmError(OracleVerificationError):
    """The signed observation requests an unsupported signature algorithm."""


class InvalidOracleSignatureError(OracleVerificationError):
    """The signature is malformed or does not match the canonical payload."""


class StaleOracleObservationError(OracleVerificationError):
    """The signed observation is outside the configured freshness window."""


@dataclass(frozen=True)
class TrustedOracleKey:
    key_id: str
    source_id: str
    source_type: str
    public_key: Ed25519PublicKey
    independent_of_phantom: bool


class TrustedOracleKeySet(dict[str, TrustedOracleKey]):
    """Active configured keys plus signed-off trust-store version metadata."""

    def __init__(self, *, trust_store_id: str, generation: int,
                 revoked_key_ids: frozenset[str], config_sha256: str):
        super().__init__()
        self.trust_store_id = trust_store_id
        self.generation = generation
        self.revoked_key_ids = revoked_key_ids
        self.config_sha256 = config_sha256


@dataclass(frozen=True)
class VerifiedOracleObservation:
    payload: Mapping[str, Any]
    key_id: str
    source_id: str
    source_type: str
    independent_of_phantom: bool
    signature_sha256: str
    payload_sha256: str
    contract_snapshot_verified: bool


def load_trusted_oracle_keys(path: str | Path) -> dict[str, TrustedOracleKey]:
    """Load explicitly provisioned Ed25519 public keys from a JSON trust file.

    The file contains ``schema_version``, ``trust_store_id``, monotonically
    increasing ``generation``, ``keys``, and ``revoked_key_ids``. Incoming
    observations never contribute trust anchors. Private key PEM is rejected.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    required_config = {"schema_version", "trust_store_id", "generation", "keys", "revoked_key_ids"}
    if not isinstance(raw, dict) or set(raw) != required_config:
        raise ValueError("oracle trust file has invalid configuration fields")
    if raw["schema_version"] != "1.0":
        raise ValueError("unsupported oracle trust configuration schema")
    if (not isinstance(raw["trust_store_id"], str) or not raw["trust_store_id"].strip()
            or not isinstance(raw["generation"], int) or isinstance(raw["generation"], bool)
            or raw["generation"] < 1 or not isinstance(raw["keys"], list)):
        raise ValueError("oracle trust store identity, generation, or keys are invalid")
    revoked = raw["revoked_key_ids"]
    if (not isinstance(revoked, list) or any(not isinstance(k, str) or not k.strip() for k in revoked)
            or len(revoked) != len(set(revoked))):
        raise ValueError("revoked_key_ids must be a unique list of nonempty key IDs")
    config = TrustedOracleKeySet(
        trust_store_id=raw["trust_store_id"], generation=raw["generation"],
        revoked_key_ids=frozenset(revoked), config_sha256=canonical_sha256(raw),
    )
    result = config
    for item in raw["keys"]:
        if not isinstance(item, dict) or set(item) != {
            "key_id", "source_id", "source_type", "public_key_pem", "independent_of_phantom"
        }:
            raise ValueError("trusted oracle key entry has invalid fields")
        if (not isinstance(item["source_type"], str)
                or item["source_type"] not in _ALLOWED_SOURCES
                or item["source_type"] in _FORBIDDEN_SOURCES):
            raise ValueError("trusted key source_type is not an approved independent source")
        pem = item["public_key_pem"]
        if not isinstance(pem, str) or "PRIVATE KEY" in pem:
            raise ValueError("trust store accepts public keys only")
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("only Ed25519 public keys are supported")
        key_id, source_id = item["key_id"], item["source_id"]
        if (not isinstance(key_id, str) or not key_id or not isinstance(source_id, str)
                or not source_id or not isinstance(item["independent_of_phantom"], bool)):
            raise ValueError("trusted key identity and independence setting are invalid")
        if key_id in result:
            raise ValueError("duplicate trusted oracle key_id")
        result[key_id] = TrustedOracleKey(
            key_id=key_id, source_id=source_id, source_type=item["source_type"],
            public_key=key, independent_of_phantom=item["independent_of_phantom"],
        )
    if set(result).intersection(config.revoked_key_ids):
        raise ValueError("revoked oracle key IDs cannot also be active")
    return result


def canonical_payload_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes signed by the oracle source."""
    try:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OracleVerificationError("signed payload is not canonical JSON data") from exc


def verify_contract_snapshot_envelope(
    envelope: Mapping[str, Any], trusted_keys: Mapping[str, TrustedOracleKey],
) -> dict[str, Any]:
    """Verify a separately signed contract-registry snapshot.

    The registry key is distinct by trust-store source type. A caller-supplied
    `signature_verified` Boolean is never accepted as a substitute.
    """
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "key_id", "algorithm", "signature", "payload"
    } or envelope.get("algorithm") != "Ed25519":
        raise OracleVerificationError("contract snapshot envelope is malformed or unsupported")
    key_id = envelope.get("key_id")
    revoked = getattr(trusted_keys, "revoked_key_ids", frozenset())
    if isinstance(key_id, str) and key_id in revoked:
        raise RevokedOracleKeyError("contract registry key has been revoked")
    trusted = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if trusted is None or trusted.source_type != "verified_contract_registry":
        raise UnknownOracleKeyError("contract snapshot key is not a trusted registry key")
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping) or "signature_verified" in payload or "registry_attestation" in payload:
        raise OracleVerificationError("contract snapshot payload contains invalid verification metadata")
    signature_text = envelope.get("signature")
    if not isinstance(signature_text, str):
        raise InvalidOracleSignatureError("contract registry signature must be base64 text")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        trusted.public_key.verify(signature, canonical_payload_bytes(payload))
    except (binascii.Error, InvalidSignature, OracleVerificationError) as exc:
        raise InvalidOracleSignatureError("contract registry signature verification failed") from exc
    return {
        **dict(payload), "signature_verified": True,
        "registry_attestation": {
            "key_id": trusted.key_id, "algorithm": "Ed25519", "signature": signature_text,
        },
    }


def _verify_nested_contract_attestation(
    contract: Mapping[str, Any], trusted_keys: Mapping[str, TrustedOracleKey],
) -> bool:
    attestation = contract.get("registry_attestation")
    if not isinstance(attestation, Mapping) or set(attestation) != {"key_id", "algorithm", "signature"}:
        return False
    key_id = attestation.get("key_id")
    revoked = getattr(trusted_keys, "revoked_key_ids", frozenset())
    if isinstance(key_id, str) and key_id in revoked:
        raise RevokedOracleKeyError("contract registry key has been revoked")
    trusted = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if trusted is None or trusted.source_type != "verified_contract_registry":
        raise UnknownOracleKeyError("contract snapshot registry key is not trusted")
    if attestation.get("algorithm") != "Ed25519" or contract.get("signature_verified") is not True:
        raise OracleVerificationError("contract snapshot verification metadata is invalid")
    signed_contract = {
        key: value for key, value in contract.items()
        if key not in {"signature_verified", "registry_attestation"}
    }
    try:
        signature = base64.b64decode(attestation["signature"], validate=True)
        trusted.public_key.verify(signature, canonical_payload_bytes(signed_contract))
    except (KeyError, binascii.Error, InvalidSignature, OracleVerificationError) as exc:
        raise InvalidOracleSignatureError("embedded contract registry signature is invalid") from exc
    return True


def verify_signed_observation(
    envelope: Mapping[str, Any], trusted_keys: Mapping[str, TrustedOracleKey], *,
    now: datetime | None = None, max_age_seconds: int = 300, future_skew_seconds: int = 30,
) -> VerifiedOracleObservation:
    """Verify envelope shape, configured Ed25519 trust, payload and freshness."""
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "key_id", "algorithm", "signature", "payload"
    }:
        raise OracleVerificationError("signed observation envelope has invalid fields")
    if envelope["algorithm"] != "Ed25519":
        raise UnsupportedOracleAlgorithmError("only Ed25519 signatures are supported")
    key_id = envelope["key_id"]
    revoked = getattr(trusted_keys, "revoked_key_ids", frozenset())
    if isinstance(key_id, str) and key_id in revoked:
        raise RevokedOracleKeyError("oracle key_id has been revoked")
    trusted = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if trusted is None:
        raise UnknownOracleKeyError("oracle key_id is not configured as trusted")
    if not is_approved_independent_source(trusted.source_type):
        raise OracleVerificationError("configured key source is not an approved independent source")
    payload = envelope["payload"]
    if not isinstance(payload, Mapping) or set(payload) != _SIGNED_PAYLOAD_FIELDS:
        raise OracleVerificationError("signed observation payload has missing or extra fields")
    if payload.get("schema_version") != SIGNED_OBSERVATION_SCHEMA:
        raise OracleVerificationError("unsupported signed observation schema")
    if payload.get("source_id") != trusted.source_id:
        raise OracleVerificationError("signed source identity does not match configured key owner")
    try:
        observation_id = str(uuid.UUID(str(payload["observation_id"])))
        event_id = str(uuid.UUID(str(payload["event_id"])))
    except (ValueError, TypeError) as exc:
        raise OracleVerificationError("observation_id and event_id must be UUIDs") from exc
    for field in ("run_id", "scenario_id", "source_id", "behavior"):
        if not isinstance(payload[field], str) or not payload[field]:
            raise OracleVerificationError(f"{field} must be a nonempty string")
    if not isinstance(payload["workload"], Mapping) or not isinstance(payload["details"], Mapping):
        raise OracleVerificationError("workload and details must be objects")
    if any(not isinstance(payload["workload"].get(field), str)
           or not payload["workload"][field].strip()
           for field in ("cluster", "namespace", "name")):
        raise OracleVerificationError("signed workload identity is incomplete")
    if not isinstance(payload["contract_snapshot"], Mapping):
        raise OracleVerificationError("signed contract_snapshot must be an object")
    if payload["workload"].get("image_digest") != payload["image_digest"]:
        raise OracleVerificationError("signed workload/image identities disagree")
    if not _DIGEST.fullmatch(str(payload["image_digest"])):
        raise OracleVerificationError("signed image_digest must be immutable sha256")
    refs = payload["evidence_references"]
    if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
        raise OracleVerificationError("evidence_references must be nonempty strings")
    if payload["expected_state"] != "conforming" or payload["observed_state"] not in {
        "violating", "conforming", "unknown"
    } or not isinstance(payload["interval_complete"], bool):
        raise OracleVerificationError("signed contract states are invalid")
    timestamp = payload["observed_at"]
    if not isinstance(timestamp, str):
        raise OracleVerificationError("signed observation timestamp must be text")
    try:
        observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError as exc:
        raise OracleVerificationError("signed observation timestamp is invalid") from exc
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise OracleVerificationError("signed observation timestamp must include timezone")
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("verification clock must be timezone-aware")
    age = (current - observed.astimezone(UTC)).total_seconds()
    if age > max_age_seconds or age < -future_skew_seconds:
        raise StaleOracleObservationError("signed oracle observation is stale or from the future")
    signature_text = envelope["signature"]
    if not isinstance(signature_text, str):
        raise InvalidOracleSignatureError("signature must be base64 text")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        signed_bytes = canonical_payload_bytes(payload)
        trusted.public_key.verify(signature, signed_bytes)
    except (binascii.Error, InvalidSignature, OracleVerificationError) as exc:
        raise InvalidOracleSignatureError("Ed25519 signature verification failed") from exc
    contract_snapshot_verified = _verify_nested_contract_attestation(
        payload["contract_snapshot"], trusted_keys,
    )
    normalized_payload = dict(payload)
    normalized_payload["observation_id"] = observation_id
    normalized_payload["event_id"] = event_id
    return VerifiedOracleObservation(
        payload=normalized_payload, key_id=trusted.key_id, source_id=trusted.source_id,
        source_type=trusted.source_type,
        independent_of_phantom=trusted.independent_of_phantom,
        signature_sha256="sha256:" + hashlib.sha256(signature).hexdigest(),
        payload_sha256="sha256:" + hashlib.sha256(signed_bytes).hexdigest(),
        contract_snapshot_verified=contract_snapshot_verified,
    )


def is_approved_independent_source(value: Any) -> bool:  # noqa: ANN401
    return isinstance(value, str) and value in _ALLOWED_SOURCES and value.lower() not in _FORBIDDEN_SOURCES


@dataclass(frozen=True)
class OracleObservation:
    run_id: str
    scenario_id: str
    workload: Mapping[str, Any]
    event_id: str
    observed_at: str
    image_digest: str
    source: str
    evidence_reference: str
    behavior: str
    details: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OracleObservation":
        required = ("run_id", "scenario_id", "workload", "event_id", "observed_at", "image_digest",
                    "source", "evidence_reference", "behavior", "details")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"observation missing required fields: {', '.join(missing)}")
        string_fields = ("run_id", "scenario_id", "event_id", "observed_at", "image_digest",
                         "source", "evidence_reference", "behavior")
        if not all(isinstance(value[key], str) and value[key] for key in string_fields):
            raise ValueError("observation identity and evidence fields must be nonempty strings")
        if not isinstance(value["details"], Mapping) or not isinstance(value["workload"], Mapping):
            raise ValueError("observation workload and details must be objects")
        if value["source"].lower() in _FORBIDDEN_SOURCES:
            raise ValueError("PHANTOM detector-derived data cannot be oracle evidence")
        if value["source"] not in _ALLOWED_SOURCES:
            raise ValueError("observation source is not an approved independent-source type")
        if not _DIGEST.fullmatch(value["image_digest"]):
            raise ValueError("observation image_digest must be an immutable sha256 digest")
        try:
            observed = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observation timestamp is invalid") from exc
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise ValueError("observation timestamp must include a timezone")
        return cls(**{key: value[key] for key in required})


@dataclass(frozen=True)
class OracleResult:
    run_id: str
    scenario_id: str
    contract_id: str | None
    contract_version: str | None
    workload: Mapping[str, Any]
    expected_state: str
    observed_state: str
    outcome: str
    assessed_at: str
    evidence_references: tuple[str, ...]
    reasons: tuple[str, ...]
    independence_basis: tuple[str, ...]
    authenticity_status: str = "unverified"
    independence_status: str = "unverified"
    observation_ids: tuple[str, ...] = ()
    signature_key_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_references"] = list(self.evidence_references)
        result["reasons"] = list(self.reasons)
        result["independence_basis"] = list(self.independence_basis)
        result["observation_ids"] = list(self.observation_ids)
        result["signature_key_ids"] = list(self.signature_key_ids)
        return result


def canonical_sha256(value: Mapping[str, Any]) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _matches_contract(observation: OracleObservation, constraints: Mapping[str, Any]) -> bool | None:
    """Return True for conforming, False for violating, None if not assessable."""
    details = observation.details
    if observation.behavior == "executable":
        path = details.get("path")
        allowed = constraints.get("allowed_executables")
        if not isinstance(path, str) or not isinstance(allowed, list):
            return None
        return path in allowed
    if observation.behavior == "file_access":
        path = details.get("path")
        prefixes = constraints.get("allowed_file_path_prefixes")
        if not isinstance(path, str) or not isinstance(prefixes, list):
            return None
        return any(path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")
                   for prefix in prefixes if isinstance(prefix, str))
    if observation.behavior == "network_connect":
        protocol, address, port = details.get("protocol"), details.get("address"), details.get("port")
        destinations = constraints.get("allowed_network_destinations")
        if protocol not in ("tcp", "udp") or not isinstance(address, str) or not isinstance(port, int):
            return None
        if not isinstance(destinations, list):
            return None
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        for dest in destinations:
            try:
                network = ipaddress.ip_network(dest["cidr"], strict=False)
                if (dest.get("protocol") == protocol and ip in network
                        and dest.get("port_min", 0) <= port <= dest.get("port_max", -1)):
                    return True
            except (KeyError, TypeError, ValueError):
                continue
        return False
    if observation.behavior == "syscall_class":
        syscall_class = details.get("class")
        allowed = constraints.get("allowed_syscall_classes")
        if not isinstance(syscall_class, str) or not isinstance(allowed, list):
            return None
        return syscall_class in allowed
    if observation.behavior == "privilege_transition":
        changed = details.get("changed")
        allowed = constraints.get("allow_privilege_transition")
        if not isinstance(changed, bool) or not isinstance(allowed, bool):
            return None
        return not changed or allowed
    if observation.behavior == "component_execution":
        status, purl = details.get("binding_status"), details.get("purl")
        allowed = constraints.get("allowed_purls")
        if status != "bound" or not isinstance(purl, str) or not isinstance(allowed, list):
            return None
        return purl in allowed
    return None


def _valid_contract_constraints(value: Any) -> bool:  # noqa: ANN401
    if not isinstance(value, Mapping):
        return False
    list_fields = (
        "allowed_executables", "allowed_file_path_prefixes",
        "allowed_network_destinations", "allowed_syscall_classes", "allowed_purls",
        "allowed_parent_child_pairs",
    )
    if any(not isinstance(value.get(field), list) for field in list_fields):
        return False
    if any(any(not isinstance(item, str) for item in value[field])
           for field in ("allowed_executables", "allowed_file_path_prefixes",
                         "allowed_syscall_classes", "allowed_purls")):
        return False
    if not value["allowed_syscall_classes"] or not isinstance(value.get("allow_privilege_transition"), bool):
        return False
    if not isinstance(value.get("max_new_processes_per_5m"), int) or value["max_new_processes_per_5m"] < 0:
        return False
    for destination in value["allowed_network_destinations"]:
        if not isinstance(destination, Mapping):
            return False
        try:
            if destination.get("protocol") not in ("tcp", "udp"):
                return False
            ipaddress.ip_network(destination["cidr"], strict=False)
            low, high = destination["port_min"], destination["port_max"]
            if not isinstance(low, int) or not isinstance(high, int) or not 1 <= low <= high <= 65535:
                return False
        except (KeyError, TypeError, ValueError):
            return False
    for relation in value["allowed_parent_child_pairs"]:
        if (not isinstance(relation, Mapping)
                or not isinstance(relation.get("parent_executable"), str)
                or not isinstance(relation.get("child_executable"), str)):
            return False
    return True


def abstain(
    *, run_id: str, scenario_id: str, workload: Mapping[str, Any], reason: str,
    contract_id: str | None = None, contract_version: str | None = None,
    expected_state: str = "contract_state_unavailable",
    authenticity_status: str = "unverified", independence_status: str = "unverified",
    observation_ids: tuple[str, ...] = (), signature_key_ids: tuple[str, ...] = (),
) -> OracleResult:
    return OracleResult(
        run_id=run_id, scenario_id=scenario_id, contract_id=contract_id,
        contract_version=contract_version, workload=dict(workload),
        expected_state=expected_state, observed_state="unknown", outcome="unknown",
        assessed_at=datetime.now().astimezone().isoformat(), evidence_references=(),
        reasons=(reason,), independence_basis=(), authenticity_status=authenticity_status,
        independence_status=independence_status, observation_ids=observation_ids,
        signature_key_ids=signature_key_ids,
    )


def _classify_contract_observations(
    *, run_id: str, scenario_id: str, contract: Mapping[str, Any] | None,
    workload: Mapping[str, Any], observations: list[Mapping[str, Any]],
    interval_complete: bool,
) -> OracleResult:
    """Evaluate independent evidence against one immutable contract snapshot.

    A violating observation is sufficient to establish a violation. Compliance
    requires a complete interval and every observation to be assessable. Any
    duplicate event with conflicting content or identity mismatch fails closed.
    """
    if not run_id or not scenario_id:
        raise ValueError("run_id and scenario_id are required")
    if contract is None:
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="no independently verified contract snapshot is available")
    contract_id, version = contract.get("contract_id"), contract.get("contract_version")
    digest = contract.get("image_digest")
    constraints = contract.get("constraints")
    contract_reference = contract.get("verification_reference")
    if (not isinstance(contract_id, str) or not contract_id
            or not isinstance(version, str) or not version
            or not isinstance(contract_reference, str) or not contract_reference
            or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            or not _valid_contract_constraints(constraints)
            or contract.get("status") != "active"
            or contract.get("signature_verified") is not True):
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="contract snapshot is not active, signature-verified, or complete")
    if workload.get("image_digest") != digest:
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="workload image digest does not match the contract snapshot",
                       contract_id=contract_id, contract_version=version)
    selector = contract.get("workload_selector")
    if not isinstance(selector, Mapping):
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="contract workload selector is missing",
                       contract_id=contract_id, contract_version=version)
    if (selector.get("cluster_name") != workload.get("cluster")
            or selector.get("namespace") != workload.get("namespace")):
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="workload is outside the contract selector",
                       contract_id=contract_id, contract_version=version)
    labels = selector.get("labels", {})
    observed_labels = workload.get("labels", {})
    if (not isinstance(labels, Mapping) or not isinstance(observed_labels, Mapping)
            or any(observed_labels.get(key) != value for key, value in labels.items())):
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="workload labels do not satisfy the contract selector",
                       contract_id=contract_id, contract_version=version)
    service_account = selector.get("service_account")
    if service_account is not None and service_account != workload.get("service_account"):
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="workload service account does not satisfy the contract selector",
                       contract_id=contract_id, contract_version=version)

    parsed: list[OracleObservation] = []
    seen: dict[str, str] = {}
    for raw in observations:
        try:
            item = OracleObservation.from_mapping(raw)
        except (TypeError, ValueError) as exc:
            return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                           reason=f"invalid or non-independent evidence: {exc}",
                           contract_id=contract_id, contract_version=version)
        identity_fields = ("cluster", "namespace", "name")
        workload_match = all(
            workload.get(field) == item.workload.get(field)
            for field in identity_fields if workload.get(field) is not None
        )
        if (item.run_id != run_id or item.scenario_id != scenario_id
                or item.image_digest != digest or item.workload.get("image_digest") != digest
                or not workload_match):
            return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                           reason="observation identity does not match the requested run, scenario, or image",
                           contract_id=contract_id, contract_version=version)
        fingerprint = canonical_sha256(dict(raw))
        previous = seen.get(item.event_id)
        if previous is not None and previous != fingerprint:
            return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                           reason="contradictory records share an event identity",
                           contract_id=contract_id, contract_version=version)
        seen[item.event_id] = fingerprint
        parsed.append(item)
    if not parsed:
        return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload,
                       reason="no independent observations were supplied",
                       contract_id=contract_id, contract_version=version)

    assessments = [_matches_contract(item, constraints) for item in parsed]
    if False in assessments:
        outcome, state = "confirmed_violation", "violating"
        reasons = ("independent observed behavior violates the applicable contract rule",)
    elif interval_complete and all(item is True for item in assessments):
        outcome, state = "confirmed_compliance", "conforming"
        reasons = ("complete independent observation interval conforms to the contract",)
    else:
        outcome, state = "unknown", "unknown"
        reasons = ("evidence is incomplete or at least one observation cannot be assessed",)

    refs = tuple(sorted({contract_reference, *(item.evidence_reference for item in parsed)}))
    sources = tuple(sorted({"verified_contract_registry", *(item.source for item in parsed)}))
    return OracleResult(
        run_id=run_id, scenario_id=scenario_id, contract_id=contract_id,
        contract_version=version, workload=dict(workload), expected_state="conforming",
        observed_state=state, outcome=outcome,
        assessed_at=datetime.now().astimezone().isoformat(), evidence_references=refs,
        reasons=reasons, independence_basis=sources,
    )


def evaluate_contract(
    *, run_id: str, scenario_id: str, contract: Mapping[str, Any] | None,
    workload: Mapping[str, Any], observations: list[Mapping[str, Any]],
    interval_complete: bool,
) -> OracleResult:
    """Fail-closed compatibility entry point: unsigned observations are unknown."""
    reason = (
        "unsigned observations are not accepted as ground truth"
        if observations else "no authenticated independent observation was supplied"
    )
    return abstain(run_id=run_id, scenario_id=scenario_id, workload=workload, reason=reason)


def evaluate_signed_observation(
    envelope: Mapping[str, Any], trusted_keys: Mapping[str, TrustedOracleKey], *,
    expected_run_id: str, expected_scenario_id: str,
    expected_workload: Mapping[str, Any], now: datetime | None = None,
    max_age_seconds: int = 300, future_skew_seconds: int = 30,
) -> tuple[OracleResult, VerifiedOracleObservation]:
    """Authenticate and evaluate one signed independent behavior observation.

    Cryptographic authenticity is separate from source independence and from
    evidence sufficiency. A valid signature from a key not configured as an
    independent source cannot establish ground truth.
    """
    verified = verify_signed_observation(
        envelope, trusted_keys, now=now,
        max_age_seconds=max_age_seconds, future_skew_seconds=future_skew_seconds,
    )
    payload = verified.payload
    identity = payload["workload"]
    mismatch = (
        payload["run_id"] != expected_run_id
        or payload["scenario_id"] != expected_scenario_id
        or payload["image_digest"] != expected_workload.get("image_digest")
        or any(expected_workload.get(field) != identity.get(field)
               for field in ("cluster", "namespace", "name")
               if expected_workload.get(field) is not None)
    )
    common = {
        "authenticity_status": "verified",
        "independence_status": "configured_independent" if verified.independent_of_phantom
        else "not_established",
        "observation_ids": (str(payload["observation_id"]),),
        "signature_key_ids": (verified.key_id,),
    }
    if mismatch:
        raise OracleVerificationError(
            "signed observation identity does not match the requested run/workload"
        )
    if not verified.independent_of_phantom:
        return abstain(
            run_id=expected_run_id, scenario_id=expected_scenario_id,
            workload=expected_workload,
            reason="signature is authentic but the configured key is not independent of PHANTOM",
            **common,
        ), verified
    refs = payload["evidence_references"]
    if not refs:
        return abstain(
            run_id=expected_run_id, scenario_id=expected_scenario_id,
            workload=expected_workload,
            reason="signed observation has no independent evidence references",
            **common,
        ), verified
    if payload["observed_state"] == "conforming" and not payload["interval_complete"]:
        return abstain(
            run_id=expected_run_id, scenario_id=expected_scenario_id,
            workload=expected_workload,
            reason="signed compliance claim lacks complete observation coverage",
            **common,
        ), verified

    contract = payload["contract_snapshot"]
    if not verified.contract_snapshot_verified:
        result = abstain(
            run_id=expected_run_id, scenario_id=expected_scenario_id,
            workload=expected_workload,
            reason="contract snapshot lacks a separately verified registry signature",
            **common,
        )
        return replace(result, evidence_references=tuple(refs)), verified
    observation = {
        "run_id": payload["run_id"], "scenario_id": payload["scenario_id"],
        "workload": identity, "event_id": payload["event_id"],
        "observed_at": payload["observed_at"], "image_digest": payload["image_digest"],
        "source": verified.source_type, "evidence_reference": refs[0],
        "behavior": payload["behavior"], "details": payload["details"],
    }
    classified = _classify_contract_observations(
        run_id=expected_run_id, scenario_id=expected_scenario_id,
        contract=contract, workload=expected_workload,
        observations=[observation], interval_complete=payload["interval_complete"],
    )
    if classified.observed_state != payload["observed_state"]:
        result = abstain(
            run_id=expected_run_id, scenario_id=expected_scenario_id,
            workload=expected_workload,
            reason="signed observed state conflicts with deterministic contract evaluation",
            contract_id=contract.get("contract_id") if isinstance(contract, Mapping) else None,
            contract_version=contract.get("contract_version") if isinstance(contract, Mapping) else None,
            **common,
        )
        return replace(result, evidence_references=tuple(refs)), verified
    return replace(
        classified,
        evidence_references=tuple(sorted(set(classified.evidence_references) | set(refs))),
        authenticity_status="verified",
        independence_status="configured_independent",
        observation_ids=(str(payload["observation_id"]),),
        signature_key_ids=(verified.key_id,),
        independence_basis=tuple(sorted(set(classified.independence_basis) | {verified.source_type})),
    ), verified
