"""Independent scenario-harness attestation adapter.

This module never accepts PHANTOM alerts or causal results. It only signs a
positive observation after scenario-specific direct assertions, a separately
signed contract snapshot, workload/image identity, and evidence references all
validate. The repository does not currently ship a live collector that produces
these assertions; without one, callers must persist an unknown attempt instead.
"""
from __future__ import annotations

import base64
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.evaluation.oracle import (
    TrustedOracleKey,
    canonical_payload_bytes,
    canonical_sha256,
    verify_contract_snapshot_envelope,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class ScenarioPolicy:
    target_service: str
    expected_state: str
    assertion_id: str
    behavior: str


@dataclass(frozen=True)
class HarnessAssertion:
    """Result of an independent, read-only scenario/workload assertion."""

    run_id: str
    scenario_id: str
    event_id: str
    workload: Mapping[str, Any]
    injection_status: str
    assertion_id: str
    assertion_passed: bool
    observed_state: str
    behavior: str
    details: Mapping[str, Any]
    evidence_references: tuple[str, ...]
    contract_envelope: Mapping[str, Any]
    observed_at: str
    interval_complete: bool = False


@dataclass(frozen=True)
class ObserverDecision:
    outcome: str
    reason: str
    signed_observation: Mapping[str, Any] | None = None


def load_observer_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load a key mounted only into an observer process, requiring mode 0600."""
    key_path = Path(path)
    if key_path.is_symlink() or not key_path.is_file():
        raise ValueError("observer signing key must be a regular non-symlink file")
    if os.name != "nt" and (key_path.stat().st_mode & 0o077):
        raise PermissionError("observer signing key must not be group/world accessible")
    loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("observer signing key must use Ed25519")
    return loaded


def load_scenario_policies(path: str | Path) -> dict[str, ScenarioPolicy]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0" or not isinstance(raw.get("scenarios"), dict):
        raise ValueError("scenario oracle policy document is malformed")
    policies: dict[str, ScenarioPolicy] = {}
    for scenario_id, value in raw["scenarios"].items():
        if (not isinstance(scenario_id, str) or not scenario_id
                or not isinstance(value, dict)
                or set(value) != {"target_service", "expected_state", "assertion_id", "behavior"}
                or not isinstance(value["target_service"], str) or not value["target_service"]
                or value["expected_state"] not in {"violating", "conforming"}
                or not isinstance(value["assertion_id"], str) or not value["assertion_id"]
                or value["behavior"] not in {
                    "executable", "file_access", "network_connect", "syscall_class",
                    "privilege_transition", "component_execution",
                }):
            raise ValueError(f"invalid scenario oracle policy for {scenario_id!r}")
        policies[scenario_id] = ScenarioPolicy(**value)
    return policies


def verify_contract_snapshot(
    envelope: Mapping[str, Any], trusted_keys: Mapping[str, TrustedOracleKey],
) -> Mapping[str, Any]:
    """Verify registry-signed contract bytes; never trust a Boolean flag alone."""
    return verify_contract_snapshot_envelope(envelope, trusted_keys)


class ScenarioOracleObserver:
    """Validate independent harness evidence and sign it for the oracle sink.

    Production instantiation must happen in the experiment observer process,
    with its private key mounted separately from the detector and sink. Merely
    using this class in the scenario runner does not make a source independent.
    """

    def __init__(
        self, *, source_id: str, key_id: str, signing_key: Ed25519PrivateKey,
        trusted_contract_keys: Mapping[str, TrustedOracleKey],
        policies: Mapping[str, ScenarioPolicy],
        max_age_seconds: int = 300,
    ):
        if not source_id or not key_id or max_age_seconds < 1:
            raise ValueError("observer identity and freshness window are required")
        self.source_id = source_id
        self.key_id = key_id
        self.signing_key = signing_key
        self.trusted_contract_keys = trusted_contract_keys
        self.policies = dict(policies)
        self.policy_sha256 = canonical_sha256({
            scenario_id: asdict(policy) for scenario_id, policy in sorted(self.policies.items())
        })
        self.max_age_seconds = max_age_seconds

    def observe(self, assertion: HarnessAssertion, *, now: datetime | None = None) -> ObserverDecision:
        """Return a signed observation only for a policy-matched, complete assertion."""
        policy = self.policies.get(assertion.scenario_id)
        if policy is None:
            return ObserverDecision("unknown", "scenario has no approved oracle policy")
        if assertion.injection_status != "succeeded":
            return ObserverDecision("unknown", "scenario injection did not succeed")
        if assertion.assertion_id != policy.assertion_id or assertion.assertion_passed is not True:
            return ObserverDecision("unknown", "required direct harness assertion is missing or failed")
        if assertion.observed_state not in {"violating", "conforming"}:
            return ObserverDecision("unknown", "direct observation did not establish a contract state")
        if assertion.observed_state != policy.expected_state:
            return ObserverDecision("unknown", "direct observation contradicts the scenario's preregistered expected state")
        if (not isinstance(assertion.run_id, str) or not assertion.run_id.strip()
                or not isinstance(assertion.scenario_id, str) or not assertion.scenario_id.strip()):
            return ObserverDecision("unknown", "run or scenario identity is missing")
        try:
            event_id = str(uuid.UUID(assertion.event_id))
        except (TypeError, ValueError):
            return ObserverDecision("unknown", "event identity is invalid")
        if not isinstance(assertion.workload, Mapping):
            return ObserverDecision("unknown", "workload identity is invalid")
        workload = dict(assertion.workload)
        if any(not isinstance(workload.get(field), str) or not workload[field].strip()
               for field in ("cluster", "namespace", "name")):
            return ObserverDecision("unknown", "workload identity is incomplete")
        digest = workload.get("image_digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            return ObserverDecision("unknown", "immutable image identity is unavailable")
        if workload.get("deployment") != policy.target_service:
            return ObserverDecision("unknown", "workload does not match the scenario's configured target")
        refs = list(assertion.evidence_references)
        if not refs or any(not isinstance(ref, str) or not ref.strip() for ref in refs):
            return ObserverDecision("unknown", "direct evidence references are missing")
        try:
            observed = datetime.fromisoformat(assertion.observed_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return ObserverDecision("unknown", "observation timestamp is invalid")
        if observed.tzinfo is None or observed.utcoffset() is None:
            return ObserverDecision("unknown", "observation timestamp lacks timezone")
        current = now or datetime.now(UTC)
        age = (current - observed.astimezone(UTC)).total_seconds()
        if age > self.max_age_seconds or age < -30:
            return ObserverDecision("unknown", "observation is stale or from the future")
        try:
            contract = verify_contract_snapshot(assertion.contract_envelope, self.trusted_contract_keys)
        except ValueError as exc:
            return ObserverDecision("unknown", str(exc))
        selector = contract.get("workload_selector")
        if (contract.get("status") != "active" or contract.get("image_digest") != digest
                or not isinstance(selector, Mapping)
                or selector.get("namespace") != workload["namespace"]
                or selector.get("cluster_name") != workload.get("cluster_name", workload["cluster"])):
            return ObserverDecision("unknown", "verified contract does not identify this workload/image")
        if policy.expected_state == "conforming" and not assertion.interval_complete:
            return ObserverDecision("unknown", "compliance requires a complete independent observation interval")
        if assertion.behavior != policy.behavior or not isinstance(assertion.details, Mapping):
            return ObserverDecision("unknown", "behavior evidence is incomplete")
        payload = {
            "schema_version": "1.0", "observation_id": str(uuid.uuid4()),
            "run_id": assertion.run_id, "scenario_id": assertion.scenario_id,
            "event_id": event_id, "observed_at": observed.astimezone(UTC).isoformat(),
            "workload": workload, "image_digest": digest, "source_id": self.source_id,
            "evidence_references": refs, "behavior": assertion.behavior,
            "details": {
                **dict(assertion.details),
                "_scenario_oracle": {
                    "assertion_id": policy.assertion_id,
                    "expected_outcome": policy.expected_state,
                    "expected_workload": policy.target_service,
                    "policy_sha256": self.policy_sha256,
                },
            },
            "contract_snapshot": {**dict(contract), "signature_verified": True},
            "expected_state": "conforming", "observed_state": assertion.observed_state,
            "interval_complete": assertion.interval_complete,
        }
        envelope = {
            "key_id": self.key_id, "algorithm": "Ed25519",
            "signature": base64.b64encode(
                self.signing_key.sign(canonical_payload_bytes(payload))
            ).decode("ascii"),
            "payload": payload,
        }
        return ObserverDecision(policy.expected_state, "independent assertion and contract signature verified", envelope)


def load_private_key_from_environment() -> Ed25519PrivateKey:
    """Load the observer-only key path; never accept inline private key material."""
    path = os.environ.get("PHANTOM_ORACLE_SIGNING_KEY_FILE")
    if not path:
        raise ValueError("PHANTOM_ORACLE_SIGNING_KEY_FILE is not configured")
    return load_observer_private_key(path)
