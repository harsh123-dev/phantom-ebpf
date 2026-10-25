"""Fail-closed contract oracle over independently collected observations.

This module does not collect observations or authenticate their producers. It
rejects PHANTOM-derived sources and evaluates independently supplied evidence
against an explicit behavioral-contract snapshot. A live oracle remains
unavailable until an independent collector supplies authenticated records.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping

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

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_references"] = list(self.evidence_references)
        result["reasons"] = list(self.reasons)
        result["independence_basis"] = list(self.independence_basis)
        return result


def canonical_sha256(value: Mapping[str, Any]) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
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
) -> OracleResult:
    return OracleResult(
        run_id=run_id, scenario_id=scenario_id, contract_id=contract_id,
        contract_version=contract_version, workload=dict(workload),
        expected_state=expected_state, observed_state="unknown", outcome="unknown",
        assessed_at=datetime.now().astimezone().isoformat(), evidence_references=(),
        reasons=(reason,), independence_basis=(),
    )


def evaluate_contract(
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
