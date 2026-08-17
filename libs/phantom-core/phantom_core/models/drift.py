"""
phantom_core.models.drift — Pydantic models for drift event ingestion (B.4).

Covers:
- RuntimeEventType
- ProcessIdentity
- WorkloadIdentity
- SbomBinding
- ContractViolation
- RuntimeEvidence
- DriftEventIngestRequest: POST /api/v1/drift-events
- DriftEventRecord: response
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from phantom_core.constants import (
    DIGEST_PATTERN,
    DRIFT_BINDING_CONFIDENCE_MAX,
    DRIFT_BINDING_CONFIDENCE_MIN,
    DRIFT_COMM_MAX_LENGTH,
    DRIFT_CONTAINER_ID_MAX_LENGTH,
    DRIFT_EXECUTABLE_PATH_MAX_LENGTH,
    DRIFT_PURL_MAX_LENGTH,
    DRIFT_VIOLATION_CONFIDENCE_MAX,
    DRIFT_VIOLATION_CONFIDENCE_MIN,
    DRIFT_VIOLATIONS_MAX,
    DRIFT_VIOLATIONS_MIN,
    SCHEMA_VERSION,
)
from phantom_core.models.common import _PhantomBaseModel

# ---------------------------------------------------------------------------
# Literal type aliases
# ---------------------------------------------------------------------------

RuntimeEventType = Literal[
    "exec",
    "file_open",
    "file_write",
    "network_connect",
    "network_accept",
    "privilege_transition",
    "namespace_change",
    "module_load",
]

IdentityStatus = Literal["resolved", "ambiguous", "missing", "stale"]

SeverityLevel = Literal["low", "medium", "high", "critical"]

ViolationType = Literal[
    "unexpected_executable",
    "unexpected_file",
    "unexpected_network",
    "unexpected_syscall_class",
    "unexpected_purl",
    "unexpected_process_relation",
    "privilege_transition",
    "rate_limit",
]

BindingStatus = Literal["resolved", "ambiguous", "missing"]

Architecture = Literal["x86_64", "arm64"]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class ProcessIdentity(_PhantomBaseModel):
    """Process identity evidence captured by the eBPF agent.

    Attributes:
        pid: Thread identifier; > 0.
        tgid: Process identifier; > 0.
        ppid: Parent process identifier; >= 0.
        uid: Effective user ID; >= 0.
        gid: Effective group ID; >= 0.
        comm: Kernel task command string; 1..16 characters.
        executable_path: Observed executable path; 1..4096 characters.
        start_time_ns: Monotonic start time for PID-reuse disambiguation; >= 0.
    """

    pid: int = Field(..., gt=0)
    tgid: int = Field(..., gt=0)
    ppid: int = Field(..., ge=0)
    uid: int = Field(..., ge=0)
    gid: int = Field(..., ge=0)
    comm: str = Field(..., min_length=1, max_length=DRIFT_COMM_MAX_LENGTH)
    executable_path: str = Field(..., min_length=1, max_length=DRIFT_EXECUTABLE_PATH_MAX_LENGTH)
    start_time_ns: int = Field(..., ge=0)


class WorkloadIdentity(_PhantomBaseModel):
    """Kubernetes workload identity resolved from cgroup metadata.

    Attributes:
        cluster_name: Kubernetes cluster name.
        namespace: Pod namespace.
        pod_name: Pod name.
        pod_uid: Kubernetes pod UID.
        container_name: Container name within the pod.
        container_id: CRI container identifier; 1..256 characters.
        image_digest: Container image sha256 digest.
        cgroup_id: Primary cgroup identifier used for identity resolution; >= 0.
        service_account: Kubernetes service account name, if available.
    """

    cluster_name: str = Field(..., min_length=1)
    namespace: str = Field(..., min_length=1)
    pod_name: str = Field(..., min_length=1)
    pod_uid: uuid.UUID
    container_name: str = Field(..., min_length=1)
    container_id: str = Field(..., min_length=1, max_length=DRIFT_CONTAINER_ID_MAX_LENGTH)
    image_digest: str
    cgroup_id: int = Field(..., ge=0)
    service_account: str | None = None

    @field_validator("image_digest", mode="after")
    @classmethod
    def _check_digest(cls, v: str) -> str:
        """Validate image_digest matches sha256:<64 hex> format.

        Args:
            v: The digest string.

        Returns:
            The validated digest string.
        """
        if not re.fullmatch(DIGEST_PATTERN, v):
            raise ValueError(f"image_digest must match {DIGEST_PATTERN!r}")
        return v


class SbomBinding(_PhantomBaseModel):
    """SBOM-to-runtime component binding evidence.

    Attributes:
        sbom_id: UUID of the SBOM record this binding references.
        purl: Package URL of the bound component; 1..2048 characters.
        binding_confidence: Confidence score [0, 1] for this binding.
        binding_status: Whether the binding was resolved, ambiguous, or missing.
    """

    sbom_id: uuid.UUID
    purl: str = Field(..., min_length=1, max_length=DRIFT_PURL_MAX_LENGTH)
    binding_confidence: float = Field(
        ...,
        ge=DRIFT_BINDING_CONFIDENCE_MIN,
        le=DRIFT_BINDING_CONFIDENCE_MAX,
    )
    binding_status: BindingStatus


class ContractViolation(_PhantomBaseModel):
    """A single behavioral contract violation observed at runtime.

    Attributes:
        violation_type: The category of contract rule that was violated.
        expected: The expected value from the contract; None if not applicable.
        observed: The actual observed value that triggered this violation.
        severity: Severity level of this violation.
        confidence: Confidence in this violation classification [0, 1].
    """

    violation_type: ViolationType
    expected: str | None = None
    observed: str = Field(..., min_length=1)
    severity: SeverityLevel
    confidence: float = Field(
        ...,
        ge=DRIFT_VIOLATION_CONFIDENCE_MIN,
        le=DRIFT_VIOLATION_CONFIDENCE_MAX,
    )


class RuntimeEvidence(_PhantomBaseModel):
    """Low-level runtime evidence from the eBPF agent.

    Attributes:
        kernel_timestamp_ns: Monotonic kernel timestamp; >= 0. Not wall clock.
        cpu: CPU ID where the event was captured; >= 0.
        architecture: CPU architecture.
        event_loss_observed: True if ring-buffer loss was observed near this event.
        correlation_id: Optional UUID linking related events across types.
        raw_event_digest: sha256 digest over the normalized raw event bytes.
    """

    kernel_timestamp_ns: int = Field(..., ge=0)
    cpu: int = Field(..., ge=0)
    architecture: Architecture
    event_loss_observed: bool
    correlation_id: uuid.UUID | None = None
    raw_event_digest: str

    @field_validator("raw_event_digest", mode="after")
    @classmethod
    def _check_digest(cls, v: str) -> str:
        """Validate raw_event_digest matches sha256:<64 hex> format.

        Args:
            v: The digest string.

        Returns:
            The validated digest string.
        """
        if not re.fullmatch(DIGEST_PATTERN, v):
            raise ValueError(f"raw_event_digest must match {DIGEST_PATTERN!r}")
        return v


# ---------------------------------------------------------------------------
# POST /api/v1/drift-events
# ---------------------------------------------------------------------------


class DriftEventIngestRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/drift-events``.

    Implements the transactional outbox ingestion contract from the
    handoff document pseudocode (Section 4).

    Attributes:
        schema_version: Always ``"v1"``.
        event_id: Agent-generated stable UUID for idempotency.
        observed_at: UTC timestamp when this event was observed.
        node_name: Kubernetes node name (DNS-label format).
        event_type: Runtime event category.
        process: Process identity evidence.
        workload: Kubernetes workload identity.
        identity_status: Quality of the workload identity resolution.
        sbom_binding: Optional SBOM-to-component binding evidence.
        violations: One or more contract violations; 1..64 items required.
        evidence: Low-level runtime evidence from the eBPF agent.
        agent_sequence: Monotonically increasing agent-local sequence number; >= 0.
        tenant_id: Logical isolation key.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    event_id: uuid.UUID
    observed_at: datetime
    node_name: str = Field(..., min_length=1)
    event_type: RuntimeEventType
    process: ProcessIdentity
    workload: WorkloadIdentity
    identity_status: IdentityStatus
    sbom_binding: SbomBinding | None = None
    violations: list[ContractViolation] = Field(
        ...,
        min_length=DRIFT_VIOLATIONS_MIN,
        max_length=DRIFT_VIOLATIONS_MAX,
    )
    evidence: RuntimeEvidence
    agent_sequence: int = Field(..., ge=0)
    tenant_id: uuid.UUID


class DriftEventRecord(_PhantomBaseModel):
    """Response body for ``POST /api/v1/drift-events``.

    Attributes:
        drift_event_id: Gateway-assigned UUID for this drift observation.
        event_id: The agent-supplied event UUID echoed for correlation.
        bdg_update_id: UUID of the outbox record enqueued for BDG mutation.
        ingestion_status: Whether this event was newly accepted or a known duplicate.
        received_at: UTC timestamp when the gateway accepted this event.
    """

    drift_event_id: uuid.UUID
    event_id: uuid.UUID
    bdg_update_id: uuid.UUID
    ingestion_status: Literal["accepted", "duplicate"]
    received_at: datetime
