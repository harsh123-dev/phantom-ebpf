"""
phantom_core.models.contracts — Pydantic models for behavioral contract API contracts (B.3).

Covers:
- WorkloadSelector: namespace/service-account/label selector
- NetworkDestination: protocol/CIDR/port range
- SyscallClass: allowed syscall class literal
- ProcessRelation: parent-child executable pair
- BehavioralConstraints: full constraint set
- BehavioralContractRegisterRequest: POST /api/v1/contracts
- BehavioralContractRecord: response record
- BehavioralContractDetailResponse: GET /api/v1/contracts/{contract_id}
- ContractListResponse: GET /api/v1/contracts
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import AnyUrl, Field, field_validator, model_validator

from phantom_core.constants import (
    CONTRACT_ALLOWED_EXECUTABLES_MAX,
    CONTRACT_ALLOWED_FILE_PATH_PREFIXES_MAX,
    CONTRACT_ALLOWED_NETWORK_DESTINATIONS_MAX,
    CONTRACT_ALLOWED_PARENT_CHILD_PAIRS_MAX,
    CONTRACT_ALLOWED_PURLS_MAX,
    CONTRACT_ALLOWED_SYSCALL_CLASSES_MAX,
    CONTRACT_ALLOWED_SYSCALL_CLASSES_MIN,
    CONTRACT_CLUSTER_NAME_MAX_LENGTH,
    CONTRACT_EXPECTED_IDENTITY_MAX_LENGTH,
    CONTRACT_EXPECTED_IDENTITY_MIN_LENGTH,
    CONTRACT_MAX_NEW_PROCESSES_PER_5M_MAX,
    CONTRACT_VERSION_PATTERN,
    CONTRACT_WORKLOAD_SELECTOR_LABELS_MAX,
    DIGEST_PATTERN,
    SCHEMA_VERSION,
)
from phantom_core.models.common import _PhantomBaseModel

# ---------------------------------------------------------------------------
# SyscallClass literal type
# ---------------------------------------------------------------------------

SyscallClass = Literal[
    "process",
    "file_read",
    "file_write",
    "network_connect",
    "network_accept",
    "namespace",
    "privilege",
    "module",
]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class NetworkDestination(_PhantomBaseModel):
    """A single allowed network destination for a behavioral contract.

    Attributes:
        protocol: Transport protocol, tcp or udp.
        cidr: Valid IPv4 or IPv6 CIDR notation (e.g. ``"10.0.0.0/8"``).
        port_min: Minimum allowed port number, inclusive; 1..65535.
        port_max: Maximum allowed port number, inclusive; must be >= port_min.
    """

    protocol: Literal["tcp", "udp"]
    cidr: str = Field(..., min_length=1)
    port_min: int = Field(..., ge=1, le=65535)
    port_max: int = Field(..., ge=1, le=65535)

    @field_validator("cidr", mode="after")
    @classmethod
    def _validate_cidr(cls, v: str) -> str:
        """Validate that cidr is a valid IPv4 or IPv6 CIDR network string.

        Args:
            v: The CIDR string.

        Returns:
            The validated CIDR string.

        Raises:
            ValueError: If the string is not valid CIDR notation.
        """
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation: {v!r}") from exc
        return v

    @model_validator(mode="after")
    def _port_range_valid(self) -> NetworkDestination:
        """Validate that port_max >= port_min.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If port_max < port_min.
        """
        if self.port_max < self.port_min:
            raise ValueError(
                f"port_max ({self.port_max}) must be >= port_min ({self.port_min})"
            )
        return self


class ProcessRelation(_PhantomBaseModel):
    """An allowed parent-child executable pair in a behavioral contract.

    Attributes:
        parent_executable: Absolute path of the parent process executable.
        child_executable: Absolute path of the child process executable.
    """

    parent_executable: str = Field(..., min_length=1)
    child_executable: str = Field(..., min_length=1)


class BehavioralConstraints(_PhantomBaseModel):
    """Complete set of behavioral constraints for a signed contract.

    Attributes:
        allowed_executables: Executable paths allowed to exec. Max 1024.
        allowed_file_path_prefixes: File path prefixes accessible without violation. Max 1024.
        allowed_network_destinations: Network destinations reachable without violation. Max 1024.
        allowed_syscall_classes: Syscall classes permitted; 1..128 entries required.
        allowed_purls: Component PURLs that may execute or be loaded. Max 4096.
        allowed_parent_child_pairs: Process parent-child exec relations. Max 1024.
        allow_privilege_transition: Whether uid/gid or capability escalation is allowed.
        max_new_processes_per_5m: Rate limit on new process creation. 0..1,000,000.
    """

    allowed_executables: list[str] = Field(..., max_length=CONTRACT_ALLOWED_EXECUTABLES_MAX)
    allowed_file_path_prefixes: list[str] = Field(
        ..., max_length=CONTRACT_ALLOWED_FILE_PATH_PREFIXES_MAX
    )
    allowed_network_destinations: list[NetworkDestination] = Field(
        ..., max_length=CONTRACT_ALLOWED_NETWORK_DESTINATIONS_MAX
    )
    allowed_syscall_classes: list[SyscallClass] = Field(
        ...,
        min_length=CONTRACT_ALLOWED_SYSCALL_CLASSES_MIN,
        max_length=CONTRACT_ALLOWED_SYSCALL_CLASSES_MAX,
    )
    allowed_purls: list[str] = Field(..., max_length=CONTRACT_ALLOWED_PURLS_MAX)
    allowed_parent_child_pairs: list[ProcessRelation] = Field(
        ..., max_length=CONTRACT_ALLOWED_PARENT_CHILD_PAIRS_MAX
    )
    allow_privilege_transition: bool
    max_new_processes_per_5m: int = Field(..., ge=0, le=CONTRACT_MAX_NEW_PROCESSES_PER_5M_MAX)


class WorkloadSelector(_PhantomBaseModel):
    """Kubernetes workload scope selector for a behavioral contract.

    Attributes:
        cluster_name: Kubernetes cluster name; 1..253 characters.
        namespace: Kubernetes namespace (DNS-label format).
        service_account: Optional service account name scoping.
        labels: Pod label selector key-value pairs; max 32 entries.
    """

    cluster_name: str = Field(..., min_length=1, max_length=CONTRACT_CLUSTER_NAME_MAX_LENGTH)
    namespace: str = Field(..., min_length=1, pattern=r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
    service_account: str | None = None
    labels: dict[str, str] = Field(
        default_factory=dict, max_length=CONTRACT_WORKLOAD_SELECTOR_LABELS_MAX
    )


# ---------------------------------------------------------------------------
# POST /api/v1/contracts
# ---------------------------------------------------------------------------


class BehavioralContractRegisterRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/contracts``.

    Registers a signed behavioral contract without activating it until
    signature verification succeeds.

    Attributes:
        schema_version: Always ``"v1"``.
        image_digest: sha256 digest of the associated container image.
        sbom_id: UUID of the associated SBOM record.
        workload_selector: Kubernetes workload scope.
        constraints: Full behavioral constraint set.
        valid_from: UTC datetime from which this contract is valid.
        valid_until: Optional UTC expiry datetime; must be later than valid_from.
        contract_version: Semantic version string matching ``^[0-9]+\\.[0-9]+\\.[0-9]+$``.
        signature_bundle_uri: https or s3 URI of the cosign signature bundle.
        expected_signing_identity: Expected Fulcio signing identity; 1..512 chars.
        expected_issuer: Expected OIDC issuer URI.
        tenant_id: Logical isolation key.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    image_digest: str
    sbom_id: uuid.UUID
    workload_selector: WorkloadSelector
    constraints: BehavioralConstraints
    valid_from: datetime
    valid_until: datetime | None = None
    contract_version: str = Field(..., pattern=CONTRACT_VERSION_PATTERN)
    signature_bundle_uri: AnyUrl
    expected_signing_identity: str = Field(
        ...,
        min_length=CONTRACT_EXPECTED_IDENTITY_MIN_LENGTH,
        max_length=CONTRACT_EXPECTED_IDENTITY_MAX_LENGTH,
    )
    expected_issuer: AnyUrl
    tenant_id: uuid.UUID

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
            raise ValueError(f"image_digest must match {DIGEST_PATTERN!r}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _valid_until_after_valid_from(self) -> BehavioralContractRegisterRequest:
        """Validate that valid_until is later than valid_from if provided.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If valid_until is not later than valid_from.
        """
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        return self


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class BehavioralContractRecord(_PhantomBaseModel):
    """Behavioral contract record returned from registration and list endpoints.

    Attributes:
        contract_id: Immutable UUID assigned at registration time.
        image_digest: sha256 digest of the associated container image.
        sbom_id: UUID of the associated SBOM record.
        contract_version: Semantic version of this contract.
        verification_status: Cosign signature verification state.
        activation_status: Contract lifecycle state.
        created_at: UTC timestamp when this record was created.
    """

    contract_id: uuid.UUID
    image_digest: str
    sbom_id: uuid.UUID
    contract_version: str
    verification_status: Literal["pending", "verified", "failed"]
    activation_status: Literal["inactive", "active", "expired", "revoked"]
    created_at: datetime


class BehavioralContractDetailResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/contracts/{contract_id}``.

    Attributes:
        record: Embedded BehavioralContractRecord.
        workload_selector: The contract's workload scope.
        constraints: The full behavioral constraint set.
        valid_from: UTC datetime from which the contract is valid.
        valid_until: Optional UTC expiry datetime.
        signature_bundle_uri: URI of the cosign signature bundle.
        signing_identity: Verified signing identity; None if not yet verified.
        issuer: Verified OIDC issuer; None if not yet verified.
        rekor_entry_uuid: Rekor transparency log entry UUID if present.
        revocation_reason: Reason for revocation if status is ``"revoked"``.
    """

    record: BehavioralContractRecord
    workload_selector: WorkloadSelector
    constraints: BehavioralConstraints
    valid_from: datetime
    valid_until: datetime | None = None
    signature_bundle_uri: str
    signing_identity: str | None = None
    issuer: str | None = None
    rekor_entry_uuid: uuid.UUID | None = None
    revocation_reason: str | None = None


class ContractListResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/contracts``.

    Attributes:
        items: Page of contract records.
        next_cursor: Opaque cursor for the next page; None if last page.
    """

    items: list[BehavioralContractRecord]
    next_cursor: str | None = None


class ContractLookupQuery(_PhantomBaseModel):
    """Query parameters for ``GET /api/v1/contracts``.

    At least one of image_digest, namespace, or activation_status is required.

    Attributes:
        image_digest: Filter by container image sha256 digest.
        namespace: Filter by Kubernetes namespace.
        activation_status: Filter by contract lifecycle state.
        limit: Maximum items to return; 1..200.
        cursor: Opaque pagination cursor.
    """

    image_digest: str | None = None
    namespace: str | None = None
    activation_status: Literal["inactive", "active", "expired", "revoked"] | None = None
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = None

    @model_validator(mode="after")
    def _at_least_one_filter(self) -> ContractLookupQuery:
        """Require at least one filter field to be provided.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If no filter is specified.
        """
        if not any([self.image_digest, self.namespace, self.activation_status]):
            raise ValueError(
                "At least one of image_digest, namespace, or activation_status is required"
            )
        return self
