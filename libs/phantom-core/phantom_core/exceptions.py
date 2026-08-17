"""
phantom_core.exceptions — Typed exception hierarchy for all PHANTOM services.

Every exception carries:
- A ``code`` class attribute: stable machine-readable error code string
  matching the ErrorResponse.error_code field.
- A human-readable message passed to the constructor.

Hierarchy:
  PhantomError (base)
  ├── AuthenticationError     — missing / invalid bearer token
  ├── AuthorizationError      — insufficient role or wrong tenant scope
  ├── ResourceNotFoundError   — referenced entity absent
  ├── ConflictError           — duplicate / conflicting resource state
  │   └── DuplicateEventError — same event_id with different digest
  ├── ValidationError         — request payload fails schema constraints
  ├── ServiceUnavailableError — upstream service or dependency unreachable
  ├── EffectNotIdentifiableError — causal DAG cycle or no adjustment set
  ├── EvidenceIncompleteError — evidence missing for report / attribution
  └── ImputationDisallowedError — PCEPS features absent; imputation disabled
"""

from __future__ import annotations


class PhantomError(Exception):
    """Base class for all PHANTOM typed exceptions.

    Args:
        message: Human-readable description of the error.
    """

    code: str = "PHANTOM_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message: str = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Authentication / Authorization
# ---------------------------------------------------------------------------


class AuthenticationError(PhantomError):
    """Raised when a bearer token is missing, expired, or structurally invalid.

    Args:
        message: Human-readable description of the authentication failure.
    """

    code: str = "AUTHENTICATION_REQUIRED"


class AuthorizationError(PhantomError):
    """Raised when a principal has insufficient role or is in the wrong tenant scope.

    Args:
        message: Human-readable description of the authorization failure.
    """

    code: str = "AUTHORIZATION_DENIED"


# ---------------------------------------------------------------------------
# Resource lifecycle
# ---------------------------------------------------------------------------


class ResourceNotFoundError(PhantomError):
    """Raised when a referenced entity does not exist or is not visible to the tenant.

    Args:
        resource_type: Type name of the missing resource (e.g. "SbomRecord").
        resource_id: Identifier that was not found.
    """

    code: str = "RESOURCE_NOT_FOUND"

    def __init__(self, resource_type: str, resource_id: str) -> None:
        super().__init__(f"{resource_type} not found: {resource_id}")
        self.resource_type: str = resource_type
        self.resource_id: str = resource_id


class ConflictError(PhantomError):
    """Raised when a resource state conflict prevents the requested operation.

    Args:
        message: Human-readable description of the conflict.
    """

    code: str = "CONFLICT"


class DuplicateEventError(ConflictError):
    """Raised when the same event_id is submitted with a different canonical digest.

    Args:
        event_id: The conflicting event identifier.
    """

    code: str = "DUPLICATE_EVENT_DIGEST_CONFLICT"

    def __init__(self, event_id: str) -> None:
        super().__init__(
            f"event_id {event_id!r} already exists with a different canonical digest"
        )
        self.event_id: str = event_id


class RevisionConflictError(ConflictError):
    """Raised when an optimistic concurrency update targets a stale revision.

    Args:
        expected_revision: The revision the caller expected.
        current_revision: The actual current revision.
    """

    code: str = "REVISION_CONFLICT"

    def __init__(self, expected_revision: int, current_revision: int) -> None:
        super().__init__(
            f"expected revision {expected_revision}, current revision is {current_revision}"
        )
        self.expected_revision: int = expected_revision
        self.current_revision: int = current_revision


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(PhantomError):
    """Raised when a request payload fails schema or semantic constraints.

    Args:
        message: Human-readable description of the validation failure.
        field: Optional field name that failed validation.
    """

    code: str = "VALIDATION_ERROR"

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field: str | None = field


# ---------------------------------------------------------------------------
# Infrastructure / availability
# ---------------------------------------------------------------------------


class ServiceUnavailableError(PhantomError):
    """Raised when a mandatory dependency (database, Redis, upstream service) is unreachable.

    Agents receiving this error MUST retry with a stable event_id.

    Args:
        dependency: Name of the unavailable dependency.
        message: Optional additional context.
    """

    code: str = "SERVICE_UNAVAILABLE"

    def __init__(self, dependency: str, message: str = "") -> None:
        detail = f" — {message}" if message else ""
        super().__init__(f"Dependency unavailable: {dependency}{detail}")
        self.dependency: str = dependency


# ---------------------------------------------------------------------------
# Causal inference
# ---------------------------------------------------------------------------


class EffectNotIdentifiableError(PhantomError):
    """Raised when the causal DAG contains a cycle or lacks a valid adjustment set.

    The attribution job MUST return status="not_identifiable" and a diagnostic
    reason string. A numeric effect MUST NOT be fabricated.

    Args:
        reason: DoWhy identification failure reason.
    """

    code: str = "EFFECT_NOT_IDENTIFIABLE"

    def __init__(self, reason: str) -> None:
        super().__init__(f"Causal effect not identifiable: {reason}")
        self.reason: str = reason


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class EvidenceIncompleteError(PhantomError):
    """Raised when referenced drift events, attributions, or scores are absent or cross-tenant.

    Args:
        message: Human-readable description of the missing evidence.
    """

    code: str = "EVIDENCE_INCOMPLETE"


class ReportAlreadyArchivedError(ConflictError):
    """Raised when an archive operation targets an already-archived incident.

    Args:
        incident_id: The already-archived incident identifier.
    """

    code: str = "REPORT_ALREADY_ARCHIVED"

    def __init__(self, incident_id: str) -> None:
        super().__init__(f"Incident {incident_id!r} is already archived")
        self.incident_id: str = incident_id


# ---------------------------------------------------------------------------
# PCEPS scoring
# ---------------------------------------------------------------------------


class ImputationDisallowedError(PhantomError):
    """Raised when PCEPS scoring requires feature imputation but allow_imputation=False.

    Args:
        missing_features: List of feature names that are absent.
    """

    code: str = "IMPUTATION_DISALLOWED"

    def __init__(self, missing_features: list[str]) -> None:
        super().__init__(
            f"Scoring requires imputation for features: {missing_features!r} "
            f"but allow_imputation=False"
        )
        self.missing_features: list[str] = missing_features
