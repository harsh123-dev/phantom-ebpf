"""
Tests for phantom_core.exceptions — validates the typed exception hierarchy.

Covers:
- Exception instantiation and attribute access
- Error code stability
- Inheritance chain correctness
"""

from __future__ import annotations

from phantom_core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DuplicateEventError,
    EffectNotIdentifiableError,
    EvidenceIncompleteError,
    ImputationDisallowedError,
    PhantomError,
    ReportAlreadyArchivedError,
    ResourceNotFoundError,
    RevisionConflictError,
    ServiceUnavailableError,
    ValidationError,
)


class TestPhantomErrorBase:
    """Tests for the PhantomError base class."""

    def test_message_attribute(self) -> None:
        """PhantomError stores the message attribute."""
        err = PhantomError("test message")
        assert err.message == "test message"
        assert str(err) == "test message"

    def test_repr(self) -> None:
        """PhantomError has a descriptive repr."""
        err = PhantomError("test")
        assert "PhantomError" in repr(err)
        assert "PHANTOM_ERROR" in repr(err)


class TestAuthErrors:
    """Tests for authentication and authorization errors."""

    def test_authentication_code(self) -> None:
        """AuthenticationError has a stable error code."""
        err = AuthenticationError("missing token")
        assert err.code == "AUTHENTICATION_REQUIRED"
        assert isinstance(err, PhantomError)

    def test_authorization_code(self) -> None:
        """AuthorizationError has a stable error code."""
        err = AuthorizationError("wrong tenant")
        assert err.code == "AUTHORIZATION_DENIED"
        assert isinstance(err, PhantomError)


class TestResourceErrors:
    """Tests for resource lifecycle errors."""

    def test_not_found(self) -> None:
        """ResourceNotFoundError stores resource_type and resource_id."""
        err = ResourceNotFoundError("SbomRecord", "abc-123")
        assert err.resource_type == "SbomRecord"
        assert err.resource_id == "abc-123"
        assert "not found" in err.message

    def test_conflict(self) -> None:
        """ConflictError has a stable error code."""
        err = ConflictError("duplicate")
        assert err.code == "CONFLICT"

    def test_duplicate_event(self) -> None:
        """DuplicateEventError is a ConflictError subclass."""
        err = DuplicateEventError("evt-1")
        assert err.event_id == "evt-1"
        assert isinstance(err, ConflictError)
        assert isinstance(err, PhantomError)

    def test_revision_conflict(self) -> None:
        """RevisionConflictError stores revision numbers."""
        err = RevisionConflictError(expected_revision=3, current_revision=5)
        assert err.expected_revision == 3
        assert err.current_revision == 5
        assert isinstance(err, ConflictError)


class TestValidationError:
    """Tests for ValidationError."""

    def test_with_field(self) -> None:
        """ValidationError can optionally specify a field name."""
        err = ValidationError("bad value", field="image_digest")
        assert err.field == "image_digest"
        assert err.code == "VALIDATION_ERROR"

    def test_without_field(self) -> None:
        """ValidationError works without a field name."""
        err = ValidationError("general failure")
        assert err.field is None


class TestServiceUnavailableError:
    """Tests for ServiceUnavailableError."""

    def test_with_message(self) -> None:
        """ServiceUnavailableError stores the dependency name."""
        err = ServiceUnavailableError("postgres", "connection refused")
        assert err.dependency == "postgres"
        assert "connection refused" in err.message

    def test_without_message(self) -> None:
        """ServiceUnavailableError works with just a dependency name."""
        err = ServiceUnavailableError("redis")
        assert err.dependency == "redis"


class TestCausalErrors:
    """Tests for causal inference errors."""

    def test_not_identifiable(self) -> None:
        """EffectNotIdentifiableError stores the diagnostic reason."""
        err = EffectNotIdentifiableError("no valid adjustment set")
        assert err.reason == "no valid adjustment set"
        assert err.code == "EFFECT_NOT_IDENTIFIABLE"


class TestReportErrors:
    """Tests for report generation errors."""

    def test_evidence_incomplete(self) -> None:
        """EvidenceIncompleteError is a PhantomError subclass."""
        err = EvidenceIncompleteError("drift event missing")
        assert err.code == "EVIDENCE_INCOMPLETE"

    def test_already_archived(self) -> None:
        """ReportAlreadyArchivedError stores the incident_id."""
        err = ReportAlreadyArchivedError("inc-1")
        assert err.incident_id == "inc-1"
        assert isinstance(err, ConflictError)


class TestImputationError:
    """Tests for PCEPS imputation errors."""

    def test_imputation_disallowed(self) -> None:
        """ImputationDisallowedError stores missing feature names."""
        err = ImputationDisallowedError(["feature_a", "feature_b"])
        assert err.missing_features == ["feature_a", "feature_b"]
        assert err.code == "IMPUTATION_DISALLOWED"
