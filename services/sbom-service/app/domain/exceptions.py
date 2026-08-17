"""
services/sbom-service/app/domain/exceptions.py

Domain-level typed exception hierarchy for the SBOM service.

Rules:
- NO imports from infrastructure/, application/, or interface/.
- Every exception carries a stable ``code`` class attribute matching
  the ErrorResponse.error_code convention from the API contracts.
- These exceptions are raised by domain entities and use-cases and
  translated to HTTP responses only in the interface layer.
"""

from __future__ import annotations


class SbomDomainError(Exception):
    """Base class for all SBOM service domain exceptions.

    Args:
        message: Human-readable description of the error.
    """

    code: str = "SBOM_DOMAIN_ERROR"

    def __init__(self, message: str) -> None:
        """Initialise with a human-readable message.

        Args:
            message: Human-readable description of the error.
        """
        super().__init__(message)
        self.message: str = message

    def __repr__(self) -> str:
        """Return a descriptive repr string.

        Returns:
            A string including the class name, code, and message.
        """
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# SBOM lifecycle
# ---------------------------------------------------------------------------


class SbomNotFoundError(SbomDomainError):
    """Raised when a referenced SBOM does not exist or is not visible to the tenant.

    Args:
        sbom_id: The UUID string that was not found.
    """

    code: str = "SBOM_NOT_FOUND"

    def __init__(self, sbom_id: str) -> None:
        """Initialise with the missing SBOM identifier.

        Args:
            sbom_id: The UUID string of the SBOM that was not found.
        """
        super().__init__(f"SBOM not found: {sbom_id}")
        self.sbom_id: str = sbom_id


class InvalidSbomError(SbomDomainError):
    """Raised when a CycloneDX document fails structural or semantic validation.

    Args:
        message: Human-readable description of the validation failure.
        field: Optional field name that failed validation.
    """

    code: str = "INVALID_SBOM"

    def __init__(self, message: str, field: str | None = None) -> None:
        """Initialise with a validation failure message.

        Args:
            message: Human-readable description of the validation failure.
            field: Optional CycloneDX field name that caused the failure.
        """
        super().__init__(message)
        self.field: str | None = field


class DigestMismatchError(SbomDomainError):
    """Raised when the declared SBOM digest does not match the computed digest.

    This indicates a transport or tampering issue; the SBOM must not be
    ingested with a mismatched digest.

    Args:
        declared: The digest value the client declared.
        computed: The digest value PHANTOM computed from the document.
    """

    code: str = "SBOM_DIGEST_MISMATCH"

    def __init__(self, declared: str, computed: str) -> None:
        """Initialise with the declared and computed digest values.

        Args:
            declared: The digest value the client declared.
            computed: The digest value PHANTOM computed from the document.
        """
        super().__init__(
            f"Declared SBOM digest {declared!r} does not match computed digest {computed!r}"
        )
        self.declared: str = declared
        self.computed: str = computed


class DuplicateSbomError(SbomDomainError):
    """Raised when the same SBOM digest is bound to a different image digest.

    Per the API contract, a 409 is returned in this case. The invariant is
    that one CycloneDX document (identified by its content digest) describes
    exactly one container image digest.

    Args:
        sbom_digest: The SBOM digest that is already registered.
        existing_image_digest: The image digest already bound to this SBOM.
        requested_image_digest: The image digest the caller is trying to bind.
    """

    code: str = "SBOM_DIGEST_IMAGE_CONFLICT"

    def __init__(
        self,
        sbom_digest: str,
        existing_image_digest: str,
        requested_image_digest: str,
    ) -> None:
        """Initialise with the conflicting digest information.

        Args:
            sbom_digest: The SBOM digest that is already registered.
            existing_image_digest: The image digest already bound to this SBOM.
            requested_image_digest: The image digest the caller is trying to bind.
        """
        super().__init__(
            f"SBOM digest {sbom_digest!r} is already bound to image "
            f"{existing_image_digest!r}; cannot rebind to {requested_image_digest!r}"
        )
        self.sbom_digest: str = sbom_digest
        self.existing_image_digest: str = existing_image_digest
        self.requested_image_digest: str = requested_image_digest


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class SignatureVerificationError(SbomDomainError):
    """Raised when cosign/Sigstore signature verification fails.

    Distinct from a transient infrastructure failure (which raises
    VerificationServiceUnavailableError instead).

    Args:
        message: Human-readable description of the verification failure.
        sbom_id: The UUID string of the SBOM whose verification failed.
    """

    code: str = "SIGNATURE_VERIFICATION_FAILED"

    def __init__(self, message: str, sbom_id: str | None = None) -> None:
        """Initialise with a verification failure message.

        Args:
            message: Human-readable description of the verification failure.
            sbom_id: Optional UUID string of the SBOM being verified.
        """
        super().__init__(message)
        self.sbom_id: str | None = sbom_id


class VerificationAlreadyInProgressError(SbomDomainError):
    """Raised when a verification job is enqueued while one is already running.

    Per the API contract, a 409 is returned when the same SBOM is already
    under active verification.

    Args:
        sbom_id: The UUID string of the SBOM that is already being verified.
    """

    code: str = "VERIFICATION_ALREADY_IN_PROGRESS"

    def __init__(self, sbom_id: str) -> None:
        """Initialise with the SBOM identifier that is already being verified.

        Args:
            sbom_id: The UUID string of the SBOM already under verification.
        """
        super().__init__(
            f"SBOM {sbom_id!r} already has a verification job in progress"
        )
        self.sbom_id: str = sbom_id


class VerificationJobNotFoundError(SbomDomainError):
    """Raised when a verification result is requested but no job exists.

    Args:
        sbom_id: The UUID string of the SBOM whose verification was queried.
    """

    code: str = "VERIFICATION_JOB_NOT_FOUND"

    def __init__(self, sbom_id: str) -> None:
        """Initialise with the SBOM identifier that has no verification job.

        Args:
            sbom_id: The UUID string of the SBOM with no verification record.
        """
        super().__init__(f"No verification record found for SBOM {sbom_id!r}")
        self.sbom_id: str = sbom_id


class VerificationServiceUnavailableError(SbomDomainError):
    """Raised when the cosign CLI or Sigstore service is transiently unavailable.

    Callers should retry the verification request later; the SBOM record
    is not altered by this failure.

    Args:
        message: Human-readable description of the unavailability.
    """

    code: str = "VERIFICATION_SERVICE_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Syft
# ---------------------------------------------------------------------------


class SyftNotInstalledError(SbomDomainError):
    """Raised when the Syft CLI binary is not found on PATH.

    Args:
        syft_path: The path or command name that was attempted.
    """

    code: str = "SYFT_NOT_INSTALLED"

    def __init__(self, syft_path: str = "syft") -> None:
        """Initialise with the path that was not found.

        Args:
            syft_path: The path or command name that was not found.
        """
        super().__init__(
            f"Syft CLI not found at {syft_path!r}; "
            f"install Syft and ensure it is on PATH"
        )
        self.syft_path: str = syft_path


class SyftImageNotFoundError(SbomDomainError):
    """Raised when Syft cannot pull or locate the specified container image.

    Args:
        image_reference: The image reference Syft attempted to analyse.
    """

    code: str = "SYFT_IMAGE_NOT_FOUND"

    def __init__(self, image_reference: str) -> None:
        """Initialise with the image reference that was not found.

        Args:
            image_reference: The image reference Syft could not resolve.
        """
        super().__init__(f"Syft could not find or pull image {image_reference!r}")
        self.image_reference: str = image_reference


class SyftParseError(SbomDomainError):
    """Raised when Syft output cannot be parsed as valid CycloneDX JSON.

    Args:
        message: Human-readable description of the parse failure.
    """

    code: str = "SYFT_PARSE_ERROR"


class SyftTimeoutError(SbomDomainError):
    """Raised when Syft does not complete within the configured timeout.

    Args:
        timeout_seconds: The timeout duration that was exceeded.
    """

    code: str = "SYFT_TIMEOUT"

    def __init__(self, timeout_seconds: float) -> None:
        """Initialise with the exceeded timeout duration.

        Args:
            timeout_seconds: The timeout duration that was exceeded.
        """
        super().__init__(
            f"Syft timed out after {timeout_seconds}s; "
            f"consider increasing the timeout or pulling the image first"
        )
        self.timeout_seconds: float = timeout_seconds


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


class SbomStorageError(SbomDomainError):
    """Raised when the object store or database cannot persist the SBOM artifact.

    Args:
        message: Human-readable description of the storage failure.
    """

    code: str = "SBOM_STORAGE_ERROR"
