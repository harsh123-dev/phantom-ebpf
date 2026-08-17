"""
api-gateway domain exceptions.

Typed exception hierarchy for gateway-level failures:
- AuthenticationError: missing or invalid bearer token
- AuthorizationError: insufficient role
- TenantMismatchError: resource belongs to a different tenant
- ResourceNotFoundError: referenced entity absent
- ConflictError: duplicate/conflicting resource state
- ValidationError: request payload fails schema constraints
- ServiceUnavailableError: upstream service unreachable

Each exception exposes http_status, error_code, and message to allow
a single FastAPI exception handler to produce consistent JSON responses.

No framework imports allowed.
"""

from __future__ import annotations

from app.domain.entities import APIErrorCode


class GatewayError(Exception):
    """Base class for all typed api-gateway exceptions.

    Attributes:
        http_status: HTTP status code for this error class.
        error_code: Machine-readable APIErrorCode.
        message: Human-readable description of the failure.
    """

    http_status: int = 500
    error_code: APIErrorCode = APIErrorCode.INTERNAL_ERROR

    def __init__(self, message: str) -> None:
        """Initialise with a human-readable message.

        Args:
            message: Human-readable description of the failure.
        """
        super().__init__(message)
        self.message = message

    def __repr__(self) -> str:
        """Return a developer-readable representation.

        Returns:
            String representation including class name and message.
        """
        return f"{self.__class__.__name__}({self.message!r})"


class AuthenticationError(GatewayError):
    """Raised when the bearer token is missing, expired, or invalid.

    Maps to HTTP 401 Unauthorized.

    Use the subclass ``TokenExpiredError`` when the token is structurally
    valid but has passed its ``exp`` claim.
    """

    http_status: int = 401
    error_code: APIErrorCode = APIErrorCode.UNAUTHENTICATED


class TokenExpiredError(AuthenticationError):
    """Raised specifically when a well-formed token has passed its exp claim.

    Maps to HTTP 401 with error_code TOKEN_EXPIRED to allow clients to
    distinguish expiry from other authentication failures.
    """

    error_code: APIErrorCode = APIErrorCode.TOKEN_EXPIRED


class TokenInvalidError(AuthenticationError):
    """Raised when the token fails signature or claims validation.

    Maps to HTTP 401 with error_code TOKEN_INVALID.
    """

    error_code: APIErrorCode = APIErrorCode.TOKEN_INVALID


class AuthorizationError(GatewayError):
    """Raised when the principal lacks a required role.

    Maps to HTTP 403 Forbidden.
    """

    http_status: int = 403
    error_code: APIErrorCode = APIErrorCode.FORBIDDEN


class TenantMismatchError(GatewayError):
    """Raised when a resource belongs to a different tenant than the principal.

    Maps to HTTP 403 Forbidden (not 404, to avoid leaking resource existence).
    """

    http_status: int = 403
    error_code: APIErrorCode = APIErrorCode.TENANT_MISMATCH


class ResourceNotFoundError(GatewayError):
    """Raised when the referenced entity does not exist for the requesting tenant.

    Maps to HTTP 404 Not Found.
    """

    http_status: int = 404
    error_code: APIErrorCode = APIErrorCode.NOT_FOUND


class ConflictError(GatewayError):
    """Raised when the request conflicts with existing resource state.

    Examples: duplicate drift event_id, same sbom_digest re-ingested.
    Maps to HTTP 409 Conflict.
    """

    http_status: int = 409
    error_code: APIErrorCode = APIErrorCode.CONFLICT


class ValidationError(GatewayError):
    """Raised when the request body fails schema or business-rule validation.

    Maps to HTTP 422 Unprocessable Entity.
    Note: Pydantic RequestValidationError is handled separately by FastAPI;
    this exception is for application-level validation failures.
    """

    http_status: int = 422
    error_code: APIErrorCode = APIErrorCode.VALIDATION_ERROR


class ServiceUnavailableError(GatewayError):
    """Raised when an upstream internal service is unreachable or returns 5xx.

    Maps to HTTP 503 Service Unavailable.
    """

    http_status: int = 503
    error_code: APIErrorCode = APIErrorCode.SERVICE_UNAVAILABLE
