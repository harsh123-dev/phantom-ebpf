"""
api-gateway domain entities.

Defines gateway-owned entities:
- PhantomRole: authorization role enum
- TenantScope: logical tenant isolation key
- AuthenticatedPrincipal: verified JWT identity value object
- APIErrorCode: canonical gateway error codes

No framework imports allowed.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# PhantomRole
# ---------------------------------------------------------------------------


class PhantomRole(str, enum.Enum):
    """Gateway authorization roles as defined in the PHANTOM RBAC policy.

    Values match the ``roles`` claim array embedded in the JWT.

    Attributes:
        AGENT: eBPF agent — may ingest drift events only.
        SBOM_WRITER: CI/CD pipeline — may ingest SBOMs and contracts.
        ANALYST: Human analyst — may read/write attributions, incidents, scores.
        VIEWER: Read-only operator — may read all resources.
        ADMIN: Platform administrator — unrestricted access.
    """

    AGENT = "phantom.agent"
    SBOM_WRITER = "phantom.sbom_writer"
    ANALYST = "phantom.analyst"
    VIEWER = "phantom.viewer"
    ADMIN = "phantom.admin"


# ---------------------------------------------------------------------------
# TenantScope
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TenantScope:
    """Logical tenant isolation key extracted from the verified JWT.

    Used to scope all database queries and resource lookups.

    Attributes:
        tenant_id: Tenant UUID from the ``tenant_id`` JWT claim.
    """

    tenant_id: uuid.UUID


# ---------------------------------------------------------------------------
# AuthenticatedPrincipal
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Verified JWT identity, ready for use in authorization checks.

    Constructed by the authentication adapter after full JWT validation.
    Immutable value object — never mutated after construction.

    Attributes:
        tenant_id: Tenant UUID from the ``tenant_id`` JWT claim.
        user_id: Subject identifier from the ``sub`` JWT claim.
        roles: Set of PhantomRole values from the ``roles`` JWT claim.
        token_jti: JWT ID (``jti`` claim) for audit logging.
    """

    tenant_id: uuid.UUID
    user_id: str
    roles: frozenset[PhantomRole]
    token_jti: str

    def has_role(self, role: PhantomRole) -> bool:
        """Return True if the principal holds the given role.

        Args:
            role: The PhantomRole to check.

        Returns:
            True if the principal has the role.
        """
        return role in self.roles

    def has_any_role(self, *roles: PhantomRole) -> bool:
        """Return True if the principal holds at least one of the given roles.

        Args:
            *roles: One or more PhantomRole values to check.

        Returns:
            True if the principal has any of the specified roles.
        """
        return bool(self.roles.intersection(roles))

    @property
    def scope(self) -> TenantScope:
        """Return the TenantScope for this principal.

        Returns:
            A TenantScope wrapping tenant_id.
        """
        return TenantScope(tenant_id=self.tenant_id)


# ---------------------------------------------------------------------------
# APIErrorCode
# ---------------------------------------------------------------------------


class APIErrorCode(str, enum.Enum):
    """Canonical gateway error codes returned in JSON error responses.

    Every 4xx/5xx response includes one of these codes in the
    ``error_code`` field for programmatic error handling.

    Attributes:
        UNAUTHENTICATED: No valid bearer token provided.
        TOKEN_EXPIRED: Bearer token has passed its expiry time.
        TOKEN_INVALID: Bearer token failed signature or claims validation.
        FORBIDDEN: Principal lacks the required role.
        TENANT_MISMATCH: Resource belongs to a different tenant.
        NOT_FOUND: Requested resource does not exist.
        CONFLICT: Request conflicts with existing resource state.
        VALIDATION_ERROR: Request body fails schema validation.
        SERVICE_UNAVAILABLE: Upstream service is unreachable.
        INTERNAL_ERROR: Unexpected server error.
    """

    UNAUTHENTICATED = "UNAUTHENTICATED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_INVALID = "TOKEN_INVALID"
    FORBIDDEN = "FORBIDDEN"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
