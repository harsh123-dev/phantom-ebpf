"""
Tests for api-gateway JWT authentication and authorization enforcement.

Covers:
- valid JWT → AuthenticatedPrincipal returned
- expired JWT → TokenExpiredError raised
- invalid signature → TokenInvalidError raised
- missing bearer token → AuthenticationError raised
- wrong role → AuthorizationError raised
- tenant mismatch → TenantMismatchError raised
- ADMIN role bypasses role and tenant checks

JWT tokens are signed locally with an RSA test key so no live JWKS
endpoint is needed.  The JWKS cache is patched at the adapter level.

All tests are pure-unit: no FastAPI TestClient, no database, no Redis.
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    TenantMismatchError,
    TokenExpiredError,
    TokenInvalidError,
)
from app.infrastructure.auth_adapter import verify_jwt
from app.infrastructure.auth_settings import AuthSettings

# ---------------------------------------------------------------------------
# Test RSA key pair (generated once per session)
# ---------------------------------------------------------------------------

_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

# JWK representation of the public key for the mock JWKS cache.
_PUBLIC_KEY_PEM = _PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# python-jose accepts raw RSA public key objects in the JWKS "keys" list.
_MOCK_KEYS = [_PUBLIC_KEY_PEM]

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

_ISSUER = "https://auth.phantom.test"
_AUDIENCE = "phantom-api-gateway"
_TENANT_ID = uuid.uuid4()
_USER_ID = "user-abc-123"
_JTI = str(uuid.uuid4())

_SETTINGS = AuthSettings.model_construct(
    jwt_issuer=_ISSUER,
    jwt_audience=_AUDIENCE,
    jwks_uri="https://auth.phantom.test/.well-known/jwks.json",
    jwt_algorithms=["RS256"],
    jwks_cache_ttl_seconds=300,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(
    *,
    sub: str = _USER_ID,
    tenant_id: str | None = str(_TENANT_ID),
    roles: list[str] | None = None,
    jti: str = _JTI,
    expire_offset: int = 3600,
    issuer: str = _ISSUER,
    audience: str = _AUDIENCE,
    extra_claims: dict | None = None,
) -> str:
    """Build and sign a JWT with the test RSA private key.

    Args:
        sub: Subject claim.
        tenant_id: Tenant UUID string; None to omit.
        roles: Role strings; defaults to [PhantomRole.ANALYST].
        jti: JWT ID claim.
        expire_offset: Seconds from now until exp (negative = already expired).
        issuer: iss claim.
        audience: aud claim.
        extra_claims: Additional claims merged into the payload.

    Returns:
        Signed JWT string.
    """
    now = int(time.time())
    payload: dict = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "jti": jti,
        "iat": now,
        "exp": now + expire_offset,
        "roles": roles if roles is not None else [PhantomRole.ANALYST.value],
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def _patch_jwks(keys: list = _MOCK_KEYS):
    """Return a context-manager patch that injects test keys into JwksCache.get_keys."""
    return patch(
        "app.infrastructure.auth_adapter._jwks_cache.get_keys",
        return_value=keys,
    )


# ---------------------------------------------------------------------------
# Tests: valid JWT
# ---------------------------------------------------------------------------


class TestValidJWT:
    """Verify that a well-formed, unexpired JWT produces an AuthenticatedPrincipal."""

    def test_returns_authenticated_principal(self) -> None:
        """A valid JWT returns an AuthenticatedPrincipal with correct fields."""
        token = _make_token(roles=[PhantomRole.ANALYST.value])
        with _patch_jwks():
            principal = verify_jwt(token, _SETTINGS)

        assert isinstance(principal, AuthenticatedPrincipal)
        assert principal.tenant_id == _TENANT_ID
        assert principal.user_id == _USER_ID
        assert principal.token_jti == _JTI
        assert PhantomRole.ANALYST in principal.roles

    def test_agent_role_mapped(self) -> None:
        """phantom.agent role is correctly mapped to PhantomRole.AGENT."""
        token = _make_token(roles=[PhantomRole.AGENT.value])
        with _patch_jwks():
            principal = verify_jwt(token, _SETTINGS)
        assert PhantomRole.AGENT in principal.roles

    def test_multiple_roles_mapped(self) -> None:
        """All roles in the token are mapped; unknown roles are ignored."""
        token = _make_token(
            roles=[
                PhantomRole.ANALYST.value,
                PhantomRole.VIEWER.value,
                "phantom.unknown_future_role",
            ]
        )
        with _patch_jwks():
            principal = verify_jwt(token, _SETTINGS)
        assert PhantomRole.ANALYST in principal.roles
        assert PhantomRole.VIEWER in principal.roles
        # Unknown role silently ignored.
        assert len(principal.roles) == 2

    def test_empty_roles_allowed(self) -> None:
        """A token with no roles is valid; principal.roles is empty."""
        token = _make_token(roles=[])
        with _patch_jwks():
            principal = verify_jwt(token, _SETTINGS)
        assert principal.roles == frozenset()

    def test_admin_role_mapped(self) -> None:
        """phantom.admin role is correctly mapped."""
        token = _make_token(roles=[PhantomRole.ADMIN.value])
        with _patch_jwks():
            principal = verify_jwt(token, _SETTINGS)
        assert PhantomRole.ADMIN in principal.roles


# ---------------------------------------------------------------------------
# Tests: expired JWT
# ---------------------------------------------------------------------------


class TestExpiredJWT:
    """Verify that an expired token raises TokenExpiredError."""

    def test_expired_token_raises(self) -> None:
        """An expired JWT raises TokenExpiredError."""
        token = _make_token(expire_offset=-1)
        with _patch_jwks(), pytest.raises(TokenExpiredError) as exc_info:
            verify_jwt(token, _SETTINGS)
        assert exc_info.value.http_status == 401
        assert "expired" in exc_info.value.message.lower()

    def test_expired_token_error_code(self) -> None:
        """TokenExpiredError carries the TOKEN_EXPIRED error code."""
        from app.domain.entities import APIErrorCode

        token = _make_token(expire_offset=-3600)
        with _patch_jwks(), pytest.raises(TokenExpiredError) as exc_info:
            verify_jwt(token, _SETTINGS)
        assert exc_info.value.error_code == APIErrorCode.TOKEN_EXPIRED


# ---------------------------------------------------------------------------
# Tests: invalid signature / claims
# ---------------------------------------------------------------------------


class TestInvalidJWT:
    """Verify that tokens with bad signatures or missing claims raise TokenInvalidError."""

    def test_wrong_audience_raises(self) -> None:
        """A token with wrong audience raises TokenInvalidError."""
        token = _make_token(audience="wrong-audience")
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)

    def test_wrong_issuer_raises(self) -> None:
        """A token with wrong issuer raises TokenInvalidError."""
        token = _make_token(issuer="https://evil.example.com")
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)

    def test_tampered_token_raises(self) -> None:
        """A token with a tampered payload raises TokenInvalidError."""
        good_token = _make_token()
        # Replace the signature with random bytes (corrupt it).
        parts = good_token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalidsignatureXXXXXXXXXX"
        with _patch_jwks(), pytest.raises((TokenInvalidError, AuthenticationError)):
            verify_jwt(tampered, _SETTINGS)

    def test_missing_sub_claim_raises(self) -> None:
        """A token missing the sub claim raises TokenInvalidError."""
        token = _make_token(sub="")
        # An empty sub counts as missing.
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)

    def test_missing_tenant_id_claim_raises(self) -> None:
        """A token without tenant_id raises TokenInvalidError."""
        token = _make_token(tenant_id=None)
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)

    def test_invalid_tenant_id_uuid_raises(self) -> None:
        """A token with a non-UUID tenant_id raises TokenInvalidError."""
        token = _make_token(tenant_id="not-a-uuid")
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)

    def test_missing_jti_claim_raises(self) -> None:
        """A token without jti raises TokenInvalidError."""
        token = _make_token(jti="")
        with _patch_jwks(), pytest.raises(TokenInvalidError):
            verify_jwt(token, _SETTINGS)


# ---------------------------------------------------------------------------
# Tests: missing bearer token (AuthenticationError at dependency layer)
# ---------------------------------------------------------------------------


class TestMissingBearerToken:
    """Verify the dependency raises AuthenticationError when no token is provided."""

    @pytest.mark.asyncio
    async def test_no_credentials_raises(self) -> None:
        """get_current_principal raises AuthenticationError when credentials=None."""
        from unittest.mock import MagicMock

        from app.interface.dependencies import get_current_principal

        request = MagicMock()
        with pytest.raises(AuthenticationError) as exc_info:
            await get_current_principal(request=request, credentials=None)
        assert exc_info.value.http_status == 401
        assert "bearer" in exc_info.value.message.lower()


# ---------------------------------------------------------------------------
# Tests: role authorization
# ---------------------------------------------------------------------------


class TestRequireRole:
    """Verify require_role dependency enforces roles correctly."""

    @pytest.mark.asyncio
    async def test_correct_role_passes(self) -> None:
        """Principal with the required role passes the role check."""
        from app.interface.dependencies import require_role

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.ANALYST}),
            token_jti=_JTI,
        )
        dep = require_role(PhantomRole.ANALYST)
        result = await dep(principal=principal)
        assert result is principal

    @pytest.mark.asyncio
    async def test_wrong_role_raises_authorization_error(self) -> None:
        """Principal lacking the required role raises AuthorizationError."""
        from app.interface.dependencies import require_role

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.VIEWER}),
            token_jti=_JTI,
        )
        dep = require_role(PhantomRole.ANALYST)
        with pytest.raises(AuthorizationError) as exc_info:
            await dep(principal=principal)
        assert exc_info.value.http_status == 403

    @pytest.mark.asyncio
    async def test_admin_bypasses_role_check(self) -> None:
        """ADMIN principal bypasses all require_role checks."""
        from app.interface.dependencies import require_role

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id="admin-user",
            roles=frozenset({PhantomRole.ADMIN}),
            token_jti=_JTI,
        )
        dep = require_role(PhantomRole.ANALYST, PhantomRole.SBOM_WRITER)
        result = await dep(principal=principal)
        assert result is principal

    @pytest.mark.asyncio
    async def test_any_matching_role_passes(self) -> None:
        """require_role with multiple roles passes if any one matches."""
        from app.interface.dependencies import require_role

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.SBOM_WRITER}),
            token_jti=_JTI,
        )
        dep = require_role(PhantomRole.ANALYST, PhantomRole.SBOM_WRITER)
        result = await dep(principal=principal)
        assert result is principal

    @pytest.mark.asyncio
    async def test_no_roles_raises_authorization_error(self) -> None:
        """Principal with empty roles raises AuthorizationError."""
        from app.interface.dependencies import require_role

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset(),
            token_jti=_JTI,
        )
        dep = require_role(PhantomRole.AGENT)
        with pytest.raises(AuthorizationError):
            await dep(principal=principal)


# ---------------------------------------------------------------------------
# Tests: tenant mismatch
# ---------------------------------------------------------------------------


class TestTenantMismatch:
    """Verify require_tenant_match enforces tenant isolation."""

    @pytest.mark.asyncio
    async def test_matching_tenant_passes(self) -> None:
        """Principal whose tenant_id matches the path parameter passes."""
        from app.interface.dependencies import require_tenant_match

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.ANALYST}),
            token_jti=_JTI,
        )
        result = await require_tenant_match(
            tenant_id=_TENANT_ID, principal=principal
        )
        assert result is principal

    @pytest.mark.asyncio
    async def test_mismatched_tenant_raises(self) -> None:
        """Principal whose tenant_id differs from path tenant raises TenantMismatchError."""
        from app.interface.dependencies import require_tenant_match

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.ANALYST}),
            token_jti=_JTI,
        )
        other_tenant = uuid.uuid4()
        with pytest.raises(TenantMismatchError) as exc_info:
            await require_tenant_match(
                tenant_id=other_tenant, principal=principal
            )
        assert exc_info.value.http_status == 403

    @pytest.mark.asyncio
    async def test_admin_bypasses_tenant_check(self) -> None:
        """ADMIN principal bypasses tenant mismatch checks."""
        from app.interface.dependencies import require_tenant_match

        principal = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id="admin-user",
            roles=frozenset({PhantomRole.ADMIN}),
            token_jti=_JTI,
        )
        other_tenant = uuid.uuid4()
        result = await require_tenant_match(
            tenant_id=other_tenant, principal=principal
        )
        assert result is principal


# ---------------------------------------------------------------------------
# Tests: AuthenticatedPrincipal helpers
# ---------------------------------------------------------------------------


class TestAuthenticatedPrincipalHelpers:
    """Unit tests for AuthenticatedPrincipal helper methods."""

    def test_has_role_true(self) -> None:
        """has_role returns True when role is present."""
        p = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.ANALYST}),
            token_jti=_JTI,
        )
        assert p.has_role(PhantomRole.ANALYST) is True

    def test_has_role_false(self) -> None:
        """has_role returns False when role is absent."""
        p = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.VIEWER}),
            token_jti=_JTI,
        )
        assert p.has_role(PhantomRole.ADMIN) is False

    def test_has_any_role_true(self) -> None:
        """has_any_role returns True when at least one role matches."""
        p = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset({PhantomRole.VIEWER}),
            token_jti=_JTI,
        )
        assert p.has_any_role(PhantomRole.ANALYST, PhantomRole.VIEWER) is True

    def test_scope_property(self) -> None:
        """scope returns TenantScope with the correct tenant_id."""
        from app.domain.entities import TenantScope

        p = AuthenticatedPrincipal(
            tenant_id=_TENANT_ID,
            user_id=_USER_ID,
            roles=frozenset(),
            token_jti=_JTI,
        )
        assert p.scope == TenantScope(tenant_id=_TENANT_ID)
