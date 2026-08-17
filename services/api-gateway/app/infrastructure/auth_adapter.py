"""
api-gateway JWKS authentication adapter.

Validates JWT bearer tokens against a JWKS endpoint,
extracts tenant_id and role claims, and returns an AuthenticatedPrincipal.

Implementation notes:
- python-jose[cryptography] is used for JWT decode (declared in pyproject.toml).
- The JWKS is fetched synchronously on first use and cached in-process for
  jwks_cache_ttl_seconds (default 300 s). This is safe because the adapter
  is only called from async request handlers — the sync fetch is short.
- NEVER log the raw token, the JWT payload, or any secret material.
- Log only: request_id (from structlog context), tenant_id, token_jti.
- Raise AuthenticationError (or subclasses) on any validation failure.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
import structlog
from jose import ExpiredSignatureError, JWTError, jwt

from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import (
    AuthenticationError,
    TokenExpiredError,
    TokenInvalidError,
)
from app.infrastructure.auth_settings import AuthSettings

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# JWKS cache (process-level, not shared across replicas)
# ---------------------------------------------------------------------------


class _JwksCache:
    """Simple in-process JWKS cache with TTL-based invalidation.

    Attributes:
        _keys: Cached JWKS key list; None if not yet fetched.
        _fetched_at: Unix timestamp of last successful fetch.
    """

    def __init__(self) -> None:
        """Initialise the cache in an empty state."""
        self._keys: list[dict[str, Any]] | None = None
        self._fetched_at: float = 0.0

    def get_keys(self, jwks_uri: str, ttl: int) -> list[dict[str, Any]]:
        """Return JWKS keys, fetching from the endpoint if the cache is stale.

        Args:
            jwks_uri: HTTPS endpoint serving the JSON Web Key Set.
            ttl: Cache TTL in seconds.

        Returns:
            List of JWK dicts from the JWKS endpoint.

        Raises:
            AuthenticationError: If the JWKS endpoint is unreachable.
        """
        now = time.monotonic()
        if self._keys is not None and (now - self._fetched_at) < ttl:
            return self._keys

        try:
            resp = httpx.get(jwks_uri, timeout=5.0)
            resp.raise_for_status()
            self._keys = resp.json().get("keys", [])
            self._fetched_at = now
            log.info("auth_adapter.jwks_refreshed", jwks_uri=jwks_uri)
            return self._keys  # _keys is non-None after assignment
        except Exception as exc:
            log.warning("auth_adapter.jwks_fetch_failed", error=str(exc))
            # Return stale keys if available rather than failing hard.
            if self._keys is not None:
                log.warning("auth_adapter.jwks_serving_stale_cache")
                return self._keys
            raise AuthenticationError(
                "Authentication service is unavailable. Try again later."
            ) from exc


_jwks_cache = _JwksCache()


# ---------------------------------------------------------------------------
# Public adapter function
# ---------------------------------------------------------------------------


def verify_jwt(raw_token: str, settings: AuthSettings) -> AuthenticatedPrincipal:
    """Validate a raw bearer token and return the verified AuthenticatedPrincipal.

    Validation steps (in order):
    1. Fetch/cache JWKS keys from the JWKS endpoint.
    2. Decode and verify signature, expiry, issuer, and audience via python-jose.
    3. Extract ``tenant_id``, ``sub``, ``roles``, and ``jti`` claims.
    4. Validate required claims are present and parseable.
    5. Map role strings to PhantomRole enum values (unknown roles are ignored).

    Args:
        raw_token: The raw JWT string (without the "Bearer " prefix).
        settings: AuthSettings instance providing issuer, audience, algorithms.

    Returns:
        A fully verified AuthenticatedPrincipal value object.

    Raises:
        TokenExpiredError: If the token has passed its ``exp`` claim.
        TokenInvalidError: If the token fails signature or claims validation.
        AuthenticationError: If the JWKS endpoint is unreachable.
    """
    # Fetch signing keys — may raise AuthenticationError if JWKS unavailable.
    keys = _jwks_cache.get_keys(
        jwks_uri=settings.jwks_uri,
        ttl=settings.jwks_cache_ttl_seconds,
    )

    try:
        payload: dict[str, Any] = jwt.decode(
            raw_token,
            keys,
            algorithms=settings.jwt_algorithms,
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except ExpiredSignatureError as exc:
        # Log jti only if available without the token contents.
        log.info("auth_adapter.token_expired")
        raise TokenExpiredError("The bearer token has expired.") from exc
    except JWTError as exc:
        log.info("auth_adapter.token_invalid", reason=type(exc).__name__)
        raise TokenInvalidError(
            "The bearer token failed signature or claims validation."
        ) from exc

    # Extract required claims.
    sub: str | None = payload.get("sub")
    jti: str | None = payload.get("jti")
    tenant_id_raw: str | None = payload.get("tenant_id")
    roles_raw: list[str] = payload.get("roles", [])

    if not sub:
        raise TokenInvalidError("Bearer token is missing the required 'sub' claim.")
    if not jti:
        raise TokenInvalidError("Bearer token is missing the required 'jti' claim.")
    if not tenant_id_raw:
        raise TokenInvalidError(
            "Bearer token is missing the required 'tenant_id' claim."
        )

    try:
        tenant_id = uuid.UUID(tenant_id_raw)
    except ValueError as exc:
        raise TokenInvalidError(
            "Bearer token 'tenant_id' claim is not a valid UUID."
        ) from exc

    # Map role strings — unknown roles are silently skipped.
    roles: frozenset[PhantomRole] = frozenset(
        PhantomRole(r) for r in roles_raw if r in PhantomRole._value2member_map_
    )

    principal = AuthenticatedPrincipal(
        tenant_id=tenant_id,
        user_id=sub,
        roles=roles,
        token_jti=jti,
    )

    # Log only non-sensitive identifiers.
    log.debug(
        "auth_adapter.principal_verified",
        tenant_id=str(tenant_id),
        token_jti=jti,
    )
    return principal
