"""
api-gateway FastAPI dependency injection helpers.

Provides:
- get_current_principal()   Extracts and verifies the bearer token.
- require_role()            Returns a dependency factory for role enforcement.
- require_tenant_match()    Validates path tenant_id matches principal.
- get_db_pool()             Yields the asyncpg connection pool.
- get_redis()               Yields the async Redis client.

These are FastAPI-specific and live in the interface layer.
They import from infrastructure (auth_adapter) but never from application.
"""

from __future__ import annotations

import uuid
from typing import Annotated

import asyncpg
import redis.asyncio as aioredis
import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.domain.entities import AuthenticatedPrincipal, PhantomRole
from app.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    TenantMismatchError,
)
from app.infrastructure.auth_adapter import verify_jwt
from app.infrastructure.auth_settings import get_auth_settings

log: structlog.BoundLogger = structlog.get_logger(__name__)

# HTTPBearer does not auto_error so we can produce a typed 401 ourselves.
_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# get_current_principal
# ---------------------------------------------------------------------------


async def get_current_principal(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ] = None,
) -> AuthenticatedPrincipal:
    """Extract, verify, and return the authenticated principal from the bearer token.

    Args:
        request: The current FastAPI Request (used for structlog context).
        credentials: HTTP Authorization header parsed by HTTPBearer.

    Returns:
        A verified AuthenticatedPrincipal.

    Raises:
        AuthenticationError: If no bearer token is present or validation fails.
    """
    if credentials is None:
        raise AuthenticationError("No bearer token provided.")

    settings = get_auth_settings()
    principal = verify_jwt(credentials.credentials, settings)
    return principal


# ---------------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------------


def require_role(*roles: PhantomRole) -> type[AuthenticatedPrincipal]:
    """Return a FastAPI dependency that enforces at least one of the given roles.

    Usage::

        @router.get("/endpoint")
        async def endpoint(
            principal: Annotated[
                AuthenticatedPrincipal,
                Depends(require_role(PhantomRole.ANALYST, PhantomRole.ADMIN)),
            ],
        ) -> ...:
            ...

    Args:
        *roles: One or more PhantomRole values; principal must hold at least one.

    Returns:
        A FastAPI Depends-compatible dependency callable.
    """
    required = frozenset(roles)

    async def _dependency(
        principal: Annotated[
            AuthenticatedPrincipal, Depends(get_current_principal)
        ],
    ) -> AuthenticatedPrincipal:
        """Inner dependency that checks role membership.

        Args:
            principal: The verified AuthenticatedPrincipal.

        Returns:
            The principal if role check passes.

        Raises:
            AuthorizationError: If the principal holds none of the required roles.
        """
        if PhantomRole.ADMIN in principal.roles:
            # ADMIN bypasses all role checks.
            return principal
        if not principal.has_any_role(*required):
            log.info(
                "authz.role_denied",
                required_roles=[r.value for r in required],
                principal_roles=[r.value for r in principal.roles],
                token_jti=principal.token_jti,
            )
            raise AuthorizationError(
                f"Required role(s): {[r.value for r in required]}. "
                f"Principal holds: {[r.value for r in principal.roles]}."
            )
        return principal

    return _dependency  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# require_tenant_match
# ---------------------------------------------------------------------------


async def require_tenant_match(
    tenant_id: uuid.UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> AuthenticatedPrincipal:
    """Validate that the path parameter tenant_id matches the JWT tenant claim.

    Args:
        tenant_id: UUID extracted from the request path.
        principal: The verified AuthenticatedPrincipal.

    Returns:
        The principal if the tenant IDs match.

    Raises:
        TenantMismatchError: If tenant_id differs from principal.tenant_id.
    """
    if PhantomRole.ADMIN in principal.roles:
        # ADMIN may operate across tenants.
        return principal

    if tenant_id != principal.tenant_id:
        log.info(
            "authz.tenant_mismatch",
            path_tenant_id=str(tenant_id),
            principal_tenant_id=str(principal.tenant_id),
            token_jti=principal.token_jti,
        )
        raise TenantMismatchError(
            f"Resource tenant {tenant_id} does not match token tenant "
            f"{principal.tenant_id}."
        )
    return principal


# ---------------------------------------------------------------------------
# get_db_pool
# ---------------------------------------------------------------------------


async def get_db_pool(request: Request) -> asyncpg.Pool:
    """Return the asyncpg connection pool from application state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The active asyncpg.Pool.

    Raises:
        RuntimeError: If the pool is not initialised on app.state.
    """
    pool: asyncpg.Pool | None = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise RuntimeError(
            "Database pool not initialised. "
            "Check the application lifespan startup handler."
        )
    return pool


# ---------------------------------------------------------------------------
# get_redis
# ---------------------------------------------------------------------------


async def get_redis(request: Request) -> aioredis.Redis:
    """Return the async Redis client from application state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The active aioredis.Redis client.

    Raises:
        RuntimeError: If the Redis client is not initialised on app.state.
    """
    redis: aioredis.Redis | None = getattr(request.app.state, "redis", None)
    if redis is None:
        raise RuntimeError(
            "Redis client not initialised. "
            "Check the application lifespan startup handler."
        )
    return redis
