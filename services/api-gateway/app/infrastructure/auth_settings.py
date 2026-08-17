"""
api-gateway authentication settings.

Reads JWT/JWKS configuration from environment variables via pydantic-settings.
All values are validated at startup; missing required values abort the process.

Environment variables:
    PHANTOM_JWT_ISSUER      Required. Expected ``iss`` claim value.
    PHANTOM_JWT_AUDIENCE    Required. Expected ``aud`` claim value.
    PHANTOM_JWKS_URI        Required. HTTPS URI of the JWKS endpoint.
    PHANTOM_JWT_ALGORITHMS  Optional. Comma-separated allowed algorithms.
                            Default: "RS256".
    PHANTOM_JWKS_CACHE_TTL  Optional. JWKS cache TTL in seconds. Default: 300.
"""

from __future__ import annotations

import functools

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Authentication configuration sourced from environment variables.

    Attributes:
        jwt_issuer: Expected ``iss`` claim in every JWT.
        jwt_audience: Expected ``aud`` claim in every JWT.
        jwks_uri: HTTPS endpoint serving the JSON Web Key Set.
        jwt_algorithms: Allowed signing algorithms (list).
        jwks_cache_ttl_seconds: Seconds to cache the fetched JWKS.
    """

    model_config = SettingsConfigDict(
        env_prefix="PHANTOM_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    jwt_issuer: str
    jwt_audience: str
    jwks_uri: str
    jwt_algorithms: list[str] = ["RS256"]
    jwks_cache_ttl_seconds: int = 300


@functools.lru_cache(maxsize=1)
def get_auth_settings() -> AuthSettings:
    """Return the cached AuthSettings singleton.

    Constructed once on first call; subsequent calls return the cached instance.
    LRU cache is intentional — settings are read-only after startup.

    Returns:
        The validated AuthSettings instance.
    """
    return AuthSettings()  # type: ignore[call-arg]
