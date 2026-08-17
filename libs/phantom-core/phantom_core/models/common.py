"""
phantom_core.models.common — Shared common Pydantic models.

Covers:
- ErrorResponse: canonical gateway error payload (B.1)
- PaginationParams: reusable limit/cursor pagination query parameters
- HealthResponse: /healthz liveness probe response (B.9)
- ReadinessResponse: /readyz readiness probe response (B.9)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from phantom_core.constants import (
    PAGINATION_LIMIT_DEFAULT,
    PAGINATION_LIMIT_MAX,
    PAGINATION_LIMIT_MIN,
    SCHEMA_VERSION,
)


class _PhantomBaseModel(BaseModel):
    """Base Pydantic model for all PHANTOM request/response schemas.

    Enforces:
    - Unknown request fields are rejected (``extra="forbid"``).
    - Strict type coercion disabled; use explicit types.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


# ---------------------------------------------------------------------------
# Error response (B.1 Global Contract Rules)
# ---------------------------------------------------------------------------


class ErrorResponse(_PhantomBaseModel):
    """Canonical error response returned by the api-gateway for all error conditions.

    Attributes:
        schema_version: Always ``"v1"``.
        error_code: Machine-readable error code (matches PhantomError.code).
        message: Human-readable error description.
        request_id: UUID that correlates this error to gateway access logs.
        details: Additional structured context (field names, limits, etc.).
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    error_code: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    request_id: uuid.UUID
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pagination (B.1 Global Contract Rules)
# ---------------------------------------------------------------------------


class PaginationParams(_PhantomBaseModel):
    """Reusable pagination query parameter model for list endpoints.

    Attributes:
        limit: Maximum number of items to return. Range 1..200, default 50.
        cursor: Opaque pagination cursor; ``None`` returns the first page.
    """

    limit: int = Field(
        default=PAGINATION_LIMIT_DEFAULT,
        ge=PAGINATION_LIMIT_MIN,
        le=PAGINATION_LIMIT_MAX,
    )
    cursor: str | None = Field(default=None)


# ---------------------------------------------------------------------------
# Health probes (B.9)
# ---------------------------------------------------------------------------


class HealthResponse(_PhantomBaseModel):
    """Response body for ``GET /healthz`` liveness probe.

    Attributes:
        status: Always ``"ok"`` when the process event loop is available.
        service: Human-readable service name.
        timestamp: UTC RFC 3339 timestamp of this response.
    """

    status: Literal["ok"]
    service: str = Field(..., min_length=1)
    timestamp: datetime


class ReadinessResponse(_PhantomBaseModel):
    """Response body for ``GET /readyz`` readiness probe.

    Attributes:
        status: ``"ready"`` when all mandatory dependencies pass;
            ``"not_ready"`` when one or more fail.
        service: Human-readable service name.
        checks: Per-dependency check results keyed by dependency name.
        timestamp: UTC RFC 3339 timestamp of this response.
    """

    status: Literal["ready", "not_ready"]
    service: str = Field(..., min_length=1)
    checks: dict[str, Literal["pass", "fail", "not_applicable"]]
    timestamp: datetime
