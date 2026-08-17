"""
api-gateway ASGI middleware stack.

Middleware applied in main.py (outermost first):
  1. RequestIDMiddleware   — generate X-Request-ID, bind to structlog context
  2. StructlogMiddleware   — log method/path/status/duration; never body or tokens
  3. PrometheusMiddleware  — emit http_requests_total and http_request_duration_seconds

Design rules:
- Request bodies are NEVER read or logged.
- Bearer tokens are NEVER included in any log record.
- Prometheus labels use parameterized route patterns, never raw path strings
  (prevents cardinality explosion from UUIDs in URLs).
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from phantom_core.metrics import API_REQUEST_DURATION, API_REQUESTS_TOTAL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match

log: structlog.BoundLogger = structlog.get_logger(__name__)

# UUID regex pattern to strip high-cardinality IDs from unmatched paths
_UUID_PATTERN: re.Pattern[str] = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# RequestIDMiddleware
# ---------------------------------------------------------------------------


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate a per-request UUID and attach it to response headers and structlog context.

    The request_id is:
    - Read from the incoming ``X-Request-ID`` header if present and valid.
    - Generated fresh (UUID4) otherwise.
    - Written to the ``X-Request-ID`` response header.
    - Bound to the structlog context for the duration of the request.

    Never logs request bodies or authorization headers.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process the request, injecting a request_id.

        Args:
            request: The incoming ASGI request.
            call_next: The next middleware or route handler.

        Returns:
            The response with X-Request-ID header set.
        """
        incoming = request.headers.get("X-Request-ID", "")
        try:
            request_id = str(uuid.UUID(incoming))
        except ValueError:
            request_id = str(uuid.uuid4())

        # Store on request state for downstream access (e.g. StructlogMiddleware).
        request.state.request_id = request_id

        # Bind to structlog for the duration of this request.
        with structlog.contextvars.bound_contextvars(request_id=request_id):
            response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# StructlogMiddleware
# ---------------------------------------------------------------------------

# Paths that are never logged (health probes generate too much noise).
_SILENT_PATHS: frozenset[str] = frozenset({"/healthz", "/readyz", "/metrics"})


class StructlogMiddleware(BaseHTTPMiddleware):
    """Log every request with method, path, status, duration, request_id.

    NEVER logs:
    - Request or response bodies.
    - Authorization headers or JWT tokens.
    - Query string values (only the path).

    Logs tenant_id when it can be extracted from structlog context
    (set by get_current_principal in downstream handlers).
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Log the request outcome after calling the next handler.

        Args:
            request: The incoming ASGI request.
            call_next: The next middleware or route handler.

        Returns:
            The response unmodified.
        """
        if request.url.path in _SILENT_PATHS:
            return await call_next(request)

        request_id: str = getattr(request.state, "request_id", "")
        t0 = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - t0) * 1000
            log.info(
                "http.request",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                request_id=request_id,
            )
            return response
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.perf_counter() - t0) * 1000
            log.error(
                "http.request.unhandled_error",
                method=request.method,
                path=request.url.path,
                error=type(exc).__name__,
                duration_ms=round(duration_ms, 2),
                request_id=request_id,
            )
            raise


# ---------------------------------------------------------------------------
# PrometheusMiddleware
# ---------------------------------------------------------------------------


def get_parameterized_route(request: Request) -> str:
    """Extract the parameterized route pattern from the Starlette router.

    Falls back to a bucketed path label when no route matches, manually
    stripping UUID patterns to prevent cardinality explosion.

    Args:
        request: The current request.

    Returns:
        A parameterized route string (e.g., ``/api/v1/drift-events``) or
        path with UUIDs replaced by ``{id}``.
    """
    route = request.scope.get("route")
    if route and getattr(route, "path", None):
        return str(route.path)

    for r in getattr(request.app, "routes", []):
        match, _ = r.matches({"type": "http", "path": request.url.path, "method": request.method})
        if match == Match.FULL:
            path_attr = getattr(r, "path", None)
            if path_attr:
                return str(path_attr)
            break

    # Strip UUID patterns manually from path to prevent high-cardinality labels
    return _UUID_PATTERN.sub("{id}", request.url.path)


_get_route_pattern = get_parameterized_route


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Emit prometheus_client metrics for every HTTP request.

    Labels use parameterized route patterns, NOT raw path strings.
    This prevents cardinality explosion from UUID-heavy paths like
    ``/api/v1/attributions/{attribution_id}``.

    Metrics emitted:
    - ``phantom_api_requests_total{route, method, status_code}``
    - ``phantom_api_request_duration_seconds{route, method, status_code}``
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Record metrics around the request.

        Args:
            request: The incoming ASGI request.
            call_next: The next middleware or route handler.

        Returns:
            The response unmodified.
        """
        if request.url.path == "/metrics":
            return await call_next(request)

        route = get_parameterized_route(request)
        method = request.method
        t0 = time.monotonic()
        status_code = "500"

        try:
            response = await call_next(request)
            status_code = str(response.status_code)
            return response
        finally:
            duration_seconds = time.monotonic() - t0
            API_REQUESTS_TOTAL.labels(
                route=route,
                method=method,
                status_code=status_code,
            ).inc()
            API_REQUEST_DURATION.labels(
                route=route,
                method=method,
                status_code=status_code,
            ).observe(duration_seconds)
