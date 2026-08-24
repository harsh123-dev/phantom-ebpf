"""
api-gateway FastAPI application entry point.

Constructs the public FastAPI application, configures structlog,
registers all routers under /api/v1, adds the WebSocket drift stream,
exposes /healthz and /readyz probes, and wires infrastructure dependencies.

Middleware stack (applied outermost first):
  1. RequestIDMiddleware   — X-Request-ID header + structlog binding
  2. StructlogMiddleware   — structured request/response logging
  3. PrometheusMiddleware  — prometheus_client metrics

Infrastructure lifecycle (FastAPI lifespan):
  Startup:  create asyncpg pool, create Redis client, run migrations
  Shutdown: close asyncpg pool, close Redis client
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from app.domain.entities import APIErrorCode
from app.domain.exceptions import GatewayError
from app.infrastructure.database import close_pool, create_pool, run_migrations
from app.interface.middleware import (
    PrometheusMiddleware,
    RequestIDMiddleware,
    StructlogMiddleware,
)

# ---------------------------------------------------------------------------
# structlog configuration
# ---------------------------------------------------------------------------

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Redis configuration helper
# ---------------------------------------------------------------------------

_DEFAULT_REDIS_URL = "redis://:phantom_dev_password@localhost:6379/0"


def _redis_url() -> str:
    """Return the REDIS_URL from the environment.

    Returns:
        Redis connection URL string.
    """
    return os.environ.get("REDIS_URL", _DEFAULT_REDIS_URL)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage infrastructure lifecycle: startup and graceful shutdown.

    Startup:
    - Creates the asyncpg connection pool.
    - Applies pending database migrations.
    - Creates the async Redis client.

    Shutdown:
    - Closes the asyncpg pool.
    - Closes the Redis client.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to the ASGI server while the application is running.
    """
    # ---------- Startup ----------
    log.info("gateway.startup")

    # Asyncpg pool.
    pool = await create_pool()
    app.state.db_pool = pool

    # Run pending migrations.
    try:
        applied = await run_migrations()
        log.info("gateway.migrations_complete", applied=applied)
    except Exception as exc:
        log.error("gateway.migrations_failed", error=str(exc))
        raise

    # Redis async client.
    redis_client = aioredis.from_url(
        _redis_url(),
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )
    app.state.redis = redis_client
    log.info("gateway.redis_connected")

    log.info("gateway.ready")
    yield

    # ---------- Shutdown ----------
    log.info("gateway.shutdown")
    await close_pool()
    await redis_client.aclose()
    log.info("gateway.shutdown_complete")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Construct and configure the PHANTOM api-gateway FastAPI application.

    Returns:
        The fully configured FastAPI application instance.
    """
    app = FastAPI(
        title="PHANTOM API Gateway",
        description=(
            "Causal Attribution of Runtime SBOM Drift — "
            "public REST/WebSocket API gateway."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ---- CORS (must be added before other middleware) ----
    # CORS_ALLOW_ORIGINS: comma-separated list of allowed origins, or "*" for all.
    # In production, set this to the exact frontend origin only.
    _cors_origins_raw = os.environ.get("CORS_ALLOW_ORIGINS", "")
    _cors_origins = (
        [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
        if _cors_origins_raw
        else []
    )
    if _cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ---- Middleware (added in reverse: first added = outermost) ----
    app.add_middleware(PrometheusMiddleware)
    app.add_middleware(StructlogMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # ---- Exception handlers ----
    @app.exception_handler(GatewayError)
    async def gateway_error_handler(
        request: Request, exc: GatewayError
    ) -> JSONResponse:
        """Convert GatewayError subclasses to structured JSON responses.

        Args:
            request: The current request.
            exc: The caught GatewayError.

        Returns:
            A JSONResponse with the error code, message, and HTTP status.
        """
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "error_code": exc.error_code.value,
                "message": exc.message,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Convert Pydantic RequestValidationError to a structured 422 response.

        Args:
            request: The current request.
            exc: The caught RequestValidationError.

        Returns:
            JSONResponse with VALIDATION_ERROR code and detail list.
        """
        return JSONResponse(
            status_code=422,
            content={
                "error_code": APIErrorCode.VALIDATION_ERROR.value,
                "message": "Request validation failed.",
                "detail": exc.errors(),
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Catch-all handler — prevents stack trace leakage on unexpected errors.

        Args:
            request: The current request.
            exc: The unexpected exception.

        Returns:
            JSON 500 with INTERNAL_ERROR code and no stack trace.
        """
        log.error(
            "gateway.unhandled_exception",
            error=type(exc).__name__,
            request_id=getattr(request.state, "request_id", None),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error_code": APIErrorCode.INTERNAL_ERROR.value,
                "message": "An unexpected internal error occurred.",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    # ---- Routers ----
    from app.interface.routers import (
        attribution_router,
        bdg_router,
        contract_router,
        drift_router,
        incident_router,
        sbom_router,
    )

    _API_PREFIX = "/api/v1"
    app.include_router(drift_router.router, prefix=_API_PREFIX)
    app.include_router(sbom_router.router, prefix=_API_PREFIX)
    app.include_router(contract_router.router, prefix=_API_PREFIX)
    app.include_router(bdg_router.router, prefix=_API_PREFIX)
    app.include_router(attribution_router.router, prefix=_API_PREFIX)
    app.include_router(incident_router.router, prefix=_API_PREFIX)

    # ---- WebSocket ----
    from app.interface.ws_drift_stream import router as ws_router

    app.include_router(ws_router)

    # ---- Health probes ----
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Kubernetes liveness probe.

        Returns:
            JSON dict with status "ok".
        """
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> JSONResponse:
        """Kubernetes readiness probe — checks DB and Redis connectivity.

        Args:
            request: The current request (used to access app.state).

        Returns:
            JSON dict with component status; HTTP 200 or 503.
        """
        checks: dict[str, str] = {}
        ok = True

        # DB check.
        try:
            pool = request.app.state.db_pool
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            checks["db"] = "ok"
        except Exception as exc:
            checks["db"] = f"error: {type(exc).__name__}"
            ok = False

        # Redis check.
        try:
            await request.app.state.redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {type(exc).__name__}"
            ok = False

        return JSONResponse(
            content=checks,
            status_code=200 if ok else 503,
        )

    # ---- Prometheus metrics endpoint ----
    # Note: /metrics has no auth. It is cluster-internal only.
    # NetworkPolicy restricts access to Prometheus scraper only.
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app


# ---------------------------------------------------------------------------
# Application singleton
# ---------------------------------------------------------------------------

app = create_app()
