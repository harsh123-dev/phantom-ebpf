"""
report-generator health probe routes.

Provides /healthz and /readyz for Kubernetes probing.

/healthz  — liveness:  always 200 once the process is running.
/readyz   — readiness: checks PostgreSQL pool and Redis connectivity.
             Returns 503 if any required component is not ready.

These routes run on HEALTH_PORT (default 8082) as a standalone
FastAPI app, separate from the Redis Streams consumer loop.
"""

from __future__ import annotations

import fastapi
import structlog
from fastapi.responses import JSONResponse

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = fastapi.APIRouter()


@router.get("/healthz", include_in_schema=False) 
async def healthz() -> dict[str, str]:
    """Liveness probe — always ok once the process is running.

    Returns:
        Status dict with ``status: ok``.
    """
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False) 
async def readyz() -> JSONResponse:
    """Readiness probe — verifies postgres and redis connectivity.

    Reads the shared STATE dict from worker.py. Returns 503 if any
    required dependency is not yet initialised.

    Returns:
        200 JSONResponse when all components are ready; 503 otherwise.
    """
    checks: dict[str, str] = {}
    all_ok = True

    try:
        from app.interface.worker import STATE
    except ImportError:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "error": "worker not initialised"},
        )

    # Postgres check.
    try:
        import asyncpg
        pool: asyncpg.Pool | None = STATE.get("pool")
        if pool is None:
            checks["postgres"] = "not_initialized"
            all_ok = False
        else:
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            checks["postgres"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["postgres"] = f"error: {exc}"
        all_ok = False

    # Redis check.
    try:
        redis_client = STATE.get("redis")
        if redis_client is None:
            checks["redis"] = "not_initialized"
            all_ok = False
        else:
            await redis_client.ping()
            checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc}"
        all_ok = False

    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "not_ready", "checks": checks},
    )
