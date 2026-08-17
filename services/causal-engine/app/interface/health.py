"""
causal-engine health probe routes.

Provides /healthz (liveness) and /readyz (readiness) endpoints
for Kubernetes probing. Checks PostgreSQL and Redis connectivity.

These routes are mounted on the lightweight FastAPI health app
that runs on HEALTH_PORT (default 8081), separate from the main
Redis Streams consumer process.
"""

from __future__ import annotations

import fastapi
import structlog
from fastapi.responses import JSONResponse

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = fastapi.APIRouter()


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Liveness probe — always 200 once the process is running.

    Returns:
        Status dict with ``status: ok``.
    """
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness probe — verifies postgres and redis connectivity.

    Attempts to import the shared _STATE dict from the worker module.
    If the worker has not yet initialised (e.g. during startup), returns
    503 with ``not_initialized`` status for each component.

    Returns:
        200 JSONResponse when all components are ready; 503 otherwise.
    """
    checks: dict[str, str] = {}
    all_ok = True

    try:
        from app.interface.worker import _STATE
    except ImportError:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "error": "worker not initialised"},
        )

    # Postgres check.
    try:
        import asyncpg
        pool: asyncpg.Pool | None = _STATE.get("db_pool")
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
        redis_client = _STATE.get("redis")
        if redis_client is None:
            checks["redis"] = "not_initialized"
            all_ok = False
        else:
            await redis_client.ping()
            checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc}"
        all_ok = False

    # XGBoost model check (only if PCEPS_MODEL_PATH was configured).
    if _STATE.get("xgboost_required"):
        checks["xgboost"] = "ok" if _STATE.get("xgboost_ready") else "not_loaded"
        if not _STATE.get("xgboost_ready"):
            all_ok = False
    else:
        checks["xgboost"] = "not_configured"

    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "not_ready", "checks": checks},
    )
