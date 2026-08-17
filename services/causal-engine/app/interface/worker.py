"""
causal-engine worker entry point.

Bootstraps the Redis Streams consumer loop for drift-event
BDG mutation and attribution job dispatch.

Startup sequence:
1. Load settings from environment variables.
2. Create asyncpg connection pool.
3. Create Redis async client.
4. Load XGBoost PCEPS model (if PCEPS_MODEL_PATH is set).
5. Initialise in-memory BehavioralDependencyGraph.
6. Wire infrastructure adapters to domain ports.
7. Wire use cases with domain ports.
8. Start the DriftEventRedisConsumer loop.
9. Expose /healthz and /readyz on HEALTH_PORT (default 8081).
   - /healthz: always returns 200 (liveness probe).
   - /readyz: checks postgres connected, redis connected,
              xgboost model loaded (if path was configured).
10. Handle SIGTERM/SIGINT for graceful shutdown.
"""

from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path
from typing import Any

import asyncpg
import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.application.use_cases import UpdateBdgUseCase
from app.domain.bdg import BehavioralDependencyGraph
from app.infrastructure.postgres_repository import (
    PostgresBdgRepository,
)
from app.infrastructure.redis_consumer import DriftEventRedisConsumer

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Settings from environment
# ---------------------------------------------------------------------------

_DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "postgresql://phantom:phantom@localhost:5432/phantom",
)
_REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_REDIS_STREAM_KEY: str = os.environ.get(
    "CAUSAL_ENGINE_STREAM_KEY", "phantom:drift-events"
)
_REDIS_CONSUMER_GROUP: str = os.environ.get(
    "CAUSAL_ENGINE_CONSUMER_GROUP", "causal-engine-bdg-updater"
)
_HEALTH_PORT: int = int(os.environ.get("HEALTH_PORT", "8081"))
_BDG_DECAY_LAMBDA: float = float(os.environ.get("BDG_DECAY_LAMBDA", "0.95"))
_BDG_DECAY_DELTA_SECONDS: float = float(
    os.environ.get("BDG_DECAY_DELTA_SECONDS", "300.0")
)
_BDG_BATCH_SIZE: int = int(os.environ.get("BDG_BATCH_SIZE", "100"))
_PCEPS_MODEL_PATH: str | None = os.environ.get("PCEPS_MODEL_PATH")


# ---------------------------------------------------------------------------
# Shared state (populated during startup)
# ---------------------------------------------------------------------------

_STATE: dict[str, Any] = {
    "db_pool": None,
    "redis": None,
    "xgboost_ready": False,
    "xgboost_required": False,
}


# ---------------------------------------------------------------------------
# Health check app (minimal FastAPI on separate port 8081)
# ---------------------------------------------------------------------------


def _build_health_app() -> FastAPI:
    """Build a minimal FastAPI app for health/readiness probes.

    /healthz: Liveness probe — always 200 once the process is up.
    /readyz:  Readiness probe — checks:
              1. PostgreSQL: can acquire a connection and run SELECT 1.
              2. Redis: can PING.
              3. XGBoost model: loaded (if PCEPS_MODEL_PATH is configured).

    Returns:
        A FastAPI app with /healthz and /readyz endpoints.
    """
    health_app = FastAPI(title="causal-engine-health", docs_url=None, redoc_url=None)

    @health_app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness probe — always ok once the process is running.

        Returns:
            Status dict.
        """
        return {"status": "ok"}

    @health_app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        """Readiness probe — verifies postgres, redis, xgboost.

        Returns:
            JSONResponse with component statuses; 200 if all ready, 503 otherwise.
        """
        checks: dict[str, str] = {}
        all_ok = True

        # --- Postgres check ---
        pool: asyncpg.Pool | None = _STATE.get("db_pool")
        if pool is None:
            checks["postgres"] = "not_initialized"
            all_ok = False
        else:
            try:
                async with pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                checks["postgres"] = "ok"
            except Exception as exc:  # noqa: BLE001
                checks["postgres"] = f"error: {exc}"
                all_ok = False

        # --- Redis check ---
        redis_client: aioredis.Redis | None = _STATE.get("redis")
        if redis_client is None:
            checks["redis"] = "not_initialized"
            all_ok = False
        else:
            try:
                await redis_client.ping()
                checks["redis"] = "ok"
            except Exception as exc:  # noqa: BLE001
                checks["redis"] = f"error: {exc}"
                all_ok = False

        # --- XGBoost model check (only if PCEPS_MODEL_PATH was configured) ---
        if _STATE.get("xgboost_required"):
            if _STATE.get("xgboost_ready"):
                checks["xgboost"] = "ok"
            else:
                checks["xgboost"] = "not_loaded"
                all_ok = False
        else:
            checks["xgboost"] = "not_configured"

        status_code = 200 if all_ok else 503
        return JSONResponse(content=checks, status_code=status_code)

    return health_app


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def _run_worker() -> None:
    """Bootstrap and run the causal-engine worker.

    Sets up all infrastructure, wires the dependency graph, and starts
    the Redis consumer loop alongside the health HTTP server.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(),
    )

    log.info("worker.starting", stream_key=_REDIS_STREAM_KEY)

    # Create asyncpg pool.
    pool = await asyncpg.create_pool(
        _DATABASE_URL,
        min_size=2,
        max_size=10,
        command_timeout=30,
    )
    _STATE["db_pool"] = pool
    log.info("worker.db_pool_created")

    # Create Redis client.
    redis_client = aioredis.from_url(_REDIS_URL, decode_responses=False)
    _STATE["redis"] = redis_client
    log.info("worker.redis_connected")

    # Optionally load XGBoost PCEPS model.
    if _PCEPS_MODEL_PATH:
        _STATE["xgboost_required"] = True
        try:
            from app.infrastructure.xgboost_scorer import XGBoostScoringAdapter  # noqa: F401
            scorer = XGBoostScoringAdapter(model_dir=Path(_PCEPS_MODEL_PATH))
            await scorer._ensure_loaded()
            _STATE["xgboost_ready"] = True
            log.info("worker.xgboost_loaded", model_path=_PCEPS_MODEL_PATH)
        except Exception as exc:
            log.warning(
                "worker.xgboost_load_failed",
                model_path=_PCEPS_MODEL_PATH,
                error=str(exc),
            )
            # Non-fatal: scoring will be unavailable until the model is fixed.

    # Initialise in-memory BDG.
    bdg = BehavioralDependencyGraph(
        decay_lambda=_BDG_DECAY_LAMBDA,
        decay_delta_seconds=_BDG_DECAY_DELTA_SECONDS,
        batch_size=_BDG_BATCH_SIZE,
    )

    # Wire infrastructure.
    bdg_repo = PostgresBdgRepository(pool)
    update_use_case = UpdateBdgUseCase(bdg=bdg, bdg_repo=bdg_repo)

    # Start a separate HTTP server for metrics on port 9090
    # so it does not share the health server (8081)
    from prometheus_client import start_http_server
    start_http_server(9090)
    log.info("worker.metrics_server_started", port=9090)

    consumer = DriftEventRedisConsumer(
        redis_client=redis_client,
        update_bdg_use_case=update_use_case,
        stream_key=_REDIS_STREAM_KEY,
        consumer_group=_REDIS_CONSUMER_GROUP,
    )

    # Build health app.
    health_app = _build_health_app()
    health_config = uvicorn.Config(
        app=health_app,
        host="0.0.0.0",
        port=_HEALTH_PORT,
        log_level="warning",
        # Disable uvicorn's own signal handling; we handle SIGTERM below.
        loop="asyncio",
    )
    health_server = uvicorn.Server(health_config)
    # Prevent uvicorn from installing its own signal handlers.
    health_server.install_signal_handlers = lambda: None  # type: ignore[attr-defined]

    # Graceful shutdown.
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _handle_signal(*_: object) -> None:
        log.info("worker.shutdown_signal")
        shutdown_event.set()

    # SIGTERM from Kubernetes; SIGINT for local Ctrl-C.
    # add_signal_handler only works on Unix; skip on Windows (tests).
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _handle_signal)
    except NotImplementedError:
        # Windows: signal handling for event loops is limited.
        log.debug("worker.signal_handler_unavailable")

    log.info("worker.started", health_port=_HEALTH_PORT)

    # Run consumer and health server concurrently.
    consumer_task = asyncio.create_task(consumer.run(), name="redis-consumer")
    health_task = asyncio.create_task(health_server.serve(), name="health-server")

    # Wait for shutdown signal.
    await shutdown_event.wait()

    log.info("worker.stopping")
    await consumer.stop()
    health_server.should_exit = True

    await asyncio.gather(consumer_task, health_task, return_exceptions=True)
    await pool.close()
    await redis_client.aclose()
    log.info("worker.stopped")


def main() -> None:
    """Entry point for the causal-engine worker process.

    Called by ``python -m app.interface.worker`` or the pyproject
    entry point.
    """
    asyncio.run(_run_worker())


if __name__ == "__main__":
    main()
