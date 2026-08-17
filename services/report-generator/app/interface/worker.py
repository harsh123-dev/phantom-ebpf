from __future__ import annotations

import asyncio
import os
import signal
import socket
from typing import Any, cast

import asyncpg
import redis.asyncio as aioredis
import structlog
import uvicorn
from asyncpg import PostgresError
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from phantom_core.logging import configure_structlog
from redis.exceptions import RedisError

from app.application.use_cases import GenerateReportUseCase
from app.infrastructure.object_store_adapter import ReportObjectStore
from app.infrastructure.postgres_repository import (
    ReportDocumentRepository,
    ReportEvidenceRepository,
)
from app.infrastructure.renderer_adapter import ReportRenderer

log: structlog.BoundLogger = structlog.get_logger(__name__)

STREAM_KEY = "phantom:stream:report.generate"
COMPLETE_STREAM_KEY = "phantom:stream:report.complete"
DEADLETTER_STREAM_KEY = "phantom:stream:report.deadletter"
CONSUMER_GROUP = "phantom-report-workers"
HEALTH_PORT = 8082

STATE: dict[str, Any] = {
    "pool": None,
    "redis": None,
    "stopping": False,
}


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def _decode_fields(fields: dict[Any, Any]) -> dict[str, str]:
    return {_decode(key): _decode(value) for key, value in fields.items()}


def _build_health_app() -> FastAPI:
    health_app = FastAPI(title="report-generator-health", docs_url=None, redoc_url=None)

    @health_app.get("/healthz", include_in_schema=False) 
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @health_app.get("/readyz", include_in_schema=False) 
    async def readyz() -> JSONResponse:
        checks: dict[str, str] = {}
        ready = True

        pool: asyncpg.Pool | None = STATE.get("pool")
        if pool is None:
            checks["postgres"] = "not_initialized"
            ready = False
        else:
            try:
                async with pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                checks["postgres"] = "ok"
            except PostgresError as exc:
                checks["postgres"] = f"error: {exc}"
                ready = False

        redis_client: aioredis.Redis | None = STATE.get("redis")
        if redis_client is None:
            checks["redis"] = "not_initialized"
            ready = False
        else:
            try:
                await redis_client.ping()
                checks["redis"] = "ok"
            except RedisError as exc:
                checks["redis"] = f"error: {exc}"
                ready = False

        return JSONResponse(content=checks, status_code=200 if ready else 503)

    return health_app


async def _ensure_consumer_group(redis_client: aioredis.Redis) -> None:
    try:
        await redis_client.xgroup_create(
            STREAM_KEY,
            CONSUMER_GROUP,
            id="0",
            mkstream=True,
        )
    except RedisError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _handle_message(
    redis_client: aioredis.Redis,
    use_case: GenerateReportUseCase,
    message_id: str,
    fields: dict[str, str],
) -> None:
    incident_id = fields.get("incident_id")
    tenant_id = fields.get("tenant_id")
    if not incident_id or not tenant_id:
        await redis_client.xadd(
            DEADLETTER_STREAM_KEY,
            {
                **fields,  # type: ignore[dict-item]
                "deadletter_reason": "missing incident_id or tenant_id",
                "source_message_id": message_id,
            },
        )
        await redis_client.xack(STREAM_KEY, CONSUMER_GROUP, message_id)
        log.warning("report_worker.message_deadlettered_invalid", message_id=message_id)
        return

    try:
        await use_case.execute(incident_id=incident_id, tenant_id=tenant_id)
        await redis_client.xack(STREAM_KEY, CONSUMER_GROUP, message_id)
        log.info(
            "report_worker.message_processed",
            message_id=message_id,
            incident_id=incident_id,
            tenant_id=tenant_id,
        )
    except Exception as exc:  # noqa: BLE001
        retry_count = int(fields.get("retry_count", "0")) + 1
        if retry_count >= 3:
            await redis_client.xadd(
                DEADLETTER_STREAM_KEY,
                {
                    **fields,  # type: ignore[dict-item]
                    "retry_count": str(retry_count),
                    "deadletter_reason": str(exc),
                    "source_message_id": message_id,
                },
            )
            await redis_client.xack(STREAM_KEY, CONSUMER_GROUP, message_id)
            log.error(
                "report_worker.message_deadlettered",
                message_id=message_id,
                incident_id=incident_id,
                tenant_id=tenant_id,
                error=str(exc),
            )
        else:
            log.warning(
                "report_worker.message_failed_will_retry",
                message_id=message_id,
                incident_id=incident_id,
                tenant_id=tenant_id,
                retry_count=retry_count,
                error=str(exc),
            )


async def _consumer_loop(
    redis_client: aioredis.Redis,
    use_case: GenerateReportUseCase,
    shutdown_event: asyncio.Event,
) -> None:
    await _ensure_consumer_group(redis_client)
    consumer_name = f"worker-{socket.gethostname()}"
    while not shutdown_event.is_set():
        messages = await redis_client.xreadgroup(
            groupname=CONSUMER_GROUP,
            consumername=consumer_name,
            streams={STREAM_KEY: ">"},
            count=10,
            block=5000,
        )
        for _, stream_messages in messages:  # type: ignore[str-unpack]
            for _raw_entry in stream_messages:  # type: ignore[union-attr]
                _entry = cast(tuple[str, dict[bytes, bytes]], _raw_entry)
                raw_message_id, raw_fields = _entry
                message_id = _decode(raw_message_id)
                fields = _decode_fields(cast(dict[Any, Any], raw_fields))
                await _handle_message(redis_client, use_case, message_id, fields)
                if shutdown_event.is_set():
                    return


async def main() -> None:
    """
    Entry point for report generator worker.
    """
    configure_structlog(service_name="report-generator")
    postgres_dsn = os.environ.get("POSTGRES_DSN", "postgresql://phantom:phantom@localhost:5432/phantom")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    pool: asyncpg.Pool | None = None
    redis_client: aioredis.Redis | None = None
    health_server: uvicorn.Server | None = None

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown() -> None:
        STATE["stopping"] = True
        shutdown_event.set()
        log.info("report_worker.shutdown_requested")

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _request_shutdown)
    except NotImplementedError:
        log.debug("report_worker.signal_handlers_unavailable")

    try:
        pool = await asyncpg.create_pool(postgres_dsn, min_size=1, max_size=10, command_timeout=30)
        STATE["pool"] = pool
        redis_client = aioredis.from_url(redis_url, decode_responses=False) 
        STATE["redis"] = redis_client

        async with pool.acquire() as conn:
            await conn.execute(ReportDocumentRepository.MIGRATION_SQL)

        evidence_repo = ReportEvidenceRepository(pool)
        document_repo = ReportDocumentRepository(pool)
        renderer = ReportRenderer()
        object_store = ReportObjectStore()
        use_case = GenerateReportUseCase(
            evidence_repo=evidence_repo,
            document_repo=document_repo,
            renderer=renderer,
            object_store=object_store,
            redis=redis_client,
        )

        health_config = uvicorn.Config(
            app=_build_health_app(),
            host="0.0.0.0",
            port=HEALTH_PORT,
            log_level="warning",
            loop="asyncio",
        )
        health_server = uvicorn.Server(health_config)
        health_server.install_signal_handlers = lambda: None  # type: ignore[attr-defined]
        health_task = asyncio.create_task(health_server.serve(), name="report-health")
        consumer_task = asyncio.create_task(
            _consumer_loop(redis_client, use_case, shutdown_event),
            name="report-consumer",
        )
        log.info("report_worker.started", health_port=HEALTH_PORT, stream=STREAM_KEY)

        done, pending = await asyncio.wait(
            {consumer_task, health_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        if health_server is not None:
            health_server.should_exit = True
        if redis_client is not None:
            await redis_client.aclose()
        if pool is not None:
            await pool.close()
        log.info("report_worker.stopped")


if __name__ == "__main__":
    asyncio.run(main())
