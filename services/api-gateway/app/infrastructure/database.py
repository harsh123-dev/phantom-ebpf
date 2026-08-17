"""
services/api-gateway/app/infrastructure/database.py

asyncpg connection pool lifecycle, query helpers, and migration runner
for the api-gateway PostgreSQL database.

Design decisions:
- Pool is a module-level singleton created at startup and closed at shutdown.
- All query calls are wrapped with structlog timing at DEBUG level.
- The migration runner applies all SQL files in lexicographic order,
  skipping versions already recorded in schema_migrations.
- Migrations run in a single transaction per file; any error rolls back
  the file and re-raises to abort startup.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import asyncpg
import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level pool singleton
# ---------------------------------------------------------------------------

_pool: asyncpg.Pool | None = None

# ---------------------------------------------------------------------------
# Settings (read from environment at startup)
# ---------------------------------------------------------------------------

_DEFAULT_DATABASE_URL = (
    "postgresql://phantom:phantom_dev_password@localhost:5432/phantom"
)


def _database_url() -> str:
    """Return the DATABASE_URL from the environment.

    Returns:
        The database URL string.
    """
    return os.environ.get("DATABASE_URL", _DEFAULT_DATABASE_URL)


# ---------------------------------------------------------------------------
# Pool lifecycle
# ---------------------------------------------------------------------------


async def create_pool(
    database_url: str | None = None,
    min_size: int = 2,
    max_size: int = 20,
    command_timeout: float = 30.0,
    statement_cache_size: int = 100,
) -> asyncpg.Pool:
    """Create and store the module-level asyncpg connection pool.

    Should be called once at application startup (FastAPI lifespan).
    Subsequent calls return the existing pool without creating a new one.

    Args:
        database_url: PostgreSQL connection URL. Defaults to DATABASE_URL env var.
        min_size: Minimum pool size (kept-alive connections).
        max_size: Maximum pool size.
        command_timeout: Default command timeout in seconds.
        statement_cache_size: Prepared statement cache size per connection.

    Returns:
        The active asyncpg.Pool.
    """
    global _pool
    if _pool is not None:
        return _pool

    url = database_url or _database_url()
    log.info(
        "database.pool_creating",
        min_size=min_size,
        max_size=max_size,
    )
    _pool = await asyncpg.create_pool(
        url,
        min_size=min_size,
        max_size=max_size,
        command_timeout=command_timeout,
        statement_cache_size=statement_cache_size,
    )
    log.info("database.pool_ready")
    return _pool


async def close_pool() -> None:
    """Close the module-level connection pool.

    Should be called once during application shutdown.
    Idempotent: does nothing if the pool is already closed or was never created.
    """
    global _pool
    if _pool is None:
        return
    log.info("database.pool_closing")
    await _pool.close()
    _pool = None
    log.info("database.pool_closed")


def get_pool() -> asyncpg.Pool:
    """Return the active connection pool.

    Returns:
        The active asyncpg.Pool.

    Raises:
        RuntimeError: If the pool has not been created yet.
    """
    if _pool is None:
        raise RuntimeError(
            "Database pool is not initialised. "
            "Call create_pool() during application startup."
        )
    return _pool


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


async def fetch(
    query: str,
    *args: Any,  # noqa: ANN401
    timeout: float | None = None,
) -> list[asyncpg.Record]:
    """Execute a SELECT query and return all rows with structlog timing.

    Args:
        query: The SQL query string.
        *args: Positional query parameters.
        timeout: Optional per-query timeout in seconds.

    Returns:
        List of asyncpg.Record rows.
    """
    pool = get_pool()
    t0 = time.perf_counter()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *args, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.debug(
        "database.fetch",
        elapsed_ms=round(elapsed_ms, 2),
        rows=len(rows),
    )
    return list(rows)


async def fetchrow(
    query: str,
    *args: Any,  # noqa: ANN401
    timeout: float | None = None,
) -> asyncpg.Record | None:
    """Execute a SELECT query and return at most one row.

    Args:
        query: The SQL query string.
        *args: Positional query parameters.
        timeout: Optional per-query timeout in seconds.

    Returns:
        A single asyncpg.Record or None if no rows match.
    """
    pool = get_pool()
    t0 = time.perf_counter()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(query, *args, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.debug(
        "database.fetchrow",
        elapsed_ms=round(elapsed_ms, 2),
        found=row is not None,
    )
    return row


async def fetchval(
    query: str,
    *args: Any,  # noqa: ANN401
    column: int = 0,
    timeout: float | None = None,
) -> Any:  # noqa: ANN401
    """Execute a query and return a single scalar value.

    Args:
        query: The SQL query string.
        *args: Positional query parameters.
        column: Column index to return (default 0).
        timeout: Optional per-query timeout in seconds.

    Returns:
        The scalar value or None.
    """
    pool = get_pool()
    t0 = time.perf_counter()
    async with pool.acquire() as conn:
        value = await conn.fetchval(query, *args, column=column, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.debug(
        "database.fetchval",
        elapsed_ms=round(elapsed_ms, 2),
    )
    return value


async def execute(
    query: str,
    *args: Any,  # noqa: ANN401
    timeout: float | None = None,
) -> str:
    """Execute a DML statement (INSERT, UPDATE, DELETE) and return status.

    Args:
        query: The SQL statement string.
        *args: Positional query parameters.
        timeout: Optional per-query timeout in seconds.

    Returns:
        PostgreSQL command status string (e.g., "INSERT 0 1").
    """
    pool = get_pool()
    t0 = time.perf_counter()
    async with pool.acquire() as conn:
        status = await conn.execute(query, *args, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.debug(
        "database.execute",
        status=status,
        elapsed_ms=round(elapsed_ms, 2),
    )
    return str(status)


async def executemany(
    query: str,
    args: Sequence[Sequence[Any]],
    timeout: float | None = None,
) -> None:
    """Execute a DML statement for each row in args.

    Args:
        query: The SQL statement string (with positional parameters).
        args: Sequence of parameter tuples.
        timeout: Optional per-query timeout in seconds.
    """
    pool = get_pool()
    t0 = time.perf_counter()
    async with pool.acquire() as conn:
        await conn.executemany(query, args, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.debug(
        "database.executemany",
        batch_size=len(args),
        elapsed_ms=round(elapsed_ms, 2),
    )


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR: Path = Path(__file__).parent / "migrations"

_SCHEMA_MIGRATIONS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INT         NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT        NOT NULL,
    CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
)
"""


async def run_migrations(
    migrations_dir: Path | None = None,
    database_url: str | None = None,
) -> int:
    """Apply all pending SQL migration files in lexicographic order.

    Each file is applied in its own transaction.  Files whose version number
    is already recorded in schema_migrations are skipped.

    Args:
        migrations_dir: Directory containing ``*.sql`` migration files.
                        Defaults to the ``migrations/`` directory adjacent
                        to this module.
        database_url: PostgreSQL connection URL. Defaults to DATABASE_URL env var.

    Returns:
        Number of migration files applied (not skipped).

    Raises:
        RuntimeError: If a migration file fails and rolls back.
    """
    migrations_dir = migrations_dir or _MIGRATIONS_DIR
    url = database_url or _database_url()

    # Use a dedicated connection (not from the pool) for migrations.
    conn: asyncpg.Connection = await asyncpg.connect(url)
    try:
        # Ensure the tracking table exists.
        await conn.execute(_SCHEMA_MIGRATIONS_TABLE_DDL)

        # Discover applied versions.
        rows = await conn.fetch("SELECT version FROM schema_migrations ORDER BY version")
        applied: set[int] = {row["version"] for row in rows}

        # Collect migration files sorted lexicographically.
        sql_files = sorted(migrations_dir.glob("*.sql"))
        applied_count = 0

        for sql_file in sql_files:
            # Extract version number from filename prefix (e.g., "001_" → 1).
            prefix = sql_file.stem.split("_")[0]
            try:
                version = int(prefix)
            except ValueError:
                log.warning("database.migration_skip_bad_name", file=sql_file.name)
                continue

            if version in applied:
                log.debug(
                    "database.migration_skip_applied",
                    version=version,
                    file=sql_file.name,
                )
                continue

            sql_text = sql_file.read_text(encoding="utf-8")
            log.info(
                "database.migration_applying",
                version=version,
                file=sql_file.name,
            )
            t0 = time.perf_counter()

            try:
                # Each file is wrapped in an explicit transaction.
                async with conn.transaction():
                    await conn.execute(sql_text)
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                log.error(
                    "database.migration_failed",
                    version=version,
                    file=sql_file.name,
                    elapsed_ms=round(elapsed_ms, 2),
                    error=str(exc),
                )
                raise RuntimeError(
                    f"Migration {sql_file.name} (version {version}) failed: {exc}"
                ) from exc

            elapsed_ms = (time.perf_counter() - t0) * 1000
            applied_count += 1
            log.info(
                "database.migration_applied",
                version=version,
                file=sql_file.name,
                elapsed_ms=round(elapsed_ms, 2),
            )

        if applied_count == 0:
            log.info("database.migrations_up_to_date")
        else:
            log.info("database.migrations_complete", applied=applied_count)

        return applied_count
    finally:
        await conn.close()
