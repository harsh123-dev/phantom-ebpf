"""Apply SBOM-service SQL migrations in its dedicated PostgreSQL schema."""
from __future__ import annotations

import logging
from pathlib import Path

import asyncpg

log = logging.getLogger(__name__)
_MIGRATIONS = Path(__file__).with_name("migrations")


async def run_migrations(
    pool: asyncpg.Pool, migrations_dir: Path | None = None
) -> int:
    """Apply unapplied numbered migrations using the SBOM schema search path.

    ``phantom_sbom`` is selected on every pool connection by the service
    lifespan. The per-schema ``schema_migrations`` table is therefore distinct
    from the API gateway's public-schema migration history.
    """
    migration_dir = migrations_dir or _MIGRATIONS
    applied_count = 0
    async with pool.acquire() as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), "
            "description TEXT NOT NULL)"
        )
        rows = await conn.fetch("SELECT version FROM schema_migrations")
        applied = {int(row["version"]) for row in rows}
        for path in sorted(migration_dir.glob("*.sql")):
            try:
                version = int(path.stem.split("_", 1)[0])
            except ValueError:
                log.warning("sbom_migration_bad_filename", extra={"migration_file": path.name})
                continue
            if version in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            log.info(
                "sbom_migration_applying",
                extra={"version": version, "migration_file": path.name},
            )
            try:
                async with conn.transaction():
                    await conn.execute(sql)
                    # Keep the runner authoritative for migrations that do not
                    # include their own version INSERT. Older migrations also
                    # write this row; ON CONFLICT makes that compatible.
                    await conn.execute(
                        "INSERT INTO schema_migrations (version, description) "
                        "VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
                        version,
                        path.stem.split("_", 1)[1].replace("_", " "),
                    )
            except Exception:
                log.exception("sbom_migration_failed", extra={"version": version})
                raise
            applied_count += 1
    log.info("sbom_migrations_complete", extra={"applied": applied_count})
    return applied_count
