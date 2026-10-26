from __future__ import annotations

from pathlib import Path

import pytest

from app.infrastructure.postgres.migrations import run_migrations


class _Connection:
    def __init__(self) -> None:
        self.migrations: dict[int, str] = {}
        self.executed_sql: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def acquire(self):
        return self

    def transaction(self):
        return self

    async def execute(self, sql: str, *args):
        self.executed_sql.append(sql)
        if sql.startswith("INSERT INTO schema_migrations") and args:
            self.migrations[int(args[0])] = str(args[1])

    async def fetch(self, _sql: str):
        return [{"version": version} for version in self.migrations]


@pytest.mark.asyncio
async def test_runner_records_additive_migration_versions_idempotently(tmp_path: Path) -> None:
    (tmp_path / "003_add_immutable_image_reference.sql").write_text(
        "ALTER TABLE sboms ADD COLUMN image_reference TEXT;"
    )
    connection = _Connection()

    assert await run_migrations(connection, tmp_path) == 1  # type: ignore[arg-type]
    assert connection.migrations == {3: "add immutable image reference"}
    assert await run_migrations(connection, tmp_path) == 0  # type: ignore[arg-type]
