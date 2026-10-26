from __future__ import annotations

import uuid
from datetime import UTC, datetime

import asyncpg
import pytest

from app.domain.entities import (
    BindingStatus,
    Component,
    ImageDigest,
    Purl,
    Sbom,
    SbomDigest,
    SbomSource,
    VerificationStatus,
)
from app.domain.exceptions import SbomStorageError
from app.infrastructure.postgres.repository import PostgresSbomRepository


class _Transaction:
    def __init__(self) -> None:
        self.rolled_back = False

    async def __aenter__(self) -> _Transaction:
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        self.rolled_back = exc_type is not None


class _Connection:
    def __init__(self) -> None:
        self.tx = _Transaction()

    def transaction(self) -> _Transaction:
        return self.tx

    async def execute(self, *_args) -> str:
        return "INSERT 0 1"

    async def executemany(self, *_args) -> None:
        raise asyncpg.PostgresError("injected component insert failure")


class _Acquire:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    async def __aenter__(self) -> _Connection:
        return self.connection

    async def __aexit__(self, *_args) -> None:
        return None


class _Pool:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection

    def acquire(self) -> _Acquire:
        return _Acquire(self.connection)


@pytest.mark.asyncio
async def test_component_failure_rolls_back_sbom_row() -> None:
    now = datetime.now(UTC)
    sbom_id = uuid.uuid4()
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    sbom = Sbom(
        sbom_id=sbom_id,
        tenant_id=uuid.uuid4(),
        image_digest=ImageDigest("sha256:" + "a" * 64),
        sbom_digest=SbomDigest.compute(document),
        cyclonedx_document=document,
        spec_version="1.5",
        source=SbomSource.SYFT,
        artifact_uri="s3://bucket/sbom.json",
        signature_bundle_uri=None,
        verification_status=VerificationStatus.PENDING,
        generated_at=now,
        created_at=now,
        purl_count=1,
    )
    component = Component(
        component_id=uuid.uuid4(),
        sbom_id=sbom_id,
        purl=Purl("pkg:generic/example@1.0"),
        name="example",
        version="1.0",
        component_type="library",
        binding_status=BindingStatus.AMBIGUOUS,
        binding_confidence=0.0,
        created_at=now,
    )
    connection = _Connection()
    repository = PostgresSbomRepository(_Pool(connection))  # type: ignore[arg-type]

    with pytest.raises(SbomStorageError, match="atomically"):
        await repository.save_with_components(sbom, [component])

    assert connection.tx.rolled_back is True
