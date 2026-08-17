from __future__ import annotations

import asyncio
import dataclasses
import json
import os
from typing import Protocol

import structlog

from app.domain.entities import IncidentReportDocument
from app.domain.exceptions import ReportStorageError

log: structlog.BoundLogger = structlog.get_logger(__name__)


class ReportStoreBackend(Protocol):
    async def put(self, key: str, content: str) -> str:
        """Store content and return its URI."""


class ReportObjectStore:
    """
    Stores rendered report JSON to local filesystem or S3.
    Backend selected by env var REPORT_STORE_BACKEND=local|s3
    """

    def __init__(self) -> None:
        backend = os.environ.get("REPORT_STORE_BACKEND", "local")
        if backend == "s3":
            self._store: ReportStoreBackend = S3ReportStore()
        else:
            self._store = LocalReportStore()

    async def save(
        self,
        tenant_id: str,
        incident_id: str,
        revision: int,
        document: IncidentReportDocument,
    ) -> str:
        """Save report. Returns storage URI."""
        key = f"reports/{tenant_id}/{incident_id}/{revision}.json"
        content = json.dumps(dataclasses.asdict(document), default=str, sort_keys=True)
        return await self._store.put(key, content)


class LocalReportStore:
    """Dev backend: saves to REPORT_STORE_PATH env var directory."""

    async def put(self, key: str, content: str) -> str:
        base = os.environ.get("REPORT_STORE_PATH", "/tmp/phantom-reports")
        path = os.path.join(base, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            await asyncio.to_thread(self._write_file, path, content)
        except OSError as exc:
            log.error("report_store.local_write_failed", path=path, error=str(exc))
            raise ReportStorageError(path=path, reason=str(exc)) from exc
        return f"file://{path}"

    def _write_file(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)


class S3ReportStore:
    """Production backend: saves to S3 bucket."""

    def __init__(self) -> None:
        self._bucket = os.environ.get("REPORT_S3_BUCKET")
        self._region = os.environ.get("AWS_REGION", "us-east-1")

    async def put(self, key: str, content: str) -> str:
        if not self._bucket:
            raise ReportStorageError(path=key, reason="REPORT_S3_BUCKET is not configured")

        # VERIFY: production image should include aioboto3 as specified for async S3 writes.
        try:
            import aioboto3
            from botocore.exceptions import (
                ClientError,
                ConnectTimeoutError,
                EndpointConnectionError,
                ReadTimeoutError,
            )
        except ImportError as exc:
            raise ReportStorageError(path=key, reason="aioboto3 is not installed") from exc

        uri = f"s3://{self._bucket}/{key}"
        try:
            session = aioboto3.Session(region_name=self._region)
            async with session.client("s3") as client:
                await client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=content.encode("utf-8"),
                    ContentType="application/json",
                )
        except (ClientError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError) as exc:
            log.error("report_store.s3_write_failed", uri=uri, error=str(exc))
            raise ReportStorageError(path=uri, reason=str(exc)) from exc
        return uri
