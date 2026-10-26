"""
services/sbom-service/app/interface/dependencies.py

FastAPI dependency injection for the SBOM service.

Provides lifespan-managed asyncpg pool, repository adapters,
use-case factories, and the object-store adapter.

All settings are read from environment variables only; no hardcoded values.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import parse_qs, unquote, urlparse

import asyncpg
import structlog
from fastapi import Depends, FastAPI, Request

from app.application.use_cases.get_sbom import GetSbomUseCase
from app.application.use_cases.ingest_sbom import IngestSbomUseCase
from app.application.use_cases.verify_sbom_signature import (
    EnqueueVerificationUseCase,
    GetVerificationResultUseCase,
    RunVerificationUseCase,
)
from app.infrastructure.cosign.client import CosignClient
from app.infrastructure.postgres.migrations import run_migrations
from app.infrastructure.postgres.repository import (
    PostgresComponentRepository,
    PostgresSbomRepository,
    PostgresVerificationJobRepository,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Object-store placeholder adapter
# ---------------------------------------------------------------------------

import uuid

from app.domain.exceptions import SbomNotFoundError, SbomStorageError
from app.domain.ports import ArtifactStorePort


class _S3ArtifactStore(ArtifactStorePort):
    """Minimal S3-compatible artifact store adapter.

    Uses the boto3/aiobotocore client configured from environment variables.
    In this stub the implementation uploads to the configured S3 bucket.

    Args:
        bucket: S3 bucket name.
        endpoint_url: Optional endpoint override (for MinIO/LocalStack).
    """

    def __init__(
        self,
        bucket: str,
        region: str,
        endpoint_url: str | None = None,
        key_prefix: str = "phantom/evidence/sboms",
        allowed_artifact_prefix: str = "phantom/evidence/",
    ) -> None:
        """Initialise the S3 store.

        Args:
            bucket: S3 bucket name.
            endpoint_url: Optional S3-compatible endpoint override.
        """
        self._bucket = bucket
        self._region = region
        self._endpoint_url = endpoint_url
        self._key_prefix = key_prefix.strip("/")
        self._allowed_artifact_prefix = allowed_artifact_prefix.strip("/") + "/"

    def _object_key(self, sbom_id: uuid.UUID) -> str:
        return f"{self._key_prefix}/{sbom_id}/cyclonedx.json"

    def _validate_external_object(
        self, artifact_uri: str, download_url: str, artifact_version_id: str
    ) -> None:
        uri = urlparse(artifact_uri)
        signed = urlparse(download_url)
        key = unquote(uri.path.lstrip("/"))
        expected_host = f"{self._bucket}.s3.{self._region}.amazonaws.com"
        if (
            uri.scheme != "s3"
            or uri.netloc != self._bucket
            or not key.startswith(self._allowed_artifact_prefix)
            or ".." in key.split("/")
            or signed.scheme != "https"
            or signed.hostname != expected_host
            or unquote(signed.path.lstrip("/")) != key
            or not signed.query
            or "X-Amz-Signature=" not in signed.query
            or parse_qs(signed.query).get("versionId") != [artifact_version_id]
        ):
            raise SbomStorageError(
                "signed artifact URL must identify the configured bucket and allowed prefix"
            )

    async def verify_external_sbom(
        self,
        artifact_uri: str,
        download_url: str,
        artifact_version_id: str,
        content_sha256: str,
        image_digest: str,
        artifact_manifest_digest: str,
        cyclonedx_document: dict[str, object],
    ) -> None:
        """Verify the existing S3 artifact using a short-lived presigned GET URL."""
        self._validate_external_object(artifact_uri, download_url, artifact_version_id)
        if not all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            for value in (content_sha256, image_digest, artifact_manifest_digest)
        ):
            raise SbomStorageError("artifact, image, and manifest digests must be sha256 values")
        try:
            import httpx

            async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
                response = await client.get(download_url)
                response.raise_for_status()
            content = response.content
            if response.headers.get("x-amz-version-id") != artifact_version_id:
                raise SbomStorageError("retrieved S3 artifact version does not match the request")
            if response.headers.get("x-amz-meta-image-config") != image_digest:
                raise SbomStorageError(
                    "S3 artifact image-config metadata does not match the workload"
                )
            if response.headers.get("x-amz-meta-image-manifest") != artifact_manifest_digest:
                raise SbomStorageError(
                    "S3 artifact manifest metadata does not match the supplied digest"
                )
            actual = "sha256:" + hashlib.sha256(content).hexdigest()
            if actual != content_sha256:
                raise SbomStorageError(
                    f"SBOM artifact SHA-256 mismatch: expected {content_sha256}, got {actual}"
                )
            parsed = json.loads(content)
            if parsed != cyclonedx_document:
                raise SbomStorageError(
                    "retrieved SBOM artifact content differs from the submitted CycloneDX document"
                )
        except SbomStorageError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SbomStorageError(f"SBOM artifact verification failed: {exc}") from exc

    async def upload_sbom(
        self,
        sbom_id: uuid.UUID,
        content: bytes,
        content_type: str = "application/json",
    ) -> str:
        """Upload SBOM bytes to S3.

        Args:
            sbom_id: The SBOM UUID used to derive the object key.
            content: Raw bytes of the serialized CycloneDX document.
            content_type: MIME type of the content.

        Returns:
            The s3:// URI where the artifact was stored.

        Raises:
            SbomStorageError: If the upload fails.
        """
        key = self._object_key(sbom_id)
        try:
            import aiobotocore.session

            session = aiobotocore.session.get_session()
            async with session.create_client(
                "s3",
                endpoint_url=self._endpoint_url,
                region_name=self._region,
            ) as client:
                await client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=content,
                    ContentType=content_type,
                )
        except Exception as exc:  # noqa: BLE001
            raise SbomStorageError(f"S3 upload failed for sbom {sbom_id}: {exc}") from exc
        return f"s3://{self._bucket}/{key}"

    async def download_sbom(self, sbom_id: uuid.UUID) -> bytes:
        """Download SBOM bytes from S3.

        Args:
            sbom_id: The SBOM UUID used to locate the object.

        Returns:
            Raw bytes of the CycloneDX document.

        Raises:
            SbomNotFoundError: If the object does not exist.
            SbomStorageError: If the download fails.
        """
        key = self._object_key(sbom_id)
        try:
            import aiobotocore.session

            session = aiobotocore.session.get_session()
            async with session.create_client(
                "s3",
                endpoint_url=self._endpoint_url,
                region_name=self._region,
            ) as client:
                resp = await client.get_object(Bucket=self._bucket, Key=key)
                return bytes(await resp["Body"].read())
        except Exception as exc:  # noqa: BLE001
            if "NoSuchKey" in str(exc):
                raise SbomNotFoundError(sbom_id=str(sbom_id)) from exc
            raise SbomStorageError(
                f"S3 download failed for sbom {sbom_id}: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI lifespan: create and tear down the asyncpg pool.

    Pool configuration is read exclusively from environment variables.
    No secrets appear in source code.

    Args:
        app: The FastAPI application instance.

    Yields:
        Nothing; state is attached to ``app.state``.
    """
    db_url = os.environ["SBOM_SERVICE_DB_URL"]
    s3_bucket = os.environ.get("SBOM_SERVICE_S3_BUCKET")
    s3_region = os.environ.get("SBOM_SERVICE_S3_REGION")
    if not s3_bucket or not s3_region:
        raise RuntimeError("SBOM_SERVICE_S3_BUCKET and SBOM_SERVICE_S3_REGION are required")
    # The API gateway and SBOM service share the Postgres server but maintain
    # separate schemas and migration histories. This prevents one service's
    # schema_migrations versions from causing the other service to skip DDL.
    migration_conn = await asyncpg.connect(dsn=db_url, command_timeout=30)
    try:
        await migration_conn.execute("CREATE SCHEMA IF NOT EXISTS phantom_sbom")
    finally:
        await migration_conn.close()

    pool = await asyncpg.create_pool(
        dsn=db_url,
        min_size=2,
        max_size=int(os.environ.get("SBOM_SERVICE_DB_POOL_MAX", "10")),
        command_timeout=30,
        server_settings={"search_path": "phantom_sbom,public"},
    )
    try:
        await run_migrations(pool)
    except Exception:
        await pool.close()
        raise
    app.state.db_pool = pool

    # Build shared infrastructure adapters.
    app.state.sbom_repo = PostgresSbomRepository(pool=pool)
    app.state.component_repo = PostgresComponentRepository(pool=pool)
    app.state.job_repo = PostgresVerificationJobRepository(pool=pool)
    app.state.artifact_store = _S3ArtifactStore(
        bucket=s3_bucket,
        region=s3_region,
        endpoint_url=os.environ.get("SBOM_SERVICE_S3_ENDPOINT_URL") or None,
        key_prefix=os.environ.get(
            "SBOM_SERVICE_S3_KEY_PREFIX", "phantom/evidence/sboms"
        ),
        allowed_artifact_prefix=os.environ.get(
            "SBOM_SERVICE_ALLOWED_ARTIFACT_PREFIX", "phantom/evidence/"
        ),
    )
    app.state.cosign_client = CosignClient(
        cosign_path=os.environ.get("COSIGN_PATH", "cosign"),
        timeout_seconds=float(os.environ.get("COSIGN_TIMEOUT_SECONDS", "120")),
        trusted_identity=os.environ.get("COSIGN_TRUSTED_IDENTITY"),
        trusted_issuer=os.environ.get("COSIGN_TRUSTED_ISSUER"),
    )

    log.info("sbom_service.startup_complete")
    yield

    await pool.close()
    log.info("sbom_service.shutdown_complete")


# ---------------------------------------------------------------------------
# FastAPI dependency providers
# ---------------------------------------------------------------------------


def _get_sbom_repo(request: Request) -> PostgresSbomRepository:
    """Extract the SBOM repository from app state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The shared PostgresSbomRepository.
    """
    return request.app.state.sbom_repo  # type: ignore[no-any-return]


def _get_component_repo(request: Request) -> PostgresComponentRepository:
    """Extract the component repository from app state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The shared PostgresComponentRepository.
    """
    return request.app.state.component_repo  # type: ignore[no-any-return]


def _get_job_repo(request: Request) -> PostgresVerificationJobRepository:
    """Extract the verification job repository from app state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The shared PostgresVerificationJobRepository.
    """
    return request.app.state.job_repo  # type: ignore[no-any-return]


def _get_artifact_store(request: Request) -> _S3ArtifactStore:
    """Extract the artifact store from app state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The shared _S3ArtifactStore.
    """
    return request.app.state.artifact_store  # type: ignore[no-any-return]


def _get_cosign_client(request: Request) -> CosignClient:
    """Extract the cosign client from app state.

    Args:
        request: The current FastAPI Request.

    Returns:
        The shared CosignClient.
    """
    return request.app.state.cosign_client  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Annotated dependency type aliases used in router signatures
# ---------------------------------------------------------------------------

SbomRepoDep = Annotated[PostgresSbomRepository, Depends(_get_sbom_repo)]
ComponentRepoDep = Annotated[PostgresComponentRepository, Depends(_get_component_repo)]
JobRepoDep = Annotated[PostgresVerificationJobRepository, Depends(_get_job_repo)]
ArtifactStoreDep = Annotated[_S3ArtifactStore, Depends(_get_artifact_store)]
CosignClientDep = Annotated[CosignClient, Depends(_get_cosign_client)]


# ---------------------------------------------------------------------------
# Use-case factory dependencies
# ---------------------------------------------------------------------------


def get_ingest_sbom_use_case(
    sbom_repo: SbomRepoDep,
    component_repo: ComponentRepoDep,
    artifact_store: ArtifactStoreDep,
) -> IngestSbomUseCase:
    """Construct an IngestSbomUseCase with injected dependencies.

    Args:
        sbom_repo: The SBOM repository.
        component_repo: The component repository.
        artifact_store: The artifact store.

    Returns:
        A ready-to-use IngestSbomUseCase instance.
    """
    return IngestSbomUseCase(
        sbom_repo=sbom_repo,
        component_repo=component_repo,
        artifact_store=artifact_store,
    )


def get_get_sbom_use_case(sbom_repo: SbomRepoDep) -> GetSbomUseCase:
    """Construct a GetSbomUseCase with injected dependencies.

    Args:
        sbom_repo: The SBOM repository.

    Returns:
        A ready-to-use GetSbomUseCase instance.
    """
    return GetSbomUseCase(sbom_repo=sbom_repo)


def get_enqueue_verification_use_case(
    sbom_repo: SbomRepoDep,
    job_repo: JobRepoDep,
) -> EnqueueVerificationUseCase:
    """Construct an EnqueueVerificationUseCase with injected dependencies.

    Args:
        sbom_repo: The SBOM repository.
        job_repo: The verification job repository.

    Returns:
        A ready-to-use EnqueueVerificationUseCase instance.
    """
    return EnqueueVerificationUseCase(sbom_repo=sbom_repo, job_repo=job_repo)


def get_get_verification_result_use_case(
    sbom_repo: SbomRepoDep,
    job_repo: JobRepoDep,
) -> GetVerificationResultUseCase:
    """Construct a GetVerificationResultUseCase with injected dependencies.

    Args:
        sbom_repo: The SBOM repository.
        job_repo: The verification job repository.

    Returns:
        A ready-to-use GetVerificationResultUseCase instance.
    """
    return GetVerificationResultUseCase(sbom_repo=sbom_repo, job_repo=job_repo)


def get_run_verification_use_case(
    sbom_repo: SbomRepoDep,
    job_repo: JobRepoDep,
    verifier: CosignClientDep,
) -> RunVerificationUseCase:
    """Build the job runner against the same persistent repositories."""
    return RunVerificationUseCase(
        sbom_repo=sbom_repo, job_repo=job_repo, verifier=verifier
    )


RunVerifyDep = Annotated[RunVerificationUseCase, Depends(get_run_verification_use_case)]


IngestSbomDep = Annotated[IngestSbomUseCase, Depends(get_ingest_sbom_use_case)]
GetSbomDep = Annotated[GetSbomUseCase, Depends(get_get_sbom_use_case)]
EnqueueVerifyDep = Annotated[
    EnqueueVerificationUseCase, Depends(get_enqueue_verification_use_case)
]
GetVerifyDep = Annotated[
    GetVerificationResultUseCase, Depends(get_get_verification_result_use_case)
]
