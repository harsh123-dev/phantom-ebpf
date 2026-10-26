from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from app.domain.exceptions import SbomStorageError
from app.interface.dependencies import _S3ArtifactStore
from app.interface.routers import SbomIngestRequestSchema


@pytest.fixture
def store() -> _S3ArtifactStore:
    return _S3ArtifactStore(
        bucket="phantom-evidence",
        region="ap-south-1",
        key_prefix="phantom/evidence/sboms",
        allowed_artifact_prefix="phantom/evidence/",
    )


def test_external_artifact_requires_exact_bucket_key_and_version(store: _S3ArtifactStore) -> None:
    store._validate_external_object(
        "s3://phantom-evidence/phantom/evidence/run/sbom.json",
        "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
        "phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature",
        "v1",
    )


@pytest.mark.parametrize(
    ("uri", "url", "version"),
    [
        (
            "s3://other-bucket/phantom/evidence/run/sbom.json",
            "https://other-bucket.s3.ap-south-1.amazonaws.com/"
            "phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature",
            "v1",
        ),
        (
            "s3://phantom-evidence/phantom/evidence/run/sbom.json",
            "https://attacker.example/phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature",
            "v1",
        ),
        (
            "s3://phantom-evidence/phantom/evidence/run/sbom.json",
            "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
            "phantom/evidence/run/sbom.json?versionId=v2&X-Amz-Signature=signature",
            "v1",
        ),
        (
            "s3://phantom-evidence/outside/sbom.json",
            "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
            "outside/sbom.json?versionId=v1&X-Amz-Signature=signature",
            "v1",
        ),
    ],
)
def test_external_artifact_rejects_wrong_identity(
    store: _S3ArtifactStore, uri: str, url: str, version: str
) -> None:
    with pytest.raises(SbomStorageError):
        store._validate_external_object(uri, url, version)


def _request(**overrides) -> dict:
    payload = {
        "image_digest": "sha256:" + "a" * 64,
        "artifact_uri": "s3://phantom-evidence/phantom/evidence/run/sbom.json",
        "cyclonedx_document": {"bomFormat": "CycloneDX", "specVersion": "1.5"},
        "declared_sbom_digest": "sha256:" + "b" * 64,
        "source": "syft",
        "generated_at": "2026-10-25T20:00:00Z",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
    }
    payload.update(overrides)
    return payload


def test_external_artifact_fields_must_be_complete() -> None:
    with pytest.raises(ValidationError, match="must be supplied together"):
        SbomIngestRequestSchema.model_validate(
            _request(artifact_download_url="https://example.invalid/sbom.json")
        )


def test_external_artifact_request_binds_version_and_image_digests() -> None:
    request = SbomIngestRequestSchema.model_validate(_request(
        artifact_download_url=(
            "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
            "phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature"
        ),
        artifact_version_id="v1",
        artifact_content_sha256="sha256:" + "c" * 64,
        artifact_manifest_digest="sha256:" + "d" * 64,
    ))
    assert request.artifact_version_id == "v1"


def test_image_digest_rejects_mutable_tag() -> None:
    with pytest.raises(ValidationError, match="image_digest"):
        SbomIngestRequestSchema.model_validate(_request(image_digest="latest"))


@pytest.mark.asyncio
async def test_external_artifact_fetch_checks_version_digest_metadata_and_document(
    store: _S3ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib
    import json

    document = {"bomFormat": "CycloneDX", "specVersion": "1.5"}
    content = json.dumps(document, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    response = httpx.Response(
        200,
        headers={
            "x-amz-version-id": "v1",
            "x-amz-meta-image-config": "sha256:" + "a" * 64,
            "x-amz-meta-image-manifest": "sha256:" + "d" * 64,
        },
        content=content,
        request=httpx.Request("GET", "https://s3.example/object"),
    )

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, _url: str) -> httpx.Response:
            return response

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _Client())
    await store.verify_external_sbom(
        artifact_uri="s3://phantom-evidence/phantom/evidence/run/sbom.json",
        download_url=(
            "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
            "phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature"
        ),
        artifact_version_id="v1",
        content_sha256=digest,
        image_digest="sha256:" + "a" * 64,
        artifact_manifest_digest="sha256:" + "d" * 64,
        cyclonedx_document=document,
    )

    with pytest.raises(SbomStorageError, match="SHA-256 mismatch"):
        await store.verify_external_sbom(
            artifact_uri="s3://phantom-evidence/phantom/evidence/run/sbom.json",
            download_url=(
                "https://phantom-evidence.s3.ap-south-1.amazonaws.com/"
                "phantom/evidence/run/sbom.json?versionId=v1&X-Amz-Signature=signature"
            ),
            artifact_version_id="v1",
            content_sha256="sha256:" + "0" * 64,
            image_digest="sha256:" + "a" * 64,
            artifact_manifest_digest="sha256:" + "d" * 64,
            cyclonedx_document=document,
        )
