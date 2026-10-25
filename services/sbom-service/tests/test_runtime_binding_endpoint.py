"""Synthetic tests for the API adapter connecting stored SBOMs to the mapper."""
from __future__ import annotations

import sys
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services/sbom-service"))

from app.domain.entities import VerificationStatus  # noqa: E402
from app.interface.routers import RuntimeBindingRequestSchema, map_runtime_binding  # noqa: E402
from tests.fixtures.mapping_fixtures import (  # noqa: E402
    IMAGE_DIGEST_A,
    PURL_REQUESTS,
    PURL_URLLIB3,
    SBOM_INDEX_A,
    SYNTHETIC_TENANT_ID,
    _COMP_REQUESTS,
    _COMP_URLLIB3,
    _SBOM_A,
)


class SbomRepo:
    def __init__(self, records):
        self.records = records

    async def get_by_image_digest(self, digest, tenant_id):
        return [r for r in self.records if str(r.image_digest) == digest and
                str(r.tenant_id) == str(tenant_id)]


class ComponentRepo:
    def __init__(self, components):
        self.components = components

    async def get_by_sbom_id(self, sbom_id, _tenant_id):
        return [c for c in self.components if c.sbom_id == sbom_id]


def _request(**overrides):
    values = {
        "event_id": uuid.uuid4(), "run_id": "synthetic-run",
        "tenant_id": uuid.UUID(SYNTHETIC_TENANT_ID), "event_type": "exec",
        "observed_at": datetime.now(UTC), "container_id": "containerd://abc",
        "image_digest": IMAGE_DIGEST_A, "pod_uid": str(uuid.uuid4()),
        "namespace": "phantom-eval", "workload_name": "worker",
        "tgid": 1001, "pid_start_time_ns": 1234,
        "executable_path": "/usr/bin/worker", "executable_hash": "a" * 64,
    }
    values.update(overrides)
    return RuntimeBindingRequestSchema.model_validate(values)


def _sbom(document):
    return replace(_SBOM_A, verification_status=VerificationStatus.VERIFIED,
                   cyclonedx_document=document)


@pytest.mark.asyncio
async def test_exact_component_hash_binds_only_verified_sbom_provenance():
    digest = "a" * 64
    sbom = _sbom({"bomFormat": "CycloneDX", "components": [
        {"purl": PURL_REQUESTS, "hashes": [{"alg": "SHA-256", "content": digest}]}
    ]})
    result = await map_runtime_binding(
        _request(), SbomRepo([sbom]), ComponentRepo([_COMP_REQUESTS])
    )
    assert result["binding_status"] == "bound"
    assert result["sbom_id"] == str(sbom.sbom_id)
    assert result["purl"] == PURL_REQUESTS
    assert result["evidence"][0]["kind"] == "executable_hash"


@pytest.mark.asyncio
async def test_same_hash_in_multiple_components_is_ambiguous():
    digest = "a" * 64
    sbom = _sbom({"bomFormat": "CycloneDX", "components": [
        {"purl": PURL_REQUESTS, "hashes": [{"alg": "SHA-256", "content": digest}]},
        {"purl": PURL_URLLIB3, "hashes": [{"alg": "SHA-256", "content": digest}]},
    ]})
    result = await map_runtime_binding(
        _request(), SbomRepo([sbom]), ComponentRepo([_COMP_REQUESTS, _COMP_URLLIB3])
    )
    assert result["binding_status"] == "ambiguous"
    assert result["purl"] is None
    assert set(result["candidate_purls"]) == {PURL_REQUESTS, PURL_URLLIB3}


@pytest.mark.asyncio
async def test_missing_sbom_and_missing_artifact_provenance_abstain():
    missing = await map_runtime_binding(_request(), SbomRepo([]), ComponentRepo([]))
    assert missing["binding_status"] == "unbound"
    assert missing["purl"] is None

    sbom = _sbom({"bomFormat": "CycloneDX", "components": []})
    insufficient = await map_runtime_binding(
        _request(executable_hash=None), SbomRepo([sbom]), ComponentRepo([])
    )
    assert insufficient["binding_status"] == "insufficient_evidence"
    assert insufficient["purl"] is None
    assert insufficient["confidence"] is None


@pytest.mark.asyncio
async def test_mismatched_digest_never_uses_other_image_sbom():
    sbom = _sbom({"bomFormat": "CycloneDX", "components": []})
    mismatched = "sha256:" + "b" * 64
    result = await map_runtime_binding(
        _request(image_digest=mismatched), SbomRepo([sbom]), ComponentRepo([])
    )
    assert result["image_digest"] == mismatched
    assert result["binding_status"] == "unbound"
    assert result["sbom_id"] is None
