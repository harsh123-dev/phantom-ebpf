"""Synthetic cosign output fixtures; no live signer or registry is involved."""

import asyncio
import base64
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.domain.entities import ImageDigest, Sbom, SbomDigest, SbomSource, VerificationStatus
from app.domain.exceptions import SignatureVerificationError, VerificationServiceUnavailableError
from app.infrastructure.cosign.client import CosignClient, _matching_cyclonedx_attestation


def _record():
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    now = datetime.now(UTC)
    return Sbom(
        sbom_id=uuid.uuid4(), tenant_id=uuid.uuid4(),
        image_digest=ImageDigest("sha256:" + "a" * 64),
        image_reference="ghcr.io/example/phantom-evaluation-target@sha256:" + "a" * 64,
        sbom_digest=SbomDigest.compute(document), cyclonedx_document=document,
        spec_version="1.5", source=SbomSource.SYFT,
        artifact_uri="s3://example/sbom.json", signature_bundle_uri=None,
        verification_status=VerificationStatus.PENDING,
        generated_at=now, created_at=now, purl_count=0,
    )


def _output(document, image_digest, predicate_type="https://cyclonedx.org/bom"):
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "subject": [{"name": "image", "digest": {"sha256": image_digest[7:]}}],
        "predicate": document,
    }
    return json.dumps({"payload": base64.b64encode(json.dumps(statement).encode()).decode()})


def test_exact_verified_statement_can_bind_record() -> None:
    record = _record()
    assert _matching_cyclonedx_attestation(
        _output(record.cyclonedx_document, record.image_digest.value), record
    )


def test_wrong_sbom_image_type_or_malformed_output_cannot_bind() -> None:
    record = _record()
    altered = {**record.cyclonedx_document, "components": [{"name": "other"}]}
    assert not _matching_cyclonedx_attestation(_output(altered, record.image_digest.value), record)
    assert not _matching_cyclonedx_attestation(
        _output(record.cyclonedx_document, "sha256:" + "b" * 64), record
    )
    assert not _matching_cyclonedx_attestation(
        _output(record.cyclonedx_document, record.image_digest.value, "other"), record
    )
    assert not _matching_cyclonedx_attestation('{"payload":"not-base64"}', record)
    assert not _matching_cyclonedx_attestation("", record)


def test_cosign_success_exit_without_matching_statement_is_rejected() -> None:
    record = _record()
    client = CosignClient(
        trusted_identity="builder@example.com", trusted_issuer="https://issuer.example"
    )
    output = _output(record.cyclonedx_document, "sha256:" + "b" * 64)
    with (
        patch.object(client, "_resolve_cosign_binary", return_value="/usr/bin/cosign"),
        patch(
            "app.infrastructure.cosign.client.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=output.encode(), stderr=b""),
        ),
        pytest.raises(SignatureVerificationError, match="does not bind"),
    ):
        asyncio.run(
            client.verify(record, "builder@example.com", "https://issuer.example", True)
        )


def test_cosign_uses_immutable_registry_reference_and_strict_trust_flags() -> None:
    record = _record()
    client = CosignClient(
        trusted_identity="builder@example.com", trusted_issuer="https://issuer.example"
    )
    output = _output(record.cyclonedx_document, record.image_digest.value)
    with (
        patch.object(client, "_resolve_cosign_binary", return_value="/usr/bin/cosign"),
        patch(
            "app.infrastructure.cosign.client.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=output.encode(), stderr=b""),
        ) as run,
    ):
        result = asyncio.run(
            client.verify(record, "builder@example.com", "https://issuer.example", True)
        )
    argv = run.call_args.args[0]
    assert argv[-1] == record.image_reference
    assert "--certificate-identity" in argv
    assert "builder@example.com" in argv
    assert "--certificate-oidc-issuer" in argv
    assert "https://issuer.example" in argv
    assert result.verification_status is VerificationStatus.VERIFIED


def test_cosign_refuses_bare_digest_without_registry_reference() -> None:
    record = _record()
    record.image_reference = None
    client = CosignClient(
        trusted_identity="builder@example.com", trusted_issuer="https://issuer.example"
    )
    with pytest.raises(VerificationServiceUnavailableError, match="immutable registry"):
        asyncio.run(client.verify(record, "builder@example.com", "https://issuer.example", True))


def test_request_cannot_choose_its_own_trust_policy() -> None:
    record = _record()
    with pytest.raises(VerificationServiceUnavailableError, match="not configured"):
        asyncio.run(
            CosignClient().verify(record, "builder@example.com", "https://issuer.example", True)
        )
    client = CosignClient(
        trusted_identity="approved@example.com", trusted_issuer="https://issuer.example"
    )
    with pytest.raises(SignatureVerificationError, match="server trust policy"):
        asyncio.run(client.verify(record, "builder@example.com", "https://issuer.example", True))


def test_keyless_verification_cannot_disable_transparency_check() -> None:
    client = CosignClient(
        trusted_identity="builder@example.com", trusted_issuer="https://issuer.example"
    )
    with pytest.raises(SignatureVerificationError, match="transparency-log"):
        asyncio.run(
            client.verify(_record(), "builder@example.com", "https://issuer.example", False)
        )
