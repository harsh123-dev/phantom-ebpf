from __future__ import annotations

import base64
import json

from verify_cyclonedx_attestation import matching_verified_statement


def _verified_line(document: dict, digest: str, predicate_type: str = "https://cyclonedx.org/bom") -> str:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [{"name": "container", "digest": {"sha256": digest[7:]}}],
        "predicate": document,
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps({"payload": payload})


def test_exact_verified_predicate_and_image_digest_match() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    digest = "sha256:" + "a" * 64
    assert matching_verified_statement([_verified_line(doc, digest)], doc, digest)


def test_wrong_digest_predicate_type_tamper_or_missing_attestation_rejected() -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    digest = "sha256:" + "a" * 64
    other = "sha256:" + "b" * 64
    assert not matching_verified_statement([_verified_line(doc, other)], doc, digest)
    assert not matching_verified_statement(
        [_verified_line(doc, digest, "https://example.invalid/predicate")], doc, digest
    )
    changed = {**doc, "components": [{"name": "tampered"}]}
    assert not matching_verified_statement([_verified_line(doc, digest)], changed, digest)
    assert not matching_verified_statement([], doc, digest)


def test_invalid_image_digest_is_rejected() -> None:
    assert not matching_verified_statement([], {}, "latest")
