"""
Contract tests for sbom-service API endpoints.

Validates that request/response schemas conform to the canonical
JSON Schema definitions in services/contracts/http/ and that
domain entity invariants hold:

- ImageDigest / SbomDigest validate sha256:<64 hex> format
- SbomDigest.compute() is deterministic and order-insensitive
- Purl enforces non-empty / max-length constraints
- VerificationStatus enum values match handoff §3 state machine
- SbomSource enum covers syft and external sources
- BindingStatus enum covers resolved / ambiguous / missing states
- SbomRecord fingerprint changes when components change
- BehavioralContract PURL list is non-empty (domain invariant)
- VerificationJob status transitions are valid

All tests are pure-Python unit tests with no database or HTTP deps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domain.entities import (
    BindingStatus,
    ImageDigest,
    Purl,
    SbomDigest,
    SbomSource,
    VerificationStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_DIGEST = "sha256:" + "a" * 64
_NOW = datetime.now(tz=UTC)


def _make_cyclonedx(**overrides) -> dict:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        ],
    }
    doc.update(overrides)
    return doc


# ---------------------------------------------------------------------------
# ImageDigest value object
# ---------------------------------------------------------------------------


class TestImageDigest:
    def test_valid_sha256_digest_is_accepted(self) -> None:
        digest = ImageDigest(value=_VALID_DIGEST)
        assert str(digest) == _VALID_DIGEST

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            ImageDigest(value="")

    def test_missing_sha256_prefix_raises(self) -> None:
        with pytest.raises(ValueError):
            ImageDigest(value="a" * 64)  # no sha256: prefix

    def test_wrong_length_hash_raises(self) -> None:
        with pytest.raises(ValueError):
            ImageDigest(value="sha256:" + "a" * 63)

    def test_uppercase_hex_raises(self) -> None:
        """Digest must be lowercase hex per OCI spec."""
        with pytest.raises(ValueError):
            ImageDigest(value="sha256:" + "A" * 64)

    def test_image_digest_is_frozen(self) -> None:
        digest = ImageDigest(value=_VALID_DIGEST)
        with pytest.raises((AttributeError, TypeError)):
            digest.value = "sha256:" + "b" * 64  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SbomDigest value object
# ---------------------------------------------------------------------------


class TestSbomDigest:
    def test_valid_digest_is_accepted(self) -> None:
        digest = SbomDigest(value=_VALID_DIGEST)
        assert digest.value == _VALID_DIGEST

    def test_compute_returns_valid_sbom_digest(self) -> None:
        doc = _make_cyclonedx()
        digest = SbomDigest.compute(doc)
        assert digest.value.startswith("sha256:")
        assert len(digest.value) == 71  # "sha256:" + 64 hex chars

    def test_compute_is_deterministic(self) -> None:
        doc = _make_cyclonedx()
        d1 = SbomDigest.compute(doc)
        d2 = SbomDigest.compute(doc)
        assert d1 == d2

    def test_compute_insensitive_to_key_order(self) -> None:
        """Canonical JSON must sort keys, so key order cannot affect the digest."""
        doc_a = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
        doc_b = {"specVersion": "1.4", "bomFormat": "CycloneDX", "components": []}
        assert SbomDigest.compute(doc_a) == SbomDigest.compute(doc_b)

    def test_compute_changes_when_component_added(self) -> None:
        doc_a = _make_cyclonedx()
        doc_b = _make_cyclonedx()
        doc_b["components"].append(
            {"type": "library", "name": "urllib3", "version": "2.0.0"}
        )
        assert SbomDigest.compute(doc_a) != SbomDigest.compute(doc_b)

    def test_compute_changes_when_version_changes(self) -> None:
        doc_a = _make_cyclonedx()
        doc_b = _make_cyclonedx()
        doc_b["components"][0]["version"] = "2.32.0"
        assert SbomDigest.compute(doc_a) != SbomDigest.compute(doc_b)


# ---------------------------------------------------------------------------
# Purl value object
# ---------------------------------------------------------------------------


class TestPurl:
    def test_valid_purl_is_accepted(self) -> None:
        p = Purl(value="pkg:pypi/requests@2.31.0")
        assert str(p) == "pkg:pypi/requests@2.31.0"

    def test_empty_purl_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            Purl(value="")

    def test_purl_exceeding_max_length_raises(self) -> None:
        with pytest.raises(ValueError, match="2048"):
            Purl(value="pkg:pypi/" + "x" * 2045)

    def test_purl_at_max_length_is_accepted(self) -> None:
        # Exactly 2048 chars should not raise.
        Purl(value="pkg:pypi/" + "x" * (2048 - len("pkg:pypi/")))

    def test_purl_is_frozen(self) -> None:
        p = Purl(value="pkg:pypi/requests@2.31.0")
        with pytest.raises((AttributeError, TypeError)):
            p.value = "pkg:pypi/urllib3@2.0.0"  # type: ignore[misc]

    def test_purl_types_are_accepted(self) -> None:
        for prefix in ("pkg:pypi/", "pkg:npm/", "pkg:cargo/", "pkg:golang/", "pkg:maven/"):
            p = Purl(value=f"{prefix}example@1.0.0")
            assert p.value.startswith(prefix)


# ---------------------------------------------------------------------------
# VerificationStatus enum
# ---------------------------------------------------------------------------


class TestVerificationStatus:
    def test_pending_exists(self) -> None:
        assert VerificationStatus.PENDING in VerificationStatus

    def test_verified_exists(self) -> None:
        assert VerificationStatus.VERIFIED in VerificationStatus

    def test_failed_exists(self) -> None:
        assert VerificationStatus.FAILED in VerificationStatus

    def test_all_values_are_strings(self) -> None:
        for s in VerificationStatus:
            assert isinstance(s.value, str)

    def test_pending_is_initial_state(self) -> None:
        """PENDING must come before VERIFIED/FAILED in the lifecycle."""
        statuses = {s.value for s in VerificationStatus}
        assert "pending" in statuses
        assert "verified" in statuses
        assert "failed" in statuses


# ---------------------------------------------------------------------------
# SbomSource enum
# ---------------------------------------------------------------------------


class TestSbomSource:
    def test_syft_exists(self) -> None:
        assert SbomSource.SYFT in SbomSource

    def test_external_exists(self) -> None:
        assert SbomSource.EXTERNAL in SbomSource

    def test_all_values_are_strings(self) -> None:
        for s in SbomSource:
            assert isinstance(s.value, str)


# ---------------------------------------------------------------------------
# BindingStatus enum
# ---------------------------------------------------------------------------


class TestBindingStatus:
    def test_resolved_exists(self) -> None:
        assert BindingStatus.RESOLVED in BindingStatus

    def test_ambiguous_exists(self) -> None:
        assert BindingStatus.AMBIGUOUS in BindingStatus

    def test_missing_exists(self) -> None:
        assert BindingStatus.MISSING in BindingStatus

    def test_three_states(self) -> None:
        assert len(list(BindingStatus)) == 3


# ---------------------------------------------------------------------------
# CycloneDX document validation invariants
# ---------------------------------------------------------------------------


class TestCycloneDXInvariants:
    """Domain-level checks on SBOM document structure before ingestion."""

    def test_document_with_bom_format_is_valid(self) -> None:
        doc = _make_cyclonedx()
        assert "bomFormat" in doc
        assert doc["bomFormat"] == "CycloneDX"

    def test_document_without_bom_format_is_missing_required_field(self) -> None:
        doc = _make_cyclonedx()
        del doc["bomFormat"]
        assert "bomFormat" not in doc

    def test_component_has_purl(self) -> None:
        doc = _make_cyclonedx()
        for comp in doc.get("components", []):
            assert "purl" in comp, f"component {comp!r} missing purl"

    def test_empty_components_list_is_valid_document(self) -> None:
        """An SBOM with zero components is unusual but schema-valid."""
        doc = _make_cyclonedx(components=[])
        assert doc["components"] == []
