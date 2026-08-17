"""
tests/sbom-service/test_domain.py

Unit tests for the SBOM service domain layer.
No I/O. No mocks. Pure business-logic assertions only.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domain.entities import (
    BindingStatus,
    Component,
    ImageDigest,
    Purl,
    Sbom,
    SbomDigest,
    SbomSource,
    VerificationJob,
    VerificationStatus,
    count_purls_in_document,
    extract_spec_version,
    validate_cyclonedx_document,
)
from app.domain.exceptions import (
    DigestMismatchError,
    DuplicateSbomError,
    SbomNotFoundError,
    SyftNotInstalledError,
    SyftTimeoutError,
    VerificationAlreadyInProgressError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)
_DIGEST = "sha256:" + "a" * 64
_UUID = uuid.uuid4()


def _make_sbom(**overrides) -> Sbom:
    """Build a minimal valid Sbom with optional field overrides."""
    defaults = dict(
        sbom_id=uuid.uuid4(),
        tenant_id=_UUID,
        image_digest=ImageDigest(value=_DIGEST),
        sbom_digest=SbomDigest(value=_DIGEST),
        cyclonedx_document={"bomFormat": "CycloneDX", "specVersion": "1.5"},
        spec_version="1.5",
        source=SbomSource.SYFT,
        artifact_uri="https://example.com/sbom.json",
        signature_bundle_uri=None,
        verification_status=VerificationStatus.PENDING,
        generated_at=_NOW,
        created_at=_NOW,
        purl_count=0,
    )
    defaults.update(overrides)
    return Sbom(**defaults)


# ---------------------------------------------------------------------------
# ImageDigest
# ---------------------------------------------------------------------------


class TestImageDigest:
    """Tests for ImageDigest value object."""

    def test_valid_digest(self) -> None:
        """Accepts a valid sha256 digest."""
        d = ImageDigest(value=_DIGEST)
        assert str(d) == _DIGEST

    def test_invalid_digest_rejected(self) -> None:
        """Rejects non-sha256 strings."""
        with pytest.raises(ValueError, match="sha256"):
            ImageDigest(value="not-a-digest")

    def test_wrong_hex_length_rejected(self) -> None:
        """Rejects sha256 with wrong hex length."""
        with pytest.raises(ValueError):
            ImageDigest(value="sha256:" + "a" * 63)


# ---------------------------------------------------------------------------
# SbomDigest
# ---------------------------------------------------------------------------


class TestSbomDigest:
    """Tests for SbomDigest value object."""

    def test_compute_is_deterministic(self) -> None:
        """compute() returns the same digest for the same document."""
        doc = {"bomFormat": "CycloneDX", "components": []}
        d1 = SbomDigest.compute(doc)
        d2 = SbomDigest.compute(doc)
        assert d1.value == d2.value

    def test_compute_is_order_independent(self) -> None:
        """compute() normalizes key order."""
        doc1 = {"bomFormat": "CycloneDX", "specVersion": "1.5"}
        doc2 = {"specVersion": "1.5", "bomFormat": "CycloneDX"}
        assert SbomDigest.compute(doc1).value == SbomDigest.compute(doc2).value

    def test_different_documents_differ(self) -> None:
        """Different documents produce different digests."""
        d1 = SbomDigest.compute({"bomFormat": "CycloneDX"})
        d2 = SbomDigest.compute({"bomFormat": "CycloneDX", "extra": "field"})
        assert d1.value != d2.value


# ---------------------------------------------------------------------------
# Purl
# ---------------------------------------------------------------------------


class TestPurl:
    """Tests for Purl value object."""

    def test_valid_purl(self) -> None:
        """Accepts a valid PURL string."""
        p = Purl(value="pkg:pypi/requests@2.31.0")
        assert str(p) == "pkg:pypi/requests@2.31.0"

    def test_empty_purl_rejected(self) -> None:
        """Rejects an empty PURL."""
        with pytest.raises(ValueError):
            Purl(value="")

    def test_too_long_purl_rejected(self) -> None:
        """Rejects a PURL exceeding 2048 characters."""
        with pytest.raises(ValueError):
            Purl(value="pkg:x/" + "a" * 2050)


# ---------------------------------------------------------------------------
# validate_cyclonedx_document
# ---------------------------------------------------------------------------


class TestValidateCycloneDxDocument:
    """Tests for the validate_cyclonedx_document domain helper."""

    def test_valid_document(self) -> None:
        """Does not raise for a minimal valid CycloneDX document."""
        validate_cyclonedx_document({"bomFormat": "CycloneDX"})

    def test_empty_document_rejected(self) -> None:
        """Empty dict is rejected."""
        with pytest.raises(ValueError, match="must not be empty"):
            validate_cyclonedx_document({})

    def test_missing_bom_format_rejected(self) -> None:
        """Document without bomFormat is rejected."""
        with pytest.raises(ValueError, match="bomFormat"):
            validate_cyclonedx_document({"specVersion": "1.5"})

    def test_wrong_bom_format_rejected(self) -> None:
        """bomFormat != 'CycloneDX' is rejected."""
        with pytest.raises(ValueError, match="CycloneDX"):
            validate_cyclonedx_document({"bomFormat": "SPDX"})


# ---------------------------------------------------------------------------
# count_purls_in_document / extract_spec_version
# ---------------------------------------------------------------------------


class TestDocumentHelpers:
    """Tests for document parsing helpers."""

    def test_count_purls_none_present(self) -> None:
        """Returns 0 when no components have PURLs."""
        doc = {"bomFormat": "CycloneDX", "components": [{"name": "foo"}]}
        assert count_purls_in_document(doc) == 0

    def test_count_purls_some_present(self) -> None:
        """Counts only components with a non-empty purl field."""
        doc = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "a", "purl": "pkg:pypi/a@1"},
                {"name": "b"},
                {"name": "c", "purl": "pkg:pypi/c@1"},
            ],
        }
        assert count_purls_in_document(doc) == 2

    def test_extract_spec_version_present(self) -> None:
        """Returns the specVersion field when present."""
        assert extract_spec_version({"specVersion": "1.5"}) == "1.5"

    def test_extract_spec_version_absent(self) -> None:
        """Returns 'unknown' when specVersion is absent."""
        assert extract_spec_version({}) == "unknown"


# ---------------------------------------------------------------------------
# Sbom entity
# ---------------------------------------------------------------------------


class TestSbomEntity:
    """Tests for the Sbom aggregate root."""

    def test_external_sbom_requires_signature_bundle(self) -> None:
        """External source without signature_bundle_uri raises ValueError."""
        with pytest.raises(ValueError, match="signature_bundle_uri"):
            _make_sbom(source=SbomSource.EXTERNAL, signature_bundle_uri=None)

    def test_external_sbom_with_signature_bundle_ok(self) -> None:
        """External source with signature_bundle_uri is accepted."""
        sbom = _make_sbom(
            source=SbomSource.EXTERNAL,
            signature_bundle_uri="https://example.com/bundle.json",
        )
        assert sbom.source == SbomSource.EXTERNAL

    def test_negative_purl_count_rejected(self) -> None:
        """Negative purl_count raises ValueError."""
        with pytest.raises(ValueError, match="purl_count"):
            _make_sbom(purl_count=-1)

    def test_naive_created_at_rejected(self) -> None:
        """Timezone-naive created_at raises ValueError."""
        with pytest.raises(ValueError, match="timezone-aware"):
            _make_sbom(created_at=datetime(2024, 1, 1))

    def test_mark_verified(self) -> None:
        """mark_verified returns a new VERIFIED Sbom with signing metadata."""
        sbom = _make_sbom()
        verified = sbom.mark_verified(
            signing_identity="user@example.com",
            issuer="https://accounts.google.com",
            verified_at=_NOW,
        )
        assert verified.verification_status == VerificationStatus.VERIFIED
        assert verified.signing_identity == "user@example.com"
        assert sbom.verification_status == VerificationStatus.PENDING  # immutable

    def test_mark_verification_failed(self) -> None:
        """mark_verification_failed returns a new FAILED Sbom."""
        sbom = _make_sbom()
        failed = sbom.mark_verification_failed(reason="bad signature")
        assert failed.verification_status == VerificationStatus.FAILED
        assert failed.verification_error == "bad signature"
        assert sbom.verification_status == VerificationStatus.PENDING  # immutable

    def test_component_count_property(self) -> None:
        """component_count reflects the number of CycloneDX components."""
        doc = {"bomFormat": "CycloneDX", "components": [{}, {}]}
        sbom = _make_sbom(cyclonedx_document=doc)
        assert sbom.component_count == 2


# ---------------------------------------------------------------------------
# Component entity
# ---------------------------------------------------------------------------


class TestComponentEntity:
    """Tests for the Component domain entity."""

    def test_from_cyclonedx_component_with_purl(self) -> None:
        """Builds a Component from a raw dict with a purl."""
        raw = {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
        comp = Component.from_cyclonedx_component(raw=raw, sbom_id=_UUID)
        assert str(comp.purl) == "pkg:pypi/requests@2.31.0"
        assert comp.version == "2.31.0"

    def test_from_cyclonedx_component_without_purl(self) -> None:
        """Components without purl default to MISSING binding status."""
        raw = {"name": "unresolvable"}
        comp = Component.from_cyclonedx_component(raw=raw, sbom_id=_UUID)
        assert comp.binding_status == BindingStatus.MISSING

    def test_empty_name_rejected(self) -> None:
        """Component with empty name raises ValueError."""
        with pytest.raises(ValueError, match="name"):
            Component(
                component_id=uuid.uuid4(),
                sbom_id=_UUID,
                purl=Purl(value="pkg:pypi/x@1"),
                name="",
                version="1",
                component_type="library",
                binding_status=BindingStatus.RESOLVED,
                binding_confidence=0.9,
                created_at=_NOW,
            )

    def test_confidence_out_of_range_rejected(self) -> None:
        """binding_confidence outside [0, 1] raises ValueError."""
        with pytest.raises(ValueError, match="binding_confidence"):
            Component(
                component_id=uuid.uuid4(),
                sbom_id=_UUID,
                purl=Purl(value="pkg:pypi/x@1"),
                name="x",
                version="1",
                component_type="library",
                binding_status=BindingStatus.RESOLVED,
                binding_confidence=1.1,
                created_at=_NOW,
            )


# ---------------------------------------------------------------------------
# VerificationJob entity
# ---------------------------------------------------------------------------


class TestVerificationJobEntity:
    """Tests for the VerificationJob domain entity."""

    def test_valid_job(self) -> None:
        """Constructs a valid VerificationJob."""
        job = VerificationJob(
            verification_job_id=uuid.uuid4(),
            sbom_id=_UUID,
            tenant_id=_UUID,
            expected_identity="user@example.com",
            expected_issuer="https://accounts.google.com",
            rekor_required=True,
            status="queued",
            submitted_at=_NOW,
        )
        assert job.status == "queued"

    def test_invalid_status_rejected(self) -> None:
        """Invalid status raises ValueError."""
        with pytest.raises(ValueError, match="status"):
            VerificationJob(
                verification_job_id=uuid.uuid4(),
                sbom_id=_UUID,
                tenant_id=_UUID,
                expected_identity="user@example.com",
                expected_issuer="https://accounts.google.com",
                rekor_required=True,
                status="unknown_status",
                submitted_at=_NOW,
            )

    def test_empty_identity_rejected(self) -> None:
        """Empty expected_identity raises ValueError."""
        with pytest.raises(ValueError, match="expected_identity"):
            VerificationJob(
                verification_job_id=uuid.uuid4(),
                sbom_id=_UUID,
                tenant_id=_UUID,
                expected_identity="",
                expected_issuer="https://accounts.google.com",
                rekor_required=True,
                status="queued",
                submitted_at=_NOW,
            )


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Tests for the domain exception hierarchy."""

    def test_sbom_not_found_code(self) -> None:
        """SbomNotFoundError has the correct code."""
        exc = SbomNotFoundError("abc")
        assert exc.code == "SBOM_NOT_FOUND"
        assert "abc" in exc.message

    def test_duplicate_sbom_error(self) -> None:
        """DuplicateSbomError stores digest fields."""
        exc = DuplicateSbomError("sha256:aaa", "sha256:bbb", "sha256:ccc")
        assert exc.code == "SBOM_DIGEST_IMAGE_CONFLICT"

    def test_digest_mismatch_error(self) -> None:
        """DigestMismatchError stores declared and computed."""
        exc = DigestMismatchError("sha256:aaa", "sha256:bbb")
        assert exc.declared == "sha256:aaa"
        assert exc.computed == "sha256:bbb"

    def test_syft_not_installed(self) -> None:
        """SyftNotInstalledError stores the path."""
        exc = SyftNotInstalledError("syft")
        assert exc.syft_path == "syft"
        assert exc.code == "SYFT_NOT_INSTALLED"

    def test_syft_timeout(self) -> None:
        """SyftTimeoutError stores timeout_seconds."""
        exc = SyftTimeoutError(300.0)
        assert exc.timeout_seconds == 300.0

    def test_verification_already_in_progress(self) -> None:
        """VerificationAlreadyInProgressError stores sbom_id."""
        exc = VerificationAlreadyInProgressError("sbom-1")
        assert exc.sbom_id == "sbom-1"
        assert exc.code == "VERIFICATION_ALREADY_IN_PROGRESS"
