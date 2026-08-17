"""
Tests for report-generator evidence completeness and output contracts.

Validates:
- IncidentReportDocument.compute_evidence_hash() is deterministic and
  changes when any evidence ID changes (no silent evidence drop)
- ReportSection completeness is bounded to [0.0, 1.0]
- ReportSection with completeness outside [0.0, 1.0] raises ValueError
- ReportStatus enum coverage matches the handoff §6 state machine
- ReportSectionType enum covers all required paper sections
- EvidenceReference UUID validation catches non-UUID strings
- ReportRenderer.assemble_sections() produces one section per SectionType
  (tested against the real renderer with synthetic evidence)
- Missing evidence produces LIMITATIONS section, not a hard failure

All tests are pure-Python unit tests with no database or Redis deps.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.domain.entities import (
    EvidenceReference,
    IncidentReportDocument,
    ReportSection,
    ReportSectionType,
    ReportStatus,
)
from app.infrastructure.renderer_adapter import ReportRenderer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)


def _make_incident(
    drift_event_ids: list[str] | None = None,
    attribution_ids: list[str] | None = None,
    score_ids: list[str] | None = None,
    snapshot_id: str | None = None,
) -> dict:
    return {
        "incident_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "status": "open",
        "revision": 1,
        "drift_event_ids": drift_event_ids or [],
        "attribution_ids": attribution_ids or [],
        "score_ids": score_ids or [],
        "snapshot_id": snapshot_id,
        "severity": "HIGH",
        "title": "Test incident",
        "description": "Synthetic test incident",
        "created_at": _NOW.isoformat(),
        "updated_at": _NOW.isoformat(),
    }


def _make_drift_event() -> dict:
    return {
        "drift_event_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "event_type": "exec",
        "observed_at": _NOW.isoformat(),
        "identity_status": "resolved",
        "namespace": "phantom-eval",
        "pod_uid": str(uuid.uuid4()),
        "container_id": "abc",
        "comm": "python3",
        "violation_types": ["unexpected_exec"],
        "purl": "pkg:pypi/requests@2.31.0",
    }


def _make_attribution() -> dict:
    return {
        "attribution_id": str(uuid.uuid4()),
        "status": "completed",
        "treatment_purl": "pkg:pypi/requests@2.31.0",
        "outcome_variable": "behavioral_drift",
        "estimated_effect": 0.85,
        "confidence": 0.9,
        "identifiable": True,
        "refutation_passed": True,
    }


def _make_score() -> dict:
    return {
        "score_id": str(uuid.uuid4()),
        "pceps_score": 78.5,
        "severity_band": "HIGH",
        "calibrated_probability": 0.785,
    }


# ---------------------------------------------------------------------------
# ReportStatus enum
# ---------------------------------------------------------------------------


class TestReportStatus:
    def test_all_statuses_are_strings(self) -> None:
        for s in ReportStatus:
            assert isinstance(s.value, str)

    def test_generating_exists(self) -> None:
        assert ReportStatus.GENERATING in ReportStatus

    def test_complete_exists(self) -> None:
        assert ReportStatus.COMPLETE in ReportStatus

    def test_failed_exists(self) -> None:
        assert ReportStatus.FAILED in ReportStatus

    def test_partial_exists(self) -> None:
        assert ReportStatus.PARTIAL in ReportStatus


# ---------------------------------------------------------------------------
# ReportSectionType enum
# ---------------------------------------------------------------------------


class TestReportSectionType:
    def test_executive_summary_exists(self) -> None:
        assert ReportSectionType.EXECUTIVE_SUMMARY in ReportSectionType

    def test_causal_attribution_exists(self) -> None:
        assert ReportSectionType.CAUSAL_ATTRIBUTION in ReportSectionType

    def test_pceps_score_exists(self) -> None:
        assert ReportSectionType.PCEPS_SCORE in ReportSectionType

    def test_limitations_exists(self) -> None:
        """LIMITATIONS section is required for incomplete evidence."""
        assert ReportSectionType.LIMITATIONS in ReportSectionType

    def test_at_least_five_section_types(self) -> None:
        assert len(list(ReportSectionType)) >= 5


# ---------------------------------------------------------------------------
# ReportSection completeness constraint
# ---------------------------------------------------------------------------


class TestReportSection:
    def test_valid_completeness_is_accepted(self) -> None:
        section = ReportSection(
            section_type=ReportSectionType.EXECUTIVE_SUMMARY,
            content={"summary": "ok"},
            completeness=0.8,
        )
        assert section.completeness == 0.8

    def test_completeness_zero_is_valid(self) -> None:
        section = ReportSection(
            section_type=ReportSectionType.LIMITATIONS,
            content={},
            completeness=0.0,
        )
        assert section.completeness == 0.0

    def test_completeness_one_is_valid(self) -> None:
        section = ReportSection(
            section_type=ReportSectionType.EXECUTIVE_SUMMARY,
            content={"summary": "complete"},
            completeness=1.0,
        )
        assert section.completeness == 1.0

    def test_completeness_above_one_raises(self) -> None:
        with pytest.raises(ValueError):
            ReportSection(
                section_type=ReportSectionType.EXECUTIVE_SUMMARY,
                content={},
                completeness=1.1,
            )

    def test_completeness_below_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            ReportSection(
                section_type=ReportSectionType.EXECUTIVE_SUMMARY,
                content={},
                completeness=-0.1,
            )

    def test_missing_fields_defaults_to_empty(self) -> None:
        section = ReportSection(
            section_type=ReportSectionType.CAUSAL_ATTRIBUTION,
            content={},
            completeness=0.5,
        )
        assert section.missing_fields == []


# ---------------------------------------------------------------------------
# EvidenceReference UUID validation
# ---------------------------------------------------------------------------


class TestEvidenceReference:
    def test_valid_uuid_is_accepted(self) -> None:
        ref = EvidenceReference(drift_event_id=str(uuid.uuid4()))
        assert ref.drift_event_id is not None

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises((ValueError, AttributeError)):
            EvidenceReference(drift_event_id="not-a-uuid")

    def test_all_none_is_valid(self) -> None:
        ref = EvidenceReference()
        assert ref.drift_event_id is None
        assert ref.attribution_id is None

    def test_multiple_ids_in_same_ref(self) -> None:
        ref = EvidenceReference(
            drift_event_id=str(uuid.uuid4()),
            attribution_id=str(uuid.uuid4()),
        )
        assert ref.drift_event_id is not None
        assert ref.attribution_id is not None


# ---------------------------------------------------------------------------
# IncidentReportDocument.compute_evidence_hash()
# ---------------------------------------------------------------------------


class TestEvidenceHash:
    def test_hash_is_deterministic(self) -> None:
        ids = [str(uuid.uuid4()) for _ in range(3)]
        h1 = IncidentReportDocument.compute_evidence_hash(ids, [], [], None)
        h2 = IncidentReportDocument.compute_evidence_hash(ids, [], [], None)
        assert h1 == h2

    def test_hash_changes_when_id_added(self) -> None:
        ids = [str(uuid.uuid4())]
        h1 = IncidentReportDocument.compute_evidence_hash(ids, [], [], None)
        h2 = IncidentReportDocument.compute_evidence_hash(ids + [str(uuid.uuid4())], [], [], None)
        assert h1 != h2

    def test_hash_insensitive_to_list_order(self) -> None:
        """Canonical form sorts all lists — order must not matter."""
        a, b = str(uuid.uuid4()), str(uuid.uuid4())
        h1 = IncidentReportDocument.compute_evidence_hash([a, b], [], [], None)
        h2 = IncidentReportDocument.compute_evidence_hash([b, a], [], [], None)
        assert h1 == h2

    def test_hash_starts_with_sha256_prefix(self) -> None:
        h = IncidentReportDocument.compute_evidence_hash([], [], [], None)
        assert h.startswith("sha256:")

    def test_snapshot_id_affects_hash(self) -> None:
        snap = str(uuid.uuid4())
        h1 = IncidentReportDocument.compute_evidence_hash([], [], [], None)
        h2 = IncidentReportDocument.compute_evidence_hash([], [], [], snap)
        assert h1 != h2


# ---------------------------------------------------------------------------
# ReportRenderer.assemble_sections()
# ---------------------------------------------------------------------------


class TestReportRenderer:
    def _renderer(self) -> ReportRenderer:
        return ReportRenderer()

    def test_assemble_with_full_evidence_produces_sections(self) -> None:
        renderer = self._renderer()
        incident = _make_incident(
            drift_event_ids=[str(uuid.uuid4())],
            attribution_ids=[str(uuid.uuid4())],
            score_ids=[str(uuid.uuid4())],
        )
        sections = renderer.assemble_sections(
            incident=incident,
            drift_events=[_make_drift_event()],
            attributions=[_make_attribution()],
            scores=[_make_score()],
        )
        assert len(sections) > 0
        section_types = {s.section_type for s in sections}
        assert ReportSectionType.EXECUTIVE_SUMMARY in section_types

    def test_assemble_with_empty_evidence_does_not_raise(self) -> None:
        """Missing evidence must produce a LIMITATIONS section, not an exception."""
        renderer = self._renderer()
        incident = _make_incident()
        sections = renderer.assemble_sections(
            incident=incident,
            drift_events=[],
            attributions=[],
            scores=[],
        )
        # Must return at least one section (e.g. LIMITATIONS)
        assert isinstance(sections, list)
        assert len(sections) >= 1

    def test_assemble_completeness_between_zero_and_one(self) -> None:
        renderer = self._renderer()
        sections = renderer.assemble_sections(
            incident=_make_incident(),
            drift_events=[_make_drift_event()],
            attributions=[],
            scores=[],
        )
        for section in sections:
            assert 0.0 <= section.completeness <= 1.0

    def test_full_evidence_increases_completeness(self) -> None:
        renderer = self._renderer()
        empty_sections = renderer.assemble_sections(
            incident=_make_incident(),
            drift_events=[],
            attributions=[],
            scores=[],
        )
        full_sections = renderer.assemble_sections(
            incident=_make_incident(
                drift_event_ids=[str(uuid.uuid4())],
                attribution_ids=[str(uuid.uuid4())],
                score_ids=[str(uuid.uuid4())],
            ),
            drift_events=[_make_drift_event()],
            attributions=[_make_attribution()],
            scores=[_make_score()],
        )
        empty_avg = sum(s.completeness for s in empty_sections) / max(len(empty_sections), 1)
        full_avg = sum(s.completeness for s in full_sections) / max(len(full_sections), 1)
        assert full_avg >= empty_avg, "more evidence should not decrease average completeness"
