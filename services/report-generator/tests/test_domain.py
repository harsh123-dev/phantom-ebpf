from __future__ import annotations

from app.domain.entities import IncidentReportDocument, ReportSection, ReportSectionType
from app.infrastructure.renderer_adapter import ReportRenderer


def test_evidence_hash_is_deterministic() -> None:
    """Same inputs in different order produce same hash."""
    hash1 = IncidentReportDocument.compute_evidence_hash(
        drift_event_ids=["b", "a"],
        attribution_ids=["d", "c"],
        score_ids=["f", "e"],
        snapshot_id="snap-1",
    )
    hash2 = IncidentReportDocument.compute_evidence_hash(
        drift_event_ids=["a", "b"],
        attribution_ids=["c", "d"],
        score_ids=["e", "f"],
        snapshot_id="snap-1",
    )
    assert hash1 == hash2


def test_evidence_hash_changes_on_different_ids() -> None:
    """Different evidence IDs produce different hash."""
    hash1 = IncidentReportDocument.compute_evidence_hash(
        drift_event_ids=["a"],
        attribution_ids=["c"],
        score_ids=["e"],
        snapshot_id="snap-1",
    )
    hash2 = IncidentReportDocument.compute_evidence_hash(
        drift_event_ids=["b"],
        attribution_ids=["c"],
        score_ids=["e"],
        snapshot_id="snap-1",
    )
    assert hash1 != hash2


def test_evidence_hash_format() -> None:
    """Hash starts with sha256: and has 64 hex chars after."""
    evidence_hash = IncidentReportDocument.compute_evidence_hash(
        drift_event_ids=["a"],
        attribution_ids=["b"],
        score_ids=["c"],
        snapshot_id="snap-1",
    )
    prefix, digest = evidence_hash.split(":", maxsplit=1)
    assert prefix == "sha256"
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)


def test_report_section_completeness_bounds() -> None:
    """completeness is always between 0.0 and 1.0."""
    section = ReportSection(
        section_type=ReportSectionType.LIMITATIONS,
        content={},
        completeness=1.0,
    )
    assert 0.0 <= section.completeness <= 1.0


def test_renderer_partial_on_missing_attributions() -> None:
    """Assembly produces PARTIAL status when attribution list empty."""
    renderer = ReportRenderer()
    sections = renderer.assemble_sections(
        incident={
            "incident_id": "incident-1",
            "title": "Runtime drift",
            "classification": "suspicious",
            "status": "open",
            "drift_event_ids": ["event-1"],
            "attribution_ids": ["attribution-1"],
            "score_ids": ["score-1"],
            "snapshot_id": "snapshot-1",
        },
        drift_events=[
            {
                "event_id": "event-1",
                "event_type": "exec",
                "identity_status": "resolved",
                "severity": "high",
            }
        ],
        attributions=[],
        scores=[{"score_id": "score-1", "score": 0.82, "severity": "high"}],
    )
    causal_section = next(
        section
        for section in sections
        if section.section_type == ReportSectionType.CAUSAL_ATTRIBUTION
    )
    assert causal_section.completeness < 0.8
    assert "attributions" in causal_section.missing_fields


def test_renderer_limitations_section_always_complete() -> None:
    """limitations section has completeness=1.0 even with missing data."""
    renderer = ReportRenderer()
    sections = renderer.assemble_sections(
        incident={"incident_id": "incident-1", "drift_event_ids": ["event-1"]},
        drift_events=[],
        attributions=[],
        scores=[],
    )
    limitations = next(
        section for section in sections if section.section_type == ReportSectionType.LIMITATIONS
    )
    assert limitations.completeness == 1.0


def test_renderer_no_exception_on_empty_evidence() -> None:
    """assemble_sections does not raise when all lists are empty."""
    renderer = ReportRenderer()
    sections = renderer.assemble_sections(
        incident={"incident_id": "incident-1"},
        drift_events=[],
        attributions=[],
        scores=[],
    )
    assert {section.section_type for section in sections} == set(ReportSectionType)
