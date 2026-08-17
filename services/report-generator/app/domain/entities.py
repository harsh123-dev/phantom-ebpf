from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ReportStatus(str, Enum):
    GENERATING = "generating"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ReportSectionType(str, Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    BEHAVIORAL_EVIDENCE = "behavioral_evidence"
    CAUSAL_ATTRIBUTION = "causal_attribution"
    GRAPH_EVIDENCE = "graph_evidence"
    PCEPS_SCORE = "pceps_score"
    LIMITATIONS = "limitations"


@dataclass(frozen=True)
class EvidenceReference:
    """Immutable reference to one piece of forensic evidence."""

    drift_event_id: str | None = None
    attribution_id: str | None = None
    score_id: str | None = None
    bdg_snapshot_id: str | None = None

    def __post_init__(self) -> None:
        for field_name, field_value in (
            ("drift_event_id", self.drift_event_id),
            ("attribution_id", self.attribution_id),
            ("score_id", self.score_id),
            ("bdg_snapshot_id", self.bdg_snapshot_id),
        ):
            if field_value is not None:
                uuid.UUID(field_value)


@dataclass(frozen=True)
class ReportSection:
    """One named section of an incident report."""

    section_type: ReportSectionType
    content: dict[str, Any]
    completeness: float
    missing_fields: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.completeness <= 1.0:
            raise ValueError(
                f"ReportSection completeness must be between 0.0 and 1.0, "
                f"got {self.completeness}"
            )


@dataclass
class IncidentReportDocument:
    """
    Complete assembled incident report.

    evidence_hash is SHA-256 of the canonical sorted JSON
    of all referenced evidence IDs. It changes if any
    evidence reference changes. It does NOT change if the
    narrative text is reformatted.
    """

    incident_id: str
    revision: int
    sections: list[ReportSection]
    evidence_hash: str
    generated_at: datetime
    generation_status: ReportStatus
    missing_evidence_summary: list[str] = field(default_factory=list)

    @staticmethod
    def compute_evidence_hash(
        drift_event_ids: list[str],
        attribution_ids: list[str],
        score_ids: list[str],
        snapshot_id: str | None,
    ) -> str:
        """
        Deterministic SHA-256 hash of canonical evidence references.

        Canonical form: sort all lists, serialize as JSON with
        sorted keys, encode UTF-8, SHA-256 digest.
        Returns: sha256:<hex>
        """
        canonical_evidence = {
            "attribution_ids": sorted(attribution_ids),
            "drift_event_ids": sorted(drift_event_ids),
            "score_ids": sorted(score_ids),
            "snapshot_id": snapshot_id,
        }
        canonical_json = json.dumps(
            canonical_evidence,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"
