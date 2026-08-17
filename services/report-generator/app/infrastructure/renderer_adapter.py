from __future__ import annotations

from collections import Counter
from datetime import datetime
from statistics import mean
from typing import Any

import structlog

from app.domain.entities import ReportSection, ReportSectionType

log: structlog.BoundLogger = structlog.get_logger(__name__)


def _first_present(source: dict[str, Any], keys: tuple[str, ...]) -> object:
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _as_iso(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


class ReportRenderer:
    """
    Assembles evidence into a structured IncidentReportDocument.

    This is NOT a template renderer. It produces structured JSON
    sections that the frontend renders. There is no HTML/PDF output.
    """

    def assemble_sections(
        self,
        incident: dict[str, Any],
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
    ) -> list[ReportSection]:
        """
        Build all report sections from evidence.

        RULE: Never fail the whole assembly because one section
        has missing data. Missing data goes into the limitations
        section and reduces that section's completeness score.
        """
        missing_evidence = self._missing_evidence(incident, drift_events, attributions, scores)
        sections = [
            self._executive_summary(incident, drift_events, attributions, scores, missing_evidence),
            self._behavioral_evidence(drift_events),
            self._causal_attribution(attributions),
            self._pceps_score(scores),
            self._graph_evidence(incident),
            self._limitations(incident, drift_events, attributions, scores, missing_evidence),
        ]
        log.info(
            "report_renderer.sections_assembled",
            incident_id=str(incident.get("incident_id")),
            sections=len(sections),
        )
        return sections

    def _missing_evidence(
        self,
        incident: dict[str, Any],
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
    ) -> list[str]:
        missing: list[str] = []
        expected_drift = len(_as_list(incident.get("drift_event_ids")))
        expected_attributions = len(_as_list(incident.get("attribution_ids")))
        expected_scores = len(_as_list(incident.get("score_ids")))

        if len(drift_events) < expected_drift:
            missing.append(f"Missing {expected_drift - len(drift_events)} drift event(s)")
        if len(attributions) < expected_attributions:
            missing.append(
                f"Missing {expected_attributions - len(attributions)} attribution result(s)"
            )
        if len(scores) < expected_scores:
            missing.append(f"Missing {expected_scores - len(scores)} PCEPS score(s)")
        if not incident.get("snapshot_id"):
            missing.append("Missing BDG snapshot reference")
        return missing

    def _executive_summary(
        self,
        incident: dict[str, Any],
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
        missing_evidence: list[str],
    ) -> ReportSection:
        observed_times: list[Any] = [
            value
            for value in (
                _first_present(event, ("observed_at", "event_time", "created_at"))
                for event in drift_events
            )
            if value is not None
        ]
        severities = [str(score.get("severity")) for score in scores if score.get("severity")]
        content = {
            "title": incident.get("title"),
            "classification": incident.get("classification"),
            "status": incident.get("status"),
            "severity": self._highest_severity(severities) or "unknown",
            "timeline": {
                "first_drift_at": _as_iso(min(observed_times)) if observed_times else None,
                "last_drift_at": _as_iso(max(observed_times)) if observed_times else None,
                "incident_created_at": _as_iso(incident.get("created_at")),
            },
            "evidence_counts": {
                "drift_events": len(drift_events),
                "attributions": len(attributions),
                "scores": len(scores),
            },
        }
        completeness = (
            1.0 if not missing_evidence
            else max(0.0, 1.0 - (0.15 * len(missing_evidence)))
        )
        return ReportSection(
            section_type=ReportSectionType.EXECUTIVE_SUMMARY,
            content=content,
            completeness=completeness,
            missing_fields=missing_evidence,
        )

    def _behavioral_evidence(self, drift_events: list[dict[str, Any]]) -> ReportSection:
        events: list[dict[str, Any]] = []
        identity_statuses: list[str] = []
        event_types: list[str] = []
        resolved_count = 0
        for event in drift_events:
            identity_status = str(
                _first_present(event, ("identity_status", "binding_status")) or "unknown"
            )
            event_type = str(event.get("event_type") or "unknown")
            identity_statuses.append(identity_status)
            event_types.append(event_type)
            if identity_status in {"resolved", "identified", "bound"}:
                resolved_count += 1
            events.append(
                {
                    "event_type": event_type,
                    "identity_status": identity_status,
                    "severity": event.get("severity"),
                    "violation_types": self._violation_types(event),
                    "observed_at": _as_iso(
                        _first_present(event, ("observed_at", "event_time", "created_at"))
                    ),
                    "node_name": _first_present(
                        event,
                        ("node_name", "pod_uid", "container_id", "component_purl"),
                    ),
                }
            )
        completeness = resolved_count / len(drift_events) if drift_events else 0.0
        return ReportSection(
            section_type=ReportSectionType.BEHAVIORAL_EVIDENCE,
            content={
                "events": events,
                "identity_breakdown": dict(Counter(identity_statuses)),
                "event_type_breakdown": dict(Counter(event_types)),
            },
            completeness=completeness,
            missing_fields=[] if drift_events else ["drift_events"],
        )

    def _causal_attribution(self, attributions: list[dict[str, Any]]) -> ReportSection:
        rows: list[dict[str, Any]] = []
        confidences: list[float] = []
        identified_count = 0
        not_identifiable_count = 0
        for attribution in attributions:
            status = str(attribution.get("status") or "unknown")
            identified = status in {"identified", "complete", "completed", "success"}
            if identified:
                identified_count += 1
            if status == "not_identifiable":
                not_identifiable_count += 1
            confidence = _first_present(attribution, ("attribution_confidence", "confidence"))
            if identified and isinstance(confidence, int | float):
                confidences.append(float(confidence))
            rows.append(
                {
                    "attribution_id": str(attribution.get("attribution_id")),
                    "status": status,
                    "identified": identified,
                    "average_treatment_effect": _first_present(
                        attribution,
                        ("average_treatment_effect", "ate"),
                    )
                    if identified
                    else None,
                    "attribution_confidence": confidence if identified else None,
                    "refutation_summary": self._refutation_summary(attribution),
                    "failure_reason": _first_present(
                        attribution,
                        ("failure_reason", "reason"),
                    )
                    if status in {"failed", "not_identifiable"}
                    else None,
                }
            )
        total = len(attributions)
        return ReportSection(
            section_type=ReportSectionType.CAUSAL_ATTRIBUTION,
            content={
                "attributions": rows,
                "identifiable_count": identified_count,
                "not_identifiable_count": not_identifiable_count,
                "mean_confidence": mean(confidences) if confidences else None,
            },
            completeness=identified_count / max(1, total),
            missing_fields=[] if attributions else ["attributions"],
        )

    def _pceps_score(self, scores: list[dict[str, Any]]) -> ReportSection:
        rows = [
            {
                "score_id": str(score.get("score_id")),
                "score": score.get("score"),
                "severity": score.get("severity"),
                "feature_completeness": score.get("feature_completeness"),
                "imputed_features": _as_list(score.get("imputed_features")),
                "model_version": score.get("model_version"),
                "scored_at": _as_iso(_first_present(score, ("scored_at", "created_at"))),
            }
            for score in scores
        ]
        numeric_scores = [
            float(score["score"])
            for score in rows
            if isinstance(score["score"], int | float)
        ]
        severities = [str(score["severity"]) for score in rows if score["severity"]]
        return ReportSection(
            section_type=ReportSectionType.PCEPS_SCORE,
            content={
                "scores": rows,
                "max_score": max(numeric_scores) if numeric_scores else None,
                "max_severity": self._highest_severity(severities),
            },
            completeness=1.0 if scores else 0.0,
            missing_fields=[] if scores else ["scores"],
        )

    def _graph_evidence(self, incident: dict[str, Any]) -> ReportSection:
        snapshot_id = incident.get("snapshot_id")
        return ReportSection(
            section_type=ReportSectionType.GRAPH_EVIDENCE,
            content={
                "snapshot_id": snapshot_id,
                "note": "BDG subgraph available via GET /api/v1/bdg/subgraphs",
            },
            completeness=1.0 if snapshot_id else 0.0,
            missing_fields=[] if snapshot_id else ["snapshot_id"],
        )

    def _limitations(
        self,
        incident: dict[str, Any],
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
        missing_evidence: list[str],
    ) -> ReportSection:
        low_confidence_warnings = self._low_confidence_warnings(drift_events, attributions, scores)
        not_identifiable_reasons = [
            str(reason)
            for reason in (
                _first_present(attribution, ("failure_reason", "reason"))
                for attribution in attributions
                if str(attribution.get("status")) == "not_identifiable"
            )
            if reason
        ]
        imputed_features = sorted(
            {
                str(feature)
                for score in scores
                for feature in _as_list(score.get("imputed_features"))
            }
        )
        event_loss_detected = any(
            bool(_first_present(event, ("event_loss_observed",)))
            or bool((event.get("evidence") or {}).get("event_loss_observed"))
            for event in drift_events
        )
        if (
            not incident.get("snapshot_id")
            and "Missing BDG snapshot reference" not in missing_evidence
        ):
            missing_evidence.append("Missing BDG snapshot reference")
        return ReportSection(
            section_type=ReportSectionType.LIMITATIONS,
            content={
                "missing_evidence": missing_evidence,
                "low_confidence_warnings": low_confidence_warnings,
                "not_identifiable_reasons": not_identifiable_reasons,
                "imputed_features": imputed_features,
                "event_loss_detected": event_loss_detected,
            },
            completeness=1.0,
            missing_fields=[],
        )

    def _violation_types(self, event: dict[str, Any]) -> list[str]:
        violations = _first_present(event, ("violation_types", "contract_violations"))
        if not isinstance(violations, list):
            return []
        result: list[str] = []
        for violation in violations:
            if isinstance(violation, dict):
                result.append(
                    str(_first_present(violation, ("violation_type", "type")) or "unknown")
                )
            else:
                result.append(str(violation))
        return result

    def _refutation_summary(self, attribution: dict[str, Any]) -> dict[str, int]:
        refutations = attribution.get("refutations") or []
        if not isinstance(refutations, list):
            return {"passed": 0, "failed": 0, "total": 0}
        passed = 0
        failed = 0
        for refutation in refutations:
            if isinstance(refutation, dict) and bool(refutation.get("passed")):
                passed += 1
            else:
                failed += 1
        return {"passed": passed, "failed": failed, "total": len(refutations)}

    def _low_confidence_warnings(
        self,
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
    ) -> list[str]:
        warnings: list[str] = []
        for event in drift_events:
            confidence = _first_present(event, ("identity_confidence", "binding_confidence"))
            if isinstance(confidence, int | float) and float(confidence) < 0.5:
                warnings.append(f"Low drift-event identity confidence: {event.get('event_id')}")
        for attribution in attributions:
            confidence = _first_present(attribution, ("attribution_confidence", "confidence"))
            if isinstance(confidence, int | float) and float(confidence) < 0.5:
                warnings.append(f"Low attribution confidence: {attribution.get('attribution_id')}")
        for score in scores:
            completeness = score.get("feature_completeness")
            if isinstance(completeness, int | float) and float(completeness) < 0.8:
                warnings.append(f"Low PCEPS feature completeness: {score.get('score_id')}")
        return warnings

    def _highest_severity(self, severities: list[str]) -> str | None:
        if not severities:
            return None
        rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return max(severities, key=lambda severity: rank.get(severity.lower(), 0))
