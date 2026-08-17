from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import asyncpg
import structlog

from app.domain.entities import (
    IncidentReportDocument,
    ReportSection,
    ReportSectionType,
    ReportStatus,
)
from app.domain.exceptions import EvidenceNotFoundError

log: structlog.BoundLogger = structlog.get_logger(__name__)


def _json_load(value: object) -> Any:  # noqa: ANN401
    if isinstance(value, str):
        return json.loads(value)
    return value


def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in dict(row).items():
        result[key] = _json_load(value)
    return result


class ReportEvidenceRepository:
    """Reads evidence from PostgreSQL for report assembly."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get_incident(self, incident_id: str, tenant_id: str) -> dict[str, Any]:
        """
        Fetch incident record including all evidence ID lists.
        Raises EvidenceNotFoundError if not found.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT *
                FROM incidents
                WHERE incident_id = $1 AND tenant_id = $2
                """,
                incident_id,
                tenant_id,
            )
        if row is None:
            raise EvidenceNotFoundError(
                incident_id=incident_id,
                missing_type="incident",
                missing_id=incident_id,
            )

        incident = _row_to_dict(row)
        incident["drift_event_ids"] = [
            str(value) for value in incident.get("drift_event_ids", []) or []
        ]
        incident["attribution_ids"] = [
            str(value) for value in incident.get("attribution_ids", []) or []
        ]
        incident["score_ids"] = [str(value) for value in incident.get("score_ids", []) or []]
        if incident.get("snapshot_id") is not None:
            incident["snapshot_id"] = str(incident["snapshot_id"])
        return incident

    async def get_drift_events(
        self,
        drift_event_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """
        Fetch drift events by ID list.
        Returns only events belonging to tenant_id.
        Missing IDs are logged as warnings, not errors.
        """
        if not drift_event_ids:
            return []

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT *
                FROM drift_events
                WHERE event_id = ANY($1::uuid[]) AND tenant_id = $2
                """,
                drift_event_ids,
                tenant_id,
            )
        events = [_row_to_dict(row) for row in rows]
        found_ids = {str(event.get("event_id")) for event in events}
        for missing_id in sorted(set(drift_event_ids) - found_ids):
            log.warning(
                "report_evidence.drift_event_missing",
                tenant_id=tenant_id,
                drift_event_id=missing_id,
            )
        return events

    async def get_attributions(
        self,
        attribution_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch attribution job results by ID list."""
        if not attribution_ids:
            return []

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT *
                FROM attribution_results
                WHERE attribution_id = ANY($1::uuid[]) AND tenant_id = $2
                """,
                attribution_ids,
                tenant_id,
            )
        attributions = [_row_to_dict(row) for row in rows]
        found_ids = {str(attribution.get("attribution_id")) for attribution in attributions}
        for missing_id in sorted(set(attribution_ids) - found_ids):
            log.warning(
                "report_evidence.attribution_missing",
                tenant_id=tenant_id,
                attribution_id=missing_id,
            )
        return attributions

    async def get_pceps_scores(
        self,
        score_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch PCEPS scores by ID list."""
        if not score_ids:
            return []

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT *
                FROM pceps_scores
                WHERE score_id = ANY($1::uuid[]) AND tenant_id = $2
                """,
                score_ids,
                tenant_id,
            )
        scores = [_row_to_dict(row) for row in rows]
        found_ids = {str(score.get("score_id")) for score in scores}
        for missing_id in sorted(set(score_ids) - found_ids):
            log.warning(
                "report_evidence.pceps_score_missing",
                tenant_id=tenant_id,
                score_id=missing_id,
            )
        return scores


class ReportDocumentRepository:
    """Persists and retrieves assembled report documents."""

    MIGRATION_SQL: str = """
    CREATE TABLE IF NOT EXISTS incident_reports (
        incident_id UUID NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        sections_json JSONB NOT NULL,
        evidence_hash TEXT NOT NULL,
        generated_at TIMESTAMPTZ NOT NULL,
        tenant_id UUID NOT NULL,
        PRIMARY KEY (incident_id, revision)
    );
    CREATE INDEX IF NOT EXISTS idx_incident_reports_tenant_incident_revision
        ON incident_reports (tenant_id, incident_id, revision DESC);
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def save_report(self, report: IncidentReportDocument, tenant_id: str) -> None:
        """
        Upsert report document.
        Table: incident_reports
        Columns: incident_id, revision, status, sections_json,
                 evidence_hash, generated_at, tenant_id
        On conflict (incident_id, revision): update status and
        sections_json only.
        """
        sections_json = json.dumps(
            [
                {
                    "section_type": section.section_type.value,
                    "content": section.content,
                    "completeness": section.completeness,
                    "missing_fields": section.missing_fields,
                }
                for section in report.sections
            ],
            default=str,
            sort_keys=True,
        )
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO incident_reports (
                    incident_id, revision, status, sections_json,
                    evidence_hash, generated_at, tenant_id
                )
                VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
                ON CONFLICT (incident_id, revision)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    sections_json = EXCLUDED.sections_json
                """,
                report.incident_id,
                report.revision,
                report.generation_status.value,
                sections_json,
                report.evidence_hash,
                report.generated_at,
                tenant_id,
            )
        log.info(
            "report_document.saved",
            tenant_id=tenant_id,
            incident_id=report.incident_id,
            revision=report.revision,
            status=report.generation_status.value,
        )

    async def get_report(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> IncidentReportDocument | None:
        """Fetch most recent report revision."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT incident_id, revision, status, sections_json,
                       evidence_hash, generated_at
                FROM incident_reports
                WHERE incident_id = $1 AND tenant_id = $2
                ORDER BY revision DESC
                LIMIT 1
                """,
                incident_id,
                tenant_id,
            )
        if row is None:
            return None

        section_rows = _json_load(row["sections_json"])
        sections = [
            ReportSection(
                section_type=ReportSectionType(section["section_type"]),
                content=section.get("content", {}),
                completeness=float(section.get("completeness", 0.0)),
                missing_fields=list(section.get("missing_fields", [])),
            )
            for section in section_rows
        ]
        generated_at: datetime = row["generated_at"]
        return IncidentReportDocument(
            incident_id=str(row["incident_id"]),
            revision=int(row["revision"]),
            sections=sections,
            evidence_hash=str(row["evidence_hash"]),
            generated_at=generated_at,
            generation_status=ReportStatus(str(row["status"])),
            missing_evidence_summary=[],
        )
