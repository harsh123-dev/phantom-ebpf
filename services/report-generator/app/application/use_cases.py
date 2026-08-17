from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
import structlog

from app.domain.entities import IncidentReportDocument, ReportSection, ReportStatus
from app.domain.exceptions import ReportAssemblyError
from app.infrastructure.object_store_adapter import ReportObjectStore
from app.infrastructure.postgres_repository import (
    ReportDocumentRepository,
    ReportEvidenceRepository,
)
from app.infrastructure.renderer_adapter import ReportRenderer

log: structlog.BoundLogger = structlog.get_logger(__name__)


class GenerateReportUseCase:
    """
    Orchestrates complete incident report generation.

    This is the only public interface of the report generator.
    All dependencies are injected.
    """

    def __init__(
        self,
        evidence_repo: ReportEvidenceRepository,
        document_repo: ReportDocumentRepository,
        renderer: ReportRenderer,
        object_store: ReportObjectStore,
        redis: aioredis.Redis,
    ) -> None:
        self._evidence_repo = evidence_repo
        self._document_repo = document_repo
        self._renderer = renderer
        self._object_store = object_store
        self._redis = redis

    async def execute(self, incident_id: str, tenant_id: str) -> IncidentReportDocument:
        """
        Full generation pipeline.

        Never let a partial evidence failure abort the whole report.
        """
        revision = 1
        evidence_hash = IncidentReportDocument.compute_evidence_hash([], [], [], None)
        try:
            incident = await self._evidence_repo.get_incident(incident_id, tenant_id)
            revision = int(incident.get("revision") or 1)
            drift_event_ids = [str(value) for value in incident.get("drift_event_ids", []) or []]
            attribution_ids = [str(value) for value in incident.get("attribution_ids", []) or []]
            score_ids = [str(value) for value in incident.get("score_ids", []) or []]
            snapshot_id = str(incident["snapshot_id"]) if incident.get("snapshot_id") else None

            drift_events = await self._evidence_repo.get_drift_events(drift_event_ids, tenant_id)
            attributions = await self._evidence_repo.get_attributions(attribution_ids, tenant_id)
            scores = await self._evidence_repo.get_pceps_scores(score_ids, tenant_id)

            evidence_hash = IncidentReportDocument.compute_evidence_hash(
                drift_event_ids=drift_event_ids,
                attribution_ids=attribution_ids,
                score_ids=score_ids,
                snapshot_id=snapshot_id,
            )
            sections = self._renderer.assemble_sections(
                incident, drift_events, attributions, scores
            )
            missing_evidence_summary = self._missing_evidence_summary(
                drift_event_ids=drift_event_ids,
                drift_events=drift_events,
                attribution_ids=attribution_ids,
                attributions=attributions,
                score_ids=score_ids,
                scores=scores,
            )
            status = self._determine_status(sections, missing_evidence_summary)
            document = IncidentReportDocument(
                incident_id=incident_id,
                revision=revision,
                sections=sections,
                evidence_hash=evidence_hash,
                generated_at=datetime.now(UTC),
                generation_status=status,
                missing_evidence_summary=missing_evidence_summary,
            )

            await self._document_repo.save_report(document, tenant_id)
            storage_uri = await self._object_store.save(tenant_id, incident_id, revision, document)
            await self._publish_completion(incident_id, tenant_id, document, storage_uri)
            return document
        except ReportAssemblyError:
            raise
        except Exception as exc:  # noqa: BLE001
            failed_document = IncidentReportDocument(
                incident_id=incident_id,
                revision=revision,
                sections=[],
                evidence_hash=evidence_hash,
                generated_at=datetime.now(UTC),
                generation_status=ReportStatus.FAILED,
                missing_evidence_summary=[str(exc)],
            )
            try:
                await self._document_repo.save_report(failed_document, tenant_id)
                await self._publish_failure(incident_id, tenant_id, str(exc))
            except Exception as publish_exc:  # noqa: BLE001
                log.error(
                    "generate_report.failure_recording_failed",
                    incident_id=incident_id,
                    tenant_id=tenant_id,
                    error=str(publish_exc),
                )
            raise ReportAssemblyError(incident_id=incident_id, reason=str(exc)) from exc

    def _determine_status(
        self,
        sections: list[ReportSection],
        missing_evidence_summary: list[str],
    ) -> ReportStatus:
        if missing_evidence_summary:
            return ReportStatus.PARTIAL
        completeness_values = [section.completeness for section in sections]
        if completeness_values and all(value >= 0.8 for value in completeness_values):
            return ReportStatus.COMPLETE
        if any(value > 0.0 for value in completeness_values):
            return ReportStatus.PARTIAL
        return ReportStatus.FAILED

    def _missing_evidence_summary(
        self,
        drift_event_ids: list[str],
        drift_events: list[dict[str, Any]],
        attribution_ids: list[str],
        attributions: list[dict[str, Any]],
        score_ids: list[str],
        scores: list[dict[str, Any]],
    ) -> list[str]:
        missing: list[str] = []
        found_drift = {str(event.get("event_id")) for event in drift_events}
        found_attributions = {
            str(attribution.get("attribution_id")) for attribution in attributions
        }
        found_scores = {str(score.get("score_id")) for score in scores}
        for drift_event_id in sorted(set(drift_event_ids) - found_drift):
            missing.append(f"drift_event:{drift_event_id}")
        for attribution_id in sorted(set(attribution_ids) - found_attributions):
            missing.append(f"attribution:{attribution_id}")
        for score_id in sorted(set(score_ids) - found_scores):
            missing.append(f"pceps_score:{score_id}")
        return missing

    async def _publish_completion(
        self,
        incident_id: str,
        tenant_id: str,
        document: IncidentReportDocument,
        storage_uri: str,
    ) -> None:
        await self._redis.xadd(
            "phantom:stream:report.complete",
            {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "status": document.generation_status.value,
                "evidence_hash": document.evidence_hash,
                "storage_uri": storage_uri,
            },
        )

    async def _publish_failure(self, incident_id: str, tenant_id: str, reason: str) -> None:
        await self._redis.xadd(
            "phantom:stream:report.failed",
            {
                "incident_id": incident_id,
                "tenant_id": tenant_id,
                "status": ReportStatus.FAILED.value,
                "reason": reason,
            },
        )
