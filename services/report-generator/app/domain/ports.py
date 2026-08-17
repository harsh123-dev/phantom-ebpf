"""
report-generator domain ports.

Abstract interfaces:
    ReportRepository:  CRUD and archive operations on IncidentReportDocument.
    EvidenceStore:     Retrieve drift events, attributions, PCEPS scores by ID.
    ReportRenderer:    Assemble structured report sections from evidence.
    ReportExporter:    Export a completed IncidentReportDocument to a storage URI.

Design constraints:
    - No framework imports.  abc and typing only.
    - All methods are async (report generation is I/O-bound).
    - Concrete implementations live in app/infrastructure/.
    - All parameters and return types reference only domain entities and
      built-in types so that the domain layer has zero infrastructure imports.
"""

from __future__ import annotations

import abc
from typing import Any

from app.domain.entities import IncidentReportDocument, ReportSection, ReportStatus

# ---------------------------------------------------------------------------
# ReportRepository — CRUD on persisted IncidentReportDocument rows
# ---------------------------------------------------------------------------


class ReportRepository(abc.ABC):
    """Abstract CRUD repository for persisted incident reports.

    Callers work only with IncidentReportDocument domain objects.
    All persistence details (SQL, object store paths) are in the adapters.
    """

    @abc.abstractmethod
    async def save(
        self,
        document: IncidentReportDocument,
        tenant_id: str,
    ) -> None:
        """Persist or update an incident report document.

        Upserts on (incident_id, tenant_id, revision).
        Callers increment revision when regenerating a report.

        Args:
            document: Fully assembled document to persist.
            tenant_id: Owning tenant UUID string.
        """

    @abc.abstractmethod
    async def get(
        self,
        incident_id: str,
        tenant_id: str,
        revision: int | None = None,
    ) -> IncidentReportDocument | None:
        """Retrieve a persisted incident report.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.
            revision: If None, return the latest revision.

        Returns:
            IncidentReportDocument if found, else None.
        """

    @abc.abstractmethod
    async def list_for_incident(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> list[IncidentReportDocument]:
        """List all report revisions for an incident.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            List of IncidentReportDocument, oldest revision first.
        """

    @abc.abstractmethod
    async def update_status(
        self,
        incident_id: str,
        tenant_id: str,
        revision: int,
        status: ReportStatus,
    ) -> None:
        """Update the generation_status field of an existing report row.

        Used to transition GENERATING → COMPLETE | PARTIAL | FAILED
        without re-writing the full document.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.
            revision: Report revision to update.
            status: New ReportStatus value.
        """

    @abc.abstractmethod
    async def archive(
        self,
        incident_id: str,
        tenant_id: str,
        before_revision: int,
    ) -> int:
        """Move old revisions to archive table.

        Revisions strictly less than before_revision are archived.
        Keeps the audit trail without bloating the live report table.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.
            before_revision: Exclusive upper bound on revisions to archive.

        Returns:
            Number of revisions archived.
        """


# ---------------------------------------------------------------------------
# EvidenceStore — read evidence from the incident evidence tables
# ---------------------------------------------------------------------------


class EvidenceStore(abc.ABC):
    """Abstract reader for the evidence referenced by an incident.

    Reads are cross-service: drift events live in api-gateway's schema,
    attributions and scores live in causal-engine's schema. Concrete
    implementations use asyncpg queries against whichever database
    they are connected to.

    All list-based fetchers:
        - Return partial results on missing IDs (log missing, never raise).
        - Always enforce tenant_id isolation.
        - Respect the order of input IDs where possible.
    """

    @abc.abstractmethod
    async def get_incident(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Fetch the incident record including evidence ID lists.

        The returned dict always contains:
            drift_event_ids: list[str]
            attribution_ids: list[str]
            score_ids:       list[str]
            snapshot_id:     str | None
            revision:        int
            status:          str

        Raises:
            EvidenceNotFoundError: if incident_id is not found for tenant.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Incident record dict.
        """

    @abc.abstractmethod
    async def get_drift_events(
        self,
        drift_event_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch drift events by ID list.

        Missing IDs are silently skipped (logged at WARNING).
        Always enforces tenant_id ownership.

        Args:
            drift_event_ids: List of drift event UUID strings.
            tenant_id: Owning tenant UUID string.

        Returns:
            List of drift event dicts. May be shorter than input if
            some IDs are not found.
        """

    @abc.abstractmethod
    async def get_attributions(
        self,
        attribution_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch causal attribution records by ID list.

        Args:
            attribution_ids: List of attribution UUID strings.
            tenant_id: Owning tenant UUID string.

        Returns:
            List of attribution record dicts.
        """

    @abc.abstractmethod
    async def get_pceps_scores(
        self,
        score_ids: list[str],
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch PCEPS score records by ID list.

        Args:
            score_ids: List of score UUID strings.
            tenant_id: Owning tenant UUID string.

        Returns:
            List of PCEPS score dicts.
        """

    @abc.abstractmethod
    async def get_bdg_snapshot(
        self,
        snapshot_id: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a BDG snapshot record.

        Args:
            snapshot_id: Snapshot UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            BDG snapshot dict or None if not found.
        """


# ---------------------------------------------------------------------------
# ReportRenderer — assemble structured sections from evidence
# ---------------------------------------------------------------------------


class ReportRenderer(abc.ABC):
    """Abstract assembler that transforms evidence dicts into report sections.

    The renderer is stateless: all inputs are passed as arguments.
    It never reads from a database. Implementations may parse, aggregate,
    and format evidence but must NEVER fail the whole assembly because
    one section has incomplete data — missing data reduces completeness
    and populates missing_fields rather than raising.
    """

    @abc.abstractmethod
    def assemble_sections(
        self,
        incident: dict[str, Any],
        drift_events: list[dict[str, Any]],
        attributions: list[dict[str, Any]],
        scores: list[dict[str, Any]],
    ) -> list[ReportSection]:
        """Build all report sections from evidence.

        Must produce sections for all ReportSectionType values.
        Sections with insufficient data have completeness < 1.0 and
        non-empty missing_fields.

        Args:
            incident: Incident record dict from EvidenceStore.
            drift_events: Drift event dicts.
            attributions: Causal attribution dicts.
            scores: PCEPS score dicts.

        Returns:
            List of ReportSection, one per ReportSectionType (order not enforced).
        """


# ---------------------------------------------------------------------------
# ReportExporter — persist a completed document to external storage
# ---------------------------------------------------------------------------


class ReportExporter(abc.ABC):
    """Abstract exporter that stores a rendered report to external storage.

    Separates the rendering concern (ReportRenderer) from the persistence
    concern (object store / database). Implementations may write to a
    local filesystem, S3, GCS, or any other blob store.
    """

    @abc.abstractmethod
    async def export(
        self,
        tenant_id: str,
        incident_id: str,
        revision: int,
        document: IncidentReportDocument,
    ) -> str:
        """Store a completed report document.

        Args:
            tenant_id: Owning tenant UUID string.
            incident_id: Incident UUID string.
            revision: Report revision number.
            document: Fully assembled IncidentReportDocument.

        Returns:
            Storage URI string (e.g. 's3://bucket/key' or 'file:///path').
        """
