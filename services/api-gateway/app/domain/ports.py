"""
api-gateway domain ports.

Abstract service port interfaces for the gateway:
    DriftEventPort:       Persist and publish drift events to downstream consumers.
    SbomServicePort:      HTTP client interface to sbom-service.
    CausalEnginePort:     HTTP client interface to causal-engine.
    ReportGeneratorPort:  HTTP client interface to report-generator.

Design constraints:
    - No framework imports: abc and typing only.
    - All methods async (gateway is fully async).
    - Concrete implementations live in app/infrastructure/service_clients.py
      and app/infrastructure/postgres_repository.py.
    - Method signatures match the API contracts in
      docs/phantom_task_2_repository_and_api_contracts_handoff.md.
"""

from __future__ import annotations

import abc
from typing import Any

# ---------------------------------------------------------------------------
# DriftEventPort — persist + publish drift events
# ---------------------------------------------------------------------------


class DriftEventPort(abc.ABC):
    """Abstract port for persisting and publishing drift events.

    Drift events are written to PostgreSQL and then published to the
    Redis Streams channel consumed by the causal engine.

    All methods enforce tenant_id isolation at the data layer.
    """

    @abc.abstractmethod
    async def save(
        self,
        event: dict[str, Any],
        tenant_id: str,
    ) -> str:
        """Persist a drift event and return its UUID.

        Args:
            event: Validated drift event dict (from domain model).
            tenant_id: Owning tenant UUID string.

        Returns:
            event_id UUID string of the persisted record.
        """

    @abc.abstractmethod
    async def get(
        self,
        event_id: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a drift event by ID.

        Args:
            event_id: Event UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Drift event dict or None if not found.
        """

    @abc.abstractmethod
    async def list_for_incident(
        self,
        incident_id: str,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List drift events for an incident.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.
            limit: Maximum number of results.
            offset: Pagination offset.

        Returns:
            List of drift event dicts ordered by observed_at DESC.
        """

    @abc.abstractmethod
    async def publish(
        self,
        event_id: str,
        tenant_id: str,
    ) -> None:
        """Publish a persisted drift event to the downstream stream.

        Called after save() to fan-out the event to the causal engine.

        Args:
            event_id: Event UUID of the already-persisted event.
            tenant_id: Owning tenant UUID string.
        """


# ---------------------------------------------------------------------------
# SbomServicePort — HTTP calls to sbom-service
# ---------------------------------------------------------------------------


class SbomServicePort(abc.ABC):
    """Abstract HTTP client interface to the sbom-service.

    Implementations delegate to the sbom-service internal REST API.
    All methods raise ServiceUnavailableError on network failures.
    """

    @abc.abstractmethod
    async def ingest_sbom(
        self,
        sbom_payload: dict[str, Any],
        tenant_id: str,
    ) -> dict[str, Any]:
        """Submit an SBOM for ingestion.

        Args:
            sbom_payload: Raw SBOM dict (CycloneDX or SPDX format).
            tenant_id: Owning tenant UUID string.

        Returns:
            Ingestion response dict with ``sbom_id`` and ``status``.
        """

    @abc.abstractmethod
    async def get_sbom(
        self,
        sbom_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Retrieve a stored SBOM by ID.

        Args:
            sbom_id: SBOM UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            SBOM record dict.
        """

    @abc.abstractmethod
    async def trigger_verification(
        self,
        sbom_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Trigger a behavioral verification job for an SBOM.

        Args:
            sbom_id: SBOM UUID string to verify.
            tenant_id: Owning tenant UUID string.

        Returns:
            Verification job dict with ``job_id`` and ``status``.
        """

    @abc.abstractmethod
    async def get_verification_status(
        self,
        job_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Retrieve the status of a verification job.

        Args:
            job_id: Verification job UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Job status dict with ``job_id``, ``status``, and optional ``result``.
        """


# ---------------------------------------------------------------------------
# CausalEnginePort — HTTP calls to causal-engine
# ---------------------------------------------------------------------------


class CausalEnginePort(abc.ABC):
    """Abstract HTTP client interface to the causal-engine.

    Exposes BDG query, attribution submission, and PCEPS scoring.
    All methods raise ServiceUnavailableError on network failures.
    """

    @abc.abstractmethod
    async def get_bdg_node(
        self,
        node_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Retrieve a BDG node by ID.

        Args:
            node_id: BDG node UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            BDG node dict.
        """

    @abc.abstractmethod
    async def get_bdg_edge(
        self,
        edge_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Retrieve a BDG edge by ID.

        Args:
            edge_id: BDG edge UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            BDG edge dict.
        """

    @abc.abstractmethod
    async def query_subgraph(
        self,
        purl: str,
        tenant_id: str,
        depth: int = 2,
    ) -> dict[str, Any]:
        """Query the BDG subgraph rooted at a component PURL.

        Args:
            purl: Package URL of the root component.
            tenant_id: Owning tenant UUID string.
            depth: Maximum hop depth from the root.

        Returns:
            Subgraph dict with ``nodes`` and ``edges`` lists.
        """

    @abc.abstractmethod
    async def submit_attribution(
        self,
        attribution_request: dict[str, Any],
        tenant_id: str,
    ) -> dict[str, Any]:
        """Submit a causal attribution job.

        Args:
            attribution_request: Attribution request dict with treatment,
                outcome, and evidence fields.
            tenant_id: Owning tenant UUID string.

        Returns:
            Attribution record dict with ``attribution_id`` and ``status``.
        """

    @abc.abstractmethod
    async def get_attribution(
        self,
        attribution_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Retrieve a causal attribution record by ID.

        Args:
            attribution_id: Attribution UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Attribution record dict.
        """

    @abc.abstractmethod
    async def submit_pceps_score(
        self,
        score_request: dict[str, Any],
        tenant_id: str,
    ) -> dict[str, Any]:
        """Submit a PCEPS scoring request.

        Args:
            score_request: PCEPS feature dict for scoring.
            tenant_id: Owning tenant UUID string.

        Returns:
            PCEPS score dict with ``score_id``, ``pceps_score``, and
            ``severity_band``.
        """


# ---------------------------------------------------------------------------
# ReportGeneratorPort — HTTP calls to report-generator
# ---------------------------------------------------------------------------


class ReportGeneratorPort(abc.ABC):
    """Abstract HTTP client interface to the report-generator service.

    Triggers report generation and retrieves completed reports.
    All methods raise ServiceUnavailableError on network failures.
    """

    @abc.abstractmethod
    async def trigger_report(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Trigger incident report generation.

        Sends a message to the report-generator Redis stream.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Trigger response dict with ``incident_id`` and ``status``.
        """

    @abc.abstractmethod
    async def get_report(
        self,
        incident_id: str,
        tenant_id: str,
        revision: int | None = None,
    ) -> dict[str, Any] | None:
        """Retrieve a completed incident report.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.
            revision: Specific revision to retrieve. None = latest.

        Returns:
            Report document dict or None if not found / not yet ready.
        """

    @abc.abstractmethod
    async def get_report_status(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Check the generation status of an incident report.

        Args:
            incident_id: Incident UUID string.
            tenant_id: Owning tenant UUID string.

        Returns:
            Status dict with ``incident_id``, ``status``, and
            optional ``revision`` and ``generated_at``.
        """
