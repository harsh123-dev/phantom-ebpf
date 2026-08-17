"""
causal-engine asyncpg PostgreSQL repository adapter.

Implements all BdgRepository and AttributionRepository domain ports, plus
PCEPSRepository and DriftEventReadRepository for persistent storage of:
  - BDG snapshots (bdg_snapshots table)
  - Attribution results (attribution_results table)
  - PCEPS scores (pceps_scores table)
  - Drift event read-path (drift_events table — written by api-gateway)

Every public method emits ``phantom_postgres_operation_duration_seconds``
with ``operation`` and ``repository`` labels.

Tables expected:
    bdg_snapshots          (snapshot_id, tenant_id, created_at, node_count,
                            edge_count, event_id_high_watermark, graph_data)
    attribution_results    (attribution_id, status, reason,
                            ate, ate_ci_lower, ate_ci_upper,
                            counterfactual_drift_probability,
                            counterfactual_status, confidence,
                            snapshot_id, estimator_name,
                            refutations, graph_diagnostics, created_at)
    pceps_scores           (score_id, drift_event_id, attribution_id,
                            score, severity, raw_probability,
                            calibrated_probability, feature_completeness,
                            imputed_features, model_version, created_at)
    drift_events           (event_id, tenant_id, event_type, event_time,
                            cluster, namespace, pod_uid, container_id,
                            image_digest, tgid, pid_start_time_ns,
                            identity_confidence, binding_confidence,
                            collector_confidence, binding_status,
                            component_purl, contract_violations,
                            event_attrs, created_at)
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import structlog
from prometheus_client import Histogram

from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    BDGSnapshot,
    PcepsScore,
    PcepsSeverity,
    RefutationResult,
)
from app.domain.ports import AttributionRepository, BdgRepository

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metric
# ---------------------------------------------------------------------------

_DB_DURATION = Histogram(
    "phantom_postgres_operation_duration_seconds",
    "Duration of PostgreSQL operations in the causal-engine",
    labelnames=["operation", "repository"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


def _observe(repository: str, operation: str, t0: float) -> None:
    """Record a DB operation duration in the Prometheus histogram.

    Args:
        repository: Repository class name label.
        operation: Method name label.
        t0: Start time from ``time.monotonic()``.
    """
    _DB_DURATION.labels(operation=operation, repository=repository).observe(
        time.monotonic() - t0
    )


# ---------------------------------------------------------------------------
# PostgresBdgRepository
# ---------------------------------------------------------------------------


class PostgresBdgRepository(BdgRepository):
    """Asyncpg-backed BdgRepository.

    Implements save_snapshot, load_snapshot, and get_latest_snapshot_id
    as specified in the domain ports. All methods emit Prometheus metrics.

    Args:
        pool: asyncpg connection pool.
    """

    _REPO = "PostgresBdgRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with asyncpg pool.

        Args:
            pool: asyncpg.Pool instance.
        """
        self._pool = pool

    async def save_snapshot(
        self,
        snapshot: BDGSnapshot,
        graph_data: dict[str, Any],
    ) -> None:
        """Persist a BDG snapshot to PostgreSQL.

        Uses ON CONFLICT DO NOTHING for idempotency — snapshots are
        immutable once committed.

        Args:
            snapshot: BDGSnapshot metadata object.
            graph_data: JSON-serializable graph representation.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO bdg_snapshots (
                        snapshot_id, tenant_id, created_at,
                        node_count, edge_count,
                        event_id_high_watermark, graph_data
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (snapshot_id) DO NOTHING
                    """,
                    str(snapshot.snapshot_id),
                    str(snapshot.tenant_id),
                    snapshot.created_at,
                    snapshot.node_count,
                    snapshot.edge_count,
                    str(snapshot.event_id_high_watermark)
                    if snapshot.event_id_high_watermark
                    else None,
                    json.dumps(graph_data),
                )
            log.info(
                "bdg_repo.snapshot_saved",
                snapshot_id=str(snapshot.snapshot_id),
                nodes=snapshot.node_count,
                edges=snapshot.edge_count,
            )
        finally:
            _observe(self._REPO, "save_snapshot", t0)

    async def load_snapshot(
        self,
        snapshot_id: uuid.UUID,
    ) -> tuple[BDGSnapshot, dict[str, Any]] | None:
        """Load a BDG snapshot by UUID.

        Args:
            snapshot_id: UUID of the snapshot.

        Returns:
            Tuple of (BDGSnapshot, graph_data_dict) or None.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT snapshot_id, tenant_id, created_at,
                           node_count, edge_count,
                           event_id_high_watermark, graph_data
                    FROM bdg_snapshots
                    WHERE snapshot_id = $1
                    """,
                    str(snapshot_id),
                )

            if row is None:
                log.warning("bdg_repo.snapshot_not_found", snapshot_id=str(snapshot_id))
                return None

            hwm = row["event_id_high_watermark"]
            snapshot = BDGSnapshot(
                snapshot_id=uuid.UUID(row["snapshot_id"]),
                tenant_id=uuid.UUID(row["tenant_id"]),
                created_at=row["created_at"],
                node_count=row["node_count"],
                edge_count=row["edge_count"],
                event_id_high_watermark=uuid.UUID(hwm) if hwm else None,
            )
            return snapshot, json.loads(row["graph_data"])
        finally:
            _observe(self._REPO, "load_snapshot", t0)

    async def get_latest_snapshot_id(
        self,
        tenant_id: uuid.UUID,
    ) -> uuid.UUID | None:
        """Get the most recent snapshot UUID for a tenant.

        Args:
            tenant_id: Tenant UUID.

        Returns:
            UUID of the latest snapshot, or None.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT snapshot_id
                    FROM bdg_snapshots
                    WHERE tenant_id = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    str(tenant_id),
                )
            return uuid.UUID(row["snapshot_id"]) if row else None
        finally:
            _observe(self._REPO, "get_latest_snapshot_id", t0)

    async def list_snapshots(
        self,
        tenant_id: uuid.UUID,
        limit: int = 20,
    ) -> list[BDGSnapshot]:
        """List BDG snapshots for a tenant, newest first.

        Args:
            tenant_id: Tenant UUID.
            limit: Maximum number of results to return.

        Returns:
            List of BDGSnapshot metadata objects (no graph_data).
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT snapshot_id, tenant_id, created_at,
                           node_count, edge_count, event_id_high_watermark
                    FROM bdg_snapshots
                    WHERE tenant_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    """,
                    str(tenant_id),
                    limit,
                )
            results: list[BDGSnapshot] = []
            for row in rows:
                hwm = row["event_id_high_watermark"]
                results.append(
                    BDGSnapshot(
                        snapshot_id=uuid.UUID(row["snapshot_id"]),
                        tenant_id=uuid.UUID(row["tenant_id"]),
                        created_at=row["created_at"],
                        node_count=row["node_count"],
                        edge_count=row["edge_count"],
                        event_id_high_watermark=uuid.UUID(hwm) if hwm else None,
                    )
                )
            return results
        finally:
            _observe(self._REPO, "list_snapshots", t0)


# ---------------------------------------------------------------------------
# PostgresAttributionRepository
# ---------------------------------------------------------------------------


class PostgresAttributionRepository(AttributionRepository):
    """Asyncpg-backed AttributionRepository.

    Args:
        pool: asyncpg connection pool.
    """

    _REPO = "PostgresAttributionRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with asyncpg pool.

        Args:
            pool: asyncpg.Pool instance.
        """
        self._pool = pool

    async def save_attribution(self, result: AttributionResult) -> None:
        """Persist an attribution result to PostgreSQL.

        Args:
            result: The AttributionResult to persist.
        """
        t0 = time.monotonic()
        refutations_json = json.dumps([
            {
                "refuter_name": r.refuter_name,
                "estimated_effect": r.estimated_effect,
                "new_effect": r.new_effect,
                "p_value": r.p_value,
                "passed": r.passed,
            }
            for r in result.refutations
        ])

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO attribution_results (
                        attribution_id, status, reason,
                        ate, ate_ci_lower, ate_ci_upper,
                        counterfactual_drift_probability,
                        counterfactual_status,
                        confidence, snapshot_id,
                        estimator_name, refutations,
                        graph_diagnostics, created_at
                    )
                    VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9,
                        $10, $11, $12, $13, $14
                    )
                    ON CONFLICT (attribution_id) DO NOTHING
                    """,
                    str(result.attribution_id),
                    result.status.value,
                    result.reason,
                    result.ate,
                    result.ate_ci_lower,
                    result.ate_ci_upper,
                    result.counterfactual_drift_probability,
                    result.counterfactual_status,
                    result.confidence,
                    str(result.snapshot_id) if result.snapshot_id else None,
                    result.estimator_name,
                    refutations_json,
                    json.dumps(result.graph_diagnostics),
                    datetime.now(tz=UTC),
                )
            log.info(
                "attribution_repo.saved",
                attribution_id=str(result.attribution_id),
                status=result.status.value,
            )
        finally:
            _observe(self._REPO, "save_attribution", t0)

    async def load_attribution(
        self,
        attribution_id: uuid.UUID,
    ) -> AttributionResult | None:
        """Load an attribution result by UUID.

        Args:
            attribution_id: UUID of the attribution.

        Returns:
            AttributionResult or None.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT attribution_id, status, reason,
                           ate, ate_ci_lower, ate_ci_upper,
                           counterfactual_drift_probability,
                           counterfactual_status, confidence,
                           snapshot_id, estimator_name,
                           refutations, graph_diagnostics
                    FROM attribution_results
                    WHERE attribution_id = $1
                    """,
                    str(attribution_id),
                )

            if row is None:
                return None

            refutations_raw = json.loads(row["refutations"] or "[]")
            refutations = [
                RefutationResult(
                    refuter_name=r["refuter_name"],
                    estimated_effect=r["estimated_effect"],
                    new_effect=r["new_effect"],
                    p_value=r.get("p_value"),
                    passed=r["passed"],
                )
                for r in refutations_raw
            ]

            return AttributionResult(
                attribution_id=uuid.UUID(row["attribution_id"]),
                status=AttributionStatus(row["status"]),
                reason=row["reason"] or "",
                ate=row["ate"],
                ate_ci_lower=row["ate_ci_lower"],
                ate_ci_upper=row["ate_ci_upper"],
                counterfactual_drift_probability=row["counterfactual_drift_probability"],
                counterfactual_status=row["counterfactual_status"] or "unavailable",
                confidence=row["confidence"],
                snapshot_id=uuid.UUID(row["snapshot_id"]) if row["snapshot_id"] else None,
                estimator_name=row["estimator_name"] or "",
                refutations=refutations,
                graph_diagnostics=json.loads(row["graph_diagnostics"] or "{}"),
            )
        finally:
            _observe(self._REPO, "load_attribution", t0)

    async def get_jobs_by_snapshot(
        self,
        snapshot_id: uuid.UUID,
        limit: int = 50,
    ) -> list[AttributionResult]:
        """Load all attribution results for a BDG snapshot.

        Args:
            snapshot_id: UUID of the BDG snapshot.
            limit: Maximum results to return.

        Returns:
            List of AttributionResult objects.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT attribution_id, status, reason,
                           ate, ate_ci_lower, ate_ci_upper,
                           counterfactual_drift_probability,
                           counterfactual_status, confidence,
                           snapshot_id, estimator_name,
                           refutations, graph_diagnostics
                    FROM attribution_results
                    WHERE snapshot_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    """,
                    str(snapshot_id),
                    limit,
                )

            results: list[AttributionResult] = []
            for row in rows:
                refutations_raw = json.loads(row["refutations"] or "[]")
                refutations = [
                    RefutationResult(
                        refuter_name=r["refuter_name"],
                        estimated_effect=r["estimated_effect"],
                        new_effect=r["new_effect"],
                        p_value=r.get("p_value"),
                        passed=r["passed"],
                    )
                    for r in refutations_raw
                ]
                results.append(AttributionResult(
                    attribution_id=uuid.UUID(row["attribution_id"]),
                    status=AttributionStatus(row["status"]),
                    reason=row["reason"] or "",
                    ate=row["ate"],
                    ate_ci_lower=row["ate_ci_lower"],
                    ate_ci_upper=row["ate_ci_upper"],
                    counterfactual_drift_probability=row["counterfactual_drift_probability"],
                    counterfactual_status=row["counterfactual_status"] or "unavailable",
                    confidence=row["confidence"],
                    snapshot_id=uuid.UUID(row["snapshot_id"]) if row["snapshot_id"] else None,
                    estimator_name=row["estimator_name"] or "",
                    refutations=refutations,
                    graph_diagnostics=json.loads(row["graph_diagnostics"] or "{}"),
                ))
            return results
        finally:
            _observe(self._REPO, "get_jobs_by_snapshot", t0)


# ---------------------------------------------------------------------------
# PostgresPCEPSRepository
# ---------------------------------------------------------------------------


class PostgresPCEPSRepository:
    """Asyncpg-backed PCEPS score persistence.

    Stores and retrieves calibrated PCEPS priority scores.

    Args:
        pool: asyncpg connection pool.
    """

    _REPO = "PostgresPCEPSRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with asyncpg pool.

        Args:
            pool: asyncpg.Pool instance.
        """
        self._pool = pool

    async def save_score(
        self,
        score: PcepsScore,
        drift_event_id: uuid.UUID,
        attribution_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        """Persist a PCEPS score record.

        Args:
            score: PcepsScore value object.
            drift_event_id: UUID of the drift event that triggered scoring.
            attribution_id: UUID of the attribution job (may be None).

        Returns:
            UUID of the newly created score record.
        """
        t0 = time.monotonic()
        score_id = uuid.uuid4()
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO pceps_scores (
                        score_id, drift_event_id, attribution_id,
                        score, severity, raw_probability,
                        calibrated_probability, feature_completeness,
                        imputed_features, model_version, created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    ON CONFLICT (score_id) DO NOTHING
                    """,
                    str(score_id),
                    str(drift_event_id),
                    str(attribution_id) if attribution_id else None,
                    score.score,
                    score.severity.value,
                    score.raw_probability,
                    score.calibrated_probability,
                    score.feature_completeness,
                    json.dumps(score.imputed_features),
                    score.model_version,
                    datetime.now(tz=UTC),
                )
            log.info(
                "pceps_repo.saved",
                score_id=str(score_id),
                drift_event_id=str(drift_event_id),
                score=score.score,
                severity=score.severity.value,
            )
            return score_id
        finally:
            _observe(self._REPO, "save_score", t0)

    async def get_score(self, score_id: uuid.UUID) -> PcepsScore | None:
        """Load a PCEPS score by ID.

        Args:
            score_id: UUID of the score record.

        Returns:
            PcepsScore or None.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT score_id, score, severity, raw_probability,
                           calibrated_probability, feature_completeness,
                           imputed_features, model_version
                    FROM pceps_scores
                    WHERE score_id = $1
                    """,
                    str(score_id),
                )
            if row is None:
                return None
            return PcepsScore(
                score=row["score"],
                severity=PcepsSeverity(row["severity"]),
                raw_probability=row["raw_probability"],
                calibrated_probability=row["calibrated_probability"],
                feature_completeness=row["feature_completeness"],
                imputed_features=json.loads(row["imputed_features"] or "[]"),
                model_version=row["model_version"] or "",
            )
        finally:
            _observe(self._REPO, "get_score", t0)

    async def get_scores_by_drift_event(
        self,
        drift_event_id: uuid.UUID,
    ) -> list[PcepsScore]:
        """Load all PCEPS scores for a drift event.

        Args:
            drift_event_id: UUID of the drift event.

        Returns:
            List of PcepsScore objects, newest first.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT score, severity, raw_probability,
                           calibrated_probability, feature_completeness,
                           imputed_features, model_version
                    FROM pceps_scores
                    WHERE drift_event_id = $1
                    ORDER BY created_at DESC
                    """,
                    str(drift_event_id),
                )
            return [
                PcepsScore(
                    score=row["score"],
                    severity=PcepsSeverity(row["severity"]),
                    raw_probability=row["raw_probability"],
                    calibrated_probability=row["calibrated_probability"],
                    feature_completeness=row["feature_completeness"],
                    imputed_features=json.loads(row["imputed_features"] or "[]"),
                    model_version=row["model_version"] or "",
                )
                for row in rows
            ]
        finally:
            _observe(self._REPO, "get_scores_by_drift_event", t0)


# ---------------------------------------------------------------------------
# PostgresDriftEventReadRepository
# ---------------------------------------------------------------------------


class PostgresDriftEventReadRepository:
    """Read-only view of drift events written by api-gateway.

    The api-gateway owns the write path for drift_events; this repository
    is read-only from the causal-engine's perspective.

    Args:
        pool: asyncpg connection pool.
    """

    _REPO = "PostgresDriftEventReadRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with asyncpg pool.

        Args:
            pool: asyncpg.Pool instance.
        """
        self._pool = pool

    async def get_drift_event(
        self,
        event_id: uuid.UUID,
    ) -> dict[str, Any] | None:
        """Load a single drift event by UUID.

        Args:
            event_id: UUID of the drift event.

        Returns:
            Dict of event fields or None.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT event_id, tenant_id, event_type, event_time,
                           cluster, namespace, pod_uid, container_id,
                           image_digest, tgid, pid_start_time_ns,
                           identity_confidence, binding_confidence,
                           collector_confidence, binding_status,
                           component_purl, contract_violations,
                           event_attrs, created_at
                    FROM drift_events
                    WHERE event_id = $1
                    """,
                    str(event_id),
                )
            if row is None:
                return None
            return _row_to_drift_event_dict(row)
        finally:
            _observe(self._REPO, "get_drift_event", t0)

    async def get_drift_events_by_snapshot(
        self,
        snapshot_id: uuid.UUID,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Load drift events associated with a BDG snapshot window.

        This is an approximation: events whose created_at falls before
        or at the snapshot's created_at are considered within scope.

        Args:
            snapshot_id: UUID of the BDG snapshot.
            limit: Maximum events to return.

        Returns:
            List of drift event dicts.
        """
        t0 = time.monotonic()
        try:
            async with self._pool.acquire() as conn:
                # First resolve the snapshot's created_at boundary.
                snap_row = await conn.fetchrow(
                    "SELECT tenant_id, created_at FROM bdg_snapshots WHERE snapshot_id = $1",
                    str(snapshot_id),
                )
                if snap_row is None:
                    return []

                rows = await conn.fetch(
                    """
                    SELECT event_id, tenant_id, event_type, event_time,
                           cluster, namespace, pod_uid, container_id,
                           image_digest, tgid, pid_start_time_ns,
                           identity_confidence, binding_confidence,
                           collector_confidence, binding_status,
                           component_purl, contract_violations,
                           event_attrs, created_at
                    FROM drift_events
                    WHERE tenant_id = $1
                      AND created_at <= $2
                    ORDER BY event_time DESC
                    LIMIT $3
                    """,
                    str(snap_row["tenant_id"]),
                    snap_row["created_at"],
                    limit,
                )
            return [_row_to_drift_event_dict(row) for row in rows]
        finally:
            _observe(self._REPO, "get_drift_events_by_snapshot", t0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_drift_event_dict(row: asyncpg.Record) -> dict[str, Any]:
    """Convert an asyncpg drift_events row to a plain dict.

    Args:
        row: asyncpg.Record from the drift_events table.

    Returns:
        Dict with all drift event fields.
    """
    return {
        "event_id": str(row["event_id"]),
        "tenant_id": str(row["tenant_id"]),
        "event_type": row["event_type"],
        "event_time": row["event_time"].isoformat() if row["event_time"] else None,
        "cluster": row["cluster"],
        "namespace": row["namespace"],
        "pod_uid": row["pod_uid"],
        "container_id": row["container_id"],
        "image_digest": row["image_digest"],
        "tgid": row["tgid"],
        "pid_start_time_ns": row["pid_start_time_ns"],
        "identity_confidence": float(row["identity_confidence"] or 1.0),
        "binding_confidence": float(row["binding_confidence"] or 1.0),
        "collector_confidence": float(row["collector_confidence"] or 1.0),
        "binding_status": row["binding_status"],
        "component_purl": row["component_purl"],
        "contract_violations": json.loads(row["contract_violations"] or "[]"),
        "event_attrs": json.loads(row["event_attrs"] or "{}"),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }
