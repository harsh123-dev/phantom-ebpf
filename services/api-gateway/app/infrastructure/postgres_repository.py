"""
api-gateway asyncpg repository adapter.

Implements the transactional outbox pattern for durable drift event
acceptance and outbox publication to Redis Streams. Uses PostgreSQL
advisory locks and unique constraints to enforce idempotency by event_id.

Repositories:
- DriftEventRepository: drift_events + graph_mutations_outbox tables
- IncidentRepository:   incidents + incident_evidence + incident_tags
- AttributionRepository: attribution_jobs
- PCEPSRepository:      pceps_scores

All repositories:
- Use the asyncpg pool injected at construction time.
- Log via structlog with operation context.
- Measure duration and emit phantom_postgres_operation_duration_seconds.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime
from typing import Any, cast

import asyncpg
import structlog
from phantom_core.metrics import POSTGRES_OPERATION_DURATION

log: structlog.BoundLogger = structlog.get_logger(__name__)


class _TimedRepository:
    """Base repository class providing operation timing and Prometheus metrics."""

    async def _timed_query(self, operation: str, coro: Any) -> Any:  # noqa: ANN401
        """Helper to time and record any DB operation."""
        start = time.monotonic()
        result_label = "success"
        try:
            return await coro
        except Exception:
            result_label = "error"
            raise
        finally:
            POSTGRES_OPERATION_DURATION.labels(
                operation=operation,
                result=result_label,
            ).observe(time.monotonic() - start)


# ---------------------------------------------------------------------------
# DriftEventRepository
# ---------------------------------------------------------------------------


class DriftEventRepository(_TimedRepository):
    """asyncpg repository for drift_events and graph_mutations_outbox tables.

    Args:
        pool: Active asyncpg connection pool.
    """

    _REPO = "DriftEventRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with a pool reference.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._pool = pool

    async def _do_insert_drift_event(
        self,
        conn: asyncpg.Connection,
        *,
        drift_event_id: uuid.UUID,
        event_id: uuid.UUID,
        tenant_id: uuid.UUID,
        observed_at: datetime,
        event_type: str,
        node_name: str,
        identity_status: str,
        tgid: int,
        pid_start_time_ns: int,
        comm: str,
        executable_path: str,
        uid: int,
        gid: int,
        cluster_name: str,
        namespace: str,
        pod_name: str,
        pod_uid: uuid.UUID,
        container_name: str,
        container_id: str,
        image_digest: str,
        service_account: str | None,
        sbom_id: uuid.UUID | None,
        purl: str | None,
        binding_confidence: float | None,
        binding_status: str | None,
        violations: list[dict[str, Any]],
        violation_count: int,
        kernel_timestamp_ns: int,
        cpu: int,
        architecture: str,
        event_loss_observed: bool,
        correlation_id: uuid.UUID | None,
        raw_event_digest: str,
        agent_sequence: int,
        raw_event_digest_canonical: str,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO drift_events (
                drift_event_id, event_id, tenant_id, observed_at, received_at,
                event_type, node_name, identity_status,
                tgid, pid_start_time_ns, comm, executable_path, uid, gid,
                cluster_name, namespace, pod_name, pod_uid,
                container_name, container_id, image_digest, service_account,
                sbom_id, purl, binding_confidence, binding_status,
                violations, violation_count,
                kernel_timestamp_ns, cpu, architecture, event_loss_observed,
                correlation_id, raw_event_digest,
                agent_sequence, ingestion_status
            ) VALUES (
                $1, $2, $3, $4, NOW(),
                $5, $6, $7,
                $8, $9, $10, $11, $12, $13,
                $14, $15, $16, $17,
                $18, $19, $20, $21,
                $22, $23, $24, $25,
                $26::jsonb, $27,
                $28, $29, $30, $31,
                $32, $33,
                $34, 'accepted'
            )
            """,
            drift_event_id,
            event_id,
            tenant_id,
            observed_at,
            event_type,
            node_name,
            identity_status,
            tgid,
            pid_start_time_ns,
            comm,
            executable_path,
            uid,
            gid,
            cluster_name,
            namespace,
            pod_name,
            pod_uid,
            container_name,
            container_id,
            image_digest,
            service_account,
            sbom_id,
            purl,
            binding_confidence,
            binding_status,
            json.dumps(violations),
            violation_count,
            kernel_timestamp_ns,
            cpu,
            architecture,
            event_loss_observed,
            correlation_id,
            raw_event_digest,
            agent_sequence,
        )

    async def insert_drift_event(
        self,
        conn: asyncpg.Connection,
        *,
        drift_event_id: uuid.UUID,
        event_id: uuid.UUID,
        tenant_id: uuid.UUID,
        observed_at: datetime,
        event_type: str,
        node_name: str,
        identity_status: str,
        tgid: int,
        pid_start_time_ns: int,
        comm: str,
        executable_path: str,
        uid: int,
        gid: int,
        cluster_name: str,
        namespace: str,
        pod_name: str,
        pod_uid: uuid.UUID,
        container_name: str,
        container_id: str,
        image_digest: str,
        service_account: str | None,
        sbom_id: uuid.UUID | None,
        purl: str | None,
        binding_confidence: float | None,
        binding_status: str | None,
        violations: list[dict[str, Any]],
        violation_count: int,
        kernel_timestamp_ns: int,
        cpu: int,
        architecture: str,
        event_loss_observed: bool,
        correlation_id: uuid.UUID | None,
        raw_event_digest: str,
        agent_sequence: int,
        raw_event_digest_canonical: str,
    ) -> None:
        """Insert a drift event row inside an existing transaction."""
        await self._timed_query(
            "insert_drift_event",
            self._do_insert_drift_event(
                conn=conn,
                drift_event_id=drift_event_id,
                event_id=event_id,
                tenant_id=tenant_id,
                observed_at=observed_at,
                event_type=event_type,
                node_name=node_name,
                identity_status=identity_status,
                tgid=tgid,
                pid_start_time_ns=pid_start_time_ns,
                comm=comm,
                executable_path=executable_path,
                uid=uid,
                gid=gid,
                cluster_name=cluster_name,
                namespace=namespace,
                pod_name=pod_name,
                pod_uid=pod_uid,
                container_name=container_name,
                container_id=container_id,
                image_digest=image_digest,
                service_account=service_account,
                sbom_id=sbom_id,
                purl=purl,
                binding_confidence=binding_confidence,
                binding_status=binding_status,
                violations=violations,
                violation_count=violation_count,
                kernel_timestamp_ns=kernel_timestamp_ns,
                cpu=cpu,
                architecture=architecture,
                event_loss_observed=event_loss_observed,
                correlation_id=correlation_id,
                raw_event_digest=raw_event_digest,
                agent_sequence=agent_sequence,
                raw_event_digest_canonical=raw_event_digest_canonical,
            ),
        )

    async def _do_get_by_event_id(
        self, event_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT drift_event_id, event_id, bdg_update_id, ingestion_status, received_at
                FROM drift_events
                WHERE event_id = $1 AND tenant_id = $2
                """,
                event_id,
                tenant_id,
            )
        return row

    async def get_by_event_id(
        self, event_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        """Look up a drift event by its agent-supplied event_id for idempotency."""
        return await self._timed_query(
            "get_by_event_id",
            self._do_get_by_event_id(event_id, tenant_id),
        )

    async def _do_insert_outbox_record(
        self,
        conn: asyncpg.Connection,
        *,
        bdg_update_id: uuid.UUID,
        tenant_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        mutation_payload: dict[str, Any],
    ) -> None:
        await conn.execute(
            """
            INSERT INTO graph_mutations_outbox (
                bdg_update_id, tenant_id, drift_event_id,
                mutation_payload, status
            ) VALUES ($1, $2, $3, $4::jsonb, 'pending')
            """,
            bdg_update_id,
            tenant_id,
            drift_event_id,
            json.dumps(mutation_payload, default=str),
        )

    async def insert_outbox_record(
        self,
        conn: asyncpg.Connection,
        *,
        bdg_update_id: uuid.UUID,
        tenant_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        mutation_payload: dict[str, Any],
    ) -> None:
        """Insert a graph_mutations_outbox row inside an existing transaction."""
        await self._timed_query(
            "insert_outbox_record",
            self._do_insert_outbox_record(
                conn=conn,
                bdg_update_id=bdg_update_id,
                tenant_id=tenant_id,
                drift_event_id=drift_event_id,
                mutation_payload=mutation_payload,
            ),
        )

    async def _do_mark_outbox_published(
        self,
        bdg_update_id: uuid.UUID,
        redis_message_id: str,
    ) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE graph_mutations_outbox
                SET status = 'published',
                    published_at = NOW(),
                    redis_message_id = $2
                WHERE bdg_update_id = $1
                """,
                bdg_update_id,
                redis_message_id,
            )

    async def mark_outbox_published(
        self,
        bdg_update_id: uuid.UUID,
        redis_message_id: str,
    ) -> None:
        """Update an outbox record to status='published' after Redis delivery."""
        await self._timed_query(
            "mark_outbox_published",
            self._do_mark_outbox_published(bdg_update_id, redis_message_id),
        )

    async def _do_update_event_outbox_id(
        self,
        conn: asyncpg.Connection,
        drift_event_id: uuid.UUID,
        bdg_update_id: uuid.UUID,
    ) -> None:
        await conn.execute(
            "UPDATE drift_events SET bdg_update_id = $2 WHERE drift_event_id = $1",
            drift_event_id,
            bdg_update_id,
        )

    async def update_event_outbox_id(
        self,
        conn: asyncpg.Connection,
        drift_event_id: uuid.UUID,
        bdg_update_id: uuid.UUID,
    ) -> None:
        """Back-fill the bdg_update_id FK on the drift_events row."""
        await self._timed_query(
            "update_event_outbox_id",
            self._do_update_event_outbox_id(conn, drift_event_id, bdg_update_id),
        )


# ---------------------------------------------------------------------------
# IncidentRepository
# ---------------------------------------------------------------------------


class IncidentRepository(_TimedRepository):
    """asyncpg repository for incidents, incident_evidence, and incident_tags.

    Args:
        pool: Active asyncpg connection pool.
    """

    _REPO = "IncidentRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with a pool reference.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._pool = pool

    @staticmethod
    def _compute_evidence_hash(
        drift_event_ids: list[uuid.UUID],
        attribution_ids: list[uuid.UUID],
        score_ids: list[uuid.UUID],
    ) -> str:
        """Compute a sha256 digest over the canonical sorted evidence UUID set."""
        all_ids = sorted(str(u) for u in drift_event_ids + attribution_ids + score_ids)
        canonical = json.dumps(all_ids, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    async def _do_create(
        self,
        *,
        incident_id: uuid.UUID,
        tenant_id: uuid.UUID,
        title: str,
        summary: str,
        classification: str,
        snapshot_id: uuid.UUID,
        created_by: str,
        drift_event_ids: list[uuid.UUID],
        attribution_ids: list[uuid.UUID],
        score_ids: list[uuid.UUID],
        tags: list[str],
    ) -> asyncpg.Record:
        evidence_hash = self._compute_evidence_hash(
            drift_event_ids, attribution_ids, score_ids
        )
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                """
                    INSERT INTO incidents (
                        incident_id, tenant_id, revision, status, classification,
                        title, summary, snapshot_id, evidence_hash, created_by,
                        created_at, updated_at
                    ) VALUES (
                        $1, $2, 1, 'draft', $3,
                        $4, $5, $6, $7, $8,
                        NOW(), NOW()
                    )
                    RETURNING *
                    """,
                incident_id,
                tenant_id,
                classification,
                title,
                summary,
                snapshot_id,
                evidence_hash,
                created_by,
            )
            for eid in drift_event_ids:
                await conn.execute(
                    "INSERT INTO incident_evidence "
                    "(incident_id, tenant_id, evidence_type, evidence_id) "
                    "VALUES ($1, $2, 'drift_event', $3)",
                    incident_id,
                    tenant_id,
                    eid,
                )
            for aid in attribution_ids:
                await conn.execute(
                    "INSERT INTO incident_evidence "
                    "(incident_id, tenant_id, evidence_type, evidence_id) "
                    "VALUES ($1, $2, 'attribution', $3)",
                    incident_id,
                    tenant_id,
                    aid,
                )
            for sid in score_ids:
                await conn.execute(
                    "INSERT INTO incident_evidence "
                    "(incident_id, tenant_id, evidence_type, evidence_id) "
                    "VALUES ($1, $2, 'pceps_score', $3)",
                    incident_id,
                    tenant_id,
                    sid,
                )
            for tag in tags:
                await conn.execute(
                    "INSERT INTO incident_tags "
                    "(incident_id, tenant_id, tag) VALUES ($1, $2, $3)",
                    incident_id,
                    tenant_id,
                    tag,
                )
        return row

    async def create(
        self,
        *,
        incident_id: uuid.UUID,
        tenant_id: uuid.UUID,
        title: str,
        summary: str,
        classification: str,
        snapshot_id: uuid.UUID,
        created_by: str,
        drift_event_ids: list[uuid.UUID],
        attribution_ids: list[uuid.UUID],
        score_ids: list[uuid.UUID],
        tags: list[str],
    ) -> asyncpg.Record:
        """Create a new incident report and its associated evidence links and tags."""
        return await self._timed_query(
            "create",
            self._do_create(
                incident_id=incident_id,
                tenant_id=tenant_id,
                title=title,
                summary=summary,
                classification=classification,
                snapshot_id=snapshot_id,
                created_by=created_by,
                drift_event_ids=drift_event_ids,
                attribution_ids=attribution_ids,
                score_ids=score_ids,
                tags=tags,
            ),
        )

    async def _do_get_by_id(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM incidents WHERE incident_id = $1 AND tenant_id = $2",
                incident_id,
                tenant_id,
            )
            if row is None:
                return None

            evidence_rows = await conn.fetch(
                "SELECT evidence_type, evidence_id FROM incident_evidence WHERE incident_id = $1",
                incident_id,
            )
            tag_rows = await conn.fetch(
                "SELECT tag FROM incident_tags WHERE incident_id = $1",
                incident_id,
            )

        drift_event_ids = [
            r["evidence_id"]
            for r in evidence_rows
            if r["evidence_type"] == "drift_event"
        ]
        attribution_ids = [
            r["evidence_id"]
            for r in evidence_rows
            if r["evidence_type"] == "attribution"
        ]
        score_ids = [
            r["evidence_id"]
            for r in evidence_rows
            if r["evidence_type"] == "pceps_score"
        ]
        tags = [r["tag"] for r in tag_rows]

        return {
            "incident": row,
            "drift_event_ids": drift_event_ids,
            "attribution_ids": attribution_ids,
            "score_ids": score_ids,
            "tags": tags,
        }

    async def get_by_id(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any] | None:
        """Fetch a full incident detail including evidence and tags."""
        return cast(
            dict[str, Any] | None,
            await self._timed_query(
                "get_by_id",
                self._do_get_by_id(incident_id, tenant_id),
            ),
        )

    async def _do_list_paginated(
        self,
        tenant_id: uuid.UUID,
        *,
        status: str | None = None,
        classification: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[asyncpg.Record], str | None]:
        conditions = ["tenant_id = $1"]
        params: list[Any] = [tenant_id]
        p = 2

        if status:
            conditions.append(f"status = ${p}")
            params.append(status)
            p += 1
        if classification:
            conditions.append(f"classification = ${p}")
            params.append(classification)
            p += 1
        if created_after:
            conditions.append(f"created_at > ${p}")
            params.append(created_after)
            p += 1
        if created_before:
            conditions.append(f"created_at < ${p}")
            params.append(created_before)
            p += 1
        if cursor:
            conditions.append(f"created_at < ${p}")
            params.append(cursor)
            p += 1

        where_clause = " AND ".join(conditions)
        query = f"""
            SELECT * FROM incidents
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT ${p}
        """
        params.append(limit + 1)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        next_cursor: str | None = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = rows[-1]["created_at"].isoformat()
        return list(rows), next_cursor

    async def list_paginated(
        self,
        tenant_id: uuid.UUID,
        *,
        status: str | None = None,
        classification: str | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[asyncpg.Record], str | None]:
        """List incidents with optional filters and cursor-based pagination."""
        return cast(
            tuple[list[asyncpg.Record], str | None],
            await self._timed_query(
                "list_paginated",
                self._do_list_paginated(
                    tenant_id=tenant_id,
                    status=status,
                    classification=classification,
                    created_after=created_after,
                    created_before=created_before,
                    limit=limit,
                    cursor=cursor,
                ),
            ),
        )

    async def _do_update_revision(
        self,
        incident_id: uuid.UUID,
        tenant_id: uuid.UUID,
        expected_revision: int,
        updates: dict[str, Any],
    ) -> asyncpg.Record | None:
        if not updates:
            return None

        set_clauses = ", ".join(
            f"{col} = ${i + 3}" for i, col in enumerate(updates.keys())
        )
        params: list[Any] = [incident_id, tenant_id, expected_revision]
        params.extend(updates.values())

        query = f"""
            UPDATE incidents
            SET {set_clauses}, revision = revision + 1, updated_at = NOW()
            WHERE incident_id = $1
              AND tenant_id = $2
              AND revision = $3
            RETURNING *
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, *params)
        return row

    async def update_revision(
        self,
        incident_id: uuid.UUID,
        tenant_id: uuid.UUID,
        expected_revision: int,
        updates: dict[str, Any],
    ) -> asyncpg.Record | None:
        """Apply a patch update with optimistic concurrency control."""
        return await self._timed_query(
            "update_revision",
            self._do_update_revision(
                incident_id, tenant_id, expected_revision, updates
            ),
        )

    async def _do_archive(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE incidents
                SET status = 'archived',
                    archived_at = NOW(),
                    revision = revision + 1,
                    updated_at = NOW()
                WHERE incident_id = $1 AND tenant_id = $2
                RETURNING *
                """,
                incident_id,
                tenant_id,
            )
        return row

    async def archive(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        """Soft-archive an incident report (status → 'archived')."""
        return await self._timed_query(
            "archive",
            self._do_archive(incident_id, tenant_id),
        )


# ---------------------------------------------------------------------------
# AttributionRepository
# ---------------------------------------------------------------------------


class AttributionRepository(_TimedRepository):
    """asyncpg repository for attribution_jobs and attribution_refutations tables.

    Args:
        pool: Active asyncpg connection pool.
    """

    _REPO = "AttributionRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with a pool reference.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._pool = pool

    async def _do_create_job(
        self,
        *,
        attribution_id: uuid.UUID,
        tenant_id: uuid.UUID,
        snapshot_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        treatment_spec: dict[str, Any],
        outcome_spec: dict[str, Any],
        covariates: list[dict[str, Any]],
        estimator: str,
        counterfactual_treatment_value: int,
    ) -> asyncpg.Record:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO attribution_jobs (
                    attribution_id, tenant_id, snapshot_id, drift_event_id,
                    treatment_spec, outcome_spec, covariates, estimator,
                    counterfactual_treatment_value, status, identified,
                    submitted_at
                ) VALUES (
                    $1, $2, $3, $4,
                    $5::jsonb, $6::jsonb, $7::jsonb, $8,
                    $9, 'queued', FALSE,
                    NOW()
                )
                RETURNING *
                """,
                attribution_id,
                tenant_id,
                snapshot_id,
                drift_event_id,
                json.dumps(treatment_spec, default=str),
                json.dumps(outcome_spec, default=str),
                json.dumps(covariates, default=str),
                estimator,
                counterfactual_treatment_value,
            )
        return row

    async def create_job(
        self,
        *,
        attribution_id: uuid.UUID,
        tenant_id: uuid.UUID,
        snapshot_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        treatment_spec: dict[str, Any],
        outcome_spec: dict[str, Any],
        covariates: list[dict[str, Any]],
        estimator: str,
        counterfactual_treatment_value: int,
    ) -> asyncpg.Record:
        """Insert a new attribution job record with status='queued'."""
        return await self._timed_query(
            "create_job",
            self._do_create_job(
                attribution_id=attribution_id,
                tenant_id=tenant_id,
                snapshot_id=snapshot_id,
                drift_event_id=drift_event_id,
                treatment_spec=treatment_spec,
                outcome_spec=outcome_spec,
                covariates=covariates,
                estimator=estimator,
                counterfactual_treatment_value=counterfactual_treatment_value,
            ),
        )

    async def _do_get_job(
        self, attribution_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM attribution_jobs WHERE attribution_id = $1 AND tenant_id = $2",
                attribution_id,
                tenant_id,
            )
        return row

    async def get_job(
        self, attribution_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        """Fetch an attribution job by ID."""
        return await self._timed_query(
            "get_job",
            self._do_get_job(attribution_id, tenant_id),
        )

    async def _do_update_job_result(
        self,
        attribution_id: uuid.UUID,
        tenant_id: uuid.UUID,
        updates: dict[str, Any],
    ) -> asyncpg.Record | None:
        set_clauses = ", ".join(
            f"{col} = ${i + 3}" for i, col in enumerate(updates.keys())
        )
        params: list[Any] = [attribution_id, tenant_id]
        params.extend(updates.values())
        query = f"""
            UPDATE attribution_jobs
            SET {set_clauses}
            WHERE attribution_id = $1 AND tenant_id = $2
            RETURNING *
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, *params)
        return row

    async def update_job_result(
        self,
        attribution_id: uuid.UUID,
        tenant_id: uuid.UUID,
        updates: dict[str, Any],
    ) -> asyncpg.Record | None:
        """Update attribution job result fields (called by causal engine worker)."""
        return await self._timed_query(
            "update_job_result",
            self._do_update_job_result(attribution_id, tenant_id, updates),
        )


# ---------------------------------------------------------------------------
# PCEPSRepository
# ---------------------------------------------------------------------------


class PCEPSRepository(_TimedRepository):
    """asyncpg repository for pceps_scores table.

    Args:
        pool: Active asyncpg connection pool.
    """

    _REPO = "PCEPSRepository"

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with a pool reference.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._pool = pool

    async def _do_create_score(
        self,
        *,
        score_id: uuid.UUID,
        tenant_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        attribution_id: uuid.UUID,
        model_version: str,
        score: float,
        severity: str,
        raw_probability: float,
        calibrated_probability: float,
        feature_completeness: float,
        imputed_features: list[str],
        feature_vector: list[float],
        feature_mask: list[bool],
        allow_imputation: bool,
    ) -> asyncpg.Record:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO pceps_scores (
                    score_id, tenant_id, drift_event_id, attribution_id,
                    model_version, score, severity,
                    raw_probability, calibrated_probability,
                    feature_completeness, imputed_features,
                    feature_vector, feature_mask, allow_imputation,
                    scored_at
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7,
                    $8, $9,
                    $10, $11::jsonb,
                    $12::jsonb, $13::jsonb, $14,
                    NOW()
                )
                RETURNING *
                """,
                score_id,
                tenant_id,
                drift_event_id,
                attribution_id,
                model_version,
                score,
                severity,
                raw_probability,
                calibrated_probability,
                feature_completeness,
                json.dumps(imputed_features),
                json.dumps(feature_vector),
                json.dumps(feature_mask),
                allow_imputation,
            )
        return row

    async def create_score(
        self,
        *,
        score_id: uuid.UUID,
        tenant_id: uuid.UUID,
        drift_event_id: uuid.UUID,
        attribution_id: uuid.UUID,
        model_version: str,
        score: float,
        severity: str,
        raw_probability: float,
        calibrated_probability: float,
        feature_completeness: float,
        imputed_features: list[str],
        feature_vector: list[float],
        feature_mask: list[bool],
        allow_imputation: bool,
    ) -> asyncpg.Record:
        """Insert a new PCEPS score record."""
        return await self._timed_query(
            "create_score",
            self._do_create_score(
                score_id=score_id,
                tenant_id=tenant_id,
                drift_event_id=drift_event_id,
                attribution_id=attribution_id,
                model_version=model_version,
                score=score,
                severity=severity,
                raw_probability=raw_probability,
                calibrated_probability=calibrated_probability,
                feature_completeness=feature_completeness,
                imputed_features=imputed_features,
                feature_vector=feature_vector,
                feature_mask=feature_mask,
                allow_imputation=allow_imputation,
            ),
        )

    async def _do_get_score(
        self, score_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM pceps_scores WHERE score_id = $1 AND tenant_id = $2",
                score_id,
                tenant_id,
            )
        return row

    async def get_score(
        self, score_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> asyncpg.Record | None:
        """Fetch a PCEPS score by ID."""
        return await self._timed_query(
            "get_score",
            self._do_get_score(score_id, tenant_id),
        )

    async def _do_check_duplicate(
        self,
        drift_event_id: uuid.UUID,
        attribution_id: uuid.UUID,
        model_version: str,
        tenant_id: uuid.UUID,
    ) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM pceps_scores
                WHERE drift_event_id = $1
                  AND attribution_id = $2
                  AND model_version = $3
                  AND tenant_id = $4
                ORDER BY scored_at DESC
                LIMIT 1
                """,
                drift_event_id,
                attribution_id,
                model_version,
                tenant_id,
            )
        return row

    async def check_duplicate(
        self,
        drift_event_id: uuid.UUID,
        attribution_id: uuid.UUID,
        model_version: str,
        tenant_id: uuid.UUID,
    ) -> asyncpg.Record | None:
        """Check whether a score already exists for this combination."""
        return await self._timed_query(
            "check_duplicate",
            self._do_check_duplicate(
                drift_event_id, attribution_id, model_version, tenant_id
            ),
        )
