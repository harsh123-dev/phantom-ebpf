"""
api-gateway command use cases.

Write-path orchestrators implementing the transactional outbox pattern
and downstream service delegation.

Architecture rules:
- Only imports from app.domain.* and the port interfaces.
- Infrastructure types (pool, redis) are injected as constructor args.
- Never imports from app.interface.*.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import redis.asyncio as aioredis
import structlog

from app.domain.exceptions import ResourceNotFoundError
from app.infrastructure.postgres_repository import (
    AttributionRepository,
    DriftEventRepository,
    IncidentRepository,
    PCEPSRepository,
)
from app.infrastructure.redis_publisher import (
    fan_out_drift_event,
    publish_attribution_job,
    publish_graph_mutation_job,
)
from app.infrastructure.service_clients import CausalEngineClient

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# IngestDriftEventCommand
# ---------------------------------------------------------------------------


class IngestDriftEventCommand:
    """Transactional outbox drift event ingestion use case.

    Implements the exact 9-step algorithm from the master context:
    1. Validate (done by FastAPI/Pydantic before command is called).
    2. Compute canonical_digest (SHA-256 of deterministic JSON).
    3. BEGIN transaction.
    4. Idempotency check — return duplicate record if already seen.
    5. INSERT event row.
    6. INSERT outbox record.
    7. COMMIT (via asyncpg transaction context manager).
    8. Publish to Redis Stream (after commit, at-least-once).
    9. Return accepted DriftEventRecord dict.

    Args:
        pool: asyncpg pool.
        redis_client: aioredis client.
    """

    def __init__(self, pool: asyncpg.Pool, redis_client: aioredis.Redis) -> None:
        """Initialise with infrastructure dependencies.

        Args:
            pool: Active asyncpg connection pool.
            redis_client: Active aioredis.Redis client.
        """
        self._repo = DriftEventRepository(pool)
        self._pool = pool
        self._redis = redis_client

    async def execute(self, request: dict[str, Any], tenant_id: uuid.UUID) -> dict[str, Any]:
        """Execute the drift event ingestion transactional outbox algorithm.

        Args:
            request: Validated DriftEventIngestRequest as a dict (model_dump).
            tenant_id: Tenant UUID from the verified JWT principal.

        Returns:
            DriftEventRecord-compatible dict.

        Raises:
            ConflictError: Not raised — duplicates are returned with status='duplicate'.
        """
        event_id: uuid.UUID = request["event_id"]

        # Step 2: Compute canonical digest (deterministic JSON serialisation).
        canonical = json.dumps(
            {k: str(v) for k, v in sorted(request.items())},
            separators=(",", ":"),
        )
        _raw_digest = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

        # Step 4 (pre-transaction fast path): idempotency check.
        existing = await self._repo.get_by_event_id(event_id, tenant_id)
        if existing:
            log.info(
                "ingest_drift_event.duplicate",
                event_id=str(event_id),
                tenant_id=str(tenant_id),
            )
            return {
                "drift_event_id": existing["drift_event_id"],
                "event_id": existing["event_id"],
                "bdg_update_id": existing["bdg_update_id"],
                "ingestion_status": "duplicate",
                "received_at": existing["received_at"],
            }

        # Generate surrogate IDs.
        drift_event_id = uuid.uuid4()
        bdg_update_id = uuid.uuid4()

        # Extract nested fields.
        proc = request["process"]
        wl = request["workload"]
        ev = request["evidence"]
        binding = request.get("sbom_binding")
        violations = [
            v if isinstance(v, dict) else v.model_dump()
            for v in request.get("violations", [])
        ]

        mutation_payload = {
            "drift_event_id": str(drift_event_id),
            "event_id": str(event_id),
            "tenant_id": str(tenant_id),
            "event_type": request["event_type"],
            "image_digest": wl.get("image_digest") if isinstance(wl, dict) else wl.image_digest,
            "observed_at": str(request["observed_at"]),
            "violations": violations,
        }

        # Normalise nested models to dicts.
        def _d(obj: Any) -> dict[str, Any]:  # noqa: ANN401
            if isinstance(obj, dict):
                return obj
            return dict(obj.model_dump())

        proc_d = _d(proc)
        wl_d = _d(wl)
        ev_d = _d(ev)

        # Steps 3–7: transactional INSERT.
        async with self._pool.acquire() as conn, conn.transaction():
            # Step 4 (in-transaction idempotency with advisory lock).
            await conn.execute(
                "SELECT pg_advisory_xact_lock($1)",
                hash(str(event_id)) & 0x7FFFFFFF,
            )
            double_check = await conn.fetchrow(
                "SELECT drift_event_id, bdg_update_id, received_at "
                "FROM drift_events WHERE event_id = $1 AND tenant_id = $2",
                event_id, tenant_id,
            )
            if double_check:
                return {
                    "drift_event_id": double_check["drift_event_id"],
                    "event_id": event_id,
                    "bdg_update_id": double_check["bdg_update_id"],
                    "ingestion_status": "duplicate",
                    "received_at": double_check["received_at"],
                }

            # Step 5: INSERT drift event.
            await self._repo.insert_drift_event(
                conn,
                drift_event_id=drift_event_id,
                event_id=event_id,
                tenant_id=tenant_id,
                observed_at=request["observed_at"],
                event_type=request["event_type"],
                node_name=request["node_name"],
                identity_status=request["identity_status"],
                tgid=proc_d["tgid"],
                pid_start_time_ns=proc_d["start_time_ns"],
                comm=proc_d["comm"],
                executable_path=proc_d["executable_path"],
                uid=proc_d["uid"],
                gid=proc_d["gid"],
                cluster_name=wl_d["cluster_name"],
                namespace=wl_d["namespace"],
                pod_name=wl_d["pod_name"],
                pod_uid=wl_d["pod_uid"],
                container_name=wl_d["container_name"],
                container_id=wl_d["container_id"],
                image_digest=wl_d["image_digest"],
                service_account=wl_d.get("service_account"),
                sbom_id=_d(binding)["sbom_id"] if binding else None,
                purl=_d(binding)["purl"] if binding else None,
                binding_confidence=_d(binding)["binding_confidence"] if binding else None,
                binding_status=_d(binding)["binding_status"] if binding else None,
                violations=violations,
                violation_count=len(violations),
                kernel_timestamp_ns=ev_d["kernel_timestamp_ns"],
                cpu=ev_d["cpu"],
                architecture=ev_d["architecture"],
                event_loss_observed=ev_d["event_loss_observed"],
                correlation_id=ev_d.get("correlation_id"),
                raw_event_digest=ev_d["raw_event_digest"],
                agent_sequence=request["agent_sequence"],
                raw_event_digest_canonical=_raw_digest,
            )

            # Step 6: INSERT outbox record.
            await self._repo.insert_outbox_record(
                conn,
                bdg_update_id=bdg_update_id,
                tenant_id=tenant_id,
                drift_event_id=drift_event_id,
                mutation_payload=mutation_payload,
            )

            # Back-fill the FK on the drift_events row.
            await self._repo.update_event_outbox_id(conn, drift_event_id, bdg_update_id)
                # Step 7: COMMIT happens on __aexit__ of conn.transaction().

        # Step 8: Publish to Redis (after durable commit, at-least-once).
        received_at = datetime.now(tz=UTC)
        try:
            redis_message_id = await publish_graph_mutation_job(
                self._redis, drift_event_id, bdg_update_id, mutation_payload
            )
            await self._repo.mark_outbox_published(bdg_update_id, redis_message_id)
            # Fan-out to WebSocket subscribers.
            await fan_out_drift_event(
                self._redis,
                tenant_id,
                {
                    "drift_event_id": str(drift_event_id),
                    "event_type": request["event_type"],
                    "namespace": wl_d["namespace"],
                    "image_digest": wl_d["image_digest"],
                    "max_severity": max(
                        (v.get("severity", "low") if isinstance(v, dict) else v.severity
                         for v in (request.get("violations") or [])),
                        key=lambda s: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0),
                        default="low",
                    ),
                    "observed_at": str(request["observed_at"]),
                },
            )
        except Exception as exc:
            # Redis is best-effort after commit. Log and continue.
            log.warning(
                "ingest_drift_event.redis_publish_failed",
                drift_event_id=str(drift_event_id),
                error=str(exc),
            )

        log.info(
            "ingest_drift_event.accepted",
            drift_event_id=str(drift_event_id),
            event_id=str(event_id),
            tenant_id=str(tenant_id),
        )

        # Step 9: Return accepted record.
        return {
            "drift_event_id": drift_event_id,
            "event_id": event_id,
            "bdg_update_id": bdg_update_id,
            "ingestion_status": "accepted",
            "received_at": received_at,
        }


# ---------------------------------------------------------------------------
# CreateIncidentCommand
# ---------------------------------------------------------------------------


class CreateIncidentCommand:
    """Create a draft incident report with evidence links and tags.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with pool.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._repo = IncidentRepository(pool)

    async def execute(
        self, request: dict[str, Any], principal_user_id: str, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Create the incident and return an IncidentReport dict.

        Args:
            request: Validated IncidentCreateRequest model_dump.
            principal_user_id: User identifier from the JWT sub claim.
            tenant_id: Tenant UUID.

        Returns:
            IncidentReport-compatible dict.
        """
        incident_id = uuid.uuid4()
        row = await self._repo.create(
            incident_id=incident_id,
            tenant_id=tenant_id,
            title=request["title"],
            summary=request["summary"],
            classification=request["classification"],
            snapshot_id=request["snapshot_id"],
            created_by=principal_user_id,
            drift_event_ids=request.get("drift_event_ids", []),
            attribution_ids=request.get("attribution_ids", []),
            score_ids=request.get("score_ids", []),
            tags=request.get("tags", []),
        )
        log.info(
            "create_incident.created",
            incident_id=str(incident_id),
            tenant_id=str(tenant_id),
        )
        return dict(row)


# ---------------------------------------------------------------------------
# UpdateIncidentCommand
# ---------------------------------------------------------------------------


class UpdateIncidentCommand:
    """Apply an analyst-approved revision to an incident report.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with pool.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._repo = IncidentRepository(pool)

    async def execute(
        self,
        incident_id: uuid.UUID,
        tenant_id: uuid.UUID,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply patch update with optimistic concurrency.

        Args:
            incident_id: UUID of the incident to update.
            tenant_id: Tenant UUID.
            request: Validated IncidentUpdateRequest model_dump.

        Returns:
            Updated IncidentReport-compatible dict.

        Raises:
            ResourceNotFoundError: If incident not found or revision mismatch.
        """
        mutable_fields = {
            k: v for k, v in {
                "title": request.get("title"),
                "summary": request.get("summary"),
                "classification": request.get("classification"),
                "status": request.get("status"),
                "resolution_notes": request.get("resolution_notes"),
            }.items() if v is not None
        }
        row = await self._repo.update_revision(
            incident_id,
            tenant_id,
            request["expected_revision"],
            mutable_fields,
        )
        if row is None:
            raise ResourceNotFoundError(
                f"Incident {incident_id} not found or revision mismatch."
            )
        return dict(row)


# ---------------------------------------------------------------------------
# ArchiveIncidentCommand
# ---------------------------------------------------------------------------


class ArchiveIncidentCommand:
    """Soft-archive an incident report.

    Args:
        pool: asyncpg pool.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Initialise with pool.

        Args:
            pool: Active asyncpg connection pool.
        """
        self._repo = IncidentRepository(pool)

    async def execute(
        self, incident_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Archive the incident (status → 'archived').

        Args:
            incident_id: UUID of the incident.
            tenant_id: Tenant UUID.

        Returns:
            IncidentArchiveResponse-compatible dict.

        Raises:
            ResourceNotFoundError: If the incident does not exist.
        """
        row = await self._repo.archive(incident_id, tenant_id)
        if row is None:
            raise ResourceNotFoundError(f"Incident {incident_id} not found.")
        return {
            "incident_id": row["incident_id"],
            "status": "archived",
            "archived_at": row["archived_at"],
            "revision": row["revision"],
        }


# ---------------------------------------------------------------------------
# SubmitAttributionCommand
# ---------------------------------------------------------------------------


class SubmitAttributionCommand:
    """Submit a causal attribution job to the causal engine.

    Args:
        pool: asyncpg pool.
        redis_client: aioredis client.
        causal_client: CausalEngineClient instance.
    """

    def __init__(
        self, pool: asyncpg.Pool, redis_client: aioredis.Redis, causal_client: CausalEngineClient
    ) -> None:
        """Initialise with infrastructure dependencies.

        Args:
            pool: Active asyncpg connection pool.
            redis_client: Active aioredis.Redis client.
            causal_client: CausalEngineClient for internal calls.
        """
        self._repo = AttributionRepository(pool)
        self._redis = redis_client
        self._causal = causal_client

    async def execute(
        self, request: dict[str, Any], tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Create the attribution job record and notify the causal engine.

        Args:
            request: Validated AttributionRequest model_dump.
            tenant_id: Tenant UUID.

        Returns:
            AttributionJobResponse-compatible dict.
        """
        attribution_id = uuid.uuid4()

        def _d(obj: Any) -> dict[str, Any]:  # noqa: ANN401
            return obj if isinstance(obj, dict) else obj.model_dump()

        row = await self._repo.create_job(
            attribution_id=attribution_id,
            tenant_id=tenant_id,
            snapshot_id=request["snapshot_id"],
            drift_event_id=request["drift_event_id"],
            treatment_spec=_d(request["treatment"]),
            outcome_spec=_d(request["outcome"]),
            covariates=[_d(c) for c in request.get("covariates", [])],
            estimator=request["estimator"],
            counterfactual_treatment_value=request["counterfactual_treatment_value"],
        )

        # Publish job notification to causal engine via Redis Stream.
        try:
            await publish_attribution_job(self._redis, attribution_id, tenant_id)
        except Exception as exc:
            log.warning(
                "submit_attribution.redis_publish_failed",
                attribution_id=str(attribution_id),
                error=str(exc),
            )

        log.info(
            "submit_attribution.queued",
            attribution_id=str(attribution_id),
            tenant_id=str(tenant_id),
        )
        return {
            "attribution_id": attribution_id,
            "status": "queued",
            "snapshot_id": request["snapshot_id"],
            "submitted_at": row["submitted_at"],
        }


# ---------------------------------------------------------------------------
# SubmitPCEPSCommand
# ---------------------------------------------------------------------------


class SubmitPCEPSCommand:
    """Submit a PCEPS scoring request to the causal engine.

    Args:
        causal_client: CausalEngineClient instance.
        pool: asyncpg pool.
    """

    def __init__(self, causal_client: CausalEngineClient, pool: asyncpg.Pool) -> None:
        """Initialise with infrastructure dependencies.

        Args:
            causal_client: CausalEngineClient for internal calls.
            pool: Active asyncpg connection pool.
        """
        self._causal = causal_client
        self._repo = PCEPSRepository(pool)

    async def execute(
        self, request: dict[str, Any], tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Forward PCEPS request to causal engine and persist the score.

        Args:
            request: Validated PcepsScoreRequest model_dump.
            tenant_id: Tenant UUID.

        Returns:
            PcepsScoreResponse-compatible dict.

        Raises:
            ServiceUnavailableError: If the causal engine is unreachable.
        """
        payload = {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in request.items()}
        payload["tenant_id"] = str(tenant_id)
        result = await self._causal.submit_pceps_score(payload)

        # Persist the score record for audit.
        score_id = uuid.UUID(result["score_id"]) if "score_id" in result else uuid.uuid4()
        try:
            await self._repo.create_score(
                score_id=score_id,
                tenant_id=tenant_id,
                drift_event_id=request["drift_event_id"],
                attribution_id=request["attribution_id"],
                model_version=request["model_version"],
                score=result.get("score", 0.0),
                severity=result.get("severity", "informational"),
                raw_probability=result.get("raw_probability", 0.0),
                calibrated_probability=result.get("calibrated_probability", 0.0),
                feature_completeness=result.get("feature_completeness", 1.0),
                imputed_features=result.get("imputed_features", []),
                feature_vector=result.get("feature_vector", []),
                feature_mask=result.get("feature_mask", []),
                allow_imputation=request.get("allow_imputation", True),
            )
        except Exception as exc:
            log.warning(
                "submit_pceps.persist_failed",
                score_id=str(score_id),
                error=str(exc),
            )

        return result
