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

    def __init__(self, pool: asyncpg.Pool, redis_client: aioredis.Redis,
                 sbom_client: Any | None = None) -> None:
        """Initialise with infrastructure dependencies.

        Args:
            pool: Active asyncpg connection pool.
            redis_client: Active aioredis.Redis client.
        """
        self._repo = DriftEventRepository(pool)
        self._pool = pool
        self._redis = redis_client
        self._sbom_client = sbom_client

    async def _publish_outbox_record(self, bdg_update_id: uuid.UUID) -> bool:
        """Publish one durable outbox item; failed attempts remain retryable."""
        record = await self._repo.get_outbox_record(bdg_update_id)
        if record is None or record["status"] == "published":
            return record is not None
        try:
            message_id = await publish_graph_mutation_job(
                self._redis,
                record["drift_event_id"],
                record["bdg_update_id"],
                record["mutation_payload"],
            )
            await self._repo.mark_outbox_published(bdg_update_id, message_id)
            return True
        except Exception as exc:  # noqa: BLE001
            try:
                await self._repo.mark_outbox_failed(bdg_update_id, str(exc))
            except Exception as db_exc:  # noqa: BLE001
                log.error("ingest_drift_event.outbox_failure_record_failed",
                          bdg_update_id=str(bdg_update_id), error=str(db_exc))
            log.warning("ingest_drift_event.redis_publish_failed",
                        bdg_update_id=str(bdg_update_id), error=str(exc))
            return False

    async def _resolve_runtime_binding(
        self, event_id: uuid.UUID, request: dict[str, Any], tenant_id: uuid.UUID
    ) -> dict[str, Any] | None:
        """Resolve one event against the SBOM service or preserve explicit unknown."""
        def as_dict(value: Any) -> dict[str, Any]:  # noqa: ANN401
            return value if isinstance(value, dict) else value.model_dump()

        process = as_dict(request["process"])
        workload = as_dict(request["workload"])
        evidence = as_dict(request["evidence"])
        digest = workload.get("image_digest")
        if not digest:
            return None
        fallback_reason = "SBOM mapping service was not available for this event"
        container_id = workload.get("container_id")
        if self._sbom_client is not None and container_id not in (None, "", "unknown"):
            try:
                observed_at = request["observed_at"]
                mapped = await self._sbom_client.map_runtime_binding({
                    "event_id": str(event_id),
                    "run_id": str(evidence.get("run_id") or ""),
                    "tenant_id": str(tenant_id),
                    "event_type": request["event_type"],
                    "observed_at": observed_at.isoformat() if isinstance(observed_at, datetime) else observed_at,
                    "container_id": container_id,
                    "image_digest": digest,
                    "pod_uid": str(workload.get("pod_uid")) if workload.get("pod_uid") else None,
                    "namespace": workload.get("namespace"),
                    "workload_name": workload.get("pod_name"),
                    "tgid": process["tgid"],
                    "pid_start_time_ns": process["start_time_ns"],
                    "executable_path": process.get("executable_path"),
                    "executable_hash": process.get("executable_hash"),
                    "comm": process.get("comm"),
                    "uid": process.get("uid"),
                    "resource_path": evidence.get("resource_path"),
                    "resource_hash": evidence.get("resource_hash"),
                })
                return {
                    "binding_status": mapped["binding_status"],
                    "image_digest": mapped["image_digest"],
                    "sbom_id": mapped.get("sbom_id"),
                    "purl": mapped.get("purl"),
                    "binding_confidence": mapped.get("confidence"),
                    "resolver_version": mapped.get("resolver_version"),
                    "mapping_method": mapped.get("method"),
                    "evidence": mapped.get("evidence", []),
                    "candidate_purls": mapped.get("candidate_purls", []),
                    "mapping_reason": mapped.get("reason"),
                }
            except Exception as exc:  # noqa: BLE001
                fallback_reason = f"SBOM mapping unavailable: {type(exc).__name__}"
                log.warning("ingest_drift_event.sbom_mapping_unavailable",
                            event_id=str(event_id), error=str(exc))
        return {
            "binding_status": "insufficient_evidence",
            "image_digest": digest,
            "sbom_id": None,
            "purl": None,
            "binding_confidence": None,
            "resolver_version": "v1",
            "mapping_method": "abstain",
            "evidence": [],
            "candidate_purls": [],
            "mapping_reason": fallback_reason,
        }

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
            outbox_id = existing.get("bdg_update_id")
            delivery_ok = (
                await self._publish_outbox_record(outbox_id)
                if outbox_id else False
            )
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
                "causal_delivery_status": "published" if delivery_ok else "pending_or_unknown",
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

        # Normalise nested models to dicts.
        def _d(obj: Any) -> dict[str, Any]:  # noqa: ANN401
            if isinstance(obj, dict):
                return obj
            return dict(obj.model_dump())

        proc_d = _d(proc)
        wl_d = _d(wl)
        ev_d = _d(ev)
        if binding is None:
            binding = await self._resolve_runtime_binding(event_id, request, tenant_id)
        binding_d = _d(binding) if binding else None
        causal_binding = None
        if binding_d:
            causal_binding = {
                "binding_status": binding_d["binding_status"],
                "image_digest": binding_d["image_digest"],
                "sbom_id": binding_d.get("sbom_id"),
                "purl": binding_d.get("purl"),
                "confidence": binding_d.get("binding_confidence")
                if binding_d.get("binding_status") == "bound" else None,
                "resolver_version": binding_d.get("resolver_version") or "",
                "method": binding_d.get("mapping_method") or "",
                "evidence": binding_d.get("evidence", []),
                "candidate_purls": binding_d.get("candidate_purls", []),
                "reason": binding_d.get("mapping_reason"),
            }
        mutation_payload = {
            "event_id": str(event_id),
            "tenant_id": str(tenant_id),
            "event_type": request["event_type"],
            "observed_at": request["observed_at"],
            "cluster": wl_d["cluster_name"],
            "workload": wl_d,
            "process": proc_d,
            "runtime_evidence": ev_d,
            "sbom_binding": causal_binding,
            "contract_violations": violations,
        }

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
                sbom_id=binding_d["sbom_id"] if binding_d and binding_d["binding_status"] == "bound" else None,
                purl=binding_d["purl"] if binding_d and binding_d["binding_status"] == "bound" else None,
                binding_confidence=binding_d["binding_confidence"] if binding_d and binding_d["binding_status"] == "bound" else None,
                binding_status=(
                    {"bound": "resolved", "ambiguous": "ambiguous", "unbound": "missing",
                     "insufficient_evidence": "missing"}[binding_d["binding_status"]]
                    if binding_d else None
                ),
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
        received_at = datetime.now(tz=UTC)  # used in fan-out payload below
        delivery_ok = await self._publish_outbox_record(bdg_update_id)
        try:
            # Fan-out to WebSocket subscribers.
            # Compute derived fields once so they can be reused below.
            _max_sev = max(
                (v.get("severity", "low") if isinstance(v, dict) else v.severity
                 for v in (request.get("violations") or [])),
                key=lambda s: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(s, 0),
                default="low",
            )
            _violation_types = [
                (v.get("violation_type", "") if isinstance(v, dict) else v.violation_type)
                for v in (request.get("violations") or [])
            ]
            await fan_out_drift_event(
                self._redis,
                tenant_id,
                {
                    # --- Fields required by the frontend isLiveDriftEvent guard ---
                    "type": "drift_event",
                    "stream_event_id": str(uuid.uuid4()),
                    "published_at": received_at.isoformat(),
                    "drift_event_id": str(drift_event_id),
                    "event_type": request["event_type"],
                    "severity": _max_sev,          # alias expected by frontend
                    "identity_status": request.get("identity_status", "resolved"),
                    "violation_types": _violation_types,
                    # --- Extra context shown in the Live Drift Feed rows ---
                    "namespace": wl_d["namespace"],
                    "pod_name": wl_d.get("pod_name", ""),
                    "container_name": wl_d.get("container_name", ""),
                    "image_digest": wl_d.get("image_digest", ""),
                    "max_severity": _max_sev,
                    "observed_at": str(request["observed_at"]),
                },
            )
        except Exception as exc:
            log.warning("ingest_drift_event.websocket_fanout_failed",
                        drift_event_id=str(drift_event_id), error=str(exc))

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
            "causal_delivery_status": "published" if delivery_ok else "pending",
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
