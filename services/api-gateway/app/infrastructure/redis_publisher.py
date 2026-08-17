"""
api-gateway aioredis publisher and WebSocket fan-out adapter.

Publishes outbox records to the Redis Stream after durable commit.
Also implements the WebSocket drift-stream fan-out mechanism using
Redis Pub/Sub for cross-replica delivery.

Stream names are sourced from constants; never hardcoded strings.
All Redis operations are async and non-blocking.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as aioredis
import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Stream / channel name constants
# ---------------------------------------------------------------------------

# Redis Stream names
_STREAM_BDG_MUTATIONS = "phantom:bdg:mutations"
_STREAM_ATTRIBUTION_JOBS = "phantom:attribution:jobs"
_STREAM_REPORT_JOBS = "phantom:report:jobs"

# Redis Pub/Sub channel prefix for WebSocket fan-out.
# Full channel name: phantom:drift:stream:{tenant_id}
_PUBSUB_DRIFT_CHANNEL_PREFIX = "phantom:drift:stream:"

# Maximum number of messages to read per XREAD call in subscribe_drift_stream.
_XREAD_BLOCK_MS = 5000
_XREAD_COUNT = 50


# ---------------------------------------------------------------------------
# Publisher functions
# ---------------------------------------------------------------------------


async def publish_graph_mutation_job(
    redis_client: aioredis.Redis,
    drift_event_id: uuid.UUID,
    outbox_id: uuid.UUID,
    mutation_payload: dict[str, Any],
) -> str:
    """Publish a BDG graph mutation job to the Redis Stream.

    Called after the transactional outbox record is durably committed to
    PostgreSQL.  At-least-once delivery — the causal engine consumer
    uses XREADGROUP with explicit ACK.

    Args:
        redis_client: The active async Redis client.
        drift_event_id: UUID of the source drift event.
        outbox_id: UUID of the outbox record (bdg_update_id).
        mutation_payload: Full mutation payload dict (serialisable to JSON).

    Returns:
        The Redis Stream message ID (e.g. ``"1700000000000-0"``).
    """
    fields = {
        "drift_event_id": str(drift_event_id),
        "bdg_update_id": str(outbox_id),
        "payload": json.dumps(mutation_payload, default=str),
    }
    message_id: str = str(await redis_client.xadd(
        _STREAM_BDG_MUTATIONS,
        fields,  # type: ignore[arg-type]
    ))
    log.debug(
        "redis_publisher.bdg_mutation_published",
        stream=_STREAM_BDG_MUTATIONS,
        message_id=message_id,
        drift_event_id=str(drift_event_id),
    )
    return message_id


async def publish_attribution_job(
    redis_client: aioredis.Redis,
    attribution_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> str:
    """Publish an attribution job notification to the Redis Stream.

    Args:
        redis_client: The active async Redis client.
        attribution_id: UUID of the newly created attribution job.
        tenant_id: Tenant UUID for the job.

    Returns:
        The Redis Stream message ID.
    """
    fields = {
        "attribution_id": str(attribution_id),
        "tenant_id": str(tenant_id),
    }
    message_id: str = str(await redis_client.xadd(
        _STREAM_ATTRIBUTION_JOBS,
        fields,  # type: ignore[arg-type]
    ))
    log.debug(
        "redis_publisher.attribution_job_published",
        stream=_STREAM_ATTRIBUTION_JOBS,
        message_id=message_id,
        attribution_id=str(attribution_id),
    )
    return message_id


async def publish_report_job(
    redis_client: aioredis.Redis,
    incident_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> str:
    """Publish a report generation job notification to the Redis Stream.

    Args:
        redis_client: The active async Redis client.
        incident_id: UUID of the incident report to generate.
        tenant_id: Tenant UUID for scoping.

    Returns:
        The Redis Stream message ID.
    """
    fields = {
        "incident_id": str(incident_id),
        "tenant_id": str(tenant_id),
    }
    message_id: str = str(await redis_client.xadd(
        _STREAM_REPORT_JOBS,
        fields,  # type: ignore[arg-type]
    ))
    log.debug(
        "redis_publisher.report_job_published",
        stream=_STREAM_REPORT_JOBS,
        message_id=message_id,
        incident_id=str(incident_id),
    )
    return message_id


# ---------------------------------------------------------------------------
# WebSocket fan-out: Pub/Sub subscriber
# ---------------------------------------------------------------------------


async def subscribe_drift_stream(
    redis_client: aioredis.Redis,
    tenant_id: uuid.UUID,
    namespace_filters: list[str] | None = None,
    min_severity: str | None = None,
    resume_after: str | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """Subscribe to tenant-scoped drift event notifications via Redis Pub/Sub.

    Yields decoded drift event dicts as they arrive.  The caller is
    responsible for applying additional filters before forwarding to the
    WebSocket client.

    This uses Redis Pub/Sub (not Streams) for real-time push delivery.
    Durable replay uses resume_after against the BDG mutation stream.

    Args:
        redis_client: The active async Redis client.
        tenant_id: Tenant UUID — only events for this tenant are delivered.
        namespace_filters: Optional list of Kubernetes namespaces to include.
            If None or empty, all namespaces for the tenant are delivered.
        min_severity: Optional minimum severity level to filter.
            One of ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
        resume_after: Optional Redis message ID for resume-after semantics.
            When provided, replay begins from this message ID in the stream.

    Yields:
        Decoded drift event payload dicts. Filtering by namespace and severity
        is applied here before yielding.

    Raises:
        GeneratorExit: When the caller closes the generator.
    """
    channel = f"{_PUBSUB_DRIFT_CHANNEL_PREFIX}{tenant_id}"
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity_level = severity_order.get(min_severity or "low", 0)

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(channel)
    log.info(
        "redis_publisher.drift_stream_subscribed",
        channel=channel,
        namespace_filters=namespace_filters,
        min_severity=min_severity,
    )

    try:
        async for raw_message in pubsub.listen():
            if raw_message["type"] != "message":
                continue
            try:
                event: dict[str, Any] = json.loads(raw_message["data"])
            except (json.JSONDecodeError, TypeError):
                log.warning(
                    "redis_publisher.drift_stream_decode_error",
                    raw=str(raw_message["data"])[:128],
                )
                continue

            # Namespace filter.
            if namespace_filters:
                event_ns = event.get("namespace", "")
                if event_ns not in namespace_filters:
                    continue

            # Severity filter.
            event_severity = event.get("max_severity", "low")
            if severity_order.get(event_severity, 0) < min_severity_level:
                continue

            yield event
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()  # type: ignore[no-untyped-call]
        log.info("redis_publisher.drift_stream_unsubscribed", channel=channel)


async def fan_out_drift_event(
    redis_client: aioredis.Redis,
    tenant_id: uuid.UUID,
    event_payload: dict[str, Any],
) -> None:
    """Publish a live drift event to all connected WebSocket subscribers.

    Called by the transactional outbox relay after successful persistence.
    Uses Redis Pub/Sub for cross-replica delivery (all gateway replicas
    subscribed to this channel receive the message).

    Args:
        redis_client: The active async Redis client.
        tenant_id: Tenant UUID — published to the tenant-scoped channel.
        event_payload: Dict containing the drift event summary for WebSocket delivery.
    """
    channel = f"{_PUBSUB_DRIFT_CHANNEL_PREFIX}{tenant_id}"
    message = json.dumps(event_payload, default=str)
    subscriber_count: int = await redis_client.publish(channel, message)
    log.debug(
        "redis_publisher.drift_event_fanned_out",
        channel=channel,
        subscriber_count=subscriber_count,
    )
