"""
causal-engine Redis Streams consumer adapter.

Consumes drift-event mutation messages from the Redis Stream
published by the api-gateway transactional outbox.
Implements at-least-once delivery with idempotency by drift_event_id.

Stream key: phantom:drift-events (one per tenant namespace in production)
Consumer group: causal-engine-bdg-updater
Consumer name: causal-engine-<hostname>

Message format (XADD fields):
    event_id            UUID of the normalized eBPF event
    event_type          Normalized event type string
    event_time_iso      UTC ISO 8601 timestamp
    tenant_id           UUID
    cluster             Kubernetes cluster name
    namespace           Kubernetes namespace
    pod_uid             Pod UID
    container_id        Container ID
    image_digest        sha256 image digest
    tgid                Thread group ID (int)
    pid_start_time_ns   Process start time (int)
    identity_confidence float
    binding_confidence  float
    collector_confidence float
    binding_status      "resolved" or other
    component_purl      Canonical PURL (may be empty)
    contract_violations JSON array of violation dicts
    event_attrs         JSON object of event attributes

Dead-letter:
    After _MAX_DELIVERY_ATTEMPTS consecutive processing failures for the
    same message ID, the message is moved to a dead-letter stream:
    phantom:dlq:graph.update
    and ACK'd from the live stream so the PEL does not grow unbounded.

Metrics:
    phantom_redis_stream_lag   Gauge: approximate number of unread messages.
"""

from __future__ import annotations

import asyncio
import json
import socket
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import redis.asyncio as aioredis
import structlog
from prometheus_client import Counter
from phantom_core.models.causal_event import CAUSAL_EVENT_STREAM, CausalEventV1
from phantom_core.metrics import REDIS_STREAM_LAG

from app.application.use_cases import UpdateBdgUseCase

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STREAM_KEY: str = CAUSAL_EVENT_STREAM
_CONSUMER_GROUP: str = "causal-engine-bdg-updater"
_BLOCK_TIMEOUT_MS: int = 5000
_BATCH_SIZE: int = 50
_ACK_BATCH_SIZE: int = 100
_MAX_DELIVERY_ATTEMPTS: int = 3
_RECLAIM_MIN_IDLE_MS: int = 30_000
_DLQ_STREAM_KEY: str = "phantom:dlq:graph.update"

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_STREAM_LAG = REDIS_STREAM_LAG

_MESSAGES_PROCESSED = Counter(
    "phantom_redis_stream_messages_total",
    "Total messages processed by the causal-engine Redis consumer",
    labelnames=["stream", "result"],  # result: success | error | dead_letter
)


# ---------------------------------------------------------------------------
# Consumer
# ---------------------------------------------------------------------------


class DriftEventRedisConsumer:
    """Redis Streams consumer for drift events.

    Reads from a Redis Stream using XREADGROUP, applies each event to
    the BDG via UpdateBdgUseCase, and acknowledges with XACK.

    At-least-once delivery: messages are acknowledged only after the
    BDG update succeeds. Idempotency is enforced by the BDG's
    idempotency index keyed on event_id.

    Dead-letter after ``_MAX_DELIVERY_ATTEMPTS``: messages that fail
    repeatedly are moved to ``phantom:dlq:graph.update`` and ACK'd
    from the live stream.

    Args:
        redis_client: An async Redis client.
        update_bdg_use_case: The BDG update use case.
        stream_key: Redis stream key to consume from.
        consumer_group: Consumer group name.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,
        update_bdg_use_case: UpdateBdgUseCase,
        stream_key: str = _STREAM_KEY,
        consumer_group: str = _CONSUMER_GROUP,
    ) -> None:
        """Initialise the consumer.

        Args:
            redis_client: Async Redis client.
            update_bdg_use_case: UpdateBdgUseCase for BDG mutation.
            stream_key: Redis stream key.
            consumer_group: Consumer group name.
        """
        self._redis = redis_client
        self._update_bdg = update_bdg_use_case
        self._stream_key = stream_key
        self._consumer_group = consumer_group
        self._consumer_name = f"causal-engine-{socket.gethostname()}"
        self._running = False
        self._pending_acks: list[str] = []
        # Track delivery attempt count per message_id for dead-lettering.
        self._delivery_attempts: dict[str, int] = {}

    async def _ensure_consumer_group(self) -> None:
        """Create the consumer group if it does not exist.

        Uses MKSTREAM to create the stream on demand.
        """
        try:
            await self._redis.xgroup_create(
                self._stream_key,
                self._consumer_group,
                id="0",
                mkstream=True,
            )
            log.info(
                "redis_consumer.group_created",
                group=self._consumer_group,
                stream=self._stream_key,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
            # Group already exists — this is expected on restart.

    async def _process_message(
        self,
        message_id: str,
        fields: dict[bytes, bytes],
    ) -> bool:
        """Process a single stream message.

        Args:
            message_id: Redis stream message ID.
            fields: Raw byte-key, byte-value dict from the stream.

        Returns:
            True if processing succeeded, False on non-fatal error.
        """
        def _f(key: str) -> str:
            value = fields.get(key.encode(), b"")
            return value.decode() if isinstance(value, bytes) else str(value)

        try:
            if _f("schema_version") != "1.0":
                raise ValueError("unsupported or missing causal event schema_version")
            event = CausalEventV1.model_validate_json(_f("event"))
            workload = event.workload
            process = event.process
            binding = event.sbom_binding.model_dump() if event.sbom_binding else {}
            evidence = event.runtime_evidence

            await self._update_bdg.execute(
                event_id=event.event_id,
                event_type=event.event_type,
                event_time=event.observed_at,
                tenant_id=str(event.tenant_id),
                cluster=event.cluster,
                namespace=str(workload["namespace"]),
                pod_uid=str(workload["pod_uid"]),
                container_id=str(workload["container_id"]),
                image_digest=str(workload["image_digest"]),
                tgid=int(process["tgid"]),
                pid_start_time_ns=int(process["start_time_ns"]),
                identity_confidence=1.0,
                binding_confidence=float(binding["confidence"])
                if binding.get("confidence") is not None else 0.0,
                collector_confidence=1.0 if evidence.get("raw_event_digest") else 0.0,
                binding_status=(
                    {"bound": "resolved", "ambiguous": "ambiguous", "unbound": "missing",
                     "insufficient_evidence": "missing"}.get(
                        str(binding.get("binding_status")), "missing"
                    )
                ),
                component_purl=binding.get("purl"),
                contract_violations=event.contract_violations,
                event_attrs={"process": process, "runtime_evidence": evidence,
                             "sbom_binding": binding, "schema_version": event.schema_version,
                             "drift_event_id": str(event.drift_event_id),
                             "outbox_id": str(event.outbox_id)},
            )

        except Exception as exc:  # noqa: BLE001
            log.error(
                "redis_consumer.process_error",
                message_id=message_id,
                error=str(exc),
            )
            _MESSAGES_PROCESSED.labels(
                stream=self._stream_key, result="error"
            ).inc()
            return False

        _MESSAGES_PROCESSED.labels(
            stream=self._stream_key, result="success"
        ).inc()
        # Clear delivery attempt counter on success.
        self._delivery_attempts.pop(message_id, None)
        return True

    async def _handle_dead_letter(
        self,
        message_id: str,
        fields: dict[bytes, bytes],
    ) -> bool:
        """Move a permanently failing message to the dead-letter stream.

        Writes the original fields plus metadata to the DLQ stream,
        then schedules an ACK so the PEL shrinks.

        Args:
            message_id: Original Redis stream message ID.
            fields: Original message fields.
        """
        try:
            dlq_fields: dict[str, str] = {
                k.decode() if isinstance(k, bytes) else k:
                v.decode() if isinstance(v, bytes) else v
                for k, v in fields.items()
            }
            dlq_fields["_original_message_id"] = message_id
            dlq_fields["_stream"] = self._stream_key
            dlq_fields["_consumer_group"] = self._consumer_group
            dlq_fields["_dead_lettered_at"] = datetime.now(tz=UTC).isoformat()

            await self._redis.xadd(_DLQ_STREAM_KEY, dlq_fields)  # type: ignore[arg-type]
            log.warning(
                "redis_consumer.dead_lettered",
                message_id=message_id,
                dlq_stream=_DLQ_STREAM_KEY,
            )
            _MESSAGES_PROCESSED.labels(
                stream=self._stream_key, result="dead_letter"
            ).inc()
            return True
        except Exception as exc:  # noqa: BLE001
            log.error(
                "redis_consumer.dead_letter_failed",
                message_id=message_id,
                error=str(exc),
            )
            _MESSAGES_PROCESSED.labels(
                stream=self._stream_key, result="dead_letter_error"
            ).inc()
            return False

    async def _flush_acks(self) -> None:
        """Flush pending XACK acknowledgements to Redis."""
        if not self._pending_acks:
            return
        try:
            requested = list(self._pending_acks)
            acknowledged = await self._redis.xack(
                self._stream_key,
                self._consumer_group,
                *self._pending_acks,
            )
            if acknowledged != len(self._pending_acks):
                log.warning("redis_consumer.ack_count_mismatch",
                          requested=len(self._pending_acks), acknowledged=acknowledged)
                still_pending: list[str] = []
                for message_id in requested:
                    pending = await self._redis.xpending_range(
                        self._stream_key, self._consumer_group,
                        min=message_id, max=message_id, count=1,
                    )
                    if pending:
                        still_pending.append(message_id)
                self._pending_acks = still_pending
            else:
                self._pending_acks.clear()
            log.debug(
                "redis_consumer.acked",
                count=acknowledged,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("redis_consumer.ack_error", error=str(exc))

    async def _update_lag_metric(self) -> None:
        """Update the stream lag Prometheus gauge.

        Uses XINFO GROUPS to read the lag for this consumer group.
        Falls back silently if the command is unavailable.
        """
        try:
            groups = await self._redis.xinfo_groups(self._stream_key)
            for group in groups:
                name = group.get("name", b"")
                if isinstance(name, bytes):
                    name = name.decode()
                if name == self._consumer_group:
                    lag = group.get("lag")
                    if lag is None:
                        continue
                    _STREAM_LAG.labels(
                        stream=self._stream_key,
                        consumer_group=self._consumer_group,
                    ).set(int(lag))
                    break
        except Exception:  # noqa: BLE001
            pass

    async def run(self) -> None:
        """Start the consumer loop.

        Runs until stop() is called. Uses XREADGROUP with blocking
        to receive messages, processes them, and ACKs in batches.
        Dead-letters messages that fail ``_MAX_DELIVERY_ATTEMPTS`` times.
        """
        await self._ensure_consumer_group()
        self._running = True

        log.info(
            "redis_consumer.started",
            stream=self._stream_key,
            group=self._consumer_group,
            consumer=self._consumer_name,
        )

        # First, reclaim any pending messages from previous crashes.
        await self._reclaim_pending()

        lag_tick = 0
        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    groupname=self._consumer_group,
                    consumername=self._consumer_name,
                    streams={self._stream_key: ">"},
                    count=_BATCH_SIZE,
                    block=_BLOCK_TIMEOUT_MS,
                )

                if not messages:
                    # No new messages; timeout is normal.
                    await self._flush_acks()
                    lag_tick += 1
                    if lag_tick % 6 == 0:  # every ~30 s, reclaim any PEL messages
                        await self._reclaim_pending()
                    if lag_tick % 12 == 0:  # every ~60 s
                        await self._update_lag_metric()
                    continue

                for _stream, message_list in messages:  # type: ignore[str-unpack]
                    for _raw_entry in message_list:  # type: ignore[union-attr]
                        entry = cast(tuple[str, dict[bytes, bytes]], _raw_entry)
                        message_id, fields = entry
                        msg_id_str = (
                            message_id.decode()
                            if isinstance(message_id, bytes)
                            else message_id
                        )

                        # Track delivery attempts for dead-lettering.
                        attempts = self._delivery_attempts.get(msg_id_str, 0) + 1
                        self._delivery_attempts[msg_id_str] = attempts

                        if attempts > _MAX_DELIVERY_ATTEMPTS:
                            # Already over threshold — dead-letter it now.
                            if await self._handle_dead_letter(msg_id_str, fields):
                                self._pending_acks.append(msg_id_str)
                                self._delivery_attempts.pop(msg_id_str, None)
                        else:
                            ok = await self._process_message(msg_id_str, fields)
                            if ok:
                                self._pending_acks.append(msg_id_str)
                            elif attempts >= _MAX_DELIVERY_ATTEMPTS:
                                # Failed on final allowed attempt → dead-letter.
                                if await self._handle_dead_letter(msg_id_str, fields):
                                    self._pending_acks.append(msg_id_str)
                                    self._delivery_attempts.pop(msg_id_str, None)

                        if len(self._pending_acks) >= _ACK_BATCH_SIZE:
                            await self._flush_acks()

                await self._flush_acks()
                lag_tick += 1
                if lag_tick % 6 == 0:
                    await self._reclaim_pending()
                await self._update_lag_metric()

            except asyncio.CancelledError:
                log.info("redis_consumer.cancelled")
                break
            except Exception as exc:  # noqa: BLE001
                log.error("redis_consumer.loop_error", error=str(exc))
                await asyncio.sleep(1.0)

        await self._flush_acks()
        log.info("redis_consumer.stopped")

    async def _reclaim_pending(self) -> None:
        """Reclaim and reprocess pending (unacked) messages from the PEL.

        XAUTOCLAIM transfers pending messages from prior consumer identities;
        XREADGROUP with "0" only returns this consumer's own entries and loses
        recovery when a pod hostname changes.
        """
        try:
            _cursor, entries, _deleted = await self._redis.xautoclaim(
                self._stream_key,
                self._consumer_group,
                self._consumer_name,
                min_idle_time=_RECLAIM_MIN_IDLE_MS,
                start_id="0-0",
                count=_BATCH_SIZE,
            )
            if not entries:
                return

            count = 0
            for raw_entry in entries:
                message_id, fields = cast(tuple[str, dict[bytes, bytes]], raw_entry)
                msg_id_str = message_id.decode() if isinstance(message_id, bytes) else message_id
                ok = await self._process_message(msg_id_str, fields)
                if ok:
                    self._pending_acks.append(msg_id_str)
                else:
                    pending = await self._redis.xpending_range(
                        self._stream_key, self._consumer_group,
                        min=msg_id_str, max=msg_id_str, count=1,
                    )
                    deliveries = int(pending[0].get("times_delivered", 1)) if pending else 1
                    if deliveries >= _MAX_DELIVERY_ATTEMPTS:
                        if await self._handle_dead_letter(msg_id_str, fields):
                            self._pending_acks.append(msg_id_str)
                    else:
                        log.warning(
                            "redis_consumer.reclaimed_message_still_pending",
                            message_id=msg_id_str,
                            deliveries=deliveries,
                        )
                count += 1

            await self._flush_acks()
            log.info("redis_consumer.reclaimed_pending", count=count)
        except Exception as exc:  # noqa: BLE001
            log.warning("redis_consumer.reclaim_error", error=str(exc))

    async def stop(self) -> None:
        """Signal the consumer loop to stop after current batch."""
        self._running = False
