from __future__ import annotations

import json
import importlib.util
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import fakeredis.aioredis
import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "libs/phantom-core"))
publisher_path = ROOT / "services/api-gateway/app/infrastructure/redis_publisher.py"
publisher_spec = importlib.util.spec_from_file_location("phantom_api_redis_publisher", publisher_path)
publisher_module = importlib.util.module_from_spec(publisher_spec)
assert publisher_spec and publisher_spec.loader
publisher_spec.loader.exec_module(publisher_module)

from app.infrastructure.redis_consumer import DriftEventRedisConsumer  # noqa: E402
import app.infrastructure.redis_consumer as redis_consumer_module  # noqa: E402
from app.application.use_cases import UpdateBdgUseCase  # noqa: E402
from app.domain.bdg import BehavioralDependencyGraph  # noqa: E402
from phantom_core.models.causal_event import CAUSAL_EVENT_STREAM  # noqa: E402
from phantom_core.models.causal_event import CausalEventV1  # noqa: E402

publish_graph_mutation_job = publisher_module.publish_graph_mutation_job


class SnapshotRepository:
    async def save_snapshot(self, *_args, **_kwargs):
        raise AssertionError("unexpected snapshot during one-event test")


@pytest.mark.asyncio
async def test_publisher_event_is_validated_processed_and_acked():
    redis = fakeredis.aioredis.FakeRedis()
    graph = BehavioralDependencyGraph(batch_size=100)
    use_case = UpdateBdgUseCase(graph, SnapshotRepository())
    consumer = DriftEventRedisConsumer(redis, use_case)
    await consumer._ensure_consumer_group()
    event_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    payload = {
        "event_id": str(event_id), "tenant_id": str(tenant_id),
        "observed_at": now.isoformat(), "event_type": "exec",
        "cluster": "phantom-k3s-lab",
        "workload": {"namespace": "phantom-eval", "pod_uid": str(uuid.uuid4()),
                     "container_id": "containerd://abc", "image_digest": "sha256:" + "a"*64},
        "process": {"tgid": 42, "start_time_ns": 100},
        "runtime_evidence": {"raw_event_digest": "sha256:" + "b"*64},
        "contract_violations": [],
    }
    drift_id, outbox_id = uuid.uuid4(), uuid.uuid4()
    await publish_graph_mutation_job(redis, drift_id, outbox_id, payload)
    batch = await redis.xreadgroup(consumer._consumer_group, "test", {CAUSAL_EVENT_STREAM: ">"})
    message_id, fields = batch[0][1][0]
    assert await consumer._process_message(message_id.decode(), fields)
    workload_key = (str(tenant_id), "phantom-k3s-lab", "phantom-eval", payload["workload"]["pod_uid"])
    assert graph.graph.has_node(workload_key)
    assert graph.graph.nodes[workload_key]["node_type"] == "workload"
    assert not any(data.get("node_type") == "purl" for _, data in graph.graph.nodes(data=True))
    assert not any(data.get("node_type") in {"contract", "drift_event"}
                   for _, data in graph.graph.nodes(data=True))
    created_nodes = graph.graph.number_of_nodes()

    # At-least-once replay is idempotent by event UUID: it cannot inflate the graph.
    await publish_graph_mutation_job(redis, drift_id, outbox_id, payload)
    replay_batch = await redis.xreadgroup(consumer._consumer_group, "test", {CAUSAL_EVENT_STREAM: ">"})
    replay_id, replay_fields = replay_batch[0][1][0]
    assert await consumer._process_message(replay_id.decode(), replay_fields)
    assert graph.graph.number_of_nodes() == created_nodes
    assert graph.graph.nodes[workload_key]["observation_count"] == 1
    assert await redis.xack(CAUSAL_EVENT_STREAM, consumer._consumer_group, replay_id) == 1
    assert await redis.xack(CAUSAL_EVENT_STREAM, consumer._consumer_group, message_id) == 1
    pending = await redis.xpending(CAUSAL_EVENT_STREAM, consumer._consumer_group)
    assert pending["pending"] == 0


@pytest.mark.asyncio
async def test_malformed_schema_is_not_processed_or_acknowledged():
    redis = fakeredis.aioredis.FakeRedis()
    graph = BehavioralDependencyGraph(batch_size=100)
    consumer = DriftEventRedisConsumer(redis, UpdateBdgUseCase(graph, SnapshotRepository()))
    await consumer._ensure_consumer_group()
    message_id = await redis.xadd(CAUSAL_EVENT_STREAM, {"schema_version": "99", "event": "{}"})
    batch = await redis.xreadgroup(consumer._consumer_group, "test", {CAUSAL_EVENT_STREAM: ">"})
    _, fields = batch[0][1][0]
    assert not await consumer._process_message(message_id.decode(), fields)
    assert graph.graph.number_of_nodes() == 0
    assert (await redis.xpending(CAUSAL_EVENT_STREAM, consumer._consumer_group))["pending"] == 1


@pytest.mark.asyncio
async def test_consumer_failure_remains_pending_and_new_consumer_recovers(monkeypatch):
    monkeypatch.setattr(redis_consumer_module, "_RECLAIM_MIN_IDLE_MS", 0)
    redis = fakeredis.aioredis.FakeRedis()
    await redis.xgroup_create(CAUSAL_EVENT_STREAM, "recovery-group", id="0", mkstream=True)
    event = {
        "event_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
        "observed_at": datetime.now(UTC).isoformat(), "event_type": "exec",
        "cluster": "phantom-k3s-lab",
        "workload": {"namespace": "phantom-eval", "pod_uid": str(uuid.uuid4()),
                     "container_id": "containerd://abc", "image_digest": "sha256:" + "c" * 64},
        "process": {"tgid": 8, "start_time_ns": 11},
        "runtime_evidence": {"raw_event_digest": "sha256:" + "d" * 64},
        "contract_violations": [],
    }
    await publish_graph_mutation_job(redis, uuid.uuid4(), uuid.uuid4(), event)
    received = await redis.xreadgroup("recovery-group", "old-worker", {CAUSAL_EVENT_STREAM: ">"})
    message_id, fields = received[0][1][0]

    class FlakyUseCase:
        async def execute(self, **_kwargs):
            raise RuntimeError("temporary graph store failure")

    failed_consumer = DriftEventRedisConsumer(redis, FlakyUseCase(), consumer_group="recovery-group")
    assert not await failed_consumer._process_message(message_id.decode(), fields)
    assert (await redis.xpending(CAUSAL_EVENT_STREAM, "recovery-group"))["pending"] == 1

    graph = BehavioralDependencyGraph(batch_size=100)
    recovered_consumer = DriftEventRedisConsumer(
        redis, UpdateBdgUseCase(graph, SnapshotRepository()), consumer_group="recovery-group"
    )
    await recovered_consumer._reclaim_pending()
    await recovered_consumer._flush_acks()
    assert graph.graph.number_of_nodes() > 0
    assert (await redis.xpending(CAUSAL_EVENT_STREAM, "recovery-group"))["pending"] == 0


def test_shared_schema_rejects_component_binding_without_provenance_or_matching_digest():
    base = {
        "event_id": str(uuid.uuid4()), "drift_event_id": str(uuid.uuid4()),
        "outbox_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
        "observed_at": datetime.now(UTC).isoformat(), "event_type": "exec",
        "cluster": "phantom-k3s-lab",
        "workload": {"namespace": "phantom-eval", "pod_uid": str(uuid.uuid4()),
                     "container_id": "containerd://abc", "image_digest": "sha256:" + "e" * 64},
        "process": {"tgid": 9, "start_time_ns": 12},
        "runtime_evidence": {"raw_event_digest": "sha256:" + "f" * 64},
        "contract_violations": [],
    }
    no_provenance = {
        "binding_status": "bound", "image_digest": base["workload"]["image_digest"],
        "sbom_id": str(uuid.uuid4()), "purl": "pkg:pypi/example@1.0",
        "confidence": 0.9, "resolver_version": "v1", "method": "path",
        "evidence": [],
    }
    with pytest.raises(ValidationError, match="evidence"):
        CausalEventV1.model_validate({**base, "sbom_binding": no_provenance})

    with pytest.raises(ValidationError, match="does not match"):
        CausalEventV1.model_validate({
            **base,
            "sbom_binding": {**no_provenance, "evidence": [{"kind": "hash"}],
                             "image_digest": "sha256:" + "0" * 64},
        })

    unbound = CausalEventV1.model_validate({
        **base,
        "sbom_binding": {
            "binding_status": "unbound", "image_digest": base["workload"]["image_digest"],
            "confidence": None, "resolver_version": "v1", "method": "image digest lookup",
            "evidence": [], "candidate_purls": [], "reason": "No SBOM registered for this digest",
        },
    })
    assert unbound.sbom_binding is not None
    assert unbound.sbom_binding.purl is None
    assert unbound.sbom_binding.confidence is None


@pytest.mark.asyncio
async def test_provenance_backed_binding_creates_component_node():
    redis = fakeredis.aioredis.FakeRedis()
    graph = BehavioralDependencyGraph(batch_size=100)
    consumer = DriftEventRedisConsumer(redis, UpdateBdgUseCase(graph, SnapshotRepository()))
    await consumer._ensure_consumer_group()
    tenant_id, event_id, drift_id, outbox_id = (uuid.uuid4() for _ in range(4))
    digest = "sha256:" + "7" * 64
    purl = "pkg:pypi/example@1.2.3"
    event = {
        "event_id": str(event_id), "tenant_id": str(tenant_id),
        "observed_at": datetime.now(UTC).isoformat(), "event_type": "exec",
        "cluster": "phantom-k3s-lab",
        "workload": {"namespace": "phantom-eval", "pod_uid": str(uuid.uuid4()),
                     "container_id": "containerd://mapped", "image_digest": digest},
        "process": {"tgid": 17, "start_time_ns": 21},
        "runtime_evidence": {"raw_event_digest": "sha256:" + "8" * 64},
        "sbom_binding": {
            "binding_status": "bound", "image_digest": digest,
            "sbom_id": str(uuid.uuid4()), "purl": purl,
            "confidence": 0.7, "resolver_version": "v1",
            "method": "executable_path match (inferred)",
            "evidence": [{"kind": "executable_path", "value": "/opt/example/bin/tool",
                          "description": "exact SBOM occurrence path", "confidence_contribution": 0.7}],
        },
        "contract_violations": [],
    }
    await publish_graph_mutation_job(redis, drift_id, outbox_id, event)
    received = await redis.xreadgroup(consumer._consumer_group, "mapping-worker", {CAUSAL_EVENT_STREAM: ">"})
    message_id, fields = received[0][1][0]
    assert await consumer._process_message(message_id.decode(), fields)
    assert any(key[1] == purl and data.get("node_type") == "purl"
               for key, data in graph.graph.nodes(data=True))
    assert await redis.xack(CAUSAL_EVENT_STREAM, consumer._consumer_group, message_id) == 1

