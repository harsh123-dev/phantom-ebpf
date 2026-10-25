from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "libs/phantom-core"))

from app.application.commands import IngestDriftEventCommand  # noqa: E402


class OutboxRepo:
    def __init__(self):
        self.record = {
            "status": "failed", "drift_event_id": uuid.uuid4(),
            "bdg_update_id": uuid.uuid4(), "mutation_payload": {
                "event_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
                "event_type": "exec", "observed_at": datetime.now(UTC).isoformat(),
                "cluster": "phantom-k3s-lab",
                "workload": {"namespace": "phantom-eval", "pod_uid": str(uuid.uuid4()),
                             "container_id": "containerd://abc", "image_digest": "sha256:" + "a" * 64},
                "process": {"tgid": 5, "start_time_ns": 10},
                "runtime_evidence": {"raw_event_digest": "sha256:" + "b" * 64},
                "contract_violations": [],
            },
        }

    async def get_outbox_record(self, _outbox_id):
        return self.record

    async def mark_outbox_failed(self, _outbox_id, _error):
        self.record["status"] = "failed"

    async def mark_outbox_published(self, _outbox_id, _message_id):
        self.record["status"] = "published"


@pytest.mark.asyncio
async def test_failed_outbox_delivery_is_retriable_and_status_is_persisted():
    redis = fakeredis.aioredis.FakeRedis()
    command = IngestDriftEventCommand(None, redis)
    command._repo = OutboxRepo()
    redis.xadd = AsyncMock(side_effect=ConnectionError("redis unavailable"))

    outbox_id = command._repo.record["bdg_update_id"]
    assert not await command._publish_outbox_record(outbox_id)
    assert command._repo.record["status"] == "failed"

    command._redis = fakeredis.aioredis.FakeRedis()
    assert await command._publish_outbox_record(outbox_id)
    assert command._repo.record["status"] == "published"


@pytest.mark.asyncio
async def test_ingestion_mapping_handoff_keeps_service_provenance():
    class MappingClient:
        async def map_runtime_binding(self, payload):
            assert payload["event_id"] == str(event_id)
            assert payload["image_digest"] == "sha256:" + "a" * 64
            return {
                "binding_status": "bound", "image_digest": payload["image_digest"],
                "sbom_id": str(uuid.uuid4()), "purl": "pkg:pypi/example@1.0",
                "confidence": 1.0, "resolver_version": "v1",
                "method": "Exact executable_hash match", "evidence": [{"kind": "executable_hash"}],
                "candidate_purls": [], "reason": None,
            }

    event_id = uuid.uuid4()
    request = {
        "event_type": "exec", "observed_at": datetime.now(UTC),
        "process": {"tgid": 7, "start_time_ns": 9, "executable_path": "/bin/example",
                    "comm": "example", "uid": 1000},
        "workload": {"image_digest": "sha256:" + "a" * 64,
                     "container_id": "containerd://abc", "pod_uid": uuid.uuid4(),
                     "namespace": "phantom-eval", "pod_name": "worker"},
        "evidence": {},
    }
    command = IngestDriftEventCommand(None, None, sbom_client=MappingClient())
    result = await command._resolve_runtime_binding(event_id, request, uuid.uuid4())
    assert result["binding_status"] == "bound"
    assert result["purl"] == "pkg:pypi/example@1.0"
    assert result["binding_confidence"] == 1.0


@pytest.mark.asyncio
async def test_missing_sbom_client_is_explicit_unknown_not_negative():
    request = {
        "process": {"tgid": 7, "start_time_ns": 9},
        "workload": {"image_digest": "sha256:" + "a" * 64,
                     "container_id": "containerd://abc"},
        "evidence": {},
    }
    command = IngestDriftEventCommand(None, None)
    result = await command._resolve_runtime_binding(uuid.uuid4(), request, uuid.uuid4())
    assert result["binding_status"] == "insufficient_evidence"
    assert result["purl"] is None
    assert result["binding_confidence"] is None
