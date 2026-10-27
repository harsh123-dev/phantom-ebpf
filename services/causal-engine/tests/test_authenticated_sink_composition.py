"""Composed local integration: gateway publisher, real consumer, oracle HTTP sink.

Redis is replaced with fakeredis. The Kubernetes agent, gateway database, and
live SBOM service are not under test; this test validates the canonical event
contract, actual causal consumer, explicit abstention on missing provenance,
and the deployed sink's HTTP/storage interface using test trust keys.
"""
from __future__ import annotations

import importlib.util
import asyncio
import base64
import json
import shutil
import socket
import subprocess
import sys
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import fakeredis.aioredis
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "libs/phantom-core"))
sys.path.insert(0, str(ROOT / "services/causal-engine"))
# research.evaluation lives at ROOT/research/evaluation and is not installed as a
# package; add the repo root to sys.path so `research.evaluation` is importable.
sys.path.insert(0, str(ROOT))

publisher_path = ROOT / "services/api-gateway/app/infrastructure/redis_publisher.py"
spec = importlib.util.spec_from_file_location("authenticated_test_publisher", publisher_path)
publisher = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(publisher)
from app.application.use_cases import UpdateBdgUseCase  # noqa: E402
from app.domain.bdg import BehavioralDependencyGraph  # noqa: E402
from app.infrastructure.redis_consumer import DriftEventRedisConsumer  # noqa: E402
from phantom_core.models.causal_event import CAUSAL_EVENT_STREAM  # noqa: E402
from research.evaluation.evidence_sink_service import create_app  # noqa: E402
from research.evaluation.oracle import (  # noqa: E402
    TrustedOracleKey, canonical_payload_bytes,
)
from research.evaluation.scenario_observer import (  # noqa: E402
    HarnessAssertion, ScenarioOracleObserver, load_scenario_policies,
)
from research.evaluation.evidence_s3 import S3EvidenceBackupClient  # noqa: E402
from research.evaluation.evidence_store import DurableEvidenceSink  # noqa: E402
from research.evaluation.tests.test_evidence_s3 import MemoryS3  # noqa: E402


class NoSnapshot:
    async def save_snapshot(self, *_args, **_kwargs):
        raise AssertionError("unexpected snapshot")


@pytest_asyncio.fixture(params=["fakeredis", "local-redis"])
async def redis_client(request, tmp_path):
    if request.param == "fakeredis":
        client = fakeredis.aioredis.FakeRedis()
        try:
            yield client
        finally:
            await client.aclose()
        return
    executable = shutil.which("redis-server")
    if executable is None:
        pytest.skip("redis-server is not installed; this environment supports fakeredis only")
    from redis.asyncio import Redis

    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    process = subprocess.Popen(
        [executable, "--bind", "127.0.0.1", "--port", str(port), "--save", "",
         "--appendonly", "no", "--dir", str(tmp_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    client = Redis(host="127.0.0.1", port=port, decode_responses=False)
    try:
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail(f"test redis-server exited with status {process.returncode}")
            try:
                await client.ping()
                break
            except Exception:
                await asyncio.sleep(0.05)
        else:
            pytest.fail("test redis-server failed readiness check")
        yield client
    finally:
        await client.aclose()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.asyncio
async def test_canonical_event_processing_to_signed_durable_sink_receipt(tmp_path, redis_client):
    redis = redis_client
    graph = BehavioralDependencyGraph(batch_size=100)
    consumer = DriftEventRedisConsumer(redis, UpdateBdgUseCase(graph, NoSnapshot()))
    await consumer._ensure_consumer_group()

    event_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    run_id, scenario_id = "integration-run-01", "net-egress-001"
    image_digest = "sha256:" + "c" * 64
    workload = {
        "cluster": "phantom-k3s-lab", "cluster_name": "phantom-k3s-lab",
        "namespace": "phantom-eval", "name": "cartservice-pod", "deployment": "cartservice",
        "pod_uid": str(uuid.uuid4()),
        "container_id": "containerd://test-container", "image_digest": image_digest,
    }
    event = {
        "event_id": str(event_id), "tenant_id": str(tenant_id),
        "drift_event_id": str(uuid.uuid4()), "outbox_id": str(uuid.uuid4()),
        "observed_at": datetime.now(UTC).isoformat(), "event_type": "network_connect",
        "cluster": "phantom-k3s-lab", "workload": workload,
        "process": {"tgid": 1234, "start_time_ns": 987654},
        "runtime_evidence": {
            "raw_event_digest": "sha256:" + "d" * 64,
            "run_id": run_id, "scenario_id": scenario_id,
        },
        "sbom_binding": {
            "binding_status": "insufficient_evidence", "image_digest": image_digest,
            "sbom_id": None, "purl": None, "confidence": None,
            "resolver_version": "test-fixture-v1", "method": "no executable hash",
            "evidence": [], "candidate_purls": [],
            "reason": "executable hash and verified SBOM provenance unavailable",
        },
        "contract_violations": [],
    }
    drift_id, outbox_id = uuid.uuid4(), uuid.uuid4()
    await publisher.publish_graph_mutation_job(redis, drift_id, outbox_id, event)
    batch = await redis.xreadgroup(
        consumer._consumer_group, "composition-test", {CAUSAL_EVENT_STREAM: ">"},
    )
    message_id, fields = batch[0][1][0]
    assert await consumer._process_message(message_id.decode(), fields)
    assert (await redis.xpending(CAUSAL_EVENT_STREAM, consumer._consumer_group))["pending"] == 1
    assert graph.graph.number_of_nodes() > 0
    assert not any(data.get("node_type") == "purl" for _, data in graph.graph.nodes(data=True))
    assert await redis.xack(CAUSAL_EVENT_STREAM, consumer._consumer_group, message_id) == 1
    assert (await redis.xpending(CAUSAL_EVENT_STREAM, consumer._consumer_group))["pending"] == 0

    # Test-only independent observer and contract-registry keys. These do not
    # provide production trust or a live workload collector.
    observer_key = Ed25519PrivateKey.generate()
    registry_key = Ed25519PrivateKey.generate()
    public_pem = observer_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    registry_pem = registry_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    trust_file = tmp_path / "trusted-keys.json"
    trust_file.write_text(
        json.dumps({
            "schema_version": "1.0", "trust_store_id": "composition-test-trust",
            "generation": 1, "revoked_key_ids": [], "keys": [
                {"key_id": "integration-test-key", "source_id": "test-independent-observer",
                 "source_type": "independent_runtime_monitor", "public_key_pem": public_pem,
                 "independent_of_phantom": True},
                {"key_id": "integration-registry-key", "source_id": "test-contract-registry",
                 "source_type": "verified_contract_registry", "public_key_pem": registry_pem,
                 "independent_of_phantom": False},
            ]}), encoding="utf-8",
    )
    contract = {
        "contract_id": "test-contract", "contract_version": "1", "image_digest": image_digest,
        "status": "active",
        "verification_reference": "test-registry://contracts/1",
        "workload_selector": {"cluster_name": "phantom-k3s-lab", "namespace": "phantom-eval",
                              "labels": {}},
        "constraints": {
            "allowed_executables": ["/worker"], "allowed_file_path_prefixes": ["/etc"],
            "allowed_network_destinations": [{"protocol": "tcp", "cidr": "10.0.0.0/24",
                                               "port_min": 443, "port_max": 443}],
            "allowed_syscall_classes": ["process"], "allowed_purls": [],
            "allowed_parent_child_pairs": [], "max_new_processes_per_5m": 1,
            "allow_privilege_transition": False,
        },
    }
    registry_envelope = {
        "key_id": "integration-registry-key", "algorithm": "Ed25519",
        "signature": base64.b64encode(
            registry_key.sign(canonical_payload_bytes(contract))
        ).decode("ascii"),
        "payload": contract,
    }
    trusted_registry = TrustedOracleKey(
        "integration-registry-key", "test-contract-registry", "verified_contract_registry",
        registry_key.public_key(), False,
    )
    observer = ScenarioOracleObserver(
        source_id="test-independent-observer", key_id="integration-test-key",
        signing_key=observer_key, trusted_contract_keys={trusted_registry.key_id: trusted_registry},
        policies=load_scenario_policies(ROOT / "research/evaluation/scenario_oracle_policies.yaml"),
    )
    assertion = HarnessAssertion(
        run_id=run_id, scenario_id=scenario_id, event_id=str(event_id), workload=workload,
        injection_status="succeeded", assertion_id="internal_sink_probe_receipt",
        assertion_passed=True, observed_state="violating", behavior="network_connect",
        details={"protocol": "tcp", "address": "10.0.0.10", "port": 8443},
        evidence_references=("test-receipt://network-observation/1",),
        contract_envelope=registry_envelope, observed_at=datetime.now(UTC).isoformat(),
    )
    observer_decision = observer.observe(assertion)
    assert observer_decision.outcome == "violating"
    envelope = observer_decision.signed_observation
    assert envelope is not None
    database = tmp_path / "sink.sqlite3"
    service = create_app(db_path=str(database), trust_path=str(trust_file), tcp_ports=())
    request = {
        "run_id": run_id, "scenario_id": scenario_id, "event_id": str(event_id),
        "workload": workload, "processing_outcome": "causal_event_processed",
        "provenance": {"binding_status": "insufficient_evidence", "event_id": str(event_id)},
        "signed_observation": envelope,
    }
    with TestClient(service) as client:
        response = client.post("/v1/receipts", json=request)
        assert response.status_code == 201, response.text
        receipt = response.json()
        assert receipt["run_id"] == run_id and receipt["scenario_id"] == scenario_id
        assert receipt["event_id"] == str(event_id)
        assert receipt["oracle_result"]["outcome"] == "confirmed_violation"
        assert receipt["oracle_verification"]["authenticity_status"] == "verified"
        assert receipt["provenance"]["binding_status"] == "insufficient_evidence"
        assert client.get(f"/v1/receipts/{receipt['receipt_id']}/verify").json()["authenticity"] == "verified"
        assert client.post("/v1/receipts", json=request).json()["receipt_id"] == receipt["receipt_id"]
        tampered = {**envelope, "payload": {**envelope["payload"], "details": {"port": 443}}}
        assert client.post("/v1/receipts", json={**request, "signed_observation": tampered}).status_code == 401
        unknown_key = {**envelope, "key_id": "untrusted-key"}
        assert client.post("/v1/receipts", json={**request, "signed_observation": unknown_key}).status_code == 401
        conflicting_decision = observer.observe(replace(
            assertion, details={"protocol": "tcp", "address": "10.0.0.10", "port": 443},
        ))
        conflict = client.post("/v1/receipts", json={
            **request, "signed_observation": conflicting_decision.signed_observation,
        })
        assert conflict.status_code == 409

    restarted = create_app(db_path=str(database), trust_path=str(trust_file), tcp_ports=())
    with TestClient(restarted) as client:
        persisted = client.get(f"/v1/receipts/{receipt['receipt_id']}").json()
        assert persisted == receipt

    # Local protocol test double only: this verifies S3-client composition and
    # receipt recovery semantics, not AWS IAM, S3, or off-node durability.
    memory_s3 = MemoryS3()
    backup_client = S3EvidenceBackupClient(memory_s3, bucket="phantom-composition-test", temp_dir=tmp_path)
    backup = backup_client.backup(database, backup_id="composition-receipt-backup")
    for suffix in ("", "-wal", "-shm"):
        candidate = database if not suffix else database.with_name(database.name + suffix)
        if candidate.exists():
            candidate.unlink()
    recovered_path = tmp_path / "restored" / "evidence.sqlite3"
    backup_client.restore(backup["key"], recovered_path, version_id=backup["version_id"])
    recovered = DurableEvidenceSink(recovered_path).get(receipt["receipt_id"])
    assert recovered["run_id"] == run_id and recovered["scenario_id"] == scenario_id
    assert recovered["integrity_sha256"] == receipt["integrity_sha256"]
