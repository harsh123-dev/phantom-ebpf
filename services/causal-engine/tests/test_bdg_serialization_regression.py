"""
Regression tests for BDG serialization and Clean Architecture boundaries.
Ensures UUIDs and datetimes are cleanly converted to primitives without
violating hexagonal layer separation.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.domain.bdg import (
    BehavioralDependencyGraph,
)
from app.domain.entities import (
    BdgEdgeType,
    BdgNodeType,
    BDGSnapshot,
)
from app.domain.serialization import deserialize_bdg, round_trip_verify, serialize_bdg
from app.application.use_cases import UpdateBdgUseCase


def test_clean_architecture_no_infrastructure_imports_in_application():
    """Verify that app.application files do NOT import from app.infrastructure."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    app_application_dir = app_dir / "application"

    violations = []
    for py_file in app_application_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("import app.infrastructure") or stripped.startswith("from app.infrastructure"):
                violations.append(f"{py_file.name}:{line_num}: {stripped}")

    assert not violations, f"Clean architecture boundary violations found in application layer:\n" + "\n".join(violations)


def test_bdg_serialization_to_pure_json_primitives():
    """Ensure serialize_bdg produces a dict strictly serializable with standard json.dumps."""
    bdg = BehavioralDependencyGraph()
    t0 = datetime.now(tz=UTC)
    ev_id = uuid.uuid4()

    key1 = bdg.upsert_node(
        node_type=BdgNodeType.PROCESS,
        natural_key=("tenant-1", "cluster-1", "ns-1", "pod-1", "c-1", 1234, 100),
        event_time=t0,
        confidence=0.9,
        label="proc-1",
        event_id=ev_id,
    )
    key2 = bdg.upsert_node(
        node_type=BdgNodeType.NETWORK_ENDPOINT,
        natural_key=("tenant-1", "cluster-1", "10.0.0.1", 443),
        event_time=t0,
        confidence=0.85,
        label="endpoint-1",
        event_id=ev_id,
    )
    bdg.upsert_edge(
        source_key=key1,
        target_key=key2,
        edge_type=BdgEdgeType.CONNECTS_TO,
        event_time=t0,
        confidence=0.95,
        event_id=ev_id,
    )

    # Serialize to dictionary using domain pure serializer
    serialized_dict = serialize_bdg(bdg)

    # Standard json.dumps WITHOUT any default=str MUST succeed
    json_bytes = json.dumps(serialized_dict)
    assert isinstance(json_bytes, str)
    assert str(ev_id) in json_bytes
    assert "CONNECTS_TO" in json_bytes or "connects_to" in json_bytes

    # Round trip verify
    assert round_trip_verify(bdg)

    # Reconstruct graph
    reconstructed = deserialize_bdg(serialized_dict)
    assert reconstructed.get_node_count() == 2
    assert reconstructed.get_edge_count() == 1
    assert reconstructed.graph.has_node(key1)
    assert reconstructed.graph.has_node(key2)


def test_deserialize_legacy_format():
    """Verify backward compatibility with legacy snapshot format {"key": ..., "data": ...}."""
    node_id = str(uuid.uuid4())
    legacy_data = {
        "nodes": [
            {
                "key": node_id,
                "data": {
                    "node_id": node_id,
                    "node_type": "process",
                    "natural_key": ["t1", "c1", "ns1", "p1", "cnt1", 100, 1],
                    "label": "legacy-proc",
                    "attributes": {},
                    "first_seen_at": "2026-10-27T00:00:00Z",
                    "last_seen_at": "2026-10-27T00:00:00Z",
                    "confidence": 0.8,
                    "observation_count": 1,
                    "evidence_refs": [],
                },
            }
        ],
        "edges": [],
        "directed": True,
        "multigraph": True,
    }

    graph = deserialize_bdg(legacy_data)
    assert graph.get_node_count() == 1


@pytest.mark.asyncio
async def test_update_bdg_use_case_saves_snapshot_without_uuid_serialization_error():
    """Verify that UpdateBdgUseCase executes and saves snapshot successfully."""
    # Create BDG with batch size = 1 to trigger immediate snapshot cut
    bdg = BehavioralDependencyGraph(batch_size=1)
    repo = AsyncMock()

    use_case = UpdateBdgUseCase(bdg=bdg, bdg_repo=repo)

    mutation = await use_case.execute(
        event_id=uuid.uuid4(),
        event_type="execve",
        event_time=datetime.now(tz=UTC),
        tenant_id="tenant-1",
        cluster="cluster-1",
        namespace="default",
        pod_uid="pod-uuid-1",
        container_id="cont-uuid-1",
        image_digest="sha256:abc",
        tgid=5000,
        pid_start_time_ns=1000,
        identity_confidence=0.9,
        binding_confidence=0.8,
        collector_confidence=0.95,
        binding_status="resolved",
        component_purl="pkg:generic/test@1.0.0",
        contract_violations=[],
        event_attrs={"binary": "/bin/sh"},
    )

    assert mutation.snapshot_cut is True
    assert repo.save_snapshot.called

    saved_snapshot, saved_data = repo.save_snapshot.call_args[0]
    # Standard json.dumps must serialize saved_data without any errors
    json_str = json.dumps(saved_data)
    assert isinstance(json_str, str)
    assert "version" in saved_data
