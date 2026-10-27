"""Cgroup inode/container-ID attribution tests using a temporary fixture tree."""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

from infrastructure.k8s.attributor import (
    AttributionStatus,
    CgroupPodAttributor,
)


def _attributor(tmp_path, container_id: str) -> CgroupPodAttributor:
    scope = tmp_path / "kubepods.slice" / f"cri-containerd-{container_id}.scope"
    scope.mkdir(parents=True)
    attributor = CgroupPodAttributor.__new__(CgroupPodAttributor)
    attributor._cgroup_root = str(tmp_path)
    attributor._cgroup_index = {}
    attributor._cgroup_index_expires = 0.0
    attributor._redis = None
    attributor._node_name = "node-a"
    attributor._namespace = "phantom-eval"
    attributor._cache_ttl = 60
    attributor._core_v1 = Mock()
    return attributor


def test_cgroup_inode_resolves_runtime_scope_container_id(tmp_path) -> None:
    container_id = "a" * 64
    attributor = _attributor(tmp_path, container_id)
    scope = tmp_path / "kubepods.slice" / f"cri-containerd-{container_id}.scope"

    assert attributor._container_id_for_cgroup(scope.stat().st_ino) == container_id


def test_cgroup_identity_is_cross_checked_against_kubernetes_status(tmp_path) -> None:
    container_id = "b" * 64
    attributor = _attributor(tmp_path, container_id)
    scope = tmp_path / "kubepods.slice" / f"cri-containerd-{container_id}.scope"
    pod_uid = uuid.uuid4()
    image_digest = "sha256:" + "c" * 64
    container_status = SimpleNamespace(
        container_id=f"containerd://{container_id}",
        image_id=f"containerd://image@{image_digest}",
        name="recommendationservice",
        state=SimpleNamespace(running=True),
    )
    pod = SimpleNamespace(
        metadata=SimpleNamespace(
            uid=str(pod_uid), name="recommendationservice-abc", namespace="phantom-eval"
        ),
        status=SimpleNamespace(container_statuses=[container_status]),
    )
    attributor._core_v1.list_namespaced_pod.return_value = SimpleNamespace(items=[pod])

    result = asyncio.run(
        attributor._query_k8s(
            scope.stat().st_ino,
            Mock(),
            event_cgroup_validated=True,
        )
    )

    assert result.status is AttributionStatus.RESOLVED
    assert result.pod_uid == pod_uid
    assert result.container_id == f"containerd://{container_id}"
    assert result.image_digest == image_digest


def test_unmatched_cgroup_does_not_guess_a_workload(tmp_path) -> None:
    attributor = _attributor(tmp_path, "d" * 64)

    result = asyncio.run(attributor._query_k8s(999999, Mock()))

    assert result.status is AttributionStatus.MISSING
    attributor._core_v1.list_namespaced_pod.assert_not_called()


def test_attributor_abstains_without_cgroup_validation(tmp_path) -> None:
    """When event_cgroup_validated=False the attributor must return MISSING immediately.

    This is the code path exercised by a short-lived process: /proc was gone
    before _read_container_id_sync ran, so cgroup_inode_matches_event is False
    and no container_id is passed to _query_k8s. The strict policy requires
    the attributor to abstain without issuing any Kubernetes API call.
    """
    attributor = _attributor(tmp_path, "e" * 64)

    result = asyncio.run(
        attributor._query_k8s(
            12345,
            attributor._core_v1,
            event_cgroup_validated=False,
        )
    )

    assert result.status is AttributionStatus.MISSING
    # No container_id was supplied and event_cgroup_validated=False, so the
    # attributor must have returned immediately without calling the k8s API.
    attributor._core_v1.list_namespaced_pod.assert_not_called()
    attributor._core_v1.list_pod_for_all_namespaces.assert_not_called()
