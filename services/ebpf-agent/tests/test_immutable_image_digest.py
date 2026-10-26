import importlib.util
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock


MODULE = Path(__file__).resolve().parents[1] / "infrastructure/k8s/attributor.py"
spec = importlib.util.spec_from_file_location("phantom_attributor_test", MODULE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_immutable_digest_extracted_from_runtime_image_id():
    digest = "sha256:" + "a" * 64
    assert module.immutable_image_digest(f"containerd://registry/image@{digest}") == digest


def test_mutable_tag_or_missing_image_id_is_not_a_digest():
    assert module.immutable_image_digest("registry/image:latest") is None
    assert module.immutable_image_digest(None) is None


class _MemoryRedis:
    def __init__(self):
        self.values = {}

    async def get(self, key):
        return self.values.get(key)

    async def setex(self, key, _ttl, value):
        self.values[key] = value


def test_unvalidated_cgroup_result_is_not_cached_as_workload_identity():
    async def run():
        attributor = module.CgroupPodAttributor.__new__(module.CgroupPodAttributor)
        attributor._redis = _MemoryRedis()
        attributor._cache_ttl = 60
        attributor._node_name = "lab-node"
        pod_uid = "1d63bf1f-ff45-459d-88ae-11b6cbadea9d"
        digest = "sha256:" + "a" * 64
        missing = module.AttributionResult(
            cgroup_id=9516, status=module.AttributionStatus.MISSING
        )
        resolved = module.AttributionResult(
            cgroup_id=9516,
            status=module.AttributionStatus.RESOLVED,
            pod_uid=module.uuid.UUID(pod_uid),
            pod_name="recommendationservice-abc",
            namespace="phantom-eval",
            container_name="server",
            image_digest=digest,
        )
        attributor._query_k8s = AsyncMock(side_effect=[missing, resolved])

        first = await attributor.attribute(9516, None)
        second = await attributor.attribute(
            9516,
            "containerd://" + "b" * 64,
            event_cgroup_validated=True,
        )

        assert first.status == module.AttributionStatus.MISSING
        assert second.status == module.AttributionStatus.RESOLVED
        assert second.namespace == "phantom-eval"
        assert second.image_digest == digest
        assert attributor._query_k8s.await_count == 2
        keys = list(attributor._redis.values)
        assert not any(key.endswith(":unattributed") for key in keys)
        assert any(key.endswith(":container:containerd://" + "b" * 64) for key in keys)

    asyncio.run(run())
