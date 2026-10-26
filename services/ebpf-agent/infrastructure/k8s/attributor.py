"""
services/ebpf-agent/infrastructure/k8s/attributor.py

Maps cgroup ID → pod UID → SBOM PURL using the Kubernetes Python API.

Architecture:
- Uses the official kubernetes-python client (not kubectl subprocess).
- Results are cached in Redis with a TTL; stale cache entries are evicted
  on each miss-and-refetch cycle.
- All attribution uncertainty states from the handoff are handled:
    - resolved   : cgroup maps unambiguously to one pod/container/SBOM PURL
    - ambiguous  : multiple pods share the cgroup ID (should not happen on
                   cgroup v2 but must be handled defensively)
    - missing    : cgroup ID not found in any running pod
    - stale      : cached result predates the pod's deletion/restart

Clean architecture: this module lives in infrastructure/; domain logic
(e.g., deciding what to do with an ambiguous binding) lives in domain/.
This module only does I/O and caching.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException
from redis.asyncio import Redis

log: structlog.BoundLogger = structlog.get_logger(__name__)
_IDENTITY_DIAGNOSTICS: bool = os.environ.get(
    "PHANTOM_IDENTITY_DIAGNOSTICS", "false"
).lower() in {"1", "true", "yes"}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS: int = 60
"""Redis TTL for cgroup → pod attribution results. 60 s balances freshness
vs. k8s API load for rapidly rescheduled pods."""

_CACHE_KEY_PREFIX: str = "phantom:attr:cgroup:"
"""Redis key prefix. Full key: phantom:attr:cgroup:<cgroup_id>"""

_MAX_PODS_PER_CGROUP: int = 1
"""Any duplicate container identity match is ambiguous and must abstain."""

_CONTAINER_SCOPE_RE = re.compile(
    r"(?:cri-containerd|docker|crio)-([0-9a-f]{64})(?:\.scope)?$"
)
_CGROUP_INDEX_TTL_SECONDS = 5.0


def immutable_image_digest(image_id: str | None) -> str | None:
    """Return an OCI digest only when the runtime reports an immutable sha256 ID."""
    if not image_id:
        return None
    match = re.search(r"sha256:[0-9a-f]{64}(?:$|[^0-9a-f])", image_id)
    return match.group(0)[:71] if match else None


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class AttributionStatus(str, Enum):
    """Binding quality matching the handoff identity_status field."""

    RESOLVED  = "resolved"
    AMBIGUOUS = "ambiguous"
    MISSING   = "missing"
    STALE     = "stale"


@dataclass(frozen=True)
class AttributionResult:
    """Result of a cgroup-to-workload attribution attempt.

    Attributes:
        cgroup_id: The cgroup ID that was looked up.
        status: Attribution quality.
        pod_uid: The pod UID if status is RESOLVED; None otherwise.
        pod_name: The pod name if status is RESOLVED; None otherwise.
        namespace: The Kubernetes namespace if RESOLVED; None otherwise.
        container_name: The container name if RESOLVED; None otherwise.
        image_digest: The container image digest if RESOLVED; None otherwise.
        purl: The SBOM PURL for the matched component if RESOLVED; None otherwise.
        binding_confidence: Confidence score in [0.0, 1.0].
        candidates: Raw candidate list when status is AMBIGUOUS.
        container_id: Runtime ID from Kubernetes status after cross-checking.
    """

    cgroup_id: int
    status: AttributionStatus
    pod_uid: uuid.UUID | None = None
    pod_name: str | None = None
    namespace: str | None = None
    container_name: str | None = None
    image_digest: str | None = None
    purl: str | None = None
    binding_confidence: float = 0.0
    candidates: list[dict[str, Any]] | None = None
    container_id: str | None = None


# ---------------------------------------------------------------------------
# Attributor
# ---------------------------------------------------------------------------


class CgroupPodAttributor:
    """Maps cgroup IDs to Kubernetes pod/container metadata.

    Uses the kubernetes-python client with in-cluster or kubeconfig auth.
    Results are cached in Redis to reduce API server load.

    Args:
        redis_client: An async Redis client for caching.
        node_name: The node name this agent runs on; used to filter pods
            returned by the k8s API to only those on this node.
        namespace: Optional namespace filter; None means all namespaces.
        cache_ttl: Redis TTL in seconds for attribution results.
        in_cluster: If True, loads in-cluster k8s credentials; if False,
            loads from kubeconfig (for local development).
    """

    def __init__(
        self,
        redis_client: Redis | None,
        node_name: str,
        namespace: str | None = None,
        cache_ttl: int = _CACHE_TTL_SECONDS,
        in_cluster: bool = True,
        cgroup_root: str | None = None,
    ) -> None:
        """Initialise the attributor.

        Args:
            redis_client: Async Redis client for caching.
            node_name: Kubernetes node name for pod filtering.
            namespace: Optional namespace filter; None = all namespaces.
            cache_ttl: Redis TTL in seconds.
            in_cluster: Load in-cluster credentials if True.
        """
        self._redis = redis_client
        self._node_name = node_name
        self._namespace = namespace
        self._cache_ttl = cache_ttl
        self._cgroup_root = cgroup_root or os.environ.get(
            "PHANTOM_CGROUP_ROOT", "/sys/fs/cgroup"
        )
        self._cgroup_index: dict[int, str] = {}
        self._cgroup_index_expires = 0.0

        if in_cluster:
            k8s_config.load_incluster_config()
        else:
            k8s_config.load_kube_config()

        self._core_v1 = k8s_client.CoreV1Api()

    def _cache_key(self, cgroup_id: int, container_id: str | None = None) -> str:
        """Build the Redis cache key for a cgroup ID.

        Args:
            cgroup_id: The cgroup ID integer.

        Returns:
            A Redis key string.
        """
        # A negative lookup without a readable container ID must not mask a
        # later lookup that has one. Keep the identity contexts separate.
        suffix = f"container:{container_id}" if container_id else "unattributed"
        return f"{_CACHE_KEY_PREFIX}{cgroup_id}:{suffix}"

    async def _get_cached(
        self, cgroup_id: int, container_id: str | None = None
    ) -> AttributionResult | None:
        """Retrieve a cached attribution result from Redis.

        Args:
            cgroup_id: The cgroup ID to look up.

        Returns:
            The cached AttributionResult, or None if not cached or expired.
        """
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(self._cache_key(cgroup_id, container_id))
            if raw is None:
                return None
            data = json.loads(raw)
            # Reconstruct the dataclass from the cached JSON.
            return AttributionResult(
                cgroup_id=data["cgroup_id"],
                status=AttributionStatus(data["status"]),
                pod_uid=uuid.UUID(data["pod_uid"]) if data.get("pod_uid") else None,
                pod_name=data.get("pod_name"),
                namespace=data.get("namespace"),
                container_name=data.get("container_name"),
                image_digest=data.get("image_digest"),
                purl=data.get("purl"),
                binding_confidence=data.get("binding_confidence", 0.0),
                candidates=data.get("candidates"),
                container_id=data.get("container_id"),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("attributor.cache_get_failed", cgroup_id=cgroup_id, error=str(exc))
            return None

    async def _set_cached(
        self, result: AttributionResult, container_id: str | None = None
    ) -> None:
        """Cache an attribution result in Redis.

        Args:
            result: The AttributionResult to cache.
        """
        if self._redis is None:
            return
        try:
            data = {
                "cgroup_id": result.cgroup_id,
                "status": result.status.value,
                "pod_uid": str(result.pod_uid) if result.pod_uid else None,
                "pod_name": result.pod_name,
                "namespace": result.namespace,
                "container_name": result.container_name,
                "image_digest": result.image_digest,
                "purl": result.purl,
                "binding_confidence": result.binding_confidence,
                "candidates": result.candidates,
                "container_id": result.container_id,
            }
            await self._redis.setex(
                self._cache_key(result.cgroup_id, container_id),
                self._cache_ttl,
                json.dumps(data),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "attributor.cache_set_failed",
                cgroup_id=result.cgroup_id,
                error=str(exc),
            )

    def _extract_cgroup_id_from_pod(self, pod: object) -> int | None:
        """Extract the cgroup ID from a pod's container statuses.

        The cgroup ID for a container is derived from its container ID.
        Kubernetes does not expose cgroup IDs in Pod status. The runtime
        cgroup directory inode is resolved by _container_id_for_cgroup.

        Args:
            pod: A kubernetes V1Pod object.

        Returns:
            The inferred cgroup ID, or None if not determinable.
        """
        # Pod status does not include this Linux runtime detail.
        return None

    def _container_id_for_cgroup(self, cgroup_id: int) -> str | None:
        """Look up a cgroup directory inode in the mounted host cgroup tree.

        This is only an index lookup, not proof that a BPF event's cgroup ID
        has inode semantics. Callers may use it only after validating the
        event's ID against that process's host-proc unified cgroup path.
        """
        now = time.monotonic()
        if now >= self._cgroup_index_expires:
            index: dict[int, str] = {}
            for root, directories, _files in os.walk(self._cgroup_root):
                for name in directories:
                    match = _CONTAINER_SCOPE_RE.search(name)
                    if not match:
                        continue
                    path = os.path.join(root, name)
                    try:
                        inode = os.stat(path, follow_symlinks=False).st_ino
                    except OSError:
                        continue
                    index[inode] = match.group(1)
            self._cgroup_index = index
            self._cgroup_index_expires = now + _CGROUP_INDEX_TTL_SECONDS
        return self._cgroup_index.get(cgroup_id)

    async def attribute(
        self,
        cgroup_id: int,
        container_id: str | None = None,
        *,
        event_cgroup_validated: bool = False,
    ) -> AttributionResult:
        """Attribute a cgroup ID to a Kubernetes pod and SBOM PURL.

        Checks the Redis cache first; on miss, queries the k8s API.
        Returns MISSING if no matching pod is found, AMBIGUOUS if multiple
        pods claim the same cgroup ID, and RESOLVED on unambiguous match.

        Args:
            cgroup_id: The cgroup ID from the eBPF event header.
            container_id: Explicit container ID string if known.

        Returns:
            An AttributionResult describing the attribution quality.
        """
        if container_id is not None and not event_cgroup_validated:
            # A container ID supplied without event-time cgroup validation is
            # not trusted, including IDs passed by older callers.
            if _IDENTITY_DIAGNOSTICS:
                log.debug(
                    "attributor.container_id_rejected",
                    cgroup_id=cgroup_id,
                    reason="event_cgroup_not_validated_against_process_cgroup",
                )
            container_id = None

        bound_log = log.bind(cgroup_id=cgroup_id, node_name=self._node_name)
        if _IDENTITY_DIAGNOSTICS:
            bound_log.debug(
                "attributor.identity_input",
                container_id_present=bool(container_id),
                event_cgroup_validated=event_cgroup_validated,
            )

        # 1. Check cache.
        # A cgroup-only cache entry cannot carry proof that the current event's
        # process cgroup matched this cgroup ID. In particular, entries written
        # by older agents may contain an unvalidated inode-derived identity.
        # Cache only when the caller supplied the event-validated runtime ID.
        cached = await self._get_cached(cgroup_id, container_id) if container_id else None
        if cached is not None:
            bound_log.debug("attributor.cache_hit", status=cached.status.value)
            return cached

        # 2. Query k8s API.
        bound_log.debug("attributor.k8s_lookup")
        result = await self._query_k8s(
            cgroup_id, bound_log, container_id, event_cgroup_validated
        )

        # 3. Cache and return.
        if container_id:
            await self._set_cached(result, container_id)
        return result

    async def _query_k8s(
        self,
        cgroup_id: int,
        bound_log: structlog.BoundLogger,
        container_id: str | None = None,
        event_cgroup_validated: bool = False,
    ) -> AttributionResult:
        """Query the Kubernetes API to find the pod for a given cgroup ID.

        Filters to pods on this node and cross-checks a runtime container ID
        resolved from the kernel event's cgroup ID.

        Args:
            cgroup_id: The cgroup ID to attribute.
            bound_log: Structured logger with cgroup_id already bound.

        Returns:
            An AttributionResult.
        """
        if not container_id:
            if not event_cgroup_validated:
                if _IDENTITY_DIAGNOSTICS:
                    bound_log.debug(
                        "attributor.cgroup_index_abstain",
                        reason="event_cgroup_not_validated_against_process_cgroup",
                    )
                return AttributionResult(
                    cgroup_id=cgroup_id,
                    status=AttributionStatus.MISSING,
                    binding_confidence=0.0,
                )
            container_id = self._container_id_for_cgroup(cgroup_id)
            if not container_id:
                if _IDENTITY_DIAGNOSTICS:
                    bound_log.debug("attributor.cgroup_index_miss")
                return AttributionResult(
                    cgroup_id=cgroup_id,
                    status=AttributionStatus.MISSING,
                    binding_confidence=0.0,
                )
            if _IDENTITY_DIAGNOSTICS:
                bound_log.debug(
                    "attributor.cgroup_index_match",
                    matched_container_id=container_id,
                )

        try:
            if self._namespace:
                pod_list = self._core_v1.list_namespaced_pod(
                    namespace=self._namespace,
                    field_selector=f"spec.nodeName={self._node_name}",
                )
            else:
                pod_list = self._core_v1.list_pod_for_all_namespaces(
                    field_selector=f"spec.nodeName={self._node_name}",
                )
        except ApiException as exc:
            bound_log.error(
                "attributor.k8s_api_error",
                status=exc.status,
                reason=exc.reason,
            )
            return AttributionResult(
                cgroup_id=cgroup_id,
                status=AttributionStatus.MISSING,
                binding_confidence=0.0,
            )

        # Cross-check cgroup-derived identity against current pod status.
        matches = []
        for pod in pod_list.items:
            if pod.status is None:
                continue
            for cs in (pod.status.container_statuses or []):
                if cs.container_id and cs.state and cs.state.running:
                    # Match logic: if container_id is provided, check if it's a substring
                    # of cs.container_id (which is typically 'containerd://<id>')
                    observed_id = cs.container_id.rsplit("/", 1)[-1]
                    requested_id = container_id.rsplit("/", 1)[-1]
                    if observed_id != requested_id:
                        continue
                    
                    matches.append({
                        "pod_uid": str(pod.metadata.uid),
                        "pod_name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container_name": cs.name,
                        "container_id": cs.container_id,
                        "image_digest": immutable_image_digest(cs.image_id),
                    })

        if not matches:
            bound_log.debug("attributor.missing")
            return AttributionResult(
                cgroup_id=cgroup_id,
                status=AttributionStatus.MISSING,
                binding_confidence=0.0,
            )

        if len(matches) > _MAX_PODS_PER_CGROUP:
            bound_log.warning(
                "attributor.ambiguous",
                candidate_count=len(matches),
            )
            return AttributionResult(
                cgroup_id=cgroup_id,
                status=AttributionStatus.AMBIGUOUS,
                binding_confidence=0.0,
                candidates=matches[:8],  # Bounded candidate list.
            )

        # Single candidate — mark as resolved with moderate confidence.
        # Full confidence requires cross-checking the image digest against
        # the verified SBOM; that happens in the application use case.
        m = matches[0]
        bound_log.debug(
            "attributor.resolved",
            pod_uid=m["pod_uid"],
            namespace=m["namespace"],
        )
        return AttributionResult(
            cgroup_id=cgroup_id,
            status=AttributionStatus.RESOLVED,
            pod_uid=uuid.UUID(m["pod_uid"]) if m["pod_uid"] else None,
            pod_name=m["pod_name"],
            namespace=m["namespace"],
            container_name=m["container_name"],
            image_digest=m["image_digest"],
            container_id=m["container_id"],
            purl=None,        # Filled by SBOM binding step.
            binding_confidence=0.7,  # Reduced until image digest is verified.
        )

    async def invalidate(self, cgroup_id: int, container_id: str | None = None) -> None:
        """Evict the cached attribution for a cgroup ID.

        Called when a pod deletion event is observed so the next lookup
        re-queries the API.

        Args:
            cgroup_id: The cgroup ID whose cache entry should be removed.
        """
        try:
            if container_id is not None:
                await self._redis.delete(self._cache_key(cgroup_id, container_id))
            else:
                # Pod deletion invalidates all identity contexts for this cgroup.
                keys = [key async for key in self._redis.scan_iter(
                    match=f"{_CACHE_KEY_PREFIX}{cgroup_id}:*"
                )]
                if keys:
                    await self._redis.delete(*keys)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "attributor.cache_invalidate_failed",
                cgroup_id=cgroup_id,
                error=str(exc),
            )
