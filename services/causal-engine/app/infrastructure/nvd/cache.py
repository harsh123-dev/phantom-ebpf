"""
causal-engine infrastructure NVD Redis cache.

Redis-backed cache for NVD CVE records with a 24-hour TTL.

Design:
- Cache key: ``phantom:nvd:cve:<cve_id>``
- Value: JSON-serialized NvdCveRecord.
- TTL: 24 hours (86400 seconds).
- Cache stampede protection:
  Before a cache miss triggers an NVD API call, a Redis SET NX lock
  (key: ``phantom:nvd:lock:<cve_id>``, TTL 30 s) is acquired.
  If the lock cannot be acquired, the caller waits 100 ms and
  re-checks the cache before retrying the API call.
- Thread-safe via async Redis operations.
"""

from __future__ import annotations

import asyncio
import json

import structlog
from redis.asyncio import Redis

from app.infrastructure.nvd.client import NvdClient, NvdCveRecord

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CACHE_KEY_PREFIX: str = "phantom:nvd:cve:"
"""Redis key prefix for NVD cache entries."""

_LOCK_KEY_PREFIX: str = "phantom:nvd:lock:"
"""Redis key prefix for stampede-protection locks."""

_DEFAULT_TTL_SECONDS: int = 86400
"""Default cache TTL: 24 hours."""

_LOCK_TTL_SECONDS: int = 30
"""Short TTL for the stampede-protection lock."""

_LOCK_WAIT_SECONDS: float = 0.1
"""Time to wait between lock retry attempts."""

_LOCK_MAX_RETRIES: int = 5
"""Maximum lock acquisition retries before falling through to the API."""


# ---------------------------------------------------------------------------
# NVD Cache
# ---------------------------------------------------------------------------


class NvdCache:
    """Redis-backed cache for NVD CVE records.

    Provides a transparent caching layer around the NvdClient.
    Cache misses trigger an NVD API call, protected by a Redis
    SET NX lock to prevent thundering-herd / cache stampede.

    Args:
        redis_client: An async Redis client.
        nvd_client: The NVD API client for cache misses.
        ttl_seconds: Cache entry TTL in seconds. Default 86400 (24h).
    """

    def __init__(
        self,
        redis_client: Redis,
        nvd_client: NvdClient,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        """Initialise the NVD cache.

        Args:
            redis_client: Async Redis client for cache storage.
            nvd_client: NVD API client for cache-miss resolution.
            ttl_seconds: Cache TTL in seconds.
        """
        self._redis = redis_client
        self._nvd = nvd_client
        self._ttl = ttl_seconds

    def _cache_key(self, cve_id: str) -> str:
        """Build the Redis cache key for a CVE ID.

        Args:
            cve_id: CVE identifier string.

        Returns:
            Full Redis key string.
        """
        return f"{_CACHE_KEY_PREFIX}{cve_id}"

    def _lock_key(self, cve_id: str) -> str:
        """Build the Redis stampede-protection lock key for a CVE ID.

        Args:
            cve_id: CVE identifier string.

        Returns:
            Full Redis lock key string.
        """
        return f"{_LOCK_KEY_PREFIX}{cve_id}"

    async def get_cve(self, cve_id: str) -> NvdCveRecord | None:
        """Get a CVE record from cache or NVD API.

        Checks Redis first; on miss, acquires a SET NX lock to prevent
        concurrent NVD API calls for the same CVE (cache stampede).
        After lock acquisition, re-checks the cache (another worker may
        have populated it while waiting for the lock), then falls back
        to the NVD API.

        Args:
            cve_id: CVE identifier (e.g. 'CVE-2024-1234').

        Returns:
            An NvdCveRecord if found, None otherwise.
        """
        # 1. Fast path: check cache.
        cached = await self._get_cached(cve_id)
        if cached is not None:
            log.debug("nvd_cache.hit", cve_id=cve_id)
            return cached

        # 2. Cache miss: acquire stampede-protection lock.
        lock_acquired = False
        for _attempt in range(_LOCK_MAX_RETRIES):
            # SET NX with EX for atomic lock acquire.
            lock_acquired = bool(
                await self._redis.set(
                    self._lock_key(cve_id),
                    "1",
                    nx=True,
                    ex=_LOCK_TTL_SECONDS,
                )
            )
            if lock_acquired:
                break
            # Lock held by another coroutine; re-check cache then retry.
            log.debug("nvd_cache.stampede_wait", cve_id=cve_id)
            await asyncio.sleep(_LOCK_WAIT_SECONDS)
            # Re-check: another worker may have populated the cache.
            re_cached = await self._get_cached(cve_id)
            if re_cached is not None:
                log.debug("nvd_cache.hit_after_wait", cve_id=cve_id)
                return re_cached

        # 3. Fetch from NVD API (with or without the lock).
        log.debug("nvd_cache.miss", cve_id=cve_id, lock_acquired=lock_acquired)
        record: NvdCveRecord | None = None
        try:
            record = await self._nvd.get_cve(cve_id)
            if record is not None:
                await self._set_cached(cve_id, record)
        except Exception as exc:  # noqa: BLE001
            log.warning("nvd_cache.api_error", cve_id=cve_id, error=str(exc))
        finally:
            # Release the lock if we acquired it.
            if lock_acquired:
                try:
                    await self._redis.delete(self._lock_key(cve_id))
                except Exception:  # noqa: BLE001
                    pass

        return record

    async def get_cached_cve(self, cve_id: str) -> NvdCveRecord | None:
        """Retrieve a cached CVE without triggering an NVD API call.

        Args:
            cve_id: CVE identifier string.

        Returns:
            An NvdCveRecord if cached, None otherwise.
        """
        return await self._get_cached(cve_id)

    async def set_cached_cve(self, cve_id: str, record: NvdCveRecord) -> None:
        """Explicitly store a CVE record in the cache.

        Args:
            cve_id: CVE identifier string.
            record: NvdCveRecord to cache.
        """
        await self._set_cached(cve_id, record)

    async def _get_cached(self, cve_id: str) -> NvdCveRecord | None:
        """Retrieve a cached CVE record from Redis.

        Args:
            cve_id: CVE identifier.

        Returns:
            An NvdCveRecord if cached, None otherwise.
        """
        try:
            raw = await self._redis.get(self._cache_key(cve_id))
            if raw is None:
                return None
            data = json.loads(raw)
            return NvdCveRecord(
                cve_id=data["cve_id"],
                description=data.get("description", ""),
                cvss_v31_base_score=data.get("cvss_v31_base_score"),
                cvss_v31_severity=data.get("cvss_v31_severity"),
                cwe_ids=data.get("cwe_ids", []),
                affected_cpe_matches=data.get("affected_cpe_matches", []),
                published_date=data.get("published_date", ""),
                last_modified_date=data.get("last_modified_date", ""),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("nvd_cache.get_error", cve_id=cve_id, error=str(exc))
            return None

    async def _set_cached(self, cve_id: str, record: NvdCveRecord) -> None:
        """Cache a CVE record in Redis with TTL.

        Args:
            cve_id: CVE identifier.
            record: The NvdCveRecord to cache.
        """
        try:
            data = {
                "cve_id": record.cve_id,
                "description": record.description,
                "cvss_v31_base_score": record.cvss_v31_base_score,
                "cvss_v31_severity": record.cvss_v31_severity,
                "cwe_ids": record.cwe_ids,
                "affected_cpe_matches": record.affected_cpe_matches,
                "published_date": record.published_date,
                "last_modified_date": record.last_modified_date,
            }
            await self._redis.setex(
                self._cache_key(cve_id),
                self._ttl,
                json.dumps(data),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("nvd_cache.set_error", cve_id=cve_id, error=str(exc))

    async def invalidate(self, cve_id: str) -> None:
        """Remove a CVE from the cache.

        Args:
            cve_id: CVE identifier to evict.
        """
        try:
            await self._redis.delete(self._cache_key(cve_id))
        except Exception as exc:  # noqa: BLE001
            log.warning("nvd_cache.invalidate_error", cve_id=cve_id, error=str(exc))
