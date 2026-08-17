"""
causal-engine infrastructure NVD 2.0 API client.

Rate-limited NVD 2.0 REST API client for CVE enrichment.
Observes the NVD rate limit policy: 5 requests per 30 seconds
(without an API key) or 50 requests per 30 seconds (with an API key).

The client fetches CVE records by CPE match string or CVE ID and
returns structured vulnerability data for PCEPS feature enrichment.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
"""NVD 2.0 CVE API endpoint."""

_DEFAULT_RATE_LIMIT_REQUESTS: int = 5
"""Default requests per window (without API key)."""

_DEFAULT_RATE_LIMIT_WINDOW_SECONDS: float = 30.0
"""Default rate-limit window in seconds."""

_API_KEY_RATE_LIMIT_REQUESTS: int = 50
"""Requests per window with an NVD API key."""


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NvdCveRecord:
    """A structured CVE record from the NVD 2.0 API.

    Attributes:
        cve_id: CVE identifier (e.g. 'CVE-2024-1234').
        description: English description of the vulnerability.
        cvss_v31_base_score: CVSS v3.1 base score, or None.
        cvss_v31_severity: CVSS v3.1 severity string, or None.
        cwe_ids: List of CWE identifiers.
        affected_cpe_matches: List of affected CPE match strings.
        published_date: Publication date string (ISO format).
        last_modified_date: Last modification date string.
    """

    cve_id: str
    description: str = ""
    cvss_v31_base_score: float | None = None
    cvss_v31_severity: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    affected_cpe_matches: list[str] = field(default_factory=list)
    published_date: str = ""
    last_modified_date: str = ""


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class _SlidingWindowRateLimiter:
    """Sliding-window rate limiter for NVD API compliance.

    Attributes:
        max_requests: Maximum requests allowed in the window.
        window_seconds: Window duration in seconds.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        """Initialise the rate limiter.

        Args:
            max_requests: Max requests per window.
            window_seconds: Window duration in seconds.
        """
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._timestamps: list[float] = []

    async def acquire(self) -> None:
        """Wait until a request slot is available.

        Blocks until the oldest request in the window has expired,
        then records the current timestamp.
        """
        now = time.monotonic()
        # Remove timestamps outside the window.
        self._timestamps = [
            t for t in self._timestamps if now - t < self._window_seconds
        ]

        if len(self._timestamps) >= self._max_requests:
            # Must wait until the oldest timestamp expires.
            sleep_time = self._window_seconds - (now - self._timestamps[0])
            if sleep_time > 0:
                log.debug(
                    "nvd_client.rate_limited",
                    sleep_seconds=round(sleep_time, 2),
                )
                await asyncio.sleep(sleep_time)
            # Clean again after sleeping.
            now = time.monotonic()
            self._timestamps = [
                t for t in self._timestamps if now - t < self._window_seconds
            ]

        self._timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# NVD Client
# ---------------------------------------------------------------------------


class NvdClient:
    """Async NVD 2.0 API client with rate limiting.

    Args:
        api_key: Optional NVD API key (increases rate limit to 50/30s).
        timeout_seconds: HTTP request timeout.
        max_retries: Maximum retry attempts on transient errors.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """Initialise the NVD client.

        Args:
            api_key: Optional NVD API key.
            timeout_seconds: HTTP request timeout.
            max_retries: Retry count on transient failures.
        """
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries

        rate_limit = (
            _API_KEY_RATE_LIMIT_REQUESTS if api_key else _DEFAULT_RATE_LIMIT_REQUESTS
        )
        self._limiter = _SlidingWindowRateLimiter(
            max_requests=rate_limit,
            window_seconds=_DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        )
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client singleton.

        Returns:
            An httpx.AsyncClient.
        """
        if self._client is None or self._client.is_closed:
            headers: dict[str, str] = {}
            if self._api_key:
                headers["apiKey"] = self._api_key
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers=headers,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client. Idempotent."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def get_cve(self, cve_id: str) -> NvdCveRecord | None:
        """Fetch a single CVE record by ID.

        Args:
            cve_id: CVE identifier (e.g. 'CVE-2024-1234').

        Returns:
            An NvdCveRecord if found, None if the CVE does not exist.

        Raises:
            httpx.HTTPStatusError: On non-retryable HTTP errors.
        """
        await self._limiter.acquire()
        client = await self._get_client()

        url = NVD_API_BASE_URL
        params = {"cveId": cve_id}

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = await client.get(url, params=params)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                return self._parse_cve_response(data)
            except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                if attempt < self._max_retries:
                    wait = 2 ** attempt
                    log.warning(
                        "nvd_client.retry",
                        cve_id=cve_id,
                        attempt=attempt,
                        wait_seconds=wait,
                        error=str(exc),
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        return None  # Unreachable; satisfies type checker.

    async def search_by_cpe(
        self,
        cpe_match_string: str,
        results_per_page: int = 20,
    ) -> list[NvdCveRecord]:
        """Search CVEs by CPE match string.

        Args:
            cpe_match_string: CPE 2.3 match string (e.g. 'cpe:2.3:a:vendor:*').
            results_per_page: Maximum results to return (NVD default 20, max 2000).

        Returns:
            List of matching NvdCveRecord objects.
        """
        await self._limiter.acquire()
        client = await self._get_client()

        params: dict[str, Any] = {
            "cpeName": cpe_match_string,
            "resultsPerPage": min(results_per_page, 2000),
        }

        try:
            resp = await client.get(NVD_API_BASE_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_cve_list_response(data)
        except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            log.error(
                "nvd_client.search_failed",
                cpe=cpe_match_string,
                error=str(exc),
            )
            return []

    @staticmethod
    def _parse_cve_response(data: dict[str, Any]) -> NvdCveRecord | None:
        """Parse a single CVE from NVD 2.0 API JSON response.

        Args:
            data: The raw JSON response dict.

        Returns:
            An NvdCveRecord if the response contains a vulnerability, else None.
        """
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return NvdClient._parse_vulnerability(vulnerabilities[0])

    @staticmethod
    def _parse_cve_list_response(data: dict[str, Any]) -> list[NvdCveRecord]:
        """Parse multiple CVEs from NVD 2.0 API JSON response.

        Args:
            data: The raw JSON response dict.

        Returns:
            List of NvdCveRecord objects.
        """
        results: list[NvdCveRecord] = []
        for vuln in data.get("vulnerabilities", []):
            record = NvdClient._parse_vulnerability(vuln)
            if record:
                results.append(record)
        return results

    @staticmethod
    def _parse_vulnerability(vuln: dict[str, Any]) -> NvdCveRecord | None:
        """Parse one vulnerability entry from the NVD response.

        Args:
            vuln: A single vulnerability dict from the NVD response.

        Returns:
            An NvdCveRecord, or None if parsing fails.
        """
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description.
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS v3.1.
        cvss_score: float | None = None
        cvss_severity: str | None = None
        metrics = cve.get("metrics", {})
        cvss_v31_list = metrics.get("cvssMetricV31", [])
        if cvss_v31_list:
            cvss_data = cvss_v31_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")

        # CWE IDs.
        cwe_ids: list[str] = []
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for desc_item in weakness.get("description", []):
                cwe_val = desc_item.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwe_ids.append(cwe_val)

        return NvdCveRecord(
            cve_id=cve_id,
            description=description,
            cvss_v31_base_score=cvss_score,
            cvss_v31_severity=cvss_severity,
            cwe_ids=cwe_ids,
            published_date=cve.get("published", ""),
            last_modified_date=cve.get("lastModified", ""),
        )
