"""
api-gateway HTTP service client adapters.

Typed async HTTP clients for internal service-to-service calls:
- SbomServiceClient: forwards SBOM ingest and verification requests
- CausalEngineClient: forwards attribution and scoring requests

All clients use httpx.AsyncClient with explicit timeouts.
Base URLs are read from environment variables at construction time.
Service errors are mapped to ServiceUnavailableError.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx
import structlog

from app.domain.exceptions import ResourceNotFoundError, ServiceUnavailableError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Timeout constants (seconds)
# ---------------------------------------------------------------------------

_DEFAULT_CONNECT_TIMEOUT = 5.0
_DEFAULT_READ_TIMEOUT = 30.0
_DEFAULT_WRITE_TIMEOUT = 10.0

_HTTPX_TIMEOUT = httpx.Timeout(
    connect=_DEFAULT_CONNECT_TIMEOUT,
    read=_DEFAULT_READ_TIMEOUT,
    write=_DEFAULT_WRITE_TIMEOUT,
    pool=_DEFAULT_CONNECT_TIMEOUT,
)

# ---------------------------------------------------------------------------
# Base URL helpers
# ---------------------------------------------------------------------------


def _sbom_service_url() -> str:
    """Return the SBOM service base URL from the environment.

    Returns:
        SBOM service base URL string.
    """
    return os.environ.get("SBOM_SERVICE_URL", "http://sbom-service:8000")


def _causal_engine_url() -> str:
    """Return the causal engine base URL from the environment.

    Returns:
        Causal engine base URL string.
    """
    return os.environ.get("CAUSAL_ENGINE_URL", "http://causal-engine:8001")


# ---------------------------------------------------------------------------
# SbomServiceClient
# ---------------------------------------------------------------------------


class SbomServiceClient:
    """Async HTTP client for the SBOM service internal API.

    All methods raise ServiceUnavailableError on network failures and
    ResourceNotFoundError on 404 responses. Other 4xx errors are re-raised
    as ServiceUnavailableError with the upstream error body as the message.

    Args:
        base_url: Base URL of the SBOM service. Defaults to SBOM_SERVICE_URL env var.
    """

    def __init__(self, base_url: str | None = None) -> None:
        """Initialise the client with a base URL.

        Args:
            base_url: Override base URL; defaults to environment variable.
        """
        self._base_url = base_url or _sbom_service_url()
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_HTTPX_TIMEOUT,
            headers={"X-Internal-Caller": "api-gateway"},
        )

    async def __aenter__(self) -> SbomServiceClient:
        """Enter async context manager.

        Returns:
            Self.
        """
        return self

    async def __aexit__(self, *args: Any) -> None:  # noqa: ANN401
        """Exit async context manager and close the HTTP client.

        Args:
            *args: Exception info (ignored).
        """
        await self._client.aclose()

    def _handle_response(self, response: httpx.Response, context: str) -> dict[str, Any]:
        """Raise appropriate gateway exceptions based on HTTP response status.

        Args:
            response: The httpx response object.
            context: Human-readable context string for error messages.

        Returns:
            Parsed JSON response dict on success (2xx).

        Raises:
            ResourceNotFoundError: On 404.
            ServiceUnavailableError: On non-2xx responses or malformed JSON.
        """
        if response.status_code == 404:
            raise ResourceNotFoundError(f"{context}: resource not found upstream.")
        if not response.is_success:
            log.warning(
                "service_client.upstream_error",
                context=context,
                status_code=response.status_code,
                body=response.text[:256],
            )
            raise ServiceUnavailableError(
                f"{context}: upstream returned {response.status_code}."
            )
        return response.json()  # type: ignore[no-any-return]

    async def ingest_sbom(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Forward a POST /sboms request to the SBOM service.

        Args:
            payload: Serialised SbomIngestRequest dict.

        Returns:
            Serialised SbomRecord dict from the upstream service.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post("/internal/v1/sboms", json=payload)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.sbom.ingest_failed", error=str(exc))
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, "ingest_sbom")

    async def get_sbom(self, sbom_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Fetch a single SBOM detail from the SBOM service.

        Args:
            sbom_id: UUID of the SBOM to fetch.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised SbomDetailResponse dict.

        Raises:
            ResourceNotFoundError: If the SBOM does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/sboms/{sbom_id}",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.sbom.get_failed", sbom_id=str(sbom_id), error=str(exc))
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, f"get_sbom({sbom_id})")

    async def trigger_verification(
        self, sbom_id: uuid.UUID, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Trigger cosign verification for an SBOM.

        Args:
            sbom_id: UUID of the SBOM to verify.
            payload: Serialised SbomVerificationRequest dict.

        Returns:
            Serialised VerificationJobResponse dict.

        Raises:
            ResourceNotFoundError: If the SBOM does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post(
                f"/internal/v1/sboms/{sbom_id}/verification", json=payload
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.sbom.trigger_verification_failed",
                sbom_id=str(sbom_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, f"trigger_verification({sbom_id})")

    async def get_verification_status(
        self, sbom_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Get the current verification status for an SBOM.

        Args:
            sbom_id: UUID of the SBOM.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised SbomVerificationResponse dict.

        Raises:
            ResourceNotFoundError: If no verification job exists.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/sboms/{sbom_id}/verification",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.sbom.get_verification_failed",
                sbom_id=str(sbom_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, f"get_verification_status({sbom_id})")

    async def register_contract(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Forward a POST /contracts request to the SBOM service.

        Args:
            payload: Serialised BehavioralContractRegisterRequest dict.

        Returns:
            Serialised BehavioralContractRecord dict.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post("/internal/v1/contracts", json=payload)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.sbom.register_contract_failed", error=str(exc))
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, "register_contract")

    async def get_contract(
        self, contract_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch a single behavioral contract from the SBOM service.

        Args:
            contract_id: UUID of the contract to fetch.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised BehavioralContractDetailResponse dict.

        Raises:
            ResourceNotFoundError: If the contract does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/contracts/{contract_id}",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.sbom.get_contract_failed",
                contract_id=str(contract_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, f"get_contract({contract_id})")

    async def list_contracts(self, params: dict[str, Any]) -> dict[str, Any]:
        """List behavioral contracts from the SBOM service.

        Args:
            params: Query parameters dict (image_digest, namespace, etc.).

        Returns:
            Serialised ContractListResponse dict.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get("/internal/v1/contracts", params=params)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.sbom.list_contracts_failed", error=str(exc))
            raise ServiceUnavailableError("SBOM service is unreachable.") from exc
        return self._handle_response(resp, "list_contracts")


# ---------------------------------------------------------------------------
# CausalEngineClient
# ---------------------------------------------------------------------------


class CausalEngineClient:
    """Async HTTP client for the causal engine internal API.

    All methods raise ServiceUnavailableError on network failures and
    ResourceNotFoundError on 404 responses.

    Args:
        base_url: Base URL of the causal engine. Defaults to CAUSAL_ENGINE_URL env var.
    """

    def __init__(self, base_url: str | None = None) -> None:
        """Initialise the client with a base URL.

        Args:
            base_url: Override base URL; defaults to environment variable.
        """
        self._base_url = base_url or _causal_engine_url()
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_HTTPX_TIMEOUT,
            headers={"X-Internal-Caller": "api-gateway"},
        )

    async def __aenter__(self) -> CausalEngineClient:
        """Enter async context manager.

        Returns:
            Self.
        """
        return self

    async def __aexit__(self, *args: Any) -> None:  # noqa: ANN401
        """Exit async context manager.

        Args:
            *args: Exception info (ignored).
        """
        await self._client.aclose()

    def _handle_response(self, response: httpx.Response, context: str) -> dict[str, Any]:
        """Raise appropriate exceptions based on HTTP response status.

        Args:
            response: The httpx response object.
            context: Human-readable context string for error messages.

        Returns:
            Parsed JSON response dict on success.

        Raises:
            ResourceNotFoundError: On 404.
            ServiceUnavailableError: On non-2xx responses.
        """
        if response.status_code == 404:
            raise ResourceNotFoundError(f"{context}: resource not found upstream.")
        if not response.is_success:
            log.warning(
                "service_client.causal.upstream_error",
                context=context,
                status_code=response.status_code,
                body=response.text[:256],
            )
            raise ServiceUnavailableError(
                f"{context}: upstream returned {response.status_code}."
            )
        return response.json()  # type: ignore[no-any-return]

    async def get_bdg_node(
        self, node_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch a single BDG node by ID.

        Args:
            node_id: UUID of the BDG node.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised BDG node dict.

        Raises:
            ResourceNotFoundError: If the node does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/bdg/nodes/{node_id}",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.causal.get_bdg_node_failed",
                node_id=str(node_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, f"get_bdg_node({node_id})")

    async def get_bdg_edge(
        self, edge_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch a single BDG edge by ID.

        Args:
            edge_id: UUID of the BDG edge.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised BDG edge dict.

        Raises:
            ResourceNotFoundError: If the edge does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/bdg/edges/{edge_id}",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.causal.get_bdg_edge_failed",
                edge_id=str(edge_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, f"get_bdg_edge({edge_id})")

    async def query_subgraph(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a subgraph query against the BDG.

        Args:
            payload: Serialised subgraph query dict.

        Returns:
            Serialised subgraph response dict.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post(
                "/internal/v1/bdg/subgraphs:query", json=payload
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.causal.query_subgraph_failed", error=str(exc))
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, "query_subgraph")

    async def submit_attribution(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit a causal attribution job to the causal engine.

        Args:
            payload: Serialised AttributionRequest dict.

        Returns:
            Serialised AttributionJobResponse dict.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post(
                "/internal/v1/attributions", json=payload
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.causal.submit_attribution_failed", error=str(exc))
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, "submit_attribution")

    async def get_attribution(
        self, attribution_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Fetch the current state of an attribution job.

        Args:
            attribution_id: UUID of the attribution job.
            tenant_id: Tenant UUID for scoping.

        Returns:
            Serialised AttributionResultResponse dict.

        Raises:
            ResourceNotFoundError: If the job does not exist.
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.get(
                f"/internal/v1/attributions/{attribution_id}",
                params={"tenant_id": str(tenant_id)},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning(
                "service_client.causal.get_attribution_failed",
                attribution_id=str(attribution_id),
                error=str(exc),
            )
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, f"get_attribution({attribution_id})")

    async def submit_pceps_score(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit a PCEPS scoring request to the causal engine.

        Args:
            payload: Serialised PcepsScoreRequest dict.

        Returns:
            Serialised PcepsScoreResponse dict.

        Raises:
            ServiceUnavailableError: On network or upstream errors.
        """
        try:
            resp = await self._client.post(
                "/internal/v1/pceps:scores", json=payload
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("service_client.causal.submit_pceps_failed", error=str(exc))
            raise ServiceUnavailableError("Causal engine is unreachable.") from exc
        return self._handle_response(resp, "submit_pceps_score")
