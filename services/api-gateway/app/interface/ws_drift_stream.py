"""
api-gateway WebSocket drift stream endpoint.

Implements:
  GET /api/v1/streams/drift  (WebSocket upgrade)

Authenticates via bearer token during handshake, enforces tenant
scope, delivers tenant-filtered live drift notifications after
durable acceptance. Supports resume-after-event-id semantics.

Close codes:
  4401  WS_CLOSE_UNAUTHENTICATED  — no valid token
  4403  WS_CLOSE_UNAUTHORIZED     — valid token, insufficient role
  4408  WS_CLOSE_INVALID_SUBSCRIPTION — malformed subscribe message
  1013  WS_CLOSE_OVERLOADED       — server overloaded / backpressure
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import fastapi
import structlog
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
from phantom_core.constants import (
    WS_CLOSE_INVALID_SUBSCRIPTION,
    WS_CLOSE_UNAUTHENTICATED,
    WS_CLOSE_UNAUTHORIZED,
    WS_NAMESPACE_FILTERS_MAX,
)

from app.infrastructure.redis_publisher import subscribe_drift_stream

router = fastapi.APIRouter(tags=["WebSocket"])
log: structlog.BoundLogger = structlog.get_logger(__name__)

# Keepalive interval in seconds.
_PING_INTERVAL_SECONDS = 30


async def _authenticate_ws(
    websocket: WebSocket, token: str | None
) -> tuple[uuid.UUID, str] | None:
    """Authenticate a WebSocket connection via a bearer token query parameter.

    Args:
        websocket: The WebSocket connection.
        token: Bearer token string from the query parameter.

    Returns:
        Tuple of (tenant_id, user_id) on success, None on auth failure.
    """
    import os

    if not token:
        await websocket.close(code=WS_CLOSE_UNAUTHENTICATED, reason="missing token")
        return None

    # Dev bypass: when AUTH_BYPASS_ENABLED=true, accept the bypass token without
    # verifying against a real JWKS server. NEVER enable in production.
    _bypass_enabled = os.environ.get("AUTH_BYPASS_ENABLED", "").lower() in ("1", "true", "yes")
    _bypass_token = os.environ.get("AUTH_BYPASS_TOKEN", "dev-bypass-token-for-local-testing")
    if _bypass_enabled and token == _bypass_token:
        log.info("ws_drift_stream.bypass_token_accepted")
        from app.domain.entities import PhantomRole
        return (
            uuid.UUID("00000000-0000-0000-0000-000000000001"),
            "dev-user",
        )

    try:
        from app.domain.entities import PhantomRole
        from app.infrastructure.auth_adapter import verify_jwt
        from app.infrastructure.auth_settings import get_auth_settings

        settings = get_auth_settings()
        principal = verify_jwt(token, settings)

        # Require AGENT or VIEWER or ANALYST or ADMIN for stream access.
        allowed_roles = {
            PhantomRole.AGENT,
            PhantomRole.VIEWER,
            PhantomRole.ANALYST,
            PhantomRole.ADMIN,
        }
        if not principal.roles.intersection(allowed_roles):
            await websocket.close(
                code=WS_CLOSE_UNAUTHORIZED, reason="insufficient role"
            )
            return None

        return principal.tenant_id, principal.user_id

    except Exception as exc:
        log.info("ws_drift_stream.auth_failed", error=str(exc))
        await websocket.close(code=WS_CLOSE_UNAUTHENTICATED, reason="invalid token")
        return None


async def _send_ping(websocket: WebSocket) -> None:
    """Send a ping control frame to keep the connection alive.

    Args:
        websocket: The WebSocket connection.
    """
    try:
        await websocket.send_text(json.dumps({"type": "ping"}))
    except Exception:
        pass


@router.websocket("/api/v1/streams/drift")
async def drift_stream(
    websocket: WebSocket,
    token: str | None = None,
) -> None:
    """WebSocket endpoint for real-time drift event streaming.

    Authentication is performed via the ``token`` query parameter before
    the connection is accepted. After authentication, the client must send
    a ``DriftStreamSubscribe`` message.  The server then streams
    ``LiveDriftEvent`` messages as they arrive from the Redis Pub/Sub channel.

    Close codes sent by the server:
    - 4401: Missing or invalid token.
    - 4403: Valid token but insufficient role.
    - 4408: Malformed or missing subscribe message.
    - 1013: Server overloaded (backpressure).

    Args:
        websocket: The WebSocket connection.
        token: Bearer token for authentication (query parameter).
    """
    await websocket.accept()

    # Authenticate.
    auth_result = await _authenticate_ws(websocket, token)
    if auth_result is None:
        return

    tenant_id, user_id = auth_result
    log.info(
        "ws_drift_stream.connected",
        tenant_id=str(tenant_id),
    )

    # Receive subscription message (first client message after accept).
    try:
        raw_sub = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        subscribe_msg: dict[str, Any] = json.loads(raw_sub)
    except (TimeoutError, json.JSONDecodeError, Exception) as exc:
        log.info("ws_drift_stream.bad_subscribe", error=str(exc))
        await websocket.close(
            code=WS_CLOSE_INVALID_SUBSCRIPTION, reason="invalid subscribe message"
        )
        return

    # Parse subscription parameters.
    namespace_filters: list[str] = subscribe_msg.get("namespace_filters") or []
    min_severity: str | None = subscribe_msg.get("min_severity")
    resume_after: str | None = subscribe_msg.get("resume_after")

    # Validate namespace_filters count.
    if len(namespace_filters) > WS_NAMESPACE_FILTERS_MAX:
        await websocket.close(
            code=WS_CLOSE_INVALID_SUBSCRIPTION,
            reason=f"namespace_filters exceeds max {WS_NAMESPACE_FILTERS_MAX}",
        )
        return

    # Send subscription acknowledgment.
    await websocket.send_text(
        json.dumps({"type": "subscribed", "tenant_id": str(tenant_id)})
    )

    redis = websocket.app.state.redis

    # Start ping/pong keepalive task.
    async def keepalive() -> None:
        """Periodic ping to maintain the WebSocket connection."""
        while True:
            await asyncio.sleep(_PING_INTERVAL_SECONDS)
            if websocket.client_state != WebSocketState.CONNECTED:
                break
            await _send_ping(websocket)

    ping_task = asyncio.create_task(keepalive())

    try:
        async for event in subscribe_drift_stream(
            redis,
            tenant_id,
            namespace_filters=namespace_filters or None,
            min_severity=min_severity,
            resume_after=resume_after,
        ):
            if websocket.client_state != WebSocketState.CONNECTED:
                break

            message = {
                "type": "drift_event",
                "data": event,
            }
            try:
                await websocket.send_text(json.dumps(message, default=str))
            except WebSocketDisconnect:
                break
            except Exception as exc:
                log.warning(
                    "ws_drift_stream.send_failed",
                    tenant_id=str(tenant_id),
                    error=str(exc),
                )
                break

    except WebSocketDisconnect:
        log.info("ws_drift_stream.client_disconnected", tenant_id=str(tenant_id))
    except Exception as exc:
        log.warning(
            "ws_drift_stream.error",
            tenant_id=str(tenant_id),
            error=str(exc),
        )
    finally:
        ping_task.cancel()
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close()
            except Exception:
                pass
        log.info("ws_drift_stream.disconnected", tenant_id=str(tenant_id))
