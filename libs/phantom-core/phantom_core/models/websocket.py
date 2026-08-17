"""
phantom_core.models.websocket — Pydantic models for WebSocket API contracts (B.9).

Covers:
- DriftStreamSubscribe: client subscription message
- LiveDriftEvent: server-sent drift notification message
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from phantom_core.constants import (
    SCHEMA_VERSION,
    WS_NAMESPACE_FILTERS_MAX,
)
from phantom_core.models.common import _PhantomBaseModel
from phantom_core.models.drift import IdentityStatus, RuntimeEventType, SeverityLevel

# ---------------------------------------------------------------------------
# Client → server
# ---------------------------------------------------------------------------


class DriftStreamSubscribe(_PhantomBaseModel):
    """WebSocket client subscription message for the drift stream.

    Sent immediately after the handshake to configure the tenant-scoped
    drift event filter. The server MUST reject connections that send an
    invalid subscription payload (close code 4408).

    Attributes:
        schema_version: Always ``"v1"``.
        type: Always ``"subscribe"``.
        namespace_filters: Optional namespace scoping; max 64 entries.
            Empty list means all namespaces visible to the tenant.
        minimum_severity: Minimum severity threshold for delivered events.
        resume_after_event_id: Resume delivery after this drift_event_id,
            enabling reconnection without loss. None = deliver from now.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    type: Literal["subscribe"]
    namespace_filters: list[str] = Field(
        default_factory=list,
        max_length=WS_NAMESPACE_FILTERS_MAX,
    )
    minimum_severity: SeverityLevel
    resume_after_event_id: uuid.UUID | None = None


# ---------------------------------------------------------------------------
# Server → client
# ---------------------------------------------------------------------------


class LiveDriftEvent(_PhantomBaseModel):
    """WebSocket server-sent live drift event notification.

    Delivered only after the drift event has been durably accepted
    by the gateway transactional outbox. The ``stream_event_id`` is
    unique per WebSocket message and may differ from ``drift_event_id``
    if multiple WebSocket connections receive the same logical event.

    Attributes:
        schema_version: Always ``"v1"``.
        type: Always ``"drift_event"``.
        stream_event_id: Unique UUID for this WebSocket delivery.
        published_at: UTC timestamp when this message was published.
        drift_event_id: UUID of the underlying drift event record.
        event_type: Runtime event category.
        severity: Severity level of the most severe violation.
        namespace: Pod namespace; None if identity is missing.
        pod_name: Pod name; None if identity is missing.
        image_digest: Container image digest; None if identity is missing.
        identity_status: Quality of the workload identity resolution.
        violation_types: List of violation type strings observed.
        attribution_id: UUID of an associated attribution job; None if not yet run.
        pceps_score: PCEPS priority score [0, 100]; None if not yet scored.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    type: Literal["drift_event"]
    stream_event_id: uuid.UUID
    published_at: datetime
    drift_event_id: uuid.UUID
    event_type: RuntimeEventType
    severity: SeverityLevel
    namespace: str | None = None
    pod_name: str | None = None
    image_digest: str | None = None
    identity_status: IdentityStatus
    violation_types: list[str]
    attribution_id: uuid.UUID | None = None
    pceps_score: float | None = Field(default=None, ge=0.0, le=100.0)
