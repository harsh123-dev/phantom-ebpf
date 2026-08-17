"""
phantom_core.models.incidents — Pydantic models for incident report API contracts (B.8).

Covers:
- IncidentCreateRequest: POST /api/v1/incidents
- IncidentReport: response record
- IncidentDetailResponse: GET /api/v1/incidents/{incident_id}
- IncidentListQuery: GET /api/v1/incidents query params
- IncidentListResponse: GET /api/v1/incidents response
- IncidentUpdateRequest: PATCH /api/v1/incidents/{incident_id}
- IncidentArchiveResponse: DELETE /api/v1/incidents/{incident_id}
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from phantom_core.constants import (
    INCIDENT_ATTRIBUTION_IDS_MAX,
    INCIDENT_DRIFT_EVENT_IDS_MAX,
    INCIDENT_DRIFT_EVENT_IDS_MIN,
    INCIDENT_RESOLUTION_NOTES_MAX_LENGTH,
    INCIDENT_SCORE_IDS_MAX,
    INCIDENT_SUMMARY_MAX_LENGTH,
    INCIDENT_SUMMARY_MIN_LENGTH,
    INCIDENT_TAG_MAX_LENGTH,
    INCIDENT_TAG_MIN_LENGTH,
    INCIDENT_TAGS_MAX,
    INCIDENT_TITLE_MAX_LENGTH,
    INCIDENT_TITLE_MIN_LENGTH,
    SCHEMA_VERSION,
)
from phantom_core.models.common import _PhantomBaseModel

# ---------------------------------------------------------------------------
# Literal type aliases
# ---------------------------------------------------------------------------

IncidentStatus = Literal["draft", "open", "resolved", "archived"]

IncidentClassification = Literal["untriaged", "benign", "suspicious", "confirmed"]


# ---------------------------------------------------------------------------
# POST /api/v1/incidents
# ---------------------------------------------------------------------------


class IncidentCreateRequest(_PhantomBaseModel):
    """Request body for ``POST /api/v1/incidents``.

    Attributes:
        schema_version: Always ``"v1"``.
        title: Incident title; 1..240 characters.
        summary: Analyst summary; 1..8000 characters.
        drift_event_ids: UUIDs of associated drift events; 1..1000 items.
        attribution_ids: UUIDs of associated attribution jobs; max 1000.
        score_ids: UUIDs of associated PCEPS scores; max 1000.
        snapshot_id: UUID of the BDG snapshot used as forensic evidence anchor.
        classification: Analyst-assigned classification.
        tags: Categorical labels; max 32, each 1..64 characters.
        tenant_id: Logical isolation key.
    """

    schema_version: Literal["v1"] = SCHEMA_VERSION  # type: ignore[assignment]
    title: str = Field(
        ..., min_length=INCIDENT_TITLE_MIN_LENGTH, max_length=INCIDENT_TITLE_MAX_LENGTH
    )
    summary: str = Field(
        ..., min_length=INCIDENT_SUMMARY_MIN_LENGTH, max_length=INCIDENT_SUMMARY_MAX_LENGTH
    )
    drift_event_ids: list[uuid.UUID] = Field(
        ...,
        min_length=INCIDENT_DRIFT_EVENT_IDS_MIN,
        max_length=INCIDENT_DRIFT_EVENT_IDS_MAX,
    )
    attribution_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=INCIDENT_ATTRIBUTION_IDS_MAX
    )
    score_ids: list[uuid.UUID] = Field(default_factory=list, max_length=INCIDENT_SCORE_IDS_MAX)
    snapshot_id: uuid.UUID
    classification: IncidentClassification
    tags: list[str] = Field(
        default_factory=list,
        max_length=INCIDENT_TAGS_MAX,
    )
    tenant_id: uuid.UUID

    @model_validator(mode="after")
    def _validate_tags(self) -> IncidentCreateRequest:
        """Validate individual tag lengths.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If any tag violates length constraints.
        """
        for tag in self.tags:
            if not (INCIDENT_TAG_MIN_LENGTH <= len(tag) <= INCIDENT_TAG_MAX_LENGTH):
                raise ValueError(
                    f"Each tag must be {INCIDENT_TAG_MIN_LENGTH}..{INCIDENT_TAG_MAX_LENGTH} "
                    f"characters, got {tag!r} (length {len(tag)})"
                )
        return self


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class IncidentReport(_PhantomBaseModel):
    """Incident report record returned from create, get, update, and list endpoints.

    Attributes:
        incident_id: Immutable UUID of this incident.
        revision: Monotonically increasing revision counter; >= 1.
        status: Lifecycle status.
        title: Incident title.
        summary: Analyst summary.
        classification: Analyst-assigned classification.
        evidence_hash: sha256 digest over the canonical evidence ID set.
        created_by: Principal identifier of the analyst who created this report.
        created_at: UTC timestamp when the report was created.
        updated_at: UTC timestamp of the most recent revision.
    """

    incident_id: uuid.UUID
    revision: int = Field(..., ge=1)
    status: IncidentStatus
    title: str
    summary: str
    classification: IncidentClassification
    evidence_hash: str
    created_by: str = Field(..., min_length=1)
    created_at: datetime
    updated_at: datetime


class IncidentDetailResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/incidents/{incident_id}``.

    Attributes:
        report: The embedded IncidentReport.
        drift_event_ids: Immutable forensic drift event UUIDs.
        attribution_ids: Immutable forensic attribution UUIDs.
        score_ids: Immutable forensic PCEPS score UUIDs.
        snapshot_id: UUID of the forensic BDG snapshot.
        tags: Current tag list.
        resolution_notes: Analyst resolution notes; None if not yet resolved.
        archived_at: UTC timestamp of archiving; None if not archived.
    """

    report: IncidentReport
    drift_event_ids: list[uuid.UUID]
    attribution_ids: list[uuid.UUID]
    score_ids: list[uuid.UUID]
    snapshot_id: uuid.UUID
    tags: list[str]
    resolution_notes: str | None = None
    archived_at: datetime | None = None


class IncidentListQuery(_PhantomBaseModel):
    """Query parameters for ``GET /api/v1/incidents``.

    Attributes:
        status: Filter by lifecycle status.
        classification: Filter by analyst classification.
        created_after: Filter for incidents created after this UTC timestamp.
        created_before: Filter for incidents created before this UTC timestamp.
        limit: Maximum items to return; 1..200.
        cursor: Opaque pagination cursor.
    """

    status: IncidentStatus | None = None
    classification: IncidentClassification | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = None

    @model_validator(mode="after")
    def _time_window_valid(self) -> IncidentListQuery:
        """Validate that created_before > created_after if both provided.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If the time window is inverted.
        """
        if (
            self.created_after is not None
            and self.created_before is not None
            and self.created_before <= self.created_after
        ):
            raise ValueError("created_before must be after created_after")
        return self


class IncidentListResponse(_PhantomBaseModel):
    """Response body for ``GET /api/v1/incidents``.

    Attributes:
        items: Page of incident reports.
        next_cursor: Opaque cursor for the next page; None if last page.
    """

    items: list[IncidentReport]
    next_cursor: str | None = None


class IncidentUpdateRequest(_PhantomBaseModel):
    """Request body for ``PATCH /api/v1/incidents/{incident_id}``.

    At least one mutable field must be provided.

    Attributes:
        expected_revision: Optimistic concurrency revision; must match current.
        title: Updated title; 1..240 characters. None = no change.
        summary: Updated summary; 1..8000 characters. None = no change.
        classification: Updated classification. None = no change.
        status: Updated lifecycle status. None = no change.
        tags: Replacement tag list. None = no change.
        resolution_notes: Updated resolution notes; max 8000 characters. None = no change.
    """

    expected_revision: int = Field(..., ge=1)
    title: str | None = Field(
        default=None,
        min_length=INCIDENT_TITLE_MIN_LENGTH,
        max_length=INCIDENT_TITLE_MAX_LENGTH,
    )
    summary: str | None = Field(
        default=None,
        min_length=INCIDENT_SUMMARY_MIN_LENGTH,
        max_length=INCIDENT_SUMMARY_MAX_LENGTH,
    )
    classification: IncidentClassification | None = None
    status: IncidentStatus | None = None
    tags: list[str] | None = None
    resolution_notes: str | None = Field(
        default=None, max_length=INCIDENT_RESOLUTION_NOTES_MAX_LENGTH
    )

    @model_validator(mode="after")
    def _at_least_one_mutable_field(self) -> IncidentUpdateRequest:
        """Require at least one mutable field to be non-None.

        Returns:
            The validated model instance.

        Raises:
            ValueError: If no mutable field is provided.
        """
        mutable_fields = [
            self.title,
            self.summary,
            self.classification,
            self.status,
            self.tags,
            self.resolution_notes,
        ]
        if all(f is None for f in mutable_fields):
            raise ValueError(
                "At least one mutable field must be provided in an update request"
            )
        return self


class IncidentArchiveResponse(_PhantomBaseModel):
    """Response body for ``DELETE /api/v1/incidents/{incident_id}``.

    Forensic evidence is never deleted; this is a soft archive only.

    Attributes:
        incident_id: UUID of the archived incident.
        status: Always ``"archived"``.
        archived_at: UTC timestamp of the archive operation.
        revision: Final revision number after archiving.
    """

    incident_id: uuid.UUID
    status: Literal["archived"]
    archived_at: datetime
    revision: int = Field(..., ge=1)
