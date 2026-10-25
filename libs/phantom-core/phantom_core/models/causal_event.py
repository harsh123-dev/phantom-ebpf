"""Versioned Redis contract between drift ingestion and the causal engine."""
from __future__ import annotations

import uuid
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from phantom_core.models.common import _PhantomBaseModel

CAUSAL_EVENT_STREAM = "phantom:drift-events"
CAUSAL_EVENT_SCHEMA_VERSION = "1.0"


class CausalSbomBindingV1(_PhantomBaseModel):
    """Resolver result with mandatory provenance for positive attribution."""

    binding_status: Literal["bound", "ambiguous", "unbound", "insufficient_evidence"]
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sbom_id: uuid.UUID | None = None
    purl: str | None = Field(default=None, min_length=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    resolver_version: str = Field(min_length=1)
    method: str = Field(min_length=1)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    candidate_purls: list[str] = Field(default_factory=list)
    reason: str | None = None

    @model_validator(mode="after")
    def require_positive_binding_provenance(self) -> "CausalSbomBindingV1":
        if self.binding_status == "bound" and (
            self.sbom_id is None or self.purl is None or self.confidence is None
        ):
            raise ValueError("bound status requires sbom_id, purl, and confidence")
        if self.binding_status == "bound" and self.confidence <= 0:
            raise ValueError("bound status requires positive evidence confidence")
        if self.binding_status == "bound" and not self.evidence:
            raise ValueError("bound status requires mapping evidence")
        if self.binding_status != "bound" and (self.purl is not None or self.confidence is not None):
            raise ValueError("non-bound status cannot assert a PURL or confidence")
        if self.binding_status != "bound" and not self.reason:
            raise ValueError("non-bound status requires an explicit reason")
        if self.binding_status == "ambiguous" and len(self.candidate_purls) < 2:
            raise ValueError("ambiguous status requires at least two candidate PURLs")
        return self


class CausalEventV1(_PhantomBaseModel):
    """Durable, self-contained event; uncertainty is explicit in evidence fields."""

    schema_version: Literal["1.0"] = CAUSAL_EVENT_SCHEMA_VERSION
    event_id: uuid.UUID
    drift_event_id: uuid.UUID
    outbox_id: uuid.UUID
    tenant_id: uuid.UUID
    observed_at: datetime
    event_type: str = Field(min_length=1)
    cluster: str = Field(min_length=1)
    workload: dict[str, Any]
    process: dict[str, Any]
    runtime_evidence: dict[str, Any]
    sbom_binding: CausalSbomBindingV1 | None = None
    contract_violations: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("observed_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_runtime_evidence(self) -> "CausalEventV1":
        required = {
            "workload": ("namespace", "pod_uid", "container_id", "image_digest"),
            "process": ("tgid", "start_time_ns"),
            "runtime_evidence": ("raw_event_digest",),
        }
        for section, keys in required.items():
            values = getattr(self, section)
            missing = [key for key in keys if values.get(key) in (None, "")]
            if missing:
                raise ValueError(f"{section} is missing required evidence: {', '.join(missing)}")
        if int(self.process["tgid"]) <= 0 or int(self.process["start_time_ns"]) < 0:
            raise ValueError("process identity values are invalid")
        digest = str(self.workload["image_digest"])
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("workload image_digest must be a sha256 digest")
        if self.sbom_binding and self.sbom_binding.image_digest != digest:
            raise ValueError("SBOM binding digest does not match workload image digest")
        return self
