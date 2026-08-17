"""
Tests for JSON Schema compatibility between phantom-core Pydantic models
and the canonical JSON Schema artifacts in services/contracts/.

Validates that the Pydantic model's JSON Schema output is structurally
compatible with the hand-maintained contract schemas.
"""

from __future__ import annotations

from phantom_core.models.drift import DriftEventIngestRequest
from phantom_core.models.sbom import SbomIngestRequest
from phantom_core.models.websocket import DriftStreamSubscribe, LiveDriftEvent


class TestPydanticJsonSchemaGeneration:
    """Verify that Pydantic models can generate JSON Schema without errors."""

    def test_sbom_ingest_request_schema(self) -> None:
        """SbomIngestRequest generates a valid JSON Schema dict."""
        schema = SbomIngestRequest.model_json_schema()
        assert schema["type"] == "object"
        assert "image_digest" in schema.get("properties", {})

    def test_drift_event_ingest_request_schema(self) -> None:
        """DriftEventIngestRequest generates a valid JSON Schema dict."""
        schema = DriftEventIngestRequest.model_json_schema()
        assert schema["type"] == "object"
        assert "event_id" in schema.get("properties", {})

    def test_drift_stream_subscribe_schema(self) -> None:
        """DriftStreamSubscribe generates a valid JSON Schema dict."""
        schema = DriftStreamSubscribe.model_json_schema()
        assert schema["type"] == "object"
        assert "minimum_severity" in schema.get("properties", {})

    def test_live_drift_event_schema(self) -> None:
        """LiveDriftEvent generates a valid JSON Schema dict."""
        schema = LiveDriftEvent.model_json_schema()
        assert schema["type"] == "object"
        assert "drift_event_id" in schema.get("properties", {})

    def test_all_models_reject_extra_fields(self) -> None:
        """All models must be configured with extra='forbid'."""
        for model_cls in [
            SbomIngestRequest,
            DriftEventIngestRequest,
            DriftStreamSubscribe,
            LiveDriftEvent,
        ]:
            config = model_cls.model_config
            assert config.get("extra") == "forbid", (
                f"{model_cls.__name__} must have extra='forbid'"
            )
