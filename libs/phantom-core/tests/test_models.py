"""
Tests for phantom_core.models — validates Pydantic model construction,
validation constraints, and rejection of unknown fields.

Each API contract section (B.2–B.9) has a corresponding test group.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from phantom_core.models.attribution import (
    AttributionRequest,
    CovariateSpec,
    OutcomeSpec,
    TreatmentSpec,
)
from phantom_core.models.bdg import (
    SubgraphQueryRequest,
)
from phantom_core.models.common import (
    ErrorResponse,
    HealthResponse,
    PaginationParams,
    ReadinessResponse,
)
from phantom_core.models.contracts import (
    ContractLookupQuery,
    NetworkDestination,
)
from phantom_core.models.drift import (
    ContractViolation,
    DriftEventIngestRequest,
    ProcessIdentity,
    RuntimeEvidence,
    WorkloadIdentity,
)
from phantom_core.models.incidents import (
    IncidentCreateRequest,
    IncidentUpdateRequest,
)
from phantom_core.models.sbom import (
    SbomIngestRequest,
)
from phantom_core.models.websocket import (
    DriftStreamSubscribe,
    LiveDriftEvent,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=UTC)
_UUID = uuid.uuid4()
_DIGEST = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# B.1 Common models
# ---------------------------------------------------------------------------


class TestErrorResponse:
    """Tests for the ErrorResponse model."""

    def test_valid_error_response(self) -> None:
        """Construct a valid ErrorResponse."""
        resp = ErrorResponse(
            error_code="VALIDATION_ERROR",
            message="invalid field",
            request_id=_UUID,
        )
        assert resp.schema_version == "v1"
        assert resp.error_code == "VALIDATION_ERROR"

    def test_rejects_unknown_fields(self) -> None:
        """ErrorResponse must reject unknown fields (extra='forbid')."""
        with pytest.raises(ValidationError):
            ErrorResponse(
                error_code="X",
                message="msg",
                request_id=_UUID,
                unknown_field="boom",  # type: ignore[call-arg]
            )


class TestPaginationParams:
    """Tests for PaginationParams."""

    def test_defaults(self) -> None:
        """Default limit is 50, cursor is None."""
        p = PaginationParams()
        assert p.limit == 50
        assert p.cursor is None

    def test_limit_out_of_range(self) -> None:
        """Limit outside 1..200 must be rejected."""
        with pytest.raises(ValidationError):
            PaginationParams(limit=0)
        with pytest.raises(ValidationError):
            PaginationParams(limit=201)


class TestHealthResponse:
    """Tests for HealthResponse."""

    def test_valid(self) -> None:
        """Construct a valid HealthResponse."""
        resp = HealthResponse(status="ok", service="test", timestamp=_NOW)
        assert resp.status == "ok"


class TestReadinessResponse:
    """Tests for ReadinessResponse."""

    def test_valid(self) -> None:
        """Construct a valid ReadinessResponse."""
        resp = ReadinessResponse(
            status="ready",
            service="test",
            checks={"postgres": "pass", "redis": "pass"},
            timestamp=_NOW,
        )
        assert resp.status == "ready"


# ---------------------------------------------------------------------------
# B.2 SBOM models
# ---------------------------------------------------------------------------


class TestSbomIngestRequest:
    """Tests for SbomIngestRequest."""

    def test_valid_syft_source(self) -> None:
        """Construct a valid SBOM ingest request with syft source."""
        req = SbomIngestRequest(
            image_digest=_DIGEST,
            artifact_uri="https://example.com/sbom.json",  # type: ignore[arg-type]
            cyclonedx_document={"bomFormat": "CycloneDX"},
            declared_sbom_digest=_DIGEST,
            source="syft",
            generated_at=_NOW,
            tenant_id=_UUID,
        )
        assert req.schema_version == "v1"

    def test_external_requires_signature(self) -> None:
        """External source must provide signature_bundle_uri."""
        with pytest.raises(ValidationError, match="signature_bundle_uri"):
            SbomIngestRequest(
                image_digest=_DIGEST,
                artifact_uri="https://example.com/sbom.json",  # type: ignore[arg-type]
                cyclonedx_document={"bomFormat": "CycloneDX"},
                declared_sbom_digest=_DIGEST,
                source="external",
                generated_at=_NOW,
                tenant_id=_UUID,
            )

    def test_invalid_digest(self) -> None:
        """Invalid digest format must be rejected."""
        with pytest.raises(ValidationError, match="Digest"):
            SbomIngestRequest(
                image_digest="not-a-digest",
                artifact_uri="https://example.com/sbom.json",  # type: ignore[arg-type]
                cyclonedx_document={"bomFormat": "CycloneDX"},
                declared_sbom_digest=_DIGEST,
                source="syft",
                generated_at=_NOW,
                tenant_id=_UUID,
            )


# ---------------------------------------------------------------------------
# B.3 Contract models
# ---------------------------------------------------------------------------


class TestNetworkDestination:
    """Tests for NetworkDestination."""

    def test_valid_ipv4_cidr(self) -> None:
        """Construct with a valid IPv4 CIDR."""
        nd = NetworkDestination(
            protocol="tcp", cidr="10.0.0.0/8", port_min=80, port_max=443
        )
        assert nd.cidr == "10.0.0.0/8"

    def test_invalid_port_range(self) -> None:
        """port_max < port_min must be rejected."""
        with pytest.raises(ValidationError, match="port_max"):
            NetworkDestination(
                protocol="tcp", cidr="10.0.0.0/8", port_min=443, port_max=80
            )

    def test_invalid_cidr(self) -> None:
        """Invalid CIDR notation must be rejected."""
        with pytest.raises(ValidationError, match="CIDR"):
            NetworkDestination(
                protocol="tcp", cidr="not-a-cidr", port_min=80, port_max=80
            )


class TestContractLookupQuery:
    """Tests for ContractLookupQuery."""

    def test_requires_at_least_one_filter(self) -> None:
        """Empty filter set must be rejected."""
        with pytest.raises(ValidationError, match="At least one"):
            ContractLookupQuery()


# ---------------------------------------------------------------------------
# B.4 Drift models
# ---------------------------------------------------------------------------


class TestDriftEventIngestRequest:
    """Tests for DriftEventIngestRequest."""

    def _build_valid_request(self) -> DriftEventIngestRequest:
        """Build a minimal valid DriftEventIngestRequest."""
        return DriftEventIngestRequest(
            event_id=_UUID,
            observed_at=_NOW,
            node_name="node-1",
            event_type="exec",
            process=ProcessIdentity(
                pid=1, tgid=1, ppid=0, uid=0, gid=0,
                comm="bash", executable_path="/bin/bash", start_time_ns=0,
            ),
            workload=WorkloadIdentity(
                cluster_name="cluster",
                namespace="default",
                pod_name="pod-1",
                pod_uid=_UUID,
                container_name="main",
                container_id="abc123",
                image_digest=_DIGEST,
                cgroup_id=42,
            ),
            identity_status="resolved",
            violations=[
                ContractViolation(
                    violation_type="unexpected_executable",
                    observed="/usr/bin/evil",
                    severity="high",
                    confidence=0.95,
                ),
            ],
            evidence=RuntimeEvidence(
                kernel_timestamp_ns=123456789,
                cpu=0,
                architecture="x86_64",
                event_loss_observed=False,
                raw_event_digest=_DIGEST,
            ),
            agent_sequence=0,
            tenant_id=_UUID,
        )

    def test_valid_request(self) -> None:
        """Construct a valid drift event ingest request."""
        req = self._build_valid_request()
        assert req.schema_version == "v1"
        assert len(req.violations) == 1

    def test_empty_violations_rejected(self) -> None:
        """violations list must have at least 1 item."""
        with pytest.raises(ValidationError):
            DriftEventIngestRequest(
                event_id=_UUID,
                observed_at=_NOW,
                node_name="node-1",
                event_type="exec",
                process=ProcessIdentity(
                    pid=1, tgid=1, ppid=0, uid=0, gid=0,
                    comm="bash", executable_path="/bin/bash", start_time_ns=0,
                ),
                workload=WorkloadIdentity(
                    cluster_name="cluster",
                    namespace="default",
                    pod_name="pod-1",
                    pod_uid=_UUID,
                    container_name="main",
                    container_id="abc123",
                    image_digest=_DIGEST,
                    cgroup_id=42,
                ),
                identity_status="resolved",
                violations=[],
                evidence=RuntimeEvidence(
                    kernel_timestamp_ns=0,
                    cpu=0,
                    architecture="x86_64",
                    event_loss_observed=False,
                    raw_event_digest=_DIGEST,
                ),
                agent_sequence=0,
                tenant_id=_UUID,
            )


# ---------------------------------------------------------------------------
# B.5 BDG models
# ---------------------------------------------------------------------------


class TestSubgraphQueryRequest:
    """Tests for SubgraphQueryRequest."""

    def test_time_bounds_inverted(self) -> None:
        """observed_before <= observed_after must be rejected."""
        with pytest.raises(ValidationError, match="observed_before"):
            SubgraphQueryRequest(
                root_node_ids=[_UUID],
                max_hops=2,
                observed_after=_NOW,
                observed_before=_NOW,
                max_nodes=100,
            )


# ---------------------------------------------------------------------------
# B.6–B.7 Attribution / PCEPS
# ---------------------------------------------------------------------------


class TestAttributionRequest:
    """Tests for AttributionRequest."""

    def test_valid(self) -> None:
        """Construct a valid attribution request."""
        req = AttributionRequest(
            snapshot_id=_UUID,
            drift_event_id=_UUID,
            treatment=TreatmentSpec(
                variable="treatment_var",
                observed_value=1,
                source_node_ids=[_UUID],
            ),
            outcome=OutcomeSpec(
                variable="runtime_sbom_drift",
                observed_value=1,
                target_node_ids=[_UUID],
            ),
            covariates=[
                CovariateSpec(
                    variable="cov_1",
                    source="workload",
                    observed_value=1.0,
                ),
            ],
            estimator="backdoor.linear_regression",
            counterfactual_treatment_value=0,
            tenant_id=_UUID,
        )
        assert req.schema_version == "v1"


# ---------------------------------------------------------------------------
# B.8 Incident models
# ---------------------------------------------------------------------------


class TestIncidentCreateRequest:
    """Tests for IncidentCreateRequest."""

    def test_valid(self) -> None:
        """Construct a valid incident create request."""
        req = IncidentCreateRequest(
            title="Test incident",
            summary="Something happened",
            drift_event_ids=[_UUID],
            snapshot_id=_UUID,
            classification="untriaged",
            tenant_id=_UUID,
        )
        assert req.schema_version == "v1"

    def test_tag_length_validation(self) -> None:
        """Tags longer than 64 chars must be rejected."""
        with pytest.raises(ValidationError, match="tag"):
            IncidentCreateRequest(
                title="Test",
                summary="Summary",
                drift_event_ids=[_UUID],
                snapshot_id=_UUID,
                classification="untriaged",
                tags=["x" * 65],
                tenant_id=_UUID,
            )


class TestIncidentUpdateRequest:
    """Tests for IncidentUpdateRequest."""

    def test_requires_at_least_one_field(self) -> None:
        """Update with no mutable fields must be rejected."""
        with pytest.raises(ValidationError, match="mutable field"):
            IncidentUpdateRequest(expected_revision=1)


# ---------------------------------------------------------------------------
# B.9 WebSocket models
# ---------------------------------------------------------------------------


class TestDriftStreamSubscribe:
    """Tests for DriftStreamSubscribe."""

    def test_valid(self) -> None:
        """Construct a valid subscription message."""
        sub = DriftStreamSubscribe(
            type="subscribe",
            minimum_severity="low",
        )
        assert sub.schema_version == "v1"
        assert sub.namespace_filters == []


class TestLiveDriftEvent:
    """Tests for LiveDriftEvent."""

    def test_valid(self) -> None:
        """Construct a valid live drift event."""
        evt = LiveDriftEvent(
            type="drift_event",
            stream_event_id=_UUID,
            published_at=_NOW,
            drift_event_id=_UUID,
            event_type="exec",
            severity="high",
            identity_status="resolved",
            violation_types=["unexpected_executable"],
        )
        assert evt.pceps_score is None
