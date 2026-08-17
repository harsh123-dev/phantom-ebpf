"""
tests/causal-engine/conftest.py

Shared pytest fixtures for causal-engine tests.

Provides:
- sample_bdg: a BehavioralDependencyGraph pre-populated with a small graph.
- sample_observations: causal observations for SCM construction.
- sample_feature_context: FeatureDerivationContext for PCEPS tests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domain.bdg import BehavioralDependencyGraph
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalObservation,
    CovariateSpec,
    OutcomeSpec,
    PcepsFeatureBaseline,
    RefutationResult,
    TreatmentSpec,
)
from app.domain.pceps.feature_extractor import FeatureDerivationContext

# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

_BASE_TIME: datetime = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
_TENANT_ID: str = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# BDG fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_bdg() -> BehavioralDependencyGraph:
    """A BDG pre-populated with a workload → container → process chain.

    Returns:
        A BehavioralDependencyGraph with nodes and edges.
    """
    bdg = BehavioralDependencyGraph(
        decay_lambda=0.95,
        decay_delta_seconds=300.0,
        batch_size=1000,  # High to avoid auto-snapshot during tests.
    )

    # Add a simple event stream.
    for i in range(5):
        event_time = _BASE_TIME + timedelta(minutes=i)
        bdg.update(
            event_id=uuid.uuid4(),
            event_type="exec" if i % 2 == 0 else "file_open",
            event_time=event_time,
            tenant_id=_TENANT_ID,
            cluster="test-cluster",
            namespace="test-ns",
            pod_uid="pod-uid-1",
            container_id="container-1",
            image_digest="sha256:abc123",
            tgid=1001,
            pid_start_time_ns=1_700_000_000_000_000_000,
            identity_confidence=0.9,
            binding_confidence=0.95,
            collector_confidence=1.0,
            binding_status="resolved",
            component_purl="pkg:pypi/requests@2.31.0",
            event_attrs={"resource_class": "/usr/lib/python3.11/abc.py"},
        )

    # Add a drift event.
    bdg.update(
        event_id=uuid.uuid4(),
        event_type="net_connect",
        event_time=_BASE_TIME + timedelta(minutes=10),
        tenant_id=_TENANT_ID,
        cluster="test-cluster",
        namespace="test-ns",
        pod_uid="pod-uid-1",
        container_id="container-1",
        image_digest="sha256:abc123",
        tgid=1001,
        pid_start_time_ns=1_700_000_000_000_000_000,
        identity_confidence=0.9,
        binding_confidence=0.95,
        collector_confidence=1.0,
        binding_status="resolved",
        component_purl="pkg:pypi/requests@2.31.0",
        contract_violations=[{
            "drift_event_id": str(uuid.uuid4()),
            "contract_id": str(uuid.uuid4()),
        }],
        event_attrs={
            "resource_class": "10.0.0.0/8",
            "protocol": "tcp",
            "port_class": "443",
        },
    )

    return bdg


# ---------------------------------------------------------------------------
# Causal observation fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_observations() -> list[CausalObservation]:
    """30 causal observation rows with variation in treatment and outcome.

    Returns:
        List of CausalObservation objects.
    """
    obs: list[CausalObservation] = []
    for i in range(30):
        treatment = 1 if i >= 15 else 0
        # Outcome correlates with treatment but is not deterministic.
        outcome = 1 if (treatment == 1 and i % 3 != 0) else 0
        obs.append(CausalObservation(
            window_index=i,
            treatment_value=treatment,
            outcome_value=outcome,
            covariates={
                "workload_role": float(i % 3),
                "namespace_risk": 0.5 if i < 20 else 0.8,
                "baseline_event_rate": 10.0 + i,
            },
        ))
    return obs


@pytest.fixture()
def sample_treatment() -> TreatmentSpec:
    """Default treatment specification.

    Returns:
        A TreatmentSpec.
    """
    return TreatmentSpec()


@pytest.fixture()
def sample_outcome() -> OutcomeSpec:
    """Default outcome specification.

    Returns:
        An OutcomeSpec.
    """
    return OutcomeSpec()


@pytest.fixture()
def sample_covariates() -> list[CovariateSpec]:
    """Sample covariate specs.

    Returns:
        List of CovariateSpec objects.
    """
    return [
        CovariateSpec(variable_name="workload_role", description="Workload role index"),
        CovariateSpec(variable_name="namespace_risk", description="Namespace risk weight"),
        CovariateSpec(variable_name="baseline_event_rate", description="Baseline event rate"),
    ]


# ---------------------------------------------------------------------------
# PCEPS fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_feature_baseline() -> PcepsFeatureBaseline:
    """A training-partition feature baseline.

    Returns:
        PcepsFeatureBaseline with reasonable medians and MADs.
    """
    return PcepsFeatureBaseline(
        medians=[
            0.1, 0.5, 0.05, 0.2, 0.03, 0.02, 0.0,
            0.01, 0.5, 0.0, 0.5, 0.0, 0.02, 0.1, 0.1, 0.0,
        ],
        mads=[
            0.05, 0.2, 0.03, 0.1, 0.02, 0.01, 0.0,
            0.005, 0.2, 0.0, 0.2, 0.0, 0.01, 0.05, 0.05, 0.0,
        ],
        model_version="test-v1",
    )


@pytest.fixture()
def sample_attribution() -> AttributionResult:
    """A completed attribution result.

    Returns:
        An AttributionResult with status=completed.
    """
    return AttributionResult(
        attribution_id=uuid.uuid4(),
        status=AttributionStatus.COMPLETED,
        ate=0.35,
        ate_ci_lower=0.1,
        ate_ci_upper=0.6,
        refutations=[
            RefutationResult(
                refuter_name="random_common_cause",
                estimated_effect=0.35,
                new_effect=0.33,
                passed=True,
            ),
        ],
        confidence=0.8,
    )


@pytest.fixture()
def sample_feature_context(
    sample_attribution: AttributionResult,
) -> FeatureDerivationContext:
    """A complete feature derivation context.

    Args:
        sample_attribution: Completed attribution fixture.

    Returns:
        A FeatureDerivationContext with all fields populated.
    """
    return FeatureDerivationContext(
        attribution=sample_attribution,
        contract_violations=3,
        evaluated_contract_rules=100,
        kl_divergence=0.5,
        kl_threshold=0.3,
        new_processes_not_in_contract=2,
        total_exec_events=50,
        unexpected_network_events=1,
        total_network_events=20,
        privilege_transition_unexpected=False,
        sensitive_file_violations=1,
        total_file_events=100,
        component_criticality=0.7,
        image_signature_invalid=False,
        namespace_risk_weight=0.6,
        service_account_privilege=False,
        event_loss_dropped=5,
        event_loss_captured=995,
        graph_centrality_current=0.15,
        graph_centrality_baseline_median=0.1,
        graph_centrality_baseline_mad=0.05,
        prior_drift_windows=3,
        prior_observed_windows=50,
        runtime_component_novelty=False,
    )
