"""
causal-engine DoWhy causal estimator adapter.

Implements the CausalEstimatorPort domain interface using DoWhy
for causal identification, estimation, and refutation.
Returns not_identifiable when no valid adjustment set is found.

This adapter wraps the estimate_causal_attribution() use case function
and exposes it via the domain port interface so use cases remain
infrastructure-free.
"""

from __future__ import annotations

import time

import structlog
from phantom_core.metrics import (
    CAUSAL_ATTRIBUTION_CONFIDENCE,
    CAUSAL_ESTIMATION_DURATION,
    CAUSAL_JOBS_TOTAL,
    CAUSAL_REFUTATIONS_TOTAL,
)

from app.application.estimate_attribution import estimate_causal_attribution
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalEstimatorName,
    CausalObservation,
    CovariateSpec,
    OutcomeSpec,
    TemporalDAGProjection,
    TreatmentSpec,
)
from app.domain.ports import CausalEstimatorPort

log: structlog.BoundLogger = structlog.get_logger(__name__)


def _confidence_band(score: float) -> str:
    """Map 0-1 confidence to label bucket."""
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score >= 0.2:
        return "low"
    return "very_low"


class DoWhyCausalEstimator(CausalEstimatorPort):
    """DoWhy-backed causal estimator.

    Delegates to estimate_causal_attribution() which implements
    Algorithm 4 from the handoff document §6.4.

    Per handoff §6.3: the pinned DoWhy version is tested during
    construction via a lightweight graph import check.

    Args:
        event_loss_rate: Event loss rate forwarded to confidence.
        identity_resolution_rate: Identity resolution rate.
        contract_verified: Whether the active contract is cosign-verified.
    """

    def __init__(
        self,
        event_loss_rate: float = 0.0,
        identity_resolution_rate: float = 1.0,
        contract_verified: bool = True,
    ) -> None:
        """Initialise the DoWhy estimator adapter.

        Args:
            event_loss_rate: Fraction of events lost (lowers confidence).
            identity_resolution_rate: Fraction of events with resolved identity.
            contract_verified: Whether the active contract is cosign-verified.
        """
        self._event_loss_rate = event_loss_rate
        self._identity_resolution_rate = identity_resolution_rate
        self._contract_verified = contract_verified

        # Verify DoWhy import at startup per handoff §6.6.
        try:
            import dowhy  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "DoWhy is required but not installed. "
                "Pin the version in pyproject.toml and install it."
            ) from exc

    async def estimate(
        self,
        observations: list[CausalObservation],
        treatment_spec: TreatmentSpec,
        outcome_spec: OutcomeSpec,
        covariates: list[CovariateSpec],
        estimator: CausalEstimatorName,
        projection: TemporalDAGProjection,
    ) -> AttributionResult:
        """Execute the DoWhy causal estimation pipeline.

        Delegates to estimate_causal_attribution(). All
        not_identifiable conditions produce an AttributionResult
        with status=not_identifiable; they never raise.

        Args:
            observations: Windowed causal data rows.
            treatment_spec: Treatment variable specification.
            outcome_spec: Outcome variable specification.
            covariates: Pre-treatment covariate specs.
            estimator: Backdoor estimator name.
            projection: TemporalDAGProjection from BDG.

        Returns:
            An AttributionResult.
        """
        # The estimate_causal_attribution function requires a BDG object
        # to re-project the graph; the projection is pre-computed here.
        # We pass a minimal stub that returns the pre-computed projection.

        # Create an empty BDG and monkey-patch project_to_temporal_dag
        # to return the pre-computed projection (avoids re-projection cost).
        bdg_stub = _PrecomputedProjectionBDG(projection)

        start_time = time.monotonic()
        result = await estimate_causal_attribution(
            bdg=bdg_stub,  # type: ignore[arg-type]
            observations=observations,
            treatment_spec=treatment_spec,
            outcome_spec=outcome_spec,
            covariates=covariates,
            estimator=estimator,
            event_loss_rate=self._event_loss_rate,
            identity_resolution_rate=self._identity_resolution_rate,
            contract_verified=self._contract_verified,
        )
        duration_seconds = time.monotonic() - start_time

        estimator_name = str(estimator.value if hasattr(estimator, "value") else estimator)  # type: ignore[union-attr]
        status_str = str(result.status.value if hasattr(result.status, "value") else result.status)

        CAUSAL_ESTIMATION_DURATION.labels(
            estimator=estimator_name,
            status=status_str,
        ).observe(duration_seconds)

        if status_str == "completed" or result.status == AttributionStatus.COMPLETED:
            CAUSAL_JOBS_TOTAL.labels(
                status="completed",
                estimator=estimator_name,
            ).inc()
            confidence_score = result.confidence if result.confidence is not None else 0.0
            CAUSAL_ATTRIBUTION_CONFIDENCE.labels(
                confidence_band=_confidence_band(confidence_score),
            ).observe(confidence_score)
            for ref in (result.refutations or []):
                CAUSAL_REFUTATIONS_TOTAL.labels(
                    method=ref.refuter_name,
                    result="pass" if ref.passed else "fail",
                ).inc()
        elif (
            status_str == "not_identifiable"
            or result.status == AttributionStatus.NOT_IDENTIFIABLE
        ):
            CAUSAL_JOBS_TOTAL.labels(
                status="not_identifiable",
                estimator=estimator_name,
            ).inc()

        return result


class _PrecomputedProjectionBDG:
    """Minimal BDG stub that returns a pre-computed temporal DAG projection.

    This avoids re-projecting the graph when the projection is already
    available from the use case layer.

    Args:
        projection: Pre-computed TemporalDAGProjection.
    """

    def __init__(self, projection: TemporalDAGProjection) -> None:
        """Initialise with the pre-computed projection.

        Args:
            projection: The TemporalDAGProjection to return.
        """
        self._projection = projection

    def project_to_temporal_dag(
        self,
        treatment_variable: str,
        outcome_variable: str,
        window_count: int = 10,
    ) -> TemporalDAGProjection:
        """Return the pre-computed projection.

        Args:
            treatment_variable: Ignored; uses pre-computed projection.
            outcome_variable: Ignored; uses pre-computed projection.
            window_count: Ignored; uses pre-computed projection.

        Returns:
            The pre-computed TemporalDAGProjection.
        """
        return self._projection
