"""
causal-engine domain ports (abstract interfaces).

Abstract interfaces for:
- BdgRepository: read/write BDG nodes, edges, and snapshots
- AttributionRepository: store and retrieve attribution jobs
- CausalEstimatorPort: execute DoWhy causal estimation
- ScoringModelPort: run XGBoost PCEPS priority scoring

No framework imports allowed; abc only.
"""

from __future__ import annotations

import abc
import uuid
from typing import Any

from app.domain.entities import (
    AttributionResult,
    BDGSnapshot,
    CausalEstimatorName,
    CausalObservation,
    CovariateSpec,
    OutcomeSpec,
    PcepsFeatureBaseline,
    PcepsFeatureVector,
    PcepsScore,
    TemporalDAGProjection,
    TreatmentSpec,
)


class BdgRepository(abc.ABC):
    """Abstract repository for BDG persistence.

    Methods:
        save_snapshot: Persist an immutable graph snapshot.
        load_snapshot: Load a snapshot by UUID.
        get_latest_snapshot_id: Get the most recent snapshot UUID.
    """

    @abc.abstractmethod
    async def save_snapshot(
        self,
        snapshot: BDGSnapshot,
        graph_data: dict[str, Any],
    ) -> None:
        """Persist a BDG snapshot.

        Args:
            snapshot: The BDGSnapshot metadata.
            graph_data: Serialized graph data.
        """
        ...

    @abc.abstractmethod
    async def load_snapshot(
        self,
        snapshot_id: uuid.UUID,
    ) -> tuple[BDGSnapshot, dict[str, Any]] | None:
        """Load a BDG snapshot by UUID.

        Args:
            snapshot_id: UUID of the snapshot.

        Returns:
            Tuple of (BDGSnapshot, graph_data) or None.
        """
        ...

    @abc.abstractmethod
    async def get_latest_snapshot_id(
        self,
        tenant_id: uuid.UUID,
    ) -> uuid.UUID | None:
        """Get the most recent snapshot UUID for a tenant.

        Args:
            tenant_id: Tenant UUID.

        Returns:
            UUID of the latest snapshot, or None.
        """
        ...


class AttributionRepository(abc.ABC):
    """Abstract repository for attribution job persistence.

    Methods:
        save_attribution: Persist an attribution result.
        load_attribution: Load by attribution UUID.
    """

    @abc.abstractmethod
    async def save_attribution(
        self,
        result: AttributionResult,
    ) -> None:
        """Persist an attribution result.

        Args:
            result: The AttributionResult to store.
        """
        ...

    @abc.abstractmethod
    async def load_attribution(
        self,
        attribution_id: uuid.UUID,
    ) -> AttributionResult | None:
        """Load an attribution result by UUID.

        Args:
            attribution_id: UUID of the attribution.

        Returns:
            AttributionResult or None.
        """
        ...


class CausalEstimatorPort(abc.ABC):
    """Abstract port for causal estimation.

    Methods:
        estimate: Run the DoWhy estimate pipeline.
    """

    @abc.abstractmethod
    async def estimate(
        self,
        observations: list[CausalObservation],
        treatment_spec: TreatmentSpec,
        outcome_spec: OutcomeSpec,
        covariates: list[CovariateSpec],
        estimator: CausalEstimatorName,
        projection: TemporalDAGProjection,
    ) -> AttributionResult:
        """Execute causal estimation.

        Args:
            observations: Windowed causal data.
            treatment_spec: Treatment variable specification.
            outcome_spec: Outcome variable specification.
            covariates: Pre-treatment covariate specs.
            estimator: The backdoor estimator name.
            projection: The temporal DAG projection.

        Returns:
            An AttributionResult.
        """
        ...


class ScoringModelPort(abc.ABC):
    """Abstract port for PCEPS scoring model.

    Methods:
        score: Run XGBoost inference + calibration.
        get_baseline: Load feature baseline.
    """

    @abc.abstractmethod
    async def score(
        self,
        features: PcepsFeatureVector,
    ) -> PcepsScore:
        """Score a feature vector.

        Args:
            features: The 16-feature PCEPS vector.

        Returns:
            A PcepsScore.
        """
        ...

    @abc.abstractmethod
    async def get_baseline(self) -> PcepsFeatureBaseline:
        """Load the training-partition feature baseline.

        Returns:
            A PcepsFeatureBaseline.
        """
        ...
