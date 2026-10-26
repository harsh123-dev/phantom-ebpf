"""
causal-engine use cases.

Orchestrates:
- UpdateBdgUseCase: apply drift event to the BDG and emit a new snapshot
- BuildScmUseCase: construct a structural causal model from a BDG snapshot
- RunAttributionUseCase: execute DoWhy causal estimation and store results
- RunPcepsScoringUseCase: score a completed attribution via XGBoost model

Imports from domain/ ports only; no infrastructure or interface imports.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import structlog

from app.domain.bdg import BehavioralDependencyGraph
from app.domain.causal import construct_causal_model
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalEstimatorName,
    CausalModelHandle,
    CausalObservation,
    CovariateSpec,
    GraphMutation,
    OutcomeSpec,
    PcepsScore,
    TreatmentSpec,
)
from app.domain.exceptions import (
    CausalModelConstructionError,
    GraphCycleError,
    InsufficientVariationError,
    PositivityFailureError,
)
from app.domain.pceps.feature_extractor import FeatureDerivationContext, derive_pceps_features
from app.domain.ports import (
    AttributionRepository,
    BdgRepository,
    CausalEstimatorPort,
    ScoringModelPort,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# UpdateBdgUseCase
# ---------------------------------------------------------------------------


class UpdateBdgUseCase:
    """Apply a single runtime event to the in-memory BDG and persist snapshot.

    Uses the BDG domain object for graph mutation and the BdgRepository
    port for snapshot persistence. Snapshot commits are driven by the
    BDG's internal batch boundary logic.

    Args:
        bdg: The active in-memory BehavioralDependencyGraph.
        bdg_repo: Port for snapshot persistence.
    """

    def __init__(
        self,
        bdg: BehavioralDependencyGraph,
        bdg_repo: BdgRepository,
    ) -> None:
        """Initialise with the BDG and persistence port.

        Args:
            bdg: Active in-memory BDG instance.
            bdg_repo: BdgRepository port for snapshot persistence.
        """
        self._bdg = bdg
        self._bdg_repo = bdg_repo

    async def execute(
        self,
        event_id: uuid.UUID,
        event_type: str,
        event_time: datetime,
        tenant_id: str,
        cluster: str,
        namespace: str,
        pod_uid: str,
        container_id: str,
        image_digest: str,
        tgid: int,
        pid_start_time_ns: int,
        identity_confidence: float,
        binding_confidence: float,
        collector_confidence: float,
        binding_status: str = "unresolved",
        component_purl: str | None = None,
        contract_violations: list[dict[str, Any]] | None = None,
        event_attrs: dict[str, Any] | None = None,
    ) -> GraphMutation:
        """Apply the event to the BDG per Algorithm 3.

        Args:
            event_id: Unique event UUID.
            event_type: Normalized event type string.
            event_time: Event observation timestamp (UTC).
            tenant_id: Tenant UUID string.
            cluster: Kubernetes cluster name.
            namespace: Kubernetes namespace.
            pod_uid: Pod UID string.
            container_id: Container ID string.
            image_digest: Container image sha256 digest.
            tgid: Thread group ID.
            pid_start_time_ns: Process start time ns (prevents PID reuse merge).
            identity_confidence: Identity resolution confidence [0, 1].
            binding_confidence: SBOM binding confidence [0, 1].
            collector_confidence: Collector quality confidence [0, 1].
            binding_status: "resolved" or other.
            component_purl: Canonical PURL if binding resolved.
            contract_violations: List of violation dicts if any.
            event_attrs: Event-specific attributes for relation mapping.

        Returns:
            A GraphMutation describing the BDG change.
        """
        mutation = self._bdg.update(
            event_id=event_id,
            event_type=event_type,
            event_time=event_time,
            tenant_id=tenant_id,
            cluster=cluster,
            namespace=namespace,
            pod_uid=pod_uid,
            container_id=container_id,
            image_digest=image_digest,
            tgid=tgid,
            pid_start_time_ns=pid_start_time_ns,
            identity_confidence=identity_confidence,
            binding_confidence=binding_confidence,
            collector_confidence=collector_confidence,
            binding_status=binding_status,
            component_purl=component_purl,
            contract_violations=contract_violations,
            event_attrs=event_attrs,
        )

        if mutation.snapshot_cut:
            # Persist the snapshot that was just cut.
            snapshot = self._bdg.snapshots[-1]
            graph_data = {
                "nodes": [
                    {
                        "key": list(n),
                        "data": dict(self._bdg.graph.nodes[n]),
                    }
                    for n in self._bdg.graph.nodes
                ],
                "edges": [
                    {
                        "source": list(u),
                        "target": list(v),
                        "data": dict(d),
                    }
                    for u, v, d in self._bdg.graph.edges(data=True)
                ],
            }
            await self._bdg_repo.save_snapshot(snapshot, graph_data)
            log.info(
                "update_bdg.snapshot_persisted",
                snapshot_id=str(snapshot.snapshot_id),
            )

        return mutation


# ---------------------------------------------------------------------------
# BuildScmUseCase
# ---------------------------------------------------------------------------


class BuildScmUseCase:
    """Construct a DoWhy CausalModel from the current BDG projection.

    Args:
        bdg: The active in-memory BehavioralDependencyGraph.
    """

    def __init__(self, bdg: BehavioralDependencyGraph) -> None:
        """Initialise with the BDG.

        Args:
            bdg: Active in-memory BDG.
        """
        self._bdg = bdg

    async def execute(
        self,
        observations: list[CausalObservation],
        treatment_spec: TreatmentSpec | None = None,
        outcome_spec: OutcomeSpec | None = None,
        covariates: list[CovariateSpec] | None = None,
        window_count: int = 10,
    ) -> CausalModelHandle | None:
        """Construct the CausalModel.

        Returns None (with not_identifiable logged) on any failure;
        raises on unexpected errors.

        Args:
            observations: Causal observation rows.
            treatment_spec: Treatment variable spec (defaults to component_version_treatment).
            outcome_spec: Outcome variable spec (defaults to runtime_sbom_drift).
            covariates: Pre-treatment covariate specs.
            window_count: Number of time windows for DAG projection.

        Returns:
            A CausalModelHandle or None if not identifiable.
        """
        t_spec = treatment_spec or TreatmentSpec()
        o_spec = outcome_spec or OutcomeSpec()
        cov_list = covariates or []

        projection = self._bdg.project_to_temporal_dag(
            treatment_variable=t_spec.variable_name,
            outcome_variable=o_spec.variable_name,
            window_count=window_count,
        )

        try:
            handle = construct_causal_model(
                projection=projection,
                observations=observations,
                treatment_name=t_spec.variable_name,
                outcome_name=o_spec.variable_name,
                covariate_names=[c.variable_name for c in cov_list],
            )
            return handle
        except (
            GraphCycleError,
            InsufficientVariationError,
            PositivityFailureError,
            CausalModelConstructionError,
        ) as exc:
            log.warning("build_scm.not_identifiable", reason=str(exc))
            return None


# ---------------------------------------------------------------------------
# RunAttributionUseCase
# ---------------------------------------------------------------------------


class RunAttributionUseCase:
    """Execute DoWhy causal estimation and store results.

    Args:
        bdg: The active in-memory BDG.
        estimator_port: Port for DoWhy estimation.
        attribution_repo: Port for attribution persistence.
    """

    def __init__(
        self,
        bdg: BehavioralDependencyGraph,
        estimator_port: CausalEstimatorPort,
        attribution_repo: AttributionRepository,
    ) -> None:
        """Initialise with BDG and ports.

        Args:
            bdg: Active in-memory BDG.
            estimator_port: CausalEstimatorPort adapter.
            attribution_repo: AttributionRepository adapter.
        """
        self._bdg = bdg
        self._estimator = estimator_port
        self._attribution_repo = attribution_repo

    async def execute(
        self,
        observations: list[CausalObservation],
        treatment_spec: TreatmentSpec | None = None,
        outcome_spec: OutcomeSpec | None = None,
        covariates: list[CovariateSpec] | None = None,
        estimator: CausalEstimatorName = "backdoor.generalized_linear_model",
        window_count: int = 10,
        event_loss_rate: float = 0.0,
        identity_resolution_rate: float = 1.0,
        contract_verified: bool = True,
    ) -> AttributionResult:
        """Execute the full attribution pipeline.

        Args:
            observations: Causal observation rows.
            treatment_spec: Treatment variable spec.
            outcome_spec: Outcome variable spec.
            covariates: Pre-treatment covariate specs.
            estimator: Backdoor estimator name.
            window_count: Time windows for DAG projection.
            event_loss_rate: Event loss rate for confidence.
            identity_resolution_rate: Identity resolution fraction.
            contract_verified: Whether the contract is cosign-verified.

        Returns:
            An AttributionResult.
        """
        t_spec = treatment_spec or TreatmentSpec()
        o_spec = outcome_spec or OutcomeSpec()
        cov_list = covariates or []

        projection = self._bdg.project_to_temporal_dag(
            treatment_variable=t_spec.variable_name,
            outcome_variable=o_spec.variable_name,
            window_count=window_count,
        )

        result = await self._estimator.estimate(
            observations=observations,
            treatment_spec=t_spec,
            outcome_spec=o_spec,
            covariates=cov_list,
            estimator=estimator,
            projection=projection,
        )

        await self._attribution_repo.save_attribution(result)
        log.info(
            "run_attribution.complete",
            attribution_id=str(result.attribution_id),
            status=result.status.value,
        )
        return result


# ---------------------------------------------------------------------------
# RunPcepsScoringUseCase
# ---------------------------------------------------------------------------


class RunPcepsScoringUseCase:
    """Score a completed attribution via the PCEPS XGBoost model.

    Args:
        scoring_model_port: Port for XGBoost inference + calibration.
        bdg: The active in-memory BDG (for centrality feature).
    """

    def __init__(
        self,
        scoring_model_port: ScoringModelPort,
        bdg: BehavioralDependencyGraph,
    ) -> None:
        """Initialise with scoring port and BDG.

        Args:
            scoring_model_port: ScoringModelPort adapter.
            bdg: Active in-memory BDG.
        """
        self._scorer = scoring_model_port
        self._bdg = bdg

    async def execute(
        self,
        attribution: AttributionResult,
        ctx: FeatureDerivationContext,
    ) -> PcepsScore:
        """Derive features and score the attribution.

        Per handoff §7.6: if attribution is not identifiable, the PCEPS
        request is rejected (f1 cannot be imputed as causal evidence).

        Args:
            attribution: The completed AttributionResult.
            ctx: Feature derivation context providing all inputs.

        Returns:
            A PcepsScore.

        Raises:
            ValueError: If the attribution is not identifiable.
        """
        if attribution.status == AttributionStatus.NOT_IDENTIFIABLE:
            raise ValueError(
                "PCEPS scoring requires an identifiable attribution result. "
                f"Attribution {attribution.attribution_id} is not_identifiable: "
                f"{attribution.reason}"
            )

        # Set the attribution on the context if not already set.
        if ctx.attribution is None:
            ctx = FeatureDerivationContext(
                **{k: v for k, v in ctx.__dict__.items() if k != "attribution"},
                attribution=attribution,
            )

        baseline = await self._scorer.get_baseline()
        features = derive_pceps_features(ctx, baseline)
        score = await self._scorer.score(features)

        log.info(
            "pceps_scoring.complete",
            attribution_id=str(attribution.attribution_id),
            score=round(score.score, 2),
            severity=score.severity.value,
            completeness=round(score.feature_completeness, 3),
        )
        return score
