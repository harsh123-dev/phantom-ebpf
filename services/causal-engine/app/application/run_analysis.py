"""
services/causal-engine/app/application/run_analysis.py

End-to-end analysis orchestration use case (Part 5 §Step 4).

Implements the traceable orchestration layer that:
  1. Accepts run manifest and BDG evidence.
  2. Builds CausalObservations from genuine upstream evidence.
  3. Runs Part 4 preflight checks (evidence gates).
  4. Invokes causal estimation ONLY when preflight permits.
  5. Returns a structured AnalysisReport with evidence IDs,
     mapping status, drift result (if provided), causal assumptions,
     and final analysis status.

Design contract:
  - Part 4 evidence gates are NEVER bypassed for convenience.
  - Drift detection and causal attribution are not conflated.
  - A graph relationship is not a causal edge.
  - A verified SBOM mapping is not proof of causation.
  - Estimator absence is recorded honestly, not fabricated.
  - Missing outcomes remain UNKNOWN; they are not relabelled.

IMPORTANT: This module does not claim that running analysis produces
a valid causal estimate. When DoWhy is unavailable (Python 3.14+),
the estimation step returns NOT_IDENTIFIABLE or ESTIMATION_FAILED,
and this report records that fact accurately.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from app.domain.causal_validation import (
    DEFAULT_CAUSAL_ASSUMPTIONS,
    PreflightReport,
    run_preflight_checks,
)
from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CovariateSpec,
    OutcomeSpec,
    TreatmentSpec,
)
from app.domain.observation_builder import (
    BuilderInsufficiency,
    CausalObservationBuilder,
    ObservationBatch,
    OutcomeLabel,
    RunManifest,
    WindowProvenance,
)


# ---------------------------------------------------------------------------
# Analysis report
# ---------------------------------------------------------------------------


@dataclass
class AnalysisReport:
    """Reproducible per-run analysis report.

    Contains every finding from the integrated pipeline, including:
    - Run and evidence identifiers
    - Observation batch summary
    - Preflight gate outcomes
    - Drift result (if available)
    - Attribution result (if estimation was attempted)
    - Explicit causal assumptions
    - Missing data, abstention reasons, and exclusion records

    No field is fabricated. Missing data is recorded as missing.

    Attributes:
        report_id: UUID of this report instance.
        run_id: Experiment run identifier.
        scenario_id: Scenario / attack identifier.
        run_completed: Whether the run reached its final phase.
        injection_succeeded: Whether the inject phase succeeded.
        ground_truth_label: Run-level ground truth (1=attack, 0=benign).
        evidence_record_count: Number of input evidence records.
        observations_built: Number of valid CausalObservation rows built.
        observations_excluded: Number of windows excluded with reasons.
        mapping_status_counts: Dict of {status_string: count}.
        treatment_evidence_ids: Evidence UUIDs for treatment assignment.
        drift_outcome: Drift decider result string, or empty.
        drift_score: KL-divergence score, or None.
        preflight_passed: Whether all Part 4 preflight gates passed.
        preflight_first_blocker_gate: Gate name of the first blocker, or empty.
        preflight_first_blocker_reason: Machine-readable reason code, or empty.
        estimation_attempted: Whether DoWhy estimation was attempted.
        estimation_status: AttributionStatus string, or empty.
        estimation_reason: Reason code from AttributionResult, or empty.
        estimation_explanation: Human-readable explanation, or empty.
        ate: Average Treatment Effect, or None.
        causal_assumptions: Explicit causal assumptions used.
        insufficiencies: Structured insufficiency records.
        provenance_records: Window provenance for each observation window.
        missing_data_summary: List of missing-field descriptions.
        exclusion_reasons: Ordered list of exclusion reasons.
    """

    report_id: uuid.UUID = field(default_factory=uuid.uuid4)
    run_id: str = ""
    scenario_id: str = ""
    run_completed: bool = False
    injection_succeeded: Optional[bool] = None
    ground_truth_label: int = -1
    evidence_record_count: int = 0
    observations_built: int = 0
    observations_excluded: int = 0
    mapping_status_counts: dict[str, int] = field(default_factory=dict)
    treatment_evidence_ids: list[str] = field(default_factory=list)
    drift_outcome: str = ""
    drift_score: Optional[float] = None
    preflight_passed: bool = False
    preflight_first_blocker_gate: str = ""
    preflight_first_blocker_reason: str = ""
    estimation_attempted: bool = False
    estimation_status: str = ""
    estimation_reason: str = ""
    estimation_explanation: str = ""
    ate: Optional[float] = None
    causal_assumptions: list[str] = field(default_factory=list)
    insufficiencies: list[BuilderInsufficiency] = field(default_factory=list)
    provenance_records: list[WindowProvenance] = field(default_factory=list)
    missing_data_summary: list[str] = field(default_factory=list)
    exclusion_reasons: list[str] = field(default_factory=list)

    @property
    def real_estimate_produced(self) -> bool:
        """True only when a numerical ATE was actually returned."""
        return (
            self.estimation_attempted
            and self.estimation_status == AttributionStatus.COMPLETED.value
            and self.ate is not None
        )


# ---------------------------------------------------------------------------
# Run analysis use case
# ---------------------------------------------------------------------------


class RunAnalysisUseCase:
    """End-to-end analysis orchestration for one experiment run.

    Connects:
      - Part 3 mapping provenance (via BDG node data or fallback)
      - Part 4 preflight evidence gates
      - Part 4 causal estimation (when prerequisites are met)

    Args:
        builder: CausalObservationBuilder instance.
        minimum_observations: Minimum observations required by preflight G1.
    """

    def __init__(
        self,
        builder: Optional[CausalObservationBuilder] = None,
        minimum_observations: int = 10,
    ) -> None:
        """Initialise the use case.

        Args:
            builder: Builder instance; creates a default if None.
            minimum_observations: Minimum for G1 gate.
        """
        self._builder = builder or CausalObservationBuilder(minimum_observations)
        self._minimum = minimum_observations

    def execute(
        self,
        manifest: RunManifest,
        bdg_node_data: Optional[list[dict[str, Any]]] = None,
        drift_result: Optional[dict[str, Any]] = None,
        estimator: str = "backdoor.linear_regression",
        covariates: Optional[list[CovariateSpec]] = None,
    ) -> AnalysisReport:
        """Run the end-to-end analysis for one experiment run.

        Steps:
          1. Build CausalObservations from manifest + BDG data.
          2. Summarise mapping provenance.
          3. Record drift result (if provided).
          4. Run Part 4 preflight gates.
          5. Attempt causal estimation if all gates pass.
          6. Return a complete AnalysisReport.

        Args:
            manifest: Parsed RunManifest.
            bdg_node_data: Optional list of BDG PURL node attribute dicts.
            drift_result: Optional dict with ``outcome``, ``final_score``,
                and ``explanation`` from DriftDecider.
            estimator: DoWhy estimator method name.
            covariates: CovariateSpec list for the SCM.

        Returns:
            Complete AnalysisReport (never raises; all errors are captured).
        """
        report = AnalysisReport(
            run_id=manifest.run_id,
            scenario_id=manifest.attack_id,
            run_completed=manifest.run_completed,
            injection_succeeded=manifest.injection_succeeded,
            ground_truth_label=manifest.ground_truth_label,
        )

        # --- Step 1: Build observations ---
        batch: ObservationBatch = self._builder.build_from_run_manifest_only(
            manifest, bdg_node_data
        )
        report.observations_built = batch.included_count
        report.observations_excluded = batch.excluded_count
        report.insufficiencies = batch.insufficiencies
        report.provenance_records = batch.provenance_records

        for insuff in batch.insufficiencies:
            report.missing_data_summary.extend(insuff.missing_fields)
            if insuff.explanation:
                report.exclusion_reasons.append(insuff.explanation)

        # --- Step 2: Mapping provenance summary ---
        counts: dict[str, int] = {}
        for s in batch.treatment_mapping_statuses:
            counts[s] = counts.get(s, 0) + 1
        report.mapping_status_counts = counts
        report.treatment_evidence_ids = [
            str(e) for e in batch.treatment_evidence_ids
        ]

        # --- Step 3: Drift result ---
        if drift_result:
            report.drift_outcome = drift_result.get("outcome", "")
            report.drift_score = drift_result.get("final_score")

        # --- Step 4: Preflight gates ---
        # Compute outcome_positive_count from observations.
        outcome_positive_count = sum(
            1 for obs in batch.observations
            if hasattr(obs, "outcome_value") and obs.outcome_value == 1
        )
        window_indices = [
            obs.window_index
            for obs in batch.observations
            if hasattr(obs, "window_index")
        ]
        mapping_statuses = batch.treatment_mapping_statuses or []

        preflight: PreflightReport = run_preflight_checks(
            observation_count=batch.included_count,
            outcome_positive_count=outcome_positive_count,
            window_indices=window_indices,
            mapping_statuses=mapping_statuses,
            minimum_observations=self._minimum,
        )
        report.preflight_passed = preflight.passed

        if preflight.first_blocker:
            report.preflight_first_blocker_gate = preflight.first_blocker.gate_name
            report.preflight_first_blocker_reason = preflight.first_blocker.reason

        # --- Step 5: Causal estimation ---
        # Only attempt if preflight passed.
        if not preflight.passed:
            report.estimation_attempted = False
            report.estimation_status = (
                preflight.first_blocker.suggested_status
                if preflight.first_blocker and preflight.first_blocker.suggested_status
                else AttributionStatus.INSUFFICIENT_EVIDENCE.value
            )
            report.estimation_reason = (
                preflight.first_blocker.reason if preflight.first_blocker else "preflight_failed"
            )
            report.estimation_explanation = (
                preflight.first_blocker.explanation
                if preflight.first_blocker
                else "One or more preflight gates failed."
            )
            report.causal_assumptions = []
            return report

        # Preflight passed — attempt estimation.
        report.estimation_attempted = True
        attribution: Optional[AttributionResult] = self._attempt_estimation(
            batch=batch,
            estimator=estimator,
            covariates=covariates or [],
        )

        if attribution is not None:
            report.estimation_status = attribution.status.value
            report.estimation_reason = attribution.reason
            report.estimation_explanation = attribution.explanation
            report.ate = attribution.ate
            report.causal_assumptions = list(attribution.causal_assumptions)
        else:
            report.estimation_status = "dependency_unavailable"
            report.estimation_reason = "dowhy_unavailable"
            report.estimation_explanation = (
                "Causal estimation engine or DoWhy dependency is unavailable."
            )
            report.ate = None
            report.causal_assumptions = []

        return report

    def _attempt_estimation(
        self,
        batch: ObservationBatch,
        estimator: str,
        covariates: list[CovariateSpec],
    ) -> Optional[AttributionResult]:
        """Attempt DoWhy causal estimation on the observation batch.

        Returns None if the estimation machinery itself is unavailable
        (e.g. DoWhy import fails). Returns an AttributionResult otherwise,
        which may itself carry ESTIMATION_FAILED or NOT_IDENTIFIABLE status.

        Args:
            batch: ObservationBatch with valid observations.
            estimator: DoWhy estimator method name.
            covariates: CovariateSpec list.

        Returns:
            AttributionResult or None.
        """
        try:
            from app.domain.bdg import BehavioralDependencyGraph  # noqa: PLC0415
        except ImportError:
            return None

        try:
            from app.application.estimate_attribution import (  # noqa: PLC0415
                estimate_causal_attribution,
            )
        except ImportError:
            return None

        import asyncio  # noqa: PLC0415
        import concurrent.futures  # noqa: PLC0415

        bdg = BehavioralDependencyGraph()

        def _run_estimation() -> AttributionResult:
            return asyncio.run(
                estimate_causal_attribution(
                    bdg=bdg,
                    observations=batch.observations,
                    treatment_spec=TreatmentSpec(),
                    outcome_spec=OutcomeSpec(),
                    covariates=covariates,
                    estimator=estimator,
                )
            )

        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    result: AttributionResult = pool.submit(_run_estimation).result()
            else:
                result = _run_estimation()

            return result
        except (KeyboardInterrupt, SystemExit):
            # Never swallow process control exceptions
            raise
        except Exception as exc:
            from app.domain.exceptions import (  # noqa: PLC0415
                CausalModelConstructionError,
                EffectNotIdentifiableError,
                GraphCycleError,
                InsufficientObservationsError,
                InsufficientVariationError,
                PositivityFailureError,
            )
            if isinstance(exc, GraphCycleError):
                return AttributionResult(
                    attribution_id=uuid.uuid4(),
                    status=AttributionStatus.INVALID_GRAPH,
                    reason="invalid_graph_cycle",
                    explanation=str(exc),
                    observation_count=len(batch.observations),
                    causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
                )
            if isinstance(exc, EffectNotIdentifiableError):
                return AttributionResult(
                    attribution_id=uuid.uuid4(),
                    status=AttributionStatus.NOT_IDENTIFIABLE,
                    reason="unidentified_effect",
                    explanation=str(exc),
                    observation_count=len(batch.observations),
                    causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
                )
            if isinstance(exc, (InsufficientVariationError, PositivityFailureError, InsufficientObservationsError)):
                return AttributionResult(
                    attribution_id=uuid.uuid4(),
                    status=AttributionStatus.INSUFFICIENT_EVIDENCE,
                    reason=type(exc).__name__.lower(),
                    explanation=str(exc),
                    observation_count=len(batch.observations),
                    causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
                )
            if isinstance(exc, CausalModelConstructionError):
                return AttributionResult(
                    attribution_id=uuid.uuid4(),
                    status=AttributionStatus.INVALID_GRAPH,
                    reason="model_construction_error",
                    explanation=str(exc),
                    observation_count=len(batch.observations),
                    causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
                )
            return AttributionResult(
                attribution_id=uuid.uuid4(),
                status=AttributionStatus.ESTIMATION_FAILED,
                reason="estimation_failed",
                explanation=(
                    f"Error during causal estimation: "
                    f"{type(exc).__name__}: {exc}"
                ),
                observation_count=len(batch.observations),
                causal_assumptions=DEFAULT_CAUSAL_ASSUMPTIONS,
            )


# ---------------------------------------------------------------------------
# Aggregate summary
# ---------------------------------------------------------------------------


@dataclass
class PipelineSummary:
    """Aggregate summary across multiple AnalysisReport instances.

    Attributes:
        total_runs: Total runs processed.
        attack_runs: Runs with ground_truth_label == 1.
        benign_runs: Runs with ground_truth_label == 0.
        completed_runs: Runs that reached their final phase.
        failed_injection_runs: Runs where inject_ok was False.
        observation_batches_sufficient: Batches with enough observations
            to attempt estimation.
        preflight_passed_count: Runs where all preflight gates passed.
        estimation_attempted_count: Runs where estimation was attempted.
        estimation_completed_count: Runs with COMPLETED status.
        real_estimates_produced: Runs with a numerical ATE.
        mapping_status_totals: Aggregate mapping status counts.
        abstention_reason_counts: Counts of each abstention reason.
        missing_data_fields: Unique missing-field descriptions.
    """

    total_runs: int = 0
    attack_runs: int = 0
    benign_runs: int = 0
    completed_runs: int = 0
    failed_injection_runs: int = 0
    observation_batches_sufficient: int = 0
    preflight_passed_count: int = 0
    estimation_attempted_count: int = 0
    estimation_completed_count: int = 0
    real_estimates_produced: int = 0
    mapping_status_totals: dict[str, int] = field(default_factory=dict)
    abstention_reason_counts: dict[str, int] = field(default_factory=dict)
    missing_data_fields: list[str] = field(default_factory=list)

    @classmethod
    def from_reports(cls, reports: list[AnalysisReport]) -> PipelineSummary:
        """Build a summary from a list of AnalysisReport instances.

        Args:
            reports: List of per-run analysis reports.

        Returns:
            Aggregated PipelineSummary.
        """
        s = cls(total_runs=len(reports))
        all_missing: set[str] = set()
        for r in reports:
            if r.ground_truth_label == 1:
                s.attack_runs += 1
            elif r.ground_truth_label == 0:
                s.benign_runs += 1
            if r.run_completed:
                s.completed_runs += 1
            if r.injection_succeeded is False:
                s.failed_injection_runs += 1
            if r.observations_built >= 10:
                s.observation_batches_sufficient += 1
            if r.preflight_passed:
                s.preflight_passed_count += 1
            if r.estimation_attempted:
                s.estimation_attempted_count += 1
            if r.estimation_status == AttributionStatus.COMPLETED.value:
                s.estimation_completed_count += 1
            if r.real_estimate_produced:
                s.real_estimates_produced += 1
            for status, count in r.mapping_status_counts.items():
                s.mapping_status_totals[status] = (
                    s.mapping_status_totals.get(status, 0) + count
                )
            if r.estimation_reason:
                s.abstention_reason_counts[r.estimation_reason] = (
                    s.abstention_reason_counts.get(r.estimation_reason, 0) + 1
                )
            all_missing.update(r.missing_data_summary)
        s.missing_data_fields = sorted(all_missing)
        return s
