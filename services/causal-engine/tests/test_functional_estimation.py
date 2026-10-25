"""
tests/test_functional_estimation.py

PHANTOM Part 6 — Compatible Causal Runtime and Functional Estimation Validation.

Tests:
1. Supported dependency import and runtime checks (distinguishing module discovery from functional import).
2. Functional causal estimation on controlled synthetic DGP with DoWhy backdoor linear regression.
3. Non-identifiable effect and correct structured abstention.
4. Estimator exception handling and distinct status outcomes.
5. Missing optional dependency handling (dependency_unavailable).
6. Production pipeline boundary: RunAnalysisUseCase, preflight checks, and AnalysisReport serialization.
7. Verification that synthetic test results remain strictly isolated from real experiment data.
"""

from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.domain.entities import (
    AttributionResult,
    AttributionStatus,
    CausalObservation,
    CausalModelHandle,
    CovariateSpec,
    OutcomeSpec,
    TemporalDAGProjection,
    TreatmentSpec,
)
from app.domain.causal import construct_causal_model
from app.domain.exceptions import (
    CausalModelConstructionError,
    GraphCycleError,
    InsufficientVariationError,
)
from app.domain.observation_builder import (
    CausalObservationBuilder,
    ObservationBatch,
    OutcomeLabel,
    RunManifest,
    RunManifestPhase,
)
from app.application.run_analysis import (
    AnalysisReport,
    PipelineSummary,
    RunAnalysisUseCase,
)
from app.application.estimate_attribution import (
    compute_attribution_confidence,
    estimate_causal_attribution,
)


# ---------------------------------------------------------------------------
# Test Suite 1: Runtime & Dependency Verification
# ---------------------------------------------------------------------------


class TestDependencyRuntimeChecks:
    """Verifies that DoWhy and its dependencies are functional in the runtime."""

    def test_distinguishes_module_spec_from_successful_import(self) -> None:
        """Explicitly tests that module discovery is not equated to functional import."""
        spec = importlib.util.find_spec("dowhy")
        assert spec is not None, "DoWhy module spec should be found in this environment"

        # Verify functional import in an isolated subprocess to guard against native DLL crashes
        res = subprocess.run(
            [sys.executable, "-c", "import dowhy; print(dowhy.__version__)"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert res.returncode == 0, f"DoWhy import failed with exit code {res.returncode}: {res.stderr}"
        assert len(res.stdout.strip()) > 0

    def test_networkx_d_separation_compatibility(self) -> None:
        """Verifies NetworkX exports d_separated required by DoWhy graph operations."""
        import networkx as nx

        assert hasattr(nx.algorithms, "d_separated") or hasattr(nx, "d_separated"), (
            f"NetworkX {nx.__version__} lacks d_separated. Pinned networkx==3.3 is required."
        )

    def test_pandas_indexing_compatibility(self) -> None:
        """Verifies pandas does not reject DoWhy's positional parameter access."""
        import pandas as pd

        s = pd.Series([1.23, 4.56], index=["const", "x"])
        # DoWhy regression_estimator accesses self.model.params[0]
        # In pandas 2.x this succeeds; in pandas 3.0 it raises KeyError: 0
        try:
            val = s[0]
            assert isinstance(val, (int, float, np.floating))
        except KeyError:
            pytest.fail("pandas >=3.0 raises KeyError on positional series access; pandas 2.2.2 is required")


# ---------------------------------------------------------------------------
# Test Suite 2: Functional Causal Estimation on Known DGP
# ---------------------------------------------------------------------------


class TestFunctionalCausalEstimationDGP:
    """End-to-end estimation with a controlled synthetic Data-Generating Process."""

    def _generate_synthetic_data(
        self,
        n: int = 300,
        seed: int = 42,
    ) -> tuple[list[CausalObservation], float]:
        """Generate synthetic observations with known positive causal effect.

        DGP:
            W ~ Normal(0, 1)            (pre-treatment confounder)
            T = 1[0.5*W + e1 > 0]       (binary treatment)
            Y = 1[1.5*T + 0.8*W + e2 > 0] (binary outcome)

        True ATE on linear risk-difference scale is approx +0.30 to +0.45.
        """
        rng = np.random.default_rng(seed)
        W = rng.standard_normal(n)
        T = (0.5 * W + rng.standard_normal(n) > 0).astype(int)
        Y = (1.5 * T + 0.8 * W + rng.standard_normal(n) > 0).astype(int)

        cov_name = "pre_treatment_load_W"
        observations = [
            CausalObservation(
                window_index=i,
                treatment_value=int(T[i]),
                outcome_value=int(Y[i]),
                covariates={cov_name: float(W[i])},
            )
            for i in range(n)
        ]
        return observations, cov_name

    def test_successful_functional_estimation_via_adapter(self) -> None:
        """Verifies DoWhy returns a finite estimate matching expected DGP sign and scale."""
        observations, cov_name = self._generate_synthetic_data(n=300, seed=42)
        treatment_name = TreatmentSpec().variable_name
        outcome_name = OutcomeSpec().variable_name

        projection = TemporalDAGProjection(
            projected_nodes=[
                (cov_name, 0),
                (treatment_name, 0),
                (outcome_name, 1),
            ],
            projected_edges=[
                ((cov_name, 0), (treatment_name, 0)),
                ((cov_name, 0), (outcome_name, 1)),
                ((treatment_name, 0), (outcome_name, 1)),
            ],
            treatment_or_outcome_in_cycle=False,
        )

        handle: CausalModelHandle = construct_causal_model(
            projection=projection,
            observations=observations,
            treatment_name=treatment_name,
            outcome_name=outcome_name,
            covariate_names=[cov_name],
        )

        model = handle.model
        estimand = model.identify_effect(proceed_when_unidentifiable=False)
        assert estimand is not None
        assert "backdoor" in str(estimand.estimand_type).lower() or "ate" in str(estimand.estimand_type).lower()

        estimate = model.estimate_effect(
            estimand,
            method_name="backdoor.linear_regression",
            control_value=0,
            treatment_value=1,
            target_units="ate",
        )

        ate = float(estimate.value)
        assert math.isfinite(ate), f"Estimate must be finite, got {ate}"
        assert ate > 0.0, f"Expected positive causal effect from DGP, got {ate}"
        assert 0.15 < ate < 0.55, f"Expected ATE in [0.15, 0.55] from DGP; got {ate:.4f}"

    @pytest.mark.asyncio
    async def test_non_identifiable_effect_abstains_correctly(self) -> None:
        """Verifies system abstains with NOT_IDENTIFIABLE when effect cannot be identified on a valid DAG."""
        import networkx as nx
        from app.domain.bdg import BehavioralDependencyGraph

        observations, _ = self._generate_synthetic_data(n=100, seed=42)
        treatment_name = TreatmentSpec().variable_name
        outcome_name = OutcomeSpec().variable_name
        unobs_cov = "U_latent"

        # Valid DAG with unobserved confounder U_latent -> treatment, U_latent -> outcome
        valid_dag_projection = TemporalDAGProjection(
            projected_nodes=[
                (unobs_cov, 0),
                (treatment_name, 0),
                (outcome_name, 1),
            ],
            projected_edges=[
                ((unobs_cov, 0), (treatment_name, 0)),
                ((unobs_cov, 0), (outcome_name, 1)),
                ((treatment_name, 0), (outcome_name, 1)),
            ],
            treatment_or_outcome_in_cycle=False,
        )

        # 1. Verify this graph is strictly acyclic (a valid DAG)
        check_dag = nx.DiGraph()
        check_dag.add_edges_from([
            (unobs_cov, treatment_name),
            (unobs_cov, outcome_name),
            (treatment_name, outcome_name),
        ])
        assert nx.is_directed_acyclic_graph(check_dag), "Projection must be an acyclic DAG"

        # 2. Observations do NOT contain U_latent, so U_latent is treated as unobserved
        obs_without_u = [
            CausalObservation(
                window_index=o.window_index,
                treatment_value=o.treatment_value,
                outcome_value=o.outcome_value,
                covariates={},
            )
            for o in observations
        ]

        # 3. Model builds cleanly without raising GraphCycleError
        handle = construct_causal_model(
            projection=valid_dag_projection,
            observations=obs_without_u,
            treatment_name=treatment_name,
            outcome_name=outcome_name,
            covariate_names=[],
        )
        assert handle is not None

        # 4. Identification reports no valid backdoor adjustment set
        estimand = handle.model.identify_effect(proceed_when_unidentifiable=False)
        assert estimand.estimands.get("backdoor") is None

        # 5. Full estimation pipeline returns NOT_IDENTIFIABLE with ate=None
        bdg = BehavioralDependencyGraph()
        result = await estimate_causal_attribution(
            bdg=bdg,
            observations=obs_without_u,
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[],
            projection=valid_dag_projection,
        )
        assert result.status == AttributionStatus.NOT_IDENTIFIABLE
        assert result.status != AttributionStatus.INVALID_GRAPH
        assert result.ate is None

    @pytest.mark.asyncio
    async def test_invalid_graph_cycle_rejected(self) -> None:
        """Verifies cyclic graph returns INVALID_GRAPH distinctly from NOT_IDENTIFIABLE."""
        from app.domain.bdg import BehavioralDependencyGraph

        observations, _ = self._generate_synthetic_data(n=100, seed=42)
        treatment_name = TreatmentSpec().variable_name
        outcome_name = OutcomeSpec().variable_name

        cyclic_projection = TemporalDAGProjection(
            projected_nodes=[(treatment_name, 0), (outcome_name, 0)],
            projected_edges=[
                ((treatment_name, 0), (outcome_name, 0)),
                ((outcome_name, 0), (treatment_name, 0)),
            ],
            treatment_or_outcome_in_cycle=True,
        )

        # 1. Direct adapter check: raises GraphCycleError
        with pytest.raises(GraphCycleError):
            construct_causal_model(
                projection=cyclic_projection,
                observations=observations,
                treatment_name=treatment_name,
                outcome_name=outcome_name,
                covariate_names=[],
            )

        # 2. Pipeline check: returns INVALID_GRAPH
        bdg = BehavioralDependencyGraph()
        result = await estimate_causal_attribution(
            bdg=bdg,
            observations=observations,
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[],
            projection=cyclic_projection,
        )
        assert result.status == AttributionStatus.INVALID_GRAPH
        assert result.status != AttributionStatus.NOT_IDENTIFIABLE
        assert result.ate is None


# ---------------------------------------------------------------------------
# Test Suite 3: Production Pipeline Boundary & Serialization
# ---------------------------------------------------------------------------


class TestPipelineBoundaryAndSerialization:
    """Verifies that the production RunAnalysisUseCase cleanly handles all statuses."""

    def test_distinguishable_status_codes(self) -> None:
        """Verifies that all status codes are structurally distinct."""
        statuses = {
            AttributionStatus.COMPLETED,
            AttributionStatus.NOT_IDENTIFIABLE,
            AttributionStatus.INSUFFICIENT_EVIDENCE,
            AttributionStatus.ESTIMATION_FAILED,
            AttributionStatus.INVALID_GRAPH,
            AttributionStatus.AMBIGUOUS_COMPONENT,
        }
        assert len(statuses) == 6
        assert "dependency_unavailable" not in [s.value for s in statuses]

    def test_no_causal_estimate_when_estimation_skipped_or_failed(self) -> None:
        """Verifies ATE is None whenever estimation is not completed."""
        for status in (
            AttributionStatus.NOT_IDENTIFIABLE,
            AttributionStatus.INSUFFICIENT_EVIDENCE,
            AttributionStatus.ESTIMATION_FAILED,
            AttributionStatus.INVALID_GRAPH,
        ):
            res = AttributionResult(
                attribution_id=uuid.uuid4(),
                status=status,
                reason="test_abstention",
                ate=None,
            )
            assert res.ate is None
            assert res.status != AttributionStatus.COMPLETED

    def test_json_serialization_handles_domain_types(self) -> None:
        """Verifies AnalysisReport serializes UUIDs, timestamps, enums, and floats cleanly."""
        report = AnalysisReport(
            report_id=uuid.uuid4(),
            run_id="test-run-001",
            scenario_id="benign-load",
            run_completed=True,
            injection_succeeded=True,
            ground_truth_label=0,
            observations_built=20,
            estimation_attempted=True,
            estimation_status=AttributionStatus.COMPLETED.value,
            ate=0.3648,
            causal_assumptions=["forced treatment->outcome edge"],
        )

        serialized = json.dumps(
            {
                "report_id": str(report.report_id),
                "run_id": report.run_id,
                "estimation_status": report.estimation_status,
                "ate": report.ate,
                "real_estimate_produced": report.real_estimate_produced,
            }
        )
        data = json.loads(serialized)
        assert data["ate"] == 0.3648
        assert data["real_estimate_produced"] is True
        assert data["estimation_status"] == "completed"

    def test_missing_dependency_produces_explicit_unavailable_status(self) -> None:
        """Verifies missing dependency produces dependency_unavailable status with ate=None."""
        use_case = RunAnalysisUseCase()

        # Build a batch that would pass preflight
        obs = [
            CausalObservation(
                window_index=i,
                treatment_value=i % 2,
                outcome_value=(i + 1) % 2,
            )
            for i in range(20)
        ]
        batch = ObservationBatch(
            run_id="synth-batch",
            observations=obs,
            included_count=len(obs),
            treatment_mapping_statuses=["VERIFIED"] * 20,
        )

        builder = CausalObservationBuilder(minimum_observations=10)
        builder.build_from_run_manifest_only = lambda *args, **kwargs: batch  # type: ignore[method-assign]
        use_case = RunAnalysisUseCase(builder=builder, minimum_observations=10)
        manifest = RunManifest(
            run_id="synth-batch",
            attack_id="test",
            attack_family="supply_chain",
            repetition=1,
            namespace="default",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-01-01T00:01:00Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[RunManifestPhase("baseline", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60.0)],
        )

        # Simulate missing dependency by monkeypatching _attempt_estimation to return None
        orig_attempt = use_case._attempt_estimation
        use_case._attempt_estimation = lambda *args, **kwargs: None  # type: ignore[method-assign]

        report = use_case.execute(manifest)
        assert report.preflight_passed is True
        assert report.estimation_attempted is True
        assert report.estimation_status == "dependency_unavailable"
        assert report.estimation_reason == "dowhy_unavailable"
        assert report.ate is None
        assert not report.real_estimate_produced

        use_case._attempt_estimation = orig_attempt

    def test_estimator_exception_produces_estimation_failed_status(self) -> None:
        """Verifies runtime exceptions during estimation produce ESTIMATION_FAILED."""
        obs = [
            CausalObservation(
                window_index=i,
                treatment_value=i % 2,
                outcome_value=(i + 1) % 2,
            )
            for i in range(20)
        ]
        batch = ObservationBatch(
            run_id="synth-batch-fail",
            observations=obs,
            included_count=len(obs),
            treatment_mapping_statuses=["VERIFIED"] * 20,
        )

        builder = CausalObservationBuilder(minimum_observations=10)
        builder.build_from_run_manifest_only = lambda *args, **kwargs: batch  # type: ignore[method-assign]
        use_case = RunAnalysisUseCase(builder=builder, minimum_observations=10)
        manifest = RunManifest(
            run_id="synth-batch-fail",
            attack_id="test",
            attack_family="supply_chain",
            repetition=1,
            namespace="default",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-01-01T00:01:00Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[RunManifestPhase("baseline", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60.0)],
        )

        # Force a runtime estimation failure by requesting an invalid estimator
        report = use_case.execute(manifest, estimator="invalid.estimator.name")
        assert report.estimation_attempted is True
        assert report.estimation_status == AttributionStatus.ESTIMATION_FAILED.value
        assert report.estimation_status != AttributionStatus.NOT_IDENTIFIABLE.value
        assert report.ate is None
        assert not report.real_estimate_produced

    def test_successful_pipeline_estimation_and_serialization(self) -> None:
        """Verifies RunAnalysisUseCase reaches estimation, completes, and serializes cleanly."""
        rng = np.random.default_rng(42)
        n = 30
        w = rng.standard_normal(n)
        t = (0.5 * w + rng.standard_normal(n) > 0).astype(int)
        y = (1.5 * t + 0.8 * w + rng.standard_normal(n) > 0).astype(int)

        obs = [
            CausalObservation(
                window_index=i,
                treatment_value=int(t[i]),
                outcome_value=int(y[i]),
                covariates={"cov_w": float(w[i])},
            )
            for i in range(n)
        ]
        batch = ObservationBatch(
            run_id="synth-pipeline-pass",
            observations=obs,
            included_count=len(obs),
            treatment_mapping_statuses=["VERIFIED"] * n,
            treatment_evidence_ids=[uuid.uuid4() for _ in range(n)],
        )

        builder = CausalObservationBuilder(minimum_observations=10)
        builder.build_from_run_manifest_only = lambda *args, **kwargs: batch  # type: ignore[method-assign]
        use_case = RunAnalysisUseCase(builder=builder, minimum_observations=10)
        manifest = RunManifest(
            run_id="synth-pipeline-pass",
            attack_id="test-attack",
            attack_family="supply_chain",
            repetition=1,
            namespace="default",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-01-01T00:01:00Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[RunManifestPhase("baseline", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60.0)],
        )

        report = use_case.execute(
            manifest=manifest,
            covariates=[CovariateSpec(variable_name="cov_w")],
            estimator="backdoor.linear_regression",
        )

        assert report.preflight_passed is True
        assert report.estimation_attempted is True
        assert report.estimation_status == AttributionStatus.COMPLETED.value
        assert report.ate is not None
        assert math.isfinite(report.ate)
        assert report.ate > 0.0
        assert report.real_estimate_produced is True
        assert len(report.causal_assumptions) > 0

        # Verify JSON serialization works without error
        serialized = json.dumps(
            {
                "report_id": str(report.report_id),
                "run_id": report.run_id,
                "estimation_status": report.estimation_status,
                "ate": report.ate,
                "real_estimate_produced": report.real_estimate_produced,
                "causal_assumptions": report.causal_assumptions,
            }
        )
        parsed = json.loads(serialized)
        assert parsed["real_estimate_produced"] is True
        assert parsed["ate"] == report.ate

    @pytest.mark.asyncio
    async def test_run_analysis_callable_from_running_async_loop(self) -> None:
        """Verifies RunAnalysisUseCase can be called from inside an active asyncio event loop."""
        rng = np.random.default_rng(42)
        n = 20
        w = rng.standard_normal(n)
        t = (0.5 * w + rng.standard_normal(n) > 0).astype(int)
        y = (1.5 * t + 0.8 * w + rng.standard_normal(n) > 0).astype(int)

        obs = [
            CausalObservation(
                window_index=i,
                treatment_value=int(t[i]),
                outcome_value=int(y[i]),
                covariates={"cov_w": float(w[i])},
            )
            for i in range(n)
        ]
        batch = ObservationBatch(
            run_id="synth-async-loop",
            observations=obs,
            included_count=len(obs),
            treatment_mapping_statuses=["VERIFIED"] * n,
        )

        builder = CausalObservationBuilder(minimum_observations=10)
        builder.build_from_run_manifest_only = lambda *args, **kwargs: batch  # type: ignore[method-assign]
        use_case = RunAnalysisUseCase(builder=builder, minimum_observations=10)
        manifest = RunManifest(
            run_id="synth-async-loop",
            attack_id="test",
            attack_family="supply_chain",
            repetition=1,
            namespace="default",
            pod_name="pod-1",
            ground_truth_label=1,
            injection_timestamp="2026-01-01T00:01:00Z",
            first_phantom_detection_timestamp=None,
            mttd_s=None,
            is_true_positive=False,
            phases=[RunManifestPhase("baseline", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60.0)],
        )

        # Must not raise RuntimeError: asyncio.run() cannot be called from a running event loop
        report = use_case.execute(manifest)
        assert report.estimation_attempted is True
        assert report.estimation_status == AttributionStatus.COMPLETED.value
        assert report.ate is not None
        assert report.real_estimate_produced is True

    @pytest.mark.asyncio
    async def test_placebo_refutation_evaluation_correctness(self) -> None:
        """Verifies that placebo treatment refutation passes when the effect drops to near zero."""
        from app.domain.bdg import BehavioralDependencyGraph

        rng = np.random.default_rng(42)
        n = 100
        w = rng.standard_normal(n)
        t = (0.5 * w + rng.standard_normal(n) > 0).astype(int)
        y = (1.5 * t + 0.8 * w + rng.standard_normal(n) > 0).astype(int)

        obs = [
            CausalObservation(
                window_index=i,
                treatment_value=int(t[i]),
                outcome_value=int(y[i]),
                covariates={"cov_w": float(w[i])},
            )
            for i in range(n)
        ]

        bdg = BehavioralDependencyGraph()
        result = await estimate_causal_attribution(
            bdg=bdg,
            observations=obs,
            treatment_spec=TreatmentSpec(),
            outcome_spec=OutcomeSpec(),
            covariates=[CovariateSpec(variable_name="cov_w")],
            estimator="backdoor.linear_regression",
        )

        assert result.status == AttributionStatus.COMPLETED
        assert result.ate is not None and result.ate > 0.0

        placebo_refutations = [r for r in result.refutations if r.refuter_name == "placebo_treatment_refuter"]
        assert len(placebo_refutations) == 1
        placebo_ref = placebo_refutations[0]
        # Placebo effect should be near 0 and marked passed
        assert abs(placebo_ref.new_effect) < abs(result.ate)
        assert placebo_ref.passed is True

    def test_non_finite_estimate_abstains_cleanly(self) -> None:
        """Verifies that NaN/Inf estimates do not count as real estimates."""
        report = AnalysisReport(
            report_id=uuid.uuid4(),
            run_id="test-nan",
            estimation_attempted=True,
            estimation_status=AttributionStatus.COMPLETED.value,
            ate=float("nan"),
        )
        # NaN is not a valid finite estimate
        assert math.isnan(report.ate)  # type: ignore[arg-type]

        # Serialization handles NaN by converting to None per pipeline serialization rules
        repo_root = Path(__file__).resolve().parents[3]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from run_pipeline_report import _serialize_report
        serialized = _serialize_report(report)
        assert serialized["ate"] is None

    def test_real_dataset_isolation_from_synthetic_smoke_tests(self) -> None:
        """Verifies synthetic smoke tests do not alter real experiment runs in datasets/raw."""
        repo_root = Path(__file__).resolve().parents[3]
        raw_index_path = repo_root / "research" / "datasets" / "raw" / "index.json"

        assert raw_index_path.exists(), "research/datasets/raw/index.json must exist"
        with open(raw_index_path, encoding="utf-8") as f:
            idx = json.load(f)

        results = idx.get("results", [])
        assert len(results) == 6, f"Expected 6 runs in raw index, found {len(results)}"

        # Verify no synthetic run ID has polluted the real dataset index
        for run_id in results:
            assert not run_id.startswith("SYNTH_"), f"Synthetic run ID {run_id} leaked into real index"
            assert not run_id.startswith("test_"), f"Test run ID {run_id} leaked into real index"


# ---------------------------------------------------------------------------
# Test Suite 4: Attribution Confidence & Diagnostic Stability Score
# ---------------------------------------------------------------------------


class TestAttributionConfidenceAndDiagnostics:
    """Verifies confidence score semantics, refutation penalties, and diagnostics."""

    def test_null_or_non_finite_ate_returns_zero_confidence(self) -> None:
        """Verifies compute_attribution_confidence returns 0.0 when ATE is None or non-finite."""
        from app.application.estimate_attribution import compute_attribution_confidence

        assert compute_attribution_confidence(
            ate=None,
            ate_ci_lower=None,
            ate_ci_upper=None,
            refutations=[],
        ) == 0.0

        assert compute_attribution_confidence(
            ate=float("nan"),
            ate_ci_lower=None,
            ate_ci_upper=None,
            refutations=[],
        ) == 0.0

        assert compute_attribution_confidence(
            ate=float("inf"),
            ate_ci_lower=None,
            ate_ci_upper=None,
            refutations=[],
        ) == 0.0

    def test_missing_or_skipped_refutations_penalize_confidence(self) -> None:
        """Verifies omitted or skipped refutations proportionately reduce confidence."""
        from app.application.estimate_attribution import compute_attribution_confidence
        from app.domain.entities import RefutationResult

        # Baseline: 3 required refutations, all 3 passed -> high score
        all_passed = [
            RefutationResult(
                refuter_name=f"ref_{i}",
                estimated_effect=0.36,
                new_effect=0.36,
                passed=True,
            )
            for i in range(3)
        ]
        score_full = compute_attribution_confidence(
            ate=0.36,
            ate_ci_lower=0.2,
            ate_ci_upper=0.5,
            refutations=all_passed,
            required_refuter_count=3,
        )
        assert score_full > 0.8

        # 0 refutations run (e.g. skipped or unsupported) -> penalized to 0.0
        score_skipped = compute_attribution_confidence(
            ate=0.36,
            ate_ci_lower=0.2,
            ate_ci_upper=0.5,
            refutations=[],
            required_refuter_count=3,
        )
        assert score_skipped == 0.0

        # 1 of 3 passed -> penalized to 1/3
        score_partial = compute_attribution_confidence(
            ate=0.36,
            ate_ci_lower=0.2,
            ate_ci_upper=0.5,
            refutations=[all_passed[0]],
            required_refuter_count=3,
        )
        assert score_partial < score_full
        assert math.isclose(score_partial, score_full * (1.0 / 3.0), rel_tol=1e-3)

    def test_failed_refutations_reduce_confidence(self) -> None:
        """Verifies failed refutations reduce diagnostic confidence."""
        from app.application.estimate_attribution import compute_attribution_confidence
        from app.domain.entities import RefutationResult

        refutations_mixed = [
            RefutationResult(refuter_name="ref_1", estimated_effect=0.36, new_effect=0.36, passed=True),
            RefutationResult(refuter_name="ref_2", estimated_effect=0.36, new_effect=0.0, passed=False),
        ]
        score = compute_attribution_confidence(
            ate=0.36,
            ate_ci_lower=0.2,
            ate_ci_upper=0.5,
            refutations=refutations_mixed,
            required_refuter_count=2,
        )
        # 1 passed out of 2 -> 50% refutation factor
        assert 0.4 < score < 0.6

    def test_attribution_result_alias_synchronization(self) -> None:
        """Verifies confidence and diagnostic_stability_score synchronize and separate diagnostics."""
        from app.domain.entities import AttributionResult, AttributionStatus

        res = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            ate=0.3648,
            confidence=0.85,
        )
        assert res.diagnostic_stability_score == 0.85
        assert res.confidence == 0.85

        res2 = AttributionResult(
            attribution_id=uuid.uuid4(),
            status=AttributionStatus.COMPLETED,
            ate=0.3648,
            diagnostic_stability_score=0.72,
        )
        assert res2.confidence == 0.72
        assert res2.diagnostic_stability_score == 0.72
