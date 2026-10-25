"""
services/causal-engine/tests/test_adversarial_challenger_m2.py

Adversarial stress-test harness authored by challenger_m2_2 for Milestone 2.
Empirically stress-tests:
1. Causal DAG construction & anti-mediator DAG conditioning rules (causal.py):
   - Mediator variables in covariates: no M -> T or M -> Y edges added.
   - Pre-treatment variables in covariates: receive both Z -> T and Z -> Y edges.
   - Mixed mediator and pre-treatment covariates.
   - Adversarial projection edges: M -> T blocked from projection edges.
   - Case insensitivity and substring matching of mediator detection.
2. Observation builder (observation_builder.py):
   - Decoupling of Y_drift from Y_hat_phantom.
   - Decoupling of T_inject from T_purl.
   - ObservationRecord schema fields, types, and immutability.
   - Exclusion of post-treatment execution artifacts from covariates.
"""

from __future__ import annotations

import dataclasses
import uuid
import pytest
import networkx as nx

from app.domain.causal import (
    POST_TREATMENT_MEDIATOR_NAMES,
    build_scm_graph,
    construct_causal_model,
    is_post_treatment_mediator,
)
from app.domain.entities import (
    CausalObservation,
    TemporalDAGProjection,
)
from app.domain.observation_builder import (
    CausalObservationBuilder,
    ObservationBatch,
    ObservationRecord,
    OutcomeLabel,
    RunManifest,
    RunManifestPhase,
    WindowProvenance,
)


# ===========================================================================
# 1. Causal DAG & Anti-Mediator Rules Stress-Tests (causal.py)
# ===========================================================================


class TestCausalDAGMediatorExclusion:
    """Adversarially challenge build_scm_graph with mediator and pre-treatment variables."""

    @pytest.fixture
    def empty_projection(self) -> TemporalDAGProjection:
        return TemporalDAGProjection(
            projected_nodes=[],
            projected_edges=[],
            treatment_or_outcome_in_cycle=False,
        )

    @pytest.mark.parametrize(
        "mediator_var",
        [
            "process_behavior",
            "syscall_count",
            "run_duration_s",
            "run_duration",
            "file_behavior",
            "network_behavior",
            "privilege_behavior",
            "contract_deviation",
            "runtime_sbom_drift",
            "b_behavior",
            "b_process",
            "spawned_pids",
            "network_packets",
            "intermediate_process_spawns",
            # Case variations
            "PROCESS_BEHAVIOR",
            "Syscall_Count",
            "RUN_DURATION_S",
            "Network_Behavior",
            # Substring variations
            "custom_process_behavior_metric",
            "intermediate_process_spawns_v2",
        ],
    )
    def test_mediator_covariates_receive_no_edges_to_treatment_or_outcome(
        self, empty_projection: TemporalDAGProjection, mediator_var: str
    ) -> None:
        """Adversarial Challenge: When mediator variables are placed in covariate_names,
        build_scm_graph MUST NOT add M -> T or M -> Y edges.
        """
        treatment = "pkg_target"
        outcome = "contract_drift"

        dag = build_scm_graph(
            projection=empty_projection,
            treatment_name=treatment,
            outcome_name=outcome,
            covariate_names=[mediator_var],
        )

        # The node may exist in the DAG as a declared variable
        assert dag.has_node(mediator_var)
        # But NO directed edge to treatment (M -> T)
        assert not dag.has_edge(
            mediator_var, treatment
        ), f"Anti-mediator violation: edge {mediator_var} -> {treatment} was added!"
        # And NO directed edge to outcome (M -> Y)
        assert not dag.has_edge(
            mediator_var, outcome
        ), f"Anti-mediator violation: edge {mediator_var} -> {outcome} was added!"

    @pytest.mark.parametrize(
        "pre_treatment_var",
        [
            "cluster_node_count",
            "kernel_version",
            "baseline_rps",
            "container_cpu_limit",
            "base_image_os",
            "repetition",
            "initial_memory_mb",
        ],
    )
    def test_pre_treatment_covariates_receive_confounding_edges(
        self, empty_projection: TemporalDAGProjection, pre_treatment_var: str
    ) -> None:
        """Verification: Pre-treatment Tier 0 confounders MUST receive both
        Z -> T and Z -> Y edges.
        """
        treatment = "pkg_target"
        outcome = "contract_drift"

        dag = build_scm_graph(
            projection=empty_projection,
            treatment_name=treatment,
            outcome_name=outcome,
            covariate_names=[pre_treatment_var],
        )

        assert dag.has_edge(
            pre_treatment_var, treatment
        ), f"Missing confounding edge: {pre_treatment_var} -> {treatment}"
        assert dag.has_edge(
            pre_treatment_var, outcome
        ), f"Missing confounding edge: {pre_treatment_var} -> {outcome}"

    def test_mixed_mediators_and_pre_treatment_covariates(
        self, empty_projection: TemporalDAGProjection
    ) -> None:
        """Adversarially mix pre-treatment and post-treatment variables in covariate_names."""
        treatment = "pkg_target"
        outcome = "contract_drift"
        covariates = [
            "cluster_node_count",   # Pre-treatment
            "process_behavior",     # Mediator
            "kernel_version",       # Pre-treatment
            "syscall_count",        # Mediator
            "run_duration_s",       # Mediator
            "baseline_rps",         # Pre-treatment
        ]

        dag = build_scm_graph(
            projection=empty_projection,
            treatment_name=treatment,
            outcome_name=outcome,
            covariate_names=covariates,
        )

        # Pre-treatment variables MUST have both confounding edges
        for pre in ["cluster_node_count", "kernel_version", "baseline_rps"]:
            assert dag.has_edge(pre, treatment), f"Missing {pre} -> {treatment}"
            assert dag.has_edge(pre, outcome), f"Missing {pre} -> {outcome}"

        # Mediators MUST have NO confounding edges
        for med in ["process_behavior", "syscall_count", "run_duration_s"]:
            assert not dag.has_edge(med, treatment), f"Illegal edge: {med} -> {treatment}"
            assert not dag.has_edge(med, outcome), f"Illegal edge: {med} -> {outcome}"

        # Core treatment -> outcome edge must always exist
        assert dag.has_edge(treatment, outcome)

    def test_adversarial_projected_edge_from_mediator_to_treatment_blocked(self) -> None:
        """Adversarial Challenge: What if a malformed or adversarial projection
        attempts to introduce an edge from a mediator into treatment (e.g. process_behavior -> pkg_target)?
        The anti-mediator rule in build_scm_graph must block M -> T.
        """
        treatment = "pkg_target"
        outcome = "contract_drift"
        projection = TemporalDAGProjection(
            projected_nodes=[("process_behavior", 1), (treatment, 1), (outcome, 2)],
            projected_edges=[
                (("process_behavior", 1), (treatment, 1)),  # Illegal M -> T in projection!
                ((treatment, 1), (outcome, 2)),             # Valid T -> Y
            ],
            treatment_or_outcome_in_cycle=False,
        )

        dag = build_scm_graph(
            projection=projection,
            treatment_name=treatment,
            outcome_name=outcome,
            covariate_names=["cluster_node_count"],
        )

        # M -> T must be blocked despite being in projected_edges
        assert not dag.has_edge(
            "process_behavior", treatment
        ), "Anti-mediator violation: projection edge process_behavior -> treatment was NOT blocked!"

    def test_construct_causal_model_with_mediators_preserves_valid_dag(self) -> None:
        """Empirically verify that construct_causal_model executes without cycle or syntax error
        when mediators are present in covariates, while properly filtering confounding edges.
        """
        treatment = "pkg_target"
        outcome = "contract_drift"
        projection = TemporalDAGProjection(
            projected_nodes=[(treatment, 1), (outcome, 2)],
            projected_edges=[((treatment, 1), (outcome, 2))],
            treatment_or_outcome_in_cycle=False,
        )

        # Create 10 observations with overlap across treatment
        # Stratum 3 has 2 treated and 2 control; stratum 4 has 3 treated and 3 control.
        t_vals = [1, 1, 0, 0, 1, 1, 1, 0, 0, 0]
        y_vals = [1, 1, 0, 0, 1, 0, 1, 0, 1, 0]
        node_counts = [3.0, 3.0, 3.0, 3.0, 4.0, 4.0, 4.0, 4.0, 4.0, 4.0]
        observations = []
        for i in range(10):
            observations.append(
                CausalObservation(
                    window_index=0,
                    treatment_value=t_vals[i],
                    outcome_value=y_vals[i],
                    covariates={
                        "cluster_node_count": node_counts[i],
                        "process_behavior": 10.0,
                        "syscall_count": 50.0,
                    },
                )
            )

        covariate_names = ["cluster_node_count", "process_behavior", "syscall_count"]

        handle = construct_causal_model(
            projection=projection,
            observations=observations,
            treatment_name=treatment,
            outcome_name=outcome,
            covariate_names=covariate_names,
        )

        assert handle is not None
        assert handle.model is not None

        # Parse GML graph back to NetworkX DiGraph to verify edges
        reconstructed_dag = nx.parse_gml(handle.graph_gml)
        labels = {node: data.get("label", str(node)) for node, data in reconstructed_dag.nodes(data=True)}
        edge_pairs = {(labels[u], labels[v]) for u, v in reconstructed_dag.edges()}

        # Core treatment -> outcome edge must be present
        assert (treatment, outcome) in edge_pairs

        # Confounder edges for pre-treatment variable must be present
        assert ("cluster_node_count", treatment) in edge_pairs
        assert ("cluster_node_count", outcome) in edge_pairs

        # Mediators must NOT have edges to treatment or outcome
        assert ("process_behavior", treatment) not in edge_pairs
        assert ("process_behavior", outcome) not in edge_pairs
        assert ("syscall_count", treatment) not in edge_pairs
        assert ("syscall_count", outcome) not in edge_pairs


# ===========================================================================
# 2. Observation Builder & Decoupling Stress-Tests (observation_builder.py)
# ===========================================================================


class TestObservationBuilderDecoupling:
    """Adversarially challenge observation builder decoupling and schema integrity."""

    def _make_manifest(
        self,
        run_id: str = "20261024T000000Z_test_run",
        is_attack: bool = True,
        inject_ok: bool = True,
        phantom_alert_ts: str | None = "2026-10-24T00:01:20Z",
        verified_contract_drift: int | None = None,
        is_true_positive: bool = False,
        target_purl: str = "pkg:pypi/lzmaffi@1.0.1",
        clean_purl: str = "pkg:pypi/lzmaffi@1.0.0",
        pre_covariates: dict[str, float] | None = None,
    ) -> RunManifest:
        phases = [
            RunManifestPhase("baseline", "2026-10-24T00:00:00Z", "2026-10-24T00:01:00Z", 60.0),
            RunManifestPhase(
                "inject",
                "2026-10-24T00:01:00Z",
                "2026-10-24T00:01:05Z",
                5.0,
                f"inject_ok={inject_ok}",
            ),
            RunManifestPhase("attack", "2026-10-24T00:01:05Z", "2026-10-24T00:02:05Z", 60.0),
            RunManifestPhase("recover", "2026-10-24T00:02:05Z", "2026-10-24T00:02:10Z", 5.0, "recover_ok=True"),
            RunManifestPhase("post_recovery", "2026-10-24T00:02:10Z", "2026-10-24T00:03:10Z", 60.0),
        ]
        return RunManifest(
            run_id=run_id,
            attack_id="xzutils-001" if is_attack else "benign-load-001",
            attack_family="backdoor" if is_attack else "benign",
            repetition=1,
            namespace="phantom-eval",
            pod_name="pod-1",
            ground_truth_label=1 if is_attack else 0,
            injection_timestamp="2026-10-24T00:01:00Z" if is_attack else None,
            first_phantom_detection_timestamp=phantom_alert_ts,
            mttd_s=20.0 if phantom_alert_ts else None,
            is_true_positive=is_true_positive,
            verified_contract_drift=verified_contract_drift,
            phases=phases,
            target_purl=target_purl if is_attack else "",
            clean_purl=clean_purl,
            pre_treatment_covariates=pre_covariates or {"cluster_node_count": 3.0, "kernel_version_int": 612},
        )

    def test_phantom_alert_alone_is_not_used_as_ydrift(self) -> None:
        """Adversarial Challenge: When PHANTOM detector fires an alert (Y_hat = 1),
        but there is NO independent oracle contract verification (verified_contract_drift=None, is_true_positive=False),
        the observation builder MUST NOT use Y_hat as Y_drift.
        Instead, it must cleanly abstain with OutcomeLabel.UNKNOWN and exclude the observation.
        """
        builder = CausalObservationBuilder()
        manifest = self._make_manifest(
            phantom_alert_ts="2026-10-24T00:01:20Z",  # Detector alert present!
            verified_contract_drift=None,             # Unverified oracle!
            is_true_positive=False,                   # Not verified TP
        )

        batch = builder.build_from_run_manifest_only(manifest)

        # Must NOT include an observation with outcome_value = 1
        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert len(batch.observation_records) == 0
        assert len(batch.insufficiencies) == 1
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN

    def test_verified_contract_drift_overrides_detector_absence(self) -> None:
        """False Negative scenario: Independent oracle verifies contract drift (Y_drift = 1),
        even though PHANTOM detector failed to alert (Y_hat = 0).
        Outcome must be POSITIVE (Y_drift = 1) with y_hat_phantom = 0.
        """
        builder = CausalObservationBuilder()
        manifest = self._make_manifest(
            phantom_alert_ts=None,          # Detector failed to alert (FN)
            verified_contract_drift=1,      # Independent oracle confirmed drift!
            is_true_positive=False,
        )

        batch = builder.build_from_run_manifest_only(manifest)

        assert batch.included_count == 1
        assert len(batch.observation_records) == 1
        rec = batch.observation_records[0]
        assert rec.outcome_value == 1
        assert rec.y_hat_phantom == 0
        assert rec.provenance.outcome_label == OutcomeLabel.POSITIVE
        assert rec.provenance.outcome_label_source == "verified_contract_drift"

    def test_benign_run_with_detector_false_alarm(self) -> None:
        """False Positive scenario: In a benign run, PHANTOM detector mistakenly fires (Y_hat = 1),
        but signed contract verifies conformance (Y_drift = 0).
        Outcome must remain NEGATIVE (Y_drift = 0), decoupled from the detector alert.
        """
        builder = CausalObservationBuilder()
        manifest = self._make_manifest(
            is_attack=False,
            phantom_alert_ts="2026-10-24T00:01:30Z",  # False alarm!
            verified_contract_drift=0,               # Verified clean
            is_true_positive=False,
        )

        batch = builder.build_from_run_manifest_only(manifest)

        assert batch.included_count == 1
        assert len(batch.observation_records) == 1
        rec = batch.observation_records[0]
        assert rec.outcome_value == 0
        assert rec.y_hat_phantom == 1  # Detector alerted
        assert rec.treatment_value == 0
        assert rec.t_inject == 0
        assert rec.t_purl == 0
        assert rec.provenance.outcome_label == OutcomeLabel.NEGATIVE

    def test_decoupling_of_t_inject_and_t_purl_on_failed_injection(self) -> None:
        """Adversarial Challenge: When injection fails (inject_ok=False):
        - T_inject MUST be 0 (delivery failed).
        - T_purl would be 1 (tampered component attempted).
        - The run MUST be classified as FAILED_INJECTION and excluded from causal estimation.
        """
        builder = CausalObservationBuilder()
        manifest = self._make_manifest(
            is_attack=True,
            inject_ok=False,  # Delivery failed!
            verified_contract_drift=None,
        )

        batch = builder.build_from_run_manifest_only(manifest)

        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert len(batch.insufficiencies) == 1
        assert batch.insufficiencies[0].reason_code == "failed_injection"

    def test_treatment_target_selection_inject_vs_purl(self) -> None:
        """Verify that treatment_target parameter separates T_inject from T_purl."""
        builder = CausalObservationBuilder()
        manifest = self._make_manifest(
            is_attack=True,
            inject_ok=True,
            verified_contract_drift=1,
        )

        # When target is inject
        batch_inject = builder.build_from_run_manifest_only(
            manifest, treatment_target="inject"
        )
        rec_inject = batch_inject.observation_records[0]
        assert rec_inject.treatment_value == 1
        assert rec_inject.t_inject == 1
        assert rec_inject.t_purl == 1

        # When target is purl
        batch_purl = builder.build_from_run_manifest_only(
            manifest, treatment_target="purl"
        )
        rec_purl = batch_purl.observation_records[0]
        assert rec_purl.treatment_value == 1
        assert rec_purl.t_inject == 1
        assert rec_purl.t_purl == 1

    def test_observation_record_schema_fields_and_immutability(self) -> None:
        """Verify ObservationRecord schema fields, types, and frozen immutability."""
        evidence_id = str(uuid.uuid4())
        bdg_data = [
            {
                "node_type": "purl",
                "mapping_status": "VERIFIED",
                "evidence_refs": [evidence_id],
            }
        ]
        manifest = self._make_manifest(
            run_id="20261024T120000Z_solarwinds-001_rep1",
            is_attack=True,
            inject_ok=True,
            verified_contract_drift=1,
            pre_covariates={"cluster_node_count": 5.0, "kernel_version": 6.8},
        )

        builder = CausalObservationBuilder()
        batch = builder.build_from_run_manifest_only(manifest, bdg_node_data=bdg_data)

        assert len(batch.observation_records) == 1
        rec = batch.observation_records[0]

        # Verify all mandatory schema fields
        assert rec.run_id == "20261024T120000Z_solarwinds-001_rep1"
        assert rec.window_id == "20261024T120000Z_solarwinds-001_rep1_w0"
        assert rec.window_index == 0
        assert rec.t_inject == 1
        assert rec.t_purl == 1
        assert rec.treatment_value == 1
        assert rec.outcome_value == 1
        assert rec.y_hat_phantom == 1
        assert rec.pre_treatment_covariates == {"cluster_node_count": 5.0, "kernel_version": 6.8}
        assert rec.event_refs == (evidence_id,)
        assert rec.provenance is not None
        assert rec.provenance.window_id == "20261024T120000Z_solarwinds-001_rep1_w0"
        assert rec.provenance.event_refs == (evidence_id,)

        # Verify immutability (frozen dataclass)
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.run_id = "mutated_id"  # type: ignore

        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.provenance.window_id = "mutated_window"  # type: ignore

    def test_post_treatment_execution_artifacts_excluded_from_covariates(self) -> None:
        """Verify that post-treatment artifacts like run_duration_s or injection_succeeded
        are NEVER placed into pre_treatment_covariates.
        """
        manifest = self._make_manifest(
            is_attack=True,
            inject_ok=True,
            verified_contract_drift=1,
        )

        builder = CausalObservationBuilder()
        batch = builder.build_from_run_manifest_only(manifest)
        rec = batch.observation_records[0]

        # Explicitly verify absence of post-treatment execution metrics
        assert "run_duration_s" not in rec.pre_treatment_covariates
        assert "run_duration" not in rec.pre_treatment_covariates
        assert "injection_succeeded" not in rec.pre_treatment_covariates
        assert "process_behavior" not in rec.pre_treatment_covariates
        assert "syscall_count" not in rec.pre_treatment_covariates

    def test_batch_aggregation_and_gate_g1_abstention(self) -> None:
        """Adversarially test multi-run batch building and preflight gate enforcement.
        1. Batch with 8 valid observations + 2 failed injections -> excluded=2, included=8.
        2. can_proceed_to_estimation is False (8 < 10).
        3. Adding 2 more benign runs -> included=10 -> can_proceed_to_estimation is True.
        4. Validate against Preflight Gates: G1, treatment variation, and anti-window slicing.
        """
        from app.domain.causal_validation import (
            gate_minimum_observations,
            gate_treatment_variation,
            gate_unique_run_ids,
            GateOutcome,
        )

        builder = CausalObservationBuilder(minimum_observations=10)
        manifests = []
        # 5 completed attacks with verified contract drift
        for i in range(5):
            manifests.append(
                self._make_manifest(
                    run_id=f"run_attack_{i:02d}",
                    is_attack=True,
                    inject_ok=True,
                    verified_contract_drift=1,
                )
            )
        # 3 benign controls
        for i in range(3):
            manifests.append(
                self._make_manifest(
                    run_id=f"run_benign_{i:02d}",
                    is_attack=False,
                    inject_ok=True,
                    verified_contract_drift=0,
                )
            )
        # 2 failed injection runs
        for i in range(2):
            manifests.append(
                self._make_manifest(
                    run_id=f"run_failed_{i:02d}",
                    is_attack=True,
                    inject_ok=False,
                    verified_contract_drift=None,
                )
            )

        batch = builder.build_from_run_batch(manifests)
        assert batch.included_count == 8
        assert batch.excluded_count == 2
        assert not batch.can_proceed_to_estimation

        # Gate G1 must block batch of 8
        g1_verdict = gate_minimum_observations(batch.included_count, minimum=10)
        assert g1_verdict.outcome == GateOutcome.BLOCK
        assert g1_verdict.reason == "too_few_observations"

        # Add 2 more benign controls to reach N=10
        manifests.append(self._make_manifest(run_id="run_benign_03", is_attack=False, inject_ok=True, verified_contract_drift=0))
        manifests.append(self._make_manifest(run_id="run_benign_04", is_attack=False, inject_ok=True, verified_contract_drift=0))

        batch10 = builder.build_from_run_batch(manifests)
        assert batch10.included_count == 10
        assert batch10.can_proceed_to_estimation

        # Gate G1 must pass batch of 10
        g1_pass = gate_minimum_observations(batch10.included_count, minimum=10)
        assert g1_pass.outcome == GateOutcome.PASS

        # Treatment variation must pass (5 treated, 5 controls)
        t_verdict = gate_treatment_variation(batch10.observation_records)
        assert t_verdict.outcome == GateOutcome.PASS

        # Anti-window slicing gate must pass (10 unique run IDs)
        run_ids = [rec.run_id for rec in batch10.observation_records]
        slice_verdict = gate_unique_run_ids(run_ids, minimum_unique_runs=10)
        assert slice_verdict.outcome == GateOutcome.PASS

    def test_window_slicing_adversarial_detection(self) -> None:
        """Adversarial Challenge: If an adversary slices 1 run into 10 windows
        to fabricate N=10 and bypass Gate G1, gate_unique_run_ids MUST detect
        the unit slicing and block estimation.
        """
        from app.domain.causal_validation import (
            gate_unique_run_ids,
            GateOutcome,
        )

        fake_sliced_run_ids = ["single_run_01"] * 10
        verdict = gate_unique_run_ids(fake_sliced_run_ids, minimum_unique_runs=10)
        assert verdict.outcome == GateOutcome.BLOCK
        assert verdict.reason == "window_slicing_detected"
        assert verdict.suggested_status == "insufficient_evidence"

    @pytest.mark.parametrize(
        "var_name,expected_is_mediator",
        [
            ("process_behavior", True),
            ("syscall_count", True),
            ("run_duration_s", True),
            ("file_behavior", True),
            ("network_behavior", True),
            ("privilege_behavior", True),
            ("contract_deviation", True),
            ("runtime_sbom_drift", True),
            ("spawned_pids", True),
            ("intermediate_process_spawns", True),
            # Non-mediator pre-treatment confounders
            ("cluster_node_count", False),
            ("kernel_version", False),
            ("baseline_rps", False),
            ("container_cpu_limit", False),
            ("repetition", False),
            ("environment", False),
            ("cloud_region", False),
        ],
    )
    def test_is_post_treatment_mediator_boundary_discrimination(
        self, var_name: str, expected_is_mediator: bool
    ) -> None:
        """Verify strict discrimination between post-treatment mediators and pre-treatment confounders."""
        assert is_post_treatment_mediator(var_name) is expected_is_mediator

