"""
tests/e2e/test_tier4_scenarios.py

Tier 4: Real-World Application Scenarios.
Covers:
1. Scenario 1: Raw dataset end-to-end audit (all 6 indexed runs verified as telemetry dropout,
   108 historical runs inventoried, verify absence of drift/injection).
2. Scenario 2: Raw3 dataset end-to-end evaluation (6 completed attacks with 3,701 drift events,
   3 failed SolarWinds injections excluded from TPR, Wilson score and bootstrap MTTD calculation).
3. Scenario 3: Real reproduction pipeline execution (run_pipeline_report.py on datasets,
   verifying gate abstentions, summary statistics, and honest limitation disclosures).
4. Scenario 4: Ground truth protocol & oracle alignment (verifying manifests against 6 oracle YAML
   files in research/evaluation/oracles/, verifying decoupled dimensions).
5. Scenario 5: Full LaTeX / CSV artifact generation and verification (verifying \\text{---} and ---
   formatting for unmeasured cells without misleading bolding or artificial 0%/100%).
"""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
import pytest
import yaml

from tests.e2e.contracts import (
    compute_ordinary_wilson_score,
    compute_mttd_statistics,
    classify_scenario_run,
    DecoupledEvaluationDimensions,
    compute_defensible_metrics,
    format_latex_cell,
    format_csv_cell,
    RunClassification,
)
from tests.e2e.conftest import isolated_service_import
from research.evaluation.metrics.evaluator import EvaluationReport, ScenarioEvaluator
from research.evaluation.scenarios.scenario_runner import ScenarioResult
from research.evaluation.metrics.comparison_table import (
    generate_comparison_table,
    generate_csv,
    write_tables,
)
import run_pipeline_report


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def raw_data_dir(repo_root: Path) -> Path:
    return repo_root / "research" / "datasets" / "raw"


@pytest.fixture
def raw3_data_dir(repo_root: Path) -> Path:
    return repo_root / "research" / "datasets" / "raw3"


@pytest.fixture
def oracles_dir(repo_root: Path) -> Path:
    return repo_root / "research" / "evaluation" / "oracles"


# ==============================================================================
# Scenario 1: Raw Dataset End-to-End Audit & Telemetry Dropout Verification
# ==============================================================================

class TestScenario1RawDatasetAudit:
    """Verifies the raw dataset audit and telemetry dropout detection."""

    def test_raw_dataset_index_and_files_exist(self, raw_data_dir: Path):
        """All 6 indexed runs in index.json must exist on disk and be valid JSON."""
        index_file = raw_data_dir / "index.json"
        assert index_file.exists(), f"Missing index.json in {raw_data_dir}"

        with open(index_file, encoding="utf-8") as f:
            idx = json.load(f)
        assert "results" in idx
        run_ids = idx["results"]
        assert len(run_ids) == 6, f"Expected 6 indexed runs, found {len(run_ids)}"

        for r_id in run_ids:
            run_path = raw_data_dir / f"{r_id}.json"
            assert run_path.exists(), f"Run JSON file missing: {run_path}"
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)
            assert data["run_id"] == r_id
            assert "phases" in data
            assert "phantom_detections" in data

    def test_raw_dataset_telemetry_dropout_verified(self, raw_data_dir: Path):
        """All 6 indexed runs must have zero detections; attacks classified as telemetry dropout, controls as benign."""
        index_file = raw_data_dir / "index.json"
        with open(index_file, encoding="utf-8") as f:
            idx = json.load(f)

        for r_id in idx["results"]:
            run_path = raw_data_dir / f"{r_id}.json"
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)

            classification = classify_scenario_run(data)
            # In the raw dataset, attack runs have empty phantom_detections (telemetry dropout),
            # while benign runs have ground_truth_label=0 (benign control).
            if data.get("ground_truth_label") == 1:
                assert classification == RunClassification.TELEMETRY_DROPOUT
            else:
                assert classification == RunClassification.BENIGN_CONTROL
            assert len(data.get("phantom_detections", [])) == 0

    def test_raw_dataset_historical_runs_inventory(self, raw_data_dir: Path):
        """Verify the presence of historical run files in raw directory."""
        all_json_files = list(raw_data_dir.glob("*.json"))
        # Exclude index.json
        run_files = [p for p in all_json_files if p.stem != "index"]
        # There are over 100 historical run files in raw/
        assert len(run_files) >= 108, f"Expected >= 108 historical files, found {len(run_files)}"

    def test_raw_dataset_preflight_gate_g1_abstains(self, repo_root: Path, raw_data_dir: Path):
        """AnalysisUseCase on raw runs must trigger gate G1 abstention due to insufficient observations."""
        with isolated_service_import("causal-engine"):
            from app.domain.observation_builder import CausalObservationBuilder, RunManifest
            from app.application.run_analysis import RunAnalysisUseCase

            builder = CausalObservationBuilder()
            use_case = RunAnalysisUseCase(builder=builder)

            index_file = raw_data_dir / "index.json"
            with open(index_file, encoding="utf-8") as f:
                idx = json.load(f)

            for r_id in idx["results"]:
                run_path = raw_data_dir / f"{r_id}.json"
                with open(run_path, encoding="utf-8") as f:
                    raw_dict = json.load(f)
                manifest = RunManifest.from_dict(raw_dict)
                report = use_case.execute(manifest)

                # Gate G1 must fail or abstain
                assert report.preflight_passed is False
                assert report.estimation_attempted is False
                assert (
                    report.preflight_first_blocker_reason != ""
                    or len(report.missing_data_summary) > 0
                    or len(report.exclusion_reasons) > 0
                )

    def test_raw_dataset_honest_evaluation_no_fabricated_metrics(self, raw_data_dir: Path):
        """Raw dataset runs must not produce non-zero TPR, precision, or MTTD when detections are absent."""
        scenario_results = []
        index_file = raw_data_dir / "index.json"
        with open(index_file, encoding="utf-8") as f:
            idx = json.load(f)

        for r_id in idx["results"]:
            run_path = raw_data_dir / f"{r_id}.json"
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)
            scenario_results.append(
                ScenarioResult(
                    run_id=r_id,
                    attack_id=data.get("attack_id", "unknown"),
                    attack_family=data.get("attack_family", "unknown"),
                    repetition=data.get("repetition", 1),
                    namespace=data.get("namespace", "phantom-eval"),
                    pod_name=data.get("pod_name", "unknown"),
                    ground_truth_label=data.get("ground_truth_label", 1),
                    first_phantom_detection_timestamp=None,
                    mttd_s=None,
                    is_true_positive=False,
                    phantom_detections=[],
                )
            )

        evaluator = ScenarioEvaluator()
        report = evaluator._evaluate_phantom(scenario_results)

        assert report.tp == 0
        assert report.tpr == 0.0
        assert report.mttd_mean_s is None
        assert report.mttd_p50_s is None


# ==============================================================================
# Scenario 2: Raw3 Dataset End-to-End Evaluation & Defensible Metrics
# ==============================================================================

class TestScenario2Raw3DatasetEvaluation:
    """Verifies the raw3 dataset evaluation with completed attacks and failed injections."""

    def test_raw3_dataset_inventory(self, raw3_data_dir: Path):
        """Raw3 must contain 9 run JSON files: 3 xzutils, 3 dep-confusion, 3 solarwinds."""
        all_json_files = sorted(raw3_data_dir.glob("*.json"))
        assert len(all_json_files) == 9, f"Expected 9 run files in raw3, found {len(all_json_files)}"

        xz_files = [p for p in all_json_files if "xzutils" in p.name]
        dep_files = [p for p in all_json_files if "dep-confusion" in p.name]
        sw_files = [p for p in all_json_files if "solarwinds" in p.name]

        assert len(xz_files) == 3
        assert len(dep_files) == 3
        assert len(sw_files) == 3

    def test_raw3_dataset_completed_attacks_and_drift_events(self, raw3_data_dir: Path):
        """6 completed attack runs must contain 3,701 total drift events and positive detections."""
        completed_files = [
            p for p in raw3_data_dir.glob("*.json")
            if "xzutils" in p.name or "dep-confusion" in p.name
        ]
        assert len(completed_files) == 6

        total_drift_events = 0
        for p in completed_files:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            assert data["is_true_positive"] is True
            assert data["mttd_s"] is not None and data["mttd_s"] > 0
            detections = data.get("phantom_detections", [])
            assert len(detections) > 0
            total_drift_events += len(detections)

        assert total_drift_events == 3701, f"Expected 3,701 total drift events, got {total_drift_events}"

    def test_raw3_dataset_failed_injections_detected(self, raw3_data_dir: Path):
        """3 SolarWinds runs must be identified as failed injections (inject_ok=False)."""
        sw_files = [p for p in raw3_data_dir.glob("*.json") if "solarwinds" in p.name]
        assert len(sw_files) == 3

        for p in sw_files:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            assert data.get("error") == "inject() returned False"
            inject_phase = next((ph for ph in data.get("phases", []) if ph.get("name") == "inject"), None)
            assert inject_phase is not None
            assert "inject_ok=False" in inject_phase.get("notes", "")

            classification = classify_scenario_run(data)
            assert classification == RunClassification.FAILED_INJECTION

    def test_raw3_dataset_defensible_metrics_calculation(self, raw3_data_dir: Path):
        """Defensible evaluation: TPR = 6/6 (1.0), failed injections excluded from TPR denominator."""
        all_runs = []

        for p in sorted(raw3_data_dir.glob("*.json")):
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            all_runs.append(data)

        assert len(all_runs) == 9

        # Compute defensible metrics
        metrics = compute_defensible_metrics(all_runs)

        assert metrics.tpr == 1.0
        assert metrics.tp == 6
        assert metrics.excluded_failed_injections == 3
        assert metrics.fpr is None  # Undefined when benign_controls == 0

    def test_raw3_dataset_wilson_score_confidence_interval(self, raw3_data_dir: Path):
        """Wilson score on 6/6 completed attacks yields defensible [0.6096, 1.0] interval."""
        lower, upper = compute_ordinary_wilson_score(successes=6, trials=6, confidence=0.95)
        assert lower == pytest.approx(0.6096, abs=0.001)
        assert upper == pytest.approx(1.0, abs=0.001)

    def test_raw3_dataset_bootstrap_mttd(self, raw3_data_dir: Path):
        """Bootstrap MTTD statistics on raw3 completed attacks."""
        mttd_values = []
        for p in sorted(raw3_data_dir.glob("*.json")):
            if "xzutils" in p.name or "dep-confusion" in p.name:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                val = data.get("mttd_s")
                assert val is not None
                mttd_values.append(val)

        assert len(mttd_values) == 6
        stats = compute_mttd_statistics(mttd_values, n_bootstrap=1000, seed=42)
        assert stats is not None
        assert stats.mean > 0
        assert stats.median > 0
        assert stats.bootstrap_ci_95 is not None
        assert stats.bootstrap_ci_95[0] <= stats.median <= stats.bootstrap_ci_95[1]


# ==============================================================================
# Scenario 3: Real Reproduction Pipeline Execution
# ==============================================================================

class TestScenario3ReproductionPipeline:
    """Verifies reproduction pipeline execution using run_pipeline_report.py."""

    def test_pipeline_report_execution_on_raw_data(self, raw_data_dir: Path, tmp_path: Path):
        """run_pipeline_report.py must execute cleanly on raw dataset and generate valid JSON."""
        out_file = tmp_path / "pipeline_report.json"
        exit_code = run_pipeline_report.main([
            "--data-dir", str(raw_data_dir),
            "--out", str(out_file),
        ])
        assert exit_code == 0
        assert out_file.exists()

        with open(out_file, encoding="utf-8") as f:
            report_data = json.load(f)

        assert "generated_at" in report_data
        assert report_data["total_runs_in_index"] == 6
        assert len(report_data["runs"]) == 6

        summary = report_data["summary"]
        assert summary["total_runs"] == 6
        assert summary["preflight_passed_count"] == 0
        assert summary["real_estimates_produced"] == 0
        assert summary["observation_batches_sufficient_for_estimation"] == 0

    def test_pipeline_report_honest_limitations_and_unsupported_claims(self, raw_data_dir: Path, tmp_path: Path):
        """Pipeline report must explicitly list honest limitations and unsupported claims."""
        out_file = tmp_path / "pipeline_report_limitations.json"
        run_pipeline_report.main([
            "--data-dir", str(raw_data_dir),
            "--out", str(out_file),
        ])

        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)

        assert "limitations" in data
        assert len(data["limitations"]) >= 6

        assert "claims_NOT_supported_by_this_data" in data
        unsupported = data["claims_NOT_supported_by_this_data"]
        expected_unsupported = [
            "Detection rate (TPR / recall)",
            "False positive rate (FPR)",
            "Precision",
            "F1 score",
            "Mean time to detection (MTTD)",
            "Causal attribution accuracy (CAA)",
            "PCEPS Brier score",
            "CPU/memory overhead (all metrics are zero in the dataset)",
            "Real-data average treatment effect (ATE)",
            "Any comparison to baseline detectors from this run batch",
        ]
        for exp in expected_unsupported:
            assert exp in unsupported, f"Expected unsupported claim '{exp}' not found in report"

    def test_pipeline_report_invalid_directory_returns_error(self, tmp_path: Path):
        """run_pipeline_report.py returns non-zero exit code when directory does not exist."""
        non_existent = tmp_path / "non_existent_dir"
        exit_code = run_pipeline_report.main([
            "--data-dir", str(non_existent),
            "--out", "-",
        ])
        assert exit_code == 1


# ==============================================================================
# Scenario 4: Ground Truth Protocol & Oracle Alignment
# ==============================================================================

class TestScenario4OracleAlignment:
    """Verifies the ground truth evaluation protocol and oracle manifest definitions."""

    def test_oracle_manifest_inventory(self, oracles_dir: Path):
        """All 6 oracle YAML files must exist in research/evaluation/oracles/."""
        expected_oracles = [
            "xzutils-001.yaml",
            "dep-confusion-001.yaml",
            "solarwinds-001.yaml",
            "benign-load-001.yaml",
            "benign-restart-001.yaml",
            "benign-update-001.yaml",
        ]
        for o_name in expected_oracles:
            o_path = oracles_dir / o_name
            assert o_path.exists(), f"Oracle manifest missing: {o_path}"

    def test_oracle_attack_and_benign_partition(self, oracles_dir: Path):
        """Oracles must partition into 3 attacks (label=1) and 3 benign controls (label=0)."""
        attack_oracles = []
        benign_oracles = []

        for p in oracles_dir.glob("*.yaml"):
            with open(p, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if doc["ground_truth_label"] == 1:
                attack_oracles.append(doc)
            elif doc["ground_truth_label"] == 0:
                benign_oracles.append(doc)
            else:
                pytest.fail(f"Invalid ground_truth_label {doc['ground_truth_label']} in {p.name}")

        assert len(attack_oracles) == 3
        assert len(benign_oracles) == 3

    def test_oracle_decoupled_dimensions_specification(self, oracles_dir: Path):
        """Each oracle specifies decoupled dimensions: injection offset, detection window, and behavioral changes."""
        for p in oracles_dir.glob("*.yaml"):
            with open(p, encoding="utf-8") as f:
                doc = yaml.safe_load(f)

            assert "attack_id" in doc
            assert "attack_family" in doc
            assert "detection_window_s" in doc
            assert doc["detection_window_s"] in (120.0, 180.0)
            assert "repetitions" in doc
            assert doc["repetitions"] == 3

            dims = DecoupledEvaluationDimensions(
                t_inject=True,
                b_verified="true" if doc["ground_truth_label"] == 1 else "false",
                y_drift="true" if len(doc.get("expected_behavioral_changes", [])) > 0 else "false",
                y_hat_phantom=False,
            )
            assert dims.is_eligible_for_causal() is True


# ==============================================================================
# Scenario 5: Full LaTeX / CSV Artifact Generation & Verification
# ==============================================================================

class TestScenario5ArtifactGeneration:
    """Verifies generation of defensible LaTeX and CSV performance tables."""

    @pytest.fixture
    def mock_evaluation_reports(self) -> list[EvaluationReport]:
        """Produces realistic reports reflecting defensible evaluation state."""
        r_phantom = EvaluationReport(
            detector_name="phantom",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tp=6,
            fp=0,
            fn=0,
            tn=0,
            tpr=1.0,
            fpr=None,  # Defensibly None due to 0 benign controls
            precision=1.0,
            recall=1.0,
            f1=1.0,
            mttd_mean_s=70.5,
            mttd_p50_s=70.0,
            mttd_p95_s=72.0,
            cpu_overhead_pct=None,  # Unmeasured
            memory_overhead_mb=None,  # Unmeasured
            false_positives_per_hour=None,
            attribution_accuracy=None,
            brier_score=None,
        )

        r_falco = EvaluationReport(
            detector_name="falco-default-rules",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tp=0,
            fp=0,
            fn=6,
            tn=0,
            tpr=0.0,
            fpr=None,
            precision=None,
            recall=0.0,
            f1=0.0,
            mttd_mean_s=None,
            mttd_p50_s=None,
            mttd_p95_s=None,
            cpu_overhead_pct=None,
            memory_overhead_mb=None,
            false_positives_per_hour=None,
            attribution_accuracy=None,
            brier_score=None,
        )

        return [r_phantom, r_falco]

    def test_latex_comparison_table_generation(self, mock_evaluation_reports):
        """generate_comparison_table generates defensible LaTeX table with \\text{---}."""
        latex_str = generate_comparison_table(mock_evaluation_reports)
        assert r"\begin{table}" in latex_str
        assert r"\end{table}" in latex_str
        assert "PHANTOM" in latex_str
        assert "Falco" in latex_str
        # Unmeasured values (fpr, cpu_overhead) must be rendered as \text{---}
        assert r"\text{---}" in latex_str

    def test_latex_extended_table_generation(self, mock_evaluation_reports):
        """generate_comparison_table with extended=True includes CAA, Brier score and MTTD percentiles."""
        ext_latex = generate_comparison_table(mock_evaluation_reports, extended=True)
        assert r"\begin{table}" in ext_latex or r"\begin{table*}" in ext_latex
        assert "CAA" in ext_latex
        assert "BS" in ext_latex
        assert r"\text{---}" in ext_latex

    def test_comparison_csv_generation(self, mock_evaluation_reports):
        """generate_csv generates valid CSV with empty string for None values."""
        csv_str = generate_csv(mock_evaluation_reports)
        reader = list(csv.DictReader(csv_str.strip().splitlines()))
        assert len(reader) == 2

        phantom_row = next(r for r in reader if "phantom" in r["detector_name"].lower())
        assert phantom_row["tpr"] == "1.0000"
        # fpr and cpu_overhead must be empty string for None values
        assert phantom_row["fpr"] == ""
        assert phantom_row["cpu_overhead_pct"] == ""

    def test_format_helpers_adhere_to_oracle_rules(self):
        """Oracle formatting helpers produce exact standard strings."""
        assert format_latex_cell(None) == r"\text{---}"
        assert format_latex_cell(1.0, is_best=True) == r"\textbf{1.000}"
        assert format_latex_cell(0.5, is_best=False) == "0.500"

        assert format_csv_cell(None) == "---"
        assert format_csv_cell(0.85) == "0.8500"
