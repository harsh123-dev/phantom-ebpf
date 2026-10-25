"""
research/evaluation/tests/test_adversarial_challenger_m4.py

Adversarial Stress Test Suite for Milestone 4:
Deterministic Reporting CLI, LaTeX/CSV Tables, and Data Exclusion Integrity.
Author: challenger_m4_1_gen2

Adversarial Challenge Dimensions:
1. CLI Robustness & Error Handling:
   - Non-existent data directory returns exit code 1 cleanly without uncaught traceback.
   - Empty directory returns exit code 1 cleanly.
   - Directory with invalid/corrupt JSON runs handles errors per run without crashing.
   - Directory with missing run files referenced in index.json records run error cleanly.
   - Deep custom output paths (--out, --tables-dir) auto-create parent directories cleanly.
   - Custom stdout output (--out -) with and without explicit --tables-dir.
   - Missing arguments or invalid flags handled gracefully by argparse.

2. Determinism Verification:
   - Multi-run byte-level comparison of emitted LaTeX and CSV tables.
   - Multi-run comparison of reports.json: metrics, Wilson CI, bootstrap MTTD CI (seed=42),
     exclusions, and data quality metrics must be bitwise identical across distinct runs.
   - Raw dataset and Raw3 dataset reproducibility.

3. Data Exclusion Integrity & Oracle Verification:
   - SolarWinds failed injections (inject_ok=False) strictly excluded from TPR denominator.
   - TPR = 1.0 (6/6) and Wilson CI [0.6096, 1.0] when solarwinds runs are excluded.
   - If solarwinds runs were erroneously included, TPR would be 6/9 = 0.667; verify this is rejected.
   - Structure and completeness of exclusion records in output JSON.
   - Verification that benign runs and valid attack runs are never misclassified as exclusions.
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import run_pipeline_report
from research.evaluation.metrics.evaluator import (
    EvaluationReport,
    ScenarioEvaluator,
    is_failed_injection,
)
from research.evaluation.scenarios.scenario_runner import PhaseRecord, ScenarioResult


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
RAW_DIR = REPO_ROOT / "research" / "datasets" / "raw"
RAW3_DIR = REPO_ROOT / "research" / "datasets" / "raw3"


# ==============================================================================
# Challenge 1: CLI Robustness & Error Boundaries
# ==============================================================================

class TestCLIErrorHandlingAndBoundaries:
    """Stress-tests run_pipeline_report CLI against adversarial inputs and edge cases."""

    def test_cli_nonexistent_directory(self, tmp_path: Path):
        """Non-existent directory must exit with code 1 and a clean stderr message."""
        bad_dir = tmp_path / "does_not_exist_at_all"
        cmd = [sys.executable, "run_pipeline_report.py", "--data-dir", str(bad_dir), "--out", "-"]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 1
        assert "ERROR: data directory not found" in res.stderr
        assert "Traceback" not in res.stderr

    def test_cli_empty_directory(self, tmp_path: Path):
        """Empty directory (no JSON files) must exit with code 1 without unhandled crash."""
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        cmd = [sys.executable, "run_pipeline_report.py", "--data-dir", str(empty_dir), "--out", "-"]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 1
        assert "ERROR: No run IDs found" in res.stderr
        assert "Traceback" not in res.stderr

    def test_cli_directory_with_corrupt_json_files(self, tmp_path: Path):
        """Directory with corrupt JSON files must process gracefully without crashing."""
        corrupt_dir = tmp_path / "corrupt_dir"
        corrupt_dir.mkdir()
        # Create an index with two runs: one corrupt JSON, one missing
        index = {"results": ["corrupt_run", "missing_run"]}
        with open(corrupt_dir / "index.json", "w", encoding="utf-8") as f:
            json.dump(index, f)
        # Create invalid JSON content
        with open(corrupt_dir / "corrupt_run.json", "w", encoding="utf-8") as f:
            f.write("{ INVALID JSON DATA ... ")

        out_file = tmp_path / "corrupt_out.json"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(corrupt_dir),
            "--out",
            str(out_file),
        ]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0
        assert out_file.exists()
        with open(out_file, encoding="utf-8") as f:
            report = json.load(f)
        assert report["total_runs_in_index"] == 2
        # Check that errors are cleanly recorded per run
        runs = report["runs"]
        assert len(runs) == 2
        corrupt_entry = next(r for r in runs if r["run_id"] == "corrupt_run")
        assert "Processing failed" in corrupt_entry["error"]
        missing_entry = next(r for r in runs if r["run_id"] == "missing_run")
        assert "Run file not found" in missing_entry["error"]

    def test_cli_nested_custom_output_paths_auto_create_parents(self, tmp_path: Path):
        """Deeply nested non-existent --out and --tables-dir paths are auto-created cleanly."""
        nested_out = tmp_path / "level1" / "level2" / "reports" / "custom_report.json"
        nested_tables = tmp_path / "tables_dir" / "levelA" / "levelB"

        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(RAW3_DIR),
            "--out",
            str(nested_out),
            "--tables-dir",
            str(nested_tables),
        ]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0, f"CLI failed: {res.stderr}"
        assert nested_out.exists()
        assert (nested_tables / "table_1_detection_performance.tex").exists()
        assert (nested_tables / "table_1_detection_performance.csv").exists()
        assert (nested_tables / "table_1_detection_performance_extended.tex").exists()

    def test_cli_stdout_mode_with_tables_dir(self, tmp_path: Path):
        """--out - with --tables-dir writes JSON to stdout and tables to specified directory."""
        tables_dir = tmp_path / "stdout_tables"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(RAW3_DIR),
            "--out",
            "-",
            "--tables-dir",
            str(tables_dir),
        ]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0
        # Check that stdout is valid JSON
        data = json.loads(res.stdout)
        assert data["schema_version"] == "v1.0.0"
        assert (tables_dir / "table_1_detection_performance.tex").exists()
        assert (tables_dir / "table_1_detection_performance.csv").exists()

    def test_cli_unrecognized_argument_handling(self):
        """Unrecognized CLI arguments should exit with code 2 without uncaught traceback."""
        cmd = [sys.executable, "run_pipeline_report.py", "--invalid-flag", "value"]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 2
        assert "unrecognized arguments" in res.stderr
        assert "Traceback" not in res.stderr


# ==============================================================================
# Challenge 2: Determinism Verification
# ==============================================================================

class TestPipelineDeterminism:
    """Stress-tests pipeline report and table generator for absolute determinism."""

    def test_raw3_pipeline_determinism(self, tmp_path: Path):
        """Multiple independent runs on raw3 produce identical metrics and table files."""
        run1_dir = tmp_path / "run1"
        run2_dir = tmp_path / "run2"
        run1_dir.mkdir()
        run2_dir.mkdir()

        out1 = run1_dir / "reports.json"
        out2 = run2_dir / "reports.json"

        # Execute run 1
        res1 = subprocess.run(
            [sys.executable, "run_pipeline_report.py", "--data-dir", str(RAW3_DIR), "--out", str(out1)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert res1.returncode == 0

        # Execute run 2
        res2 = subprocess.run(
            [sys.executable, "run_pipeline_report.py", "--data-dir", str(RAW3_DIR), "--out", str(out2)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert res2.returncode == 0

        with open(out1, encoding="utf-8") as f:
            d1 = json.load(f)
        with open(out2, encoding="utf-8") as f:
            d2 = json.load(f)

        # 1. Scientific Metrics must be strictly identical
        assert d1["metrics"] == d2["metrics"]
        assert d1["metrics"]["tpr"] == 1.0
        assert d1["metrics"]["tpr_ci_wilson"] == d2["metrics"]["tpr_ci_wilson"]
        assert d1["metrics"]["mttd_ci_bootstrap"] == d2["metrics"]["mttd_ci_bootstrap"]

        # 2. Exclusions must be identical
        assert d1["exclusions"] == d2["exclusions"]
        assert len(d1["exclusions"]) == 3

        # 3. Data quality counts must be identical
        assert d1["data_quality"] == d2["data_quality"]
        assert d1["summary"] == d2["summary"]

        # 4. Baselines and overhead metrics identical
        assert d1["baselines"] == d2["baselines"]
        assert d1["overhead"] == d2["overhead"]

        # 5. Tables must be byte-for-byte identical
        tex1 = (run1_dir / "table_1_detection_performance.tex").read_text(encoding="utf-8")
        tex2 = (run2_dir / "table_1_detection_performance.tex").read_text(encoding="utf-8")
        assert tex1 == tex2

        csv1 = (run1_dir / "table_1_detection_performance.csv").read_text(encoding="utf-8")
        csv2 = (run2_dir / "table_1_detection_performance.csv").read_text(encoding="utf-8")
        assert csv1 == csv2

        ext_tex1 = (run1_dir / "table_1_detection_performance_extended.tex").read_text(encoding="utf-8")
        ext_tex2 = (run2_dir / "table_1_detection_performance_extended.tex").read_text(encoding="utf-8")
        assert ext_tex1 == ext_tex2

    def test_raw_pipeline_determinism(self, tmp_path: Path):
        """Multiple independent runs on raw dataset produce identical dropout records."""
        out1 = tmp_path / "raw_out1.json"
        out2 = tmp_path / "raw_out2.json"

        res1 = subprocess.run(
            [sys.executable, "run_pipeline_report.py", "--data-dir", str(RAW_DIR), "--out", str(out1)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert res1.returncode == 0

        res2 = subprocess.run(
            [sys.executable, "run_pipeline_report.py", "--data-dir", str(RAW_DIR), "--out", str(out2)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert res2.returncode == 0

        with open(out1, encoding="utf-8") as f:
            d1 = json.load(f)
        with open(out2, encoding="utf-8") as f:
            d2 = json.load(f)

        assert d1["metrics"] == d2["metrics"]
        assert d1["summary"] == d2["summary"]
        assert d1["data_quality"] == d2["data_quality"]
        # In raw/, 3 attack runs suffered collection dropout and 3 are benign controls (total = 6)
        assert d1["summary"]["collection_dropouts"] == 3
        assert d1["summary"]["benign_count"] == 3
        assert d1["data_quality"]["total_runs"] == 6


# ==============================================================================
# Challenge 3: Data Exclusion Integrity
# ==============================================================================

class TestDataExclusionIntegrity:
    """Verifies that failed injections are strictly excluded and never pollute TPR."""

    def test_solarwinds_exclusion_in_pipeline_report(self, tmp_path: Path):
        """Pipeline report excludes solarwinds runs from TPR denominator."""
        out_file = tmp_path / "raw3_report.json"
        cmd = [
            sys.executable,
            "run_pipeline_report.py",
            "--data-dir",
            str(RAW3_DIR),
            "--out",
            str(out_file),
        ]
        res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
        assert res.returncode == 0

        with open(out_file, encoding="utf-8") as f:
            report = json.load(f)

        # Total runs in raw3 index is 9
        assert report["total_runs_in_index"] == 9

        # Exclusions must contain exactly 3 runs
        exclusions = report["exclusions"]
        assert len(exclusions) == 3

        excluded_ids = {e["scenario_id"] for e in exclusions}
        assert excluded_ids == {
            "solarwinds-001_rep1",
            "solarwinds-001_rep2",
            "solarwinds-001_rep3",
        }
        for e in exclusions:
            assert e["reason"] == "failed_injection"
            assert "inject() returned False" in e["error"]
            assert "EXPERIMENT_PROTOCOL.md" in e["notes"]

        # Detection metrics must reflect 6 completed attacks, NOT 9
        metrics = report["metrics"]
        assert metrics["n_attack_scenarios"] == 6
        assert metrics["excluded_failed_injections"] == 3
        assert metrics["tp"] == 6
        assert metrics["fn"] == 0
        assert metrics["tpr"] == 1.0  # 6 / 6

        # Standard Wilson score for 6/6 at 95% confidence must be [0.6096, 1.0000]
        ci = metrics["tpr_ci_wilson"]
        assert ci is not None
        assert ci[0] == pytest.approx(0.6096, abs=0.001)
        assert ci[1] == pytest.approx(1.0000, abs=0.001)

    def test_adversarial_counterfactual_unexcluded_tpr_divergence(self):
        """Demonstrate that failure to exclude solarwinds drops TPR to 6/9 = 0.667."""
        # Load raw3 runs
        runs = []
        for p in sorted(RAW3_DIR.glob("*.json")):
            with open(p, encoding="utf-8") as f:
                runs.append(json.load(f))
        assert len(runs) == 9

        evaluator = ScenarioEvaluator()

        # Build ScenarioResult objects without failed injection handling
        scenario_results_naive = []
        for r in runs:
            sr = ScenarioResult(
                run_id=r["run_id"],
                attack_id=r["attack_id"],
                attack_family="supply-chain",
                repetition=int(r.get("repetition", 1)),
                namespace=r.get("namespace", "default"),
                pod_name=r.get("pod_name", "target"),
                ground_truth_label=1,
                is_true_positive=bool(r.get("is_true_positive", False)),
                mttd_s=r.get("mttd_s"),
                # Intentionally omitting inject_ok or setting inject_ok=True
            )
            scenario_results_naive.append(sr)

        # In naive mode: without failed injection exclusion
        reports_naive = evaluator.evaluate(
            scenario_results=scenario_results_naive,
            detections={"falco-default-rules": [], "trivy-sbom-static": [], "isolation-forest-syscall-frequency": []},
        )
        phantom_naive = next(rep for rep in reports_naive if rep.detector_name == "phantom")

        # In naive mode: 6 TPs out of 9 attacks -> TPR = 6/9 = ~0.6667
        assert phantom_naive.n_attack_scenarios == 9
        assert phantom_naive.tpr == pytest.approx(6 / 9, abs=0.001)
        assert phantom_naive.tpr != 1.0

        # Now test with proper failed injection detection
        scenario_results_proper = []
        for r in runs:
            sr = ScenarioResult(
                run_id=r["run_id"],
                attack_id=r["attack_id"],
                attack_family="supply-chain",
                repetition=int(r.get("repetition", 1)),
                namespace=r.get("namespace", "default"),
                pod_name=r.get("pod_name", "target"),
                ground_truth_label=1,
                is_true_positive=bool(r.get("is_true_positive", False)),
                mttd_s=r.get("mttd_s"),
                error=r.get("error", ""),
            )
            if "solarwinds" in r["attack_id"]:
                sr.inject_ok = False
            scenario_results_proper.append(sr)

        reports_proper = evaluator.evaluate(
            scenario_results=scenario_results_proper,
            detections={"falco-default-rules": [], "trivy-sbom-static": [], "isolation-forest-syscall-frequency": []},
        )
        phantom_proper = next(rep for rep in reports_proper if rep.detector_name == "phantom")

        # In proper mode: 6 TPs out of 6 valid attacks, 3 excluded -> TPR = 1.0
        assert phantom_proper.n_attack_scenarios == 6
        assert phantom_proper.excluded_failed_injections == 3
        assert phantom_proper.tpr == 1.0

    def test_benign_and_valid_attacks_never_falsely_excluded(self):
        """Verify that benign runs and valid attack runs are never classified as failed injections."""
        from datetime import datetime, timezone
        now = datetime.now(tz=timezone.utc)

        # 1. Valid attack scenario
        sr_valid = ScenarioResult(
            run_id="valid_attack_01",
            attack_id="xzutils-001",
            attack_family="supply-chain",
            repetition=1,
            namespace="default",
            pod_name="victim",
            ground_truth_label=1,
            is_true_positive=True,
            mttd_s=14.5,
            error="",
            phases=[PhaseRecord(name="inject", start_time=now, duration_s=10.0, notes="Rollout successful")],
        )
        sr_valid.inject_ok = True
        assert is_failed_injection(sr_valid) is False

        # 2. Valid benign control scenario
        sr_benign = ScenarioResult(
            run_id="benign_control_01",
            attack_id="benign-load-001",
            attack_family="benign",
            repetition=1,
            namespace="default",
            pod_name="victim",
            ground_truth_label=0,
            is_true_positive=False,
            mttd_s=None,
            error="",
            phases=[PhaseRecord(name="baseline", start_time=now, duration_s=60.0, notes="Normal load")],
        )
        assert is_failed_injection(sr_benign) is False
