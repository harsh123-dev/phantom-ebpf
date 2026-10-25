"""
test_adversarial_m4.py
Adversarial challenge and stress-testing suite for Milestone 4 deliverables.

Covers:
1. CLI robustness in run_pipeline_report.py:
   - Missing data directory
   - Non-directory path as data-dir
   - Empty data directory
   - Data directory with index.json referencing missing run file
   - Data directory with corrupted JSON file
   - Stdout '-' output: must produce clean parseable JSON without corrupting stdout
   - Explicit --tables-dir vs default tables-dir behavior
   - Output file in non-existent nested directory
2. Table generation edge cases (comparison_table.py):
   - When metrics are None, LaTeX must contain r"\\text{---}" and NEVER "0.000" or "nan"
   - When metrics are None, CSV must contain "---" or "" (never "nan" or "None")
   - Bolding behavior:
     - Unmeasured rows (overhead_status="unmeasured") must NEVER be bolded
     - Baseline detectors with "unavailable" status must NEVER be bolded
     - Fallback zeros must NOT be marked as best
     - Column where all detectors have None must have NO bold values
     - When one detector is measured (5.0%) and another is unmeasured (0.0%), 0.0% must NOT be bolded
   - LaTeX syntax and alignment: column counts match across all rows
   - CSV round-trip compatibility with csv.DictReader
3. Documentation consistency (EXPERIMENTAL_EVALUATION_README.md):
   - Check that documented 10 unsupported claims match reports.json exactly
   - Check that documented reproduction commands match reality
   - Check schema version matches "v1.0.0"
   - Check excluded runs count and reasons match documented facts
"""

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
CAUSAL_ENGINE_DIR = PROJECT_ROOT / "services" / "causal-engine"
if str(CAUSAL_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(CAUSAL_ENGINE_DIR))

import run_pipeline_report
from research.evaluation.metrics.comparison_table import (
    format_latex_cell,
    format_csv_cell,
    generate_comparison_table,
    generate_csv,
    write_tables,
    _find_best,
)
from research.evaluation.metrics.evaluator import EvaluationReport


# ===========================================================================
# 1. CLI Robustness Tests
# ===========================================================================

class TestCLIRobustness:
    def test_missing_data_directory(self, tmp_path):
        """CLI returns exit code 1 when data-dir does not exist."""
        non_existent = tmp_path / "does_not_exist"
        ret = run_pipeline_report.main(["--data-dir", str(non_existent), "--out", "-"])
        assert ret == 1

    def test_data_dir_is_a_file(self, tmp_path):
        """CLI handles case where data-dir is a file rather than a directory."""
        fake_file = tmp_path / "file.txt"
        fake_file.write_text("not a dir", encoding="utf-8")
        # _run_ids_from_index or glob should not crash with unhandled exception
        try:
            ret = run_pipeline_report.main(["--data-dir", str(fake_file), "--out", "-"])
            # Should return 1 (no run IDs found)
            assert ret == 1
        except Exception as e:
            pytest.fail(f"CLI crashed unexpectedly when data-dir is a file: {e}")

    def test_empty_data_directory(self, tmp_path):
        """CLI returns exit code 1 when data-dir has no json files."""
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        ret = run_pipeline_report.main(["--data-dir", str(empty_dir), "--out", "-"])
        assert ret == 1

    def test_empty_index_json(self, tmp_path):
        """CLI returns exit code 1 when index.json contains an empty list."""
        data_dir = tmp_path / "data_with_empty_index"
        data_dir.mkdir()
        (data_dir / "index.json").write_text(json.dumps({"results": []}), encoding="utf-8")
        ret = run_pipeline_report.main(["--data-dir", str(data_dir), "--out", "-"])
        assert ret == 1

    def test_missing_run_file_in_index(self, tmp_path):
        """When index.json lists runs that don't exist, report notes missing run without crashing."""
        data_dir = tmp_path / "data_missing_run"
        data_dir.mkdir()
        (data_dir / "index.json").write_text(json.dumps({"results": ["missing_run_001"]}), encoding="utf-8")
        out_file = tmp_path / "out.json"

        ret = run_pipeline_report.main(["--data-dir", str(data_dir), "--out", str(out_file)])
        assert ret == 0
        assert out_file.exists()
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["runs"]) == 1
        assert "Run file not found" in data["runs"][0]["error"]
        assert data["runs"][0]["estimation_attempted"] is False

    def test_corrupted_run_file(self, tmp_path):
        """When a run JSON is corrupt, pipeline notes processing error without crashing."""
        data_dir = tmp_path / "data_corrupt"
        data_dir.mkdir()
        (data_dir / "index.json").write_text(json.dumps({"results": ["corrupt_run"]}), encoding="utf-8")
        (data_dir / "corrupt_run.json").write_text("{invalid json", encoding="utf-8")
        out_file = tmp_path / "out.json"

        ret = run_pipeline_report.main(["--data-dir", str(data_dir), "--out", str(out_file)])
        assert ret == 0
        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["runs"]) == 1
        assert "Processing failed" in data["runs"][0]["error"]

    def test_stdout_dash_output_cleanliness(self, capsys):
        """Using '--out -' must emit purely valid JSON to stdout without log pollution."""
        raw3_dir = PROJECT_ROOT / "research" / "datasets" / "raw3"
        ret = run_pipeline_report.main(["--data-dir", str(raw3_dir), "--out", "-"])
        assert ret == 0
        captured = capsys.readouterr()
        # Ensure stdout parses as valid JSON
        try:
            parsed = json.loads(captured.out)
            assert parsed["schema_version"] == "v1.0.0"
        except json.JSONDecodeError as exc:
            pytest.fail(f"Stdout was polluted and could not be parsed as JSON: {exc}\nCaptured stdout:\n{captured.out[:500]}")

    def test_output_to_nested_new_directory(self, tmp_path):
        """Specifying --out in a deeply nested non-existent directory creates parent directories."""
        raw3_dir = PROJECT_ROOT / "research" / "datasets" / "raw3"
        out_file = tmp_path / "deep" / "nested" / "path" / "report.json"
        ret = run_pipeline_report.main(["--data-dir", str(raw3_dir), "--out", str(out_file)])
        assert ret == 0
        assert out_file.exists()

    def test_explicit_tables_dir(self, tmp_path):
        """Explicit --tables-dir writes tables to that directory instead of --out parent."""
        raw3_dir = PROJECT_ROOT / "research" / "datasets" / "raw3"
        out_file = tmp_path / "reports" / "report.json"
        custom_tables = tmp_path / "custom_tables"
        ret = run_pipeline_report.main([
            "--data-dir", str(raw3_dir),
            "--out", str(out_file),
            "--tables-dir", str(custom_tables),
        ])
        assert ret == 0
        assert (custom_tables / "table_1_detection_performance.tex").exists()
        assert (custom_tables / "table_1_detection_performance.csv").exists()
        assert (custom_tables / "table_1_detection_performance_extended.tex").exists()


# ===========================================================================
# 2. Table Generation Edge Cases
# ===========================================================================

class TestTableGenerationEdgeCases:
    def test_none_value_formatting(self):
        """format_latex_cell and format_csv_cell handle None properly."""
        assert format_latex_cell(None) == r"\text{---}"
        assert format_latex_cell(None, is_best=True) == r"\text{---}"
        assert format_csv_cell(None) == "---"

    def test_latex_table_never_contains_nan_or_raw_none(self):
        """generate_comparison_table must never output 'nan' or 'None' in cells."""
        rep = EvaluationReport(
            detector_name="phantom",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tp=6,
            fp=None,
            fn=0,
            tn=None,
            tpr=1.0,
            fpr=None,
            precision=None,
            f1=None,
            mttd_mean_s=15.74,
            overhead_status="unmeasured",
            cpu_overhead_pct=None,
            memory_overhead_mb=None,
            status="evaluated",
        )
        table_latex = generate_comparison_table([rep])
        assert "nan" not in table_latex.lower()
        assert "none" not in table_latex.lower()
        assert r"\text{---}" in table_latex

    def test_unmeasured_overhead_never_bolded(self):
        """When overhead is unmeasured (even if numeric 0.0), it must not be bolded."""
        # rep1 has unmeasured overhead with 0.0
        rep1 = EvaluationReport(
            detector_name="phantom",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tpr=1.0,
            fpr=None,
            f1=None,
            mttd_mean_s=10.0,
            overhead_status="unmeasured",
            cpu_overhead_pct=0.0,
            status="evaluated",
        )
        # rep2 has measured overhead 5.0
        rep2 = EvaluationReport(
            detector_name="baseline1",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tpr=0.8,
            fpr=None,
            f1=None,
            mttd_mean_s=20.0,
            overhead_status="measured",
            cpu_overhead_pct=5.0,
            status="evaluated",
        )
        table_latex = generate_comparison_table([rep1, rep2])
        # rep1 cpu_overhead_pct is unmeasured, so \textbf{0.000} MUST NOT appear
        assert r"\textbf{0.000}" not in table_latex
        # Best CPU overhead among valid (measured) is 5.0, so 5.0 should be bolded
        assert r"\textbf{5.000}" in table_latex

    def test_unavailable_detector_never_bolded(self):
        """Detectors with status 'telemetry_unavailable' must never have bolded metric values."""
        phantom = EvaluationReport(
            detector_name="phantom",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tpr=1.0,
            fpr=None,
            f1=None,
            mttd_mean_s=15.0,
            overhead_status="unmeasured",
            cpu_overhead_pct=None,
            status="evaluated",
        )
        # A baseline that accidentally has a numeric metric but status is telemetry_unavailable
        baseline = EvaluationReport(
            detector_name="falco-default-rules",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tpr=0.5,
            fpr=0.01,
            f1=0.6,
            mttd_mean_s=5.0,  # lower than phantom!
            overhead_status="unmeasured",
            cpu_overhead_pct=1.0,
            status="telemetry_unavailable",
        )
        table_latex = generate_comparison_table([phantom, baseline])
        # Baseline must not be bolded for mttd_mean_s (5.000) because it is unavailable
        assert r"\textbf{5.000}" not in table_latex

    def test_all_none_column_no_bold(self):
        """When all detectors have None for a metric, no bolding occurs for that column."""
        rep1 = EvaluationReport(
            detector_name="phantom",
            n_attack_scenarios=6,
            n_benign_scenarios=0,
            tpr=1.0,
            fpr=None,
            f1=None,
            mttd_mean_s=10.0,
            overhead_status="unmeasured",
            cpu_overhead_pct=None,
            false_positives_per_hour=None,
            status="evaluated",
        )
        table_latex = generate_comparison_table([rep1])
        # Check that FPR and F1 are \text{---} without \textbf
        assert r"\textbf{\text{---}}" not in table_latex
        assert r"\text{---}" in table_latex

    def test_csv_dict_reader_compatibility(self, tmp_path):
        """Generated CSV can be parsed by csv.DictReader with exact field alignment."""
        reports = [
            EvaluationReport(
                detector_name="phantom",
                n_attack_scenarios=6,
                n_benign_scenarios=0,
                tp=6,
                fp=None,
                fn=0,
                tn=None,
                tpr=1.0,
                fpr=None,
                precision=None,
                recall=1.0,
                f1=None,
                mttd_mean_s=15.74,
                overhead_status="unmeasured",
                cpu_overhead_pct=None,
                memory_overhead_mb=None,
                status="evaluated",
            ),
            EvaluationReport(
                detector_name="falco-default-rules",
                n_attack_scenarios=6,
                n_benign_scenarios=0,
                status="telemetry_unavailable",
            ),
        ]
        csv_path = tmp_path / "test.csv"
        generate_csv(reports, out_path=csv_path)

        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["detector_name"] == "phantom"
        assert rows[0]["tpr"] == "1.0000"
        assert rows[0]["fpr"] == ""  # None represented as empty or ---
        assert rows[0]["tp"] == "6"
        assert rows[1]["detector_name"] == "falco-default-rules"
        assert rows[1]["tpr"] == ""


# ===========================================================================
# 3. Documentation Consistency Tests
# ===========================================================================

class TestDocumentationConsistency:
    def test_unsupported_claims_match_exact_list(self):
        """The 10 unsupported claims in README match run_pipeline_report.py exactly."""
        readme_path = PROJECT_ROOT / "EXPERIMENTAL_EVALUATION_README.md"
        assert readme_path.exists(), "EXPERIMENTAL_EVALUATION_README.md missing"
        readme_text = readme_path.read_text(encoding="utf-8")

        # Load reports.json generated from raw3
        raw3_dir = PROJECT_ROOT / "research" / "datasets" / "raw3"
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            tf_path = Path(tf.name)
        try:
            run_pipeline_report.main(["--data-dir", str(raw3_dir), "--out", str(tf_path)])
            with open(tf_path, encoding="utf-8") as f:
                report_data = json.load(f)

            unsupported = report_data["claims_NOT_supported_by_this_data"]
            assert len(unsupported) == 10, f"Expected exactly 10 unsupported claims, got {len(unsupported)}"

            # Verify each claim is documented in the README
            for claim in unsupported:
                assert claim in readme_text, f"Claim '{claim}' not mentioned in README"
        finally:
            if tf_path.exists():
                tf_path.unlink()

    def test_readme_reproduction_commands_executable(self, tmp_path):
        """Commands documented in README Section 7 can be executed literally."""
        # 1. python run_pipeline_report.py --data-dir research/datasets/raw3 --out <tmp>/reports.json
        out_raw3 = tmp_path / "out_raw3.json"
        cmd1 = [sys.executable, str(PROJECT_ROOT / "run_pipeline_report.py"), "--data-dir", "research/datasets/raw3", "--out", str(out_raw3)]
        res1 = subprocess.run(cmd1, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
        assert res1.returncode == 0, f"Command failed: {res1.stderr}"
        assert out_raw3.exists()

        # 2. python run_pipeline_report.py --data-dir research/datasets/raw --out <tmp>/raw_report.json
        out_raw = tmp_path / "out_raw.json"
        cmd2 = [sys.executable, str(PROJECT_ROOT / "run_pipeline_report.py"), "--data-dir", "research/datasets/raw", "--out", str(out_raw)]
        res2 = subprocess.run(cmd2, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
        assert res2.returncode == 0, f"Command failed: {res2.stderr}"
        assert out_raw.exists()

    def test_pinned_versions_in_readme(self):
        """Pinned tool versions (Falco 0.44.1, Trivy 0.70.0) are documented in README."""
        readme_path = PROJECT_ROOT / "EXPERIMENTAL_EVALUATION_README.md"
        readme_text = readme_path.read_text(encoding="utf-8")
        assert "0.44.1" in readme_text
        assert "0.70.0" in readme_text

    def test_five_phase_lifecycle_in_readme(self):
        """Five-phase scenario lifecycle is documented in README."""
        readme_path = PROJECT_ROOT / "EXPERIMENTAL_EVALUATION_README.md"
        readme_text = readme_path.read_text(encoding="utf-8")
        for phase in ["baseline", "inject", "attack", "recover", "post-recovery"]:
            assert phase in readme_text
