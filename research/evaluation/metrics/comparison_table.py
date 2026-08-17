"""
research/evaluation/metrics/comparison_table.py

Generates the paper's detection performance comparison tables.

Produces:
    1. LaTeX table (TABLE_1 from handoff §7.3) — Detection Performance Comparison.
       Columns: Detector, TPR, FPR, F1, MTTD(s), CPU Overhead, FP/hr.
       The best value in each column is bold. PHANTOM row is always first.

    2. Extended LaTeX table including all metrics (for appendix/supplementary).

    3. CSV file for post-processing in notebooks (table_1_detection_performance.ipynb).

Usage (standalone):
    python research/evaluation/metrics/comparison_table.py \\
        --results-dir research/datasets/raw/ \\
        --output-dir research/evaluation/results/

Usage (from evaluator):
    from research.evaluation.metrics.comparison_table import generate_comparison_table
    latex_str = generate_comparison_table(reports)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from typing import Any

from research.evaluation.metrics.evaluator import EvaluationReport

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Table column definitions
# ---------------------------------------------------------------------------

# Columns for TABLE_1 (main paper table — handoff §7.3).
_TABLE_1_COLS: list[tuple[str, str, bool]] = [
    # (field_name, latex_header, higher_is_better)
    ("tpr",                       r"TPR",          True),
    ("fpr",                       r"FPR",          False),
    ("f1",                        r"F1",           True),
    ("mttd_mean_s",               r"MTTD(s)",      False),
    ("cpu_overhead_pct",          r"CPU\%",        False),
    ("false_positives_per_hour",  r"FP/hr",        False),
]

# Extended columns for appendix table.
_TABLE_EXTENDED_COLS: list[tuple[str, str, bool]] = [
    ("tpr",                       r"TPR",          True),
    ("fpr",                       r"FPR",          False),
    ("precision",                 r"Prec.",        True),
    ("recall",                    r"Recall",       True),
    ("f1",                        r"F1",           True),
    ("mttd_mean_s",               r"MTTD$_\mu$(s)", False),
    ("mttd_p50_s",                r"MTTD$_{50}$(s)", False),
    ("mttd_p95_s",                r"MTTD$_{95}$(s)", False),
    ("cpu_overhead_pct",          r"CPU\%",        False),
    ("memory_overhead_mb",        r"Mem(MB)",      False),
    ("false_positives_per_hour",  r"FP/hr",        False),
    ("attribution_accuracy",      r"CAA",          True),
    ("brier_score",               r"BS",           False),
]

# Preferred detector display order.
_DETECTOR_ORDER: list[str] = [
    "phantom",
    "falco-default-rules",
    "trivy-sbom-static",
    "isolation-forest-syscall-frequency",
    "cvss-only",
]

# Display name overrides for LaTeX table.
_DISPLAY_NAMES: dict[str, str] = {
    "phantom":                              r"\textbf{PHANTOM (ours)}",
    "falco-default-rules":                  r"Falco (default rules)",
    "trivy-sbom-static":                    r"Trivy (static scan)",
    "isolation-forest-syscall-frequency":   r"IsoForest (na\"{i}ve)",
    "cvss-only":                            r"CVSS-only",
}


def _fmt(val: float | None, decimal: int = 3) -> str:
    """Format a metric value for the LaTeX table cell.

    Args:
        val: Metric value or None (displayed as —).
        decimal: Number of decimal places.

    Returns:
        Formatted string.
    """
    if val is None:
        return r"\text{---}"
    return f"{val:.{decimal}f}"


def _bold(s: str) -> str:
    """Wrap a string in LaTeX bold.

    Args:
        s: Value string.

    Returns:
        LaTeX bold string.
    """
    return rf"\textbf{{{s}}}"


def _sort_reports(reports: list[EvaluationReport]) -> list[EvaluationReport]:
    """Sort reports by the preferred detector display order.

    Detectors not in _DETECTOR_ORDER appear at the end in insertion order.

    Args:
        reports: List of EvaluationReport.

    Returns:
        Sorted list.
    """
    order_map = {name: i for i, name in enumerate(_DETECTOR_ORDER)}
    return sorted(
        reports,
        key=lambda r: order_map.get(r.detector_name, len(_DETECTOR_ORDER)),
    )


def _find_best(
    reports: list[EvaluationReport],
    field: str,
    higher_is_better: bool,
) -> float | None:
    """Find the best value for a metric field across all reports.

    Args:
        reports: List of EvaluationReport.
        field: Attribute name.
        higher_is_better: True if higher values are better.

    Returns:
        Best value or None if all values are None.
    """
    vals = [
        getattr(r, field)
        for r in reports
        if getattr(r, field) is not None
    ]
    if not vals:
        return None
    return max(vals) if higher_is_better else min(vals)


def generate_comparison_table(
    reports: list[EvaluationReport],
    caption: str = "Detection performance comparison across detectors and scenarios.",
    label: str = "tab:detection_performance",
    extended: bool = False,
) -> str:
    """Generate a LaTeX table from a list of EvaluationReport objects.

    The best value in each metric column is bolded.
    The PHANTOM row appears first.
    A ``\\dagger`` footnote marks MTTD as undefined for static scanners (Trivy).

    Args:
        reports: List of EvaluationReport (one per detector).
        caption: LaTeX table caption.
        label: LaTeX label for cross-referencing.
        extended: If True, generate the extended appendix table with
            all metrics. If False, generate the compact TABLE_1.

    Returns:
        LaTeX table string.
    """
    sorted_reports = _sort_reports(reports)
    cols = _TABLE_EXTENDED_COLS if extended else _TABLE_1_COLS

    # Compute best values for bold formatting.
    best: dict[str, float | None] = {
        field: _find_best(sorted_reports, field, higher_is_better)
        for field, _, higher_is_better in cols
    }

    # Build column spec.
    n_metric_cols = len(cols)
    col_spec = "l" + "r" * n_metric_cols
    header_row = (
        "Detector & "
        + " & ".join(latex_hdr for _, latex_hdr, _ in cols)
        + r" \\"
    )

    rows: list[str] = []
    for report in sorted_reports:
        display = _DISPLAY_NAMES.get(
            report.detector_name,
            report.detector_name.replace("_", r"\_"),
        )
        cells: list[str] = [display]
        for field, _, higher_is_better in cols:
            val = getattr(report, field)
            formatted = _fmt(val, decimal=3)
            best_val = best.get(field)
            if (
                best_val is not None
                and val is not None
                and abs(val - best_val) < 1e-9
            ):
                formatted = _bold(formatted)
            cells.append(formatted)
        rows.append(" & ".join(cells) + r" \\")

    table = [
        r"\begin{table}[h]",
        r"\centering",
        rf"\caption{{{caption}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{col_spec}}}",
        r"\hline",
        header_row,
        r"\hline",
        *rows,
        r"\hline",
        r"\end{tabular}",
        r"\vspace{0.5em}",
        (
            r"\footnotesize{$\dagger$ MTTD is undefined for Trivy (point-in-time scanner). "
            r"PHANTOM (ours) is the proposed system; all others are baselines.}"
        ),
        r"\end{table}",
    ]

    return "\n".join(table)


def generate_csv(
    reports: list[EvaluationReport],
    out_path: Path | None = None,
) -> str:
    """Generate a CSV of all metric values for notebook processing.

    Includes all fields from EvaluationReport that are numeric or None.

    Args:
        reports: List of EvaluationReport.
        out_path: If provided, write CSV to this path.

    Returns:
        CSV string.
    """
    sorted_reports = _sort_reports(reports)
    all_cols = _TABLE_EXTENDED_COLS

    fieldnames = ["detector_name"] + [field for field, _, _ in all_cols] + [
        "tp", "fp", "fn", "tn",
        "n_attack_scenarios", "n_benign_scenarios",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for report in sorted_reports:
        row: dict[str, Any] = {"detector_name": report.detector_name}
        for field, _, _ in all_cols:
            val = getattr(report, field)
            row[field] = f"{val:.4f}" if isinstance(val, float) else (str(val) if val is not None else "")
        row["tp"] = report.tp
        row["fp"] = report.fp
        row["fn"] = report.fn
        row["tn"] = report.tn
        row["n_attack_scenarios"] = report.n_attack_scenarios
        row["n_benign_scenarios"] = report.n_benign_scenarios
        writer.writerow(row)

    csv_str = output.getvalue()

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(csv_str)
        log.info("comparison_table.csv_written", extra={"path": str(out_path)})

    return csv_str


def write_tables(
    reports: list[EvaluationReport],
    output_dir: Path,
    prefix: str = "table_1",
) -> dict[str, Path]:
    """Write all table formats (LaTeX main, LaTeX extended, CSV) to disk.

    Args:
        reports: List of EvaluationReport.
        output_dir: Directory to write files into.
        prefix: File name prefix.

    Returns:
        Dict mapping format name → written path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}

    # Main TABLE_1 LaTeX.
    latex_main = generate_comparison_table(reports, extended=False)
    p_main = output_dir / f"{prefix}_detection_performance.tex"
    p_main.write_text(latex_main)
    paths["latex_main"] = p_main

    # Extended LaTeX (appendix).
    latex_ext = generate_comparison_table(
        reports,
        caption=(
            "Extended detection performance results including all metrics. "
            "CAA = Causal Attribution Accuracy (PHANTOM only). "
            "BS = PCEPS Brier Score (PHANTOM only)."
        ),
        label="tab:detection_performance_extended",
        extended=True,
    )
    p_ext = output_dir / f"{prefix}_detection_performance_extended.tex"
    p_ext.write_text(latex_ext)
    paths["latex_extended"] = p_ext

    # CSV.
    p_csv = output_dir / f"{prefix}_detection_performance.csv"
    generate_csv(reports, out_path=p_csv)
    paths["csv"] = p_csv

    log.info(
        "comparison_table.written",
        extra={"files": {k: str(v) for k, v in paths.items()}},
    )
    return paths


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse
    import sys

    _REPO_ROOT = Path(__file__).resolve().parents[3]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    from research.evaluation.metrics.evaluator import EvaluationReport

    parser = argparse.ArgumentParser(
        description="Generate comparison tables from saved EvaluationReport JSON files."
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=_REPO_ROOT / "research" / "datasets" / "raw",
        help="Directory containing ScenarioResult JSON files.",
    )
    parser.add_argument(
        "--reports-json",
        type=Path,
        default=None,
        help="Path to a pre-computed EvaluationReport list JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "research" / "evaluation" / "results",
        help="Directory to write output tables.",
    )
    args = parser.parse_args()

    if args.reports_json and args.reports_json.exists():
        with args.reports_json.open() as fh:
            raw_reports = json.load(fh)
        loaded_reports = [EvaluationReport(**r) for r in raw_reports]
    else:
        print(
            "No --reports-json provided. "
            "Run run_all_scenarios.py and evaluator.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    paths = write_tables(loaded_reports, args.output_dir)
    for fmt, path in paths.items():
        print(f"{fmt}: {path}")


# ---------------------------------------------------------------------------
# load_scenario_results — loader helper (used by comparison pipeline)
# ---------------------------------------------------------------------------


def load_scenario_results(results_dir: Path) -> list[Any]:
    """Load all ScenarioResult JSON files from a directory.

    Looks for files matching ``*.json`` in ``results_dir`` that are not
    the ``index.json`` file produced by run_all_scenarios.py.

    Args:
        results_dir: Directory containing per-run scenario JSON files.

    Returns:
        List of raw dicts (each matching the ScenarioResult.to_dict() schema).
        Callers that need ScenarioResult objects should import and use
        ``ScenarioResult`` from ``scenario_runner``.
    """
    results: list[Any] = []
    if not results_dir.exists():
        log.warning("load_scenario_results.dir_missing", path=str(results_dir))
        return results

    for path in sorted(results_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            results.append(data)
            log.debug("load_scenario_results.loaded", path=str(path))
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "load_scenario_results.failed",
                path=str(path),
                error=str(exc),
            )
    return results

