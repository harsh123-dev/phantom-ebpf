"""
run_pipeline_report.py

Deterministic PHANTOM evaluation pipeline report and table generator CLI.

Evaluates real experimental runs from research/datasets/raw or research/datasets/raw3
using the hardened ScenarioEvaluator, Wilson score confidence intervals, bootstrap MTTD,
and table generator without fabricating missing evidence, labels, or telemetry.

Usage (from project root):
    python run_pipeline_report.py [--data-dir PATH] [--out PATH] [--tables-dir PATH]

Arguments:
    --data-dir    Path to datasets directory (e.g. research/datasets/raw3).
                  Default: research/datasets/raw
    --out         Path to write the JSON report (default: stdout).
    --tables-dir  Path to directory for LaTeX and CSV comparison tables.
                  Default: parent directory of --out (if writing to file).

Output format:
    {
      "schema_version": "v1.0.0",
      "generated_at": "<ISO 8601>",
      "python_version": "<version>",
      "dowhy_available": false,
      "data_dir": "<path>",
      "total_runs_in_index": 9,
      "runs": [ {...per-run causal report...} ],
      "summary": { ...aggregate summary with data quality counts... },
      "data_quality": { ...completed_attacks, failed_injections, collection_dropouts, benign_count... },
      "exclusions": [ {...run exclusions with reasons...} ],
      "metrics": { ...tpr, tpr_ci_wilson, fpr, precision, f1, mttd stats... },
      "overhead": { ...cpu, memory, lag, status="unmeasured"... },
      "baselines": { ...falco, trivy, isolation-forest status="telemetry_unavailable"... },
      "detector_reports": [ {...per-detector report dicts...} ],
      "limitations": [ ...honest limitation disclosures... ],
      "claims_NOT_supported_by_this_data": [ ...10 unsupported claims... ]
    }
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Bootstrap: ensure project root and causal-engine are on sys.path.
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_CAUSAL_ENGINE_DIR = _SCRIPT_DIR / "services" / "causal-engine"
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
if str(_CAUSAL_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_CAUSAL_ENGINE_DIR))

from research.evaluation.metrics.comparison_table import (
    generate_comparison_table,
    generate_csv,
    write_tables,
)
from research.evaluation.metrics.evaluator import (
    EvaluationReport,
    ScenarioEvaluator,
    is_failed_injection,
)
from research.evaluation.scenarios.scenario_runner import (
    MetricsSnapshot,
    PhaseRecord,
    ScenarioResult,
)

log = logging.getLogger(__name__)


def _check_dowhy() -> bool:
    """Return True if dowhy is genuinely functional in this environment.

    Performs an isolated smoke-import in a subprocess to ensure native DLLs
    load cleanly without crashing the interpreter (e.g. Windows error 0xc0000139)
    or hanging. Module discovery alone (find_spec) is not sufficient.
    """
    import importlib.util
    import subprocess

    if importlib.util.find_spec("dowhy") is None:
        return False

    try:
        res = subprocess.run(
            [sys.executable, "-c", "import dowhy"],
            capture_output=True,
            timeout=20,
        )
        return res.returncode == 0
    except Exception:
        return False


def _load_manifest_dict(path: Path) -> dict:
    """Load a run JSON file and return its dict."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _run_ids_from_index(data_dir: Path) -> list[str]:
    """Load run IDs from index.json, or fall back to all JSON files."""
    index_path = data_dir / "index.json"
    if index_path.exists():
        with open(index_path, encoding="utf-8") as f:
            idx = json.load(f)
        return idx.get("results", [])
    # Fallback: use all JSON files sorted (excluding non-scenario files).
    return [
        p.stem for p in sorted(data_dir.glob("*.json"))
        if p.stem not in ("index", "reports", "reports_summary")
    ]


def _find_run_file(data_dir: Path, run_id: str) -> Path | None:
    """Find the JSON file for a given run_id."""
    direct = data_dir / f"{run_id}.json"
    if direct.exists():
        return direct
    # Search all JSON files for a match.
    for p in data_dir.glob("*.json"):
        if p.stem == run_id:
            return p
    return None


def _serialize_report(report: object) -> dict:
    """Serialize an AnalysisReport to a plain dict for JSON output."""
    import dataclasses  # noqa: PLC0415
    import uuid  # noqa: PLC0415

    def _conv(val):
        if dataclasses.is_dataclass(val) and not isinstance(val, type):
            return {k: _conv(v) for k, v in dataclasses.asdict(val).items()}
        if isinstance(val, list):
            return [_conv(x) for x in val]
        if isinstance(val, dict):
            return {k: _conv(v) for k, v in val.items()}
        if isinstance(val, uuid.UUID):
            return str(val)
        if isinstance(val, float) and (val != val):  # NaN check
            return None
        if hasattr(val, "value") and isinstance(val.value, str):  # Enum
            return val.value
        if hasattr(val, "isoformat"):  # datetime
            return val.isoformat()
        return val

    return _conv(report)


def _dict_to_scenario_result(data: dict[str, Any]) -> ScenarioResult:
    """Reconstruct a ScenarioResult from a serialized dict."""
    def _dt(val: str | None) -> datetime | None:
        if not val:
            return None
        try:
            return datetime.fromisoformat(val.rstrip("Z")).replace(tzinfo=timezone.utc)
        except Exception:
            return None

    phases: list[PhaseRecord] = []
    inject_failed_in_phase = False
    for p in data.get("phases", []):
        pr = PhaseRecord(
            name=p.get("name", ""),
            start_time=_dt(p.get("start_time")) or datetime.now(tz=timezone.utc),
        )
        if p.get("end_time"):
            pr.end_time = _dt(p["end_time"])
        pr.duration_s = float(p.get("duration_s", 0))
        pr.notes = p.get("notes", "")
        if pr.name == "inject" and "inject_ok=False" in pr.notes:
            inject_failed_in_phase = True
        phases.append(pr)

    snapshots: list[MetricsSnapshot] = []
    for m in data.get("metrics_snapshots", []):
        snapshots.append(MetricsSnapshot(
            timestamp=_dt(m.get("timestamp")) or datetime.now(tz=timezone.utc),
            cpu_usage_cores=float(m.get("cpu_usage_cores", 0)),
            memory_rss_mb=float(m.get("memory_rss_mb", 0)),
            event_lag_p95_ms=float(m.get("event_lag_p95_ms", 0)),
            phase=m.get("phase", ""),
        ))

    sr = ScenarioResult(
        run_id=data.get("run_id", ""),
        attack_id=data.get("attack_id", ""),
        attack_family=data.get("attack_family", ""),
        repetition=int(data.get("repetition", 1)),
        namespace=data.get("namespace", ""),
        pod_name=data.get("pod_name", ""),
        ground_truth_label=int(data.get("ground_truth_label", 0)),
        mttd_s=data.get("mttd_s"),
        is_true_positive=bool(data.get("is_true_positive", False)),
        phases=phases,
        phantom_detections=data.get("phantom_detections", []),
        falco_detections=data.get("falco_detections", []),
        metrics_snapshots=snapshots,
        scenario_label=data.get("scenario_label", {}),
        error=data.get("error", ""),
    )
    sr.injection_timestamp = _dt(data.get("injection_timestamp"))
    sr.first_phantom_detection_timestamp = _dt(
        data.get("first_phantom_detection_timestamp")
    )
    if "inject_ok" in data:
        sr.inject_ok = bool(data["inject_ok"])
    elif inject_failed_in_phase or "inject() returned False" in sr.error:
        sr.inject_ok = False
    else:
        sr.inject_ok = True
    return sr


def main(argv: list[str] | None = None) -> int:
    """Entry point for the deterministic pipeline report script.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = argparse.ArgumentParser(
        description="PHANTOM deterministic experimental evaluation report and tables CLI"
    )
    parser.add_argument(
        "--data-dir",
        default=str(_SCRIPT_DIR / "research" / "datasets" / "raw"),
        help="Path to datasets directory (default: research/datasets/raw)",
    )
    parser.add_argument(
        "--out",
        default="-",
        help="Output path for JSON report (default: stdout)",
    )
    parser.add_argument(
        "--tables-dir",
        default=None,
        help="Directory to write LaTeX and CSV comparison tables (default: parent of --out, or output/)",
    )
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"ERROR: data directory not found: {data_dir}", file=sys.stderr)
        return 1

    run_ids = _run_ids_from_index(data_dir)
    if not run_ids:
        print(f"ERROR: No run IDs found in {data_dir}", file=sys.stderr)
        return 1

    dowhy_available = _check_dowhy()

    # Import causal engine domain modules.
    from app.domain.observation_builder import CausalObservationBuilder, RunManifest
    from app.application.run_analysis import RunAnalysisUseCase, PipelineSummary

    builder = CausalObservationBuilder()
    use_case = RunAnalysisUseCase(builder=builder)

    reports: list[dict] = []
    typed_reports = []
    scenario_results: list[ScenarioResult] = []

    for run_id in run_ids:
        run_file = _find_run_file(data_dir, run_id)
        if run_file is None:
            reports.append({
                "run_id": run_id,
                "error": f"Run file not found: {run_id}.json",
                "estimation_attempted": False,
            })
            continue

        try:
            raw_dict = _load_manifest_dict(run_file)
            manifest = RunManifest.from_dict(raw_dict)
            report = use_case.execute(manifest)
            typed_reports.append(report)
            reports.append(_serialize_report(report))

            # Also deserialize into ScenarioResult for detection evaluator
            sr = _dict_to_scenario_result(raw_dict)
            scenario_results.append(sr)
        except Exception as exc:  # noqa: BLE001
            reports.append({
                "run_id": run_id,
                "error": f"Processing failed: {exc}",
                "estimation_attempted": False,
            })

    summary = PipelineSummary.from_reports(typed_reports)

    # -----------------------------------------------------------------------
    # Detection & Baseline Evaluation
    # -----------------------------------------------------------------------
    evaluator = ScenarioEvaluator(
        detection_window_s=300.0,
        phantom_detector_name="phantom",
    )
    baselines = {
        "falco-default-rules": [],
        "trivy-sbom-static": [],
        "isolation-forest-syscall-frequency": [],
    }
    eval_reports = evaluator.evaluate(
        scenario_results=scenario_results,
        detections=baselines,
    )
    phantom_report = next((rep for rep in eval_reports if rep.detector_name == "phantom"), None)

    # Identify exclusions (failed injections per EXPERIMENT_PROTOCOL.md §3.1)
    exclusions: list[dict[str, Any]] = []
    for sr in scenario_results:
        if is_failed_injection(sr):
            exclusions.append({
                "run_id": sr.run_id,
                "scenario_id": f"{sr.attack_id}_rep{sr.repetition}",
                "reason": "failed_injection",
                "error": sr.error or "inject() returned False",
                "notes": (
                    "Phase 2 injection failed (rollout status timeout / inject_ok=False); "
                    "excluded from detection sensitivity (TPR) denominators per EXPERIMENT_PROTOCOL.md §3.1."
                ),
            })

    # Data quality summary counts
    completed_attacks = sum(
        1 for sr in scenario_results
        if sr.ground_truth_label == 1
        and not is_failed_injection(sr)
        and (len(sr.phantom_detections) > 0 or sr.is_true_positive)
    )
    failed_injections = len(exclusions)
    collection_dropouts = sum(
        1 for sr in scenario_results
        if sr.ground_truth_label == 1
        and not is_failed_injection(sr)
        and len(sr.phantom_detections) == 0
        and not sr.is_true_positive
    )
    benign_count = sum(1 for sr in scenario_results if sr.ground_truth_label == 0)

    # Formulate limitations and unsupported claims
    if dowhy_available:
        dowhy_note = (
            f"DoWhy causal estimator is functional in this environment ({sys.version.split()[0]}). "
            "However, no real-data causal estimates were produced because real experiment runs "
            "lack per-window drift labels and have too few observations (preflight gate G1 failed)."
        )
    else:
        dowhy_note = (
            f"DoWhy causal estimator is not functional in this environment ({sys.version.split()[0]}). "
            "No real causal estimates were produced."
        )

    limitations = [
        dowhy_note,
        "Total telemetry collection dropout in raw/ (2026-08-23): All 6 indexed runs in raw/ contain zero detections "
        "due to collector API client port-forward disconnection; lack of detections represents a telemetry collection "
        "dropout, NOT evidence of negative drift or true negative detector silence.",
        "Zero benign controls in raw3 (N_benign = 0): False Positive Rate (FPR), Precision, and F1 score are mathematically "
        "undefined without negative-class controls and cannot be fabricated as zero.",
        "Upstream identity resolution failure: 100% of recorded drift detections in raw3 (3,701/3,701) have pod_name='unknown', "
        "container_name='unknown', null sbom_id, null purl, and dummy sha256:000... image digests. Component-level causal "
        "attribution cannot be empirically established from raw telemetry.",
        "Unmeasured Prometheus overhead: Resource metrics (cpu_usage_cores, memory_rss_mb, event_lag_p95_ms) all defaulted to 0.0 "
        "due to unhandled collection errors on query failure. True monitoring overhead is unmeasured, not zero.",
        "Failed injection exclusions: 3 out of 9 runs in raw3 (all 3 repetitions of solarwinds-001) failed injection rollout "
        "(inject_ok=False) and were excluded from detection sensitivity (TPR) denominators per protocol.",
        "Preflight Gate G1 software sanity guard: Sample size N < 10 failed preflight sanity check; causal estimation cleanly "
        "abstained with 'insufficient_evidence: too_few_observations' without bypassing technical software gates.",
        "Per-window runtime_sbom_drift outcome labels do not exist. CausalObservation rows cannot be built with valid outcome "
        "values from the current dataset.",
        "Baseline telemetry absence: Falco alert logs are empty, Trivy static scans represent point-in-time image vulnerability "
        "scans unlinked to runtime drift windows, and IsolationForest runtime anomaly streams were uncollected. Baseline metrics "
        "are recorded as telemetry_unavailable / NR.",
    ]

    claims_not_supported = [
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

    # Metrics dictionary conforming to interface contract
    phantom_metrics = {
        "detector_name": "phantom",
        "status": phantom_report.status if phantom_report else "unknown",
        "tpr": phantom_report.tpr if phantom_report else None,
        "tpr_ci_wilson": list(phantom_report.tpr_ci_wilson) if (phantom_report and phantom_report.tpr_ci_wilson) else None,
        "fpr": phantom_report.fpr if phantom_report else None,
        "precision": phantom_report.precision if phantom_report else None,
        "recall": phantom_report.recall if phantom_report else None,
        "f1": phantom_report.f1 if phantom_report else None,
        "mttd_mean": phantom_report.mttd_mean_s if phantom_report else None,
        "mttd_median": phantom_report.mttd_median_s if phantom_report else None,
        "mttd_iqr": phantom_report.mttd_iqr_s if phantom_report else None,
        "mttd_p95": phantom_report.mttd_p95_s if phantom_report else None,
        "mttd_ci_bootstrap": list(phantom_report.mttd_ci_bootstrap) if (phantom_report and phantom_report.mttd_ci_bootstrap) else None,
        "tp": phantom_report.tp if phantom_report else None,
        "fp": phantom_report.fp if phantom_report else None,
        "fn": phantom_report.fn if phantom_report else None,
        "tn": phantom_report.tn if phantom_report else None,
        "n_attack_scenarios": phantom_report.n_attack_scenarios if phantom_report else 0,
        "n_benign_scenarios": phantom_report.n_benign_scenarios if phantom_report else 0,
        "excluded_failed_injections": phantom_report.excluded_failed_injections if phantom_report else 0,
    }

    overhead_metrics = {
        "status": phantom_report.overhead_status if phantom_report else "unmeasured",
        "cpu_overhead_pct": phantom_report.cpu_overhead_pct if phantom_report else None,
        "memory_overhead_mb": phantom_report.memory_overhead_mb if phantom_report else None,
        "event_lag_p95_ms": phantom_report.event_lag_p95_ms if phantom_report else None,
    }

    baselines_metrics = {
        rep.detector_name: {
            "status": rep.status,
            "tpr": rep.tpr,
            "tpr_ci_wilson": list(rep.tpr_ci_wilson) if rep.tpr_ci_wilson else None,
            "fpr": rep.fpr,
            "precision": rep.precision,
            "recall": rep.recall,
            "f1": rep.f1,
            "mttd_mean_s": rep.mttd_mean_s,
            "notes": rep.notes,
        }
        for rep in eval_reports if rep.detector_name != "phantom"
    }

    output = {
        "schema_version": "v1.0.0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "python_version": sys.version,
        "dowhy_available": dowhy_available,
        "data_dir": str(data_dir),
        "total_runs_in_index": len(run_ids),
        "runs": reports,
        "summary": {
            "total_runs": summary.total_runs,
            "attack_runs": summary.attack_runs,
            "benign_runs": summary.benign_runs,
            "completed_runs": summary.completed_runs,
            "failed_injection_runs": summary.failed_injection_runs,
            "observation_batches_sufficient_for_estimation": summary.observation_batches_sufficient,
            "preflight_passed_count": summary.preflight_passed_count,
            "estimation_attempted_count": summary.estimation_attempted_count,
            "estimation_completed_count": summary.estimation_completed_count,
            "real_estimates_produced": summary.real_estimates_produced,
            "completed_attacks": completed_attacks,
            "failed_injections": failed_injections,
            "collection_dropouts": collection_dropouts,
            "benign_count": benign_count,
            "mapping_status_totals": summary.mapping_status_totals,
            "abstention_reason_counts": summary.abstention_reason_counts,
            "missing_data_fields": summary.missing_data_fields,
        },
        "data_quality": {
            "total_runs": len(run_ids),
            "completed_attacks": completed_attacks,
            "failed_injections": failed_injections,
            "collection_dropouts": collection_dropouts,
            "benign_count": benign_count,
        },
        "exclusions": exclusions,
        "metrics": phantom_metrics,
        "detection_metrics": phantom_metrics,
        "overhead": overhead_metrics,
        "baselines": baselines_metrics,
        "detector_reports": [rep.to_dict() for rep in eval_reports],
        "limitations": limitations,
        "claims_NOT_supported_by_this_data": claims_not_supported,
    }

    # -----------------------------------------------------------------------
    # Comparison Table Output Generation
    # -----------------------------------------------------------------------
    target_tables_dir: Path | None = None
    if args.tables_dir is not None:
        target_tables_dir = Path(args.tables_dir)
    elif args.out != "-":
        target_tables_dir = Path(args.out).parent

    if target_tables_dir is not None:
        target_tables_dir.mkdir(parents=True, exist_ok=True)
        write_tables(eval_reports, target_tables_dir, prefix="table_1")
        print(f"Comparison tables written to {target_tables_dir}", file=sys.stderr)

    # -----------------------------------------------------------------------
    # JSON Report Output
    # -----------------------------------------------------------------------
    if args.out == "-":
        print(json.dumps(output, indent=2))
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"Report written to {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
