"""
research/evaluation/baselines/run_baselines.py

CLI driver for the PHANTOM baseline comparison evaluation.

Reads ScenarioResult JSON files from research/datasets/raw/,
runs Falco / Trivy / IsolationForest detections for each scenario,
invokes ScenarioEvaluator to compute TPR/FPR/F1/MTTD, and writes:
    - research/evaluation/results/reports.json       (EvaluationReport list)
    - research/evaluation/results/table_1_*.tex      (LaTeX tables)
    - research/evaluation/results/table_1_*.csv      (CSV tables)

Usage:
    python research/evaluation/baselines/run_baselines.py \\
        [--namespace phantom-eval] \\
        [--raw-dir research/datasets/raw] \\
        [--prometheus http://localhost:9090/api/v1/query_range] \\
        [--falco-log /var/log/falco/events.jsonl] \\
        [--output-dir research/evaluation/results] \\
        [--dry-run]

The --dry-run flag:
    - Installs Falco in dry-run mode (logs but skips Helm/kubectl).
    - Skips Trivy scans (records empty results).
    - Uses synthetic IsolationForest training data.
    - Still runs ScenarioEvaluator and writes output files.
    
Environment variables (override defaults):
    NAMESPACE          Kubernetes namespace.
    PHANTOM_API_URL    PHANTOM API Gateway (for PHANTOM report — read-only).
    PROMETHEUS_URL     Prometheus query_range endpoint.
    FALCO_LOG          Falco JSON-lines alert log path.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.baselines.base_baseline import Detection
from research.evaluation.baselines.falco_baseline import FalcoBaseline
from research.evaluation.baselines.isolation_forest_baseline import IsolationForestBaseline
from research.evaluation.baselines.trivy_baseline import TrivyBaseline
from research.evaluation.metrics.comparison_table import write_tables
from research.evaluation.metrics.evaluator import EvaluationReport, ScenarioEvaluator
from research.evaluation.scenarios.scenario_runner import MetricsSnapshot, PhaseRecord, ScenarioResult

log = logging.getLogger(__name__)

_RAW_DIR_DEFAULT = _REPO_ROOT / "research" / "datasets" / "raw"
_OUTPUT_DIR_DEFAULT = _REPO_ROOT / "research" / "evaluation" / "results"


# ---------------------------------------------------------------------------
# ScenarioResult deserialization helpers
# ---------------------------------------------------------------------------


def _load_scenario_results(raw_dir: Path) -> list[ScenarioResult]:
    """Load all ScenarioResult JSON files from raw_dir.

    Args:
        raw_dir: Directory containing ScenarioResult JSON files.

    Returns:
        List of ScenarioResult objects.
    """
    results: list[ScenarioResult] = []

    for json_file in sorted(raw_dir.glob("*.json")):
        if json_file.name in ("index.json", "reports.json"):
            continue
        try:
            with json_file.open() as fh:
                data = json.load(fh)
            sr = _dict_to_scenario_result(data)
            results.append(sr)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "load.scenario_result.failed",
                extra={"file": str(json_file), "error": str(exc)},
            )

    log.info("load.scenario_results.done", extra={"n": len(results)})
    return results


def _dict_to_scenario_result(data: dict[str, Any]) -> ScenarioResult:
    """Reconstruct a ScenarioResult from a serialized dict.

    Args:
        data: Deserialized JSON dict from ScenarioResult.to_dict().

    Returns:
        ScenarioResult instance.
    """
    def _dt(val: str | None) -> datetime | None:
        if not val:
            return None
        return datetime.fromisoformat(val.rstrip("Z")).replace(tzinfo=timezone.utc)

    phases: list[PhaseRecord] = []
    for p in data.get("phases", []):
        pr = PhaseRecord(
            name=p["name"],
            start_time=_dt(p.get("start_time")) or datetime.now(tz=timezone.utc),
        )
        if p.get("end_time"):
            pr.end_time = _dt(p["end_time"])
        pr.duration_s = float(p.get("duration_s", 0))
        pr.notes = p.get("notes", "")
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
    return sr


# ---------------------------------------------------------------------------
# Baseline detection collection
# ---------------------------------------------------------------------------


def _collect_baseline_detections(
    baseline: FalcoBaseline | TrivyBaseline | IsolationForestBaseline,
    scenario_results: list[ScenarioResult],
) -> list[Detection]:
    """Collect detections from one baseline across all scenario time windows.

    For each scenario, determines the relevant time window (injection → end
    of attack phase for attack scenarios; full scenario duration for benign),
    then calls baseline.get_detections() for that window.

    Args:
        baseline: A configured, setup-complete baseline instance.
        scenario_results: List of ScenarioResult from run_all_scenarios.

    Returns:
        Flat list of Detection objects tagged with scenario_id.
    """
    all_detections: list[Detection] = []

    for result in scenario_results:
        if not result.phases:
            continue

        # Determine window start and end.
        # For attack scenarios: baseline phase start → post_recovery phase end.
        # For benign scenarios: same.
        start_phase = next((p for p in result.phases if p.name == "baseline"), None)
        end_phase = next((p for p in reversed(result.phases) if p.end_time), None)

        if not start_phase or not start_phase.start_time:
            continue
        if not end_phase or not end_phase.end_time:
            continue

        since = start_phase.start_time
        until = end_phase.end_time

        # Trivy: scan images just before the attack window.
        if isinstance(baseline, TrivyBaseline):
            attack_phase = next(
                (p for p in result.phases if p.name == "attack"), None
            )
            if attack_phase and attack_phase.start_time:
                scan_time = attack_phase.start_time
                # Trigger image scan for the target pod's image.
                image = result.scenario_label.get(
                    "attack_image", result.scenario_label.get("target_image", "")
                )
                if image:
                    baseline.scan_image(image, scan_time=scan_time)

        try:
            dets = baseline.get_detections(since=since, until=until)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "baseline.get_detections.error",
                extra={
                    "baseline": baseline.name,
                    "scenario": result.run_id,
                    "error": str(exc),
                },
            )
            dets = []

        for det in dets:
            det.scenario_id = result.run_id

        all_detections.extend(dets)

    log.info(
        "baseline.detections.collected",
        extra={"baseline": baseline.name, "n": len(all_detections)},
    )
    return all_detections


# ---------------------------------------------------------------------------
# PHANTOM detections → Detection list (for unified evaluation)
# ---------------------------------------------------------------------------


def _phantom_detections_from_results(
    scenario_results: list[ScenarioResult],
) -> list[Detection]:
    """Extract PHANTOM detections from ScenarioResult fields as Detection objects.

    This allows the ScenarioEvaluator to also process PHANTOM results through
    the same baseline detection-matching logic (as a cross-check).

    Args:
        scenario_results: ScenarioResult list.

    Returns:
        List of Detection objects for PHANTOM drift events.
    """
    detections: list[Detection] = []
    for result in scenario_results:
        for evt in result.phantom_detections:
            ts_raw = evt.get("observed_at") or evt.get("created_at") or ""
            try:
                ts = datetime.fromisoformat(ts_raw.rstrip("Z")).replace(
                    tzinfo=timezone.utc
                )
            except (ValueError, AttributeError):
                continue
            detections.append(Detection(
                detected_at=ts,
                scenario_id=result.run_id,
                detector_name="phantom",
                confidence=float(evt.get("pceps_score", 0.5) or 0.5) / 100.0,
                raw_alert=evt,
                rule_name=evt.get("violation_type", ""),
                namespace=evt.get("namespace", ""),
                pod_name=result.pod_name,
                service_name=result.scenario_label.get("target_service", ""),
            ))
    return detections


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_baselines(
    namespace: str,
    raw_dir: Path,
    prometheus_url: str,
    falco_log: str,
    output_dir: Path,
    dry_run: bool,
) -> list[EvaluationReport]:
    """Run all three baselines and compute comparison metrics.

    Args:
        namespace: Kubernetes namespace.
        raw_dir: Directory containing ScenarioResult JSON files.
        prometheus_url: Prometheus query_range API URL.
        falco_log: Falco JSON-lines alert log path.
        output_dir: Output directory for report files.
        dry_run: If True, skip cluster calls.

    Returns:
        List of EvaluationReport (one per detector including PHANTOM).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Load scenario results                                                #
    # ------------------------------------------------------------------ #
    scenario_results = _load_scenario_results(raw_dir)
    if not scenario_results:
        log.error("run_baselines.no_scenario_results", extra={"raw_dir": str(raw_dir)})
        print(
            f"[ERROR] No ScenarioResult JSON files found in {raw_dir}.\n"
            "Run run_all_scenarios.py first.",
            file=sys.stderr,
        )
        return []

    log.info(
        "run_baselines.start",
        extra={
            "n_scenarios": len(scenario_results),
            "attack": sum(1 for r in scenario_results if r.ground_truth_label == 1),
            "benign": sum(1 for r in scenario_results if r.ground_truth_label == 0),
        },
    )

    # ------------------------------------------------------------------ #
    # Instantiate baselines                                                #
    # ------------------------------------------------------------------ #
    falco = FalcoBaseline(
        namespace=namespace,
        alert_log_path=falco_log,
        dry_run=dry_run,
    )
    trivy = TrivyBaseline(
        scan_output_dir=raw_dir / "trivy",
        dry_run=dry_run,
    )
    isoforest = IsolationForestBaseline(
        prometheus_url=prometheus_url,
        model_path=raw_dir / "isoforest_model.pkl",
        dry_run=dry_run,
    )

    baselines: list[FalcoBaseline | TrivyBaseline | IsolationForestBaseline] = [
        falco,
        trivy,
        isoforest,
    ]

    # ------------------------------------------------------------------ #
    # Setup baselines                                                      #
    # ------------------------------------------------------------------ #
    for bl in baselines:
        log.info("baseline.setup.start", extra={"baseline": bl.name})
        ok = bl.setup(namespace)
        if not ok:
            log.warning("baseline.setup.failed", extra={"baseline": bl.name})
        else:
            log.info("baseline.setup.ok", extra={"baseline": bl.name})

    # Calibrate IsoForest threshold on the benign baseline phases.
    benign_results = [r for r in scenario_results if r.ground_truth_label == 0]
    if benign_results and not dry_run:
        # Use the first benign scenario's baseline phase for calibration.
        first_benign = benign_results[0]
        baseline_phase = next(
            (p for p in first_benign.phases if p.name == "baseline"), None
        )
        if baseline_phase and baseline_phase.start_time and baseline_phase.end_time:
            isoforest.collect_training_windows(
                start=baseline_phase.start_time,
                end=baseline_phase.end_time,
            )

    # ------------------------------------------------------------------ #
    # Collect detections per baseline                                      #
    # ------------------------------------------------------------------ #
    detections_by_baseline: dict[str, list[Detection]] = {}

    for bl in baselines:
        log.info("baseline.collect.start", extra={"baseline": bl.name})
        dets = _collect_baseline_detections(bl, scenario_results)
        detections_by_baseline[bl.name] = dets

    # ------------------------------------------------------------------ #
    # Teardown baselines                                                   #
    # ------------------------------------------------------------------ #
    for bl in baselines:
        ok = bl.teardown()
        if not ok:
            log.warning("baseline.teardown.failed", extra={"baseline": bl.name})

    # ------------------------------------------------------------------ #
    # Run ScenarioEvaluator                                                #
    # ------------------------------------------------------------------ #
    evaluator = ScenarioEvaluator(
        detection_window_s=300.0,
        phantom_detector_name="phantom",
    )
    reports = evaluator.evaluate(
        scenario_results=scenario_results,
        detections=detections_by_baseline,
    )

    # ------------------------------------------------------------------ #
    # Write report JSON                                                    #
    # ------------------------------------------------------------------ #
    reports_path = output_dir / "reports.json"
    with reports_path.open("w") as fh:
        json.dump([r.to_dict() for r in reports], fh, indent=2, default=str)
    log.info("run_baselines.reports_written", extra={"path": str(reports_path)})

    # ------------------------------------------------------------------ #
    # Generate LaTeX and CSV tables                                        #
    # ------------------------------------------------------------------ #
    written = write_tables(reports, output_dir)
    for fmt, path in written.items():
        log.info("run_baselines.table_written", extra={"fmt": fmt, "path": str(path)})

    # ------------------------------------------------------------------ #
    # Print summary to stdout                                              #
    # ------------------------------------------------------------------ #
    _print_summary(reports)

    return reports


def _print_summary(reports: list[EvaluationReport]) -> None:
    """Print a human-readable summary table of evaluation reports.

    Args:
        reports: List of EvaluationReport.
    """
    header = f"{'Detector':<42} {'TPR':>6} {'FPR':>6} {'F1':>6} {'MTTD(s)':>8} {'CPU%':>6} {'FP/hr':>7}"
    sep = "-" * len(header)
    print("\n" + sep)
    print(header)
    print(sep)
    for r in reports:
        mttd = f"{r.mttd_mean_s:.1f}" if r.mttd_mean_s is not None else "  N/A"
        print(
            f"{r.detector_name:<42} "
            f"{r.tpr:>6.3f} "
            f"{r.fpr:>6.3f} "
            f"{r.f1:>6.3f} "
            f"{mttd:>8} "
            f"{r.cpu_overhead_pct:>6.2f} "
            f"{r.false_positives_per_hour:>7.3f}"
        )
    print(sep + "\n")

    # PHANTOM attribution accuracy (if available).
    phantom_report = next((r for r in reports if r.detector_name == "phantom"), None)
    if phantom_report and phantom_report.attribution_accuracy is not None:
        print(f"PHANTOM Causal Attribution Accuracy (CAA): {phantom_report.attribution_accuracy:.3f}")
    if phantom_report and phantom_report.brier_score is not None:
        print(f"PHANTOM PCEPS Brier Score:                 {phantom_report.brier_score:.4f}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(
        description="Run PHANTOM baseline comparisons and compute evaluation metrics."
    )
    parser.add_argument(
        "--namespace",
        default="phantom-eval",
        help="Kubernetes namespace.",
    )
    parser.add_argument(
        "--raw-dir", "--results-dir",
        type=Path,
        default=_RAW_DIR_DEFAULT,
        dest="raw_dir",
        help="Directory containing ScenarioResult JSON files.",
    )
    parser.add_argument(
        "--prometheus",
        default="http://localhost:9090/api/v1/query_range",
        help="Prometheus query_range API URL.",
    )
    parser.add_argument(
        "--falco-log",
        default="/var/log/falco/events.jsonl",
        help="Falco JSON-lines alert log path.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_OUTPUT_DIR_DEFAULT,
        help="Output directory for report files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip cluster calls; use synthetic data.",
    )
    args = parser.parse_args()

    reports = run_baselines(
        namespace=args.namespace,
        raw_dir=args.raw_dir,
        prometheus_url=args.prometheus,
        falco_log=args.falco_log,
        output_dir=args.output_dir,
        dry_run=args.dry_run,
    )
    print(f"Reports written to {args.output_dir}/reports.json ({len(reports)} detectors).")
