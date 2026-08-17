from __future__ import annotations

import json
from pathlib import Path


def main() -> None:
    raw = Path("research/datasets/raw_completed")
    index = json.loads((raw / "index.json").read_text())

    rows: list[dict] = []
    families: dict[str, dict[str, int]] = {}
    snapshots: list[dict] = []

    for run_id in index["results"]:
        data = json.loads((raw / f"{run_id}.json").read_text())
        rows.append(data)

        family = families.setdefault(
            data["attack_family"],
            {"attack": 0, "benign": 0, "tp": 0, "fp": 0},
        )
        if data["ground_truth_label"] == 1:
            family["attack"] += 1
        else:
            family["benign"] += 1
        if data.get("is_true_positive"):
            family["tp"] += 1
        if data["ground_truth_label"] == 0 and data.get("phantom_detections"):
            family["fp"] += 1

        snapshots.extend(data.get("metrics_snapshots", []))

    attack = sum(1 for r in rows if r["ground_truth_label"] == 1)
    benign = sum(1 for r in rows if r["ground_truth_label"] == 0)
    tp = sum(1 for r in rows if r.get("is_true_positive"))
    fp = sum(1 for r in rows if r["ground_truth_label"] == 0 and r.get("phantom_detections"))
    fn = attack - tp
    tn = benign - fp

    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0

    benign_seconds = 0.0
    for row in rows:
        if row["ground_truth_label"] == 0:
            benign_seconds += sum(p.get("duration_s") or 0.0 for p in row.get("phases", []))
    fp_per_hour = fp / (benign_seconds / 3600.0) if benign_seconds else 0.0

    reports = json.loads(Path("research/evaluation/results/reports.json").read_text())

    lines = [
        "# PHANTOM Local Dry-Run Numbers Summary",
        "",
        "Generated: 2026-08-08",
        "",
        "## Execution Notes",
        "- Docker was installed, but Docker Desktop Linux engine was not running, so PostgreSQL/Redis and migrations were skipped.",
        "- eBPF agent was skipped because this run is local Windows dry-run.",
        "- Local stub endpoints returned empty PHANTOM drift events and empty Prometheus vectors so the implemented dry-run runner could complete without network timeouts.",
        "- Completed scenario set: research/datasets/raw_completed/index.json (18 runs).",
        "",
        "## Scenario Coverage",
        f"- Total scenario runs: {len(rows)}",
        f"- Attack runs: {attack}",
        f"- Benign runs: {benign}",
        f"- Repetitions per scenario: {index.get('repetitions')}",
        f"- Namespace: {index.get('namespace')}",
        "",
        "## TABLE 1: Detection Performance (Actual Local Dry-Run)",
        "| Detector | TP | FN | FP | TN | TPR | FPR | Precision | F1 | MTTD | FP/hr |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| PHANTOM | {tp} | {fn} | {fp} | {tn} | {tpr:.3f} | {fpr:.3f} | {precision:.3f} | {f1:.3f} | N/A | {fp_per_hour:.3f} |",
        "",
        "## Baseline Detector Table",
        "| Detector | TPR | FPR | F1 | MTTD(s) | CPU% | FP/hr |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]

    for report in reports:
        mttd = "N/A" if report["mttd_mean_s"] is None else str(report["mttd_mean_s"])
        lines.append(
            f"| {report['detector_name']} | {report['tpr']:.3f} | {report['fpr']:.3f} | "
            f"{report['f1']:.3f} | {mttd} | {report['cpu_overhead_pct']:.2f} | "
            f"{report['false_positives_per_hour']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Aggregate By Scenario Family",
            "| Family | Attack Runs | Benign Runs | TP | FP | Mean MTTD |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for family_name in sorted(families):
        family = families[family_name]
        lines.append(
            f"| {family_name} | {family['attack']} | {family['benign']} | "
            f"{family['tp']} | {family['fp']} | N/A |"
        )

    cpus = [s.get("cpu_usage_cores", 0.0) for s in snapshots]
    mems = [s.get("memory_rss_mb", 0.0) for s in snapshots]
    lags = [s.get("event_lag_p95_ms", 0.0) for s in snapshots]

    lines.extend(
        [
            "",
            "## TABLE 2: Causal Attribution",
            "- Total attributions: 0",
            "- Identifiability rate: N/A",
            "- Attribution accuracy: N/A",
            "- Mean attribution confidence: N/A",
            "- Reason: no PHANTOM drift events were emitted in local dry-run, so there were no attribution records to evaluate.",
            "",
            "## TABLE 3: PCEPS Model Performance",
            "- AUC-ROC: N/A",
            "- Brier score: N/A",
            "- Training samples from real drift evidence: 0",
            "- Reason: local dry-run generated labels but no real feature evidence; training on seeded synthetic features would fabricate model quality.",
            "",
            "## TABLE 4: Overhead Metrics (Prometheus Dry-Run)",
            f"- Metrics snapshots: {len(snapshots)}",
            f"- Mean CPU usage cores: {(sum(cpus) / len(cpus) if cpus else 0.0):.4f}",
            f"- Mean memory RSS MB: {(sum(mems) / len(mems) if mems else 0.0):.2f}",
            f"- Mean event lag P95 ms: {(sum(lags) / len(lags) if lags else 0.0):.2f}",
            "- Event loss rate: N/A (not emitted by local dry-run)",
            "",
            "## Files",
            "- Scenario log: research/datasets/scenario_run_log.txt",
            "- Baseline log: research/datasets/baseline_run_log.txt",
            "- Completed raw results: research/datasets/raw_completed/",
            "- Baseline reports: research/evaluation/results/reports.json",
            "- Detection table CSV: research/evaluation/results/table_1_detection_performance.csv",
        ]
    )

    out = Path("research/datasets/phantom_numbers_summary.md")
    out.write_text("\n".join(lines) + "\n")
    print(out)


if __name__ == "__main__":
    main()
