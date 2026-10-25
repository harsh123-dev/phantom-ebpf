"""Independent Empirical Verification Script for EXPERIMENTAL_EVALUATION_AUDIT.md

This script verifies every factual claim made in EXPERIMENTAL_EVALUATION_AUDIT.md
against the raw datasets in research/datasets/raw/ and research/datasets/raw3/.
"""
from __future__ import annotations

import json
import math
import os
from collections import Counter
from pathlib import Path
import statistics


def get_inject_ok(phases: list[dict]) -> bool | None:
    for p in phases:
        if isinstance(p, dict) and p.get("name") == "inject":
            notes = p.get("notes", "")
            if "inject_ok=True" in notes:
                return True
            elif "inject_ok=False" in notes:
                return False
    return None


def check_raw_dataset(raw_dir: Path) -> dict:
    results = {}
    json_files = sorted([f for f in raw_dir.iterdir() if f.is_file() and f.suffix == ".json"])
    results["total_json_files"] = len(json_files)

    index_path = raw_dir / "index.json"
    results["has_index_json"] = index_path.exists()
    
    with open(index_path, "r", encoding="utf-8") as fp:
        index_data = json.load(fp)
    
    indexed_run_ids = index_data.get("results", [])
    results["indexed_run_count"] = len(indexed_run_ids)
    results["indexed_run_ids"] = indexed_run_ids

    scenario_files = [f for f in json_files if f.name != "index.json"]
    results["scenario_json_count"] = len(scenario_files)

    legacy_files = [f for f in scenario_files if f.stem not in indexed_run_ids]
    indexed_files = [f for f in scenario_files if f.stem in indexed_run_ids]

    results["legacy_json_count"] = len(legacy_files)
    results["indexed_files_count"] = len(indexed_files)

    # Date distribution of legacy files
    legacy_dates = Counter()
    legacy_scenarios = Counter()
    legacy_inject_ok = Counter()
    legacy_sizes = []

    indexed_scenarios = Counter()
    indexed_inject_ok = Counter()
    indexed_sizes = []

    all_phantom_dets = []
    all_falco_dets = []
    all_metrics_snapshots = []

    for f in scenario_files:
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        # Check phantom_detections
        pdets = data.get("phantom_detections", [])
        all_phantom_dets.append((f.name, len(pdets)))

        # Check falco_detections
        fdets = data.get("falco_detections", [])
        all_falco_dets.append((f.name, len(fdets)))

        # Check metrics snapshots
        msnaps = data.get("metrics_snapshots", [])
        for snap in msnaps:
            all_metrics_snapshots.append(
                (f.name, snap.get("cpu_usage_cores"), snap.get("memory_rss_mb"), snap.get("event_lag_p95_ms"))
            )

        inject_ok = get_inject_ok(data.get("phases", []))
        scen_id = data.get("attack_id") or data.get("scenario_id") or ("_".join(f.stem.split("_")[1:-1]) if len(f.stem.split("_")) > 2 else f.stem)

        if f.stem not in indexed_run_ids:
            # Parse date prefix
            date_prefix = f.stem.split("T")[0] if "T" in f.stem else f.stem[:8]
            legacy_dates[date_prefix] += 1
            legacy_scenarios[scen_id] += 1
            legacy_inject_ok[inject_ok] += 1
            legacy_sizes.append(f.stat().st_size)
        else:
            indexed_scenarios[scen_id] += 1
            indexed_inject_ok[inject_ok] += 1
            indexed_sizes.append(f.stat().st_size)

    results["all_phantom_dets_zero"] = all(count == 0 for _, count in all_phantom_dets)
    results["all_falco_dets_zero"] = all(count == 0 for _, count in all_falco_dets)

    # Check metrics
    results["all_metrics_zero"] = all(
        cpu == 0.0 and rss == 0.0 and lag == 0.0
        for _, cpu, rss, lag in all_metrics_snapshots
    )
    results["metrics_snapshot_count"] = len(all_metrics_snapshots)

    results["legacy_dates"] = dict(legacy_dates)
    results["legacy_scenarios"] = dict(legacy_scenarios)
    results["legacy_inject_ok"] = dict(legacy_inject_ok)
    if legacy_sizes:
        results["legacy_sizes_min"] = min(legacy_sizes)
        results["legacy_sizes_max"] = max(legacy_sizes)
        results["legacy_sizes_mean"] = sum(legacy_sizes) / len(legacy_sizes)

    results["indexed_scenarios"] = dict(indexed_scenarios)
    results["indexed_inject_ok"] = dict(indexed_inject_ok)
    results["indexed_sizes"] = indexed_sizes

    # Check other files in raw
    isoforest_path = raw_dir / "isoforest_model.pkl"
    results["has_isoforest_model"] = isoforest_path.exists()
    if isoforest_path.exists():
        results["isoforest_size"] = isoforest_path.stat().st_size

    trivy_dir = raw_dir / "trivy"
    results["has_trivy_dir"] = trivy_dir.is_dir()
    if trivy_dir.is_dir():
        results["trivy_file_count"] = len(list(trivy_dir.iterdir()))

    return results


def check_raw3_dataset(raw3_dir: Path) -> dict:
    results = {}
    json_files = sorted([f for f in raw3_dir.iterdir() if f.is_file() and f.suffix == ".json"])
    results["total_json_files"] = len(json_files)

    solarwinds_runs = []
    completed_runs = []

    all_detections = []
    mttd_values = []
    run_file_sizes = {}
    metrics_snapshots_raw3 = []

    for f in json_files:
        run_file_sizes[f.name] = f.stat().st_size
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        scen_id = data.get("attack_id") or data.get("scenario_id")
        inject_ok = get_inject_ok(data.get("phases", []))
        phase_names = [p.get("name") if isinstance(p, dict) else p for p in data.get("phases", [])]
        is_tp = data.get("is_true_positive")
        mttd = data.get("mttd_s")
        pdets = data.get("phantom_detections", [])
        fdets = data.get("falco_detections", [])
        error = data.get("error")

        for snap in data.get("metrics_snapshots", []):
            metrics_snapshots_raw3.append(
                (f.name, snap.get("cpu_usage_cores"), snap.get("memory_rss_mb"), snap.get("event_lag_p95_ms"))
            )

        if scen_id and "solarwinds" in scen_id:
            solarwinds_runs.append({
                "file": f.name,
                "scenario_id": scen_id,
                "inject_ok": inject_ok,
                "phases": phase_names,
                "is_tp": is_tp,
                "mttd_s": mttd,
                "pdets_len": len(pdets),
                "fdets_len": len(fdets),
                "error": error,
                "size": f.stat().st_size,
                "metrics_snapshot_count": len(data.get("metrics_snapshots", [])),
            })
        else:
            completed_runs.append({
                "file": f.name,
                "scenario_id": scen_id,
                "inject_ok": inject_ok,
                "phases": phase_names,
                "is_tp": is_tp,
                "mttd_s": mttd,
                "pdets_len": len(pdets),
                "fdets_len": len(fdets),
                "error": error,
                "size": f.stat().st_size,
                "metrics_snapshot_count": len(data.get("metrics_snapshots", [])),
            })
            mttd_values.append(mttd)
            all_detections.extend(pdets)

    results["solarwinds_runs"] = solarwinds_runs
    results["completed_runs"] = completed_runs
    results["total_detections"] = len(all_detections)
    results["mttd_values"] = mttd_values
    results["metrics_snapshots_raw3_count"] = len(metrics_snapshots_raw3)
    results["all_metrics_raw3_zero"] = all(
        cpu == 0.0 and rss == 0.0 and lag == 0.0
        for _, cpu, rss, lag in metrics_snapshots_raw3
    )

    # MTTD calculations
    if mttd_values:
        mean_mttd = statistics.mean(mttd_values)
        median_mttd = statistics.median(mttd_values)
        sorted_mttd = sorted(mttd_values)
        q_inc = statistics.quantiles(sorted_mttd, n=4, method="inclusive")
        q_exc = statistics.quantiles(sorted_mttd, n=4, method="exclusive")
        results["mttd_mean"] = mean_mttd
        results["mttd_median"] = median_mttd
        results["mttd_sorted"] = sorted_mttd
        results["quantiles_inclusive"] = q_inc
        results["quantiles_exclusive"] = q_exc
        results["iqr_inclusive"] = q_inc[2] - q_inc[0]
        results["iqr_exclusive"] = q_exc[2] - q_exc[0]

    # Detailed detection fields
    results["det_count"] = len(all_detections)
    results["pod_names"] = Counter(d.get("pod_name") for d in all_detections)
    results["container_names"] = Counter(d.get("container_name") for d in all_detections)
    results["container_ids"] = Counter(
        "known" if d.get("container_id") and d.get("container_id") != "unknown" else "unknown"
        for d in all_detections
    )
    results["container_id_known_values"] = Counter(
        d.get("container_id") for d in all_detections if d.get("container_id") != "unknown"
    )
    results["image_digests"] = Counter(d.get("image_digest") for d in all_detections)
    results["sbom_ids"] = Counter(str(d.get("sbom_id")) for d in all_detections)
    results["purls"] = Counter(str(d.get("purl")) for d in all_detections)
    results["binding_confidences"] = Counter(str(d.get("binding_confidence")) for d in all_detections)
    results["binding_statuses"] = Counter(str(d.get("binding_status")) for d in all_detections)
    results["identity_statuses"] = Counter(d.get("identity_status") for d in all_detections)
    results["event_types"] = Counter(d.get("event_type") for d in all_detections)
    results["comms"] = Counter(d.get("comm") for d in all_detections)
    results["event_loss"] = Counter(d.get("event_loss_observed") for d in all_detections)
    results["architectures"] = Counter(d.get("architecture") for d in all_detections)
    results["nodes"] = Counter(d.get("node_name") for d in all_detections)

    # Check benign controls in raw3
    ground_truth_labels = []
    for f in json_files:
        with open(f, "r", encoding="utf-8") as fp:
            d = json.load(fp)
            ground_truth_labels.append(d.get("ground_truth_label"))
    results["ground_truth_labels"] = Counter(ground_truth_labels)

    return results


def check_wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    p = k / n
    denom = 1 + (z ** 2) / n
    center = (p + (z ** 2) / (2 * n)) / denom
    margin = (z / denom) * math.sqrt((p * (1 - p) / n) + ((z ** 2) / (4 * (n ** 2))))
    return (center - margin, center + margin)


def main():
    print("=== EMPIRICAL VERIFICATION OF EXPERIMENTAL_EVALUATION_AUDIT.md ===")
    raw_dir = Path("research/datasets/raw")
    raw3_dir = Path("research/datasets/raw3")

    print("\n--- 1. Auditing research/datasets/raw/ ---")
    raw_res = check_raw_dataset(raw_dir)
    print(f"Total JSON files: {raw_res['total_json_files']}")
    print(f"Has index.json: {raw_res['has_index_json']}")
    print(f"Indexed runs in index.json: {raw_res['indexed_run_count']}")
    print(f"Indexed run IDs: {raw_res['indexed_run_ids']}")
    print(f"Scenario JSON files count: {raw_res['scenario_json_count']}")
    print(f"Legacy JSON count: {raw_res['legacy_json_count']}")
    print(f"All phantom_detections == []: {raw_res['all_phantom_dets_zero']}")
    print(f"All falco_detections == []: {raw_res['all_falco_dets_zero']}")
    print(f"All metrics snapshots (CPU, RSS, lag) == 0.0: {raw_res['all_metrics_zero']} (total {raw_res['metrics_snapshot_count']} snapshots)")
    print(f"Legacy file dates: {raw_res['legacy_dates']}")
    print(f"Legacy scenario distribution: {raw_res['legacy_scenarios']}")
    print(f"Legacy inject_ok: {raw_res['legacy_inject_ok']}")
    print(f"Legacy file sizes: min={raw_res.get('legacy_sizes_min')}, max={raw_res.get('legacy_sizes_max')}, mean={raw_res.get('legacy_sizes_mean'):.2f}")
    print(f"Indexed inject_ok: {raw_res['indexed_inject_ok']}")
    print(f"Indexed sizes: {raw_res['indexed_sizes']}")
    print(f"Isoforest model exists: {raw_res['has_isoforest_model']}, size={raw_res.get('isoforest_size')}")
    print(f"Trivy directory exists: {raw_res['has_trivy_dir']}, files={raw_res.get('trivy_file_count')}")

    print("\n--- 2. Auditing research/datasets/raw3/ ---")
    raw3_res = check_raw3_dataset(raw3_dir)
    print(f"Total JSON files: {raw3_res['total_json_files']}")
    print(f"SolarWinds failed injection runs ({len(raw3_res['solarwinds_runs'])}):")
    for sw in raw3_res['solarwinds_runs']:
        print(f"  {sw['file']}: scen={sw['scenario_id']}, inject_ok={sw['inject_ok']}, phases={sw['phases']}, dets={sw['pdets_len']}, size={sw['size']}, err={sw['error']}")

    print(f"\nCompleted attack runs ({len(raw3_res['completed_runs'])}):")
    for cr in raw3_res['completed_runs']:
        print(f"  {cr['file']}: scen={cr['scenario_id']}, inject_ok={cr['inject_ok']}, phases={cr['phases']}, dets={cr['pdets_len']}, mttd={cr['mttd_s']}, size={cr['size']}")

    print(f"\nTotal detections across completed runs: {raw3_res['total_detections']}")
    print(f"MTTD values: {raw3_res['mttd_values']}")
    print(f"MTTD sorted: {raw3_res['mttd_sorted']}")
    print(f"MTTD mean: {raw3_res['mttd_mean']:.6f} (claimed: 15.74s)")
    print(f"MTTD median: {raw3_res['mttd_median']:.6f} (claimed: 5.52s)")
    print(f"MTTD quantiles inclusive: {raw3_res['quantiles_inclusive']}, IQR inclusive: {raw3_res['iqr_inclusive']:.6f}")
    print(f"MTTD quantiles exclusive: {raw3_res['quantiles_exclusive']}, IQR exclusive: {raw3_res['iqr_exclusive']:.6f}")

    # Check numpy IQR if available
    try:
        import numpy as np
        q75, q25 = np.percentile(raw3_res['mttd_values'], [75, 25])
        print(f"NumPy percentile 75/25: q75={q75:.6f}, q25={q25:.6f}, IQR={q75-q25:.6f} (claimed: 4.88s)")
    except ImportError:
        pass

    # Check scipy or statsmodels or custom
    # Let's see what formula gives 4.88s:
    # Sorted: [2.578247, 2.607243, 4.681537, 6.349775, 7.87591, 70.331969]
    # Q1 and Q3:
    s = raw3_res['mttd_sorted']
    # If method is n=6, Q1 and Q3 can be:
    # 7.87591 - 2.607243 = 5.268667
    # Or linear interpolation:
    print(f"Metrics snapshots in raw3: count={raw3_res['metrics_snapshots_raw3_count']}, all zero: {raw3_res['all_metrics_raw3_zero']}")
    print(f"Ground truth labels in raw3: {raw3_res['ground_truth_labels']} (0 benign controls)")

    print("\n--- 3. Field-Level Analysis of 3,701 Detections in raw3/ ---")
    print(f"Detection count: {raw3_res['det_count']}")
    print(f"pod_names: {raw3_res['pod_names']}")
    print(f"container_names: {raw3_res['container_names']}")
    print(f"container_ids: {raw3_res['container_ids']}")
    print(f"known container_id values: {raw3_res['container_id_known_values']}")
    print(f"image_digests: {raw3_res['image_digests']}")
    print(f"sbom_ids: {raw3_res['sbom_ids']}")
    print(f"purls: {raw3_res['purls']}")
    print(f"binding_confidences: {raw3_res['binding_confidences']}")
    print(f"binding_statuses: {raw3_res['binding_statuses']}")
    print(f"identity_statuses: {raw3_res['identity_statuses']}")
    print(f"event_types: {raw3_res['event_types']}")
    print(f"comms: {raw3_res['comms']}")
    print(f"event_loss_observed: {raw3_res['event_loss']}")
    print(f"architectures: {raw3_res['architectures']}")
    print(f"node_names: {raw3_res['nodes']}")

    print("\n--- 4. Wilson Score Check ---")
    wilson_lower, wilson_upper = check_wilson_interval(6, 6)
    print(f"Ordinary Wilson Score for 6/6 at z=1.96: [{wilson_lower:.4f}, {wilson_upper:.4f}] (claimed: [0.6096, 1.0000])")


if __name__ == "__main__":
    main()
