#!/usr/bin/env python3
"""Recompute run-level detection and latency summaries from PHANTOM raw3 records.

This script does not treat individual duplicated drift-event records as
independent detections. It treats each successfully injected scenario run as
one observation and excludes failed injections from the detection denominator.
"""
from __future__ import annotations

import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "research" / "datasets" / "raw3"
OUT_DIR = Path(__file__).resolve().parent


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def percentile_linear(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = percentile / 100 * (len(ordered) - 1)
    lo = math.floor(rank)
    hi = min(lo + 1, len(ordered) - 1)
    fraction = rank - lo
    return ordered[lo] + fraction * (ordered[hi] - ordered[lo])


def main() -> None:
    records: list[dict] = []
    for path in sorted(RAW_DIR.glob("*.json")):
        if path.name == "isoforest_model.pkl":
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        record["_source"] = path.name
        records.append(record)

    # A valid outcome needs a completed injection/attack phase. In the
    # checked-in raw3 set, the three SolarWinds-style records failed injection.
    valid: list[dict] = []
    failed: list[dict] = []
    for record in records:
        phases = record.get("phases") or []
        has_attack = any(p.get("name") == "attack" for p in phases)
        if record.get("error") or not has_attack or not record.get("injection_timestamp"):
            failed.append(record)
        else:
            valid.append(record)

    attack = [r for r in valid if r.get("ground_truth_label") == 1]
    tp = sum(bool(r.get("is_true_positive")) for r in attack)
    fn = len(attack) - tp
    # There are no benign records, so false-positive metrics are undefined.
    fpr = None
    precision = None
    f1 = None

    latencies: list[float] = []
    latency_consistent = True
    per_run: list[dict] = []
    for record in valid:
        raw_events = record.get("phantom_detections") or []
        unique_ids = {event.get("drift_event_id") or event.get("event_id") for event in raw_events}
        unique_ids.discard(None)
        identity_status = Counter(event.get("identity_status", "missing") for event in raw_events)
        component_bound = sum(bool(event.get("purl") and event.get("sbom_id")) for event in { (item.get("drift_event_id") or item.get("event_id")): item for item in raw_events }.values())
        injection = parse_time(record.get("injection_timestamp"))
        first = parse_time(record.get("first_phantom_detection_timestamp"))
        recomputed = (first - injection).total_seconds() if injection and first else None
        stored = record.get("mttd_s")
        same_latency = recomputed is None or (stored is not None and math.isclose(recomputed, float(stored), abs_tol=1e-5))
        latency_consistent &= same_latency
        if recomputed is not None:
            latencies.append(recomputed)
        per_run.append({
            "run_id": record.get("run_id"),
            "source_file": record["_source"],
            "attack_id": record.get("attack_id"),
            "valid_attack_run": True,
            "ground_truth_label": record.get("ground_truth_label"),
            "event_positive_label": bool(record.get("is_true_positive")),
            "failed_injection": False,
            "raw_drift_records": len(raw_events),
            "unique_drift_ids": len(unique_ids),
            "first_event_mttd_s_recomputed": recomputed,
            "stored_mttd_s": stored,
            "latency_match": same_latency,
            "identity_status_counts": dict(Counter({identity: sum(1 for event in { (item.get("drift_event_id") or item.get("event_id")): item for item in raw_events }.values() if event.get("identity_status", "missing") == identity) for identity in {event.get("identity_status", "missing") for event in raw_events}})),
            "events_with_purl_and_sbom_binding": component_bound,
        })
    for record in failed:
        per_run.append({
            "run_id": record.get("run_id"),
            "source_file": record["_source"],
            "attack_id": record.get("attack_id"),
            "valid_attack_run": False,
            "ground_truth_label": record.get("ground_truth_label"),
            "event_positive_label": bool(record.get("is_true_positive")),
            "failed_injection": True,
            "failure": record.get("error") or "missing completed attack phase",
            "raw_drift_records": len(record.get("phantom_detections") or []),
            "unique_drift_ids": 0,
            "first_event_mttd_s_recomputed": None,
            "stored_mttd_s": record.get("mttd_s"),
            "latency_match": None,
            "identity_status_counts": {},
            "events_with_purl_and_sbom_binding": 0,
        })

    families: dict[str, list[dict]] = defaultdict(list)
    for record in valid:
        families[record.get("attack_family", record.get("attack_id", "unknown"))].append(record)

    summary = {
        "source_directory": str(RAW_DIR),
        "all_json_records": len(records),
        "valid_attack_runs": len(attack),
        "failed_or_incomplete_runs_excluded": len(failed),
        "failed_run_reasons": {r.get("run_id", r["_source"]): (r.get("error") or "missing completed attack phase") for r in failed},
        "run_unit_attack_confusion_counts": {"tp": tp, "fn": fn, "fp": None, "tn": None},
        "attack_run_event_positive_fraction": tp / len(attack) if attack else None,
        "precision": precision,
        "f1": f1,
        "fpr": fpr,
        "benign_control_runs": sum(r.get("ground_truth_label") == 0 for r in valid),
        "latency_n": len(latencies),
        "latency_mean_s": statistics.mean(latencies) if latencies else None,
        "latency_median_s": statistics.median(latencies) if latencies else None,
        "latency_p95_linear_s": percentile_linear(latencies, 95),
        "latency_timestamps_match_stored_mttd": latency_consistent,
        "latency_values_s": latencies,
        "attack_families": {
            family: {
                "valid_runs": len(rows),
                "event_positive_runs": sum(bool(r.get("is_true_positive")) for r in rows),
                "failed_runs": 0,
            }
            for family, rows in sorted(families.items())
        },
        "claims_not_verifiable_from_raw3": [
            "false-positive rate (no benign controls)",
            "precision and F1 as full binary-detection metrics (no negative-class controls)",
            "component-level causal attribution (detections have unresolved identity and no PURL/SBOM bindings)",
            "PCEPS predictive performance and calibration (no PCEPS scores or labeled pre-compromise windows)",
            "runtime overhead and event-loss rates (saved metric snapshots are all zero and no measurement provenance is included)",
        ],
    }
    (OUT_DIR / "PHANTOM_Validation_Summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (OUT_DIR / "PHANTOM_Run_Level_Validation.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = sorted({key for row in per_run for key in row})
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in per_run:
            writer.writerow({key: json.dumps(value) if isinstance(value, (dict, list)) else value for key, value in row.items()})
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
