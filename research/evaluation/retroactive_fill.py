#!/usr/bin/env python3
"""
research/evaluation/retroactive_fill.py

Retroactively fill phantom_detections, is_true_positive, and mttd_s in
existing scenario JSON files by querying the PHANTOM API for drift events
that occurred during each scenario's attack-observation window.

This is needed when the port-forward was not running during the original
evaluation run, causing phantom_detections=[] for all scenarios even though
PHANTOM was detecting and storing events in the database.

Usage:
    python3 research/evaluation/retroactive_fill.py \
        --raw-dir research/datasets/raw/ \
        --phantom-api http://localhost:8080 \
        [--token <bearer_token>] \
        [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def query_drift_events(
    api_base: str,
    since: datetime,
    until: datetime,
    token: str = "",
    timeout: float = 15.0,
) -> list[dict]:
    """Query PHANTOM API for drift events in [since, until]."""
    try:
        import httpx
    except ImportError:
        log.error("httpx not installed. Run: pip3 install httpx")
        return []

    since_iso = since.isoformat().replace("+00:00", "Z")
    url = f"{api_base.rstrip('/')}/api/v1/drift-events"
    params = {"since": since_iso, "limit": 500}
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            events = data.get("items", data) if isinstance(data, dict) else data
            if not isinstance(events, list):
                log.warning("Unexpected API response shape: %s", type(events))
                return []

            # Filter to [since, until].
            filtered = []
            for ev in events:
                ts_raw = ev.get("observed_at") or ev.get("created_at", "")
                if not ts_raw:
                    filtered.append(ev)
                    continue
                ts = _parse_dt(ts_raw)
                if ts and since <= ts <= until:
                    filtered.append(ev)
            return filtered

    except Exception as exc:
        log.warning("API query failed: %s", exc)
        return []


def fill_scenario(
    scenario: dict,
    api_base: str,
    token: str,
    dry_run: bool,
) -> dict:
    """Fill phantom_detections and derived fields for one scenario."""
    run_id = scenario.get("run_id", "?")

    # Skip if already has detections.
    existing = scenario.get("phantom_detections", [])
    if existing:
        log.info("[%s] already has %d detections — skipping", run_id, len(existing))
        return scenario

    injection_ts_raw = scenario.get("injection_timestamp")
    if not injection_ts_raw:
        log.info("[%s] no injection_timestamp (benign or failed) — skipping", run_id)
        return scenario

    injection_ts = _parse_dt(injection_ts_raw)
    if not injection_ts:
        log.warning("[%s] cannot parse injection_timestamp: %s", run_id, injection_ts_raw)
        return scenario

    # Determine attack window end from phases.
    attack_end: datetime | None = None
    for phase in scenario.get("phases", []):
        if phase.get("name") == "attack" and phase.get("end_time"):
            attack_end = _parse_dt(phase["end_time"])
            break

    # Fallback: injection + 300s.
    if attack_end is None:
        attack_end = injection_ts + timedelta(seconds=300)

    detection_window_s = 180.0
    label = scenario.get("scenario_label")
    if isinstance(label, dict):
        detection_window_s = float(label.get("detection_window_s") or 180.0)
    detection_deadline_ts = injection_ts + timedelta(seconds=detection_window_s)

    log.info(
        "[%s] querying API  since=%s  until=%s",
        run_id,
        injection_ts.isoformat(),
        attack_end.isoformat(),
    )

    if dry_run:
        log.info("[%s] dry-run — skipping actual query", run_id)
        return scenario

    detections = query_drift_events(api_base, injection_ts, attack_end, token)
    log.info("[%s] found %d drift events", run_id, len(detections))

    scenario["phantom_detections"] = detections

    # Recompute is_true_positive and mttd_s.
    if detections and scenario.get("ground_truth_label") == 1:
        for det in detections:
            det_ts_raw = det.get("observed_at") or det.get("created_at", "")
            if not det_ts_raw:
                continue
            det_ts = _parse_dt(det_ts_raw)
            if det_ts and det_ts <= detection_deadline_ts:
                mttd = (det_ts - injection_ts).total_seconds()
                scenario["is_true_positive"] = True
                scenario["mttd_s"] = mttd
                scenario["first_phantom_detection_timestamp"] = det_ts.isoformat()
                log.info("[%s] TRUE POSITIVE — mttd=%.1fs", run_id, mttd)
                break
        else:
            log.info("[%s] detections found but none within window — FALSE NEGATIVE", run_id)

    return scenario


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retroactively fill phantom_detections in scenario JSONs."
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=_REPO_ROOT / "research" / "datasets" / "raw",
    )
    parser.add_argument(
        "--phantom-api",
        default="http://localhost:8080",
    )
    parser.add_argument("--token", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    scenario_files = sorted(args.raw_dir.glob("*.json"))
    scenario_files = [f for f in scenario_files if f.name != "index.json"]

    if not scenario_files:
        log.error("No scenario JSON files found in %s", args.raw_dir)
        sys.exit(1)

    log.info("Found %d scenario files", len(scenario_files))

    updated = 0
    skipped = 0
    failed = 0

    for path in scenario_files:
        try:
            scenario = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Cannot read %s: %s", path.name, exc)
            failed += 1
            continue

        original_tp = scenario.get("is_true_positive", False)
        filled = fill_scenario(scenario, args.phantom_api, args.token, args.dry_run)

        new_det_count = len(filled.get("phantom_detections", []))

        if new_det_count > 0 and not original_tp:
            updated += 1
        else:
            skipped += 1

        if not args.dry_run:
            path.write_text(json.dumps(filled, indent=2, default=str), encoding="utf-8")

    log.info("Done. Updated=%d  Skipped=%d  Failed=%d", updated, skipped, failed)

    # Quick summary of filled results.
    all_scenarios = []
    for path in sorted(args.raw_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            all_scenarios.append(json.loads(path.read_text()))
        except Exception:
            pass

    attack = [r for r in all_scenarios if r.get("ground_truth_label") == 1 and not r.get("error")]
    benign = [r for r in all_scenarios if r.get("ground_truth_label") == 0 and not r.get("error")]
    tps = [r for r in attack if r.get("is_true_positive")]
    fps = [r for r in benign if r.get("phantom_detections")]
    mttds = [r["mttd_s"] for r in attack if r.get("mttd_s")]

    print("\n=== POST-FILL SUMMARY ===")
    print(f"Attack scenarios : {len(attack)}")
    print(f"Benign scenarios : {len(benign)}")
    if attack:
        print(f"True Positives   : {len(tps)} / {len(attack)} (TPR={len(tps)/len(attack):.3f})")
    if benign:
        print(f"False Positives  : {len(fps)} / {len(benign)} (FPR={len(fps)/len(benign):.3f})")
    if mttds:
        print(f"Mean MTTD        : {sum(mttds)/len(mttds):.1f}s")
        print(f"P50  MTTD        : {sorted(mttds)[len(mttds)//2]:.1f}s")
    else:
        print("Mean MTTD        : N/A (no detections within window)")


if __name__ == "__main__":
    main()
