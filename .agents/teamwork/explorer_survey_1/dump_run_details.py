import json
from pathlib import Path
from datetime import datetime

raw_dir = Path(r"d:\project-1\research\datasets\raw")
raw3_dir = Path(r"d:\project-1\research\datasets\raw3")

with open(raw_dir / "index.json", "r", encoding="utf-8") as f:
    raw_index = json.load(f)

runs_raw = raw_index["results"]

def get_run_details(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        d = json.load(f)
    
    phases = d.get("phases", [])
    inject_phase = next((p for p in phases if p.get("name") == "inject"), None)
    attack_phase = next((p for p in phases if p.get("name") == "attack"), None)
    recover_phase = next((p for p in phases if p.get("name") == "recover"), None)
    
    dets = d.get("phantom_detections", [])
    falco = d.get("falco_detections", [])
    snaps = d.get("metrics_snapshots", [])
    
    return {
        "file_name": filepath.name,
        "file_size": filepath.stat().st_size,
        "run_id": d.get("run_id"),
        "attack_id": d.get("attack_id"),
        "attack_family": d.get("attack_family"),
        "repetition": d.get("repetition"),
        "namespace": d.get("namespace"),
        "pod_name": d.get("pod_name"),
        "ground_truth_label": d.get("ground_truth_label"),
        "injection_timestamp": d.get("injection_timestamp"),
        "first_phantom_detection_timestamp": d.get("first_phantom_detection_timestamp"),
        "mttd_s": d.get("mttd_s"),
        "is_true_positive": d.get("is_true_positive"),
        "error": d.get("error"),
        "phase_names": [p.get("name") for p in phases],
        "inject_notes": inject_phase.get("notes") if inject_phase else None,
        "inject_duration_s": inject_phase.get("duration_s") if inject_phase else None,
        "recover_notes": recover_phase.get("notes") if recover_phase else None,
        "phantom_detections_count": len(dets),
        "falco_detections_count": len(falco),
        "metrics_snapshots_count": len(snaps),
        "target_purl": d.get("scenario_label", {}).get("target_purl"),
        "clean_purl": d.get("scenario_label", {}).get("clean_purl"),
        "target_service": d.get("scenario_label", {}).get("target_service"),
        "control_endpoint": d.get("scenario_label", {}).get("control_endpoint"),
        "expected_changes": d.get("scenario_label", {}).get("expected_changes"),
        "detection_window_s": d.get("scenario_label", {}).get("detection_window_s"),
    }

print("=== RAW INDEXED RUNS (6) ===")
for r in runs_raw:
    p = raw_dir / f"{r}.json"
    det = get_run_details(p)
    print(json.dumps(det, indent=2))

print("\n=== RAW3 ALL RUNS (9) ===")
for p in sorted(raw3_dir.glob("*.json")):
    det = get_run_details(p)
    print(json.dumps(det, indent=2))
