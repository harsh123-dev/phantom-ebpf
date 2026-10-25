import json
import os
from pathlib import Path

raw_dir = Path(r"d:\project-1\research\datasets\raw")
raw3_dir = Path(r"d:\project-1\research\datasets\raw3")

print("=== RAW INDEX.JSON ===")
index_path = raw_dir / "index.json"
if index_path.exists():
    with open(index_path) as f:
        idx = json.load(f)
        print(json.dumps(idx, indent=2))
        raw_indexed_runs = idx.get("results", [])
else:
    raw_indexed_runs = []

print("\n=== RAW FILES SUMMARY ===")
all_raw_files = list(raw_dir.glob("*.json"))
print(f"Total json files in raw/: {len(all_raw_files)}")

def inspect_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        run_id = data.get("run_id")
        attack_id = data.get("attack_id")
        attack_family = data.get("attack_family")
        repetition = data.get("repetition")
        ns = data.get("namespace")
        pod = data.get("pod_name")
        gt_label = data.get("ground_truth_label")
        inject_ts = data.get("injection_timestamp")
        first_det_ts = data.get("first_phantom_detection_timestamp")
        mttd = data.get("mttd_s")
        is_tp = data.get("is_true_positive")
        err = data.get("error", "")
        
        phases = data.get("phases", [])
        phase_names = [p.get("name") for p in phases]
        inject_phase = next((p for p in phases if p.get("name") == "inject"), None)
        inject_notes = inject_phase.get("notes") if inject_phase else ""
        
        phantom_dets = data.get("phantom_detections", [])
        falco_dets = data.get("falco_detections", [])
        snapshots = data.get("metrics_snapshots", [])
        
        # Check event details
        sample_det = phantom_dets[0] if phantom_dets else {}
        container_id = sample_det.get("container_id")
        image_digest = sample_det.get("image_digest")
        sbom_id = sample_det.get("sbom_id")
        purl = sample_det.get("purl")
        identity_status = sample_det.get("identity_status")
        event_loss = sample_det.get("event_loss_observed")
        
        return {
            "run_id": run_id,
            "attack_id": attack_id,
            "attack_family": attack_family,
            "repetition": repetition,
            "pod": pod,
            "gt_label": gt_label,
            "inject_ts": inject_ts,
            "first_det_ts": first_det_ts,
            "mttd": mttd,
            "is_tp": is_tp,
            "err": err,
            "phase_names": phase_names,
            "inject_notes": inject_notes,
            "n_phantom_dets": len(phantom_dets),
            "n_falco_dets": len(falco_dets),
            "n_snapshots": len(snapshots),
            "sample_container_id": container_id,
            "sample_image_digest": image_digest,
            "sample_sbom_id": sbom_id,
            "sample_purl": purl,
            "sample_identity_status": identity_status,
            "sample_event_loss": event_loss,
        }
    except Exception as e:
        return {"error": str(e), "file": str(filepath)}

print("\n--- 6 RUNS IN RAW (from index.json) ---")
for r in raw_indexed_runs:
    fn = raw_dir / f"{r}.json"
    if fn.exists():
        info = inspect_file(fn)
        print(f"Run: {r}")
        print(f"  attack_id: {info.get('attack_id')}, rep: {info.get('repetition')}, gt_label: {info.get('gt_label')}")
        print(f"  inject_ts: {info.get('inject_ts')}, inject_notes: {info.get('inject_notes')}")
        print(f"  is_tp: {info.get('is_tp')}, mttd: {info.get('mttd')}, err: {info.get('err')}")
        print(f"  phantom_dets: {info.get('n_phantom_dets')}, falco_dets: {info.get('n_falco_dets')}, snapshots: {info.get('n_snapshots')}")
        print(f"  phases: {info.get('phase_names')}")
        print(f"  sample_det: sbom_id={info.get('sample_sbom_id')}, purl={info.get('sample_purl')}, id_status={info.get('sample_identity_status')}, c_id={info.get('sample_container_id')}")
    else:
        print(f"Run: {r} NOT FOUND")

print("\n--- ALL 9 RUNS IN RAW3 ---")
raw3_files = sorted(list(raw3_dir.glob("*.json")))
for fn in raw3_files:
    info = inspect_file(fn)
    print(f"Run: {fn.name}")
    print(f"  attack_id: {info.get('attack_id')}, rep: {info.get('repetition')}, gt_label: {info.get('gt_label')}")
    print(f"  inject_ts: {info.get('inject_ts')}, inject_notes: {info.get('inject_notes')}")
    print(f"  is_tp: {info.get('is_tp')}, mttd: {info.get('mttd')}, err: {info.get('err')}")
    print(f"  phantom_dets: {info.get('n_phantom_dets')}, falco_dets: {info.get('n_falco_dets')}, snapshots: {info.get('n_snapshots')}")
    print(f"  phases: {info.get('phase_names')}")
    print(f"  sample_det: sbom_id={info.get('sample_sbom_id')}, purl={info.get('sample_purl')}, id_status={info.get('sample_identity_status')}, c_id={info.get('sample_container_id')}")
