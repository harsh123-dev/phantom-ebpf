import json
from pathlib import Path

raw_dir = Path(r"d:\project-1\research\datasets\raw")
raw3_dir = Path(r"d:\project-1\research\datasets\raw3")

with open(raw_dir / "index.json", "r", encoding="utf-8") as f:
    raw_index = json.load(f)

print("### Raw Dataset Runs (`research/datasets/raw/`, N=6)")
print("| Run ID | File Size (B) | Scenario ID | Family | Rep | GT | inject_ok | is_tp | MTTD (s) | Error | Ph. Dets | Falco | Snaps | Classification |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")

for r in raw_index["results"]:
    fn = raw_dir / f"{r}.json"
    d = json.loads(fn.read_text(encoding="utf-8"))
    phases = d.get("phases", [])
    inj = next((p for p in phases if p.get("name") == "inject"), None)
    inj_ok = inj.get("notes") if inj else "N/A"
    gt = d['ground_truth_label']
    cls = "Benign Control (Telemetry Dropout)" if gt == 0 else "Attack Run (Telemetry Dropout / Disconnected Collector)"
    print(f"| `{d['run_id']}` | {fn.stat().st_size} | `{d['attack_id']}` | {d['attack_family']} | {d['repetition']} | {d['ground_truth_label']} | {inj_ok} | {d['is_true_positive']} | {d['mttd_s']} | `{d['error']}` | {len(d['phantom_detections'])} | {len(d['falco_detections'])} | {len(d['metrics_snapshots'])} | {cls} |")

print("\n### Raw3 Dataset Runs (`research/datasets/raw3/`, N=9)")
print("| Run ID | File Size (B) | Scenario ID | Family | Rep | GT | inject_ok | is_tp | MTTD (s) | Error | Ph. Dets | Falco | Snaps | Classification |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")

for fn in sorted(raw3_dir.glob("*.json")):
    d = json.loads(fn.read_text(encoding="utf-8"))
    phases = d.get("phases", [])
    inj = next((p for p in phases if p.get("name") == "inject"), None)
    inj_ok = inj.get("notes") if inj else "N/A"
    err = d.get("error", "")
    gt = d['ground_truth_label']
    dets = len(d.get("phantom_detections", []))
    if err == "inject() returned False" or inj_ok == "inject_ok=False":
        cls = "Failed Injection (`inject_ok=False`, Rollout Failure)"
    elif dets > 0 and d.get("is_true_positive"):
        cls = "Completed Attack Run (Alerts Captured, Ambiguous Identity)"
    else:
        cls = "Incomplete / Unverified Run"
    print(f"| `{d['run_id']}` | {fn.stat().st_size} | `{d['attack_id']}` | {d['attack_family']} | {d['repetition']} | {d['ground_truth_label']} | {inj_ok} | {d['is_true_positive']} | {d['mttd_s']} | `{err}` | {len(d['phantom_detections'])} | {len(d['falco_detections'])} | {len(d['metrics_snapshots'])} | {cls} |")
