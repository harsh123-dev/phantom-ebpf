import json
from pathlib import Path
from collections import Counter

raw3_dir = Path(r"d:\project-1\research\datasets\raw3")

print("=== RAW3 DETAILED TELEMETRY ANALYSIS ===")

for f in sorted(raw3_dir.glob("*.json")):
    data = json.loads(f.read_text(encoding="utf-8"))
    run_id = data.get("run_id")
    attack_id = data.get("attack_id")
    rep = data.get("repetition")
    gt = data.get("ground_truth_label")
    is_tp = data.get("is_true_positive")
    mttd = data.get("mttd_s")
    err = data.get("error")
    dets = data.get("phantom_detections", [])
    
    event_types = Counter([d.get("event_type") for d in dets])
    id_statuses = Counter([d.get("identity_status") for d in dets])
    pod_names = Counter([d.get("pod_name") for d in dets])
    container_names = Counter([d.get("container_name") for d in dets])
    container_ids = Counter([d.get("container_id") for d in dets])
    image_digests = Counter([d.get("image_digest") for d in dets])
    sboms = Counter([d.get("sbom_id") for d in dets])
    purls = Counter([d.get("purl") for d in dets])
    event_loss = Counter([d.get("event_loss_observed") for d in dets])
    nodes = Counter([d.get("node_name") for d in dets])
    
    print(f"\nRun: {run_id}")
    print(f"  Attack: {attack_id} (rep {rep}), GT: {gt}, is_tp: {is_tp}, MTTD: {mttd}, err: '{err}'")
    print(f"  Total Detections: {len(dets)}")
    if dets:
        print(f"  Event Types: {dict(event_types)}")
        print(f"  Identity Statuses: {dict(id_statuses)}")
        print(f"  Pod Names: {dict(pod_names)}")
        print(f"  Container IDs: {dict(container_ids)}")
        print(f"  Image Digests: {dict(image_digests)}")
        print(f"  SBOM IDs: {dict(sboms)}")
        print(f"  PURLs: {dict(purls)}")
        print(f"  Event Loss Observed: {dict(event_loss)}")
        print(f"  Nodes: {dict(nodes)}")
        # Check first and last detection timestamps
        first_det = dets[0].get("observed_at")
        last_det = dets[-1].get("observed_at")
        print(f"  Time range: {first_det} to {last_det}")
