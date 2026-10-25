import os
import json
import math
from collections import Counter

raw_dir = r"d:\project-1\research\datasets\raw"
raw3_dir = r"d:\project-1\research\datasets\raw3"

raw_jsons = [f for f in os.listdir(raw_dir) if f.endswith(".json")]
print(f"Total JSON files in raw: {len(raw_jsons)}")
raw_scenarios = [f for f in raw_jsons if f != "index.json"]
print(f"Scenario JSON files in raw: {len(raw_scenarios)}")

with open(os.path.join(raw_dir, "index.json"), "r") as f:
    idx = json.load(f)
print(f"Indexed results in index.json: {len(idx.get('results', []))}")

total_raw_detections = 0
total_raw_falco = 0
inject_ok_raw = Counter()
for f in raw_scenarios:
    with open(os.path.join(raw_dir, f), "r") as fp:
        data = json.load(fp)
        dets = data.get("phantom_detections", [])
        falco = data.get("falco_detections", [])
        total_raw_detections += len(dets)
        total_raw_falco += len(falco)
        phases = data.get("phases", {})
        inject_phase = phases.get("inject", {}) if isinstance(phases, dict) else {}
        notes = inject_phase.get("notes", {}) if isinstance(inject_phase, dict) else {}
        inject_ok = notes.get("inject_ok")
        inject_ok_raw[str(inject_ok)] += 1

print(f"Total phantom_detections in raw: {total_raw_detections}")
print(f"Total falco_detections in raw: {total_raw_falco}")
print(f"inject_ok distribution in raw: {inject_ok_raw}")

raw3_jsons = sorted([f for f in os.listdir(raw3_dir) if f.endswith(".json")])
print(f"\nTotal JSON files in raw3: {len(raw3_jsons)}")

dets_raw3 = []
mttds = []
for f in raw3_jsons:
    with open(os.path.join(raw3_dir, f), "r") as fp:
        data = json.load(fp)
        sc_id = data.get("scenario_id")
        rep = data.get("repetition")
        is_tp = data.get("is_true_positive")
        mttd = data.get("mttd_s")
        dets = data.get("phantom_detections", [])
        phases = data.get("phases", {})
        inject_ok = None
        if isinstance(phases, dict) and "inject" in phases:
            inject_ok = phases["inject"].get("notes", {}).get("inject_ok")
        print(f"{f}: sc={sc_id}, rep={rep}, is_tp={is_tp}, mttd={mttd}, dets={len(dets)}, inject_ok={inject_ok}")
        dets_raw3.extend(dets)
        if mttd is not None:
            mttds.append(mttd)

print(f"\nTotal detections in raw3: {len(dets_raw3)}")
print(f"MTTDs in raw3: {mttds}")
mean_mttd = sum(mttds) / len(mttds)
sorted_mttds = sorted(mttds)
n = len(sorted_mttds)
# Median for n=6: average of index 2 and index 3
median_mttd = (sorted_mttds[2] + sorted_mttds[3]) / 2.0
# Q1: median of lower half [2.578, 2.607, 4.681] -> 2.607243
# Q3: median of upper half [6.349, 7.875, 70.331] -> 7.875910
# or standard percentile
q1 = sorted_mttds[1] # index 1 is 2.607243
q3 = sorted_mttds[4] # index 4 is 7.875910
iqr = q3 - q1
print(f"Sorted MTTDs: {sorted_mttds}")
print(f"Mean MTTD: {mean_mttd:.4f}, Median: {median_mttd:.4f}, IQR: {iqr:.4f}")

# Check fields in detections
pod_names = Counter(d.get("pod_name") for d in dets_raw3)
container_names = Counter(d.get("container_name") for d in dets_raw3)
container_ids = Counter(d.get("container_id") == "unknown" for d in dets_raw3)
image_digests = Counter(d.get("image_digest") for d in dets_raw3)
sbom_ids = Counter(d.get("sbom_id") is None for d in dets_raw3)
purls = Counter(d.get("purl") is None for d in dets_raw3)
identity_statuses = Counter(d.get("identity_status") for d in dets_raw3)
event_types = Counter(d.get("event_type") for d in dets_raw3)
comms = Counter(d.get("comm") for d in dets_raw3)
loss = Counter(d.get("event_loss_observed") for d in dets_raw3)

print("\nDetections field verification:")
print("pod_names:", pod_names)
print("container_names:", container_names)
print("container_ids (unknown == True):", container_ids)
print("image_digests:", image_digests)
print("sbom_ids (is None == True):", sbom_ids)
print("purls (is None == True):", purls)
print("identity_statuses:", identity_statuses)
print("event_types:", event_types)
print("comms:", comms)
print("event_loss_observed:", loss)

# Wilson score verification:
def wilson_score_interval(k: int, n: int, confidence: float = 0.95):
    z = 1.959963984540054
    p = k / n
    denom = 1 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    spread = (z / denom) * math.sqrt((p * (1 - p)) / n + (z**2) / (4 * n**2))
    return max(0.0, center - spread), min(1.0, center + spread)

print("\nWilson score intervals:")
print("6/6:", wilson_score_interval(6, 6))
print("0/6:", wilson_score_interval(0, 6))
