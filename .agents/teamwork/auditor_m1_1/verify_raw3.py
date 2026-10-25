import os
import json
import numpy as np
from collections import Counter

raw3_dir = r'd:\project-1\research\datasets\raw3'
all_files = os.listdir(raw3_dir)
json_files = sorted([f for f in all_files if f.endswith('.json')])
print('Total files in raw3:', len(all_files))
print('Total JSON files in raw3:', len(json_files))

solarwinds_runs = []
completed_runs = []
all_dets = []
mttds = []

for f in json_files:
    p = os.path.join(raw3_dir, f)
    sz = os.path.getsize(p)
    with open(p) as fp:
        d = json.load(fp)
    run_id = d.get('run_id')
    attack_id = d.get('attack_id')
    phases = [ph.get('name') for ph in d.get('phases', [])]
    durations = [ph.get('duration_s') for ph in d.get('phases', [])]
    inject_notes = ""
    for ph in d.get('phases', []):
        if ph.get('name') == 'inject':
            inject_notes = ph.get('notes', '')
    pdets = d.get('phantom_detections', [])
    mttd = d.get('mttd_s')
    is_tp = d.get('is_true_positive')
    err = d.get('error')
    
    print(f"{f}: size={sz}, attack={attack_id}, phases={phases}, len(pdets)={len(pdets)}, mttd={mttd}, is_tp={is_tp}, err={err}")
    
    if 'solarwinds' in f:
        solarwinds_runs.append((f, sz, phases, inject_notes, err, len(pdets), is_tp, mttd, sum(durations)))
    else:
        completed_runs.append((f, sz, phases, len(pdets), mttd, is_tp))
        all_dets.extend(pdets)
        if mttd is not None:
            mttds.append(mttd)

print('\n--- Solarwinds runs ---')
for sw in solarwinds_runs:
    print(sw)

print('\n--- Completed attack runs ---')
for cr in completed_runs:
    print(cr)

print(f'\nTotal detections in raw3: {len(all_dets)}')
print(f'MTTD list: {mttds}')
mean_mttd = np.mean(mttds)
median_mttd = np.median(mttds)
q75, q25 = np.percentile(mttds, [75, 25])
iqr_mttd = q75 - q25
print(f'MTTD stats: Mean={mean_mttd:.4f}, Median={median_mttd:.4f}, IQR={iqr_mttd:.4f} (q25={q25:.4f}, q75={q75:.4f})')

# Detailed field analysis of all detections
pod_names = Counter(d.get('pod_name') for d in all_dets)
container_names = Counter(d.get('container_name') for d in all_dets)
container_ids = Counter(d.get('container_id') for d in all_dets)
image_digests = Counter(d.get('image_digest') for d in all_dets)
sbom_ids = Counter(d.get('sbom_id') for d in all_dets)
purls = Counter(d.get('purl') for d in all_dets)
binding_confs = Counter(d.get('binding_confidence') for d in all_dets)
binding_statuses = Counter(d.get('binding_status') for d in all_dets)
identity_statuses = Counter(d.get('identity_status') for d in all_dets)
event_types = Counter(d.get('event_type') for d in all_dets)
comms = Counter(d.get('comm') for d in all_dets)
loss_observed = Counter(d.get('event_loss_observed') for d in all_dets)
nodes = Counter(d.get('node_name') for d in all_dets)

print('\npod_names:', pod_names)
print('container_names:', container_names)
print('container_ids (unknown vs others):', container_ids.get('unknown'), sum(v for k, v in container_ids.items() if k != 'unknown'))
for k, v in container_ids.items():
    if k != 'unknown':
        print(f'  resolved container_id: {k} (count={v})')
print('image_digests:', image_digests)
print('sbom_ids:', sbom_ids)
print('purls:', purls)
print('binding_confs:', binding_confs)
print('binding_statuses:', binding_statuses)
print('identity_statuses:', identity_statuses)
print('event_types:', event_types)
print('comms:', comms)
print('loss_observed:', loss_observed)
print('nodes:', nodes)
