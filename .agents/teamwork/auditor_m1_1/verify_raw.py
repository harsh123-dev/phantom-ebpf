import os
import json
from collections import Counter

raw_dir = r'd:\project-1\research\datasets\raw'
all_files = os.listdir(raw_dir)
json_files = [f for f in all_files if f.endswith('.json')]
print('Total files in raw:', len(all_files))
print('Total JSON files in raw:', len(json_files))

with open(os.path.join(raw_dir, 'index.json')) as fp:
    idx = json.load(fp)

results = idx.get('results', [])
print('Index results count:', len(results))
indexed_filenames = set()
for r in results:
    indexed_filenames.add(r + '.json')
    print('  indexed:', r)

scenario_files = [f for f in json_files if f != 'index.json']
print('Total scenario JSON files in raw:', len(scenario_files))

legacy_files = [f for f in scenario_files if f not in indexed_filenames]
print('Legacy files count in raw:', len(legacy_files))

legacy_dates = Counter(f[:8] for f in legacy_files)
print('Legacy dates distribution:', sorted(legacy_dates.items()))

# Detections, inject_ok, falco, metrics in all 113 scenario files
non_empty_phantom = 0
non_empty_falco = 0
inject_ok_true = 0
inject_ok_false = 0
nonzero_metrics = 0
legacy_inject_true = 0
legacy_inject_false = 0

for f in scenario_files:
    with open(os.path.join(raw_dir, f)) as fp:
        data = json.load(fp)
    pdets = data.get('phantom_detections', [])
    if len(pdets) > 0:
        non_empty_phantom += 1
    fdets = data.get('falco_detections', [])
    if len(fdets) > 0:
        non_empty_falco += 1
    inj = data.get('inject_ok')
    if inj is True:
        inject_ok_true += 1
        if f in legacy_files:
            legacy_inject_true += 1
    elif inj is False:
        inject_ok_false += 1
        if f in legacy_files:
            legacy_inject_false += 1
    snapshots = data.get('metrics_snapshots', [])
    for snap in snapshots:
        if snap.get('cpu_usage_cores', 0.0) != 0.0 or snap.get('memory_rss_mb', 0.0) != 0.0 or snap.get('event_lag_p95_ms', 0.0) != 0.0:
            nonzero_metrics += 1

print(f'non_empty_phantom: {non_empty_phantom} / {len(scenario_files)}')
print(f'non_empty_falco: {non_empty_falco} / {len(scenario_files)}')
print(f'All scenario files inject_ok_true: {inject_ok_true}, inject_ok_false: {inject_ok_false}')
print(f'Legacy files inject_ok_true: {legacy_inject_true}, inject_ok_false: {legacy_inject_false}')
print(f'nonzero_metrics snapshots count: {nonzero_metrics}')

iso_path = os.path.join(raw_dir, 'isoforest_model.pkl')
if os.path.exists(iso_path):
    print(f'isoforest_model.pkl size: {os.path.getsize(iso_path)} bytes')

trivy_path = os.path.join(raw_dir, 'trivy')
if os.path.exists(trivy_path):
    print(f'trivy dir exists: {os.path.isdir(trivy_path)}, contains: {len(os.listdir(trivy_path))} files')
