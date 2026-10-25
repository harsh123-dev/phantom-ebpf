import os
import json
from collections import Counter

raw_dir = r'd:\project-1\research\datasets\raw'
all_files = os.listdir(raw_dir)
json_files = [f for f in all_files if f.endswith('.json')]

with open(os.path.join(raw_dir, 'index.json')) as fp:
    idx = json.load(fp)

results = idx.get('results', [])
indexed_filenames = set(r + '.json' for r in results)
scenario_files = [f for f in json_files if f != 'index.json']
legacy_files = [f for f in scenario_files if f not in indexed_filenames]

inject_true_legacy = 0
inject_false_legacy = 0
inject_other_legacy = 0

inject_true_indexed = 0
inject_false_indexed = 0

for f in scenario_files:
    with open(os.path.join(raw_dir, f)) as fp:
        d = json.load(fp)
    # find inject phase notes
    inj_notes = ""
    for p in d.get('phases', []):
        if p.get('name') == 'inject':
            inj_notes = p.get('notes', '')
    
    is_true = 'inject_ok=True' in inj_notes
    is_false = 'inject_ok=False' in inj_notes
    
    if f in legacy_files:
        if is_true:
            inject_true_legacy += 1
        elif is_false:
            inject_false_legacy += 1
        else:
            inject_other_legacy += 1
            print('Other legacy:', f, inj_notes, d.get('error'))
    else:
        if is_true:
            inject_true_indexed += 1
        elif is_false:
            inject_false_indexed += 1
        else:
            print('Other indexed:', f, inj_notes)

print('Legacy inject_true:', inject_true_legacy)
print('Legacy inject_false:', inject_false_legacy)
print('Legacy inject_other:', inject_other_legacy)
print('Indexed inject_true:', inject_true_indexed)
print('Indexed inject_false:', inject_false_indexed)

# Check scenario distribution in legacy
legacy_scenarios = Counter()
for f in legacy_files:
    with open(os.path.join(raw_dir, f)) as fp:
        d = json.load(fp)
    sc_id = d.get('attack_id') or d.get('scenario_label') or f.split('_')[1]
    legacy_scenarios[sc_id] += 1
print('Legacy scenarios distribution:', sorted(legacy_scenarios.items()))

# Check isoforest model size in raw and other dirs
for root, dirs, files in os.walk(r'd:\project-1'):
    for f in files:
        if 'isoforest' in f:
            p = os.path.join(root, f)
            print('Found isoforest file:', p, os.path.getsize(p))
