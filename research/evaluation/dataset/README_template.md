# PHANTOM eBPF Behavioral Trace Dataset v1

## Description

Labeled eBPF runtime event traces from PHANTOM supply-chain attack detection experiments.

- **Created at:** {{CREATED_AT}}
- **PHANTOM version:** `{{PHANTOM_VERSION}}`
- **Total events:** {{EVENT_COUNT}}
- **Total scenarios:** {{SCENARIO_COUNT}}
- **Label source:** `experiment_oracle` — labels are **never** derived from PHANTOM outputs.

## Quick Start

```python
import pandas as pd

traces = pd.read_parquet('traces.parquet')
labels = pd.read_parquet('labels.parquet')

# All attack-phase events
attack_traces = traces[traces['label'] == 1]

# Join with scenario labels
merged = traces.merge(labels, on='scenario_id')

# Event type distribution per attack family
print(attack_traces.groupby('attack_family')['event_type'].value_counts())

# Detection latency for PHANTOM (TP scenarios only)
tp = labels[(labels['is_attack']) & (labels['detection_timestamp_phantom'].notna())]
tp['mttd_s'] = (
    tp['detection_timestamp_phantom'] - tp['injection_timestamp']
).dt.total_seconds()
print(tp[['attack_family', 'mttd_s']].describe())
```

## Schema — traces.parquet

{{SCHEMA_TABLE}}

## Schema — labels.parquet

| Column | Description |
|---|---|
| `label_id` | Stable UUID for this label row |
| `experiment_id` | Attack ID grouping all repetitions |
| `scenario_id` | Individual run_id (matches traces.scenario_id) |
| `attack_id` | Attack manifest attack_id |
| `attack_family` | Attack taxonomy label |
| `repetition` | Repetition index (1-based) |
| `label` | Oracle ground truth: 1=attack, 0=benign |
| `is_attack` | Boolean: label == 1 |
| `is_pre_compromise` | True for windows after injection, before compromise marker |
| `is_compromised` | True once the oracle compromise marker occurred |
| `injection_timestamp` | Oracle timestamp immediately after inject() returned |
| `compromise_time_ns` | Oracle timestamp of first beacon connection (from sink log) |
| `detection_timestamp_phantom` | First PHANTOM detection after injection |
| `detection_timestamp_falco` | First Falco alert after injection |
| `recovery_timestamp` | Timestamp when recover() completed |
| `ground_truth_purl` | Oracle PURL of the substituted/added component |
| `ground_truth_service` | Target Kubernetes service |
| `expected_identifiable` | Whether causal effect should be identifiable |
| `oracle_manifest_path` | Relative path to oracle YAML manifest |
| `clean_image_digest` | SHA-256 digest of the clean image |
| `attack_image_digest` | SHA-256 digest of the attack image |
| `phase_durations` | JSON dict of phase_name → duration_s |
| `notes` | Free-text notes without secrets |

## Attack Scenarios

{{ATTACK_SCENARIOS}}

## Benign Control Scenarios

Three benign controls are included to measure false positive rates:

- **benign-update-001**: Legitimate dependency patch update (`lzmaffi@1.0.0 → 1.0.1`).
  No behavioral changes expected. Tests FPR under normal maintenance.
- **benign-load-001**: k6 high-load burst (no image/package changes).
  Tests whether PHANTOM triggers on syscall frequency shifts alone.
- **benign-restart-001**: Pod deletion and reschedule.
  Tests whether PHANTOM triggers on process re-initialization.

## Split Strategy

**Strategy:** `{{SPLIT_STRATEGY}}`

Splits are assigned by scenario family and time — not by random event rows.
This prevents leakage from temporal autocorrelation and repeated Pods.

| Split | Contents |
|---|---|
| **Train** | All benign control scenarios + non-held-out attack repetitions |
| **Validation** | One held-out repetition per attack family (threshold calibration only) |
| **Test** | Final held-out repetition per attack family |

No Pod UID, container ID, or time-adjacent windows cross split boundaries.
The same attack image cannot appear in both validation and test sets.

## Reproducibility

- Parquet written with Snappy compression.
- SHA-256 checksums in `manifest.json`.
- `manifest.json` records PHANTOM git commit, schema version, and label source.
- Oracle manifests in `research/evaluation/oracles/` are the ground truth.
- Trivy vulnerability DB frozen once before experiment batch (version pinned).

## Checksums

```
traces.parquet SHA-256: {{TRACES_SHA256}}
labels.parquet SHA-256: {{LABELS_SHA256}}
```

## Ethical Considerations

This dataset contains **no PII**, no real credentials, no real network endpoints, and no
real system paths. All attacks were conducted in isolated Kubernetes clusters with
controlled cluster-internal endpoints only.

Privacy mitigations applied to every trace row:
- **PID / Pod UID / container ID**: replaced with salted SHA-256 hashes (not reversible).
- **File paths**: replaced with coarse categories (tmp|proc|lib|bin|etc|home|other).
- **IP addresses**: classified as `cluster|private|public|none` (no raw IPs stored).
- **DNS domains**: classified as `cluster_service|controlled_sink|external|none`.
- **Command arguments**: SHA-256 fingerprint only (no raw argv stored).
- **UID**: classified as `root|service|unknown`.

## License

- **Trace/label data**: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Packaging scripts**: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Citation

If you use this dataset, please cite the PHANTOM paper (citation to be provided at camera-ready).

## Known Limitations

- Benchmark: Online Boutique only. Other workloads may show different behavioral patterns.
- Attack realism: Synthetic controlled payloads. Real supply-chain attacks may behave differently.
- eBPF event loss: Measured and reported in `manifest.json` (ringbuf_lost_delta column).
- Clock skew: Mitigated by node time sync (chrony); same-node latency calculations used.
- Kernel version: Requires kernel ≥ 5.8 for BPF_MAP_TYPE_RINGBUF.
