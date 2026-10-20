# PHANTOM Evaluation Pipeline — README

## Overview

This directory contains the full reproducible evaluation pipeline for:

> **PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral
> Contracts in Kubernetes**

The pipeline executes attack and benign scenarios, collects PHANTOM detections
and baseline-detector alerts, and computes all metrics reported in the paper's
detection performance table (Table 1).

---

## Directory Structure

```
research/evaluation/
├── attacks/                    # Attack implementations (xzutils, dep-confusion, solarwinds)
│   ├── base_attack.py          # AttackManifest + BaseAttack ABC
│   ├── dependency_confusion.py # Dependency Confusion attack
│   ├── xzutils_style.py        # XZ-Utils style library backdoor
│   └── solarwinds_style.py     # SolarWinds-style build-pipeline compromise
├── baselines/                  # Baseline detectors (Falco, Trivy, IsolationForest)
├── metrics/
│   ├── evaluator.py            # ScenarioEvaluator — TP/FP/FN/TN/MTTD/F1
│   └── comparison_table.py     # LaTeX + CSV table generator
├── oracles/                    # Ground-truth YAML manifests (never modified by PHANTOM)
│   ├── xzutils-001.yaml
│   ├── dep-confusion-001.yaml
│   ├── benign-load-001.yaml
│   ├── benign-restart-001.yaml
│   └── benign-update-001.yaml
├── scenarios/
│   ├── scenario_runner.py      # 5-phase runner (baseline→inject→attack→recover→post)
│   └── run_all_scenarios.py    # Top-level orchestration (attack + benign scenarios)
├── tests/                      # Unit tests (synthetic data only)
│   ├── conftest.py
│   ├── test_evaluator.py
│   └── test_scenario_runner.py
├── experiment_config.yaml      # Reproducible run configuration
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Package metadata + pytest config
├── retroactive_fill.py         # Post-hoc PHANTOM API query if port-forward was down
└── run_full_evaluation.sh      # Master shell script for full pipeline
```

Raw per-run results are written to `research/datasets/raw/<run_id>.json`.
Computed tables are written to `research/evaluation/results/`.

---

## Prerequisites

```bash
# Python ≥ 3.11
pip install -r research/evaluation/requirements.txt

# Or install the package in editable mode (from repo root):
pip install -e research/evaluation/

# External tools:
# kubectl configured for the evaluation cluster
# Falco 0.44.1 (helm chart falcosecurity/falco@4.3.1)
# Trivy 0.70.0 on PATH
```

---

## Running Unit Tests

Tests exercise all metric computation and result serialization logic using
**synthetic** fixtures. No Kubernetes access is required.

```bash
# From repo root:
python -m pytest research/evaluation/tests/ -v

# With coverage:
python -m pytest research/evaluation/tests/ -v --cov=research.evaluation.metrics --cov=research.evaluation.scenarios

# Unit tests only (skip integration):
python -m pytest research/evaluation/tests/ -v -m unit
```

Expected output: all 37 tests pass, 0 errors.

---

## Running the Full Evaluation Pipeline

### Option A: Shell script (recommended for paper runs)

```bash
# Required environment:
export NAMESPACE="phantom-eval"
export PHANTOM_API_URL="http://localhost:8080"
export PROMETHEUS_URL="http://localhost:9090/api/v1/query"
export API_TOKEN="<bearer_token>"

# Dry run (no kubectl calls, exercises orchestration only):
DRY_RUN=1 bash research/evaluation/run_full_evaluation.sh

# Full run (requires live EKS cluster):
bash research/evaluation/run_full_evaluation.sh
```

### Option B: Python directly

```bash
# Dry run — all scenarios, 3 reps each, no kubectl:
python research/evaluation/scenarios/run_all_scenarios.py \
    --namespace phantom-eval \
    --dry-run \
    --repetitions 3

# Live run:
python research/evaluation/scenarios/run_all_scenarios.py \
    --namespace phantom-eval \
    --phantom-api http://localhost:8080 \
    --token <bearer_token> \
    --repetitions 3
```

---

## Result Schema

Each scenario run produces a JSON file at
`research/datasets/raw/<run_id>.json` with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | `str` | Unique ID: `<YYYYMMDDTHHMMSSz>_<attack_id>_rep<N>` |
| `attack_id` | `str` | Scenario ID (e.g. `xzutils-001`) |
| `attack_family` | `str` | Taxonomy label |
| `repetition` | `int` | 1-based repetition index |
| `namespace` | `str` | Kubernetes namespace |
| `pod_name` | `str` | Target pod name |
| `ground_truth_label` | `int` | 1 = attack, 0 = benign |
| `injection_timestamp` | `str \| null` | ISO 8601 UTC; null for benign |
| `first_phantom_detection_timestamp` | `str \| null` | ISO 8601 UTC; null if no TP |
| `mttd_s` | `float \| null` | Seconds from injection to first detection; null if FN |
| `is_true_positive` | `bool` | True if detected within `detection_window_s` |
| `phases` | `list[PhaseRecord]` | Timestamps + duration for each phase |
| `phantom_detections` | `list[dict]` | All drift-event records from PHANTOM API |
| `falco_detections` | `list[dict]` | All Falco alert records during the scenario |
| `metrics_snapshots` | `list[MetricsSnapshot]` | Prometheus overhead at each phase |
| `scenario_label` | `dict` | Oracle ground-truth metadata |
| `error` | `str` | Non-empty if the run did not complete normally |

---

## Metric Definitions

All definitions match the paper's §4.

| Metric | Definition | Unit |
|--------|-----------|------|
| TP | Attack run detected within `detection_window_s` | count |
| FN | Attack run not detected within `detection_window_s` | count |
| FP | Benign run that produced at least one PHANTOM detection | count |
| TN | Benign run with no PHANTOM detections | count |
| TPR (Recall) | `TP / (TP + FN)` | — |
| FPR | `FP / (FP + TN)` | — |
| Precision | `TP / (TP + FP)` | — |
| F1 | `2 · Precision · Recall / (Precision + Recall)` | — |
| FP/hr | `FP / (total_benign_duration_s / 3600)` | per hour |
| MTTD | `t_detection − t_injection` for TP runs only | seconds |

**Evaluation unit**: one scenario repetition (a "run").

**Alert matching policy**: `first_within_window` — the earliest PHANTOM
detection within `detection_window_s` after `injection_timestamp` counts
as the single TP for that run. Subsequent alerts from the same run are not
re-counted.

**Invalid run policy**: runs where `error != ""` are recorded in a separate
`n_incomplete` count and are **not** silently counted as FN or TN. They are
reported in the final table's footnotes.

**MTTD exclusions**: FN runs are excluded from MTTD. If a run has
`injection_timestamp = None` (aborted before injection), it is also excluded
from MTTD.

**Undefined denominators**: precision, TPR, FPR, and F1 return 0.0 (not NaN
or ∞) when their denominator is zero. This is explicitly documented in the
paper and in the source code.

---

## Statistical Reporting

For each metric over repeated runs, the pipeline reports:

- Sample count (N)
- Mean
- Median (p50)
- 95th percentile (p95)
- Full value list (for external distribution analysis)

> **Small-sample warning**: With 3 repetitions per scenario (N=6 attack runs,
> N=9 benign runs), all estimates are preliminary and carry high uncertainty.
> Confidence intervals are not reported for N < 20. Results should be
> interpreted as pilot measurements, not definitive claims of statistical
> significance.

---

## Reproducing the Published Results

```bash
# 1. Check out the exact commit used for the paper run:
git checkout <paper_commit_sha>

# 2. Verify PHANTOM image digests:
kubectl get pods -n phantom -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}'

# 3. Run the full pipeline:
bash research/evaluation/run_full_evaluation.sh

# 4. Compare with archived results:
diff research/evaluation/results/table_1_detection_performance.csv \
     research/evaluation/results3/table_1_detection_performance.csv
```

> The `results3/` directory contains the raw outputs from the actual paper
> evaluation run. Do not modify these files.

---

## Files Changed by This Implementation

| File | Change |
|------|--------|
| `metrics/evaluator.py` | Fixed dead MTTD branch in `_evaluate_baseline` |
| `pyproject.toml` | **New** — pytest config + package metadata |
| `experiment_config.yaml` | **New** — reproducible run configuration |
| `tests/__init__.py` | **New** — makes tests a Python package |
| `tests/conftest.py` | **New** — shared SYNTHETIC fixtures |
| `tests/test_evaluator.py` | **New** — 37 evaluator unit tests |
| `tests/test_scenario_runner.py` | **New** — ScenarioResult/PhaseRecord tests |
| `EVALUATION_README.md` | **New** — this document |
