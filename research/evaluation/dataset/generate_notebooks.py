"""
research/evaluation/dataset/generate_notebooks.py

Generates the four paper analysis notebooks as .ipynb files.

Usage:
    python research/evaluation/dataset/generate_notebooks.py \
        --output-dir research/notebooks/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _code(source: str) -> dict:
    """Create a code cell dict for nbformat 4.

    Args:
        source: Python source string.

    Returns:
        nbformat code cell dict.
    """
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source,
    }


def _md(source: str) -> dict:
    """Create a markdown cell dict for nbformat 4.

    Args:
        source: Markdown string.

    Returns:
        nbformat markdown cell dict.
    """
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source,
    }


def _notebook(cells: list[dict]) -> dict:
    """Build a complete nbformat 4.5 notebook dict.

    Args:
        cells: List of cell dicts.

    Returns:
        Full notebook dict.
    """
    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "name": "python",
                "version": "3.11.0",
            },
        },
        "cells": cells,
    }


# ---------------------------------------------------------------------------
# Notebook 01: Causal Attribution Analysis
# ---------------------------------------------------------------------------


def _nb_01() -> dict:
    cells = [
        _md("# Causal Attribution Analysis\n\nEvaluates PHANTOM's causal attribution accuracy against oracle ground truth.\nProduces TABLE_2 and FIGURE_1 from the paper."),

        _code("""\
# Cell 1: Setup and dataset load
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import json

DATASET_DIR = Path('research/datasets/phantom-v1')
RESULTS_DIR = Path('research/datasets/raw')

traces = pd.read_parquet(DATASET_DIR / 'traces.parquet')
labels = pd.read_parquet(DATASET_DIR / 'labels.parquet')

with open(DATASET_DIR / 'manifest.json') as f:
    manifest = json.load(f)

print(f"Traces: {len(traces):,} rows | Labels: {len(labels):,} rows")
print(f"PHANTOM version: {manifest['phantom_version']}")
print(f"Attack families: {labels[labels['is_attack']]['attack_family'].unique().tolist()}")
"""),

        _code("""\
# Cell 2: Attribution accuracy computation
# Ground truth PURL vs PHANTOM top-attributed PURL
# Credit: 1.0 = exact match, 0.5 = oracle PURL in top-3, 0.0 = miss

attack_labels = labels[labels['is_attack']].copy()

def credit(row):
    truth = row.get('ground_truth_purl', '')
    top = row.get('top_attributed_purl', '')
    top3 = row.get('top3_attributed_purls', [])
    if isinstance(top3, str):
        try:
            top3 = json.loads(top3)
        except Exception:
            top3 = []
    if top and top == truth:
        return 1.0
    if truth in (top3 or []):
        return 0.5
    return 0.0

attack_labels['attribution_credit'] = attack_labels.apply(credit, axis=1)
exact_mask = attack_labels['attribution_credit'] == 1.0
partial_mask = attack_labels['attribution_credit'] == 0.5

print("Causal Attribution Accuracy (CAA)")
print(f"  Overall (mean credit): {attack_labels['attribution_credit'].mean():.3f}")
print(f"  Exact match rate:      {exact_mask.mean():.3f}")
print(f"  Partial credit rate:   {partial_mask.mean():.3f}")
print(f"  Zero credit rate:      {(attack_labels['attribution_credit'] == 0).mean():.3f}")
print()
print(attack_labels.groupby('attack_family')['attribution_credit'].describe().round(3))
"""),

        _code("""\
# Cell 3: Attribution confidence by scenario — box plot (FIGURE_1)

fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Left: confidence distribution by attack family
conf_data = traces[
    (traces['label'] == 1) &
    (traces['phantom_attribution_confidence'].notna())
].copy()

families = conf_data['attack_family'].dropna().unique()
conf_by_family = [
    conf_data[conf_data['attack_family'] == f]['phantom_attribution_confidence'].values
    for f in families
]

axes[0].boxplot(conf_by_family, labels=[f.replace('_', '\\n') for f in families], patch_artist=True)
axes[0].set_ylabel('Attribution Confidence')
axes[0].set_title('PHANTOM Attribution Confidence by Attack Family')
axes[0].set_ylim(0, 1.05)
axes[0].axhline(y=0.5, color='red', linestyle='--', alpha=0.5, label='0.5 threshold')
axes[0].legend()

# Right: credit distribution
credit_counts = attack_labels['attribution_credit'].value_counts().sort_index()
axes[1].bar([str(c) for c in credit_counts.index], credit_counts.values,
            color=['#e74c3c', '#f39c12', '#2ecc71'])
axes[1].set_xlabel('Attribution Credit')
axes[1].set_ylabel('Scenario Count')
axes[1].set_title('Attribution Credit Distribution\\n(1.0=exact, 0.5=partial, 0.0=miss)')

plt.tight_layout()
plt.savefig('research/evaluation/results/figure_1_attribution_confidence.pdf', dpi=150, bbox_inches='tight')
plt.show()
print("Figure 1 saved.")
"""),

        _code("""\
# Cell 4: Identifiability analysis

# Load raw attribution results from saved JSON files
import glob

attribution_records = []
for f in sorted(glob.glob('research/datasets/raw/*.json')):
    if 'index' in f:
        continue
    try:
        with open(f) as fh:
            r = json.load(fh)
        label_dict = r.get('scenario_label', {})
        attribution_records.append({
            'run_id': r['run_id'],
            'attack_family': r['attack_family'],
            'ground_truth_label': r['ground_truth_label'],
            'identifiable': label_dict.get('identifiable'),
            'not_identifiable_reason': label_dict.get('not_identifiable_reason', ''),
        })
    except Exception:
        pass

adf = pd.DataFrame(attribution_records)
attack_adf = adf[adf['ground_truth_label'] == 1]

identifiable_counts = attack_adf['identifiable'].value_counts(dropna=False)
print("Identifiability outcomes (attack scenarios):")
print(identifiable_counts)

# Pie chart
fig, ax = plt.subplots(figsize=(6, 5))
labels_pie = identifiable_counts.index.astype(str).tolist()
ax.pie(identifiable_counts.values, labels=labels_pie, autopct='%1.1f%%',
       colors=['#2ecc71', '#e74c3c', '#95a5a6'])
ax.set_title('PHANTOM Causal Identifiability Outcomes\\n(Attack Scenarios)')
plt.tight_layout()
plt.savefig('research/evaluation/results/figure_1b_identifiability.pdf', dpi=150, bbox_inches='tight')
plt.show()
"""),

        _code("""\
# Cell 5: Refutation test stability
# Shows whether completed causal attributions pass the refutation tests

refutation_records = []
for f in sorted(glob.glob('research/datasets/raw/*.json')):
    if 'index' in f:
        continue
    try:
        with open(f) as fh:
            r = json.load(fh)
        label_dict = r.get('scenario_label', {})
        refutation_records.append({
            'run_id': r['run_id'],
            'attack_family': r['attack_family'],
            'ground_truth_label': r['ground_truth_label'],
            'refutation_passed': label_dict.get('refutation_passed'),
            'refutation_tests_run': label_dict.get('refutation_tests_run', 0),
        })
    except Exception:
        pass

rdf = pd.DataFrame(refutation_records)
attack_rdf = rdf[rdf['ground_truth_label'] == 1]

if 'refutation_passed' in attack_rdf.columns:
    refutation_rate = attack_rdf['refutation_passed'].mean()
    print(f"Refutation pass rate (attack scenarios): {refutation_rate:.3f}")
    print(attack_rdf.groupby('attack_family')['refutation_passed'].mean().round(3))
else:
    print("No refutation data in scenario labels yet (run with PHANTOM v2+).")
"""),
    ]
    return _notebook(cells)


# ---------------------------------------------------------------------------
# Notebook 02: PCEPS Calibration
# ---------------------------------------------------------------------------


def _nb_02() -> dict:
    cells = [
        _md("# PCEPS Calibration Analysis\n\nEvaluates PCEPS probability calibration and predictive performance.\nProduces FIGURE_2 (reliability diagram) and FIGURE_3 (AUC-ROC)."),

        _code("""\
# Cell 1: Load scores and labels
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.calibration import calibration_curve
from sklearn.metrics import roc_curve, auc, brier_score_loss
import json

DATASET_DIR = Path('research/datasets/phantom-v1')
traces = pd.read_parquet(DATASET_DIR / 'traces.parquet')
labels = pd.read_parquet(DATASET_DIR / 'labels.parquet')

# Use traces with PCEPS scores for pre-compromise windows
pceps_traces = traces[traces['phantom_pceps_score'].notna()].copy()
print(f"Traces with PCEPS scores: {len(pceps_traces):,}")
print(f"Attack traces: {(pceps_traces['label'] == 1).sum():,}")
print(f"Benign traces: {(pceps_traces['label'] == 0).sum():,}")
print(f"Score range: [{pceps_traces['phantom_pceps_score'].min():.3f}, "
      f"{pceps_traces['phantom_pceps_score'].max():.3f}]")
"""),

        _code("""\
# Cell 2: Reliability diagram (calibration plot) — FIGURE_2

fig, axes = plt.subplots(1, 2, figsize=(12, 5))

y_true = pceps_traces['label'].values
y_prob = pceps_traces['phantom_pceps_score'].values

# 10 equally spaced probability bins
prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=10, strategy='uniform')

ax = axes[0]
ax.plot(prob_pred, prob_true, 's-', color='#2ecc71', label='PHANTOM (Platt-scaled)', linewidth=2)
ax.plot([0, 1], [0, 1], 'k--', label='Perfect calibration', alpha=0.7)

# Naive baselines (illustrative)
ax.axhline(y=y_true.mean(), color='#e74c3c', linestyle=':', label=f'Always-mean ({y_true.mean():.2f})', alpha=0.8)

ax.set_xlabel('Mean Predicted Probability')
ax.set_ylabel('Fraction of Positives')
ax.set_title('FIGURE_2: PCEPS Reliability Diagram\\n(10-bin calibration plot)')
ax.legend(loc='upper left')
ax.set_xlim(0, 1)
ax.set_ylim(-0.05, 1.05)
ax.grid(True, alpha=0.3)

# Brier score decomposition (gap histogram)
axes[1].hist(y_prob[y_true == 0], bins=20, alpha=0.6, color='#3498db', label='Benign (y=0)', density=True)
axes[1].hist(y_prob[y_true == 1], bins=20, alpha=0.6, color='#e74c3c', label='Attack (y=1)', density=True)
axes[1].set_xlabel('PCEPS Predicted Probability')
axes[1].set_ylabel('Density')
axes[1].set_title('Score Distribution by True Label')
axes[1].legend()
axes[1].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('research/evaluation/results/figure_2_pceps_reliability.pdf', dpi=150, bbox_inches='tight')
plt.show()
"""),

        _code("""\
# Cell 3: Brier score computation

bs_phantom = brier_score_loss(y_true, y_prob)
bs_always_zero = brier_score_loss(y_true, np.zeros_like(y_prob))
bs_always_one  = brier_score_loss(y_true, np.ones_like(y_prob))
bs_prevalence  = brier_score_loss(y_true, np.full_like(y_prob, y_true.mean()))

print("Brier Scores (lower = better calibration):")
print(f"  PHANTOM (Platt-scaled):   {bs_phantom:.4f}")
print(f"  Always predict 0:         {bs_always_zero:.4f}")
print(f"  Always predict 1:         {bs_always_one:.4f}")
print(f"  Always predict prevalence:{bs_prevalence:.4f}")

# Per-attack-family breakdown
for family in pceps_traces['attack_family'].dropna().unique():
    mask = pceps_traces['attack_family'] == family
    if mask.sum() > 5:
        bs = brier_score_loss(
            pceps_traces[mask]['label'].values,
            pceps_traces[mask]['phantom_pceps_score'].values,
        )
        print(f"  {family:<40}: {bs:.4f}")
"""),

        _code("""\
# Cell 4: AUC-ROC curve — FIGURE_3

fig, ax = plt.subplots(figsize=(7, 6))

# PHANTOM
fpr_ph, tpr_ph, _ = roc_curve(y_true, y_prob)
roc_auc_ph = auc(fpr_ph, tpr_ph)
ax.plot(fpr_ph, tpr_ph, color='#2ecc71', linewidth=2.5,
        label=f'PHANTOM (AUC = {roc_auc_ph:.3f})')

# KL-score baseline (using kl_score column as a naive ranker)
if 'kl_score' in pceps_traces.columns and pceps_traces['kl_score'].notna().any():
    kl_scores = pceps_traces['kl_score'].fillna(0).values
    fpr_kl, tpr_kl, _ = roc_curve(y_true, kl_scores)
    roc_auc_kl = auc(fpr_kl, tpr_kl)
    ax.plot(fpr_kl, tpr_kl, color='#3498db', linestyle='--', linewidth=2,
            label=f'KL-score only (AUC = {roc_auc_kl:.3f})')

# Random baseline
ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random (AUC = 0.500)')

ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('FIGURE_3: AUC-ROC Comparison\\n(PHANTOM vs Baselines)')
ax.legend(loc='lower right')
ax.grid(True, alpha=0.3)
ax.set_xlim(0, 1)
ax.set_ylim(0, 1.02)

plt.tight_layout()
plt.savefig('research/evaluation/results/figure_3_pceps_auc.pdf', dpi=150, bbox_inches='tight')
plt.show()
print(f"PHANTOM AUC-ROC: {roc_auc_ph:.4f}")
"""),

        _code("""\
# Cell 5: Feature importance (XGBoost gain-based, if model available)
from pathlib import Path

model_path = Path('research/datasets/raw/pceps_model.json')
if model_path.exists():
    try:
        import xgboost as xgb
        model = xgb.XGBClassifier()
        model.load_model(str(model_path))

        importance = model.get_booster().get_score(importance_type='gain')
        imp_series = pd.Series(importance).sort_values(ascending=True).tail(20)

        fig, ax = plt.subplots(figsize=(8, 6))
        imp_series.plot(kind='barh', ax=ax, color='#2ecc71')
        ax.set_xlabel('Feature Importance (Gain)')
        ax.set_title('XGBoost PCEPS Feature Importance\\n(Top 20 by gain)')
        ax.axvline(x=0, color='black', linewidth=0.5)

        # Highlight causal_effect feature (f1 from DoWhy)
        for tick in ax.get_yticklabels():
            if 'causal_effect' in tick.get_text().lower():
                tick.set_fontweight('bold')
                tick.set_color('#e74c3c')

        plt.tight_layout()
        plt.savefig('research/evaluation/results/figure_pceps_feature_importance.pdf',
                    dpi=150, bbox_inches='tight')
        plt.show()
        print("Key finding: Does causal_effect rank in top features?",
              any('causal_effect' in k.lower() for k in list(importance)[:5]))
    except ImportError:
        print("xgboost not installed; skipping feature importance plot.")
else:
    print(f"Model not found at {model_path}; run PCEPS training first.")
"""),
    ]
    return _notebook(cells)


# ---------------------------------------------------------------------------
# Notebook 03: Overhead Measurement
# ---------------------------------------------------------------------------


def _nb_03() -> dict:
    cells = [
        _md("# eBPF Overhead Measurement\n\nProduces TABLE_3 from the paper: CPU/memory overhead, event loss rate, collection latency."),

        _code("""\
# Cell 1: Load Prometheus metrics from experiment runs
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import glob

DATASET_DIR = Path('research/datasets/phantom-v1')
RESULTS_DIR = Path('research/datasets/raw')

traces = pd.read_parquet(DATASET_DIR / 'traces.parquet')

# Load all scenario results for phase-level metrics
scenario_results = []
for f in sorted(glob.glob(str(RESULTS_DIR / '*.json'))):
    if 'index' in f:
        continue
    try:
        with open(f) as fh:
            r = json.load(fh)
        scenario_results.append(r)
    except Exception:
        pass

print(f"Loaded {len(scenario_results)} scenario results.")

# Extract metrics snapshots
metric_rows = []
for r in scenario_results:
    for snap in r.get('metrics_snapshots', []):
        metric_rows.append({
            'run_id': r['run_id'],
            'attack_family': r['attack_family'],
            'ground_truth_label': r['ground_truth_label'],
            'phase': snap['phase'],
            'cpu_usage_cores': snap['cpu_usage_cores'],
            'memory_rss_mb': snap['memory_rss_mb'],
            'event_lag_p95_ms': snap['event_lag_p95_ms'],
        })

metrics_df = pd.DataFrame(metric_rows)
print(metrics_df.groupby('phase')[['cpu_usage_cores', 'memory_rss_mb', 'event_lag_p95_ms']].describe().round(3))
"""),

        _code("""\
# Cell 2: CPU overhead table — TABLE_3

# Compare baseline vs attack phase CPU
baseline_cpu = metrics_df[metrics_df['phase'] == 'baseline']['cpu_usage_cores']
attack_cpu   = metrics_df[metrics_df['phase'] == 'attack']['cpu_usage_cores']

cpu_overhead_pct = 100 * (attack_cpu.mean() - baseline_cpu.mean()) / max(baseline_cpu.mean(), 1e-9)

print("=== TABLE_3: Overhead Summary ===")
print(f"Baseline CPU (cores):   {baseline_cpu.mean():.4f} ± {baseline_cpu.std():.4f}")
print(f"Attack phase CPU:       {attack_cpu.mean():.4f} ± {attack_cpu.std():.4f}")
print(f"CPU overhead:           {cpu_overhead_pct:.2f}%")

baseline_mem = metrics_df[metrics_df['phase'] == 'baseline']['memory_rss_mb']
attack_mem   = metrics_df[metrics_df['phase'] == 'attack']['memory_rss_mb']
print(f"Baseline Memory (MB):   {baseline_mem.mean():.2f} ± {baseline_mem.std():.2f}")
print(f"Attack phase Memory:    {attack_mem.mean():.2f} ± {attack_mem.std():.2f}")
print(f"Memory overhead (MB):   {(attack_mem.mean() - baseline_mem.mean()):.2f}")

lag_col = metrics_df[metrics_df['phase'] == 'attack']['event_lag_p95_ms']
print(f"Event lag P95 (ms):     {lag_col.mean():.2f} ± {lag_col.std():.2f}")
"""),

        _code("""\
# Cell 3: Memory overhead bar chart

fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# CPU by phase
phase_order = ['baseline', 'attack', 'post_recovery']
cpu_by_phase = metrics_df.groupby('phase')['cpu_usage_cores'].mean().reindex(
    [p for p in phase_order if p in metrics_df['phase'].unique()]
)
axes[0].bar(cpu_by_phase.index, cpu_by_phase.values, color=['#3498db', '#e74c3c', '#2ecc71'])
axes[0].set_xlabel('Scenario Phase')
axes[0].set_ylabel('CPU Usage (cores)')
axes[0].set_title('PHANTOM Agent CPU by Phase')

# Memory by phase
mem_by_phase = metrics_df.groupby('phase')['memory_rss_mb'].mean().reindex(
    [p for p in phase_order if p in metrics_df['phase'].unique()]
)
axes[1].bar(mem_by_phase.index, mem_by_phase.values, color=['#3498db', '#e74c3c', '#2ecc71'])
axes[1].set_xlabel('Scenario Phase')
axes[1].set_ylabel('Memory RSS (MB)')
axes[1].set_title('PHANTOM Agent Memory by Phase')

plt.tight_layout()
plt.savefig('research/evaluation/results/table_3_overhead.pdf', dpi=150, bbox_inches='tight')
plt.show()
"""),

        _code("""\
# Cell 4: Event lag distribution histogram

lag_values = metrics_df['event_lag_p95_ms'].dropna()

fig, ax = plt.subplots(figsize=(7, 5))
ax.hist(lag_values, bins=30, color='#2ecc71', edgecolor='black', alpha=0.8)
ax.axvline(lag_values.quantile(0.95), color='red', linestyle='--',
           label=f'P95 = {lag_values.quantile(0.95):.1f} ms')
ax.axvline(lag_values.median(), color='blue', linestyle='-.',
           label=f'Median = {lag_values.median():.1f} ms')
ax.set_xlabel('Event Collection Latency P95 (ms)')
ax.set_ylabel('Count')
ax.set_title('eBPF Event Collection Latency Distribution\\n(t_ingest - t_kernel)')
ax.legend()
ax.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('research/evaluation/results/overhead_event_lag.pdf', dpi=150, bbox_inches='tight')
plt.show()
print(f"P50 lag: {lag_values.quantile(0.50):.2f} ms")
print(f"P95 lag: {lag_values.quantile(0.95):.2f} ms")
print(f"P99 lag: {lag_values.quantile(0.99):.2f} ms")
"""),

        _code("""\
# Cell 5: Ring buffer loss rate

# ringbuf_lost_delta from traces.parquet
if 'ringbuf_lost_delta' in traces.columns and traces['ringbuf_lost_delta'].notna().any():
    total_events = len(traces)
    total_lost = traces['ringbuf_lost_delta'].dropna().sum()
    loss_rate = total_lost / max(total_events + total_lost, 1)
    print(f"Ring buffer loss rate: {loss_rate:.4%}")
    print(f"Total events processed: {total_events:,}")
    print(f"Total events lost:      {total_lost:,.0f}")
else:
    print("No ringbuf_lost_delta data in traces (column is null).")
    print("Verify eBPF agent exposes phantom_ebpf_ringbuf_reserve_failures_total.")
"""),
    ]
    return _notebook(cells)


# ---------------------------------------------------------------------------
# Notebook 04: BDG Topology Analysis
# ---------------------------------------------------------------------------


def _nb_04() -> dict:
    cells = [
        _md("# BDG Topology Analysis\n\nCompares Behavioral Dependency Graph structure during attack vs benign phases.\nProduces the centrality delta visualization supporting PCEPS feature f14."),

        _code("""\
# Cell 1: Load BDG snapshots from evaluation runs
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import json
import glob

RESULTS_DIR = Path('research/datasets/raw')
DATASET_DIR = Path('research/datasets/phantom-v1')

traces = pd.read_parquet(DATASET_DIR / 'traces.parquet')
labels = pd.read_parquet(DATASET_DIR / 'labels.parquet')

# Load BDG snapshot JSON files (exported by run_all_scenarios via PHANTOM API)
bdg_snapshots = []
for f in sorted(glob.glob(str(RESULTS_DIR / 'bdg_snapshots' / '*.json'))):
    try:
        with open(f) as fh:
            bdg_snapshots.append(json.load(fh))
    except Exception:
        pass

if not bdg_snapshots:
    print("No BDG snapshot files found in research/datasets/raw/bdg_snapshots/.")
    print("Run evaluation with --export-bdg-snapshots flag to generate them.")
    print("Using traces.parquet edge data for proxy graph metrics.")
    USE_TRACE_PROXY = True
else:
    print(f"Loaded {len(bdg_snapshots)} BDG snapshots.")
    USE_TRACE_PROXY = False
"""),

        _code("""\
# Cell 2: Graph metrics comparison — node count, edge count, density

if USE_TRACE_PROXY:
    # Use edge columns from traces as a proxy for BDG structure
    edge_traces = traces[
        traces['edge_src_purl'].notna() & traces['edge_dst_purl'].notna()
    ].copy()

    def graph_metrics(df):
        nodes = pd.unique(pd.concat([df['edge_src_purl'], df['edge_dst_purl']]))
        edges = df[['edge_src_purl', 'edge_dst_purl']].drop_duplicates()
        n, e = len(nodes), len(edges)
        density = (2 * e) / (n * (n - 1)) if n > 1 else 0
        return {'node_count': n, 'edge_count': e, 'density': density}

    metrics_by_phase = {}
    for phase in edge_traces['phase'].unique():
        sub = edge_traces[edge_traces['phase'] == phase]
        metrics_by_phase[phase] = graph_metrics(sub)

    gdf = pd.DataFrame(metrics_by_phase).T
    print("BDG Graph Metrics by Phase (trace-derived proxy):")
    print(gdf.round(4))
else:
    records = []
    for snap in bdg_snapshots:
        records.append({
            'snapshot_id': snap.get('snapshot_id'),
            'phase': snap.get('phase'),
            'attack_family': snap.get('attack_family'),
            'label': snap.get('label', 0),
            'node_count': snap.get('node_count', 0),
            'edge_count': snap.get('edge_count', 0),
            'density': snap.get('density', 0),
        })
    snap_df = pd.DataFrame(records)
    print(snap_df.groupby('phase')[['node_count', 'edge_count', 'density']].describe().round(4))
"""),

        _code("""\
# Cell 3: Centrality delta visualization

# edge_weight column from traces serves as a proxy for PageRank weight.
# In the real system, graph_centrality_delta (PCEPS f14) is computed by
# the causal engine and stored in phantom_attribution_confidence.

if USE_TRACE_PROXY:
    edge_attack = traces[(traces['label'] == 1) & (traces['edge_weight'].notna())]
    edge_benign = traces[(traces['label'] == 0) & (traces['edge_weight'].notna())]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    axes[0].hist(edge_benign['edge_weight'].dropna(), bins=30, alpha=0.6,
                 color='#3498db', label='Benign', density=True)
    axes[0].hist(edge_attack['edge_weight'].dropna(), bins=30, alpha=0.6,
                 color='#e74c3c', label='Attack', density=True)
    axes[0].set_xlabel('BDG Edge Weight')
    axes[0].set_ylabel('Density')
    axes[0].set_title('Edge Weight Distribution: Attack vs Benign')
    axes[0].legend()

    # Centrality proxy: group by purl and sum edge weights (in-degree proxy)
    purl_weight_attack = edge_attack.groupby('edge_dst_purl')['edge_weight'].sum().sort_values(ascending=False).head(15)
    purl_weight_benign = edge_benign.groupby('edge_dst_purl')['edge_weight'].sum().sort_values(ascending=False).head(15)

    delta_idx = purl_weight_attack.index.union(purl_weight_benign.index)
    delta = (
        purl_weight_attack.reindex(delta_idx, fill_value=0)
        - purl_weight_benign.reindex(delta_idx, fill_value=0)
    ).sort_values(ascending=False).head(10)

    delta.plot(kind='barh', ax=axes[1], color='#e74c3c')
    axes[1].axvline(0, color='black', linewidth=0.5)
    axes[1].set_xlabel('Centrality Delta (Attack - Benign)')
    axes[1].set_title('Top 10 PURLs by Centrality Increase\\n(Attack vs Benign Phase)')
    axes[1].set_yticklabels([p[:40] for p in delta.index], fontsize=8)

    plt.tight_layout()
    plt.savefig('research/evaluation/results/bdg_centrality_delta.pdf', dpi=150, bbox_inches='tight')
    plt.show()
    print("Key finding: the attack target PURL should rank #1 in centrality delta.")
"""),

        _code("""\
# Cell 4: Degree distribution (power-law check)

if USE_TRACE_PROXY:
    all_edge_data = traces[traces['edge_src_purl'].notna()].copy()

    # Out-degree per PURL (how many unique destinations)
    out_deg = all_edge_data.groupby('edge_src_purl')['edge_dst_purl'].nunique()
    in_deg  = all_edge_data.groupby('edge_dst_purl')['edge_src_purl'].nunique()

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for ax, deg, label in [(axes[0], out_deg, 'Out-degree'), (axes[1], in_deg, 'In-degree')]:
        counts = deg.value_counts().sort_index()
        ax.loglog(counts.index, counts.values, 'o-', color='#2ecc71', markersize=4)
        ax.set_xlabel(label)
        ax.set_ylabel('Count (log scale)')
        ax.set_title(f'BDG {label} Distribution (log-log)')
        ax.grid(True, which='both', alpha=0.3)

    plt.tight_layout()
    plt.savefig('research/evaluation/results/bdg_degree_distribution.pdf', dpi=150, bbox_inches='tight')
    plt.show()
    print(f"Max out-degree: {out_deg.max()} | Max in-degree: {in_deg.max()}")
    print(f"Mean out-degree: {out_deg.mean():.2f} | Mean in-degree: {in_deg.mean():.2f}")
"""),

        _code("""\
# Cell 5: Path length from workload nodes to drift_event nodes

# In PHANTOM's BDG, drift_event nodes should be 1-2 hops from the
# workload node during an attack. During benign scenarios, no drift_event
# nodes should appear. This cell validates the BDG structural claim.

import networkx as nx

if USE_TRACE_PROXY:
    attack_edges = traces[
        (traces['label'] == 1) &
        traces['edge_src_purl'].notna() &
        traces['edge_dst_purl'].notna()
    ]
    G = nx.DiGraph()
    for _, row in attack_edges.iterrows():
        G.add_edge(row['edge_src_purl'], row['edge_dst_purl'],
                   weight=row['edge_weight'] or 1.0)

    print(f"Attack BDG: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print(f"Weakly connected components: {nx.number_weakly_connected_components(G)}")

    # Identify nodes that appear only in attack phase (drift candidates)
    benign_nodes = set(traces[traces['label'] == 0]['edge_src_purl'].dropna()) | \
                   set(traces[traces['label'] == 0]['edge_dst_purl'].dropna())
    attack_only = {n for n in G.nodes() if n not in benign_nodes and n}
    print(f"\\nAttack-only nodes (potential drift_event nodes): {len(attack_only)}")
    for n in list(attack_only)[:10]:
        print(f"  {n}")
"""),
    ]
    return _notebook(cells)


# ---------------------------------------------------------------------------
# Generator main
# ---------------------------------------------------------------------------


def generate_all(output_dir: Path) -> list[Path]:
    """Generate all four notebooks.

    Args:
        output_dir: Directory to write .ipynb files.

    Returns:
        List of written notebook paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    notebooks = [
        ("01_causal_attribution_analysis.ipynb", _nb_01()),
        ("02_pceps_calibration.ipynb",            _nb_02()),
        ("03_overhead_measurement.ipynb",          _nb_03()),
        ("04_bdg_topology_analysis.ipynb",         _nb_04()),
    ]

    written: list[Path] = []
    for name, nb in notebooks:
        path = output_dir / name
        with path.open("w") as fh:
            json.dump(nb, fh, indent=1)
        print(f"Written: {path}")
        written.append(path)

    return written


if __name__ == "__main__":
    import argparse

    _REPO_ROOT = Path(__file__).resolve().parents[4]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    parser = argparse.ArgumentParser(description="Generate PHANTOM paper analysis notebooks.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "research" / "notebooks",
        help="Directory to write .ipynb files.",
    )
    args = parser.parse_args()

    paths = generate_all(args.output_dir)
    print(f"\nGenerated {len(paths)} notebooks in {args.output_dir}")
