# Comprehensive Survey Report: R5 (Baselines & Overhead) & R6 (Reporting & Documentation)

**Date**: 2026-10-24  
**Author**: `explorer_survey_3` (Teamwork Explorer)  
**Investigation Scope**: Requirements R5 and R6 of PHANTOM Experimental Evaluation  
**Target Repository**: `d:\project-1`  

---

## 1. Executive Summary

This investigation conducted a forensic code and dataset audit of the PHANTOM baseline evaluation, resource telemetry, and reporting infrastructure.

### Key Discoveries

1. **Complete Baseline Telemetry Absence Treated as 0% Detection**:
   In both historical evaluation datasets (`research/datasets/raw/` with 114 files and `research/datasets/raw3/` with 9 files), **zero baseline telemetry records exist**.
   - `falco_detections` is empty (`[]`) in 100% of the raw runs. Falco was never actively logging during the test runs (or was run in dry-run mode, producing warnings `falco.alert_log_missing`).
   - Trivy vulnerability scan outputs (`research/datasets/raw/trivy/`) are non-existent (directory is empty).
   - IsolationForest was evaluated without a reachable Prometheus server, causing all windowed queries to return empty arrays.
   - **Critical Methodological Flaw**: The evaluation harness (`research/evaluation/metrics/evaluator.py`) mechanically classified the complete absence of baseline detections as False Negatives ($FN=6$) for all 6 completed attack runs. This generated Table 1 entries showing Falco ($TPR=0.000$), Trivy ($TPR=0.000$), and IsoForest ($TPR=0.000$) versus PHANTOM ($TPR=1.000$), when in reality baseline telemetry was **unmeasured / missing**, not evaluated.

2. **Silent Zero-Fallback Fabricating Zero Overhead**:
   In `research/evaluation/scenarios/scenario_runner.py` (lines 606–637), queries to Prometheus for CPU, memory, and event lag catch connection and query exceptions and silently return `0.0`. Consequently, every single `metrics_snapshot` across all raw runs in `raw/` and `raw3/` contains `cpu_usage_cores: 0.0`, `memory_rss_mb: 0.0`, and `event_lag_p95_ms: 0.0`. Downstream, `evaluator.py` calculated `cpu_overhead_pct: 0.0`, and LaTeX/CSV generation emitted `CPU%: 0.000`. Runtime overhead was **unmeasured**, but the pipeline published fabricated zero overhead.

3. **Absence of Benign Controls Masked Undefined Denominators**:
   `raw3/` contains only 9 attack runs (6 completed, 3 failed injections) and **zero benign controls** ($N_{\text{benign}} = 0$). Despite having zero negative cases, `reports.json` and Table 1 reported $FPR=0.000$, $\text{Precision}=1.000$, and $F1=1.000$. Under standard detection theory, without negative controls, False Positive Rate, Specificity, Precision, and F1 are mathematically **undefined** and must be reported as unavailable (`null` or `---`), not zero or 1.0.

4. **Reporting Pipeline Lacks Statistical Uncertainty & Provenance**:
   - Wilson score confidence intervals are completely absent from `evaluator.py`.
   - MTTD is reported as a single sample mean without IQR or bootstrap uncertainty intervals.
   - `reports.json` is an unversioned flat list lacking schema metadata, dataset hashes, run exclusion explanations (such as the 3 failed SolarWinds injections), or data quality summaries.
   - Neither `EXPERIMENTAL_EVALUATION_README.md` nor `EXPERIMENT_PROTOCOL.md` currently exists in the repository.

---

## 2. Detailed Survey of R5: Baseline Comparisons

### 2.1 Falco 0.44.1 Baseline

#### Configuration & Version Pins
- **Class**: `FalcoBaseline` in `research/evaluation/baselines/falco_baseline.py`
- **Application Version**: Falco 0.44.1 (`FALCO_VERSION = "0.44.1"`)
- **Helm Chart**: `falcosecurity/falco@4.3.1` (`FALCO_CHART_VERSION = "4.3.1"`)
- **Helm Repository**: `https://falcosecurity.github.io/charts`
- **Release Name**: `phantom-eval-falco`
- **Driver Configuration**:
  ```python
  "--set driver.kind=ebpf"
  "--set falco.json_output=true"
  "--set falco.log_level=info"
  "--set falco.priority=warning"
  "--set falco.file_output.enabled=true"
  "--set falco.file_output.filename=/var/log/falco/events.jsonl"
  ```
- **Alert Ingestion Logic**:
  - Primary: `kubectl logs -l app.kubernetes.io/name=falco -n {falco_namespace} --since-time {since_time}`
  - Fallback: Reading host file `/var/log/falco/events.jsonl`
  - Priority mapping: CRITICAL/EMERGENCY $\to 1.0$, ERROR $\to 0.9$, WARNING $\to 0.7$, NOTICE $\to 0.5$, INFO $\to 0.3$, DEBUG $\to 0.1$. Filtered by `min_priority >= WARNING`.

#### Physical Data Audit
- No Falco log files or event dumps exist in `research/` or anywhere in the repository.
- In `research/datasets/baseline_run_log.txt`:
  ```
  2026-08-08 20:27:37,451 INFO research.evaluation.baselines.falco_baseline falco.setup.dry_run_skipped
  2026-08-08 20:27:37,776 WARNING research.evaluation.baselines.falco_baseline falco.alert_log_missing
  ```
- In all 9 JSON files in `research/datasets/raw3/`:
  - `"falco_detections": []` (0 detections in every run).
- In all 114 JSON files in `research/datasets/raw/`:
  - `"falco_detections": []` (0 detections in every run).

#### Scientific Assessment & Gaps
When `run_baselines.py` was executed, Falco was either not deployed or dry-run was enabled. The alert log `/var/log/falco/events.jsonl` was missing. The evaluator received 0 detections and recorded $TP=0, FN=6, TPR=0.0$.
**Defect**: Treating absent logs as verified non-detection violates scientific integrity. If Falco was not active, its metrics must be reported as `unavailable` / `unmeasured` with explicit attribution to missing telemetry.

---

### 2.2 Trivy 0.70.0 Static SBOM/Image Scanner

#### Configuration & Version Pins
- **Class**: `TrivyBaseline` in `research/evaluation/baselines/trivy_baseline.py`
- **Application Version**: Trivy 0.70.0 (`TRIVY_VERSION = "0.70.0"`)
- **Execution Command**: `trivy image --format json --scanners vuln --output <out_path> <image>`
- **Database Pinning**: `trivy image --download-db-only` executed during `setup()` to freeze vulnerability databases before runs.
- **Detection Matching**: CVEs with severity HIGH or CRITICAL; mapped to confidence ($CRITICAL=1.0, HIGH=0.8$). Scan timestamp is assigned as detection time.

#### Physical Data Audit
- Output directory `research/datasets/raw/trivy/` exists but contains **0 files**.
- No Trivy JSON scan output files exist anywhere in the repository.
- `baseline_run_log.txt` records `trivy.setup.dry_run_skipped`.

#### Conceptual & Methodological Mismatch
1. **Task Formulation Mismatch**:
   Trivy is a static vulnerability and SBOM scanner. It inspects container images at build/deploy time. In runtime supply-chain attacks:
   - *XZ-Utils style*: An adversary executes runtime commands or drops a modified shared library / wheel inside a running container post-launch. Trivy cannot observe process injection or in-memory modifications.
   - *Dependency confusion*: Injected via local pod environment changes (e.g. `pip.conf` pointing to malicious private index). Trivy scans the baseline container image, not dynamically installed packages in ephemeral layers.
   - *SolarWinds style*: The SBOM attached to the image declares clean components; an undeclared worker binary is injected into the pipeline or image. Trivy confirms the clean SBOM matches known CVEs; it cannot detect the presence of unauthorized executable code that lacks CVE signatures.
2. **Evaluation Defect**:
   In `results3/reports.json`, Trivy is assigned $TP=0, FN=6, TPR=0.0$. Not only were the scans never run, but comparing a static scan directly against runtime behavioral drift without Task Demarcation is misleading. If Trivy is included, the evaluation protocol must explicitly define the static task vs. runtime task boundary.

---

### 2.3 IsolationForest Anomaly Detector

#### Configuration & Architecture
- **Class**: `IsolationForestBaseline` in `research/evaluation/baselines/isolation_forest_baseline.py`
- **Model Parameters**:
  - `n_estimators`: 200
  - `random_state`: 42
  - `window_seconds`: 10
  - `contamination`: 0.05
- **Feature Vector (17 dimensions)**:
  - 16 eBPF syscall event types: `execve`, `clone`, `fork`, `openat`, `connect`, `accept`, `sendmsg`, `recvmsg`, `tcp_sendmsg`, `tcp_cleanup_rbuf`, `dns_query`, `unlink`, `chmod`, `ptrace`, `setuid`, `capset` (L1 normalized across the 16 features).
  - 1 total event volume feature: $\log(1 + \sum \text{events})$.
- **Data Source**:
  - PromQL query: `increase(phantom_ebpf_events_captured_total{event_type="..."}[10s])` via Prometheus `query_range` endpoint.

#### Physical Data Audit
- Model files exist:
  - `research/datasets/raw3/isoforest_model.pkl` (2,358,245 bytes, written 2026-09-06)
  - `research/datasets/raw/isoforest_model.pkl` (2,357,445 bytes, written 2026-08-08)
- Model inspection confirms:
  - Type: `sklearn.ensemble.IsolationForest`
  - $n\_features\_in = 17$, $n\_estimators = 200$, $offset = -0.4984$, $threshold = -0.5$.
- However, `baseline_run_log.txt` reveals:
  ```
  2026-08-08 20:27:37,767 INFO research.evaluation.baselines.isolation_forest_baseline isoforest.fit.done
  2026-08-08 20:27:37,776 INFO research.evaluation.baselines.isolation_forest_baseline isoforest.model_saved
  ```
  The model was fit in dry-run mode using synthetic Poisson noise (`rng.poisson(lam=5.0, size=17)`), not real cluster telemetry.
- When `get_detections()` was called during the evaluation of `raw3`, Prometheus was not running. `_collect_windows_from_prometheus_with_timestamps()` caught HTTP errors and returned `[]`, resulting in 0 detections and a false $TPR=0.000$.

---

## 3. Detailed Survey of R5: Resource-Overhead Accounting

### 3.1 Prometheus Monitoring Architecture
The system architecture defines Prometheus metric endpoints across services:
- eBPF Agent: `phantom_ebpf_events_captured_total`, `phantom_event_collection_latency_seconds`, `phantom_ebpf_ringbuf_reserve_failures_total`.
- Container Metrics (cAdvisor / kubelet): `container_cpu_usage_seconds_total`, `container_memory_rss`.

### 3.2 Silent Zero-Fallback in `scenario_runner.py`
In `research/evaluation/scenarios/scenario_runner.py`:
```python
605:         def _query(promql: str) -> float:
606:             try:
607:                 with httpx.Client(timeout=self._timeout) as client:
608:                     resp = client.get(
609:                         self._prometheus,
610:                         params={"query": promql},
611:                     )
612:                     resp.raise_for_status()
613:                     data = resp.json()
614:                     results = data.get("data", {}).get("result", [])
615:                     if results:
616:                         return float(results[0]["value"][1])
617:             except Exception as exc:  # noqa: BLE001
618:                 log.debug("prometheus.query_failed", extra={"promql": promql, "error": str(exc)})
619:             return 0.0
```
When Prometheus is not responding:
- `cpu_usage_cores` returns `0.0`
- `memory_rss_mb` returns `0.0`
- `event_lag_p95_ms` returns `0.0`

### 3.3 Historical Data Audit
We audited all 9 runs in `research/datasets/raw3/` and all 114 runs in `research/datasets/raw/`.
- Every `metrics_snapshots` record contains `0.0` for all metrics:
  ```json
  {
    "timestamp": "2026-09-05T22:31:01.628534+00:00",
    "cpu_usage_cores": 0.0,
    "memory_rss_mb": 0.0,
    "event_lag_p95_ms": 0.0,
    "phase": "baseline"
  }
  ```
- In `research/evaluation/metrics/evaluator.py`:
  ```python
  275:         cpu_base = _safe_mean([s.cpu_usage_cores for s in baseline_snaps])
  276:         cpu_attack = _safe_mean([s.cpu_usage_cores for s in attack_snaps])
  277:         cpu_overhead_pct = (
  278:             100.0 * (cpu_attack - cpu_base) / max(cpu_base, 1e-9)
  279:             if cpu_base > 0
  280:             else 0.0
  281:         )
  ```
  Because `cpu_base == 0.0`, `cpu_overhead_pct` became `0.0`.
- In `results3/reports.json`:
  ```json
  "cpu_overhead_pct": 0.0,
  "memory_overhead_mb": 0.0,
  "event_lag_p95_ms": 0.0
  ```
- In `results3/table_1_detection_performance.tex`:
  `\textbf{PHANTOM (ours)} & \textbf{1.000} & \textbf{0.000} & \textbf{1.000} & \textbf{15.740} & \textbf{0.000} & \textbf{0.000}`
- In `research/notebooks/03_overhead_measurement.ipynb`:
  Cell 2 prints `Baseline CPU (cores): 0.0000`, `Attack phase CPU: 0.0000`, `CPU overhead: 0.00%`.

### 3.4 Required Accounting Protocol
Under Requirement R5:
1. When Prometheus telemetry is missing, values must remain `null` in JSON and `\text{---}` or `NR` in LaTeX.
2. The evaluator must never convert missing data or zero base into `0.0%` overhead.
3. The report must state explicitly:
   > *"Resource overhead is unmeasured. No live Prometheus telemetry samples were captured during the scenario runs."*

---

## 4. Detailed Survey of R6: Deterministic Reporting Pipeline

### 4.1 CLI Entry Points & Execution Pipeline
The reporting workflow consists of the following components:
1. `research/evaluation/run_full_evaluation.sh`:
   Shell entry point for end-to-end execution. Accepts `DRY_RUN=1`, `NAMESPACE`, `PROMETHEUS_URL`, etc.
2. `research/evaluation/baselines/run_baselines.py`:
   Loads scenario JSONs from `--raw-dir`, sets up baselines, collects detections, runs `ScenarioEvaluator.evaluate()`, writes `reports.json`, and invokes `comparison_table.write_tables()`.
3. `research/evaluation/metrics/comparison_table.py`:
   Generates LaTeX tables (`table_1_detection_performance.tex`, `table_1_detection_performance_extended.tex`) and CSV (`table_1_detection_performance.csv`).
4. `research/evaluation/retroactive_fill.py`:
   Post-hoc tool designed to query the PHANTOM API to populate drift detections in scenarios where live polling failed.

### 4.2 Schema Analysis of `reports.json`

#### Current Schema
Currently, `reports.json` is a flat JSON array of objects with the following structure:
```json
[
  {
    "detector_name": "phantom",
    "n_attack_scenarios": 6,
    "n_benign_scenarios": 0,
    "tp": 6,
    "fp": 0,
    "fn": 0,
    "tn": 0,
    "tpr": 1.0,
    "fpr": 0.0,
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "false_positives_per_hour": 0.0,
    "mttd_mean_s": 15.74,
    "mttd_p50_s": 5.52,
    "mttd_p95_s": 54.72,
    "mttd_values_s": [70.33, 6.35, 4.68, 2.61, 7.88, 2.58],
    "cpu_overhead_pct": 0.0,
    "memory_overhead_mb": 0.0,
    "event_lag_p95_ms": 0.0,
    "attribution_accuracy": 1.0,
    "attribution_exact": 1.0,
    "attribution_partial": 0.0,
    "brier_score": null,
    "notes": "..."
  }
]
```

#### Required Versioned Schema per R6
To satisfy R6, `reports.json` must be structured as a top-level object containing provenance, data quality summaries, run exclusions, and statistical bounds:
```json
{
  "$schema": "https://phantom-security.io/schemas/evaluation-report-v1.json",
  "version": "1.0.0",
  "generated_at": "2026-10-24T05:55:00Z",
  "provenance": {
    "git_commit": "abc1234...",
    "dataset_directory": "research/datasets/raw3",
    "evaluation_mode": "offline_verified"
  },
  "data_quality_summary": {
    "total_runs_inspected": 9,
    "completed_attack_runs": 6,
    "failed_injections": 3,
    "benign_control_runs": 0,
    "excluded_runs": [
      {
        "run_id": "20260905T231139Z_solarwinds-001_rep1",
        "reason": "inject_failed",
        "detail": "inject() returned False"
      },
      {
        "run_id": "20260905T231616Z_solarwinds-001_rep2",
        "reason": "inject_failed",
        "detail": "inject() returned False"
      },
      {
        "run_id": "20260905T232054Z_solarwinds-001_rep3",
        "reason": "inject_failed",
        "detail": "inject() returned False"
      }
    ],
    "telemetry_status": {
      "phantom_drift_events": "present_6_runs",
      "falco_alert_logs": "missing",
      "trivy_scan_logs": "missing",
      "prometheus_resource_metrics": "unmeasured"
    }
  },
  "reports": [
    {
      "detector_name": "phantom",
      "status": "evaluated_event_presence_only",
      "sample_size": {
        "n_attack_eligible": 6,
        "n_attack_failed_excluded": 3,
        "n_benign_eligible": 0
      },
      "confusion_matrix": {
        "tp": 6,
        "fp": null,
        "fn": 0,
        "tn": null
      },
      "metrics": {
        "tpr": {
          "point": 1.0,
          "wilson_ci_95": [0.6096, 1.0000]
        },
        "fpr": {
          "point": null,
          "status": "undefined_no_benign_controls"
        },
        "precision": {
          "point": null,
          "status": "undefined_no_benign_controls"
        },
        "f1": {
          "point": null,
          "status": "undefined_no_benign_controls"
        },
        "mttd_seconds": {
          "mean": 15.74,
          "median": 5.52,
          "iqr": 4.53,
          "p95": 54.72,
          "bootstrap_ci_95": [4.12, 42.15],
          "raw_values": [70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247]
        },
        "overhead": {
          "cpu_overhead_pct": null,
          "memory_overhead_mb": null,
          "event_lag_p95_ms": null,
          "status": "unmeasured"
        },
        "attribution_accuracy": {
          "point": null,
          "status": "unsupported_runtime_identity_ambiguous"
        }
      }
    },
    {
      "detector_name": "falco-default-rules",
      "status": "telemetry_unavailable",
      "metrics": {
        "tpr": null,
        "fpr": null,
        "f1": null,
        "mttd_seconds": null,
        "overhead": null
      }
    },
    {
      "detector_name": "trivy-sbom-static",
      "status": "task_mismatch_and_telemetry_unavailable",
      "metrics": {
        "tpr": null,
        "fpr": null,
        "f1": null,
        "mttd_seconds": null,
        "overhead": null
      }
    },
    {
      "detector_name": "isolation-forest-syscall-frequency",
      "status": "telemetry_unavailable",
      "metrics": {
        "tpr": null,
        "fpr": null,
        "f1": null,
        "mttd_seconds": null,
        "overhead": null
      }
    }
  ],
  "limitations": [
    "Evaluated on N=6 completed attack runs across 2 families (xzutils-001, dep-confusion-001).",
    "3 build-pipeline tampering runs (solarwinds-001) failed injection and were excluded from detection denominators.",
    "No benign control runs are available in raw3; FPR, specificity, precision, and F1 cannot be estimated.",
    "Runtime identity in raw drift events is ambiguous/unresolved; component-level causal attribution accuracy cannot be confirmed.",
    "Baseline detector telemetry was not captured during test execution; comparative metrics are unavailable.",
    "Prometheus resource telemetry was not recorded; CPU/memory overhead remains unmeasured."
  ]
}
```

---

### 4.3 LaTeX & CSV Table Generation (`comparison_table.py`)

#### Critical Flaws in Current Implementation
1. **Bold Formatting Trap**:
   In `comparison_table.py` (lines 185–216):
   `_find_best(sorted_reports, field, higher_is_better)` searches for min/max values. Because baseline FPR and CPU% defaulted to `0.0`, the script bolded them as best performers:
   ```latex
   \textbf{PHANTOM (ours)} & \textbf{1.000} & \textbf{0.000} & \textbf{1.000} & \textbf{15.740} & \textbf{0.000} & \textbf{0.000} \\
   Falco (default rules) & 0.000 & \textbf{0.000} & 0.000 & \text{---} & \textbf{0.000} & \textbf{0.000} \\
   Trivy (static scan) & 0.000 & \textbf{0.000} & 0.000 & \text{---} & \textbf{0.000} & \textbf{0.000} \\
   IsoForest (na\"{i}ve) & 0.000 & \textbf{0.000} & 0.000 & \text{---} & \textbf{0.000} & \textbf{0.000} \\
   ```
2. **Missing Denominator Annotations**:
   The table title in `results3/table_1_detection_performance.tex` specifies `($N=6$ valid attack runs)`, but does not disclose that $N_{\text{benign}} = 0$.
3. **CSV Export Distortions**:
   `results3/table_1_detection_performance.csv` outputs `0.0000` for baseline TPR, FPR, F1, and CPU%, which when parsed by pandas or downstream scripts appears as genuine measured zero values rather than NaN / missing data.

---

### 4.4 Statistical Uncertainty & Mathematical Formulations

#### 1. Standard (Ordinary) Wilson Score Interval
Requirement R4 and Acceptance Criteria mandate:
> *"Compute proportion uncertainty intervals using the standard (ordinary) Wilson score interval without continuity correction, matching the exact mathematical formula ($[0.6096, 1.0000]$ for $6/6$)"*

Mathematical formulation:
For $x$ successes in $n$ trials with confidence level $1 - \alpha$ ($z = 1.95996 \approx 1.96$ for 95% CI):
$$\tilde{n} = n + z^2$$
$$\tilde{p} = \frac{x + \frac{z^2}{2}}{\tilde{n}}$$
$$\text{margin} = \frac{z}{\tilde{n}} \sqrt{\frac{x(n - x)}{n} + \frac{z^2}{4}}$$
$$\text{Lower} = \max\left(0.0, \tilde{p} - \text{margin}\right), \quad \text{Upper} = \min\left(1.0, \tilde{p} + \text{margin}\right)$$

For $x=6, n=6, z=1.96$:
- $\tilde{n} = 6 + 1.96^2 = 6 + 3.8416 = 9.8416$
- $\tilde{p} = \frac{6 + 1.9208}{9.8416} = \frac{7.9208}{9.8416} \approx 0.804828$
- $\text{margin} = \frac{1.96}{9.8416} \sqrt{0 + \frac{3.8416}{4}} = \frac{1.96 \times 0.98}{9.8416} = \frac{1.9208}{9.8416} \approx 0.195172$
- Lower bound: $0.804828 - 0.195172 = 0.609656 \approx 0.6096$
- Upper bound: $\min(1.0, 0.804828 + 0.195172) = 1.0000$
This matches the exact target $[0.6096, 1.0000]$.

#### 2. MTTD Summary & IQR
Current MTTD values in `raw3`:
$$[70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247]$$
Sorted order:
$$[2.578247, 2.607243, 4.681537, 6.349775, 7.875910, 70.331969]$$
- Mean: $15.7374 \approx 15.74 \text{ s}$
- Median (P50): $5.5157 \approx 5.52 \text{ s}$
- Q1 (25th percentile): $2.6072 \text{ s}$
- Q3 (75th percentile): $7.8759 \text{ s}$
- Interquartile Range (IQR): $Q3 - Q1 = 7.8759 - 2.6072 = 5.2687 \approx 5.27 \text{ s}$
- P95: $54.7180 \approx 54.72 \text{ s}$

---

## 5. Detailed Survey of R6: Documentation Architecture

### 5.1 Existing Documentation State
- `research/evaluation/EVALUATION_README.md`:
  - Contains overview, directory layout, prerequisite setup, and reproduction instructions.
  - **Omissions**:
    - Does not clearly separate offline-verified analysis from live-cluster execution requirements.
    - Mentions "all 37 tests pass" (test suite currently has 60 tests).
    - Does not inventory failed runs (`solarwinds-001`).
    - Does not document the missing baseline telemetry or unmeasured overhead.
- `output/final_review/PHANTOM_Research_Paper_Final_Source.tex` & `PHANTOM_Experiment_Validation.md`:
  - Contains rigorous audit findings (noting that completed attacks were 6, failed 3, baselines unmeasured, overhead unmeasured).
  - However, these findings are in the paper source and audit notes, not yet formalized into the canonical repo evaluation documentation (`EXPERIMENTAL_EVALUATION_README.md` and `EXPERIMENT_PROTOCOL.md`).

### 5.2 Specification for `EXPERIMENTAL_EVALUATION_README.md`
This document must be authored to fulfill R6:
1. **System & Environment Requirements**:
   - Python 3.11+, PyTorch/scikit-learn, DoWhy/NetworkX, Docker, Kubernetes/kubectl, Helm 3.
   - Pinned dependencies: Falco 0.44.1 (chart 4.3.1), Trivy 0.70.0, Kubernetes 1.36.2.
2. **Offline-Verified vs. Live-Cluster Execution Demarcation**:
   - *Offline-Verified Mode*: Can be run on any workstation without Kubernetes or root privileges. Processes saved raw JSON records (`research/datasets/raw3/`), applies ground-truth oracles, runs Preflight Gate G1, generates `reports.json`, and outputs LaTeX/CSV tables.
   - *Live-Cluster Execution Mode*: Requires AWS EKS / KinD cluster with eBPF capability (`BPF_PROG_TYPE_KPROBE`, `TRACEPOINT`), privileged DaemonSets, Prometheus scraping, and running microservices (Google Cloud Microservices Demo).
3. **Scenario Lifecycle**:
   - Phase 1 Baseline (benign observation, 120s)
   - Phase 2 Inject (`inject_ok` verification)
   - Phase 3 Attack observation (120s observation window, polling drift events)
   - Phase 4 Recover (rollback, cleanup)
   - Phase 5 Post-recovery (60s observation of signal decay)
4. **Reproduction Commands**:
   - Exact CLI commands to regenerate all reports and tables deterministically.
5. **Honest Limitations & Exclusions**:
   - Clear disclosure of the 6-run evaluation boundary, failed SolarWinds injections, absence of benign controls in raw3, missing baseline telemetry, and unmeasured overhead.

### 5.3 Specification for `EXPERIMENT_PROTOCOL.md` (R2 Alignment)
1. **Decoupling of Four Dimensions**:
   - Dimension 1: `inject_ok` (injection delivery success).
   - Dimension 2: Independently verified runtime behavior (sink receipts, process verification).
   - Dimension 3: Verified contract violation / drift ($Y_{\text{drift}}$ evaluated against signed contract).
   - Dimension 4: PHANTOM detection alert ($\hat{Y}_{\text{phantom}}$).
2. **Causal Estimand Formalization**:
   - Formal separation between $T_{\text{inject}} \to Y_{\text{drift}}$ and component attribution $T_{\text{purl}} \to Y_{\text{drift}}$.
   - Anti-mediator DAG conditioning rules (forbidding conditioning on downstream runtime events as pre-treatment confounders).

---

## 6. Comprehensive Gap Matrix & Recommendations

| Requirement | Current Repo State | Root Cause / Defect | Recommended Technical Modification | Downstream Lead |
|---|---|---|---|---|
| **R5: Falco Baseline** | `falco_detections: []` in all runs; $TPR=0.000$ in Table 1 | Falco alert log was absent (`/var/log/falco/events.jsonl` missing); evaluator treated missing log as $FN=6$. | Update evaluator to mark Falco as `telemetry_unavailable` / `NR`; never report 0.0% recall when logs were missing. | Implementation Lead |
| **R5: Trivy Baseline** | `raw/trivy/` empty; $TPR=0.000$ in Table 1 | Scans never executed; static scan task was conflated with runtime drift detection. | Mark Trivy as `unavailable` for raw3; document task mismatch in `EXPERIMENT_PROTOCOL.md` and `EXPERIMENTAL_EVALUATION_README.md`. | Implementation Lead |
| **R5: IsoForest Baseline** | Model fit on synthetic data; $TPR=0.000$ in Table 1 | Prometheus was unreachable at evaluation time; 0 vectors retrieved; evaluator counted as $FN=6$. | Mark IsoForest as `telemetry_unavailable` when Prometheus series is missing. | Implementation Lead |
| **R5: Overhead Telemetry** | All snapshots contain `0.0`; Table 1 reports `CPU%: 0.000` | `scenario_runner.py` catches Prometheus connection errors and silently defaults to `0.0`. | Record overhead as `null` / `"unmeasured"`; display as `\text{---}` in LaTeX. Update `evaluator.py` to prevent $0.0/0.0 \to 0.0\%$. | Implementation Lead |
| **R6: Wilson Intervals** | No confidence intervals in `evaluator.py` | Wilson score interval formula was omitted from evaluator. | Implement standard Wilson score formula without continuity correction in `evaluator.py`; verify $[0.6096, 1.0000]$ for 6/6. | Implementation Lead |
| **R6: MTTD Statistics** | Only mean MTTD reported | Median and IQR are not computed or reported in main table. | Add median, IQR, and bootstrap interval calculations to `evaluator.py` and `reports.json`. | Implementation Lead |
| **R6: Undefined Denominators** | Reports $FPR=0.0, Prec=1.0, F1=1.0$ when $N_{\text{benign}}=0$ | Evaluator hardcodes zero or ignores absence of benign controls. | Return `null` / `"undefined"` for FPR, Precision, Specificity, and F1 when negative denominator is 0. | Implementation Lead |
| **R6: Run Exclusions** | 3 failed SolarWinds runs omitted without audit log in `reports.json` | Failed runs were silently dropped from the final report list. | Include `data_quality_summary.excluded_runs` in `reports.json` documenting failed injection reasons. | Implementation Lead |
| **R6: Deterministic JSON Schema** | Flat unversioned array in `reports.json` | Lack of schema versioning, metadata, and provenance block. | Create versioned `reports.json` schema (v1.0.0) with provenance, exclusions, and metrics. | Implementation Lead |
| **R6: Table Formatting** | LaTeX generator bolds `0.000` FPR and `0.000` CPU% | `comparison_table.py` blindly bolds minimum values even when they represent missing/zero data. | In `comparison_table.py`, do not bold missing/unavailable entries; render unavailable cells as `\text{---}`. | Implementation Lead |
| **R6: README Documentation** | `EXPERIMENTAL_EVALUATION_README.md` is missing | Only older `EVALUATION_README.md` exists. | Author comprehensive `EXPERIMENTAL_EVALUATION_README.md` documenting environment, offline vs live, lifecycles, and reproduction. | Documentation Lead |
| **R6: Protocol Specification** | `EXPERIMENT_PROTOCOL.md` is missing | Independent ground-truth protocol not formalized in repo root. | Author `EXPERIMENT_PROTOCOL.md` formalizing 4-dimension decoupling, hypotheses, and DAG estimands. | Documentation Lead |

---

## 7. Conclusion

Requirements R5 and R6 address foundational scientific validity:
- R5 mandates honest accounting of baseline detectors (preventing the fabrication of zero-baseline recall when telemetry is absent) and resource overhead (preventing the fabrication of zero CPU/memory cost).
- R6 mandates mathematical precision in reporting (Wilson score intervals, median/IQR MTTD, explicit undefined denominators) and complete documentation (`EXPERIMENTAL_EVALUATION_README.md` and `EXPERIMENT_PROTOCOL.md`).

All authoritative code paths, data files, configurations, and mathematical formulas have been identified and verified. The path forward for implementation and documentation is clearly charted.
