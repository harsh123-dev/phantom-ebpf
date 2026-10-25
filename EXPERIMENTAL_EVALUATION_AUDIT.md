# EXPERIMENTAL EVALUATION AUDIT: PHANTOM DATASET FORENSIC AUDIT & INVENTORY

**Document Version**: 1.0.0  
**Audit Date**: 2026-10-24  
**Audit Scope**: Forensic examination of experimental telemetry records across `research/datasets/raw/`, `research/datasets/raw3/`, and `research/evaluation/`  
**Classification**: Research Data Integrity & Provenance Attestation  

---

## 1. Executive Summary & Forensic Audit Mandate

This document establishes the authoritative forensic audit of all raw experimental datasets collected during the development and evaluation of **PHANTOM** (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*).

### 1.1 Integrity Mandate & Core Findings
A rigorous scientific evaluation requires empirical honesty regarding the state of raw experimental records. Past evaluation summaries (notably `research/evaluation/results3/reports.json`) reported perfect detection rates (TPR=1.0, Precision=1.0, F1=1.0), zero overhead (0.0% CPU, 0 MB RAM), and 100% attribution accuracy. A forensic line-by-line inspection of the underlying raw records reveals severe systemic discrepancies:

1. **Total Telemetry Collection Dropout in `raw/` (114 JSON records)**:
   - All 6 indexed evaluation runs in `research/datasets/raw/index.json` (3 attack scenarios, 3 benign controls) and all 107 legacy scenario JSON records contain zero PHANTOM detections (`phantom_detections = []`).
   - The evaluation runner executed attack injections and logged `inject_ok=True`, but the collector API polling client failed to receive or record detector events due to disconnected port-forwarding during the run.
   - **Crucial Rule**: The absence of detections in `raw/` is a **telemetry collection failure**, NOT evidence of negative drift or a successful detector abstention. Treating the 3 benign runs in `raw/` as True Negatives ($TN=3$) is scientifically invalid and strictly prohibited.

2. **Rollout Failures in `raw3/` (3 out of 9 runs)**:
   - In `research/datasets/raw3/`, all 3 repetitions of `solarwinds-001` failed during Phase 2 injection (`inject_ok=False`, `error: "inject() returned False"`), timing out after ~126.7 seconds during `kubectl rollout status`.
   - The scenario runner correctly aborted execution before phases 3–5. These runs represent **failed injection interventions**, not detector false negatives. They cannot evaluate detection sensitivity ($TPR$) or causal attribution.

3. **Severe Upstream Identity Resolution Failure in `raw3/` (3,701 Detections)**:
   - Across the 6 completed attack runs in `raw3/` (3 `xzutils-001`, 3 `dep-confusion-001`), 3,701 drift detections were recorded.
   - **100% (3,701 / 3,701)** have `pod_name = "unknown"`, `container_name = "unknown"`, `sbom_id = null`, and `purl = null`.
   - **99.08% (3,667 / 3,701)** have `container_id = "unknown"`, while only 34 detections (0.92%) resolved a containerd runtime ID.
   - **100% (3,701 / 3,701)** have dummy all-zero image digests (`sha256:0000000000000000000000000000000000000000000000000000000000000000`).
   - Consequently, the claim of `attribution_accuracy: 1.0` in legacy reports was unsubstantiated by raw telemetry; the runtime-to-SBOM mapping layer was completely unlinked in the actual cluster telemetry.

4. **Event Type Divergence from Oracle Specifications**:
   - The scenario oracles define expected runtime anomalies as `unexpected_process_spawn`, `unexpected_network_connect`, and `unexpected_file_access`.
   - In reality, **100% of the 3,701 recorded drift events** in `raw3/` consist solely of container runtime lifecycle operations:
     - `privilege_transition`: 2,555 events (69.04%) with executable `runc:[2:INIT]`
     - `namespace_change`: 1,146 events (30.96%) with executables `runc:[1:CHILD]`, `containerd`, and `runc`.
   - Exactly zero process spawn, network connect, or file access events were recorded.

5. **Complete Absence of Benign Controls in `raw3/` ($N_{\text{benign}} = 0$)**:
   - `research/datasets/raw3/` contains 9 runs, all intended as attack scenarios. It contains **zero benign control runs**.
   - As a mathematical consequence, False Positive Rate ($FPR$), Precision, and F1 score are undefined without external assumptions, because the denominator for false positives ($FP + TN = 0$) is completely empty.

6. **Prometheus Fallback Zeros & Baseline Telemetry Absence**:
   - All Prometheus overhead snapshots in both `raw/` and `raw3/` report `cpu_usage_cores: 0.0`, `memory_rss_mb: 0.0`, and `event_lag_p95_ms: 0.0`. Inspection of `ScenarioRunner.collect_metrics_snapshot` reveals an unhandled connection error that defaults all metrics to `0.0` on query failure. This represents **unmeasured overhead**, not zero resource consumption.
   - Baseline Falco alert logs are empty (`falco_detections = []`) across all 122 raw records. Trivy static scans represent offline image evaluations unlinked to runtime drift windows. Baseline IsolationForest anomaly logs were never captured during runs.

---

## 2. Dataset Architecture & Storage Layout

The repository preserves experimental records under two primary dataset directories in `research/datasets/`:

```
research/datasets/
├── raw/                                     # Initial 6-scenario evaluation run + 107 legacy attempts
│   ├── index.json                           # Registry pointing to 6 evaluation runs
│   ├── 20260823T201630Z_xzutils-001_rep1.json
│   ├── 20260823T201938Z_dep-confusion-001_rep1.json
│   ├── 20260823T202255Z_solarwinds-001_rep1.json
│   ├── 20260823T202826Z_benign-update-001_rep1.json
│   ├── 20260823T203128Z_benign-load-001_rep1.json
│   ├── 20260823T203429Z_benign-restart-001_rep1.json
│   ├── [107 legacy scenario JSON files]     # Pre-index trial runs (20260808, 20260818, 20260823)
│   ├── isoforest_model.pkl                  # Serialized IsolationForest baseline model (2,464,121 bytes)
│   └── trivy/                               # Static image vulnerability scan reports (JSON)
└── raw3/                                    # Hardened multi-repetition attack evaluation
    ├── 20260905T223101Z_xzutils-001_rep1.json
    ├── 20260905T223752Z_xzutils-001_rep2.json
    ├── 20260905T224442Z_xzutils-001_rep3.json
    ├── 20260905T225102Z_dep-confusion-001_rep1.json
    ├── 20260905T225804Z_dep-confusion-001_rep2.json
    ├── 20260905T230506Z_dep-confusion-001_rep3.json
    ├── 20260905T231139Z_solarwinds-001_rep1.json
    ├── 20260905T231616Z_solarwinds-001_rep2.json
    └── 20260905T232054Z_solarwinds-001_rep3.json
```

### 2.1 File Count Verification
- `research/datasets/raw/`:
  - 1 `index.json`
  - 113 scenario execution JSON files (6 indexed runs + 107 legacy runs)
  - Total JSON files = 114
  - 1 binary model pickle (`isoforest_model.pkl`)
  - 1 subdirectory (`trivy/`) containing static scan reports
- `research/datasets/raw3/`:
  - Exactly 9 scenario execution JSON files

---

## 3. Comprehensive Inventory of Raw Records

### 3.1 Inventory Table: `research/datasets/raw/` (Indexed Batch, $N=6$)
Generated: `2026-08-23T20:37:29.544741+00:00`  
Namespace: `phantom-eval`  
Evaluation Profile: 1 repetition per scenario, 60s baseline, 70s attack, 50s post-recovery.

| # | Run ID | File Size (Bytes) | Scenario ID | Target Service | Ground Truth Label ($Y$) | Delivery (`inject_ok`) | PHANTOM Detections | True Positive (`is_tp`) | MTTD (s) | Falco Alerts | Prometheus Overhead Snapshots | Forensic Classification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `20260823T201630Z_xzutils-001_rep1` | 2,731 | `xzutils-001` | `recommendationservice` | 1 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |
| 2 | `20260823T201938Z_dep-confusion-001_rep1` | 2,745 | `dep-confusion-001` | `emailservice` | 1 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |
| 3 | `20260823T202255Z_solarwinds-001_rep1` | 2,757 | `solarwinds-001` | `cartservice` | 1 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |
| 4 | `20260823T202826Z_benign-update-001_rep1` | 2,564 | `benign-update-001` | `recommendationservice` | 0 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |
| 5 | `20260823T203128Z_benign-load-001_rep1` | 2,506 | `benign-load-001` | `recommendationservice` | 0 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |
| 6 | `20260823T203429Z_benign-restart-001_rep1` | 2,500 | `benign-restart-001` | `cartservice` | 0 | `True` | 0 | `False` | `None` | 0 | 3 ($0.0$ fallback) | **Telemetry Collection Dropout** |

### 3.2 Inventory Table: `research/datasets/raw3/` ($N=9$)
Generated: `2026-09-05T22:31:01Z` to `2026-09-05T23:25:00Z`  
Namespace: `phantom-eval`  
Evaluation Profile: 3 attack scenarios × 3 repetitions, 120s baseline, 120s attack window, 120s post-recovery.

| # | Run ID | File Size (Bytes) | Scenario ID | Target Service | Ground Truth Label ($Y$) | Delivery (`inject_ok`) | PHANTOM Detections | True Positive (`is_tp`) | MTTD (s) | Falco Alerts | Prometheus Overhead Snapshots | Forensic Classification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `20260905T223101Z_xzutils-001_rep1` | 411,108 | `xzutils-001` | `recommendationservice` | 1 | `True` | 239 | `True` | 70.33 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 2 | `20260905T223752Z_xzutils-001_rep2` | 1,120,634 | `xzutils-001` | `recommendationservice` | 1 | `True` | 654 | `True` | 6.35 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 3 | `20260905T224442Z_xzutils-001_rep3` | 1,173,468 | `xzutils-001` | `recommendationservice` | 1 | `True` | 684 | `True` | 4.68 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 4 | `20260905T225102Z_dep-confusion-001_rep1` | 1,233,562 | `dep-confusion-001` | `emailservice` | 1 | `True` | 720 | `True` | 2.61 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 5 | `20260905T225804Z_dep-confusion-001_rep2` | 1,172,084 | `dep-confusion-001` | `emailservice` | 1 | `True` | 684 | `True` | 7.88 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 6 | `20260905T230506Z_dep-confusion-001_rep3` | 1,233,504 | `dep-confusion-001` | `emailservice` | 1 | `True` | 720 | `True` | 2.58 | 0 | 3 ($0.0$ fallback) | **Completed Attack Run** |
| 7 | `20260905T231139Z_solarwinds-001_rep1` | 1,765 | `solarwinds-001` | `cartservice` | 1 | `False` | 0 | `False` | `None` | 0 | 1 ($0.0$ fallback) | **Failed Injection (`inject_ok=False`)** |
| 8 | `20260905T231616Z_solarwinds-001_rep2` | 1,766 | `solarwinds-001` | `cartservice` | 1 | `False` | 0 | `False` | `None` | 0 | 1 ($0.0$ fallback) | **Failed Injection (`inject_ok=False`)** |
| 9 | `20260905T232054Z_solarwinds-001_rep3` | 1,766 | `solarwinds-001` | `cartservice` | 1 | `False` | 0 | `False` | `None` | 0 | 1 ($0.0$ fallback) | **Failed Injection (`inject_ok=False`)** |

### 3.3 Inventory of Legacy Unindexed Runs in `raw/` ($N=107$)
In addition to the 6 runs registered in `index.json`, `research/datasets/raw/` contains 107 legacy scenario JSON execution logs. Forensic categorization of these 107 records reveals the iterative development history of the evaluation harness:

1. **Temporal Batches**:
   - `20260808` (August 8, 2026): 44 scenario execution records.
   - `20260818` (August 18, 2026): 21 scenario execution records.
   - `20260823` (August 23, 2026): 42 trial records immediately preceding the final 6 indexed runs.
2. **Scenario Distribution**:
   - `xzutils-001`: 20 runs
   - `dep-confusion-001`: 20 runs
   - `solarwinds-001`: 19 runs
   - `benign-update-001`: 17 runs
   - `benign-load-001`: 16 runs
   - `benign-restart-001`: 15 runs
3. **Execution Delivery Status**:
   - `inject_ok = True`: 87 runs
   - `inject_ok = False`: 20 runs (infrastructure errors including wheel compilation failures, Docker daemon registry errors, `kubectl cp` timeouts, and `kubectl exec` exit status 2)
4. **Detection Outcome Across All 107 Legacy Runs**:
   - **`len(phantom_detections) == 0` in exactly 107 out of 107 files** (100%).
   - **`len(falco_detections) == 0` in exactly 107 out of 107 files** (100%).
   - File sizes range from 1,785 bytes to 2,787 bytes (mean: 2,502.9 bytes), matching the size of the 6 indexed runs.
   - Every file in `raw/` suffered from the same disconnected API collector defect.

---

## 4. Empirical Run Classification Matrix

Every experimental record across the datasets is categorized into one of four mutually exclusive forensic states:

```
                                  [ Experimental Run Record ]
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       │ Telemetry Collector Active & Reachable?       │
                       ▼                                               ▼
                     [ YES ]                                         [ NO ]
                       │                                               │
            ┌──────────┴──────────┐                                    ▼
            │ Injection Succeeded?│                       ┌─────────────────────────┐
            ▼                     ▼                       │  Telemetry Collection   │
         [ YES ]                [ NO ]                    │         Dropout         │
            │                     │                       └─────────────────────────┘
      ┌─────┴─────┐               ▼
      │ Ground    │   ┌───────────────────────┐           • raw/ (6 indexed runs)
      │ Truth?    │   │   Failed Injection    │           • raw/ (107 legacy runs)
      ▼           ▼   │   (inject_ok=False)   │
    [ GT=1 ]   [ GT=0 ]└───────────────────────┘
      │           │   • raw3/ solarwinds rep1-3
      │           ▼
      │     ┌───────────┐
      │     │  Benign   │
      │     │  Control  │
      │     └───────────┘
      │     • raw3/: N=0 (missing!)
      ▼
┌───────────┐
│ Completed │
│  Attack   │
└───────────┘
• raw3/ xzutils rep1-3
• raw3/ dep-confusion rep1-3
```

### 4.1 Classification Summary Table

| Category | Definition | Included Runs | Count | Scientific Status & Usage Restrictions |
|---|---|---|---|---|
| **Completed Attack Run** | Injection succeeded (`inject_ok=True`), full phase lifecycle completed (`phases: [baseline, inject, attack, recover, post_recovery]`), detector telemetry captured. | `raw3/xzutils-001_rep1` to `rep3`<br>`raw3/dep-confusion-001_rep1` to `rep3` | 6 | Valid for True Positive ($TP$) evaluation and Mean Time To Detect ($MTTD$). Ineligible for causal attribution due to upstream identity resolution failure. |
| **Failed Injection** | Injection aborted in Phase 2 (`inject_ok=False`, `error: "inject() returned False"`), phases truncated to `[baseline, inject]`, 0 detections. | `raw3/solarwinds-001_rep1` to `rep3`<br>`raw/` (20 legacy runs with injection errors) | 3 in `raw3/`<br>(20 in `raw/`) | **Must be excluded from detection sensitivity ($TPR$) denominators.** These are execution delivery failures, not detector False Negatives. Ineligible for causal attribution. |
| **Benign Control** | Legitimate workload intervention ($Y_{\text{drift}}=0$), verified monitoring coverage, zero contract violations. | `raw3/`: **0 runs** ($N=0$)<br>`raw/`: 3 intended runs (all dropped) | 0 valid | **Zero valid benign controls exist in `raw3/`.** Evaluating $FPR$, Precision, or F1 on `raw3/` alone is mathematically undefined. |
| **Telemetry Collection Dropout** | Scenario executed, but detector API polling disconnected or unrecorded (`phantom_detections = []`). | `raw/` all 6 indexed runs<br>`raw/` all 107 legacy runs | 113 scenario records | **Prohibited from being treated as True Negatives or False Negatives.** Entire batch invalid for quantitative performance evaluation. |

---

## 5. Telemetry & Field-Level Audit

### 5.1 Event Counts and Latency Distributions (`raw3/`)
Across the 6 completed attack runs in `raw3/`, a total of **3,701 drift detections** were recorded:

| Scenario Run ID | Total Detections | First Detection Timestamp | Injection Timestamp | MTTD ($s$) |
|---|---|---|---|---|
| `20260905T223101Z_xzutils-001_rep1` | 239 | `2026-09-05T22:34:20.520590Z` | `2026-09-05T22:33:10.188621Z` | 70.331969 |
| `20260905T223752Z_xzutils-001_rep2` | 654 | `2026-09-05T22:39:58.749007Z` | `2026-09-05T22:39:52.399232Z` | 6.349775 |
| `20260905T224442Z_xzutils-001_rep3` | 684 | `2026-09-05T22:46:48.887141Z` | `2026-09-05T22:46:44.205604Z` | 4.681537 |
| `20260905T225102Z_dep-confusion-001_rep1` | 720 | `2026-09-05T22:53:05.150495Z` | `2026-09-05T22:53:02.543252Z` | 2.607243 |
| `20260905T225804Z_dep-confusion-001_rep2` | 684 | `2026-09-05T23:00:09.972301Z` | `2026-09-05T23:00:02.096391Z` | 7.875910 |
| `20260905T230506Z_dep-confusion-001_rep3` | 720 | `2026-09-05T23:07:09.118944Z` | `2026-09-05T23:07:06.540697Z` | 2.578247 |
| **Total / Summary** | **3,701** | — | — | **Mean: 15.74s, Median: 5.52s, IQR: 4.88s** |

### 5.2 Event Type Distribution & Divergence from Oracle Specifications
The oracle manifest files in `research/evaluation/oracles/` (`xzutils-001.yaml` and `dep-confusion-001.yaml`) specify the expected behavioral anomalies resulting from the payload execution:
- `unexpected_process_spawn` (e.g. executing `/tmp/.phantom_beacon.py` or `python -m acme_email_templates.beacon`)
- `unexpected_network_connect` (e.g. TCP connect to `phantom-sink:8443` or `phantom-sink:4445`)
- `unexpected_file_access` (e.g. touching `/tmp/.phantom_beacon.py`)

**Forensic Audit Reality**:
The actual 3,701 drift records in `raw3/` contain:
- `privilege_transition`: **2,555 events** (69.04%)
- `namespace_change`: **1,146 events** (30.96%)
- `unexpected_process_spawn`: **0 events** (0.00%)
- `unexpected_network_connect`: **0 events** (0.00%)
- `unexpected_file_access`: **0 events** (0.00%)

**Root Cause**:
The kernel-level eBPF probes triggered primarily on container runtime setup actions (`runc` setting up namespaces and dropping/escalating capabilities during pod lifecycle hooks) rather than application-layer execution inside the container. 
Inspection of the executable comms confirms this:
- `runc:[2:INIT]`: 2,555 events (69.04%)
- `runc:[1:CHILD]`: 936 events (25.29%)
- `containerd`: 188 events (5.08%)
- `runc`: 22 events (0.59%)

### 5.3 Upstream Identity Resolution Failure Analysis
To link an eBPF kernel event to a software bill of materials (SBOM), the agent must correlate the kernel thread group ID (`tgid`) to a container cgroup, query the Kubernetes CRI/API for the pod name, container name, and image digest, and cross-reference the image SBOM for the package URL (`purl`).

Forensic analysis of all 3,701 drift detection records in `raw3/` reveals a complete collapse of this identity pipeline:

```
[ eBPF Kernel Probe: tgid / pid ]
                 │
                 ▼  (Metadata Lookup Failed in Agent DaemonSet)
        ┌────────────────────────────────────────────────────────┐
        │ Field                  Value across all 3,701 records │
        ├────────────────────────────────────────────────────────┤
        │ pod_name               "unknown"            (100.00%) │
        │ container_name         "unknown"            (100.00%) │
        │ container_id           "unknown"             (99.08%) │
        │ image_digest           sha256:000... (zeros) (100.00%) │
        │ sbom_id                null                 (100.00%) │
        │ purl                   null                 (100.00%) │
        │ binding_confidence     null                 (100.00%) │
        │ identity_status        "ambiguous"           (99.08%) │
        │                        "missing"             (0.92%)  │
        └────────────────────────────────────────────────────────┘
```

#### Detailed Breakdown:
- **`pod_name`**: Exactly 3,701 / 3,701 records contain `"unknown"` (100.00% missing).
- **`container_name`**: Exactly 3,701 / 3,701 records contain `"unknown"` (100.00% missing).
- **`container_id`**: 3,667 records contain `"unknown"` (99.08%). Only 34 records in `xzutils-001_rep3` resolved to `containerd://eccf8ee01107e5c5dd5fc94d05bddbd8c3b5404672780fa96c33d58ad23600bb`. Even in these 34 records, `pod_name` remained `"unknown"`, and `identity_status` was marked `"missing"`.
- **`image_digest`**: Exactly 3,701 / 3,701 records contain the placeholder string `sha256:0000000000000000000000000000000000000000000000000000000000000000` (100.00% dummy).
- **`sbom_id` and `purl`**: Exactly 3,701 / 3,701 records are `null` (100.00% unmapped).
- **`binding_confidence` and `binding_status`**: Exactly 3,701 / 3,701 records are `null`.
- **`identity_status`**: 3,667 records are `"ambiguous"` (99.08%), and 34 records are `"missing"` (0.92%).

**Implication for Downstream Causal Attribution**:
Because no detection event is bound to a concrete SBOM component or package URL (`purl`), component attribution ($T_{\text{purl}} \to Y_{\text{drift}}$) cannot be empirically identified from these raw records. The causal engine's Preflight Gate G2 (`gate_component_mapping_quality`) must block any attempt to attribute drift on this dataset with `AMBIGUOUS_COMPONENT`.

### 5.4 Kernel Ring Buffer Integrity vs. Metadata Lookup
- **`event_loss_observed`**: `false` across all 3,701 records.
- **`agent_sequence`**: Monotonically increments per node without gaps.
- **Architectures**: 100% `x86_64`.
- **Nodes**: Telemetry is distributed across two cluster worker nodes:
  - `ip-172-31-5-170.ap-south-1.compute.internal`: 1,877 detections (50.72%)
  - `ip-172-31-22-173.ap-south-1.compute.internal`: 1,824 detections (49.28%)
- **Findings**: The eBPF kernel perf ring-buffer operated correctly without packet drops. The failure was strictly an **upstream userspace cgroup metadata resolution failure** inside the node daemonset.

---

## 6. Baseline Detector & Resource-Overhead Telemetry Audit

### 6.1 Prometheus Resource-Overhead Query Fallback Zeros
In `results3/reports.json`, PHANTOM was reported to impose:
- `cpu_overhead_pct`: `0.0`
- `memory_overhead_mb`: `0.0`
- `event_lag_p95_ms`: `0.0`

**Forensic Audit of Implementation**:
Inspecting `research/evaluation/scenarios/scenario_runner.py` (lines 605–620):
```python
def collect_metrics_snapshot(self, phase: str) -> MetricsSnapshot:
    try:
        response = httpx.get(self.prometheus_url, params={"query": query}, timeout=5.0)
        # Parse PromQL results...
    except Exception as exc:
        logger.warning(f"Failed to query Prometheus: {exc}")
        return MetricsSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            cpu_usage_cores=0.0,
            memory_rss_mb=0.0,
            event_lag_p95_ms=0.0,
            phase=phase,
        )
```
During the execution of both `raw/` and `raw3/`, the evaluation cluster lacked an active port-forward to Prometheus on port 9090. The `try...except` block caught the connection error on every single snapshot, returning artificial `0.0` values.
**Requirement**: Evaluators must record overhead metrics as `null` / `"unmeasured"`, NEVER as `0.0`. Claiming 0.0% overhead is a scientific fabrication.

### 6.2 Falco 0.44.1 Baseline Telemetry Absence
- Across all 15 indexed scenario runs (`raw/` and `raw3/`), `falco_detections` is an empty list (`[]`).
- `research/evaluation/scenarios/scenario_runner.py` tails `/var/log/falco/events.jsonl`.
- In the evaluation cluster, either Falco was not scheduled on the workload nodes or the log file was unmounted.
- **Requirement**: Baseline detectors with missing telemetry must be reported as `status: "telemetry_unavailable"` and their metrics set to `None` / `\text{---}`. Reporting $TPR = 0.0$ for Falco conflates unmeasured baseline collection with baseline detector failure.

### 6.3 Trivy 0.70.0 Static Analysis Demarcation
- Directory `research/datasets/raw/trivy/` contains static vulnerability scans of container images.
- Trivy evaluates static package lists against CVE databases at build/deployment time. It does NOT monitor runtime syscalls or detect behavioral drift.
- **Requirement**: Static scanning must be explicitly demarcated from runtime drift detection. Reporting Trivy as an inferior runtime detector with $TPR=0.0$ on dynamic drift is a category error.

### 6.4 Isolation Forest Syscall Baseline Telemetry
- Model file `research/datasets/raw/isoforest_model.pkl` (2,464,121 bytes) exists.
- However, no per-window anomaly score logs were collected or linked to individual scenario runs in `raw/` or `raw3/`.
- **Requirement**: Isolation Forest baseline must be reported as unmeasured/unavailable for these runs.

---

## 7. Historical Evaluation Report Critique (`reports.json`)

A critical comparison between the raw dataset truth and the historical report (`research/evaluation/results3/reports.json`) highlights the issues that this audit rectifies:

| Dimension | Claimed in `results3/reports.json` | Forensic Reality in Raw Datasets | Methodological Defect Fixed |
|---|---|---|---|
| **Sample Size** | $N=6$ attack runs, $N=0$ benign | 9 total runs in `raw3/`: 6 completed attacks, 3 failed injections, 0 benign | Silently dropped the 3 failed `solarwinds-001` runs without documenting rollouts. |
| **Benign Controls** | $n_{\text{benign}} = 0$ | $n_{\text{benign}} = 0$ in `raw3/`; 3 in `raw/` (all dropouts) | Zero valid benign controls exist. |
| **False Positive Rate** | $\text{FPR} = 0.0$ | $\frac{FP}{FP + TN} = \frac{0}{0}$ (Undefined) | Division by zero masked as 0.0. Must return `None`. |
| **Precision** | $\text{Precision} = 1.0$ | $\frac{TP}{TP + FP} = \frac{6}{6 + \text{undefined}}$ | Precision is mathematically undefined without negative control evaluation. |
| **F1 Score** | $F_1 = 1.0$ | Undefined | Harmonic mean of precision and recall is undefined when precision is undefined. |
| **Overhead** | CPU 0.0%, RSS 0.0 MB, Lag 0.0 ms | Prometheus connection failed; all snapshots fell back to 0.0 | Connection timeout converted to zero overhead. Must report `unmeasured`. |
| **Attribution Accuracy** | $\text{Attribution} = 1.0$ | 100% of detections have `purl = null` and `sbom_id = null` | Claim was ungrounded in raw telemetry. Must report `ambiguous` / abstain. |
| **Baseline Detectors** | Falco, Trivy, IsoForest: $\text{TPR} = 0.0$ | Telemetry logs missing/uncollected for all baselines | Missing baseline telemetry conflated with detector failure. Must report `NR`. |
| **Confidence Intervals** | None reported | TPR should report Standard Wilson Score Interval: $[0.6096, 1.0000]$ | Failure to report statistical uncertainty for small $N=6$. |

---

## 8. Audit Conclusions & Mandates for Downstream Pipelines

### 8.1 Invalidation Conditions
Any downstream claim, evaluation report, or table that violates the following rules is scientifically invalid:
1. **Rule 1 (No Inferred True Negatives)**: No scenario record from `research/datasets/raw/` may be counted as a True Negative ($TN$). All 114 records in `raw/` are telemetry collection dropouts.
2. **Rule 2 (Failed Injection Exclusion)**: The 3 repetitions of `solarwinds-001` in `raw3/` must be categorized as `failed_injection` and excluded from detection sensitivity ($TPR$) and attribution denominators. They must be explicitly listed in the report exclusions list with error `inject() returned False`.
3. **Rule 3 (Undefined Metric Handling)**: When $N_{\text{benign}} = 0$, $FPR$, Precision, and F1 must evaluate to `None` / `null` / `\text{---}`, not default to 0.0 or 1.0.
4. **Rule 4 (Unmeasured Overhead)**: Resource overhead must report as `null` / `"unmeasured"`. Emitting 0.0% CPU or 0.0 MB RAM is prohibited.
5. **Rule 5 (Baseline Absence Demarcation)**: Baseline detectors lacking verified event logs must be marked as `telemetry_unavailable` / `NR`, not penalized with $TPR=0.0$.
6. **Rule 6 (Causal Gate G1 Preservation)**: Gate G1 ($N \ge 10$) must cleanly block estimation on existing datasets with `insufficient_evidence: too_few_observations`. Synthetic window slicing to circumvent G1 is strictly forbidden.
7. **Rule 7 (Component Identity Abstention)**: Because 100% of drift detections in `raw3/` have `purl = null`, Gate G2 must block component attribution with `ambiguous_component`.

---
*Attested and Certified by Worker M1 (Data Audit & Experimental Protocol Track).*
