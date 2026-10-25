# Comprehensive Investigation & Survey Report: R1 & R2
**Author**: `explorer_survey_1` (`teamwork_preview_spec_miner`)  
**Date**: 2026-10-24  
**Target Scope**: R1 (Real Experimental Data Audit & Inventory) & R2 (Independent Ground-Truth & Experimental Protocol)  
**Parent Orchestrator**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Working Directory**: `d:\project-1\.agents\teamwork\explorer_survey_1`

---

## 1. Executive Summary

This survey provides the authoritative empirical audit of all existing raw experimental records across `research/datasets/raw/` (114 files, 6 indexed runs), `research/datasets/raw3/` (9 runs), and `research/evaluation/`. It establishes the theoretical and empirical foundations required to author `EXPERIMENTAL_EVALUATION_AUDIT.md` (R1) and `EXPERIMENT_PROTOCOL.md` (R2).

### Key Empirical Findings:
1. **Raw Dataset (`research/datasets/raw/`)**: All 6 indexed runs (3 attack, 3 benign) suffer from **100% telemetry collection dropout** (`phantom_detections = []`). While attack injections reported `inject_ok=True`, no detector telemetry was recorded because the API polling / port-forward was disconnected during evaluation. Treating these empty lists as true negatives or successful abstentions is scientifically invalid.
2. **Raw3 Dataset (`research/datasets/raw3/`)**:
   - **Failed Injections**: All 3 repetitions of `solarwinds-001` failed during rollout (`inject_ok=False`, `error: "inject() returned False"`), aborting after phase 2 with 0 detections.
   - **Completed Attack Runs**: The remaining 6 runs (3 `xzutils-001`, 3 `dep-confusion-001`) yielded 3,701 drift detections with mean MTTD of 15.74s (median 5.52s).
   - **Severe Upstream Identity Dropout**: Across all 3,701 recorded drift events in `raw3/`, `pod_name` is `"unknown"` (100%), `container_id` is `"unknown"` (99.08%, 3,667/3,701), `image_digest` is all zeros (`sha256:000...`, 100%), `sbom_id` is `None` (100%), `purl` is `None` (100%), and `identity_status` is `"ambiguous"` (99.08%) or `"missing"` (0.92%).
   - **Event Type Divergence**: The oracle manifests specify expected behavioral changes as `unexpected_process_spawn`, `unexpected_network_connect`, and `unexpected_file_access`. However, 100% of the recorded drift events in `raw3/` are strictly `namespace_change` (1,146 events) and `privilege_transition` (2,555 events) triggered by container runtime initialization (`runc:[2:INIT]`).
   - **Absence of Controls**: `raw3/` contains **zero benign control runs** ($N=0$), making false positive rate ($FPR$), precision, and F1 mathematically undefined without prior assumptions.
3. **Baseline Detector Telemetry**: Falco alert logs are empty across all runs (`falco_detections = []`), Trivy SBOM static scans are not linked to execution windows, and IsolationForest anomaly outputs are absent from run records. Reporting 0.0 for baseline TPR without verified telemetry conflates baseline detector failure with unmeasured baseline collection.
4. **Prometheus Overhead Telemetry**: CPU cores, memory RSS, and collection lag are recorded as `0.0` in all snapshots due to PromQL fallback on query/connection failure, concealing genuine agent resource overhead.
5. **Causal Estimation Decoupling**: In previous evaluations, `inject_ok`, runtime network connection, contract drift, and detector alerts were conflated. Furthermore, within-run temporal windows were improperly treated as independent units. Preflight Gate G1 ($N \ge 10$) must be enforced strictly as a technical sanity guard, cleanly abstaining on existing datasets (`too_few_observations`).

---

## 2. Comprehensive Raw Dataset Inventory (R1)

### 2.1 Inventory Table: Raw Dataset (`research/datasets/raw/`)
Generated at `2026-08-23T20:37:29Z` in namespace `phantom-eval`. Evaluated with 1 repetition per scenario.

| # | Run ID | File Size (Bytes) | Scenario ID | Attack Family | Rep | GT Label | `inject_ok` | True Pos (`is_tp`) | MTTD (s) | Error String | Detections (Phantom) | Falco Alerts | Prometheus Snaps | Empirical Classification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `20260823T201630Z_xzutils-001_rep1` | 2,731 | `xzutils-001` | `supply_chain_backdoor` | 1 | 1 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Attack Run — Telemetry Dropout (Disconnected Collector) |
| 2 | `20260823T201938Z_dep-confusion-001_rep1` | 2,745 | `dep-confusion-001` | `dependency_confusion` | 1 | 1 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Attack Run — Telemetry Dropout (Disconnected Collector) |
| 3 | `20260823T202255Z_solarwinds-001_rep1` | 2,757 | `solarwinds-001` | `build_pipeline_tampering` | 1 | 1 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Attack Run — Telemetry Dropout (Disconnected Collector) |
| 4 | `20260823T202826Z_benign-update-001_rep1` | 2,564 | `benign-update-001` | `benign_update` | 1 | 0 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Benign Control — Telemetry Dropout (Unverified Coverage) |
| 5 | `20260823T203128Z_benign-load-001_rep1` | 2,506 | `benign-load-001` | `high_load` | 1 | 0 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Benign Control — Telemetry Dropout (Unverified Coverage) |
| 6 | `20260823T203429Z_benign-restart-001_rep1` | 2,500 | `benign-restart-001` | `pod_restart` | 1 | 0 | `True` | `False` | `None` | `""` | 0 | 0 | 3 | Benign Control — Telemetry Dropout (Unverified Coverage) |

*Historical Archive Context*: Besides the 6 indexed runs above, `research/datasets/raw/` contains 108 unindexed historical scenario JSON files across two prior batches:
- `20260808`: 44 files (attempts with varying phase durations and repetitions).
- `20260818`: 21 files.
- `20260823`: 42 additional files preceding the final indexed batch.
*Audited Fact*: Across **all 114 JSON files** in `research/datasets/raw/`, `len(phantom_detections) == 0`. Every file in `raw/` represents a telemetry collection dropout.

---

### 2.2 Inventory Table: Raw3 Dataset (`research/datasets/raw3/`)
Generated at `2026-09-05T22:31:01Z` to `2026-09-05T23:25:00Z` in namespace `phantom-eval`. Intended as 3 attacks × 3 repetitions.

| # | Run ID | File Size (Bytes) | Scenario ID | Attack Family | Rep | GT Label | `inject_ok` | True Pos (`is_tp`) | MTTD (s) | Error String | Detections (Phantom) | Falco Alerts | Prometheus Snaps | Empirical Classification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `20260905T223101Z_xzutils-001_rep1` | 411,108 | `xzutils-001` | `supply_chain_backdoor` | 1 | 1 | `True` | `True` | 70.33 | `""` | 239 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 2 | `20260905T223752Z_xzutils-001_rep2` | 1,120,634 | `xzutils-001` | `supply_chain_backdoor` | 2 | 1 | `True` | `True` | 6.35 | `""` | 654 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 3 | `20260905T224442Z_xzutils-001_rep3` | 1,173,468 | `xzutils-001` | `supply_chain_backdoor` | 3 | 1 | `True` | `True` | 4.68 | `""` | 684 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 4 | `20260905T225102Z_dep-confusion-001_rep1` | 1,233,562 | `dep-confusion-001` | `dependency_confusion` | 1 | 1 | `True` | `True` | 2.61 | `""` | 720 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 5 | `20260905T225804Z_dep-confusion-001_rep2` | 1,172,084 | `dep-confusion-001` | `dependency_confusion` | 2 | 1 | `True` | `True` | 7.88 | `""` | 684 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 6 | `20260905T230506Z_dep-confusion-001_rep3` | 1,233,504 | `dep-confusion-001` | `dependency_confusion` | 3 | 1 | `True` | `True` | 2.58 | `""` | 720 | 0 | 3 | Completed Attack (Alerts Captured, Identity Ambiguous) |
| 7 | `20260905T231139Z_solarwinds-001_rep1` | 1,765 | `solarwinds-001` | `build_pipeline_tampering` | 1 | 1 | `False` | `False` | `None` | `inject() returned False` | 0 | 0 | 1 | Failed Injection (`inject_ok=False`, Rollout Failure) |
| 8 | `20260905T231616Z_solarwinds-001_rep2` | 1,766 | `solarwinds-001` | `build_pipeline_tampering` | 2 | 1 | `False` | `False` | `None` | `inject() returned False` | 0 | 0 | 1 | Failed Injection (`inject_ok=False`, Rollout Failure) |
| 9 | `20260905T232054Z_solarwinds-001_rep3` | 1,766 | `solarwinds-001` | `build_pipeline_tampering` | 3 | 1 | `False` | `False` | `None` | `inject() returned False` | 0 | 0 | 1 | Failed Injection (`inject_ok=False`, Rollout Failure) |

---

### 2.3 Detailed Telemetry & Field Audit

#### A. Event Counts and Type Distribution (`raw3/` Completed Runs)
Across the 6 completed attack runs in `raw3/`, a total of **3,701 drift detections** were recorded:
- **`privilege_transition`**: 2,555 events (69.04%)
- **`namespace_change`**: 1,146 events (30.96%)
- **Oracle Expected Events**:
  - `unexpected_process_spawn`: **0 events** recorded.
  - `unexpected_network_connect`: **0 events** recorded.
  - `unexpected_file_access`: **0 events** recorded.

#### B. Identity Resolution & SBOM Mapping Quality
Analysis of the JSON records for all 3,701 drift events demonstrates severe identity extraction dropouts in the eBPF agent / API gateway:
- `pod_name`: `"unknown"` in 3,701 / 3,701 events (100% missing).
- `container_name`: `"unknown"` in 3,701 / 3,701 events (100% missing).
- `container_id`: `"unknown"` in 3,667 events (99.08%). Only 34 events in `xzutils-001_rep3` resolved to `containerd://eccf8ee01107...`.
- `image_digest`: `sha256:0000000000000000000000000000000000000000000000000000000000000000` in 3,701 / 3,701 events (100% dummy/zero hash).
- `sbom_id`: `null` in 3,701 / 3,701 events (100% unmapped).
- `purl`: `null` in 3,701 / 3,701 events (100% unmapped).
- `identity_status`: `"ambiguous"` in 3,667 events (99.08%), `"missing"` in 34 events (0.92%).
- `violations`: Contained raw JSON string specifying:
  `[{"expected": null, "observed": "runc:[2:INIT]", "severity": "high", "confidence": 0.99, "violation_type": "unexpected_process_relation"}]`.

#### C. Telemetry Dropouts & Loss Flags
- `event_loss_observed`: `false` in all 3,701 detection records. The eBPF perf ring-buffer did not drop events; rather, the container metadata lookup (cgroup-to-pod association) failed in the agent daemonset, causing all events to fallback to dummy container identifiers.
- `agent_sequence`: Monotonically incremented per node.

#### D. Overhead Telemetry (Prometheus)
- In both `raw/` and `raw3/`, `metrics_snapshots` recorded:
  - `cpu_usage_cores`: `0.0`
  - `memory_rss_mb`: `0.0`
  - `event_lag_p95_ms`: `0.0`
- *Root Cause Analysis*: `ScenarioRunner.collect_metrics_snapshot` wraps `httpx.get(prometheus_url)` in a `try...except` block that returns `0.0` on connection failure or empty PromQL response. In the evaluation cluster, Prometheus was either not deployed or port-forwarding on port 9090 was not active. This must be recorded as **unmeasured / unavailable**, NOT zero overhead.

#### E. Baseline Detector Telemetry
- `falco_detections`: `[]` in all 15 runs. Falco was either not deployed in the namespace or `/var/log/falco/events.jsonl` was unpopulated.
- `trivy`: Directory `research/datasets/raw/trivy/` exists, containing static scan results, but these represent offline static image scans, not runtime drift detection.
- `isolation_forest`: Model files `isoforest_model.pkl` (~2.35 MB) exist in both `raw/` and `raw3/`, but no baseline anomaly logs were collected during scenario runs.

#### F. Infrastructure Context
- Nodes observed: `ip-172-31-5-170.ap-south-1.compute.internal` and `ip-172-31-22-173.ap-south-1.compute.internal`.
- Kernel timestamps: 64-bit nanosecond monotonic clock (`kernel_timestamp_ns` ~41,740,129,438,431 ns, representing ~11.59 hours of node uptime).
- Target cluster architecture: AWS EKS v1.36.2 (`eks.6` platform), Linux 64-bit x86_64, containerd runtime.

---

## 3. Ground Truth, Contracts & Oracle Audit (R2)

### 3.1 Existing Ground Truth Artifacts
The ground truth manifests are stored under `research/evaluation/oracles/`:
1. `xzutils-001.yaml`: Backdoor in `recommendationservice`, replacing `pkg:pypi/lzmaffi@1.0.0` with `pkg:pypi/lzmaffi@1.0.1-phantom-backdoor`. Sink endpoint `phantom-sink:8443`.
2. `dep-confusion-001.yaml`: Dependency confusion in `emailservice`, injecting `pkg:pypi/acme-email-templates@9.9.9`. Sink endpoint `phantom-sink:4445`.
3. `solarwinds-001.yaml`: Build tampering in `cartservice`, injecting undeclared worker `pkg:generic/phantom-background-worker@0.1.0`. Sink endpoint `phantom-sink:4446`.
4. `benign-update-001.yaml`: Legitimate patch update `pkg:pypi/lzmaffi@1.0.1`. GT=0.
5. `benign-load-001.yaml`: K6 load burst on `recommendationservice`. GT=0.
6. `benign-restart-001.yaml`: Pod deletion and rescheduling for `cartservice`. GT=0.

### 3.2 Decoupling the Four Dimensions

To achieve scientific defensibility, experimental protocols must never treat detection as evidence of drift or injection as proof of runtime violation. The evaluation protocol must explicitly decouple four distinct dimensions:

```
[ Dimension 1: Delivery ]
        T_inject (inject_ok == True)
                    │
                    ▼
[ Dimension 2: Physical Runtime Execution ]
        B_verified (Sink receipts, /proc inspection)
                    │
                    ▼
[ Dimension 3: Normative Evaluation vs. Contract ]
        Y_drift (Runtime behavior ∉ Declared Signed Contract)
                    │
                    ▼
[ Dimension 4: Detector Performance ]
        Y_hat_phantom (PHANTOM alert fired within detection window)
```

#### Detailed Definitions:

1. **Injection Delivery Success ($T_{\text{inject}} \in \{0, 1\}$ or $\text{inject\_ok}$)**:
   - Evaluates whether the injection mechanism completed without error.
   - For `solarwinds-001` in `raw3/`, `inject_ok = False` due to deployment rollout timeout.
   - *Rule*: When $\text{inject\_ok} = \text{False}$, the run is classified as **Failed Injection**. It cannot evaluate detection performance ($\hat{Y}$) or causal attribution, because the intervention was never delivered.

2. **Independently Verified Behavior ($B_{\text{verified}} \in \{0, 1, \text{unknown}\}$)**:
   - Physical evidence that the injected payload actually executed in the workload (e.g. HTTP POST receipt at `phantom-sink:8443`, or active process in `/proc/*/cmdline`).
   - *Audit finding*: In `raw/` and `raw3/`, sink receipt logs were **not captured** or persisted. Independent runtime verification relies solely on best-effort `verify_injection()` return codes.
   - *Rule*: When physical execution cannot be verified from independent evidence, $B_{\text{verified}}$ remains **`unknown`**.

3. **Verified Contract Drift ($Y_{\text{drift}} \in \{0, 1, \text{unknown}\}$)**:
   - **Critical Scientific Decoupling**: A runtime network connection or process spawn is merely runtime activity; it is NOT automatically contract drift!
   - Runtime activity constitutes drift ($Y_{\text{drift}} = 1$) **if and only if** that specific activity violates the cryptographically signed container behavioral contract.
   - If an activity is permitted by the signed contract, $Y_{\text{drift}} = 0$, even if an attack was attempted.
   - *Rule*: If independent verification or contract coverage is insufficient to verify violation, $Y_{\text{drift}}$ must remain **`unknown`**. Imputing $Y_{\text{drift}} = 0$ or $Y_{\text{drift}} = 1$ without independent oracle evidence is strictly prohibited.

4. **PHANTOM Detection Alert ($\hat{Y}_{\text{phantom}} \in \{0, 1\}$)**:
   - The empirical output of the PHANTOM detector during the evaluation window.
   - $\hat{Y}_{\text{phantom}} = 1$ if at least one qualified drift alert occurs within `[t_injection, t_injection + detection_window_s]`.
   - *Rule*: Detector output must never be used to label ground truth. A True Positive requires BOTH verified drift ($Y_{\text{drift}} = 1$) AND detector alert ($\hat{Y}_{\text{phantom}} = 1$).

---

## 4. Formal Causal Protocol & Anti-Mediator DAG Specification (R2)

### 4.1 Independent Experimental Units
- **Strict Rule**: **ONE RUN = ONE EXPERIMENTAL UNIT** ($N=1$ per scenario repetition).
- Splitting a single run into multiple within-run temporal windows to inflate sample size is strictly prohibited for causal inference.
- Within-run temporal windows ($W_1, W_2, \dots$) are valid **only** as diagnostic timeline markers (e.g., measuring latency from injection to detection, MTTD). They are longitudinal, serially correlated observations of a single experimental unit, not independent cross-sectional units.

### 4.2 Formal Causal Estimands

We distinguish two separate causal queries with fundamentally different DAG structures:

#### Estimand 1: Experiment-Level Injection Intervention Effect
- **Query**: What is the average causal effect of the external attack injection intervention on container contract drift?
  $$\tau_{\text{inject}} = \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 1)] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 0)]$$
- **Structural DAG**:
  $$X_{\text{pre}} \longrightarrow T_{\text{inject}} \longrightarrow B_{\text{behavior}} \longrightarrow Y_{\text{drift}} \longrightarrow \hat{Y}_{\text{phantom}}$$
- **Anti-Mediator Conditioning Rule**:
  - $B_{\text{behavior}}$ (eBPF events, sink receipts) is a **post-treatment mediator**.
  - Conditioning on $B_{\text{behavior}}$ blocks the causal mechanism from $T_{\text{inject}}$ to $Y_{\text{drift}}$ and induces collider stratification bias (M-bias) if unobserved node-level noise exists.
  - Confounders $X_{\text{pre}}$ must be strictly pre-treatment (e.g. cluster node hardware, baseline workload RPS, namespace security policies).

#### Estimand 2: Component Attribution Effect
- **Query**: Did the substitution of a specific software component $T_{\text{purl}}$ cause the observed runtime contract drift?
  $$\tau_{\text{purl}} = \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{backdoor})] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{clean})]$$
- **Structural DAG**:
  $$X_{\text{workload}} \longrightarrow T_{\text{purl}} \longrightarrow B_{\text{process}} \longrightarrow Y_{\text{drift}}$$
- **Anti-Mediator Conditioning Rule**:
  - Post-treatment execution artifacts (such as intermediate spawned threads, child cgroups, or dynamic syscall sequences) are mediators.
  - Preflight checks must enforce that no post-treatment variable is included in the adjustment set $Z$.

### 4.3 Preflight Gate G1 ($N \ge 10$) Software Sanity Guard

1. **Role of Gate G1**:
   - $N \ge 10$ is strictly a **technical software sanity guard** to prevent singular or rank-deficient regression matrices in OLS/GLM estimators and avoid division by zero in matching estimators.
   - Passing $N \ge 10$ is **NOT** proof of statistical power, sample adequacy, or causal identifiability.
2. **Empirical Grounding on Current Datasets**:
   - `research/datasets/raw/`: $N=6$ (3 attack, 3 benign, all telemetry dropped).
   - `research/datasets/raw3/`: $N=9$ (6 completed attacks, 3 failed injections, 0 controls).
   - Both datasets strictly fail Gate G1 ($N < 10$).
3. **Mandatory Abstention**:
   - The causal engine must cleanly abstain with:
     `status = "insufficient_evidence", reason = "too_few_observations"`
   - Bypassing G1 by synthetic window expansion or unverified imputation is strictly forbidden.

---

## 5. Specification Mining Tables

### 5.1 Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|---|---|---|---|---|---|---|
| 1 | Dataset Storage | Raw Result Serialization | Per-run JSON schema containing phases, detections, metrics snapshots, and oracle labels | Scenario execution parameters | `<run_id>.json` | Writes `"error"` field if aborted | `scenarios/scenario_runner.py` |
| 2 | Dataset Index | Index Manifest | Central registry of completed scenario runs for evaluation batch | Batch execution results | `index.json` containing `results: list[str]` | Missing runs omitted | `datasets/raw/index.json` |
| 3 | Telemetry Collection | PHANTOM API Polling | Polling `/api/v1/drift-events?since=<iso_ts>` every 5s | API URL, Bearer token, start timestamp | List of drift-event dicts | Returns `[]` on HTTP error | `scenarios/scenario_runner.py:553` |
| 4 | Telemetry Collection | Retroactive API Fill | Post-hoc script to populate drift events from database when port-forward failed | Raw JSON directory, API endpoint | Updates JSON files in-place | Skips files without injection TS | `evaluation/retroactive_fill.py` |
| 5 | Baseline Detectors | Falco Collector | Tail parsing of Falco alert log `/var/log/falco/events.jsonl` | File path, lower-bound datetime | List of parsed Falco alert dicts | Logs warning, returns `[]` | `scenarios/scenario_runner.py:227` |
| 6 | Overhead Profiling | Prometheus Querying | Queries container CPU, RSS, event lag latency via PromQL | Prometheus query endpoint, PromQL strings | `MetricsSnapshot` (cores, MB, ms) | Returns `0.0` on connection failure | `scenarios/scenario_runner.py:605` |
| 7 | Metric Evaluation | First-Within-Window Matching | Earliest detection within `detection_window_s` counts as single TP; subsequent alerts ignored | Detection list, injection timestamp | `is_true_positive: bool`, `mttd_s: float` | `mttd_s = None` if no detection | `scenarios/scenario_runner.py:458` |
| 8 | Metric Evaluation | Run-Level Evaluator | Computes TP/FP/FN/TN, TPR, FPR, Precision, Recall, F1, MTTD (mean, p50, p95), FP/hr | List of `ScenarioResult` | `EvaluationReport` | Returns `0.0` on zero denominator | `metrics/evaluator.py:238` |
| 9 | Statistical Uncertainty | Wilson Score Interval | Standard Wilson score interval without continuity correction | Success count $k$, Total count $n$, $\alpha=0.05$ | Interval $[p_{\text{lower}}, p_{\text{upper}}]$ | Returns $[0, 0]$ or raises on invalid $n$ | `ORIGINAL_REQUEST.md:35` |
| 10 | Metric Evaluation | Attribution Accuracy | Compares top attributed PURL against oracle PURL (1.0 exact, 0.5 top-3 in chain, 0.0 otherwise) | `top_attributed_purl`, oracle PURL | Attribution accuracy score | Returns `None` if data missing | `metrics/evaluator.py:476` |
| 11 | Causal Validation | Preflight Gate G1 | Minimum observation count technical guard ($N \ge 10$) | Observation count $N$, threshold | `GateVerdict(PASS/BLOCK)` | Suggested status `insufficient_evidence` | `causal_validation.py:126` |
| 12 | Causal Validation | Preflight Gate G2 | Checks component mapping status quality (blocks UNRESOLVED/INVALID) | Mapping status list | `GateVerdict(PASS/BLOCK)` | Suggested status `ambiguous_component` | `causal_validation.py:145` |
| 13 | Causal Validation | Preflight Gate G3/G4 | Verifies temporal precedence ($T \prec Y$ and $X \prec T$) | Variable timestamp bounds | `GateVerdict(PASS/BLOCK)` | Suggested status `invalid_graph` | `causal_validation.py:202` |
| 14 | Causal Engine | Positivity Check | Verifies treatment variation across all covariate strata | Dataframe, treatment, covariates | Boolean overlap check | Raises `PositivityFailureError` | `domain/causal.py:84` |
| 15 | Attack Injection | Idempotent Workload Injection | Injects backdoor, dependency confusion, or worker into pod via kubectl cp/exec | Target namespace, pod name | Boolean success (`inject_ok`) | Captures stderr, returns `False` | `attacks/base_attack.py:192` |
| 16 | Attack Recovery | Workload Rollback | Restores clean component or undoes deployment rollout | Target namespace, pod name | Boolean success (`recover_ok`) | Logs error, returns `False` | `attacks/base_attack.py:219` |

---

### 5.2 Edge Cases & Observed Failure Modes

| # | Feature | Input Condition | Observed Behavior | Failure Mode / Implication |
|---|---|---|---|---|
| 1 | Prometheus Snapshots | Prometheus down or unreachable | `MetricsSnapshot(cpu=0.0, mem=0.0, lag=0.0)` | Silent masking: query failure converted to 0.0 overhead rather than unmeasured/null. |
| 2 | Scenario Runner Phase 2 | Rollout timeout during `solarwinds-001` | `inject_ok = False`, phases truncated to `[baseline, inject]`, `error = "inject() returned False"` | Scenario aborted; phases 3-5 skipped; 0 detections recorded. Correctly logged as failed injection. |
| 3 | Evaluator Denominators | Zero benign scenarios ($N_{\text{benign}} = 0$ in `raw3/`) | `precision = 1.0`, `recall = 1.0`, `fpr = 0.0`, `f1 = 1.0` | False precision: zero benign runs artificially eliminates false positives from denominator. |
| 4 | eBPF Agent Metadata | Pod/cgroup lookup failure in agent | `pod_name = "unknown"`, `container_id = "unknown"`, `image_digest = "sha256:000..."` | Drift events detected at kernel level cannot be linked to workload SBOMs. |
| 5 | Evaluator MTTD | False Negative run ($is\_tp = False$) | `mttd_s = None` | Evaluator excludes FN from MTTD list; mean computed strictly on TP runs. |
| 6 | Causal Engine Preflight | Small run count ($N = 6$ or $N = 9$) | Gate G1 triggers `BLOCK` | Emits `REASON_TOO_FEW_OBSERVATIONS`, preventing numerical crash in DoWhy. |
| 7 | Causal Engine Refutations | Placebo refuter effect vanishes to 0 | Refutation passes if $|new\_effect| < 0.2 \cdot |ate|$ | Refutation correctly distinguishes placebo null from stability bound. |
| 8 | Retroactive Fill | Old JSON missing detections | `query_drift_events` filters by $[t_{\text{inject}}, t_{\text{attack\_end}}]$ | Retroactive query matches events by timestamp if DB has records. |

---

## 6. Authoritative Blueprints for Downstream Deliverables

### 6.1 Blueprint for R1: `EXPERIMENTAL_EVALUATION_AUDIT.md`
Downstream implementers should structure `EXPERIMENTAL_EVALUATION_AUDIT.md` around:
1. **Full Run Inventory**: Tables from §2.1 and §2.2 containing all 6 runs in `raw/` and 9 runs in `raw3/`.
2. **Explicit Classification Matrix**:
   - `raw/`: 6 runs classified as Telemetry Collection Dropout (3 attack, 3 benign).
   - `raw3/`: 3 runs classified as Failed Injections (`solarwinds-001`), 6 runs classified as Completed Attacks (`xzutils-001`, `dep-confusion-001`).
3. **Telemetry & Dropout Disclosures**:
   - Disclose 100% missing `pod_name`, `container_id`, `sbom_id`, and `purl` in `raw3/`.
   - Disclose Prometheus query failure and prohibition of claiming 0.0 overhead.
   - Disclose Falco baseline absence.
4. **No Absent True Negatives**:
   - Explicitly rule that absent detections in `raw/` are NOT True Negatives.

### 6.2 Blueprint for R2: `EXPERIMENT_PROTOCOL.md`
Downstream implementers should structure `EXPERIMENT_PROTOCOL.md` around:
1. **Unit of Analysis Definition**:
   - One run = one independent experimental unit.
   - Forbid cross-sectional pooling of temporal diagnostic windows.
2. **Decoupled 4-Dimensional Protocol**:
   - Decouple $T_{\text{inject}} \to B_{\text{verified}} \to Y_{\text{drift}} \to \hat{Y}_{\text{phantom}}$.
   - Explicit oracle verification rules: sink receipts are network activity, not automatically drift; drift requires signed contract violation.
   - Insufficient evidence must resolve strictly to `unknown`.
3. **Causal DAG & Anti-Mediator Specification**:
   - Formalize DAGs for intervention effect vs. component attribution.
   - State explicit anti-mediator conditioning prohibition.
4. **Preflight Gate G1 Specification**:
   - Define $N \ge 10$ as software sanity guard.
   - Mandate abstention on existing datasets.
