# EXPERIMENTAL EVALUATION: PHANTOM EMPIRICAL EVALUATION & REPRODUCTION GUIDE

**Document Version**: 1.0.0  
**Target System**: PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*)  
**Scope**: Experimental methodology, offline vs. live cluster execution demarcation, dataset audit reconciliation, scenario lifecycles, reproduction commands, and honest limitation disclosures.

---

## 1. Executive Summary & Document Overview

This document provides the authoritative reproduction manual, architectural specification, and forensic integrity attestation for the experimental evaluation of **PHANTOM**.

PHANTOM monitors container execution using eBPF kernel probes, constructs Behavioral Dependency Graphs (BDGs), evaluates runtime activity against cryptographically signed container behavioral contracts, and attributes observed drift to software supply chain components via structural causal models.

A defensible scientific evaluation requires strict empirical honesty regarding the capabilities and limitations of experimental telemetry. This document:
1. Clearly demarcates between **offline-verified reproduction** (evaluating historical telemetry records) and **live-cluster infrastructure** (executing live Kubernetes microservices).
2. Establishes the formal **five-phase scenario lifecycle** and independent experimental unit model.
3. Reconciles raw dataset records (`research/datasets/raw/` and `research/datasets/raw3/`) with forensic audit findings.
4. Discloses dataset limitations, excluded runs, and the authoritative list of unsupported claims.
5. Provides exact, step-by-step reproduction commands.

---

## 2. Execution Modes: Offline-Verified vs. Live-Cluster Demarcation

The evaluation framework supports two explicitly demarcated operational modes:

```
+---------------------------------------------------------------------------------------------------+
| MODE 1: OFFLINE-VERIFIED INFRASTRUCTURE (Reproduction & Statistical Track)                        |
| - Evaluates authentic raw JSON telemetry records (raw/ N=6 dropouts, raw3/ N=9 runs)             |
| - Runs deterministic pipeline CLI (run_pipeline_report.py) emitting reports.json (v1.0.0)         |
| - Computes exact ordinary Wilson score intervals & bootstrap MTTD percentile intervals            |
| - Evaluates causal Preflight Gate G1 (N >= 10) software sanity guard and abstention handling      |
| - Generates LaTeX & CSV comparison tables rendering \text{---} and --- for unmeasured cells       |
| - Dependencies: Python 3.11–3.14, pytest, pyyaml, scikit-learn                                     |
| - Docker required: NO (requires_docker = False)                                                   |
| - Root/eBPF required: NO                                                                          |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| MODE 2: LIVE-CLUSTER INFRASTRUCTURE (Execution & Telemetry Collection Track)                      |
| - Multi-node Kubernetes cluster (AWS EKS v1.28–v1.30 or bare-metal Linux)                         |
| - Target workload: Google Cloud Boutique microservices (11 services)                              |
| - Host Linux kernel >= 5.15 with BTF & BPF CO-RE enabled (CONFIG_DEBUG_INFO_BTF=y)                |
| - PHANTOM eBPF DaemonSet + Causal Engine + SBOM Service + PostgreSQL + Redis                     |
| - Live Prometheus v2.45+ monitoring stack for CPU, memory, and event lag metrics                  |
| - Baseline detectors: Falco 0.44.1 (modern eBPF probe), Trivy 0.70.0 (SBOM scan), IsolationForest  |
| - Dedicated mock out-of-band sinks (phantom-sink:8443, phantom-sink:4445, phantom-sink:4446)      |
| - Requires root privileges, kernel headers, and live cloud/virtualized infrastructure              |
+---------------------------------------------------------------------------------------------------+
```

### 2.1 Mode 1: Offline-Verified Reproduction Track (`offline_verified`)
- **Objective**: Independent, deterministic verification of experimental results from archived raw run records without requiring cloud infrastructure or privileged kernel access.
- **Environment Requirements**:
  - Python 3.11, 3.12, 3.13, or 3.14.
  - Standard user permissions (no root, no sudo).
  - No container runtime or Docker daemon required (`requires_docker = False`).
  - Native Windows, macOS, or Linux operating system.
- **Artifacts Handled**:
  - `research/datasets/raw/`: 114 scenario JSON files (6 indexed evaluation runs + 107 legacy runs).
  - `research/datasets/raw3/`: 9 scenario execution JSON files (6 completed attacks, 3 failed injections).
  - `research/evaluation/oracles/`: 6 oracle YAML specifications.
- **Output Artifacts**:
  - `output/reports.json` (schema v1.0.0)
  - `output/table_1_detection_performance.tex`
  - `output/table_1_detection_performance.csv`
  - `output/table_1_detection_performance_extended.tex`

### 2.2 Mode 2: Live-Cluster Execution Track (`live_cluster`)
- **Objective**: End-to-end deployment, behavioral contract generation, attack injection, and live telemetry capture.
- **Environment Requirements**:
  - AWS EKS or bare-metal Kubernetes cluster (v1.28–v1.30).
  - Linux kernel >= 5.15 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and eBPF support.
  - Container runtime: `containerd` v1.6+.
  - Dedicated namespace: `phantom-eval`.
  - Prometheus v2.45+ monitoring stack scraping pod metrics and eBPF exporter metrics.
  - Out-of-band mock verification sink (`phantom-sink`).
- **Software Dependencies & Pinned Tooling**:
  - **Falco**: Version **0.44.1** (pinned) with default ruleset and modern eBPF driver.
  - **Trivy**: Version **0.70.0** (pinned) for container image SBOM generation and vulnerability scanning.
  - **Isolation Forest**: scikit-learn 1.4+ trained on baseline syscall frequencies.
  - **DoWhy**: Causal inference library for structural causal models and backdoor adjustment.

---

## 3. Five-Phase Scenario Lifecycle & Experimental Unit Model

### 3.1 The Independent Experimental Unit
Per `EXPERIMENT_PROTOCOL.md` §2.1:
$$\text{ONE RUN} = \text{ONE INDEPENDENT EXPERIMENTAL UNIT} \quad (N=1 \text{ per repetition})$$
An experimental unit is an independently instantiated, freshly deployed Kubernetes scenario run encompassing the complete lifecycle. Temporal observation windows within a run are longitudinal time slices valid strictly for timeline diagnostics (e.g., MTTD); they **must never be sliced into independent cross-sectional units** to artificially inflate sample size $N$ or bypass preflight gates.

### 3.2 Five-Phase Lifecycle Specification
Every experimental run traverses five sequential phases:

```
+---------------+    +------------+    +---------------+    +-------------+    +-------------------+
|  1. BASELINE  | -> |  2. INJECT | -> |   3. ATTACK   | -> |  4. RECOVER | -> |  5. POST-RECOVERY |
|   (60s-120s)  |    |  (kubectl) |    |  (60s-180s)   |    |  (rollback) |    |     (50s-60s)     |
+---------------+    +------------+    +---------------+    +-------------+    +-------------------+
```

1. **Phase 1: Baseline (`baseline`, 60s–120s)**:
   - Target microservice is deployed under clean, benign conditions.
   - Background synthetic user traffic is generated against the service mesh.
   - Resource metrics (CPU, RSS memory) and baseline syscall frequencies are collected.
2. **Phase 2: Injection (`inject`)**:
   - The scenario harness delivers the intervention (e.g., via `kubectl cp`, rollout patch, or container restart).
   - Harness verifies delivery success and records `inject_ok`:
     - `inject_ok = True`: Container rollout completes, readiness probes pass.
     - `inject_ok = False`: Rollout times out or crashes (e.g., `solarwinds-001` in `raw3/`).
   - Injection timestamp ($t_{\text{inject}}$) is recorded.
3. **Phase 3: Attack (`attack`, 60s–180s)**:
   - Malicious payload initiates runtime activity (e.g., sink connection, backdoor spawn).
   - Detection window boundary is strictly enforced (`detection_window_s = 120.0s` or `180.0s`, max `300.0s`).
   - If detector fires within $[t_{\text{inject}}, t_{\text{inject}} + \text{detection\_window\_s}]$, alert is recorded and MTTD is calculated.
4. **Phase 4: Recovery (`recover`, 5s–30s)**:
   - Mitigation command or pod rollback restores the clean container configuration.
   - Harness logs `recover_ok` (True/False).
5. **Phase 5: Post-Recovery (`post-recovery`, 50s–60s)**:
   - Workload is observed to verify contract normalization and ensure no persistent background tampering remains.

---

## 4. Forensic Dataset Audit & Inventory Reconciliation

A rigorous evaluation requires reconciling published claims with the forensic reality of the raw telemetry:

### 4.1 Real Datasets Inventory
- `research/datasets/raw/` ($N=6$ indexed, 114 total files):
  - 3 attack scenarios (`xzutils-001`, `dep-confusion-001`, `solarwinds-001`), 3 benign controls (`benign-load-001`, `benign-restart-001`, `benign-update-001`).
  - **Forensic Reality**: **Total Telemetry Collection Dropout**. 100% of runs have empty PHANTOM detections (`phantom_detections = []`) due to disconnected API port-forwarding during the run.
  - **Integrity Rule**: Absence of detections in `raw/` represents **telemetry collection failure**, NOT true negative detector silence. Treating the 3 benign runs as True Negatives ($TN=3$) is scientifically invalid and strictly prohibited.
- `research/datasets/raw3/` ($N=9$ runs):
  - 3 repetitions each of `xzutils-001`, `dep-confusion-001`, and `solarwinds-001`.
  - **6 Completed Attack Runs**: 3 `xzutils-001` and 3 `dep-confusion-001` completed successfully with verified eBPF drift events and $TPR = 6/6 = 1.000$ (Wilson 95% CI: $[0.6097, 1.0000]$).
  - **3 Failed Injections (`solarwinds-001`)**: All 3 repetitions timed out during Phase 2 rollout (`inject_ok = False`, `error: "inject() returned False"`). Excluded from TPR denominators.
  - **Zero Benign Controls ($N_{\text{benign}} = 0$)**: `raw3/` contains no benign runs. Consequently, False Positive Rate ($FPR$), Precision, and F1 score are mathematically undefined without negative-class controls.

### 4.2 Excluded Runs & Handling Rules
Per `EXPERIMENT_PROTOCOL.md` §3.1, failed injections must be excluded from detection sensitivity ($TPR$) denominators because the intervention was never delivered:
- `20260905T231139Z_solarwinds-001_rep1`: Excluded (Rollout timeout, `inject() returned False`).
- `20260905T231616Z_solarwinds-001_rep2`: Excluded (Rollout timeout, `inject() returned False`).
- `20260905T232054Z_solarwinds-001_rep3`: Excluded (Rollout timeout, `inject() returned False`).

### 4.3 Telemetry & Identity Limitations
- **Upstream Identity Collapse**:
  - Across the 3,701 recorded drift events in `raw3/`, 100% have `pod_name = "unknown"`, `container_name = "unknown"`, null `sbom_id`, null `purl`, and dummy `sha256:0000000000000000000000000000000000000000000000000000000000000000` image digests.
  - The runtime-to-SBOM mapping layer was completely unlinked in the actual cluster telemetry; claims of 100% Causal Attribution Accuracy (CAA) were unsubstantiated by raw telemetry.
- **Unmeasured Resource Overhead**:
  - All Prometheus snapshots in `raw/` and `raw3/` report `0.0` CPU, `0.0` memory, and `0.0` event lag due to unhandled collection query failures. True monitoring overhead is **unmeasured/null**, not zero.
- **Baseline Telemetry Absence**:
  - Falco alert files were empty (`falco_detections = []`).
  - Trivy static scans represent point-in-time image vulnerability scans unlinked to runtime drift windows.
  - Isolation Forest live detection stream was uncollected.
  - Baseline metrics are classified as `telemetry_unavailable` / `NR`.

---

## 5. Statistical Methodology & Integrity Standards

To eliminate methodological artifacts and inflated claims, PHANTOM evaluation enforces:

1. **Strict Contract-Drift Ground-Truth Labeling Rules**:
   - Label $Y_{\text{drift}} = 0$ **only** when the applicable contract and independent evidence establish that observed behavior conforms to allowed behavior.
   - Label $Y_{\text{drift}} = 1$ **only** when verified behavior violates an applicable contract rule.
   - If the contract is missing, ambiguous, incomplete, or silent about behavior that cannot otherwise be established as authorized, preserve $Y_{\text{drift}} = \text{unknown}$.
   - **Do NOT infer ground truth from PHANTOM alerts** ($Y_{\text{drift}} \ne \hat{Y}_{\text{phantom}}$).
   - Benign runs lacking verified contract conformance remain $Y_{\text{drift}} = \text{unknown}$ and are never defaulted to true negatives.
2. **Standard Ordinary Wilson Score Intervals**:
   - For all binary proportions (e.g. $TPR$), uncertainty is quantified using the standard ordinary Wilson score interval without continuity correction:
     $$CI_{95\%} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
   - For $6/6$ true positives at $z=1.96$: $[0.6097, 1.0000]$ (exact math $[0.60966, 1.0000]$).
3. **Bootstrap Percentile Intervals for MTTD**:
   - Non-parametric bootstrap resampling ($B=2000$, seeded deterministically) produces 95% percentile confidence intervals for Mean Time To Detect (MTTD).
   - In addition to mean, median (P50), IQR, and P95 percentiles are reported to prevent skew from outliers.
4. **Preflight Gate G1 Technical Software Guard**:
   - Sample size $N \ge 10$ is strictly a technical sanity guard to prevent singular/rank-deficient regression matrices in structural causal estimation.
   - Gate G1 cleanly abstains with `insufficient_evidence: too_few_observations` on small batches without bypasses.
5. **Table Formatting & Bolding Rules**:
   - Undefined and unmeasured metrics render as `\text{---}` in LaTeX and `---` in CSV.
   - Bolding in LaTeX is restricted to genuine measured maxima/minima; unmeasured zeros and fallback values are never bolded.

---

## 6. The 10 Claims NOT Supported by Existing Data

In accordance with scientific defensibility, the following 10 claims **CANNOT BE MADE** from the current historical datasets:

1. **Detection rate (TPR / recall)**: Unsubstantiated on `raw/` due to 100% telemetry collection dropouts.
2. **False positive rate (FPR)**: Mathematically undefined on `raw3/` due to zero benign control runs ($N_{\text{benign}} = 0$).
3. **Precision**: Undefined on `raw3/` due to zero benign controls ($FP + TN = 0$).
4. **F1 score**: Undefined on `raw3/` due to undefined Precision.
5. **Mean time to detection (MTTD)**: Unsubstantiated on `raw/` due to zero detections.
6. **Causal attribution accuracy (CAA)**: Unsubstantiated on `raw3/` due to 100% null PURL, null SBOM ID, and unknown pod identity resolution failure.
7. **PCEPS Brier score**: Unsubstantiated due to absence of probabilistic exploit predictions in raw telemetry.
8. **CPU/memory overhead (all metrics are zero in the dataset)**: Unmeasured due to Prometheus query fallback zeros.
9. **Real-data average treatment effect (ATE)**: Causal estimation abstained due to Preflight Gate G1 failure ($N < 10$).
10. **Any comparison to baseline detectors from this run batch**: Telemetry unavailable for Falco, Trivy, and Isolation Forest.

---

## 7. Step-by-Step Reproduction Commands

### 7.1 Running the Master Deterministic Evaluation Pipeline
Execute the deterministic pipeline CLI on the `raw3/` dataset:
```bash
python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json
```
This generates:
- `output/reports.json`: Versioned (schema v1.0.0) JSON report containing data quality summaries, run exclusions, Wilson score intervals, bootstrap MTTD intervals, honest limitations, and unsupported claims.
- `output/table_1_detection_performance.tex`: LaTeX comparison table rendering `\text{---}` for undefined cells without bolding zeros.
- `output/table_1_detection_performance.csv`: CSV comparison table.
- `output/table_1_detection_performance_extended.tex`: Extended LaTeX table for supplementary material.

To evaluate the legacy `raw/` dataset:
```bash
python run_pipeline_report.py --data-dir research/datasets/raw --out output/raw_report.json
```

### 7.2 Running Test Suites
Run the milestone and scenario verification test suites:
```bash
# Verify Feature 17 (Pipeline CLI), Feature 18 (Tables), Feature 19 (Documentation)
python -m pytest tests/e2e/test_tier1_features.py -k "Feature17 or Feature18 or Feature19"

# Verify Scenario 3 (Reproduction Pipeline) and Scenario 5 (Artifact Generation)
python -m pytest tests/e2e/test_tier4_scenarios.py -k "Scenario3 or Scenario5"

# Run complete E2E test suite (Tiers 1–4)
python -m pytest tests/e2e/

# Run domain unit test suites
python -m pytest research/evaluation/tests/
python -m pytest services/causal-engine/tests/
python -m pytest services/sbom-service/tests/
```

### 7.3 Auditing Historical Records
Inspect the authoritative audit inventory and protocol specification:
- `EXPERIMENTAL_EVALUATION_AUDIT.md`: Forensic audit of raw datasets.
- `EXPERIMENT_PROTOCOL.md`: Authoritative ground-truth and causal evaluation protocol.
- `PROJECT.md`: Architecture, feature inventory, and milestone status.

---

## 8. Summary of Evaluation Artifacts

| Artifact | Location | Description |
|---|---|---|
| Master Evaluation CLI | `run_pipeline_report.py` | Deterministic pipeline CLI evaluating actual run records |
| Evaluation Readme | `EXPERIMENTAL_EVALUATION_README.md` | Authoritative reproduction and environment specification |
| Forensic Audit | `EXPERIMENTAL_EVALUATION_AUDIT.md` | Line-by-line audit of raw dataset records |
| Experiment Protocol | `EXPERIMENT_PROTOCOL.md` | Decoupled ground truth, DAG, and sanity gates |
| Versioned Report | `output/reports.json` | Schema v1.0.0 deterministic empirical evaluation report |
| LaTeX Comparison Table | `output/table_1_detection_performance.tex` | TABLE 1 formatted for paper submission |
| CSV Comparison Table | `output/table_1_detection_performance.csv` | Machine-readable table for downstream analysis |
| Archived Paper Results | `research/evaluation/results3/` | Updated reports.json, LaTeX, and CSV tables |
