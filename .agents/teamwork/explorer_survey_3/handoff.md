# Handoff Report: R5 & R6 Survey (explorer_survey_3)

**Type**: Hard Handoff  
**Agent**: `explorer_survey_3` (teamwork_preview_explorer)  
**Recipient**: `orchestrator_1` (4299c465-79cb-468c-95c3-8aed4c92f7f9)  
**Subject**: Survey & Investigation of Baseline Comparisons (R5), Resource-Overhead Accounting (R5), and Deterministic Reporting & Documentation (R6)  
**Date**: 2026-10-24  

---

## 1. Observation

### 1.1 Baseline Telemetry Absence
- **Falco 0.44.1**:
  - `research/evaluation/baselines/falco_baseline.py` lines 71–77 define `FALCO_VERSION = "0.44.1"` and `FALCO_CHART_VERSION = "4.3.1"`.
  - In `research/datasets/baseline_run_log.txt`:
    ```
    2026-08-08 20:27:37,451 INFO research.evaluation.baselines.falco_baseline falco.setup.dry_run_skipped
    2026-08-08 20:27:37,776 WARNING research.evaluation.baselines.falco_baseline falco.alert_log_missing
    ```
  - Across all 9 files in `research/datasets/raw3/` and 114 files in `research/datasets/raw/`, `"falco_detections"` is empty (`[]`). No raw Falco log files (`events.jsonl`) exist anywhere on disk.
- **Trivy 0.70.0**:
  - `research/evaluation/baselines/trivy_baseline.py` lines 73–74 define `TRIVY_VERSION = "0.70.0"`. Line 94 sets output directory to `research/datasets/raw/trivy`.
  - Directory `research/datasets/raw/trivy` contains 0 files.
  - `research/datasets/baseline_run_log.txt` records `trivy.setup.dry_run_skipped`.
- **IsolationForest Baseline**:
  - `research/evaluation/baselines/isolation_forest_baseline.py` defines 17 features (16 syscalls + log1p total count), `_N_ESTIMATORS = 200`, `_RANDOM_STATE = 42`.
  - Pickled model files exist at `research/datasets/raw3/isoforest_model.pkl` (2,358,245 bytes) and `research/datasets/raw/isoforest_model.pkl` (2,357,445 bytes).
  - Inspection via Python confirmed `n_features_in_ = 17`, `len(estimators_) = 200`, `threshold = -0.5`.
  - `baseline_run_log.txt` records that fitting occurred in dry-run mode using synthetic data.
- **Evaluator Classification of Absent Baseline Telemetry**:
  - In `research/evaluation/metrics/evaluator.py` lines 375–428, if a baseline returns no detections in an attack window, it is classified as $FN$.
  - In `research/evaluation/results3/reports.json` lines 37–116, Falco, Trivy, and IsoForest are each assigned `tp: 0, fp: 0, fn: 6, tn: 0, tpr: 0.0`.

### 1.2 Resource Overhead Telemetry Fallback
- In `research/evaluation/scenarios/scenario_runner.py` lines 605–619:
  ```python
  def _query(promql: str) -> float:
      try:
          with httpx.Client(timeout=self._timeout) as client:
              resp = client.get(self._prometheus, params={"query": promql})
              resp.raise_for_status()
              data = resp.json()
              results = data.get("data", {}).get("result", [])
              if results:
                  return float(results[0]["value"][1])
      except Exception as exc:
          log.debug("prometheus.query_failed", extra={"promql": promql, "error": str(exc)})
      return 0.0
  ```
- All 9 files in `raw3/` contain `metrics_snapshots` where `cpu_usage_cores: 0.0`, `memory_rss_mb: 0.0`, `event_lag_p95_ms: 0.0`.
- In `research/evaluation/metrics/evaluator.py` lines 275–281:
  `cpu_overhead_pct = (100.0 * (cpu_attack - cpu_base) / max(cpu_base, 1e-9) if cpu_base > 0 else 0.0)`. Since `cpu_base == 0.0`, overhead was set to `0.0`.
- `results3/reports.json` lines 27–29 records `"cpu_overhead_pct": 0.0, "memory_overhead_mb": 0.0, "event_lag_p95_ms": 0.0`.
- `results3/table_1_detection_performance.tex` line 9 outputs `\textbf{PHANTOM (ours)} & ... & \textbf{0.000} & \textbf{0.000}`.

### 1.3 Denominator & Data Quality State
- `raw3/` contains 9 attack runs: 6 completed (`xzutils-001` rep 1–3, `dep-confusion-001` rep 1–3), 3 failed injections (`solarwinds-001` rep 1–3 with `error: "inject() returned False"`).
- `raw3/` contains 0 benign control runs.
- `results3/reports.json` line 5 records `"n_benign_scenarios": 0`, but lines 11–14 record `"fpr": 0.0, "precision": 1.0, "f1": 1.0`.
- In `research/evaluation/metrics/comparison_table.py` lines 209–215, bolding logic `abs(val - best_val) < 1e-9` caused baseline FPR (`0.000`) and CPU overhead (`0.000`) to be bolded as optimal.

### 1.4 Existing Tests and Documentation
- Test suite run: `python -m pytest research/evaluation/tests -v` $\to$ **60 passed in 0.14s**.
- `test_evaluator.py` line 227 contains `test_failed_run_fn_in_evaluator`, asserting that failed injection runs are counted as $FN=1$.
- `EVALUATION_README.md` exists, but neither `EXPERIMENTAL_EVALUATION_README.md` nor `EXPERIMENT_PROTOCOL.md` exists in the repository.

---

## 2. Logic Chain

1. **Premise**: In `scenario_runner.py` (line 619), unhandled exceptions during Prometheus queries return `0.0`.
2. **Observation**: All 9 raw scenario JSONs in `raw3/` contain `cpu_usage_cores: 0.0, memory_rss_mb: 0.0, event_lag_p95_ms: 0.0` in every metrics snapshot.
3. **Inference**: Prometheus was either not reachable or returned empty series during the cluster test runs. Live telemetry was never captured.
4. **Premise**: In `evaluator.py` (line 280), if `cpu_base <= 0`, `cpu_overhead_pct` evaluates to `0.0`.
5. **Inference**: The evaluation pipeline silently converted missing Prometheus telemetry into a false claim of 0.0% CPU overhead, 0.0 MB memory overhead, and 0.0 ms event lag. Under R5, this must be corrected to report `null` / `"unmeasured"`.
6. **Premise**: In `falco_baseline.py` and `trivy_baseline.py`, missing logs and dry-run execution resulted in empty detection lists `[]`.
7. **Observation**: In `evaluator.py` (lines 407–428), any detector with 0 detections in an attack window is evaluated as $TP=0, FN=N_{\text{attack}}$.
8. **Inference**: Falco and Trivy were penalized with 0% TPR ($FN=6$) due to absent telemetry, rather than being marked as `telemetry_unavailable`. This falsely exaggerated PHANTOM's comparative performance.
9. **Premise**: Under detection theory, $FPR = \frac{FP}{FP + TN}$, $\text{Precision} = \frac{TP}{TP + FP}$, $F1 = \frac{2 \cdot P \cdot R}{P + R}$.
10. **Observation**: `raw3` contains 0 benign control runs ($N_{\text{benign}} = 0$, so $FP=0, TN=0$).
11. **Inference**: The denominator for FPR is $0 + 0 = 0$. Similarly, without benign exposures, false positive rate cannot be bounded. Therefore, FPR, Precision, and F1 are mathematically undefined and must be emitted as `null` / `"undefined"`, not `0.0` or `1.0`.
12. **Premise**: Requirement R4 mandates standard Wilson score interval without continuity correction ($[0.6096, 1.0000]$ for 6/6 at $z=1.96$).
13. **Observation**: `evaluator.py` does not implement Wilson score intervals.
14. **Inference**: Implementing the standard Wilson score formula without continuity correction is required for binary rate uncertainty reporting.

---

## 3. Caveats

1. **Historical Raw Dataset (`research/datasets/raw/`)**:
   `raw/` contains 114 JSON records from earlier runs in August 2026. A sample of these records showed 0 detections and `pod_name: "dry-run-pod"`. These legacy records do not represent valid live cluster runs and should not be confused with the 9 authoritative runs in `raw3/`.
2. **PCEPS and Causal Attribution in Saved Events**:
   Drift events stored in `raw3/` contain ambiguous process identity (`identity_status: "ambiguous"` or `null`) and lack PURL / SBOM annotations. While the code in `services/causal-engine` and `services/sbom-service` implements causal graph estimation and PCEPS feature extraction, the saved empirical records do not support component-level attribution.
3. **Cluster Access**:
   This survey was conducted strictly in read-only offline mode on the existing workspace filesystem without active AWS EKS or Kubernetes cluster credentials.

---

## 4. Conclusion

1. **R5 Status**:
   - Baseline comparative metrics (Falco 0.44.1, Trivy 0.70.0, IsolationForest) are currently invalid because baseline telemetry was never captured. They must be reported as `telemetry_unavailable` / `NR` for historical runs.
   - Resource overhead is unmeasured due to silent zero-fallback in `scenario_runner.py`. It must be reported as `null` / `"unmeasured"`, never fabricated as 0.0.
2. **R6 Status**:
   - `reports.json` must be upgraded to a versioned schema (v1.0.0) containing data quality summaries, run exclusion reasons (3 failed SolarWinds injections), Wilson score confidence intervals ($[0.6096, 1.0000]$ for 6/6), MTTD median/IQR, and honest limitation disclosures.
   - `comparison_table.py` must be updated to prevent bolding unmeasured/zero fallbacks and output `\text{---}` for undefined cells.
   - `EXPERIMENTAL_EVALUATION_README.md` and `EXPERIMENT_PROTOCOL.md` must be created to demarcate offline-verified vs live-cluster execution and decouple injection delivery from contract drift.

---

## 5. Verification Method

1. **Run Unit Tests**:
   Execute the evaluation test suite to confirm baseline test suite integrity:
   ```bash
   python -m pytest research/evaluation/tests -v
   ```
   *Expected outcome*: 60 passed.
2. **Verify Telemetry Zeros in Raw Files**:
   Execute:
   ```bash
   python -c "import json, glob; print([m for f in glob.glob('research/datasets/raw3/*.json') for m in json.load(open(f))['metrics_snapshots'] if m['cpu_usage_cores'] > 0])"
   ```
   *Expected outcome*: `[]` (confirms all CPU snapshots are exactly 0.0).
3. **Verify Absence of Baseline Logs**:
   Execute:
   ```bash
   python -c "import json, glob; print([len(json.load(open(f))['falco_detections']) for f in glob.glob('research/datasets/raw3/*.json')])"
   ```
   *Expected outcome*: `[0, 0, 0, 0, 0, 0, 0, 0, 0]`.
4. **Inspect Survey Report**:
   Inspect full survey documentation:
   `d:\project-1\.agents\teamwork\explorer_survey_3\survey_report.md`
