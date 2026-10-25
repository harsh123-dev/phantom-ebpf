# Forensic Integrity Audit Report: Milestone 4

**Auditor Agent**: auditor_m4_1_gen2  
**Role**: forensic_auditor (critic, specialist, auditor)  
**Working Directory**: `d:\project-1\.agents\teamwork\auditor_m4_1_gen2`  
**Target**: Milestone 4 (R6: Deterministic Reporting & Comprehensive Documentation)  
**Parent Conversation ID**: `702ee561-473a-479f-b16c-b11ebb13b529`  
**Timestamp**: 2026-10-24T10:57:00Z  
**Integrity Mode**: Benchmark Mode (maximum strictness per `ORIGINAL_REQUEST.md`)  
**Verdict**: **CLEAN**

---

## 1. Observation

A forensic investigation was conducted across all Milestone 4 work products, source code, data records, mathematical formulations, and execution outputs.

### 1.1 Master Pipeline Command & Report Schema (`run_pipeline_report.py`, `output/reports.json`)
- **CLI Implementation** (`run_pipeline_report.py:43–525`):
  - Accepts `--data-dir`, `--out`, and `--tables-dir` with automated parent directory creation.
  - Reconstructs `ScenarioResult` objects via `_dict_to_scenario_result()` from raw scenario JSON records.
  - Dynamically detects failed injections using `is_failed_injection()` (`inject_ok=False`, `error: "inject() returned False"`).
  - Evaluates detection metrics via `ScenarioEvaluator`, producing `EvaluationReport`s.
  - Integrates Causal Engine Preflight Gate G1 (`gate_minimum_observations`, $N \ge 10$) via `RunAnalysisUseCase`, enforcing software sanity guards without bypassing evidence requirements.
- **Output Report Schema (`output/reports.json`)**:
  - `schema_version`: `"v1.0.0"`
  - `total_runs_in_index`: 9
  - `data_quality`: `{"total_runs": 9, "completed_attacks": 6, "failed_injections": 3, "collection_dropouts": 0, "benign_count": 0}`
  - `exclusions`: Exactly 3 records (`solarwinds-001_rep1`, `solarwinds-001_rep2`, `solarwinds-001_rep3`), all documenting `reason: "failed_injection"`, `error: "inject() returned False"`, and note citing `EXPERIMENT_PROTOCOL.md §3.1`.
  - `metrics`:
    - `tpr`: `1.0`
    - `tpr_ci_wilson`: `[0.6097, 1.0]`
    - `fpr`: `null` (not fabricated as 0.0)
    - `precision`: `null`
    - `f1`: `null`
    - `mttd_mean`: `15.74`
    - `mttd_median`: `5.52`
    - `mttd_iqr`: `4.37`
    - `mttd_p95`: `54.72`
    - `mttd_ci_bootstrap`: `[3.57, 38.04]`
    - `tp`: 6, `fn`: 0, `fp`: null, `tn`: null
    - `n_attack_scenarios`: 6, `n_benign_scenarios`: 0, `excluded_failed_injections`: 3
  - `overhead`:
    - `status`: `"unmeasured"`
    - `cpu_overhead_pct`: `null`
    - `memory_overhead_mb`: `null`
    - `event_lag_p95_ms`: `null`
  - `baselines`:
    - `falco-default-rules`: `status: "telemetry_unavailable"`, `tpr: null`
    - `trivy-sbom-static`: `status: "task_mismatch_and_telemetry_unavailable"`, `tpr: null`
    - `isolation-forest-syscall-frequency`: `status: "telemetry_unavailable"`, `tpr: null`
  - `limitations`: 9 substantive disclosures (covering Gate G1, failed injections, collection dropout in `raw/`, missing benign controls in `raw3/`, identity pipeline collapse, and unmeasured Prometheus overhead).
  - `claims_NOT_supported_by_this_data`: Complete 10-item enumeration of unsupported claims matching `EXPERIMENTAL_EVALUATION_AUDIT.md`.

### 1.2 Raw Dataset Integrity Reconciliation (`research/datasets/raw3/`)
Direct empirical inspection of all 9 JSON files in `research/datasets/raw3/`:
- **6 Completed Attack Runs**:
  - `20260905T223101Z_xzutils-001_rep1`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=70.331969`, 239 detections.
  - `20260905T223752Z_xzutils-001_rep2`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=6.349775`, 654 detections.
  - `20260905T224442Z_xzutils-001_rep3`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=4.681537`, 684 detections.
  - `20260905T225102Z_dep-confusion-001_rep1`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=2.607243`, 720 detections.
  - `20260905T225804Z_dep-confusion-001_rep2`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=7.875910`, 684 detections.
  - `20260905T230506Z_dep-confusion-001_rep3`: `ground_truth_label=1`, `inject_ok=True`, `is_true_positive=True`, `mttd_s=2.578247`, 720 detections.
  - Derived values: $\text{Mean MTTD} = \frac{70.331969 + 6.349775 + 4.681537 + 2.607243 + 7.875910 + 2.578247}{6} = 15.7374 \approx 15.74\text{s}$.
  - Sorted MTTD: $[2.578247, 2.607243, 4.681537, 6.349775, 7.875910, 70.331969]$.
  - Median: $\frac{4.681537 + 6.349775}{2} = 5.5156 \approx 5.52\text{s}$.
  - Percentiles (linear interpolation): $Q1 = 3.1258$, $Q3 = 7.4944$, $\text{IQR} = 4.3686 \approx 4.37\text{s}$, $P95 = 54.7180 \approx 54.72\text{s}$.
  - Bootstrap CI ($B=2000, \text{seed}=42$): $[3.57, 38.04]$.
- **3 Failed Injections**:
  - `20260905T231139Z_solarwinds-001_rep1`, `rep2`, `rep3`: all have `error: "inject() returned False"`, `phases[1].notes: "inject_ok=False"`, `phases` truncated to `[baseline, inject]`, and zero detections.
  - All 3 are genuinely excluded from detection sensitivity ($TPR$) denominators.
- **Benign Runs**: Exactly 0. $FPR$, Precision, and F1 are properly recorded as `null` / undefined.

### 1.3 Statistical Uncertainty & Wilson Score Formula (`wilson_score.py`)
- Inspected `research/evaluation/metrics/wilson_score.py:54–94`:
  - Implements the exact standard ordinary Wilson score interval without continuity correction:
    $$\text{Center} = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{Margin} = \frac{z}{1 + \frac{z^2}{n}}\sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}$$
  - At $k=6, n=6, \alpha=0.05$ ($z = 1.95996398454$):
    - Computed exact interval: `(0.6096657120978346, 1.0)`.
    - Rounded to 4 decimal places: `[0.6097, 1.0000]`.
  - Static analysis confirmed: no hardcoding of 0.6096 or 0.6097 in `evaluator.py`, `run_pipeline_report.py`, or `comparison_table.py`. The metric is computed dynamically via pure arithmetic.

### 1.4 Comparison Table Generation (`comparison_table.py`, `output/table_1_*`)
- Inspected `research/evaluation/metrics/comparison_table.py:89–274`:
  - `format_latex_cell`: Renders `None` as `\text{---}`.
  - `format_csv_cell`: Renders `None` as `---` (or empty strings in DictWriter).
  - `_find_best`: Filters out detectors with `"unavailable"` status and unmeasured overhead. Never treats unmeasured zeros as best values.
- Emitted LaTeX table (`output/table_1_detection_performance.tex`):
  ```latex
  \textbf{PHANTOM (ours)} & \textbf{1.000} & \text{---} & \text{---} & \textbf{15.740} & \text{---} & \text{---} \\
  Falco (default rules) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
  Trivy (static scan) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
  IsoForest (na\"{i}ve) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
  ```
  Zero bolded zeros; unmeasured baselines and overhead are cleanly rendered as `\text{---}`.

### 1.5 Reproduction & Documentation (`EXPERIMENTAL_EVALUATION_README.md`)
- Authoritative documentation at project root:
  - Explicit demarcation of Mode 1 (Offline-verified, `requires_docker=False`, no root) vs. Mode 2 (Live-cluster, AWS EKS, eBPF daemonset, Prometheus).
  - Complete 5-phase scenario lifecycle specification (`baseline`, `inject`, `attack`, `recover`, `post_recovery`).
  - Pinned baseline tooling versions (Falco 0.44.1, Trivy 0.70.0).
  - Explicit listing of the 10 unsupported claims.

### 1.6 Empirical Test Execution
Independent test execution yielded:
- `python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports_audit_test.json`:
  - Exit code: 0
  - Byte-for-byte deterministic match against `output/reports.json` (excluding execution timestamp and generated report UUIDs).
- `python -m pytest research/evaluation/tests/test_evaluator.py`:
  - 37 passed in 2.09s (100% pass)
- `python -m pytest research/evaluation/tests/test_adversarial_challenger_m4.py`:
  - 11 passed in 101.43s (100% pass)
- `python -m pytest tests/e2e/test_tier1_features.py -k "Feature17 or Feature18 or Feature19"`:
  - 15 passed in 35.52s (100% pass)
- `python -m pytest tests/e2e/test_tier4_scenarios.py -k "Scenario3 or Scenario5"`:
  - 7 passed in 14.50s (100% pass)

---

## 2. Logic Chain

1. **Premise 1**: The benchmark mode integrity specification strictly prohibits hardcoded test results, facade implementations, fabricated verification outputs, and bypassing preflight gates.
2. **Premise 2**: Direct static analysis across `run_pipeline_report.py`, `evaluator.py`, `comparison_table.py`, and `wilson_score.py` confirmed that all metrics are computed from deserialized `ScenarioResult` objects and raw JSON records, with zero hardcoded return values or facade classes.
3. **Premise 3**: Empirical recalculation from the 9 raw files in `research/datasets/raw3/` independently verified that $TP=6$, $TPR=1.0$, $\text{MTTD}=15.74\text{s}$, $\text{IQR}=4.37\text{s}$, and 3 SolarWinds runs are rollout failures with `inject_ok=False`.
4. **Premise 4**: Mathematical audit of `compute_ordinary_wilson_score` verified that the formula implemented matches the textbook standard Wilson interval without continuity correction, yielding $(0.6096657..., 1.0)$, formatted as $[0.6097, 1.0000]$.
5. **Premise 5**: Inspection of report serialization and table formatting demonstrated that missing baseline telemetry is classified as `telemetry_unavailable` / `\text{---}`, missing Prometheus metrics as `unmeasured` / `null`, and undefined negative-class metrics ($FPR$, Precision, $F1$) as `null` / `\text{---}` without bolded zeros.
6. **Premise 6**: Preflight Gate G1 ($N \ge 10$) was executed by `RunAnalysisUseCase` on every run, cleanly returning `insufficient_evidence: too_few_observations` without any bypass mechanism.
7. **Inference**: Every claim made by Worker M4 is verified empirically and found to be completely authentic, reproducible, and compliant with all project constraints.

---

## 3. Caveats

1. **Python 3.14 Environment Packages**: As documented in `worker_m4/handoff.md` and `EXPERIMENTAL_EVALUATION_README.md`, `pytest-asyncio` and `asyncpg` are not installed in the Windows Python 3.14 environment; direct async API route unit tests require those packages, but all M4 CLI, evaluation, math, and E2E test suites execute and pass without them.
2. **Historical Telemetry Limitations**: The audit confirms that the raw data in `raw3/` has zero benign runs and unlinked SBOM/PURL identities; the work product under audit authentically acknowledges these deficiencies rather than attempting to conceal them.
3. **No Caveats Beyond Above**: All observations are verified directly on disk.

---

## 4. Conclusion

**Verdict: CLEAN**

Milestone 4 exhibits zero integrity violations:
- Zero hardcoded metrics or fake report outputs.
- Zero facade implementations or bypasses of Preflight Gate G1.
- Authentic data exclusion of failed injections (`inject_ok=False`).
- Pure mathematical calculation of standard ordinary Wilson score intervals.
- Honest and transparent accounting of unmeasured overhead, unavailable baseline telemetry, and empirical data quality limitations.

---

## 5. Verification Method

To independently reproduce this forensic audit:

1. **Re-run the deterministic pipeline and verify report contents**:
   ```bash
   python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports_audit.json
   ```
   Inspect `output/reports_audit.json`. Verify:
   - `exclusions` has 3 SolarWinds records with `reason: "failed_injection"`.
   - `metrics.tpr` is `1.0`, `metrics.tpr_ci_wilson` is `[0.6097, 1.0]`, `metrics.fpr` is `null`.
   - `overhead.status` is `"unmeasured"`.

2. **Verify mathematical Wilson score computation**:
   ```bash
   python -c "from research.evaluation.metrics.wilson_score import compute_ordinary_wilson_score; print(compute_ordinary_wilson_score(6, 6))"
   ```
   Output: `(0.6096657120978346, 1.0)`.

3. **Verify comparison table formatting**:
   Inspect `output/table_1_detection_performance.tex`. Verify all baseline cells and unmeasured overhead cells contain `\text{---}` and no zeros are bolded.

4. **Execute all test suites**:
   ```bash
   python -m pytest research/evaluation/tests/test_evaluator.py
   python -m pytest research/evaluation/tests/test_adversarial_challenger_m4.py
   python -m pytest tests/e2e/test_tier1_features.py -k "Feature17 or Feature18 or Feature19"
   python -m pytest tests/e2e/test_tier4_scenarios.py -k "Scenario3 or Scenario5"
   ```

5. **Invalidation Conditions**:
   - Fabricating non-null $FPR$ or Precision on `raw3/`.
   - Bolding unmeasured zero overhead in LaTeX tables.
   - Including `solarwinds-001` in $TPR$ denominators.
   - Bypassing Preflight Gate G1 to fabricate ATE estimates.
