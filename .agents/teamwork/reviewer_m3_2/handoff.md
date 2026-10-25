# Independent Review & Adversarial Critic Report: Milestone 3

**Reviewer**: `reviewer_m3_2` (teamwork_preview_reviewer / critic)  
**Date**: 2026-10-24  
**Target Milestone**: Milestone 3 (R4 & R5: Defensible Detection, Mapping & Statistical Uncertainty)  
**Verdict**: **APPROVE**  
**Overall Risk Assessment**: **LOW**  

---

## 1. Observation

Direct examination of implementation codebases, formulas, and test execution yielded the following observations:

### 1.1 Source Code Verification
- **`research/evaluation/metrics/wilson_score.py`**:
  - Pure-math implementation of the ordinary Wilson score confidence interval without continuity correction.
  - Critical value $z = 1.959963984540054$ for $95\%$ confidence level (lines 33-52).
  - Explicit formulas for center and margin terms (lines 84-89):
    $$p^* = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{margin} = \frac{z}{1 + \frac{z^2}{n}}\sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}$$
  - Bound checking: `lower = max(0.0, center - margin)`, `upper = min(1.0, center + margin)`.
  - Zero-trial handling: `trials == 0` returns `(None, None)`.
  - For $k=6, n=6$, returns $(0.6096657..., 1.0)$, exactly matching $[0.6096, 1.0000]$ specification.

- **`research/evaluation/metrics/evaluator.py`**:
  - `is_failed_injection(r)` (lines 206-224) verifies injection delivery failure via `inject_ok is False`, phase notes containing `inject_ok=False`, or error strings containing `inject() returned False`.
  - Exclusion from TPR denominators (lines 323-327, 448-450):
    - Failed injections are segregated into `failed_attack_results` and counted in `excluded_failed_injections`.
    - TPR is computed over `valid_attack_results` ($denom = tp + fn$), excluding failed injections from the denominator.
  - Undefined denominator policy (lines 804-825):
    - `fpr`: returns `None` if `denom_fpr == 0` or `fp is None`.
    - `precision`: returns `None` if `denom_prec == 0` or `tp is None`.
    - `f1`: returns `None` if `precision is None` or `recall is None` or `precision + recall == 0`.
    - `tpr`: returns `None` if `denom_tpr == 0`.
    - Zero is never fabricated as a fallback.
  - Baseline telemetry absence classification (lines 451-484):
    - If `not detections`: classified as `telemetry_unavailable` (or `task_mismatch_and_telemetry_unavailable` for Trivy).
    - `tp=None`, `fn=None`, `tpr=None`, `fpr=None`, `precision=None`, `f1=None`.
    - Does NOT count missing detections as False Negatives ($FN=6, TPR=0.0$).
  - Resource overhead accounting (lines 352-376):
    - Checks `has_live_overhead` across baseline and attack Prometheus snapshots.
    - If missing or all-zero, sets `overhead_status = "unmeasured"`, `cpu_overhead_pct = None`, `memory_overhead_mb = None`, `event_lag_p95_ms = None`.
  - Bootstrap MTTD statistics (lines 718-760):
    - Computes mean, median ($P_{50}$), IQR ($P_{75} - P_{25}$), $P_{95}$, and 95% non-parametric bootstrap percentile interval with $B=2,000$ resamples. If $N < 2$, returns `None` for bootstrap CI.

- **`research/evaluation/metrics/comparison_table.py`**:
  - `format_latex_cell(val, precision=3, is_best=False)` (lines 89-97): renders `None` as `\text{---}` and bold values as `\textbf{...}`.
  - `format_csv_cell(val, precision=4)` (lines 99-104): renders `None` as `---`.
  - `generate_csv` (lines 275-323): produces clean CSV for DataFrame ingestion with empty strings `""` for `None` values.
  - Table bolding logic in `_find_best` and `generate_comparison_table` (lines 149-186, 227-249):
    - Explicitly filters out detectors with `status` containing `"unavailable"` and unmeasured overhead.
    - Prevents unmeasured zeros or missing cells from ever being selected or bolded as best.

- **`services/causal-engine/app/domain/causal_validation.py`**:
  - Forward-reference analysis:
    - Line 282: `gate_independent_experimental_units = gate_unique_run_ids` placed after line 214 definition.
    - Line 431: `gate_covariates_precede_treatment = gate_covariates_pre_treatment` placed after line 391 definition.
    - No forward-reference NameErrors exist.

### 1.2 Independent Test Execution
1. Evaluation unit tests:
   ```powershell
   python -m pytest research/evaluation/tests/
   ```
   **Result**: `64 passed in 2.09s` (100% pass rate).
2. Targeted Tier 1 feature tests:
   ```powershell
   python -m pytest tests/e2e/test_tier1_features.py -k "Feature09 or Feature10 or Feature13 or Feature14 or Feature16"
   ```
   **Result**: `25 passed, 80 deselected in 0.17s` (100% pass rate).
3. Complete Tier 1 E2E feature tests:
   ```powershell
   python -m pytest tests/e2e/test_tier1_features.py
   ```
   **Result**: `105 passed in 44.59s` (100% pass rate).
4. Full E2E Test Suite (Tiers 1–4):
   ```powershell
   python -m pytest tests/e2e/
   ```
   **Result**: `242 passed in 96.50s` (100% pass rate across all 4 tiers).
5. Causal Engine unit and domain tests:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests
   ```
   **Result**: `357 passed, 927 warnings in 42.42s` (100% pass rate).
6. SBOM Service unit and domain tests:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests
   ```
   **Result**: `177 passed in 1.33s` (100% pass rate).

### 1.3 Integrity Verification
- No hardcoded test results found in `wilson_score.py`, `evaluator.py`, `comparison_table.py`, or `causal_validation.py`.
- No dummy or facade implementations detected.
- No shortcuts or external delegators bypassing core calculations.
- No fabricated verification outputs or self-certifying artifacts.

---

## 2. Logic Chain

1. *From §1.1 (`wilson_score.py`)*: The implementation evaluates the exact closed-form algebraic expression for the ordinary Wilson score interval. For $k=6, n=6$ at $\alpha=0.05$, the analytical lower bound is $0.6096657...$ which rounds to $0.6096$, and upper bound is clamped at $1.0000$. The code adheres strictly to `EXPERIMENT_PROTOCOL.md` §7.1.
2. *From §1.1 (`evaluator.py` lines 206-224, 323-327)*: If an attack payload delivery fails (`inject_ok=False`), the scenario does not produce physical execution or contract drift. Including it in the detector's False Negative count penalizes the detector for an unexecuted attack, violating the decoupling of Intervention Delivery ($T_{\text{inject}}$) from Detector Alert ($\hat{Y}_{\text{phantom}}$). Excluding failed injections ensures that TPR reflects genuine detection sensitivity ($TPR = 6/6 = 1.0000$ instead of $6/7 = 0.8571$).
3. *From §1.1 (`evaluator.py` lines 804-825)*: When negative control scenarios are absent (e.g., $TN=0, FP=0$ as in `raw3/`), $FPR = \frac{FP}{FP+TN} = \frac{0}{0}$, which is undefined. Reporting $0.0$ would falsely assert an empirical false positive rate of zero. Returning `None` correctly signals that the rate cannot be estimated from the dataset.
4. *From §1.1 (`evaluator.py` lines 451-484)*: Baselines without telemetry traces did not execute active monitoring during the historical runs. Penalizing them with $FN=6, TPR=0.0$ would misrepresent telemetry collection gaps as detector failure. Classifying them as `telemetry_unavailable` / `NR` adheres to scientific reporting standards.
5. *From §1.1 (`comparison_table.py` lines 149-186, 227-249)*: Excluding unavailable detectors and unmeasured metrics from the candidate set for bolding ensures that missing values and zero-fallbacks cannot be bolded as "best". Formatting `None` as `\text{---}` in LaTeX and `---` in CSV conforms to publication guidelines.
6. *From §1.1 (`causal_validation.py` lines 282, 431)*: Defining aliases after function declarations ensures Python symbol resolution succeeds without circularity or forward-reference runtime errors.
7. *From §1.2*: All 64 evaluation tests, 357 causal engine tests, 177 sbom service tests, and 242 end-to-end tests execute and pass without regressions.

---

## 3. Caveats

- **Historical Raw Datasets**: In `research/datasets/raw3/`, all 6 completed runs are attack scenarios ($N_{\text{benign}} = 0$). Consequently, metrics requiring benign units (FPR, Precision, F1) are legitimately `None`. This is an inherent property of the raw dataset, not an evaluator limitation.
- **Bootstrap MTTD Sample Size**: For $N=6$, bootstrap percentile intervals provide an empirical dispersion estimate, but tight asymptotic guarantees require larger samples ($N \ge 30$). The report correctly discloses sample size and reports both median and IQR alongside the bootstrap interval.

---

## 4. Conclusion

The Milestone 3 implementation in `research/evaluation/metrics/evaluator.py`, `research/evaluation/metrics/comparison_table.py`, and `services/causal-engine/app/domain/causal_validation.py` is sound, mathematically defensible, and fully compliant with `PROJECT.md`, `EXPERIMENT_PROTOCOL.md`, and `ORIGINAL_REQUEST.md`.

**Verdict**: **APPROVE**

---

## 5. Verification Method

To independently reproduce and verify this assessment:

1. **Verify Research Evaluation Suite**:
   ```powershell
   python -m pytest research/evaluation/tests/ -v
   ```
   *Expected*: 64 passed.

2. **Verify Targeted Milestone 3 E2E Features**:
   ```powershell
   python -m pytest tests/e2e/test_tier1_features.py -k "Feature09 or Feature10 or Feature13 or Feature14 or Feature16" -v
   ```
   *Expected*: 25 passed.

3. **Verify Full E2E Test Suite (Tiers 1–4)**:
   ```powershell
   python -m pytest tests/e2e/ -v
   ```
   *Expected*: 242 passed.

4. **Verify Causal Engine Test Suite**:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -v
   ```
   *Expected*: 357 passed.

5. **Verify SBOM Service Test Suite**:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests -v
   ```
   *Expected*: 177 passed.

6. **Verify Wilson Score Exact Calculation**:
   ```powershell
   python -c "from research.evaluation.metrics.wilson_score import compute_ordinary_wilson_score; print(compute_ordinary_wilson_score(6, 6))"
   ```
   *Expected*: `(0.6096657120978346, 1.0)`.

---

## Quality Review Summary

- **Verdict**: APPROVE
- **Findings**:
  - No Critical findings.
  - No Major findings.
  - Minor note: In `generate_csv`, `None` values serialize as empty strings `""` for tabular spreadsheet/DataFrame parsers, whereas `format_csv_cell` serializes `None` as `---` for formatted textual export; both behaviors are tested and conformant with expectations.
- **Verified Claims**:
  - Failed injection runs excluded from TPR denominator: VERIFIED via `evaluator.py:323` and `test_tier1_features.py:456`.
  - Undefined metric denominators return `None`: VERIFIED via `evaluator.py:804` and `test_evaluator.py:244`.
  - Missing baselines report `telemetry_unavailable` / `NR`: VERIFIED via `evaluator.py:453` and `test_tier1_features.py:667`.
  - Prometheus missing data reports `unmeasured` / `None`: VERIFIED via `evaluator.py:361` and `test_tier1_features.py:700`.
  - Table outputs `\text{---}` in LaTeX and prevents unmeasured bolding: VERIFIED via `comparison_table.py:89` and `test_tier1_features.py:739`.
  - Forward-reference alias clean: VERIFIED via `causal_validation.py:282, 431` and 357 passing causal tests.
- **Coverage Gaps**: None within M3 scope.

---

## Adversarial Review & Challenge Summary

- **Overall Risk Assessment**: LOW

### Challenges

#### Challenge 1: Empty or Zero-Trial Input Batches
- **Assumption Challenged**: Evaluator could encounter a batch with 0 attack runs and 0 benign runs, or all failed injections.
- **Attack Scenario**: Calling `ScenarioEvaluator.evaluate([], {})` or calling with only failed injection runs.
- **Stress Test**: Tested with `compute_defensible_metrics([])` and `_build_report` with 0 counts.
- **Result**: Evaluator returns `EvaluationReport` with `tp=0, fn=0, tpr=None, fpr=None, precision=None, f1=None` without raising `ZeroDivisionError`.
- **Status**: PASS.

#### Challenge 2: Detector Metric Tie-Breaking in LaTeX Table Generation
- **Assumption Challenged**: Multiple detectors achieve the identical best numeric score (e.g. multiple achieving TPR=1.0).
- **Attack Scenario**: Both PHANTOM and another baseline have `tpr=1.0`.
- **Stress Test**: Checked `is_best = (best_val is not None and val is not None and abs(val - best_val) < 1e-9)`.
- **Result**: All detectors achieving the best score within numerical precision ($10^{-9}$) receive bold formatting without order-dependent suppression.
- **Status**: PASS.

#### Challenge 3: Small-Sample Bootstrap MTTD Stability
- **Assumption Challenged**: Non-parametric bootstrap with $N=1$ or $N=0$ could cause index errors or variance underflow.
- **Attack Scenario**: Passing 0 or 1 latency to `_compute_mttd_stats`.
- **Stress Test**: Evaluated `_compute_mttd_stats([10.0])` and `_compute_mttd_stats([])`.
- **Result**: For $N=1$, returns mean=10.0, median=10.0, IQR=0.0, bootstrap_ci=None. For $N=0$, returns all None.
- **Status**: PASS.
