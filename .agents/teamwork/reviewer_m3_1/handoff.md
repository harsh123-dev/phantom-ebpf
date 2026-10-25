# Review and Handoff Report — Milestone 3 (R4 & R5: Defensible Detection, Mapping & Statistical Uncertainty)

**Reviewer**: `reviewer_m3_1` (teamwork_preview_reviewer)  
**Parent / Caller**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Verdict**: **APPROVE**  
**Integrity Audit**: **PASS** (Zero integrity violations; genuine algorithmic implementations; no facades or hardcoded test values)

---

## 1. Observation

Direct, independent observations of the Milestone 3 implementation and verification outputs:

1. **Standard Ordinary Wilson Score Interval Implementation** (`research/evaluation/metrics/wilson_score.py`):
   - Implements `compute_ordinary_wilson_score(successes, trials, confidence=0.95)` with aliases `wilson_score_interval` and `wilson_score`.
   - Uses exact quadratic root formulation:
     $$\text{center} = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{margin} = \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}$$
     $$\text{lower} = \max(0.0, \text{center} - \text{margin}), \quad \text{upper} = \min(1.0, \text{center} + \text{margin})$$
   - Critical value $z$: uses `1.959963984540054` for 95% confidence (or SciPy `norm.ppf(0.975)` when available).
   - Direct execution of `wilson_score_interval(6, 6)` outputs `(0.6096657120978346, 1.0)`. Rounded to 4 decimal places, this is `(0.6097, 1.0)`, matching the protocol benchmark $[0.6096, 1.0000]$ within $\pm 0.0001$.
   - Handles $n=0$ by returning `(None, None)`.
   - Validates input boundaries: raises `ValueError` for $n < 0$, $k < 0$, or $k > n$.

2. **Non-Parametric Bootstrap Percentile Interval for MTTD** (`research/evaluation/metrics/evaluator.py`):
   - In `_compute_mttd_stats(mttd_values, n_bootstrap=2000, seed=42)`:
     - Resamples with replacement $B=2000$ times over true positive latencies.
     - Computes percentile bounds at $2.5\%$ (index 50) and $97.5\%$ (index 1950).
     - Reports `mttd_mean_s`, `mttd_median_s` (alias `mttd_p50_s`, `mttd_median`), `mttd_iqr_s` (alias `mttd_iqr`), `mttd_p95_s`, and `mttd_ci_bootstrap`.
     - Handles $n < 2$ by returning `bootstrap_ci = None` (preventing degenerate zero-width intervals on single-sample inputs).
     - Handles $n = 0$ by returning all `None`.

3. **Evaluator Integration & Denominator Defensibility** (`research/evaluation/metrics/evaluator.py`):
   - `is_failed_injection(r)` checks `inject_ok is False`, `r.error` substring matching (`"inject() returned False"`, `"inject() raised"`, `"inject_ok=False"`), inject phase notes, and scenario labels.
   - Failed injection runs are excluded from `tp`, `fn`, and `tpr` denominators in both PHANTOM and baseline evaluations.
   - Exclusions are tracked via `excluded_failed_injections` on `EvaluationReport` and serialized to dict.
   - When denominators are zero ($TP+FN=0$, $FP+TN=0$, or $TP+FP=0$), metrics $TPR$, $FPR$, $Precision$, and $F1$ return `None`, never defaulting to $0.0$ or $1.0$.
   - Wilson score interval is attached to `EvaluationReport.tpr_ci_wilson` (and property alias `tpr_wilson_ci`).
   - Baselines with missing telemetry are classified with `status="telemetry_unavailable"` (or `"task_mismatch_and_telemetry_unavailable"` for Trivy) with all performance metrics set to `None`.
   - Missing or all-zero Prometheus snapshots are classified with `overhead_status="unmeasured"` and `cpu_overhead_pct = None`.

4. **Comparison Table & Bolding Rules** (`research/evaluation/metrics/comparison_table.py`):
   - `format_latex_cell` renders `None` as `\text{---}`.
   - `format_csv_cell` renders `None` as `---`.
   - `_find_best` explicitly excludes detectors with `status` containing `"unavailable"` and reports with `overhead_status == "unmeasured"`, preventing unmeasured zeros or undefined fallbacks from being bolded in LaTeX tables.

5. **Independent Test Execution Results**:
   - `python -m pytest research/evaluation/tests/ -v`:
     `64 passed in 1.90s` (100% pass)
   - `python -m pytest tests/e2e/test_tier1_features.py -k "Feature11 or Feature12" -v`:
     `10 passed, 95 deselected in 0.14s` (100% pass)
   - `python -m pytest tests/e2e/test_tier1_features.py -k "TestFeature09" -v`:
     `5 passed, 100 deselected in 0.14s` (100% pass)
   - `python -m pytest tests/e2e/ -v`:
     `242 passed in 95.50s` (100% pass across all 4 tiers)
   - `.\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -q`:
     `357 passed in 41.02s` (100% pass)
   - `.\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests -q`:
     `177 passed in 1.64s` (100% pass)

---

## 2. Logic Chain

1. *From Observation 1*: The formula implemented in `compute_ordinary_wilson_score` is derived from the exact quadratic solution $(\hat{p}-p)^2 = z^2 \frac{p(1-p)}{n}$ without continuity correction. For $k=6, n=6$, the lower bound evaluates to $1 / (1 + z^2/6) = 0.6096657...$ with $z=1.95996398454$. Truncated arithmetic with $z=1.96$ yields $0.6096$, while full precision rounding yields $0.6097$. Tests in `test_tier1_features.py` assert `round(lower, 4) in (0.6096, 0.6097)` and `test_evaluator.py` asserts `lower == pytest.approx(0.6096, abs=0.001)`. Both precision levels are satisfied, adhering strictly to EXPERIMENT_PROTOCOL.md §7.1 and PROJECT.md Feature 11.
2. *From Observation 2*: Time-to-detect distributions are inherently right-skewed and non-normal. Reporting median and IQR provides non-parametric central tendency and dispersion, while a $B=2000$ percentile bootstrap interval on true positive latencies provides a distribution-free confidence bound. Using deterministic seeding (`seed=42`) ensures full reproducibility without Monte Carlo drift between test runs.
3. *From Observation 3*: Failed injections represent harness delivery failures where the workload did not receive the attack intervention. Counting them as false negatives would penalize detector sensitivity for scenario delivery bugs, violating experimental validity (EXPERIMENT_PROTOCOL.md §3.1). Excluded failed runs are accurately segregated, ensuring $TPR = 6/6 = 1.0$ on completed attacks with `excluded_failed_injections = 1`.
4. *From Observation 3 & 4*: When negative controls are absent ($FP+TN=0$), $FPR$ is mathematically undefined. Defaulting undefined rates to $0.0$ falsely certifies zero false alarms. Preserving `None` and formatting as `\text{---}` / `---` accurately reflects experimental limitations without fabricating performance claims.
5. *From Observation 5*: All 840 independent tests across the entire codebase (`research/evaluation/tests`: 64, `tests/e2e`: 242, `causal-engine`: 357, `sbom-service`: 177) pass cleanly with zero regressions.

---

## 3. Caveats

- **SciPy vs. Pure-Math Fallback**: `wilson_score.py` optionally imports SciPy for arbitrary quantiles, but defaults to exact standard constants for standard confidence levels (90%, 95%, 98%, 99%). This ensures environments without SciPy execute identically without degradation.
- **Reproducibility of Bootstrap**: Bootstrap resamples use Python's `random.Random(42)`. If external callers require custom seeds, the parameter is exposed in `_compute_mttd_stats`.
- **Baseline Telemetry**: Real raw datasets (`raw/`, `raw3/`) did not record live Falco daemon logs or Trivy runtime evaluations. Classifying them as `telemetry_unavailable` / `task_mismatch_and_telemetry_unavailable` is the scientifically honest representation, leaving comparative cells as `---`.

---

## 4. Conclusion

**Verdict: APPROVE**

Milestone 3 (R4 & R5: Defensible Detection, Mapping & Statistical Uncertainty) fully satisfies all requirements of `ORIGINAL_REQUEST.md`, `PROJECT.md`, and `EXPERIMENT_PROTOCOL.md`:
- Standard ordinary Wilson score interval without continuity correction is mathematically verified and tested.
- Non-parametric bootstrap percentile interval for MTTD ($B=2000$) with median and IQR reporting is verified and tested.
- Evaluator integration excludes failed injections, handles undefined denominators cleanly with `None`, attaches Wilson intervals, and classifies unavailable baselines and unmeasured overhead without fabrication.
- Zero integrity violations detected; zero regressions across 840 tests.

---

## 5. Verification Method

To independently verify this evaluation:

1. **Verify standard Wilson score math**:
   ```powershell
   python -c "from research.evaluation.metrics.wilson_score import wilson_score_interval; print(wilson_score_interval(6, 6))"
   ```
   *Expected output*: `(0.6096657120978346, 1.0)`

2. **Verify evaluation unit tests**:
   ```powershell
   python -m pytest research/evaluation/tests/ -v
   ```
   *Expected output*: 64 passed.

3. **Verify Milestone 3 E2E feature tests**:
   ```powershell
   python -m pytest tests/e2e/test_tier1_features.py -k "Feature09 or Feature10 or Feature11 or Feature12 or Feature14 or Feature15 or Feature16" -v
   ```
   *Expected output*: 35 passed.

4. **Verify full E2E test suite**:
   ```powershell
   python -m pytest tests/e2e/ -v
   ```
   *Expected output*: 242 passed.

5. **Verify causal engine and SBOM service regression suites**:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -q
   .\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests -q
   ```
   *Expected output*: 357 passed and 177 passed.

---

## Quality Review Summary

- **Correctness**: Ordinary Wilson score and bootstrap percentile formulas match literature definitions and protocol specifications. Failed injection filtering and undefined denominator handling prevent mathematical artifacts.
- **Completeness**: Evaluator outputs all required metric fields, confidence intervals, aliases, and serialization schemas.
- **Code Quality**: Clear type annotations, docstrings explaining statistical formulas, robust error handling for invalid arguments.
- **Regression Safety**: All 840 tests in the project pass.

## Adversarial Review & Challenge Summary

- **Overall Risk Assessment**: LOW
- **Assumption 1 (Sample size for bootstrap)**: Single-sample or zero-sample latency inputs could trigger `ZeroDivisionError` or degenerate zero-width intervals.
  - *Result*: Pass. `_compute_mttd_stats` returns `None` for $n < 2$.
- **Assumption 2 (Zero trials for Wilson score)**: $n=0$ trials could trigger division by zero in quadratic denominator.
  - *Result*: Pass. `compute_ordinary_wilson_score` returns `(None, None)` for $n=0$.
- **Assumption 3 (Negative controls absence)**: Datasets without benign runs (e.g., `raw3/`) could cause division by zero in FPR.
  - *Result*: Pass. `_build_report` checks `denom_fpr > 0 and fp is not None`, returning `None`.
- **Assumption 4 (Unmeasured baselines falsely winning comparison tables)**: Unmeasured 0.0% overhead or uncollected detector telemetry could be bolded as "best" in LaTeX tables.
  - *Result*: Pass. `comparison_table.py` filters out reports with `telemetry_unavailable` and `overhead_status == "unmeasured"` before selecting column minima/maxima.
