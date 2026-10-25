# Tier 5 Adversarial Coverage Hardening: Evaluation, Metrics, and Reporting Components

**Agent ID**: `challenger_t5_2`  
**Working Directory**: `d:\project-1\.agents\teamwork\challenger_t5_2`  
**Milestone**: Phase 4 / Tier 5 Adversarial Coverage Hardening  
**Target Scope**: Evaluation, Metrics, Table Generation, and Reporting Pipeline CLI  

---

## 1. Observation

### 1.1 Direct File Observations
Forensic and white-box analysis was conducted on the four target implementation modules:
1. `research/evaluation/metrics/wilson_score.py` (lines 33–94):
   - Pure-math standard ordinary Wilson score interval implementation without continuity correction.
   - Formula center: `(p + (z2 / (2.0 * n))) / denom` where `denom = 1.0 + (z2 / n)`.
   - Formula margin: `(z / denom) * math.sqrt(max(0.0, variance_term))` where `variance_term = (p * (1.0 - p) / n) + (z2 / (4.0 * n * n))`.
   - Bounds: `lower = max(0.0, center - margin)`, `upper = min(1.0, center + margin)`.
   - Critical value `z` for 95% CI is hardcoded at `1.959963984540054`.
2. `research/evaluation/metrics/evaluator.py`:
   - `_compute_mttd_stats` (lines 718–761): Uses `statistics.mean`, `statistics.median`, `_safe_percentile`, and non-parametric bootstrap resampling (`n_bootstrap=2000`, `seed=42`). Correctly gates bootstrap CI with `if n < 2: bootstrap_ci = None`.
   - `_build_report` (lines 804–831): Preserves `None` when denominators are zero:
     - `denom_tpr = (tp + fn)`: returns `tpr = None`, `recall = None`, `tpr_ci_wilson = None` when `denom_tpr == 0`.
     - `denom_fpr = (fp + tn)`: returns `fpr = None` when `denom_fpr == 0`.
     - `denom_prec = (tp + fp)`: returns `precision = None` when `denom_prec == 0`.
     - `f1 = round(2.0 * precision * recall / (precision + recall), 4)` only when `precision is not None and recall is not None and (precision + recall) > 0`, else `f1 = None`.
     - `fp_per_hour = None` when `total_benign_s == 0`.
   - `is_failed_injection` (lines 206–225): Accurately filters failed injections across `r.inject_ok is False`, `r.error`, `phases.notes`, and `scenario_label.inject_ok`.
   - `_evaluate_baseline` (lines 452–484): Classifies baselines with empty detections as `telemetry_unavailable` (or `task_mismatch_and_telemetry_unavailable` for Trivy), returning `None` for all rates without fabricating False Negatives.
3. `research/evaluation/metrics/comparison_table.py`:
   - `_find_best` (lines 149–185): Ignores reports with `"unavailable"` in status. Filters out unmeasured overhead (`getattr(r, "overhead_status", "measured") != "unmeasured"`).
   - `generate_comparison_table` (lines 234–248): Enforces `can_bold = not is_unavailable and not (is_field_overhead and is_unmeasured_overhead)`. Cell formatting uses `format_latex_cell` rendering `None` as `\text{---}`.
   - `generate_csv` (lines 275–324): Formats missing fields as empty strings, preserving valid CSV column structure.
4. `run_pipeline_report.py`:
   - `_run_ids_from_index` (lines 113–125): Gracefully falls back from `index.json` to sorted file globbing.
   - `_dict_to_scenario_result` (lines 164–226): Reconstructs `ScenarioResult` with safe field defaults, detecting rollout timeouts and phase notes.
   - `main` (lines 258–267): Enforces exit code 1 on non-existent or empty directories. Catches per-run exceptions, logging `Processing failed: <exc>` into `runs` array while keeping overall CLI execution intact.

### 1.2 Test Execution Results
An adversarial test suite with 51 comprehensive tests was authored in `tests/e2e/test_tier5_metrics_adversarial.py`.
- First run (`pytest tests/e2e/test_tier5_metrics_adversarial.py`):
  - 35 passed, 16 failed initially due to:
    1. Numerical float precision: for $k=0, n=1000$, `lower` evaluated to $2.168404344971009 \times 10^{-19}$ rather than exact float `0.0`.
    2. Dataclass constructor signature: `ScenarioResult.__init__()` takes required positional arguments (`run_id`, `attack_id`, `attack_family`, `repetition`, `namespace`, `pod_name`, `ground_truth_label`) while `inject_ok` is assigned as an attribute.
    3. `Detection.__init__()` requires positional arguments `(detected_at, scenario_id, detector_name, confidence)`.
    4. Table bolding assertion checked the entire line containing `\textbf{0.000}` for FPR (best score) rather than isolating the CPU overhead column (which correctly suppressed bolding for unmeasured 0.0).
- Second run:
  - 50 passed, 1 failed (`Detection.__init__()` signature refinement).
- Third run:
  - **51 passed in 26.14s** (`pytest tests/e2e/test_tier5_metrics_adversarial.py`).
- Full E2E regression run:
  - Command: `pytest tests/e2e/`
  - Result: **387 passed in 115.61s** (Tiers 1, 2, 3, 4, 5).
- Service test suite preservation checks:
  - `python -m pytest research/evaluation/tests`: **114 passed in 87.90s**
  - `.\.venv-causal\Scripts\pytest services\causal-engine\tests`: **357 passed in 33.96s**
  - `.\.venv-causal\Scripts\pytest services\sbom-service\tests`: **177 passed in 1.53s**

---

## 2. Logic Chain

1. **Wilson Score Mathematical Rigor**:
   - Boundary tests for $k=0, n=1$ yield $[0.0, 0.7935]$ matching $z^2/(1+z^2) = 3.84146 / 4.84146 \approx 0.79346$.
   - Boundary tests for $k=1, n=1$ yield $[0.2065, 1.0]$.
   - For $k=6, n=6$ at 95% confidence, analytical lower bound is $0.609665712...$, exactly matching $[0.6096, 1.0000]$ (or $0.6097$ rounded).
   - Invariant symmetry $l(k, n) = 1 - u(n-k, n)$ holds to $10^{-7}$ across arbitrary fractions.
   - Monotonic expansion across confidence levels 0.90, 0.95, 0.98, 0.99 verified.
   - Exception handling: $n=0$ returns `(None, None)`; $n < 0$, $k < 0$, and $k > n$ strictly raise `ValueError`.

2. **Bootstrap MTTD Stability**:
   - For empty lists, all 5 MTTD metrics return `None` without `ZeroDivisionError`.
   - For single values ($n=1$), mean=median=p95=val, IQR=0.0, and bootstrap CI returns `None` (requiring $n \ge 2$).
   - For identical values (zero variance), bootstrap CI collapses to exact `(val, val)` without division by zero.
   - For heavy-tailed distributions with extreme outliers, bootstrap CI bounds the empirical mean deterministically with fixed seed (`seed=42`).

3. **Denominator Preservation & Attribution**:
   - In datasets without negative controls ($N_{\text{benign}}=0$), `ScenarioEvaluator` sets `fp = None, tn = None`, propagating to `fpr = None, precision = None, f1 = None`. It never fabricates 0.0 or 1.0.
   - When positive predictions are zero ($TP=0, FP=0$), `precision` is `None`.
   - When recall and precision are zero, `f1` is `None` without `ZeroDivisionError`.
   - Failed injection exclusions: All 5 signatures (`inject_ok=False`, error substrings, phase notes, scenario labels) are strictly excluded from the TPR denominator and tallied under `excluded_failed_injections`.
   - Telemetry dropouts (delivered attacks with dropped telemetry) are correctly counted as FN ($TPR=0.0$).

4. **Table Formatting and Unmeasured Overhead Suppression**:
   - When overhead status is `"unmeasured"`, `_find_best` filters out the detector, and `can_bold` suppresses bolding. Even if CPU overhead defaults to `0.0`, the cell is rendered as `0.000` without `\textbf{}`.
   - Baselines with missing telemetry render `\text{---}` in LaTeX and `---` in CSV, with zero bolding.

5. **Reporting Pipeline Robustness**:
   - Corrupted JSON records in the dataset directory do not crash `run_pipeline_report.py`. The CLI logs run-level errors and completes with valid JSON.
   - Missing fields in scenario dictionaries are safely handled by `_dict_to_scenario_result`.
   - Synthetic datasets with 100% failed injections correctly report `tpr = None`, `excluded_failed_injections = N`.
   - Synthetic datasets with 100% telemetry dropouts correctly report `tpr = 0.0`, `collection_dropouts = N`.

---

## 3. Caveats

1. **Floating Point Rounding in Wilson Score Lower Bound**:
   - For $k=0$ and large $n$ (e.g. $n=1000$), `center - margin` evaluates to $2.1684 \times 10^{-19}$ due to IEEE 754 floating point arithmetic instead of exact float `0.0`. Tests must use `math.isclose(lower, 0.0, abs_tol=1e-9)` or round to decimal precision. This does not affect rounded reporting (4 or 5 decimal places).
2. **DoWhy Platform Requirement**:
   - As audited in `CAUSAL_RUNTIME_AUDIT.md`, `services/causal-engine` tests require `.venv-causal` (Python 3.12 with asyncpg and dowhy). In Python 3.14 on Windows, `_check_dowhy()` in `run_pipeline_report.py` cleanly detects the absence of DoWhy and logs honest limitation notes without crashing.

---

## 4. Conclusion

All components in the Evaluation, Metrics, Table Generation, and Reporting CLI pipeline have been rigorously stress-tested against boundary conditions, corrupt data, zero denominators, and extreme numerical distributions. Zero unhandled exceptions or invalid bolding artifacts remain.

**Verdict**: **APPROVE**

---

## 5. Verification Method

### 5.1 Run the New Tier 5 Adversarial Test Suite
```powershell
pytest tests/e2e/test_tier5_metrics_adversarial.py -v
```
*Expected Result*: 51 passed.

### 5.2 Run the Entire E2E Test Suite (Tiers 1–5)
```powershell
pytest tests/e2e/
```
*Expected Result*: 387 passed.

### 5.3 Run Component and Service Test Suites
```powershell
python -m pytest research/evaluation/tests/
.\.venv-causal\Scripts\pytest services\causal-engine\tests/
.\.venv-causal\Scripts\pytest services\sbom-service\tests/
```
*Expected Results*:
- `research/evaluation/tests`: 114 passed
- `services/causal-engine/tests`: 357 passed
- `services/sbom-service/tests`: 177 passed

### 5.4 Invalidation Conditions
The verification is invalidated if:
1. `compute_ordinary_wilson_score(6, 6)` produces a lower bound outside $[0.6096, 0.6097]$.
2. Zero-negative scenarios produce non-None values for FPR, Precision, or F1.
3. Unmeasured CPU/memory overhead ($0.0$) is wrapped in `\textbf{}` in generated LaTeX comparison tables.
4. `run_pipeline_report.py` raises an unhandled traceback when encountering a corrupted JSON file.
