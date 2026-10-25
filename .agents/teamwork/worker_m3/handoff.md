# Handoff Report — Milestone 3 (R4 & R5: Defensible Detection, Mapping & Statistical Uncertainty)

## 1. Observation
1. **Wilson Score Specification**:
   - `EXPERIMENT_PROTOCOL.md` §7 specifies the ordinary Wilson score interval for binomial proportion without continuity correction:
     $$p^* = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}} \quad \text{and} \quad \Delta = \frac{z}{1 + \frac{z^2}{n}}\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}$$
   - For $k=6, n=6$ at 95% confidence ($z \approx 1.959963984540054$), the exact interval is $[0.6096, 1.0000]$.
   - `research/evaluation/metrics/wilson_score.py` was created to implement `wilson_score_interval(successes, trials, confidence=0.95)` and `wilson_score_lower_bound(successes, trials, confidence=0.95)`.
2. **Evaluator Defensible Denominator & Telemetry Rules**:
   - In `research/evaluation/metrics/evaluator.py`, failed injection runs (`inject_ok=False` or `is_failed_injection(r)`) previously counted towards False Negatives ($FN$), artificially deflating $TPR = TP / (TP + FN)$.
   - When denominators are 0 (e.g. no benign scenarios $TN + FP == 0$, or no positive predictions $TP + FP == 0$), metrics $FPR$, $Precision$, and $F1$ previously defaulted to `0.0` instead of `None`.
   - Baseline detectors (`falco-default-rules`, `trivy-sbom-static`, `isolation-forest-syscall-frequency`) with no alert telemetry or task mismatches previously reported $FN=6, TPR=0.0$.
   - Live Prometheus metrics when absent or all zeros were previously recorded as `0.0` CPU/Memory overhead.
   - Evaluator now excludes failed injections from TPR denominator, returns `None` for zero denominators, attaches Wilson score confidence intervals to `EvaluationReport.tpr_ci_wilson`, classifies missing baseline telemetry as `telemetry_unavailable` / `task_mismatch_and_telemetry_unavailable` with `None` values, marks unmeasured overhead as `overhead_status="unmeasured"`, and calculates non-parametric bootstrap percentile intervals for MTTD ($B=2000$).
3. **Table & CSV Formatting Rules**:
   - In `research/evaluation/metrics/comparison_table.py`, helper functions `format_latex_cell` and `format_csv_cell` are exported.
   - Missing or `None` values are formatted as `\text{---}` in LaTeX and `---` in `format_csv_cell`.
   - In `generate_csv`, `None` entries render as empty strings `""` for table ingestion.
   - In `_find_best` and `generate_comparison_table`, detectors with `status="telemetry_unavailable"` and unmeasured overhead are excluded from candidate pools for bolding best metrics.
4. **Causal Engine Forward Reference Check**:
   - `services/causal-engine/app/domain/causal_validation.py` line 431 contains:
     ```python
     gate_covariates_precede_treatment = gate_covariates_pre_treatment
     ```
     This alias is defined after `gate_covariates_pre_treatment` (lines 352-429). The previously suspected forward-reference at line 283 was already removed.
5. **Test Results**:
   - `python -m pytest research/evaluation/tests/ -v`:
     `64 passed in 1.69s` (100% pass)
   - `python -m pytest tests/e2e/ -v`:
     `242 passed in 72.46s` (100% pass)
   - `.\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -v`:
     `357 passed in 11.23s` (100% pass)

## 2. Logic Chain
1. *From Observation 1*: The exact formula without continuity correction produces lower bound $\frac{1 + \frac{1.95996^2}{12} - 1.95996\sqrt{\frac{1.95996^2}{144}}}{1 + \frac{1.95996^2}{6}} \approx 0.609635...$ which rounds to $0.6096$. Bounding the upper limit to $1.0$ guarantees $[0.6096, 1.0000]$ for 6/6 trials. Setting $n=0$ to return `(None, None)` handles zero-trial scenarios defensibly.
2. *From Observation 2*: Injections where the delivery payload failed (`t_inject=False` or `inject_ok=False`) cannot test detection capability because no runtime anomaly occurred; including them falsely increases $FN$ and corrupts causal validity. Therefore, filtering them out preserves the true $TPR=6/6=1.0000$ (with 95% Wilson interval $[0.6096, 1.0000]$) while recording `excluded_failed_injections=1`.
3. *From Observation 2*: When no benign scenarios exist, $FPR = FP / (FP + TN)$ has a denominator of zero. Reporting `0.0` would falsely claim zero false alarms rather than acknowledging the metric is undefined due to the absence of negative trials. Preserving `None` accurately reflects experimental bounds.
4. *From Observation 2 & 3*: Baselines that failed to run or lacked Prometheus telemetry should not be credited with $0\%$ CPU overhead or penalized with $TPR=0.0$. Classifying them as `telemetry_unavailable` and overhead as `unmeasured` avoids misleading tabular comparisons and prevents LaTeX tables from bolding absent measurements as "best".
5. *From Observation 4 & 5*: The alias in `causal_validation.py` is sound and non-circular, verified by 357 passing unit tests in `services/causal-engine/tests`. The full 242-test E2E suite and 64-test research evaluation suite pass cleanly without regressions.

## 3. Caveats
- Baseline execution in the raw dataset did not include active Falco or Isolation Forest telemetry daemons; they are therefore marked as `telemetry_unavailable`. If live sensor traces are added in future datasets, `evaluator.py` is designed to parse them seamlessly without modification.
- Bootstrap percentile intervals for MTTD with $B=2000$ use deterministic random seeding (`random.Random(42)`) when invoked to ensure reproducibility across test runs.

## 4. Conclusion
Milestone 3 (R4 & R5: Defensible Detection, Mapping & Statistical Uncertainty) is fully implemented, verified, and complete:
- Pure-math standard Wilson score interval implemented in `research/evaluation/metrics/wilson_score.py`.
- Defensible evaluation metrics implemented in `research/evaluation/metrics/evaluator.py`.
- LaTeX table and CSV formatting with robust bolding implemented in `research/evaluation/metrics/comparison_table.py`.
- Forward-reference check confirmed clean in `services/causal-engine/app/domain/causal_validation.py`.
- Unit tests updated and expanded in `research/evaluation/tests/test_evaluator.py`.
- All 64 evaluation tests and 242 end-to-end tests pass (100%).

## 5. Verification Method
To independently verify:
1. Run research evaluation unit tests:
   ```powershell
   python -m pytest research/evaluation/tests/ -v
   ```
   *Expected result*: 64 passed, 0 failed.
2. Run full end-to-end test suite:
   ```powershell
   python -m pytest tests/e2e/ -v
   ```
   *Expected result*: 242 passed, 0 failed.
3. Run causal engine domain tests:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests/ -v
   ```
   *Expected result*: 357 passed, 0 failed.
4. Verify Wilson interval calculation:
   ```powershell
   python -c "from research.evaluation.metrics.wilson_score import wilson_score_interval; print(wilson_score_interval(6, 6))"
   ```
   *Expected result*: `(0.6096, 1.0)`.
