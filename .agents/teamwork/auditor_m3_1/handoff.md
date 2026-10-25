# Forensic Audit Report — Milestone 3 (Defensible Detection, Mapping & Statistical Uncertainty)

**Work Product**: Milestone 3 Implementations
- `research/evaluation/metrics/wilson_score.py`
- `research/evaluation/metrics/evaluator.py`
- `research/evaluation/metrics/comparison_table.py`
- `services/causal-engine/app/domain/causal_validation.py`
- `research/evaluation/tests/test_evaluator.py`

**Profile**: General Project (Integrity Mode: Benchmark)  
**Auditor**: `auditor_m3_1`  
**Verdict**: **CLEAN**

---

## 1. Observation

### 1.1 Static Analysis & Prohibited Pattern Scan
1. **Scan for Hardcoded Test Results and Return Values**:
   - Grep for `0.6096` across `research/evaluation`:
     - `research/evaluation/metrics/wilson_score.py:16`: docstring documentation only.
     - `research/evaluation/tests/test_evaluator.py:482,493`: test assertion only (`assert lower == pytest.approx(0.6096, abs=0.001)`).
     - No hardcoded string literals or return constants matching expected values exist in any production calculation.
   - Grep for scenario IDs (e.g. `solarwinds`) in `evaluator.py`:
     - 0 matches. Failed injections are detected purely via dynamic attributes (`r.inject_ok is False`, `r.error`, and phase notes), not scenario name filtering.
   - Grep for `NotImplementedError`, `TODO`, `FIXME`, or `pass` in `research/evaluation/metrics/` and `services/causal-engine/app/domain/causal_validation.py`:
     - 0 occurrences. No stubbed implementations or facade classes exist.

### 1.2 Mathematical Fidelity of Wilson Score Interval
1. **Formula Implementation in `research/evaluation/metrics/wilson_score.py` (lines 79–93)**:
   ```python
   n = float(trials)
   p = float(successes) / n
   z = _get_z(confidence)
   z2 = z * z

   denom = 1.0 + (z2 / n)
   center = (p + (z2 / (2.0 * n))) / denom

   variance_term = (p * (1.0 - p) / n) + (z2 / (4.0 * n * n))
   margin = (z / denom) * math.sqrt(max(0.0, variance_term))

   lower = max(0.0, center - margin)
   upper = min(1.0, center + margin)

   return (lower, upper)
   ```
2. **Empirical Execution Results**:
   - `k=6, n=6, confidence=0.95` ($z = 1.959963984540054$):
     `output: (0.6096657120978346, 1.0)`
     Four decimal places: `[0.6096, 1.0000]` (or `0.6097` rounded).
   - `k=0, n=6, confidence=0.95`:
     `output: (0.0, 0.39033428790216534)` $\implies [0.0000, 0.3904]$.
   - `k=5, n=10, confidence=0.95`:
     `output: (0.236593090512564, 0.7634069094874361)`.
   - `k=0, n=0`:
     `output: (None, None)`.
   - Input validation:
     `compute_ordinary_wilson_score(-1, 5)` $\to$ `ValueError: successes must be between 0 and 5, got -1`
     `compute_ordinary_wilson_score(6, 5)` $\to$ `ValueError: successes must be between 0 and 5, got 6`
     `compute_ordinary_wilson_score(3, -2)` $\to$ `ValueError: trials must be non-negative, got -2`

### 1.3 Anti-Cheating & Defensible Evaluation Rules
1. **Failed Injection Exclusion (`evaluator.py:206–224`)**:
   - `is_failed_injection()` checks `getattr(r, "inject_ok", None) is False`, errors matching `"inject() returned False"`, `"inject() raised"`, or phase notes.
   - In synthetic empirical testing with arbitrary scenario ID `custom-attack-002` where `inject_ok=False`, the failed run was excluded from the TPR denominator:
     `TP: 1, FN: 0, TPR: 1.0, excluded_failed_injections: 1`.
2. **Zero Denominator Handling (`evaluator.py:804–830`)**:
   - When no attack scenarios: `tpr=None`, `recall=None`, `tpr_ci_wilson=None`.
   - When no benign scenarios: `fp=None`, `tn=None`, `fpr=None`.
   - When no negative scenarios, Precision denominator $(TP+FP)$ cannot confirm false alarm absence, correctly yielding `precision=None` and `f1=None`.
   - When both attack and benign scenarios exist ($1\text{ TP}, 1\text{ TN}$):
     `tpr=1.0`, `fpr=0.0`, `precision=1.0`, `f1=1.0`.
   - Denominators of zero NEVER default to $0.0$ or $1.0$.
3. **Missing Baseline Telemetry Handling (`evaluator.py:452–483`)**:
   - If baseline detections list is empty:
     - Falco: `status="telemetry_unavailable"`, `tpr=None`, `fn=None`, `overhead_status="unmeasured"`.
     - Trivy: `status="task_mismatch_and_telemetry_unavailable"`, `tpr=None`, `fn=None`.
     - No fabricated False Negatives ($FN=6$) or fabricated zero true positive rates ($TPR=0.0$).
4. **Resource Overhead Accounting (`evaluator.py:352–376`)**:
   - If Prometheus snapshots are absent or all zeros:
     `overhead_status="unmeasured"`, `cpu_overhead_pct=None`, `memory_overhead_mb=None`, `event_lag_p95_ms=None`.
     No fabricated 0.0% overhead.
5. **Comparison Table LaTeX & CSV Formatting (`comparison_table.py`)**:
   - `format_latex_cell`: Renders `None` as `\text{---}`.
   - `format_csv_cell`: Renders `None` as `---`.
   - `generate_csv`: Renders `None` as empty strings for tabular data.
   - `_find_best`: Detectors with `status="telemetry_unavailable"` and unmeasured overhead are excluded from candidate pools, ensuring unmeasured or unavailable metrics are NEVER bolded.
6. **Causal Engine Preflight Validation (`causal_validation.py`)**:
   - `gate_minimum_observations`: Enforces $N \ge 10$ as minimum technical software sanity guard preventing rank-deficient regression matrices, explicitly disclaiming that passing implies statistical power or causal identifiability.
   - `gate_unique_run_ids`: Forbids window slicing (one run = one unit).
   - Line 431: `gate_covariates_precede_treatment = gate_covariates_pre_treatment` is cleanly defined after the referenced function.

### 1.4 Independent Test Suite Executions
1. `python -m pytest research/evaluation/tests/ -q`:
   `103 passed in 3.95s` (100% pass)
2. `python -m pytest tests/e2e/ -q`:
   `242 passed in 93.29s` (100% pass)
3. `.\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -q`:
   `357 passed, 927 warnings in 46.54s` (100% pass)

---

## 2. Logic Chain

1. *From Observation 1.1*: No hardcoded constants, expected values, or facade placeholders were identified in `wilson_score.py`, `evaluator.py`, `comparison_table.py`, or `causal_validation.py`. The codebase implements genuine computational logic satisfying Benchmark Mode integrity requirements.
2. *From Observation 1.2*: `wilson_score.py` computes the exact ordinary Wilson score confidence interval without continuity correction. For $k=6, n=6$ at $\alpha=0.05$ ($z \approx 1.959964$), the raw lower bound $\frac{1}{1 + z^2/6} = 0.6096657...$ satisfies the $[0.6096, 1.0000]$ bounds specified by `ORIGINAL_REQUEST.md` and `EXPERIMENT_PROTOCOL.md` §7.1. Invalid inputs and zero trials are handled deterministically without errors.
3. *From Observation 1.3*: Failed injection runs are filtered based on delivery status rather than hardcoded scenario names, correctly preserving $TPR=1.0$ on delivered attacks without falsely penalizing detector sensitivity for deployment harness errors. Zero denominators consistently return `None` rather than fabricating zero false alarms or zero detection capability. Missing baselines and Prometheus metrics cleanly abstain with `telemetry_unavailable` and `unmeasured`, preventing misleading comparative bolding in generated LaTeX tables.
4. *From Observation 1.3 & 1.4*: The forward-reference check in `causal_validation.py` is sound and non-circular. Preflight Gate G1 satisfies all protocol requirements. All 103 evaluation tests, 242 end-to-end tests, and 357 causal engine domain tests pass with 100% success.
5. *Synthesis*: Every forensic check mandated by the Integrity Forensics protocol passes empirically without exception.

---

## 3. Caveats

- In the current offline environment, baseline detectors (Falco, Trivy, IsolationForest) do not have live eBPF telemetry traces in the raw historical dataset; they are therefore defensively categorized as `telemetry_unavailable` / `task_mismatch_and_telemetry_unavailable`, and resource overhead is classified as `unmeasured`. This accurately reflects experimental realities without fabricating metrics.
- All tests were executed in the project virtual environments without internet access, ensuring full offline reproducibility.

---

## 4. Conclusion

**Verdict: CLEAN**

Milestone 3 implementations exhibit high integrity and strict adherence to the scientific requirements:
- Pure-math standard Wilson score interval implemented without continuity correction.
- Dynamic exclusion of failed injections based on delivery status.
- Defensible handling of undefined denominators (`None`).
- Honest accounting of unavailable baselines and unmeasured resource overhead.
- Defensible table formatting preventing bolding of unmeasured metrics.
- 100% test pass across evaluation, E2E, and causal-engine test suites.

Milestone 3 is **APPROVED** without reservation.

---

## 5. Verification Method

To independently verify this audit:

1. **Verify Wilson Score Mathematical Fidelity**:
   ```powershell
   python -c "from research.evaluation.metrics.wilson_score import compute_ordinary_wilson_score; res = compute_ordinary_wilson_score(6, 6); print(res); assert round(res[0], 4) in (0.6096, 0.6097); assert res[1] == 1.0"
   ```
   *Expected output*: `(0.6096657120978346, 1.0)` with exit code 0.

2. **Run Research Evaluation Unit & Adversarial Test Suites**:
   ```powershell
   python -m pytest research/evaluation/tests/ -v
   ```
   *Expected result*: 103 passed, 0 failed.

3. **Run Full Opaque-Box E2E Test Suite**:
   ```powershell
   python -m pytest tests/e2e/ -q
   ```
   *Expected result*: 242 passed, 0 failed.

4. **Run Causal Engine Domain Test Suite**:
   ```powershell
   .\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -q
   ```
   *Expected result*: 357 passed, 0 failed.
