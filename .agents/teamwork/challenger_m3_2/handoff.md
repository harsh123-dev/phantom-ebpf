# Milestone 3 Challenge Report: Evaluator & Comparison Table Stress-Testing

**Agent**: `challenger_m3_2` (teamwork_preview_challenger)  
**Parent**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Date**: 2026-10-24  
**Scope**: Adversarial verification and empirical stress-testing of `research/evaluation/metrics/evaluator.py` and `research/evaluation/metrics/comparison_table.py` against the real `raw3` dataset, missing baseline classification, table formatting, and bolding logic.  
**Verdict**: **APPROVE**

---

## 1. Observation

Direct examination and empirical test execution against `worker_m3`'s implementation yielded the following observations:

1. **Real `raw3` Dataset Execution & Exclusion Handling**:
   - `research/datasets/raw3/` contains 9 scenario runs:
     - 3 runs of `xzutils-001` (`rep1`, `rep2`, `rep3`): completed attacks with `is_true_positive=True`, valid telemetry.
     - 3 runs of `dep-confusion-001` (`rep1`, `rep2`, `rep3`): completed attacks with `is_true_positive=True`, valid telemetry.
     - 3 runs of `solarwinds-001` (`rep1`, `rep2`, `rep3`): failed injections containing `"error": "inject() returned False"` and `phases[1].notes: "inject_ok=False"`.
   - In `research/evaluation/metrics/evaluator.py` (`is_failed_injection`, lines 206–224), runs with `inject_ok=False`, `inject() returned False`, or `inject() raised` are detected.
   - When `ScenarioEvaluator().evaluate()` is run on all 9 runs in `raw3/`:
     ```python
     phantom.n_attack_scenarios == 6
     phantom.excluded_failed_injections == 3
     phantom.tp == 6
     phantom.fn == 0
     phantom.tpr == 1.0
     phantom.tpr_ci_wilson == (0.6097, 1.0)
     phantom.n_benign_scenarios == 0
     phantom.fp is None
     phantom.tn is None
     phantom.fpr is None
     phantom.precision is None
     phantom.f1 is None
     phantom.false_positives_per_hour is None
     phantom.overhead_status == "unmeasured"
     phantom.cpu_overhead_pct is None
     ```
   - All 3 failed injections (`solarwinds-001` repetitions 1–3) are excluded from the TPR denominator, yielding an exact denominator of 6, not 9.

2. **Baseline Telemetry Absence and Task Mismatch Classification**:
   - In `research/evaluation/metrics/evaluator.py` (`_evaluate_baseline`, lines 451–483):
     ```python
     is_trivy = "trivy" in detector_name.lower()
     if not detections:
         status = "task_mismatch_and_telemetry_unavailable" if is_trivy else "telemetry_unavailable"
         return EvaluationReport(
             detector_name=detector_name,
             n_attack_scenarios=len(valid_attack_results),
             n_benign_scenarios=len(benign_results),
             excluded_failed_injections=len(failed_attack_results),
             tp=None, fp=None, fn=None, tn=None,
             tpr=None, tpr_ci_wilson=None, fpr=None, precision=None,
             recall=None, f1=None, false_positives_per_hour=None,
             overhead_status="unmeasured",
             cpu_overhead_pct=None, memory_overhead_mb=None,
             event_lag_p95_ms=None,
             status=status,
             notes=status,
         )
     ```
   - For `falco-default-rules` and `isolation-forest-syscall-frequency`, `status` evaluates to `"telemetry_unavailable"` with all metrics set to `None`.
   - For `trivy-sbom-static`, `status` evaluates to `"task_mismatch_and_telemetry_unavailable"` with all metrics set to `None`.
   - At no point are missing baselines penalized with `fn=6` or `tpr=0.0`.

3. **Comparison Table & CSV Formatting**:
   - In `research/evaluation/metrics/comparison_table.py` (`format_latex_cell`, lines 89–96):
     ```python
     def format_latex_cell(val: float | None, precision: int = 3, is_best: bool = False) -> str:
         if val is None:
             return r"\text{---}"
         formatted = f"{val:.{precision}f}"
         if is_best:
             return rf"\textbf{{{formatted}}}"
         return formatted
     ```
   - In `format_csv_cell` (lines 99–104):
     ```python
     def format_csv_cell(val: float | None, precision: int = 4) -> str:
         if val is None:
             return "---"
         return f"{val:.{precision}f}"
     ```
   - In `generate_comparison_table` (lines 248–250), all undefined metrics across PHANTOM and baseline rows render verbatim as `\text{---}`.
   - In `generate_csv` (lines 307–311), `None` fields render as empty strings `""`, adhering to standard CSV parsing and notebook ingestion requirements.

4. **Adversarial Bolding Logic Stress-Testing**:
   - In `research/evaluation/metrics/comparison_table.py` (`_find_best`, lines 167–176 and `generate_comparison_table`, lines 241–247):
     ```python
     valid_reports = [
         r for r in reports
         if not (hasattr(r, "status") and "unavailable" in getattr(r, "status", ""))
     ]
     if "overhead" in field or "cpu" in field or "memory" in field:
         valid_reports = [
             r for r in valid_reports
             if getattr(r, "overhead_status", "measured") != "unmeasured"
         ]
     ...
     can_bold = not is_unavailable and not (is_field_overhead and is_unmeasured_overhead)
     ```
   - Stress-test with an unmeasured overhead report (`cpu_overhead_pct=0.0`, `overhead_status="unmeasured"`): excluded from `_find_best`, `can_bold` evaluates to `False`, never bolded.
   - Stress-test with an unavailable baseline with spoofed metrics (`tpr=1.0`, `status="telemetry_unavailable"`): excluded from `_find_best`, `can_bold` evaluates to `False`, never bolded.
   - Stress-test where all detectors have unmeasured overhead: `_find_best` returns `None`, no entries in the CPU column are bolded.

5. **Empirical Execution of 18 Adversarial Tests**:
   - Created `research/evaluation/tests/test_adversarial_challenger_m3.py` containing 18 stress test cases across real `raw3` data, formatting, bolding bypass attempts, and boundary inputs.
   - Result: 18 passed in 2.60s.
   - Full evaluation suite: `python -m pytest research/evaluation/tests/ -v`: 103 passed in 3.58s.
   - Target E2E Tier 1 suite: `pytest tests/e2e/test_tier1_features.py -k "Feature09 or Feature10 or Feature13 or Feature14 or Feature15 or Feature16" -v`: 30 passed in 0.20s.
   - Full E2E suite: `pytest tests/e2e/ -v`: 242 passed in 93.56s (100%).
   - Dedicated causal suite: `.\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -v`: 357 passed in 31.66s (100%).
   - Dedicated sbom suite: `.\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests/ -v`: 177 passed in 1.39s (100%).

---

## 2. Logic Chain

1. *From Observation 1*: `EXPERIMENT_PROTOCOL.md` §3.1 and `PROJECT.md` Feature 9 mandate that when an intervention fails to deploy (`inject_ok=False`), the run cannot evaluate detector sensitivity and must be excluded from the TPR denominator. The `raw3` dataset contains 3 such runs (`solarwinds-001` rep1–3). Empirical execution confirms `excluded_failed_injections == 3` and the TPR denominator is exactly $6$, producing $TPR = 6/6 = 1.0000$ with ordinary Wilson 95% confidence interval $[0.6096, 1.0000]$.
2. *From Observation 1*: In `raw3/`, no benign control scenarios were collected ($N_{\text{benign}} = 0$). Per `EXPERIMENT_PROTOCOL.md` §7 and `PROJECT.md` Feature 10, zero-denominator metrics must evaluate to `None` rather than fabricated `0.0`. Empirical execution confirms $FPR$, $Precision$, $F1$, and $FP/\text{hr}$ evaluate strictly to `None`.
3. *From Observation 2*: Under `EXPERIMENT_PROTOCOL.md` §3.2 and `PROJECT.md` Feature 14, detectors lacking collected telemetry must not be treated as true negatives ($TN$) or false negatives ($FN=6, TPR=0.0$). The empirical output confirms Falco, Trivy, and IsolationForest are classified as `telemetry_unavailable` or `task_mismatch_and_telemetry_unavailable` with all metric values `None`.
4. *From Observation 3*: Under `PROJECT.md` Feature 16, missing or unmeasured metrics must be rendered defensively. In LaTeX, `format_latex_cell(None)` outputs `\text{---}`, and `generate_comparison_table` formats all undefined cells as `\text{---}`. In CSV, `format_csv_cell(None)` renders `---`, and `generate_csv` emits clean, standard CSV representations.
5. *From Observation 4*: Under `PROJECT.md` Feature 16, unmeasured zeros (e.g. absence of Prometheus metrics) and missing baselines must never be bolded as optimal. The two-tier filtering in `_find_best` and `generate_comparison_table` ensures:
   - Detectors with `"unavailable"` in `status` are excluded from candidate pools and cannot bold.
   - Detectors with `overhead_status == "unmeasured"` are excluded from overhead candidate pools and cannot bold.
   - When all measurements are absent or unmeasured, no cell is bolded.

---

## 3. Challenge Report

### Challenge Summary
**Overall risk assessment**: **LOW**

The evaluator and comparison table implementations strictly satisfy all defensible statistical requirements, denominator handling rules, and formatting invariants.

### Challenges Tested

#### 1. [Low] SolarWinds Failed Injection Contamination
- **Assumption challenged**: Solarwinds-001 failed injection runs might inadvertently be counted as False Negatives, corrupting the TPR denominator.
- **Attack scenario**: Loaded and evaluated real `raw3` files containing 3 solarwinds failure runs.
- **Result**: PASSED. Solarwinds runs were recognized via `is_failed_injection()`, excluded from $TPR$ denominator ($TP=6, FN=0, N=6$), and recorded in `excluded_failed_injections=3`.

#### 2. [Low] Zero-Denominator Metric Defaulting
- **Assumption challenged**: Lack of benign control runs in `raw3` might trigger division-by-zero exceptions or default $FPR$ and $Precision$ to $0.0$.
- **Attack scenario**: Evaluated attack-only dataset without benign controls.
- **Result**: PASSED. $FPR$, $Precision$, $F1$, and $FP/\text{hr}$ cleanly evaluated to `None`.

#### 3. [Low] Missing Baseline Telemetry Penalization
- **Assumption challenged**: Baselines with empty detections might be scored as $FN=6, TPR=0.0$.
- **Attack scenario**: Passed empty detections dict for Falco, Trivy, and IsolationForest.
- **Result**: PASSED. Classified as `telemetry_unavailable` and `task_mismatch_and_telemetry_unavailable` with `None` across all metric fields.

#### 4. [Low] Unmeasured Overhead Bolding Exploit
- **Assumption challenged**: An unmeasured overhead reporting $0.0$ CPU overhead might be selected as the minimal (optimal) overhead and bolded in LaTeX.
- **Attack scenario**: Constructed adversarial evaluation reports where an unmeasured detector reported $0.0\%$ CPU overhead against a measured detector reporting $4.5\%$.
- **Result**: PASSED. Unmeasured report was excluded from `_find_best`, `can_bold` was disabled, and only the measured $4.5\%$ was eligible.

#### 5. [Low] Unavailable Baseline Bolding Exploit
- **Assumption challenged**: A baseline with `status="telemetry_unavailable"` but manually injected $TPR=1.0$ might be bolded in LaTeX.
- **Attack scenario**: Constructed adversarial report with unavailable status and $TPR=1.0$.
- **Result**: PASSED. Excluded from `_find_best`, `can_bold` was disabled, and no bold formatting was applied.

#### 6. [Low] Boundary Inputs Handling
- **Attack scenario**: Evaluated empty inputs, all-failed batches, benign-only batches, and single-observation bootstrap samples.
- **Result**: PASSED. Handled gracefully without unhandled exceptions.

### Unchallenged Areas
- Full end-to-end report pipeline generation (`run_pipeline_report.py`) and LaTeX document compilation belong to Milestone 4.

---

## 4. Caveats

- In `generate_csv`, `None` values are serialized as empty strings `""` per RFC 4180 standard to allow direct ingestion by CSV parsers (e.g., pandas `read_csv`), while the cell formatting function `format_csv_cell(None)` returns `"---"`. This dual behavior is intentional and verified by tests in Tier 1 and Tier 4.
- In `research/datasets/raw3`, no benign control scenarios were collected. All metrics depending on benign data ($FPR, Precision, F1$) correctly evaluate to `None`.

---

## 5. Conclusion

**Verdict: APPROVE**

Milestone 3's evaluation and table formatting components (`evaluator.py`, `comparison_table.py`, and `wilson_score.py`) are robust, defensible, and fully compliant with `PROJECT.md`, `EXPERIMENT_PROTOCOL.md`, and `ORIGINAL_REQUEST.md`:
1. Failed injections in `raw3` (3 solarwinds runs) are excluded from the TPR denominator, yielding an exact denominator of 6, $TPR = 1.0000$, and ordinary Wilson score interval $[0.6096, 1.0000]$.
2. Zero-denominator metrics ($FPR$, $Precision$, $F1$) cleanly preserve `None` on attack-only datasets.
3. Missing baseline telemetry is classified as `telemetry_unavailable` / `task_mismatch_and_telemetry_unavailable` with `None` metrics rather than fabricated zero recall.
4. Table generation renders `\text{---}` for `None` values in LaTeX, and `---` via `format_csv_cell`.
5. Bolding logic strictly rejects unmeasured overhead and unavailable baselines.
6. All 103 evaluation tests, 30 Tier 1 M3 tests, 242 E2E tests, 357 causal engine tests, and 177 sbom service tests pass cleanly (100%).

---

## 6. Verification Method

To independently reproduce the empirical challenge verification:

```powershell
# 1. Run the new adversarial stress test suite (18 passed)
python -m pytest research/evaluation/tests/test_adversarial_challenger_m3.py -v

# 2. Run all research evaluation tests (103 passed)
python -m pytest research/evaluation/tests/ -v

# 3. Verify Tier 1 M3 E2E feature tests (30 passed)
pytest tests/e2e/test_tier1_features.py -k "Feature09 or Feature10 or Feature13 or Feature14 or Feature15 or Feature16" -v

# 4. Verify full E2E test suite across Tiers 1-4 (242 passed)
pytest tests/e2e/ -v

# 5. Verify causal engine tests (357 passed)
.\.venv-causal\Scripts\python.exe -m pytest services/causal-engine/tests -v

# 6. Verify sbom service tests (177 passed)
.\.venv-causal\Scripts\python.exe -m pytest services/sbom-service/tests/ -v
```
