## 2026-10-24T07:00:07Z
You are worker_m3 (teamwork_preview_worker). Your working directory is d:\project-1\.agents\teamwork\worker_m3.
Your parent is orchestrator_1 (conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9).

MANDATORY: Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.
Read PROJECT.md at: d:\project-1\PROJECT.md.
Read EXPERIMENT_PROTOCOL.md at: d:\project-1\EXPERIMENT_PROTOCOL.md.
Read survey report at: d:\project-1\.agents\teamwork\explorer_survey_3\survey_report.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

EXCLUSIVE WRITE OWNERSHIP:
You own exclusively:
- research/evaluation/metrics/wilson_score.py
- research/evaluation/metrics/evaluator.py
- research/evaluation/metrics/comparison_table.py
- services/causal-engine/app/domain/causal_validation.py (fix forward-reference line 283)
- research/evaluation/tests/ (update test assertions)
Do NOT modify raw datasets or sbom-service files.

TASK DETAILS (Milestone 3: R4 & R5 - Defensible Detection, Mapping & Statistical Uncertainty):
1. Create `research/evaluation/metrics/wilson_score.py`:
   - Implement pure-math standard (ordinary) Wilson score interval without continuity correction.
   - Exact mathematical formula matching EXPERIMENT_PROTOCOL.md §7:
     Center: (p + z^2/(2n)) / (1 + z^2/n)
     Margin: (z / (1 + z^2/n)) * sqrt(p*(1-p)/n + z^2/(4n^2))
     Lower: max(0.0, center - margin)
     Upper: min(1.0, center + margin)
   - Must match [0.6096, 1.0000] for 6/6 at z=1.95996...
   - Handle n=0 gracefully (returns None or (None, None)).
2. Update `research/evaluation/metrics/evaluator.py`:
   - Exclude failed injections (`inject_ok=False`, e.g. solarwinds-001) from detection sensitivity (TPR) denominators.
   - Return None for FPR, Precision, and F1 when denominators are zero (e.g. FP + TN == 0, TP + FP == 0), rather than defaulting to 0.0 or 1.0.
   - Integrate Wilson score intervals for TPR and other binary rates.
   - Implement non-parametric bootstrap percentile interval for MTTD (B=2000 resamples), and report median and IQR alongside mean.
   - Baseline accounting: If baseline telemetry is absent (Falco, Trivy, IsoForest logs empty), classify as `telemetry_unavailable` / `NR` rather than False Negatives (FN=6, TPR=0.0).
   - Resource overhead: Record Prometheus CPU%, memory RSS MB, and event lag as unmeasured/null when Prometheus metrics are missing, not converted to 0.0.
3. Update `research/evaluation/metrics/comparison_table.py`:
   - Output `\text{---}` in LaTeX and `---` in CSV for None / undefined cells.
   - Fix bolding logic to prevent bolding unmeasured zeros or undefined fallbacks.
4. Fix forward-reference in `services/causal-engine/app/domain/causal_validation.py`:
   - Move line 283 (`gate_covariates_precede_treatment = gate_covariates_pre_treatment`) to after line 392 (e.g. line 425) where `gate_covariates_pre_treatment` is defined.
5. Update `research/evaluation/tests/test_evaluator.py`:
   - Update tests asserting old incorrect behavior (`test_failed_run_fn_in_evaluator` and `test_fpr_undefined_no_negatives`) to assert the new defensible behavior (failed injections excluded from TPR denominators; undefined denominators returning None).
6. Execute and verify all tests:
   - `python -m pytest research/evaluation/tests/ -v`
   - `pytest tests/e2e/ -v`
7. Author 5-component handoff report at `d:\project-1\.agents\teamwork\worker_m3\handoff.md` and send message to parent.
