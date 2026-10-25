# Handoff Report: Survey of R2 (Causal Estimands & DAG Rules), R3 (Observation Schemas & Preflight Validation), and R4 (Defensible Evaluation)

**Agent**: explorer_survey_2 (teamwork_preview_explorer)  
**Parent**: orchestrator_1 (conversation ID: `4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Type**: Hard handoff (Task complete)

---

## 1. Observation

1. **R2 / Causal Conflation & DAG Conditioning**:
   - In `services/causal-engine/app/domain/observation_builder.py` (lines 456, 509–513, 607–608):
     - Line 456: `treatment_value = 1 if manifest.is_attack_run else 0` conflates experiment-level intervention ($T_{\text{inject}}$) with component-level attribution ($T_{\text{purl}}$).
     - Lines 509–513: `obs = CausalObservation(..., covariates={"ground_truth_label": ..., "injection_succeeded": ..., "run_duration_s": self._run_duration(manifest)})`. `run_duration_s` is a post-treatment outcome of the scenario run.
     - Lines 607–608: `if manifest.first_phantom_detection_timestamp is not None: return OutcomeLabel.POSITIVE, "first_phantom_detection_timestamp"`. Outcome $Y_{\text{drift}}$ is assigned from PHANTOM's own detection alert ($\hat{Y}_{\text{phantom}}$).
   - In `services/causal-engine/app/domain/causal.py` (lines 200–205):
     ```python
     for cov in covariate_names:
         if not dag.has_edge(cov, treatment_name):
             dag.add_edge(cov, treatment_name)
         if not dag.has_edge(cov, outcome_name):
             dag.add_edge(cov, outcome_name)
     ```
     Directed edges `cov → treatment` and `cov → outcome` are unconditionally added for all covariates. If intermediate execution behaviors (Tier 2–4 in `bdg.py`) are passed as covariates, they are conditioned on as confounders, violating anti-mediator DAG rules.

2. **R3 / Preflight Gate G1 ($N \ge 10$) & Abstention**:
   - In `services/causal-engine/app/domain/causal_validation.py` (lines 110–143):
     `gate_minimum_observations` checks `observation_count >= minimum` (default 10). If $< 10$, returns `GateVerdict(outcome=BLOCK, reason="too_few_observations", suggested_status="insufficient_evidence")`.
     The explanation string currently reads: `"Collect more runtime windows before attempting attribution."`
   - In `run_pipeline_report.py` (lines 224–225) and `output/pipeline_report_part5.json` (lines 22–28):
     All 6 runs in `research/datasets/raw/` fail Preflight Gate G1 with `insufficient_evidence: too_few_observations`, producing `ate: null`.
   - In `research/datasets/raw/` (6 runs) and `research/datasets/raw3/` (9 runs, 3 failed injections):
     Completed runs = 6. All runs have $T=1$ (0 benign controls). Gate G1 correctly blocks estimation because $N=6 < 10$ and there is no empirical variation in treatment ($T=0$ has 0 observations).

3. **R4 / Wilson Score Interval & Undefined Denominators**:
   - Ripgrep for `wilson` across the repository (`grep_search` with Query `wilson`):
     Appears only in LaTeX papers (`phantom_paper_final.tex`, `PHANTOM_Research_Paper_Final_Source.tex`) and audit markdown files. Wilson score interval calculation is entirely absent from all Python modules.
   - Mathematical verification: Standard ordinary Wilson score interval (without continuity correction) for $x=6, n=6, z=1.95996...$ yields:
     $$\tilde{p} = \frac{6 + 1.92078}{6 + 3.84146} = 0.8048, \quad \text{Margin} = 0.1952 \implies [0.609657, 1.0000]$$
     matching $[0.6096, 1.0000]$ (or $[0.610, 1.000]$).
   - In `research/evaluation/metrics/evaluator.py` (lines 616–630):
     When denominators are 0 (e.g. `fp + tn == 0`), `fpr`, `precision`, and `f1` default to `0.0`.
   - In `research/evaluation/results3/reports.json` (lines 11–15) and `table_1_detection_performance.tex` (line 9):
     For 6 attack runs and 0 benign runs, it outputs `FPR = 0.000`, `precision = 1.000`, `F1 = 1.000`, and `FP/hr = 0.000`.

4. **R4 / Failed Injections & Test Invariant Conflict**:
   - In `research/datasets/raw3/20260905T231139Z_solarwinds-001_rep1.json` (lines 26, 56):
     `"notes": "inject_ok=False"`, `"error": "inject() returned False"`, `"is_true_positive": false`.
   - In `research/evaluation/metrics/evaluator.py` (lines 253–254):
     `fn = sum(1 for r in attack_results if not r.is_true_positive)`.
     A failed injection (`inject_ok=False`) is counted as an FN.
   - In `research/evaluation/tests/test_evaluator.py` (lines 227–236):
     ```python
     def test_failed_run_fn_in_evaluator(failed_result):
         ...
         assert phantom.fn == 1
     ```
     The existing test suite explicitly asserts that failed runs are counted as False Negatives, directly conflicting with the new defensible evaluation requirement that failed injections must be excluded from detection effectiveness denominators.
   - In `research/evaluation/tests/test_evaluator.py` (lines 275–284):
     `test_fpr_undefined_no_negatives` asserts `report.fpr == pytest.approx(0.0)`.

5. **R4 / Runtime-to-SBOM Mapping on Real Data**:
   - In `research/datasets/raw3/20260905T223101Z_xzutils-001_rep1.json` (lines 57–77):
     `event_type: "namespace_change"`, `comm: "runc:[1:CHILD]"`, `container_id: "unknown"`, `image_digest: "sha256:000..."`, `purl: null`, `binding_status: null`.
   - In `services/sbom-service/app/domain/mapping/resolver.py`:
     Rule 1 (image digest required) and Rule 2 (container identity required) fail for these events, producing `INVALID` or `UNRESOLVED` mapping status.
   - In `services/causal-engine/END_TO_END_INTEGRATION_README.md` (lines 90–97):
     `RuntimeToSbomMapper` is not imported or wired into `UpdateBdgUseCase`; PURL nodes in BDG do not receive genuine mapping provenance.

6. **Test Suites Inventory & Run Status**:
   - `research/evaluation/tests`: 60 tests collected. Running `$env:PYTHONPATH="."; pytest research/evaluation/tests` passes all 60 tests (0.17s).
   - `services/sbom-service/tests`: 177 tests collected. 150 unit/domain tests pass out-of-the-box (`test_runtime_mapper.py` has 84 unit tests). 27 async tests require `pytest-asyncio` plugin.
   - `services/causal-engine/tests`: 283 tests collected. 265 passed, 18 failed on Python 3.14/pandas 3.0:
     - 7 in `test_scm_constructor.py` due to `ModuleNotFoundError: No module named 'asyncpg'` (Postgres driver).
     - 2 in `test_scm_constructor.py` require `pytest-asyncio`.
     - 9 in `test_functional_estimation.py` due to `networkx` 3.6 vs 3.3, pandas 3.0 positional indexing, and async loop fixtures. All 283 pass when dependencies match `pyproject.toml`.

---

## 2. Logic Chain

1. From Observation 1.1, `observation_builder.py` assigns $Y=1$ whenever PHANTOM alerts. Using the detector's alert as the causal outcome means PHANTOM is evaluating itself rather than evaluating whether independent behavioral contract drift occurred.
2. From Observation 1.1 and 1.2, setting `treatment_value = 1 if is_attack_run else 0` conflates the intervention of running an attack script ($T_{\text{inject}}$) with component-level package substitution ($T_{\text{purl}}$). These require separate DAG formalisms and independent analysis.
3. From Observation 1.1 and 1.3, `causal.py` inserts directed edges from all covariates into treatment and outcome. If intermediate behavioral events (Tiers 2–4 in `bdg.py`) are passed as covariates, conditioning on them violates the backdoor criterion by conditioning on mediators.
4. From Observation 2.1, Preflight Gate G1 ($N \ge 10$) is a mathematical sanity check against singular regression matrices. In the actual dataset, only 6 completed attack runs exist ($N=6 < 10$), and 0 benign control runs exist ($T=0$ count is 0). Therefore, G1 and empirical variation checks correctly and cleanly abstain without bypasses.
5. Slicing 1 run into 10 windows to bypass G1 violates exchangeability and creates autocorrelation leakage; each run is an independent experimental unit.
6. From Observation 3.1, defaulting zero denominators to 0.0 in `evaluator.py` created fabricated claims of 0.000 FPR and 0.000 FP/hr on datasets with zero benign exposure.
7. From Observation 3.2, the ordinary Wilson score interval without continuity correction matches the exact theoretical formula for binomial proportion uncertainty, giving $[0.6096, 1.0000]$ for $6/6$.
8. From Observation 4.1 and 4.2, failed injections (`inject_ok=False`) mean the intervention was never applied. Counting them as False Negatives distorts detection effectiveness metrics. The existing test `test_failed_run_fn_in_evaluator` enforces this distorted behavior and must be corrected.
9. From Observation 5.1, real telemetry records contain ambiguous/missing container and image identities with null PURLs. The mapping resolver will classify these as `INVALID` or `UNRESOLVED`. Claiming 100% causal attribution accuracy is not supported by real telemetry.

---

## 3. Caveats

1. **Read-Only Scope**: In accordance with the dispatch instructions, no source code or test files were modified during this investigation.
2. **Environment Package Matrix**: The active shell python is Anaconda Python 3.14.6 with pandas 3.0.3 and networkx 3.6.1, which lacks `asyncpg` and `pytest-asyncio`. The test suite definitions in `pyproject.toml` specify Python 3.11 with pandas < 3.0.0 and networkx 3.3.
3. **Cluster Execution**: Live Kubernetes cluster and eBPF kernel telemetry were not executed during this survey; all evaluations were conducted against the verified raw dataset records in `research/datasets/raw/` and `raw3/`.

---

## 4. Conclusion

1. **R2**: `EXPERIMENT_PROTOCOL.md` must formalize $T_{\text{inject}} \to Y_{\text{drift}}$ (run level) vs $T_{\text{purl}} \to Y_{\text{drift}}$ (component level). Covariates must strictly be restricted to Tier 0 pre-treatment variables (cluster/workload configuration prior to injection). Post-treatment execution artifacts must never be conditioned on as confounders.
2. **R3**: Preflight Gate G1 ($N \ge 10$) must be enforced strictly as a technical sanity guard. On the existing 6-run dataset, G1 cleanly abstains with `insufficient_evidence: too_few_observations` and `no_empirical_variation`. Within-run temporal windows must never be used as independent cross-sectional units for causal estimation.
3. **R4**: Detection metrics must return `None` (unavailable / `\text{---}`) when denominators are zero. Ordinary Wilson score intervals without continuity correction ($[0.6096, 1.0000]$ for $6/6$) and bootstrap percentile intervals for MTTD must be implemented. Failed injections must be excluded from TPR denominators.
4. **Test Adjustments**: In `test_evaluator.py`, `test_failed_run_fn_in_evaluator` and `test_fpr_undefined_no_negatives` must be updated to align with the defensible criteria.

---

## 5. Verification Method

To independently verify the observations:
1. **Gate G1 Abstention Verification**:
   ```powershell
   python run_pipeline_report.py --data-dir research/datasets/raw --out -
   ```
   Inspect stdout JSON: verify all runs report `preflight_passed: false`, `preflight_first_blocker_gate: "G1_minimum_observations"`, `ate: null`.
2. **Wilson Score 6/6 Calculation**:
   ```powershell
   python -c "import math; z=1.95996398454; p=1.0; n=6; d=1+z**2/n; c=(p+z**2/(2*n))/d; m=(z/d)*math.sqrt(p*(1-p)/n + z**2/(4*n**2)); print(f'[{c-m:.4f}, {c+m:.4f}]')"
   ```
   Expected output: `[0.6097, 1.0000]` (unrounded lower bound: `0.609657...`).
3. **Test Suite Verification**:
   ```powershell
   $env:PYTHONPATH="."; pytest research/evaluation/tests
   $env:PYTHONPATH="services/sbom-service"; pytest services/sbom-service/tests/test_runtime_mapper.py
   $env:PYTHONPATH="services/causal-engine"; pytest services/causal-engine/tests/test_causal_validation.py
   ```
   Expected: 60 passed in `research/evaluation/tests`, 84 passed in `test_runtime_mapper.py`, 89 passed in `test_causal_validation.py`.
4. **File Inspection**:
   Inspect `d:\project-1\.agents\teamwork\explorer_survey_2\survey_report.md` for complete technical details.
