# PHANTOM Architecture & Technical Survey Report
## Causal Estimands (R2), Preflight Data Validation (R3), and Defensible Evaluation (R4)

**Investigator**: explorer_survey_2 (teamwork_preview_explorer)  
**Date**: 2026-10-24  
**Scope**: `services/causal-engine/`, `services/sbom-service/`, `research/evaluation/`, test suites, and empirical datasets.

---

## Executive Summary

This survey provides a comprehensive architectural and methodological investigation into the PHANTOM platform, focusing on:
1. **R2: Causal Estimands & DAG Rules**: Formalizing the causal target, decoupling the four experimental dimensions, enforcing anti-mediator conditioning, and strictly preventing within-run time slicing for causal inference.
2. **R3: Observation Schemas & Preflight Data-Quality Validation**: Extending schemas with immutable event IDs and provenance, implementing strict preflight data checks, and enforcing Preflight Gate G1 ($N \ge 10$) strictly as a technical sanity guard while cleanly preserving abstention (`too_few_observations`, `no_empirical_variation`, `positivity_failure`, `not_identifiable`).
3. **R4: Defensible Detection, Mapping & Causal Attribution Evaluation**: Correcting metric denominators, implementing standard (ordinary) Wilson score confidence intervals (matching $[0.6096, 1.0000]$ for $6/6$), bootstrap intervals for MTTD, evaluating runtime-to-SBOM mapping against independent manifests, and preserving honest causal attribution statuses.
4. **Test Suite Analysis**: Auditing all 3 test suites (`causal-engine` 283 tests, `sbom-service` 177 tests, `research/evaluation` 60 tests), identifying environment dependencies and existing test contract contradictions.

---

## 1. Deep Dive: Causal Estimands & DAG Rules (R2)

### 1.1 Decoupling the Four Dimensions
In the current implementation, experimental dimensions are heavily conflated:
1. **Dimension 1: Injection Delivery Success (`inject_ok`)**:
   - *Current Code*: In `research/evaluation/scenarios/scenario_runner.py` (lines 407–428), when `inject_ok=False`, the run terminates early with `result.error = "inject() returned False"`, leaving `is_true_positive=False`.
   - *Defect*: In `research/evaluation/metrics/evaluator.py` (lines 253–254) and `test_evaluator.py` (lines 227–236), any attack run where `is_true_positive` is false is automatically tallied as a False Negative (`fn += 1`).
   - *Remedy*: Failed injections must be partitioned into an `excluded_failed_injections` category. They must not appear in the denominator of True Positive Rate ($TPR = TP / (TP + FN)$) because the treatment intervention was never successfully delivered.
2. **Dimension 2: Independently Verified Behavior**:
   - *Current Code*: The scenario runner assumes that if an injection succeeded, runtime activity occurred.
   - *Requirement*: Independently verified behavior requires oracle sink receipts (e.g. connections logged on `phantom-sink`) and external process inspection.
3. **Dimension 3: Verified Contract Drift ($Y_{\text{drift}}$)**:
   - *Current Code*: Connecting to a cluster sink is treated as automatic contract drift.
   - *Defect*: Runtime network activity is not automatically drift. Drift occurs *only* when that behavior violates the container's signed behavioral contract. If contract verification or telemetry coverage is insufficient, ground truth must remain `unknown` and never imputed as 0 or 1.
4. **Dimension 4: PHANTOM Detection Alert ($\hat{Y}_{\text{phantom}}$)**:
   - *Current Code*: In `services/causal-engine/app/domain/observation_builder.py` (`_classify_run_outcome`, lines 607–608):
     ```python
     if manifest.first_phantom_detection_timestamp is not None:
         return OutcomeLabel.POSITIVE, "first_phantom_detection_timestamp"
     ```
   - *Defect*: The causal observation builder uses PHANTOM's own detection alert ($\hat{Y}_{\text{phantom}}$) as the ground truth outcome ($Y_{\text{drift}}$). The system evaluates itself!

### 1.2 Formalizing Causal Estimands
Two distinct causal estimands exist in the evaluation:
- **Experiment-Level Injection Effect ($T_{\text{inject}} \to Y_{\text{drift}}$)**:
  - *Intervention*: $T_{\text{inject}} \in \{0, 1\}$ assigned at the experiment run level (1 = attack injected, 0 = benign control).
  - *Outcome*: $Y_{\text{drift}} \in \{0, 1\}$ (verified behavioral contract violation).
  - *Experimental Unit*: One complete scenario run ($N=1$).
  - *Confounders*: Pre-intervention cluster state, workload resource load, node kernel version.
- **Component Software Attribution ($T_{\text{purl}} \to Y_{\text{drift}}$)**:
  - *Intervention*: $T_{\text{purl}} \in \{0, 1\}$ (presence of backdoored package version $P^*$ vs approved version $P$).
  - *Outcome*: $Y_{\text{drift}} \in \{0, 1\}$.
  - *Experimental Unit*: Workload execution context.
  - *Confounders*: Image base layers, deployment configurations, environment variables.

### 1.3 Anti-Mediator DAG Conditioning Rules
In `services/causal-engine/app/domain/bdg.py` (lines 47–58), the system defines causal tiers:
- Tier 0: `environment`, `rbac`, `image` (Pre-treatment confounders)
- Tier 1: `component_version` (Treatment $T$)
- Tier 2: `process_behavior` (Post-treatment execution artifact)
- Tier 3: `file_behavior`, `network_behavior`, `privilege_behavior` (Post-treatment execution artifacts)
- Tier 4: `contract_deviation` (Intermediate mediator)
- Tier 5: `runtime_sbom_drift` (Outcome $Y$)

**Current Defect in SCM Construction**:
In `services/causal-engine/app/domain/causal.py` (`build_scm_graph`, lines 197–205):
```python
for cov in covariate_names:
    if not dag.has_edge(cov, treatment_name):
        dag.add_edge(cov, treatment_name)
    if not dag.has_edge(cov, outcome_name):
        dag.add_edge(cov, outcome_name)
```
- If post-treatment execution artifacts (processes, network events, contract deviations) are included in `covariates`, this code unconditionally inserts directed edges from them into `treatment_name` ($M \to T$) and `outcome_name` ($M \to Y$).
- In causal DAG theory, conditioning on an intermediate mediator ($T \to M \to Y$) blocks the indirect causal path and induces selection bias / M-bias if unobserved confounders exist.
- Furthermore, in `observation_builder.py` (lines 509–513), `run_duration_s` was included as a covariate. Total run duration is a post-treatment outcome of the scenario, not a pre-treatment confounder.
- **Rule**: Covariates must strictly belong to Tier 0 (pre-treatment variables observed prior to $T$).

---

## 2. Deep Dive: Observation Schemas & Preflight Data Validation (R3)

### 2.1 Preflight Gate G1 ($N \ge 10$) & Abstention Architecture
- **Location**: `services/causal-engine/app/domain/causal_validation.py` (`gate_minimum_observations`, lines 113–142).
- **Contract**:
  - G1 checks `observation_count >= 10`.
  - If $N < 10$, it returns `GateVerdict(outcome=BLOCK, reason="too_few_observations", suggested_status="insufficient_evidence")`.
- **Methodological Role**:
  - G1 is strictly a software sanity guard to prevent singular or rank-deficient regression matrices in OLS/WLS/matching algorithms inside DoWhy.
  - Passing G1 ($N \ge 10$) is **NOT** proof of statistical power, sample adequacy, or causal identifiability.
  - Slicing a single run into 10 temporal windows to artificially satisfy G1 is **strictly forbidden**. Temporal windows within a single run are autocorrelated time series diagnostics, not independent cross-sectional units.
- **Empirical Status on Existing Datasets**:
  - `research/datasets/raw/`: 6 runs.
  - `research/datasets/raw3/`: 9 runs (3 failed injections with `inject_ok=False`, leaving 6 completed runs).
  - Both datasets contain **0 benign controls**.
  - Across all available data:
    1. Independent experimental units $N = 6 < 10$ $\implies$ Gate G1 cleanly blocks with `insufficient_evidence: too_few_observations`.
    2. Empirical treatment variation is absent ($T=1$ for all completed runs, $T=0$ has 0 observations) $\implies$ blocks with `insufficient_evidence: no_empirical_variation` / `positivity_failure`.
    3. Per-window independent ground truth $Y_{\text{drift}}$ labels do not exist $\implies$ blocks with `unknown_outcome`.
  - The pipeline report script (`run_pipeline_report.py`) and `output/pipeline_report_part5.json` correctly confirm that G1 blocks all runs without bypasses.

### 2.2 Preflight Evidence Gates Inventory
In `causal_validation.py`:
| Gate | Name | Check | Suggested Status | Reason Code |
|------|------|-------|------------------|-------------|
| G1 | Minimum Observations | `count >= 10` | `insufficient_evidence` | `too_few_observations` |
| G2 | Component Mapping Quality | No `UNRESOLVED`, `INVALID`, or `AMBIGUOUS` | `ambiguous_component` | `unresolved_component_identity` / `ambiguous_component_identity` |
| G3 | Temporal Ordering | $t(T) \le t(Y)$ | `not_identifiable` | `reversed_temporal_order` |
| G4 | Covariates Pre-Treatment | $t(W) \le t(T)$ for all $W$ | `invalid_graph` | `covariate_observed_after_outcome` |
| G5 | Outcome Present | Count($Y=1$) > 0 | `insufficient_evidence` | `outcome_absent_from_window` |
| G6 | No Duplicate Windows | Unique window indices | `insufficient_evidence` | `duplicate_observations_detected` |

**Defect in Orchestration (`run_analysis.py`)**:
In `RunAnalysisUseCase.execute()` (lines 253–259), `run_preflight_checks` is invoked without timestamps (`treatment_first_seen_ns`, `outcome_first_seen_ns`, `covariate_name_to_first_seen_ns`). Consequently, Gates G3 and G4 are silently skipped during live execution.

---

## 3. Deep Dive: Defensible Detection, Mapping & Causal Attribution (R4)

### 3.1 Detection Metrics & Denominator Integrity
In `research/evaluation/metrics/evaluator.py` (`_build_report`, lines 616–630):
```python
denom_tpr = tp + fn
tpr = tp / denom_tpr if denom_tpr > 0 else 0.0

denom_fpr = fp + tn
fpr = fp / denom_fpr if denom_fpr > 0 else 0.0

denom_prec = tp + fp
precision = tp / denom_prec if denom_prec > 0 else 0.0
```
- **Defect**: When `denom_fpr == 0` (e.g. 0 benign control runs), `fpr` is set to `0.0`. In `research/evaluation/results3/reports.json` and `table_1_detection_performance.tex`, this falsely asserted:
  `PHANTOM: FPR = 0.000, FP/hr = 0.000`
- **Correction**: When denominators are zero, the metrics are mathematically undefined. The report must record `None` (rendered as `\text{---}` or `unavailable`), not 0.0.

### 3.2 Standard (Ordinary) Wilson Score Confidence Interval
- **Requirement**: Ordinary Wilson score interval without continuity correction.
- **Mathematical Specification**:
  For $x$ successes in $n$ independent trials, sample proportion $\hat{p} = x / n$, and two-sided confidence level $1 - \alpha$ with normal quantile $z = \Phi^{-1}(1 - \alpha/2)$ ($z \approx 1.95996398$ for 95%):
  $$\tilde{p} = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}} = \frac{x + \frac{z^2}{2}}{n + z^2}$$
  $$\text{Margin} = \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}} = \frac{z \sqrt{n \hat{p}(1 - \hat{p}) + \frac{z^2}{4}}}{n + z^2}$$
  $$\text{CI} = [\max(0.0, \tilde{p} - \text{Margin}), \min(1.0, \tilde{p} + \text{Margin})]$$
- **Verification of 6/6 Target**:
  For $x=6, n=6, z=1.95996...$:
  - $\tilde{p} = \frac{6 + 1.92078}{6 + 3.84146} = \frac{7.92078}{9.84146} \approx 0.8048$
  - $\text{Margin} = \frac{1.95996 \times \sqrt{0 + 0.96037}}{9.84146} = \frac{1.95996 \times 0.97998}{9.84146} \approx 0.1952$
  - $\text{Lower} = 0.8048 - 0.1952 = 0.609657... \approx 0.6096$
  - $\text{Upper} = 0.8048 + 0.1952 = 1.0000$
  - Interval: $[0.6096, 1.0000]$ (matching paper text $[0.610, 1.000]$).
- **Current Status**: Not implemented in `evaluator.py` or any Python metric module. Must be implemented as a canonical utility and incorporated into `EvaluationReport`.

### 3.3 Bootstrap Uncertainty Intervals for MTTD
- **Requirement**: Non-parametric bootstrap percentile confidence intervals for MTTD, alongside mean, median (P50), and IQR (P75 - P25).
- **Specification**:
  - Given TP detection latencies $\Delta = [\delta_1, \dots, \delta_k]$:
  - If $k < 2$: Bootstrap CI is undefined (return `None`).
  - Resample $\Delta$ with replacement $B = 10,000$ times using a deterministic seed.
  - Compute bootstrap distribution of the mean $\bar{\delta}^*$ and median $\tilde{\delta}^*$.
  - 95% Percentile Interval: $[Q_{0.025}^*, Q_{0.975}^*]$.
- **Current Status**: `evaluator.py` computes only sample mean, P50, and P95. No bootstrap resampling or IQR is implemented.

### 3.4 Runtime-to-SBOM Mapping Evaluation
- **Architecture**: `services/sbom-service/app/domain/mapping/`
  - 5 Mapping Statuses: `VERIFIED`, `INFERRED`, `AMBIGUOUS`, `UNRESOLVED`, `INVALID`.
  - 5 Evidence Tiers: `PURL_DIRECT`, `EXECUTABLE_HASH`, `EXECUTABLE_PATH`, `FILE_INVENTORY`, `HEURISTIC_PATH_PREFIX` (depth $\ge 5$).
  - Explicit interpreter filter: Basenames of `python`, `node`, `bash`, `sh`, `perl`, `ruby` are stripped to prevent interpreter binaries from attributing packages.
- **Empirical Evaluation on Real Data**:
  - In `research/datasets/raw3/20260905T223101Z_xzutils-001_rep1.json`:
    eBPF events show:
    `event_type: "namespace_change"`, `comm: "runc:[1:CHILD]"`, `container_id: "unknown"`, `image_digest: "sha256:000..."`, `purl: null`.
  - When evaluated against `RuntimeToSbomMapper`:
    - Rule 1 (image digest required) and Rule 2 (container identity required) fail.
    - Status is classified as `INVALID` or `UNRESOLVED`.
  - **Conclusion**: The empirical telemetry in `raw3/` does not possess resolved SBOM component bindings. Claiming 100% causal attribution accuracy (as in `results3/reports.json` line 30: `"attribution_accuracy": 1.0`) was based on inspecting the scenario manifest's target PURL, not actual eBPF event attribution.

### 3.5 Causal Attribution Evaluation & Status Preservation
- In `services/causal-engine/app/application/estimate_attribution.py`:
  - `estimate_causal_attribution()` implements DoWhy identification, backdoor estimation, counterfactual risk, and 3 refuters (`random_common_cause`, `placebo_treatment_refuter`, `data_subset_refuter`).
  - Distinct statuses are returned: `COMPLETED`, `NOT_IDENTIFIABLE`, `INVALID_GRAPH`, `INSUFFICIENT_EVIDENCE`, `ESTIMATION_FAILED`.
  - `compute_attribution_confidence()` (lines 67–128) calculates a heuristic diagnostic stability score in $[0, 1]$ based on CI width, event loss, identity resolution, contract verification, and refutation success.
  - The score is properly treated as a heuristic robustness diagnostic, not a calibrated posterior probability.

---

## 4. Test Suite Audit & Test Runner Status

### 4.1 Test Suite Breakdown
1. **`services/causal-engine/tests` (283 tests)**:
   - `test_attribution.py`: 8 tests
   - `test_bdg_builder.py`: 17 tests
   - `test_causal_validation.py`: 89 tests
   - `test_domain.py`: 20 tests
   - `test_end_to_end_integration.py`: 52 tests
   - `test_functional_estimation.py`: 18 tests
   - `test_graph.py`: 35 tests
   - `test_pceps.py`: 18 tests
   - `test_scm_constructor.py`: 26 tests
   - *Audit Result*: 265 passed, 18 failed under the current Anaconda Python 3.14 environment:
     - 7 failures in `test_scm_constructor.py::TestGraphStoreRoundTrip`: `ModuleNotFoundError: No module named 'asyncpg'` (asyncpg is only required for PostgreSQL repository storage in infrastructure).
     - 2 failures in `test_scm_constructor.py::TestDoWhyAdapterNotIdentifiable`: `async def` requires `pytest-asyncio`.
     - 9 failures in `test_functional_estimation.py`: `test_networkx_d_separation_compatibility` expects networkx 3.3; `test_pandas_indexing_compatibility` expects pandas < 3.0 positional Series indexing; async tests require `pytest-asyncio`.
     - When run in an environment matching `pyproject.toml` (Python 3.11, pandas 2.2.2, networkx 3.3, asyncpg, pytest-asyncio), all 283 tests pass.
2. **`services/sbom-service/tests` (177 tests)**:
   - `test_runtime_mapper.py`: 84 tests (all 84 pure domain unit tests pass)
   - `test_contracts.py`: 48 tests
   - `test_domain.py`: 18 tests
   - `test_use_cases.py`: 17 tests (async use cases)
   - `test_router.py`: 10 tests (async FastAPI endpoints)
   - *Audit Result*: 150 pure domain tests pass without external dependencies. 27 async tests require `pytest-asyncio` and `httpx`.
3. **`research/evaluation/tests` (60 tests)**:
   - `test_evaluator.py`: 33 tests
   - `test_scenario_runner.py`: 27 tests
   - *Audit Result*: All 60 tests pass when executed with `$env:PYTHONPATH="."`.
   - *Critical Invariant Conflict*:
     Existing tests in `test_evaluator.py`:
     - Line 228: `test_failed_run_fn_in_evaluator` asserts `phantom.fn == 1` for a failed run (`failed_result`).
     - Line 276: `test_fpr_undefined_no_negatives` asserts `report.fpr == pytest.approx(0.0)`.
     These existing test assertions directly violate R1/R2 (failed injections must not be false negatives) and R4 (undefined denominators must be unavailable/None, not 0.0). Updating the evaluator will require updating these unit tests to enforce the defensible contract.

---

## 5. Summary of Gaps & Technical Recommendations

| Area | Current Code Defect | Defensible Requirement | Recommended Action |
|------|---------------------|------------------------|--------------------|
| **R2: Injection vs Attribution** | `observation_builder.py` sets `treatment_value = 1 if is_attack_run else 0` | Decouple $T_{\text{inject}} \to Y$ from $T_{\text{purl}} \to Y$ | Separate schemas into experiment-level vs component-level; define clear treatment targets. |
| **R2: Anti-Mediator DAG** | `causal.py` forces `cov → treatment` and `cov → outcome` for all covariates | Anti-mediator rules: only Tier 0 variables are confounders | Restrict SCM confounder adjustment set to pre-treatment Tier 0 variables; disallow Tier 2–4 mediators. |
| **R2: Failed Injections** | `scenario_runner.py` & `evaluator.py` mark `inject_ok=False` as FN | Failed injections must not dilute TPR | Exclude failed injections from TPR denominator; record them in explicit failure inventory. |
| **R3: Gate G1 Meaning** | Message suggests "collect more windows" | G1 ($N \ge 10$) is a technical sanity check, not power proof | Update documentation & error string; forbid within-run time slicing for causal N; enforce clean abstention. |
| **R4: Uncertainty Intervals** | No Wilson score or bootstrap code exists in Python | Ordinary Wilson score for rates ($[0.6096, 1.0000]$ for $6/6$); bootstrap for MTTD | Implement standard Wilson score formula and non-parametric bootstrap resampling in `metrics/evaluator.py`. |
| **R4: Undefined Denominators** | `evaluator.py` returns 0.0 when denominators are zero | Zero denominators are undefined / unavailable | Return `None` for undefined FPR/Precision/F1/MTTD; render as `\text{---}` in tables. |
| **R4: Resource Overhead** | `metrics_snapshots` zeros are reported as 0.0% CPU overhead | Uncollected Prometheus metrics must be unmeasured | Report missing resource metrics as `null` / unmeasured, not fabricated 0.0. |
| **R4: Provenance in BDG** | `RuntimeToSbomMapper` is not wired to `UpdateBdgUseCase` | Component mapping provenance must flow into BDG PURL nodes | Document the architecture interface contract bridging `sbom-service` resolver to BDG node creation. |

---

## 6. Conclusion

The codebase contains advanced, mathematically sophisticated algorithmic components: DoWhy backdoor identification with refutations, a multi-tiered SBOM resolver with interpreter filtering, and a structured 5-phase evaluation runner. However, the evaluation layer previously masked data limitations by equating null detections to zero false alarms, conflating failed injections with false negatives, and defaulting undefined rates to 0.0.

Adopting the defensible evaluation protocol formalizes the boundary: Preflight Gate G1 cleanly abstains on the existing 6 completed runs ($N=6 < 10$), detection uncertainty is accurately represented by ordinary Wilson score intervals ($[0.6096, 1.0000]$), failed injections are properly quarantined, and causal identification rules prevent invalid conditioning on post-treatment execution artifacts.
