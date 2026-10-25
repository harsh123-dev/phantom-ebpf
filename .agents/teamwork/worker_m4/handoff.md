# Handoff Report: Milestone 4 (R6 - Deterministic Reporting & Comprehensive Documentation)

**Agent**: worker_m4  
**Role**: implementer, qa, specialist  
**Working Directory**: `d:\project-1\.agents\teamwork\worker_m4`  
**Parent**: orchestrator_1 (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Timestamp**: 2026-10-24T08:06:00Z  

---

## 1. Observation

### 1.1 Pre-Modification State
- Historical evaluation outputs in `research/evaluation/results3/reports.json`, `table_1_detection_performance.tex`, and `table_1_detection_performance.csv` contained fabricated metrics:
  - `fpr: 0.0`, `precision: 1.0`, `f1: 1.0`, `attribution_accuracy: 1.0` despite zero benign controls in `raw3/` ($N_{\text{benign}} = 0$) and 100% missing PURL/SBOM IDs in raw detections.
  - `cpu_overhead_pct: 0.0`, `memory_overhead_mb: 0.0`, `event_lag_p95_ms: 0.0` despite all Prometheus snapshots defaulting to 0.0 due to unhandled collection query errors.
  - `table_1_detection_performance.tex` contained bolded unmeasured zeros: `\textbf{0.000}`.
- `run_pipeline_report.py` was originally an initial Part 5 script executing only `RunAnalysisUseCase` on `raw/`, lacking integration with the hardened `ScenarioEvaluator`, Wilson score intervals, bootstrap MTTD, failed injection exclusions, schema v1.0.0, and comparison table emission.
- `EXPERIMENTAL_EVALUATION_README.md` was absent at the project root.

### 1.2 Implemented Changes
- **`run_pipeline_report.py`**:
  - Implemented deterministic CLI taking `--data-dir`, `--out`, and `--tables-dir`.
  - Reconstructs `ScenarioResult` objects via `_dict_to_scenario_result()` for each indexed run in the dataset.
  - Detects failed injections via `is_failed_injection()` and populates `exclusions` (excluding the 3 SolarWinds rollout timeouts from TPR denominators per `EXPERIMENT_PROTOCOL.md` §3.1).
  - Evaluates detection metrics with `ScenarioEvaluator`, computing standard ordinary Wilson score intervals (`tpr_ci_wilson`) and deterministic bootstrap MTTD intervals (`mttd_ci_bootstrap`, seed=42).
  - Emits versioned `reports.json` (schema v1.0.0) containing data quality summaries (`completed_attacks`, `failed_injections`, `collection_dropouts`, `benign_count`), `exclusions`, `metrics`, `overhead`, `baselines`, `limitations`, and the complete 10-item `claims_NOT_supported_by_this_data`.
  - Emits reproducible LaTeX and CSV comparison tables (`table_1_detection_performance.tex`, `table_1_detection_performance.csv`, `table_1_detection_performance_extended.tex`) via `write_tables()`, rendering `\text{---}` and `---` for unmeasured/undefined cells without bolding zeros.
- **`EXPERIMENTAL_EVALUATION_README.md`**:
  - Authored comprehensive guide at project root specifying offline-verified (`requires_docker = False`) vs. live-cluster (`requires_docker = True`, AWS EKS, eBPF daemonset, Prometheus) demarcation.
  - Specified five-phase scenario lifecycle (`baseline`, `inject`, `attack`, `recover`, `post-recovery`).
  - Documented pinned tool versions (Falco 0.44.1, Trivy 0.70.0).
  - Detailed dataset audit findings, failed injection disclosures, and step-by-step reproduction commands.
- **Output Artifacts**:
  - Populated `output/` and synchronized `research/evaluation/results3/` with `reports.json`, `table_1_detection_performance.tex`, and `table_1_detection_performance.csv`.

### 1.3 Execution & Verification Results
- `python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json`:
  - Exit code: 0
  - Output: `Comparison tables written to output`, `Report written to output\reports.json`
- `python run_pipeline_report.py --data-dir research/datasets/raw3 --out research/evaluation/results3/reports.json`:
  - Exit code: 0
  - Output: `Comparison tables written to research\evaluation\results3`, `Report written to research\evaluation\results3\reports.json`
- `python -m pytest tests/e2e/test_tier1_features.py -k "Feature17 or Feature18 or Feature19"`:
  - Exit code: 0
  - Result: `15 passed, 90 deselected in 32.67s`
- `python -m pytest tests/e2e/test_tier4_scenarios.py -k "Scenario3 or Scenario5"`:
  - Exit code: 0
  - Result: `7 passed, 14 deselected in 12.65s`
- `python -m pytest tests/e2e/test_tier2_boundaries.py -k "Feature17 or Feature18 or Feature19"`:
  - Exit code: 0
  - Result: `15 passed, 90 deselected in 21.46s`
- `python -m pytest tests/e2e/test_tier3_interactions.py -k "pipeline_report"`:
  - Exit code: 0
  - Result: `2 passed, 9 deselected in 13.58s`
- `python -m pytest tests/e2e/`:
  - Exit code: 0
  - Result: `242 passed in 66.17s` (100% pass across Tiers 1–4)
- `python -m pytest research/evaluation/tests/`:
  - Exit code: 0
  - Result: `103 passed in 3.51s` (100% pass)

---

## 2. Logic Chain

1. **Premise 1**: The original request (R6) and acceptance criteria mandate a deterministic reporting command producing a versioned `reports.json` (schema v1.0.0) and LaTeX/CSV tables rendering `\text{---}` / `---` for undefined metrics without bolding zeros.
2. **Premise 2**: Forensic audit findings in `EXPERIMENTAL_EVALUATION_AUDIT.md` proved that `raw3/` contains 6 completed attack runs ($TPR = 6/6 = 1.000$, Wilson 95% CI $[0.6097, 1.0000]$), 3 rollout timeouts (`solarwinds-001`, `inject_ok=False`), zero benign controls ($N_{\text{benign}} = 0$), and fallback zeros for Prometheus snapshots.
3. **Premise 3**: In `run_pipeline_report.py`, integrating `ScenarioEvaluator` with `_dict_to_scenario_result()` enables direct evaluation of raw JSON files from `raw3/` (or `raw/`), producing `EvaluationReport`s where:
   - Failed injections are cleanly identified and excluded from TPR denominators, with structured exclusion records in `exclusions`.
   - Wilson score intervals and bootstrap MTTD intervals are computed without heuristic approximations.
   - Undefined metrics ($FPR$, Precision, $F1$) remain `None` rather than fabricated zeros.
   - Baseline detectors (`falco-default-rules`, `trivy-sbom-static`, `isolation-forest-syscall-frequency`) are classified as `telemetry_unavailable` / `NR`.
   - Resource overhead is recorded as `unmeasured` / `null`.
4. **Premise 4**: Table generation via `write_tables()` formats LaTeX tables with `\text{---}` and CSV with `---` (and empty strings for DictReader compatibility), without bolding any unmeasured or fallback cells.
5. **Premise 5**: Authoring `EXPERIMENTAL_EVALUATION_README.md` at project root provides the required architectural demarcation between `offline_verified` (no Docker/root needed) and `live_cluster` execution, details the five-phase scenario lifecycle, and documents the 10 unsupported claims.
6. **Inference**: Executing the pipeline and running the full test suite confirms that all Milestone 4 acceptance criteria and E2E opaque-box tests pass with zero regressions.

---

## 3. Caveats

1. **Environment-Specific Async Packages**: As noted during unit testing, `pytest-asyncio` and `asyncpg` are not installed in the Windows Python 3.14 environment; async router unit tests in `services/sbom-service` and `services/causal-engine` require those packages when executed directly, which is explicitly disclosed in `EXPERIMENTAL_EVALUATION_README.md`.
2. **Dataset Bounds**: All empirical metrics reflect the actual data in `research/datasets/raw3/` (6 completed attacks, 3 failed SolarWinds injections, 0 benign runs); no synthetic benign runs were injected into raw datasets to artificially define FPR.
3. **No Caveats Beyond Above**: All requested features and contracts operate genuinely and deterministically.

---

## 4. Conclusion

Milestone 4 (R6: Deterministic Reporting & Comprehensive Documentation) is fully complete:
- `run_pipeline_report.py` implements the deterministic pipeline CLI emitting versioned `reports.json` (schema v1.0.0) and LaTeX/CSV tables.
- `EXPERIMENTAL_EVALUATION_README.md` is authored at the project root with full environment specifications, reproduction instructions, and limitation disclosures.
- `output/` and `research/evaluation/results3/` contain genuine, reproducible evaluation outputs and comparison tables.
- 100% of Milestone 4 test requirements and 100% of the entire E2E test suite (242/242 tests) pass cleanly.

---

## 5. Verification Method

To independently verify the implementation:

1. **Run the Deterministic Report Pipeline**:
   ```bash
   python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json
   ```
   Inspect `output/reports.json`, `output/table_1_detection_performance.tex`, and `output/table_1_detection_performance.csv`. Confirm `schema_version == "v1.0.0"`, `exclusions` contains 3 SolarWinds runs, `tpr_ci_wilson` is present, `fpr` is `null`, and LaTeX table contains `\text{---}` without bolded zeros.

2. **Verify Milestone 4 E2E Features**:
   ```bash
   python -m pytest tests/e2e/test_tier1_features.py -k "Feature17 or Feature18 or Feature19"
   ```
   Expected: 15 passed.

3. **Verify Scenarios 3 and 5**:
   ```bash
   python -m pytest tests/e2e/test_tier4_scenarios.py -k "Scenario3 or Scenario5"
   ```
   Expected: 7 passed.

4. **Verify Full E2E Test Suite**:
   ```bash
   python -m pytest tests/e2e/
   ```
   Expected: 242 passed.

5. **Invalidation Conditions**:
   - Any test failure in `tests/e2e/`.
   - Modifying `reports.json` to fabricate non-null FPR or bold unmeasured zeros in `table_1_detection_performance.tex`.
   - Bypassing failed injection exclusions from detection denominators.
