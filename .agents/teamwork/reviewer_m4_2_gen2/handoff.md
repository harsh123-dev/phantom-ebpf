# Independent Review & Adversarial Critic Report: Milestone 4 (R6)

**Agent**: reviewer_m4_2_gen2  
**Role**: reviewer, critic  
**Target Milestone**: Milestone 4 (R6: Deterministic Reporting & Comprehensive Documentation)  
**Target Work Products**: `EXPERIMENTAL_EVALUATION_README.md`, `run_pipeline_report.py`, `research/evaluation/metrics/comparison_table.py`, `output/reports.json`, `output/table_1_detection_performance.tex`, `output/table_1_detection_performance.csv`  
**Timestamp**: 2026-10-24T10:55:00Z  

---

## 1. Observation

### 1.1 Documentation Verification (`EXPERIMENTAL_EVALUATION_README.md`)
- **Offline vs. Live Demarcation**:
  - `EXPERIMENTAL_EVALUATION_README.md` lines 26–53 explicitly demarcate between:
    - **Mode 1 (`offline_verified`)**: Evaluates authentic raw JSON telemetry records (`raw/` $N=6$, `raw3/` $N=9$ runs), executes `run_pipeline_report.py`, requires standard Python without container or root privileges (`requires_docker = False`).
    - **Mode 2 (`live_cluster`)**: Multi-node Kubernetes cluster (AWS EKS v1.28–v1.30 or bare-metal Linux), kernel >= 5.15 with BTF (`CONFIG_DEBUG_INFO_BTF=y`), live Prometheus v2.45+, pinned detector tooling (Falco 0.44.1, Trivy 0.70.0, IsolationForest), requiring root privileges.
- **Five-Phase Scenario Lifecycle**:
  - Lines 89–125 document the 5 phases: Phase 1: `baseline` (60s–120s), Phase 2: `inject` (`inject_ok` verification), Phase 3: `attack` (60s–180s, enforced detection window), Phase 4: `recover` (rollback/mitigation), Phase 5: `post-recovery` (50s–60s stabilization).
- **Unsupported Claims**:
  - Lines 183–198 enumerate the authoritative list of 10 claims that CANNOT be made from the existing datasets:
    1. Detection rate (TPR / recall) on `raw/`
    2. False positive rate (FPR) on `raw3/` ($N_{\text{benign}} = 0$)
    3. Precision on `raw3/`
    4. F1 score on `raw3/`
    5. Mean time to detection (MTTD) on `raw/`
    6. Causal attribution accuracy (CAA) on `raw3/`
    7. PCEPS Brier score
    8. CPU/memory overhead (fallback zeros)
    9. Real-data average treatment effect (ATE) (Preflight Gate G1 failure $N < 10$)
    10. Any comparison to baseline detectors from this run batch
- **Reproduction Commands**:
  - Lines 200–241 provide exact reproduction commands for pipeline execution and testing across datasets (`raw3/` and `raw/`).

### 1.2 Table & Report Formatting Verification (`output/`)
- **`output/table_1_detection_performance.tex`**:
  - LaTeX table structure inspected: lines 1–17 define standard tabular environment with column spec `\begin{tabular}{lrrrrrr}`.
  - Line 9: `\textbf{PHANTOM (ours)} & \textbf{1.000} & \text{---} & \text{---} & \textbf{15.740} & \text{---} & \text{---} \\`
  - Lines 10–12: Missing baselines (Falco, Trivy, IsoForest) render `\text{---}` for all metric columns.
  - Footnote present at line 16: `\footnotesize{$\dagger$ MTTD is undefined for Trivy (point-in-time scanner). PHANTOM (ours) is the proposed system; all others are baselines.}`
  - No unmeasured zeros are bolded (`\textbf{0.000}` does not appear).
- **`output/table_1_detection_performance.csv`**:
  - CSV header contains 20 columns: `detector_name,tpr,fpr,precision,recall,f1,mttd_mean_s,mttd_p50_s,mttd_p95_s,cpu_overhead_pct,memory_overhead_mb,false_positives_per_hour,attribution_accuracy,brier_score,tp,fp,fn,tn,n_attack_scenarios,n_benign_scenarios`.
  - Empty cells are formatted as empty strings for standard CSV parser compatibility, while CLI print renders `---`.
- **`output/reports.json`**:
  - Validated schema `schema_version: "v1.0.0"`.
  - Contains `data_quality`: `total_runs: 9, completed_attacks: 6, failed_injections: 3, collection_dropouts: 0, benign_count: 0`.
  - Contains `exclusions`: 3 records for SolarWinds rollout timeouts (`solarwinds-001_rep1`, `rep2`, `rep3`), with `reason: "failed_injection"` and notes citing `EXPERIMENT_PROTOCOL.md` §3.1.
  - Contains `metrics`: `tpr: 1.0`, `tpr_ci_wilson: [0.6097, 1.0]`, `fpr: null`, `precision: null`, `f1: null`, `mttd_mean: 15.74`, `mttd_ci_bootstrap: [3.57, 38.04]`.
  - Contains `overhead`: `status: "unmeasured"`, `cpu_overhead_pct: null`.
  - Contains `baselines`: Falco, Trivy, and IsoForest with `status: "telemetry_unavailable"` and `tpr: null`.
  - Contains all 10 items in `claims_NOT_supported_by_this_data`.

### 1.3 Implementation Inspection & Integrity Audit
- **`run_pipeline_report.py`**:
  - Evaluates actual runs via `_run_ids_from_index()` and `_dict_to_scenario_result()`.
  - Accurately integrates `ScenarioEvaluator.evaluate()` and `CausalObservationBuilder` + `RunAnalysisUseCase`.
  - No hardcoded test outputs or dummy facades detected.
- **`research/evaluation/metrics/comparison_table.py`**:
  - In `_find_best()` (lines 150–186): explicitly filters out reports with `status` containing "unavailable" and overhead with status "unmeasured", ensuring unmeasured zeros or missing values are never evaluated as candidates for bold formatting.
  - In `generate_comparison_table()` (lines 234–250): `can_bold` is set to `False` for unavailable detectors and unmeasured overhead metrics, preventing false bolding. Missing values render as `\text{---}` via `format_latex_cell()`.

### 1.4 Test Suite Execution
- **Command 1**: `python -m pytest research/evaluation/tests/`
  - Output: `103 passed in 4.11s`
  - Exit code: 0
- **Command 2**: `python -m pytest tests/e2e/`
  - Output: `242 passed in 90.26s` across all tiers (Tiers 1–4)
  - Exit code: 0
- **Command 3**: Adversarial evaluation on `research/datasets/raw`:
  - `python run_pipeline_report.py --data-dir research/datasets/raw --out output/test_raw_report.json`
  - Exit code: 0; successfully handled total telemetry dropout runs without uncaught exceptions, reporting `collection_dropouts` and `\text{---}` appropriately.

---

## 2. Logic Chain

1. **Requirement & Standard**: R6 mandates deterministic pipeline reporting emitting `reports.json` (v1.0.0) and LaTeX/CSV tables, alongside `EXPERIMENTAL_EVALUATION_README.md` clearly demarcating offline-verified vs. live-cluster requirements, detailing the 5-phase scenario lifecycle, and listing unsupported claims.
2. **Observation Alignment**:
   - `EXPERIMENTAL_EVALUATION_README.md` at project root provides thorough, accurate coverage of all required sections, including the demarcation between `requires_docker = False` and live cluster operations, the 5 lifecycle phases, the 10 unsupported claims, and reproduction commands.
   - `output/table_1_detection_performance.tex` and `.csv` accurately reflect the empirical state of `raw3/`: $TPR = 1.000$ (Wilson CI $[0.6097, 1.0000]$), with undefined $FPR$, $F1$, and overhead metrics formatted as `\text{---}` rather than fabricated zeros, and zero instances of unmeasured bolded zeros.
   - Missing baselines (Falco, Trivy, IsolationForest) are handled cleanly without runtime exceptions, labeled as `telemetry_unavailable` / `NR`.
   - The test suites in `research/evaluation/tests/` (103/103) and `tests/e2e/` (242/242) pass with 100% success.
3. **Adversarial Assessment**:
   - Stress testing `run_pipeline_report.py` against both `raw3/` and `raw/` verified deterministic outputs, lack of crash on dropouts, and proper exclusion accounting.
   - No integrity violations, hardcoded test shortcuts, facades, or self-certifying bypasses were discovered.
4. **Deduction**: The implementation fully satisfies all requirements of Milestone 4 (R6) and complies with the scientific integrity standards of the project.

---

## 3. Caveats

1. **Live Cluster Execution**: Full live cluster execution (Mode 2) with real kernel eBPF probes and live Prometheus scraping requires Linux kernel >= 5.15 with BTF support, AWS EKS/bare-metal Kubernetes, and root privileges. Offline reproduction (Mode 1) is verified and passes completely on the local environment without these requirements, which is explicitly disclosed in `EXPERIMENTAL_EVALUATION_README.md`.
2. **Dataset Scarcity**: Current empirical metrics derive exclusively from the 9 runs in `raw3/` (6 completed attacks, 3 rollout timeouts, 0 benign runs). As documented, $FPR$, Precision, and $F1$ remain undefined due to lack of benign controls.

---

## 4. Conclusion

**Verdict**: **`APPROVE`**

Milestone 4 (R6: Deterministic Reporting & Comprehensive Documentation) meets all scientific defensibility standards, architectural guidelines, and test requirements. The documentation is honest and exhaustive, the deterministic pipeline operates flawlessly, and the comparison tables render cleanly without fabricating unmeasured metrics.

---

## 5. Verification Method

To independently reproduce the review verification:

1. **Inspect Documentation**:
   - View `d:\project-1\EXPERIMENTAL_EVALUATION_README.md` and verify Section 2 (offline vs. live cluster demarcation), Section 3 (five-phase scenario lifecycle), Section 6 (10 unsupported claims), and Section 7 (reproduction commands).

2. **Verify Table & Report Outputs**:
   - View `d:\project-1\output\table_1_detection_performance.tex` and verify `\text{---}` formatting for undefined cells and missing baselines.
   - View `d:\project-1\output\reports.json` and verify `schema_version == "v1.0.0"`, `exclusions` (3 SolarWinds runs), `overhead: {status: "unmeasured"}`, and `claims_NOT_supported_by_this_data`.

3. **Run Pipeline Command**:
   ```bash
   python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json
   ```
   Verify exit code 0 and valid emission to `output/`.

4. **Execute Test Suites**:
   ```bash
   python -m pytest research/evaluation/tests/
   python -m pytest tests/e2e/
   ```
   Verify 103 passed in `research/evaluation/tests/` and 242 passed in `tests/e2e/`.

5. **Invalidation Conditions**:
   - Bolding unmeasured zero overhead (`\textbf{0.000}`) in `table_1_detection_performance.tex`.
   - Modifying `reports.json` to report non-null FPR or CAA on `raw3/`.
   - Any test failure in `tests/e2e/` or `research/evaluation/tests/`.
