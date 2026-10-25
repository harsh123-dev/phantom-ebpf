# Phase 5: Final Deterministic Reporting & Artifact Synchronization — Handoff Report

## 1. Observation

1. **Pipeline Execution Commands & Output**:
   - Executed: `python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json`
     - Exit code: 0
     - Output:
       ```
       Comparison tables written to output
       Report written to output\reports.json
       ```
   - Executed: `python run_pipeline_report.py --data-dir research/datasets/raw3 --out research/evaluation/results3/reports.json`
     - Exit code: 0
     - Output:
       ```
       Comparison tables written to research\evaluation\results3
       Report written to research\evaluation\results3\reports.json
       ```

2. **Artifact Inventory and Integrity**:
   - `output/reports.json`: 35,096 bytes; schema version `"v1.0.0"`. Contains mandatory top-level keys:
     - `schema_version`: `"v1.0.0"`
     - `data_quality`: `total_runs: 9`, `completed_attacks: 6`, `failed_injections: 3`, `collection_dropouts: 0`, `benign_count: 0`
     - `exclusions`: 3 entries (`20260905T231139Z_solarwinds-001_rep1`, `20260905T231616Z_solarwinds-001_rep2`, `20260905T232054Z_solarwinds-001_rep3`) with `reason: "failed_injection"` and `error: "inject() returned False"`
     - `metrics`: `tpr: 1.0`, `tpr_ci_wilson: [0.6097, 1.0]`, `fpr: null`, `precision: null`, `recall: 1.0`, `f1: null`, `mttd_mean: 15.74`, `mttd_median: 5.52`, `mttd_iqr: 4.37`, `mttd_p95: 54.72`, `mttd_ci_bootstrap: [3.57, 38.04]`, `tp: 6`, `fp: null`, `fn: 0`, `tn: null`
     - `overhead`: `status: "unmeasured"`, `cpu_overhead_pct: null`, `memory_overhead_mb: null`, `event_lag_p95_ms: null`
     - `baselines`: `falco-default-rules` (`telemetry_unavailable`), `trivy-sbom-static` (`task_mismatch_and_telemetry_unavailable`), `isolation-forest-syscall-frequency` (`telemetry_unavailable`)
     - `limitations`: 9 itemized entries covering DoWhy preflight G1 abstention, telemetry dropouts, zero benign controls, upstream identity collapse, unmeasured overhead, failed injection exclusions, and missing baseline telemetry.
     - `claims_NOT_supported_by_this_data`: 10 explicit unsupported claims listed verbatim.
   - `output/table_1_detection_performance.tex`: 858 bytes. Renders:
     ```latex
     \begin{table}[h]
     \centering
     \caption{Detection performance comparison across detectors and scenarios.}
     \label{tab:detection_performance}
     \begin{tabular}{lrrrrrr}
     \hline
     Detector & TPR & FPR & F1 & MTTD(s) & CPU\% & FP/hr \\
     \hline
     \textbf{PHANTOM (ours)} & \textbf{1.000} & \text{---} & \text{---} & \textbf{15.740} & \text{---} & \text{---} \\
     Falco (default rules) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
     Trivy (static scan) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
     IsoForest (na\"{i}ve) & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} & \text{---} \\
     \hline
     \end{tabular}
     \vspace{0.5em}
     \footnotesize{$\dagger$ MTTD is undefined for Trivy (point-in-time scanner). PHANTOM (ours) is the proposed system; all others are baselines.}
     \end{table}
     ```
   - `output/table_1_detection_performance.csv`: 435 bytes. Renders clean empty cells without unmeasured zeros for baseline/unmeasured values.
   - `output/table_1_detection_performance_extended.tex`: 1,419 bytes.
   - `research/evaluation/results3/reports.json`: 35,096 bytes. All keys and values identical to `output/reports.json` (excluding execution timestamp and ephemeral UUIDs).
   - `research/evaluation/results3/table_1_detection_performance.tex`: 858 bytes. Bitwise identical to `output/table_1_detection_performance.tex`.
   - `research/evaluation/results3/table_1_detection_performance.csv`: 435 bytes. Bitwise identical to `output/table_1_detection_performance.csv`.
   - `research/evaluation/results3/table_1_detection_performance_extended.tex`: 1,419 bytes. Bitwise identical to `output/table_1_detection_performance_extended.tex`.
   - Documentation files exist and are populated:
     - `EXPERIMENTAL_EVALUATION_README.md`: 17,681 bytes, 256 lines
     - `EXPERIMENTAL_EVALUATION_AUDIT.md`: 29,414 bytes, 360 lines
     - `EXPERIMENT_PROTOCOL.md`: 25,881 bytes, 356 lines

3. **Bitwise Determinism & Zero-Bolding Suppression**:
   - Running the pipeline twice into independent destination folders produced 100% bitwise identical files for `table_1_detection_performance.tex` (858 bytes), `table_1_detection_performance.csv` (435 bytes), and `table_1_detection_performance_extended.tex` (1,419 bytes).
   - In `table_1_detection_performance.tex`, undefined and unmeasured cells render as `\text{---}`, and zero bolding suppression prevents any bolding of fallback zeros. Only measured best values (`\textbf{1.000}` for TPR, `\textbf{15.740}` for MTTD) are bolded.
   - In `reports.json`, all statistical distributions, metrics, data quality counts, and limitations are completely deterministic across runs.

4. **Test Regression Suite Verification**:
   - `python -m pytest tests/e2e/ -v`:
     - Result: `389 passed in 105.82s (0:01:45)` across Tiers 1–5.
   - `python -m pytest research/evaluation/tests/ -v`:
     - Result: `114 passed in 81.66s (0:01:21)`.
   - Total tests executed and passed: 503 / 503 (100% pass rate).

## 2. Logic Chain

1. **Step 1 (Deterministic Pipeline Execution)**: The user request mandated running `run_pipeline_report.py` on `research/datasets/raw3` emitting to both `output/reports.json` and `research/evaluation/results3/reports.json`. As shown in Observation 1, both pipeline runs executed cleanly with exit code 0 and generated corresponding reports and comparison tables.
2. **Step 2 (Schema & Artifact Validation)**: Observation 2 verified that all 10 expected files exist with non-zero byte size. Structural JSON parsing confirmed schema `v1.0.0` compliance, including all 8 required top-level sections (`data_quality`, `exclusions`, `metrics`, `overhead`, `baselines`, `limitations`, `claims_NOT_supported_by_this_data`).
3. **Step 3 (Consistency & Determinism Check)**: Observation 3 compared table generation and report outputs across separate pipeline invocations and between target directories (`output/` vs `research/evaluation/results3/`). All LaTeX and CSV tables proved 100% bitwise identical. The JSON report proved completely identical in data values, summaries, and metrics (with differences confined strictly to the generation timestamp and per-run UUIDs).
4. **Step 4 (Zero-Bolding Suppression Verification)**: Observation 2 & 3 confirmed that in both main and extended tables, missing telemetry and unmeasured Prometheus metrics render as `\text{---}` rather than `0.000`, and no unmeasured zeros are bolded, satisfying the honest empirical presentation requirements.
5. **Step 5 (Comprehensive Regression Testing)**: Observation 4 confirmed that all 389 E2E tests (covering Tiers 1 through 5) and all 114 evaluation unit/adversarial tests pass without failure, confirming zero regressions across the evaluation framework.

## 3. Caveats

- In the current offline Windows execution environment without Docker daemon and PostgreSQL (`asyncpg`), unit tests in `services/causal-engine/tests/` requiring live `asyncpg` or `pytest-asyncio` plugin cannot be executed offline; this is explicitly documented in `EXPERIMENTAL_EVALUATION_README.md` under Mode 1 (Offline-Verified) vs Mode 2 (Live-Cluster) demarcation. All offline-verified E2E tests (`tests/e2e/`) and evaluation tests (`research/evaluation/tests/`) pass 100%.
- Per `EXPERIMENT_PROTOCOL.md`, `raw3/` contains 0 benign runs and 3 failed injections; thus FPR, Precision, and F1 remain `None` (`\text{---}`) by mathematical definition.

## 4. Conclusion

Phase 5: Final Deterministic Reporting & Artifact Synchronization is completely and successfully executed.
- All evaluation artifacts in `output/` and `research/evaluation/results3/` have been generated and synchronized deterministically.
- All schema requirements (v1.0.0) and honesty constraints (10 unsupported claims, 9 limitations, clean zero-bolding suppression) are strictly satisfied.
- 100% of required regression tests pass (389 e2e tests + 114 evaluation tests).

## 5. Verification Method

To independently verify this evaluation state:

1. **Verify pipeline execution and artifact synchronization**:
   ```bash
   python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json
   python run_pipeline_report.py --data-dir research/datasets/raw3 --out research/evaluation/results3/reports.json
   ```

2. **Verify bitwise table equivalence**:
   ```powershell
   fc.exe output\table_1_detection_performance.tex research\evaluation\results3\table_1_detection_performance.tex
   fc.exe output\table_1_detection_performance.csv research\evaluation\results3\table_1_detection_performance.csv
   ```

3. **Execute test regression checks**:
   ```bash
   python -m pytest tests/e2e/ -v
   python -m pytest research/evaluation/tests/ -v
   ```
