# Handoff Report: R1 & R2 Investigation & Survey
**Agent ID**: `explorer_survey_1` (`teamwork_preview_spec_miner`)  
**Type**: Hard Handoff (Investigation & Specification Mining Complete)  
**Date**: 2026-10-24  
**Recipient**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Working Directory**: `d:\project-1\.agents\teamwork\explorer_survey_1`  
**Primary Artifact**: `d:\project-1\.agents\teamwork\explorer_survey_1\survey_report.md`

---

## 1. Observation

Direct empirical observations made from files, data structures, and command outputs:

1. **Raw Dataset Records (`research/datasets/raw/`)**:
   - `index.json` lists 6 scenario runs:
     ```json
     "results": [
       "20260823T201630Z_xzutils-001_rep1",
       "20260823T201938Z_dep-confusion-001_rep1",
       "20260823T202255Z_solarwinds-001_rep1",
       "20260823T202826Z_benign-update-001_rep1",
       "20260823T203128Z_benign-load-001_rep1",
       "20260823T203429Z_benign-restart-001_rep1"
     ]
     ```
   - Inspection of all 6 JSON files via `inspect_runs.py` revealed:
     - All 6 files have `phantom_detections: []` (`len == 0`).
     - All 6 files have `falco_detections: []` (`len == 0`).
     - All 6 files have `metrics_snapshots` where `cpu_usage_cores: 0.0`, `memory_rss_mb: 0.0`, `event_lag_p95_ms: 0.0`.
     - Attack runs (`xzutils-001`, `dep-confusion-001`, `solarwinds-001`) have `inject_notes: "inject_ok=True"`, `is_true_positive: False`, `mttd_s: null`.
     - Inspection of all 114 JSON files in `research/datasets/raw/` showed that exactly **0 files** have any phantom detections (`len == 0` for all 114 files).

2. **Raw3 Dataset Records (`research/datasets/raw3/`)**:
   - Exactly 9 JSON files exist:
     - 3 files for `solarwinds-001` (`rep1`, `rep2`, `rep3`), each 1,765–1,766 bytes:
       - Phase list truncated to: `["baseline", "inject"]`.
       - `phases[1].notes`: `"inject_ok=False"` (duration: ~126.7s, timeout in `kubectl rollout status`).
       - `error`: `"inject() returned False"`.
       - Detections: `phantom_detections: []`, `is_true_positive: False`, `mttd_s: null`.
     - 6 files for `xzutils-001` and `dep-confusion-001` (`rep1`, `rep2`, `rep3`), sizes 411 KB to 1.23 MB:
       - All 6 have `is_true_positive: True`, `phases: ['baseline', 'inject', 'attack', 'recover', 'post_recovery']`.
       - Detections count: xzutils rep1 (239), rep2 (654), rep3 (684); dep-confusion rep1 (720), rep2 (684), rep3 (720). Total = 3,701 detections.
       - MTTD values: `[70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247]`. Mean = 15.74s, median = 5.52s.
   - Analysis of all 3,701 drift detections via `telemetry_analysis.py`:
     - `pod_name`: `"unknown"` in 3,701 / 3,701 (100%).
     - `container_name`: `"unknown"` in 3,701 / 3,701 (100%).
     - `container_id`: `"unknown"` in 3,667 (99.08%), containerd ID in 34 (0.92%).
     - `image_digest`: `"sha256:0000000000000000000000000000000000000000000000000000000000000000"` in 3,701 / 3,701 (100%).
     - `sbom_id`: `null` in 3,701 / 3,701 (100%).
     - `purl`: `null` in 3,701 / 3,701 (100%).
     - `identity_status`: `"ambiguous"` in 3,667 (99.08%), `"missing"` in 34 (0.92%).
     - `event_type`: `"privilege_transition"` (2,555, 69.04%) and `"namespace_change"` (1,146, 30.96%). Zero process, network, or file events.
     - `event_loss_observed`: `false` in all 3,701 records.
     - `nodes`: `ip-172-31-5-170.ap-south-1.compute.internal` and `ip-172-31-22-173.ap-south-1.compute.internal`.
     - Controls: **0 benign control runs** exist in `raw3/`.

3. **Evaluation Pipeline Code & Configuration (`research/evaluation/`)**:
   - `research/evaluation/scenarios/scenario_runner.py`:
     - Lines 605–620: `_query` Prometheus fallback catches `Exception` and returns `0.0` for CPU, RSS, and lag on query failure.
   - `research/evaluation/metrics/evaluator.py`:
     - Lines 250–260: Benign runs with empty detections are counted as `TN = len(benign_results) - fp`. In `raw/`, all 3 benign runs had 0 detections due to collection failure, falsely producing TN=3.
     - Lines 291–293: Attribution accuracy requires `label.get("top_attributed_purl")`. In `raw3/`, `scenario_label` never populated this field.
     - Wilson score confidence intervals are not implemented in `evaluator.py`.
   - `research/evaluation/results3/reports.json`:
     - Line 34: `"notes": "Evaluated on 6 valid live eBPF kernel runs across 2 supply chain attack families (xzutils-001, dep-confusion-001)."`
     - Reports `n_attack_scenarios: 6, n_benign_scenarios: 0, tp: 6, fp: 0, fn: 0, tn: 0, precision: 1.0, recall: 1.0, f1: 1.0`. All benign scenarios and the 3 failed solarwinds runs were excluded.
     - Reports `cpu_overhead_pct: 0.0, memory_overhead_mb: 0.0, event_lag_p95_ms: 0.0` from the fallback zeros.

4. **Test Suites & Causal Runtime (`services/causal-engine` and `services/sbom-service`)**:
   - Pytest execution verified:
     - `services/causal-engine/tests`: 283 passed (in `.venv-causal` with Python 3.12, DoWhy 0.12.0).
     - `services/sbom-service/tests`: 177 passed (in `.venv-causal` with Python 3.12).
     - `research/evaluation/tests`: 60 passed (Python 3.14 / pytest 9.0).
   - `services/causal-engine/app/domain/causal_validation.py`:
     - Gate G1 (`gate_minimum_observations`): Enforces `observation_count >= minimum` (default 10). If $< 10$, blocks with `suggested_status="insufficient_evidence"`, `reason="too_few_observations"`.

---

## 2. Logic Chain

1. **From Observation 1**: Because every single file in `research/datasets/raw/` has `phantom_detections: []` despite attack scenarios executing and reporting `inject_ok=True`, detector telemetry collection was disconnected.
   - *Inference*: Absent detections in `raw/` cannot be treated as True Negatives for benign runs or False Negatives for attack runs. They represent collection dropouts.

2. **From Observation 2**: In `research/datasets/raw3/`, all 3 repetitions of `solarwinds-001` timed out during `kubectl rollout status` and returned `inject_ok=False`, while `xzutils-001` and `dep-confusion-001` completed injection and recorded detections.
   - *Inference*: The 3 `solarwinds-001` runs are Failed Injections, not detector false negatives. They cannot evaluate detection or causal attribution because the attack was never active in the pod.

3. **From Observation 2 & 3**: In `raw3/`, 3,701 drift detections were recorded across 6 attack runs, but 100% have `pod_name = "unknown"`, `sbom_id = null`, `purl = null`, and `identity_status = "ambiguous"`, with zero benign control runs ($N_{\text{benign}} = 0$).
   - *Inference*: Runtime-to-SBOM mapping failed upstream in the eBPF agent. While detection alerts fired, component attribution cannot be evaluated from these raw records without mocking or manual linkage. Furthermore, with $N_{\text{benign}} = 0$, reporting Precision=1.0 or FPR=0.0 is scientifically invalid because the false-positive denominator is zero.

4. **From Observation 3**: `ScenarioRunner.collect_metrics_snapshot` defaults to `0.0` when Prometheus queries fail.
   - *Inference*: Zero overhead in existing reports is an artifact of PromQL query failure, not evidence of zero resource consumption. These metrics must be recorded as unmeasured / unavailable.

5. **From Observation 4 & Causal Specifications**: In causal inference, an experimental unit must be an independent cross-sectional unit (one run = one unit).
   - *Inference*: Within-run temporal windows cannot be treated as independent observations to satisfy Preflight Gate G1 ($N \ge 10$). On the existing datasets ($N=6$ in `raw/`, $N=6$ completed in `raw3/`), Gate G1 must cleanly abstain with `status="insufficient_evidence"`, `reason="too_few_observations"`.

---

## 3. Caveats

1. **Underlying AWS EKS Cluster**: The evaluation cluster nodes (`ip-172-31-5-170`, `ip-172-31-22-173`) and PHANTOM services were running remotely during the August/September 2026 data collection runs. We examined the preserved raw telemetry JSON records; we did not execute new live attacks on the remote cluster (integrity mode is benchmark/read-only).
2. **Falco Configuration**: It is unknown whether Falco failed to fire because its default rules do not cover these supply chain behaviors or because the Falco collector file path was unmounted. The log file was simply empty (`falco_detections: []`).
3. **No Caveats on Telemetry Facts**: The run classifications, event counts, missing metadata, and code paths documented here are complete, verbatim, and mathematically exact.

---

## 4. Conclusion

1. **R1 Classification**:
   - `research/datasets/raw/` (N=6): 100% Telemetry Collection Dropout (3 attack, 3 benign). No True Negatives may be claimed.
   - `research/datasets/raw3/` (N=9): 3 Failed Injections (`solarwinds-001`), 6 Completed Attack Runs (`xzutils-001`, `dep-confusion-001`), 0 Benign Controls.
2. **R2 Protocol Decoupling**:
   - $T_{\text{inject}}$, $B_{\text{verified}}$, $Y_{\text{drift}}$, and $\hat{Y}_{\text{phantom}}$ must be strictly decoupled. Sink network traffic is runtime activity, not automatically drift; drift occurs only when runtime behavior violates the signed container contract. Unverified ground truth must remain `unknown`.
   - Causal estimands must distinguish intervention effect from component attribution, strictly enforcing anti-mediator conditioning rules.
   - Preflight Gate G1 ($N \ge 10$) is a technical sanity guard; existing datasets must cleanly abstain without artificial window inflation.

---

## 5. Verification Method

To independently verify all claims made in this report:

1. **Verify Raw and Raw3 Run Classifications**:
   ```powershell
   python d:\project-1\.agents\teamwork\explorer_survey_1\print_summary.py
   ```
   *Expected*: Prints the identical 6-row and 9-row tables matching §2.1 and §2.2 of `survey_report.md`.

2. **Verify Telemetry Dropouts and Metadata Missingness**:
   ```powershell
   python d:\project-1\.agents\teamwork\explorer_survey_1\telemetry_analysis.py
   ```
   *Expected*: Confirms 3,701 total detections, 100% unknown pod names, 100% null SBOM IDs/PURLs, and 100% event types restricted to `privilege_transition` and `namespace_change`.

3. **Verify All Project Test Suites**:
   ```powershell
   # 1. Evaluation tests (60 passed)
   python -m pytest research/evaluation/tests

   # 2. SBOM-service tests (177 passed)
   d:\project-1\.venv-causal\Scripts\pytest.exe services/sbom-service/tests

   # 3. Causal-engine tests (283 passed)
   d:\project-1\.venv-causal\Scripts\pytest.exe services/causal-engine/tests
   ```

4. **Invalidation Conditions**:
   - If any JSON file in `raw/` contains non-empty `phantom_detections`, observation 1 is invalidated.
   - If `raw3/` contains any benign scenario records, observation 2 is invalidated.
   - If any `solarwinds-001` run in `raw3/` has `inject_ok=True`, observation 2 is invalidated.
