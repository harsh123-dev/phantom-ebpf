# Handoff Report: Milestone 1 (R1 & R2)
**Agent ID**: `worker_m1` (`teamwork_preview_worker`)  
**Type**: Hard Handoff (Milestone 1 Complete)  
**Date**: 2026-10-24  
**Recipient**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Working Directory**: `d:\project-1\.agents\teamwork\worker_m1`  
**Primary Deliverables**:
- `d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md` (R1)
- `d:\project-1\EXPERIMENT_PROTOCOL.md` (R2)

---

## 1. Observation

Direct empirical observations made from files, data structures, and command outputs:

1. **Dataset Records in `research/datasets/raw/`**:
   - `index.json` contains 6 results: `20260823T201630Z_xzutils-001_rep1`, `20260823T201938Z_dep-confusion-001_rep1`, `20260823T202255Z_solarwinds-001_rep1`, `20260823T202826Z_benign-update-001_rep1`, `20260823T203128Z_benign-load-001_rep1`, `20260823T203429Z_benign-restart-001_rep1`.
   - In addition to `index.json` and the 6 indexed runs, there are 107 legacy scenario JSON files (dates: 44 from `20260808`, 21 from `20260818`, 42 from `20260823`), totaling 114 JSON files in the directory.
   - Across **all 113 scenario JSON files** in `research/datasets/raw/`:
     - `len(phantom_detections) == 0` (100% empty list).
     - `len(falco_detections) == 0` (100% empty list).
     - `cpu_usage_cores: 0.0`, `memory_rss_mb: 0.0`, `event_lag_p95_ms: 0.0` in all metrics snapshots.
     - 87 legacy files had `inject_ok=True`, and 20 had `inject_ok=False` (e.g. `Command '['kubectl', 'cp', ...] returned non-zero exit status 1`).

2. **Dataset Records in `research/datasets/raw3/`**:
   - Exactly 9 scenario JSON files exist (batch from `2026-09-05T22:31:01Z` to `2026-09-05T23:25:00Z` in namespace `phantom-eval`).
   - 3 files for `solarwinds-001` (`rep1`, `rep2`, `rep3`), each 1,765–1,766 bytes:
     - Truncated phases: `["baseline", "inject"]`.
     - Phase notes: `inject_ok=False`, duration: ~126.7s (timeout in `kubectl rollout status`).
     - Error: `inject() returned False`.
     - Detections: `phantom_detections: []`, `is_true_positive: False`, `mttd_s: null`.
   - 6 files for `xzutils-001` and `dep-confusion-001` (`rep1`, `rep2`, `rep3`), sizes 411,108 to 1,233,562 bytes:
     - Phases: `["baseline", "inject", "attack", "recover", "post_recovery"]`.
     - `is_true_positive: True`.
     - Detections count: 239, 654, 684, 720, 684, 720. Total = **3,701 drift detections**.
     - MTTD values: `[70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247]`. Mean = 15.74s, median = 5.52s, IQR = 4.88s.
   - Full quantitative scan of all 3,701 detection records:
     - `pod_name`: `"unknown"` in 3,701 / 3,701 (100.00%).
     - `container_name`: `"unknown"` in 3,701 / 3,701 (100.00%).
     - `container_id`: `"unknown"` in 3,667 (99.08%), resolved containerd ID in 34 (0.92%).
     - `image_digest`: `sha256:0000000000000000000000000000000000000000000000000000000000000000` in 3,701 / 3,701 (100.00%).
     - `sbom_id`: `null` in 3,701 / 3,701 (100.00%).
     - `purl`: `null` in 3,701 / 3,701 (100.00%).
     - `identity_status`: `"ambiguous"` in 3,667 (99.08%), `"missing"` in 34 (0.92%).
     - `event_type`: `privilege_transition` (2,555, 69.04%) and `namespace_change` (1,146, 30.96%). Zero process spawn, network connect, or file access events recorded.
     - `comm`: `runc:[2:INIT]` (2,555), `runc:[1:CHILD]` (936), `containerd` (188), `runc` (22).
     - `event_loss_observed`: `false` across all 3,701 records.
     - Controls: **0 benign control runs** exist in `raw3/` ($N_{\text{benign}} = 0$).

3. **Codebase Inspection in `research/evaluation/` and `services/causal-engine/`**:
   - `research/evaluation/scenarios/scenario_runner.py` lines 605–620: `collect_metrics_snapshot` wraps Prometheus query in `try...except` and returns `0.0` for CPU, RSS, and lag on query failure or connection drop.
   - `research/evaluation/results3/reports.json`:
     - Reported `n_benign_scenarios: 0`, but reported `fpr: 0.0, precision: 1.0, f1: 1.0`.
     - Reported `attribution_accuracy: 1.0, attribution_exact: 1.0` despite 100% null PURLs.
     - Reported `cpu_overhead_pct: 0.0, memory_overhead_mb: 0.0, event_lag_p95_ms: 0.0` from fallback zeros.
     - Reported baseline detectors (Falco, Trivy, IsoForest) as `tpr: 0.0` when logs were uncollected.
   - `services/causal-engine/app/domain/causal_validation.py`:
     - Gate G1 (`gate_minimum_observations`): Enforces `observation_count >= minimum` (default 10). If $< 10$, blocks with `suggested_status="insufficient_evidence"`, `reason="too_few_observations"`.
     - Gate G2 (`gate_component_mapping_quality`): Blocks `UNRESOLVED`, `INVALID`, and `AMBIGUOUS` mapping statuses.

4. **Test Suite Verification**:
   - `research/evaluation/tests`: 60 passed in 0.13s (Python 3.14).
   - `services/sbom-service/tests`: 177 passed in 1.26s (Python 3.12).
   - `services/causal-engine/tests`: 283 passed in 30.00s (Python 3.12).
   - Total: 520 tests passing.

---

## 2. Logic Chain

1. **Telemetry Dropout Classification in `raw/` (from Observation 1)**:
   - Because all 113 scenario records in `raw/` contain zero detections regardless of whether the scenario was an attack or benign control, and regardless of `inject_ok=True`, detector telemetry collection was disconnected.
   - *Inference*: Absent detections cannot be counted as True Negatives for benign controls or False Negatives for attack scenarios. The entire `raw/` dataset represents a telemetry collection dropout.

2. **Rollout Exclusion Classification in `raw3/` (from Observation 2)**:
   - All 3 repetitions of `solarwinds-001` timed out in `kubectl rollout status`, failed injection (`inject_ok=False`), and aborted before executing the payload.
   - *Inference*: These 3 runs are Failed Injections, not detector False Negatives. They must be excluded from detection sensitivity ($TPR$) denominators and causal evaluation.

3. **Undefined Metric Denominators in `raw3/` (from Observation 2 & 3)**:
   - `raw3/` contains 6 completed attack runs and 0 benign control runs.
   - *Inference*: The denominator for False Positive Rate ($FP + TN$) is 0. Precision and F1 also depend on negative control evaluation. Therefore, $FPR$, Precision, and F1 are mathematically undefined and must return `None` / `\text{---}`, rather than defaulting to 0.0 or 1.0.

4. **Identity Resolution & Causal Abstention (from Observation 2 & 3)**:
   - 100% of the 3,701 drift detections in `raw3/` have `purl = null`, `sbom_id = null`, and `pod_name = "unknown"`.
   - *Inference*: Runtime-to-SBOM mapping failed upstream in the eBPF agent daemonset. Gate G2 must block any attempt to attribute drift on this dataset with `AMBIGUOUS_COMPONENT`.
   - Furthermore, both datasets have $N < 10$ ($N=6$ in `raw/` dropouts, $N=6$ completed in `raw3/`), so Gate G1 must cleanly block with `insufficient_evidence: too_few_observations`.

5. **Decoupling Protocol (from Observation 2 & 3)**:
   - Injection delivery ($T_{\text{inject}}$), independent physical execution ($B_{\text{verified}}$), contract drift ($Y_{\text{drift}}$), and detector alerts ($\hat{Y}_{\text{phantom}}$) are distinct dimensions.
   - Egress connection to a mock sink is network activity; it is NOT drift unless it violates the cryptographically signed container contract. When independent verification is uncaptured, labels must remain `unknown`, never imputed.

6. **Anti-Mediator Conditioning Rule**:
   - In the DAG $T_{\text{purl}} \to B_{\text{process}} \to Y_{\text{drift}}$, intermediate processes and syscalls are post-treatment mediators. Conditioning on mediators blocks the causal path or induces collider stratification bias (M-bias). Covariates must be strictly Tier 0 pre-treatment variables.

---

## 3. Caveats

1. **Remote AWS EKS Cluster Telemetry**: The raw records were collected from an AWS EKS v1.36.2 cluster (`eks.6` platform, containerd, nodes `ip-172-31-5-170` and `ip-172-31-22-173`). Under benchmark integrity constraints, we did not execute new live attacks on the remote cluster; our audit is strictly an empirical forensic audit of the preserved raw records.
2. **Falco Rule Deployment Context**: Falco logs were empty (`falco_detections = []`). It cannot be proven from log files alone whether Falco's rule engine ignored the container events or whether the log collector path `/var/log/falco/events.jsonl` was unmounted. In either case, baseline telemetry is uncollected and must be reported as `telemetry_unavailable` / `NR`.
3. **No Caveats on Forensic Audit Facts**: The counts (114 files in `raw/`, 9 files in `raw3/`, 3,701 detections, 100% missing pod names/PURLs) are verbatim, exact, and independently verifiable.

---

## 4. Conclusion

1. **`EXPERIMENTAL_EVALUATION_AUDIT.md` (R1)**:
   - Successfully created at `d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md` (359 lines, 29,414 bytes).
   - Complete inventory and classification of all 114 files in `raw/` (6 indexed + 107 legacy scenario runs + index.json) and all 9 runs in `raw3/`.
   - Complete empirical classification: 6 completed attack runs, 3 failed injections, 0 valid benign controls, 113 telemetry collection dropouts.
   - Full disclosure of upstream identity resolution collapse (100% missing pod names, 100% null PURLs/SBOM IDs).
   - Full disclosure of Prometheus fallback zeros and empty Falco logs.
   - Explicit prohibition on treating collection dropouts as True Negatives.

2. **`EXPERIMENT_PROTOCOL.md` (R2)**:
   - Successfully created at `d:\project-1\EXPERIMENT_PROTOCOL.md` (355 lines, 25,881 bytes).
   - Formally establishes hypotheses $H_1, H_2, H_3$.
   - Defines independent experimental units (1 run = 1 unit) and prohibits window slicing to inflate sample size.
   - Strictly decouples the 4 dimensions: $T_{\text{inject}}$, $B_{\text{verified}}$, $Y_{\text{drift}}$, and $\hat{Y}_{\text{phantom}}$.
   - Formalizes causal estimands $\tau_{\text{inject}}$ and $\tau_{\text{purl}}$ with structural DAGs and anti-mediator conditioning rules.
   - Establishes Preflight Gate G1 ($N \ge 10$) strictly as a technical software sanity guard and mandates clean abstention on small/imbalanced datasets.
   - Specifies standard ordinary Wilson score interval ($[0.6096, 1.0000]$ for $6/6$) and bootstrap MTTD.

---

## 5. Verification Method

To independently verify all findings and artifacts:

1. **Verify Deliverable Files Exist**:
   ```powershell
   python -c "
   import os
   for f in ['EXPERIMENTAL_EVALUATION_AUDIT.md', 'EXPERIMENT_PROTOCOL.md']:
       print(f, os.path.exists(f), os.path.getsize(f))
   "
   ```

2. **Verify Dataset Run Classifications and Counts**:
   ```powershell
   python -c "
   import os, json
   with open('research/datasets/raw/index.json') as fp:
       idx = json.load(fp)
   print('Raw indexed runs:', len(idx['results']))
   raw_files = [f for f in os.listdir('research/datasets/raw') if f.endswith('.json')]
   print('Total JSON files in raw:', len(raw_files))
   raw3_files = [f for f in os.listdir('research/datasets/raw3') if f.endswith('.json')]
   print('Total JSON files in raw3:', len(raw3_files))
   "
   ```

3. **Verify Detections and Upstream Identity Resolution Failure in Raw3**:
   ```powershell
   python -c "
   import os, json
   from collections import Counter
   raw3 = 'research/datasets/raw3'
   dets = []
   for f in os.listdir(raw3):
       if f.endswith('.json'):
           with open(os.path.join(raw3, f)) as fp:
               dets.extend(json.load(fp).get('phantom_detections', []))
   print('Total detections:', len(dets))
   print('Event types:', Counter(d.get('event_type') for d in dets))
   print('Unknown pod names:', sum(1 for d in dets if d.get('pod_name') == 'unknown'))
   print('Null PURLs:', sum(1 for d in dets if d.get('purl') is None))
   print('Null SBOM IDs:', sum(1 for d in dets if d.get('sbom_id') is None))
   "
   ```

4. **Verify All Test Suites Continue to Pass**:
   ```powershell
   python -m pytest research/evaluation/tests
   d:\project-1\.venv-causal\Scripts\pytest.exe services/sbom-service/tests
   d:\project-1\.venv-causal\Scripts\pytest.exe services/causal-engine/tests
   ```

5. **Invalidation Conditions**:
   - If any JSON file in `research/datasets/raw/` contains non-empty `phantom_detections`, the observation of 100% collection dropout in `raw/` is invalidated.
   - If any `solarwinds-001` run in `raw3/` has `inject_ok=True`, the failed injection classification is invalidated.
   - If any detection record in `raw3/` has a non-null `purl` or known `pod_name`, the upstream identity failure observation is invalidated.
