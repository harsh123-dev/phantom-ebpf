# PHANTOM Experiment Validation

## Scope and unit of analysis

The primary checked-in raw dataset is `research/datasets/raw3/`. The metric unit used below is a **successfully injected attack run**, not an individual drift-event row. `scenario_run_log.txt` shows three SolarWinds-style injections returning false; their JSON records have no attack phase and are excluded from detection denominators. There are six completed attack runs: three `xzutils-001` and three `dep-confusion-001`. There are no benign controls in this dataset.

Run `python output/phantom_audit/validate_results.py` from the repository root to regenerate `PHANTOM_Validation_Summary.json` and `PHANTOM_Run_Level_Validation.csv` from raw3. The script recomputes event-window latency and uses linear interpolation for the 95th percentile, matching the evaluator's `_safe_percentile` convention.

## Reported metrics and verification

| Reported metric or claim | Source artifact | Recomputed / inspected result | Status |
|---|---|---|---|
| Six successful live runs: 3 XZ-style and 3 dependency confusion | `research/datasets/raw3/*.json`; `research/datasets/scenario_run_log.txt`; `research/evaluation/results3/reports.json` | Six completed attack runs in raw3. Six have `is_true_positive=true`. Three further JSON records are invalid for effectiveness analysis because `inject() returned False`. | **Verified as record contents, not as accurate attacks** |
| 6 TP, 0 FN on the six valid records | `raw3/*.json`; scenario runner | Six runs contain at least one event record inside the detection window under the runner's event-presence rule. This is not component-level detection: recorded event IDs are `namespace_change` / `privilege_transition`; identity is ambiguous or missing, PURL and SBOM ID are null. | **Partially verified; weak detection oracle** |
| TPR / attack-run event-positive fraction = 1.000 | `raw3/*.json`; `results3/reports.json` | 6/6 = 1.000 for this limited event-presence rule. Wilson 95% CI for 6/6: [0.610, 1.000]. The six-run `results3` summary aligns with the first six raw records. | **Verified narrowly; not evidence of generalization** |
| TPR = 0.889 and F1 = 0.872 | `phantom_paper_final.tex` | These numbers do not derive from checked-in raw3 or `results3`; no corresponding 9 valid attack runs are present. | **Unverified; removed from revised paper** |
| FPR = 0.050, precision = 1.000, F1 = 1.000 | `research/evaluation/results3/reports.json`, CSV; evaluator | `n_benign_scenarios=0`. The evaluator substitutes 0.0 for zero denominators, which makes FPR and FP/hr look like measured zeros. FPR, precision, and binary F1 are not estimable without negative-class controls. | **Unverified / undefined** |
| MTTD 70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247 s | `raw3/*.json` | Recomputed as first recorded detection timestamp minus injection timestamp; all six match stored MTTD to <10 microseconds. | **Verified as timestamp arithmetic** |
| Mean 15.740 s, median 5.520 s, P95 54.720 s | `results3/reports.json`, CSV | Recomputed raw values: mean 15.737447 s; median 5.515656 s; P95 linear interpolation 54.717954 s. The published two-decimal numbers match after rounding. | **Verified for six event-positive runs; event attribution remains uncertain** |
| Long first XZ run explanation | XZ rep 1 JSON | First event is at 70.331969 s. Its timestamp and scenario are present; no log evidence establishes why it was late. | **Unable to verify cause** |
| 100% causal attribution accuracy; exact process, hash, container, pod | `results3/reports.json`; raw3 records | The report stores attribution accuracy as 1.0, but raw records have no ground-truth PURL attribution result; all drift records have `identity_status=ambiguous`, null `purl` and `sbom_id`, unknown pod/container, zero image digest. | **Unverified; identity evidence contradicts exact mapping claims** |
| PCEPS AUC-ROC 0.923 and Brier 0.081 | Paper, notebooks, code | No model, calibration artifact, feature windows, prediction file, label file, or evaluation output backing these values was located. The source implements the model/scoring pipeline but not evidence of these reported outcomes. | **Unverified; removed from results claims** |
| CPU overhead 3.1%, max 4.8%, memory and lag figures | Paper; raw3 snapshots; `results3/reports.json` | All raw3 CPU, memory, and lag snapshots are exactly 0.0. The summary carries zero overhead and zero event lag. There is no measurement provenance; these zeros cannot establish a measured zero-cost system. | **Unverified** |
| Falco, Trivy, Isolation Forest zero recall | `baseline_run_log.txt`; `results3/reports.json`; baseline source | Log says Falco and Trivy setup were skipped in dry-run, Falco alert files were missing, and all baseline output was zero. Trivy is a static vulnerability/image scanner, not a runtime detector. Isolation Forest was fit but no valid live detection stream is shown. | **Unverified as comparative performance; excluded from revised claims** |
| SolarWinds-style build pipeline attack outcome | three SolarWinds raw3 files | All fail injection (`inject() returned False`), have no attack phase and no detections. | **Unresolved; rerun required** |

## Metric definitions and recomputation

For attack-run labels, `TPR = TP/(TP+FN)`. Run-level true positive in the saved scenario code means at least one PHANTOM API drift event has a timestamp within the scenario's detection window. This operational definition does not require the event type, process, package, or component to match the attack oracle. It therefore validates only an event-positive run count.

`FPR = FP/(FP+TN)`, `precision = TP/(TP+FP)`, and `F1 = 2*precision*recall/(precision+recall)` require the corresponding positive and negative samples. The current raw3 data has zero benign controls; those metrics are undefined from this corpus. The evaluator currently returns 0 for zero denominators, which should not be interpreted as observed zero false alarms.

Latency is `first_phantom_detection_timestamp - injection_timestamp`. The six stored values agree with timestamp arithmetic. Median is the midpoint for an even sample. P95 uses linear interpolation at rank `p*(n-1)`, as implemented by `research/evaluation/metrics/evaluator.py::_safe_percentile`.

The raw3 event arrays contain duplicated records: 3,701 rows correspond to 205 unique drift-event IDs across six valid runs. They are not independent attack trials and were not used as the metric denominator.

## Baselines and reproducibility

The repository's `baseline_run_log.txt` records a dry-run. Falco setup was skipped and alert log files were absent; Trivy setup was skipped; Isolation Forest fit a model, but the resulting table shows zeros for every detector. These files do not establish comparative recall. Trivy remains relevant to declared-image vulnerability scanning, but a failure to alert on a runtime behavior change is not evidence of inferior runtime detection.

The checked-in records identify a cluster name and timestamps, but do not include a complete reproducibility manifest with cluster/image digests, kernel and container runtime versions, Prometheus raw samples, collector loss counters, exact deployed configuration, attack oracle outcomes, and baseline raw outputs. The shell script documents desired version pins; those are not proof that the recorded runs used them.

Prior ChatGPT conversations outside the materials in this workspace were not available for independent review. Existing handoff documents are treated as design intent; source code and records were used to establish implementation/evaluation status.
