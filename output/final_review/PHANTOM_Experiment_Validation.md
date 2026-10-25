# PHANTOM Experiment Validation

This report rechecks the manuscript's quantitative claims against the saved `research/datasets/raw3/` JSON records and related repository logs. Values below are not extrapolated beyond those artifacts.

## Run-level outcomes

| Metric or claim | Source artifact | Recomputed/observed result | Validation |
|---|---|---:|---|
| Total raw3 records | `research/datasets/raw3/*.json` | 9 | Verified |
| Completed attack runs | Same records | 6: 3 `xzutils-001`, 3 `dep-confusion-001` | Verified |
| Failed SolarWinds-style injections | Same records; `inject()` outcome | 3; no attack phase | Verified; failed injections are not false negatives |
| Run-level event-positive windows | Completed raw3 runs | 6/6 recorded at least one drift event | Verified as event presence only; not component-level detection |
| Event-positive fraction interval | Six binary event-presence observations | Wilson 95% CI [0.610, 1.000] | Recomputed using the two-sided 95% Wilson score interval ($z=1.96$) with $x=6$, $n=6$; descriptive, small sample |
| True negatives/benign windows | raw3 records | No valid controls; no TN denominator | Unavailable |
| Precision, recall, F1, specificity, FPR, FP/hour | Requires positive oracle for correct attack detection and valid benign/control denominator | Not defined from supplied evidence | Unavailable; not zero |
| Causal attribution accuracy | Aggregate result claims 1.0; raw records | No per-run predicted PURL compared with oracle; identity unresolved | Unverified; excluded from paper results |

## Latency validation

Definition used by the saved evaluation: injection timestamp to the first saved PHANTOM drift-event timestamp, within the raw record's 120-second post-injection observation window. Unit of analysis is one scenario run, not each duplicated API event row.

| Attack family/run group | Supplied latencies (s) | Recomputed statistic (s) | Validation |
|---|---|---:|---|
| `xzutils-001` (3 runs) | 70.331969, 6.349775, 4.681537 | — | Each stored MTTD matches its timestamps |
| `dep-confusion-001` (3 runs) | 2.607243, 7.875910, 2.578247 | — | Each stored MTTD matches its timestamps |
| Six completed runs | Same six values | Mean 15.737447; median 5.515656; linear-interpolated P95 54.717954 | Verified; paper rounds to 15.74, 5.52, 54.72 |
| Long first XZ run | 70.331969 | Cause not established by logs | Unverified; no causal explanation asserted |

## Baselines

| Baseline | Saved source | Observed configuration/output | Validation |
|---|---|---|---|
| Falco default rules | `research/datasets/baseline_run_log.txt`, `research/evaluation/baselines/` | Setup skipped in dry-run mode; alert logs missing | Zero recall not a valid comparative result |
| Trivy static SBOM scan | Same | Setup skipped in dry-run mode | Not a runtime detector; live-attack recall comparison is task-mismatched absent a separately defined task |
| Isolation Forest syscall-frequency baseline | Same | Fit used synthetic frequency data rather than matched raw attack traces | Not a matched baseline |
| PHANTOM aggregate baseline report | `research/evaluation/results3/reports.json` and generated tables | Aggregate entries include zeros/attribution claims inconsistent with supporting records | Not used as performance evidence |

## PCEPS and overhead

| Claim | Artifacts inspected | Result | Validation |
|---|---|---|---|
| PCEPS AUC/Brier or prediction quality | Training code, saved results, model/output inventory, earlier audit | No trained model, calibration artifact, scored windows, test labels, or reproducible metrics linked to the paper | Unsupported; no performance value retained |
| PCEPS implementation | `services/causal-engine/app/infrastructure/` and related model code | Feature/training/calibration/scoring pathways exist; 16 feature inputs plus mask | Implemented code pathway; not experimental performance |
| Runtime CPU/memory/event-loss overhead | Saved metric snapshots and available logs | Snapshots are zero but lack raw samples/provenance | Unmeasured, not zero |

## Legacy records and benign controls

The older `research/datasets/raw/` directory contains 114 JSON records. A structural inspection found no nonempty `phantom_detections` field and 44 records with `pod_name="dry-run-pod"`. The presence of labels such as benign scenario names does not establish that these are live control runs. They are not used to estimate false positives or true negatives.

## Reproducibility fields absent from raw3

- Linux kernel and host hardware/instance type.
- Kubernetes and container-runtime versions.
- Exact eBPF collector/framework version and runtime settings.
- Immutable image digests and experiment commit linked to each run.
- Exact Python and DoWhy package versions used for the experiment.
- Resolved process/container/pod-to-PURL ground-truth mapping.
- Raw Prometheus samples and event-loss measurement provenance.
- Matched valid benign controls and baseline detection outputs.

The source repository has scripts and infrastructure definitions, but their existence does not fill these raw-run omissions.

## Proposed next experiment protocol (not yet run)

1. **Controls and attacks.** Freeze a signed baseline contract before collection. Run routine package upgrades, workload-only configuration changes, load changes, and pod restart/autoscaling controls alongside the two successful attack families and repaired SolarWinds-style injection. Use the same 120-second observation interval, collector settings, workload image except for the intended intervention, and independent run IDs. Randomize run order where practical. Pre-register expected events and labels.
2. **Identity ground truth.** For every run, archive the trusted SBOM and image digest; target PURL; pod/container ID; PID plus process start time and parent lineage; injected artifact digest; expected target and actual deployment identity. Keep the oracle record separate from PHANTOM output. Record the PHANTOM predicted PURL, abstention, confidence, and evidence. Report exact-match component attribution as correct only when the predicted PURL equals the independently recorded target; report unresolved/abstained cases separately.
3. **Detection and benign alert measurement.** Define the episode as the unit. A positive is a predeclared attack episode with a confirmed drift alert; controls establish the negative denominator. Report TP/FP/FN/TN, precision, recall, F1, specificity, FPR, and false alarms per observation hour, with confidence intervals and explicit zero-denominator handling. Keep event presence distinct from confirmed attack detection.
4. **Matched baselines.** Run Falco with documented rules tailored to observable scenario behavior and preserve rule/config versions and alert output. Run Trivy only on a clearly defined static-vulnerability/SBOM task, not as a live-runtime detector. Fit the frequency Isolation Forest only on training-only benign traces and evaluate on held-out runs. Give all applicable runtime detectors the same event stream/window and independent labels; publish raw outputs and commands.
5. **PCEPS prospective evaluation.** Define a future outcome and horizon before training (for example, whether an independently confirmed compromise occurs within a fixed follow-up interval). Split by independent workload/run and time so that windows from one run cannot cross train/calibration/test partitions. Fit medians, XGBoost, and Platt parameters only on training/calibration partitions. Report ROC-AUC, PR-AUC, Brier score, ECE/reliability plot, confidence intervals, and a simple baseline only after scoring held-out labeled outcomes. Record model and calibration digests.
6. **Overhead and telemetry loss.** Compare collector-disabled and collector-enabled deployments under the same workload, image, request/load schedule, host, kernel, Kubernetes, and container-runtime versions. Capture time-series CPU and memory samples, event-processing latency, events emitted/received/dropped, and application throughput/latency for a fixed duration over multiple independent repetitions. Record collector settings, Prometheus raw samples, clock source, and run manifests. Report distributions and event-loss counts; do not infer zero overhead from absent measurements.
7. **Ablation and sensitivity.** On the same held-out labeled runs, compare frequency-only versus variable-order Markov contracts, remove BDG features, remove causal features, and remove identity evidence one at a time. Sweep contract and score thresholds using training/validation data only, then lock them before test. Compare causal ranking with dependency/graph heuristics using the same component ground truth. Treat every result as future work until collected.

