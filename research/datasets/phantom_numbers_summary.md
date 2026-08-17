# PHANTOM Local Dry-Run Numbers Summary

Generated: 2026-08-08

## Execution Notes
- Docker was installed, but Docker Desktop Linux engine was not running, so PostgreSQL/Redis and migrations were skipped.
- eBPF agent was skipped because this run is local Windows dry-run.
- Local stub endpoints returned empty PHANTOM drift events and empty Prometheus vectors so the implemented dry-run runner could complete without network timeouts.
- Completed scenario set: research/datasets/raw_completed/index.json (18 runs).

## Scenario Coverage
- Total scenario runs: 18
- Attack runs: 9
- Benign runs: 9
- Repetitions per scenario: 3
- Namespace: phantom-eval

## TABLE 1: Detection Performance (Actual Local Dry-Run)
| Detector | TP | FN | FP | TN | TPR | FPR | Precision | F1 | MTTD | FP/hr |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PHANTOM | 0 | 9 | 0 | 9 | 0.000 | 0.000 | 0.000 | 0.000 | N/A | 0.000 |

## Baseline Detector Table
| Detector | TPR | FPR | F1 | MTTD(s) | CPU% | FP/hr |
|---|---:|---:|---:|---:|---:|---:|
| phantom | 0.000 | 0.000 | 0.000 | N/A | 0.00 | 0.000 |
| falco-default-rules | 0.000 | 0.000 | 0.000 | N/A | 0.00 | 0.000 |
| trivy-sbom-static | 0.000 | 0.000 | 0.000 | N/A | 0.00 | 0.000 |
| isolation-forest-syscall-frequency | 0.000 | 0.000 | 0.000 | N/A | 0.00 | 0.000 |

## Aggregate By Scenario Family
| Family | Attack Runs | Benign Runs | TP | FP | Mean MTTD |
|---|---:|---:|---:|---:|---:|
| benign_update | 0 | 3 | 0 | 0 | N/A |
| build_pipeline_tampering | 3 | 0 | 0 | 0 | N/A |
| dependency_confusion | 3 | 0 | 0 | 0 | N/A |
| high_load | 0 | 3 | 0 | 0 | N/A |
| pod_restart | 0 | 3 | 0 | 0 | N/A |
| supply_chain_backdoor | 3 | 0 | 0 | 0 | N/A |

## TABLE 2: Causal Attribution
- Total attributions: 0
- Identifiability rate: N/A
- Attribution accuracy: N/A
- Mean attribution confidence: N/A
- Reason: no PHANTOM drift events were emitted in local dry-run, so there were no attribution records to evaluate.

## TABLE 3: PCEPS Model Performance
- AUC-ROC: N/A
- Brier score: N/A
- Training samples from real drift evidence: 0
- Reason: local dry-run generated labels but no real feature evidence; training on seeded synthetic features would fabricate model quality.

## TABLE 4: Overhead Metrics (Prometheus Dry-Run)
- Metrics snapshots: 54
- Mean CPU usage cores: 0.0000
- Mean memory RSS MB: 0.00
- Mean event lag P95 ms: 0.00
- Event loss rate: N/A (not emitted by local dry-run)

## Files
- Scenario log: research/datasets/scenario_run_log.txt
- Baseline log: research/datasets/baseline_run_log.txt
- Completed raw results: research/datasets/raw_completed/
- Baseline reports: research/evaluation/results/reports.json
- Detection table CSV: research/evaluation/results/table_1_detection_performance.csv
