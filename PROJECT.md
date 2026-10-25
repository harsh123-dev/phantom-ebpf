# Project: PHANTOM Experimental Evaluation Hardening

## Architecture
PHANTOM (Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes) consists of:
- `research/evaluation/`: Scenario runner, baseline collectors (Falco, Trivy, IsolationForest), metrics evaluator, comparison tables, deterministic reporting pipeline.
- `services/causal-engine/`: Causal DAG formulation, structural causal models (SCM), Preflight validation gates (Gate G1 $N \ge 10$, empirical variation), ATE estimation, abstention handling.
- `services/sbom-service/`: Runtime-to-SBOM mapping resolver, package manifest parsing, PURL attribution.
- `research/datasets/`: Historical raw runs (`raw/`, `raw3/`), model pickles, telemetry logs.

```
                      +---------------------------------------+
                      | Raw Datasets & Scenario Telemetry     |
                      | (raw/ N=6 dropouts, raw3/ N=9 runs)   |
                      +-------------------+-------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| Milestone 1: Data Audit & Protocol      | E2E Testing Track                       |
| - EXPERIMENTAL_EVALUATION_AUDIT.md      | - TEST_INFRA.md                         |
| - EXPERIMENT_PROTOCOL.md                | - Tiers 1-4 Opaque-Box Test Suite       |
| - Decoupled T_inject, B, Y_drift, Y_hat | - Publishes TEST_READY.md               |
+--------------------+--------------------+--------------------+--------------------+
                     |                                         |
                     v                                         |
+--------------------+--------------------+                    |
| Milestone 2: Observation & Preflight   |                    |
| - Gate G1 (N >= 10) Software Sanity    |                    |
| - Clean Abstention on Small Batches    |                    |
| - Anti-Mediator DAG Enforcement        |                    |
+--------------------+--------------------+                    |
                     |                                         |
                     v                                         |
+--------------------+--------------------+                    |
| Milestone 3: Defensible Metrics & Stats|                    |
| - Ordinary Wilson Score [0.6096, 1.000]|                    |
| - Bootstrap MTTD Percentile Intervals  |                    |
| - Undefined Denominator Handling (null)|                    |
| - Baseline Telemetry Absence -> NR     |                    |
| - Resource Overhead -> unmeasured/null |                    |
+--------------------+--------------------+                    |
                     |                                         |
                     v                                         |
+--------------------+--------------------+                    |
| Milestone 4: Reporting & Docs          |                    |
| - Deterministic reports.json (v1.0.0)  |                    |
| - LaTeX / CSV Table Generation         |                    |
| - EXPERIMENTAL_EVALUATION_README.md    |                    |
+--------------------+--------------------+                    |
                     |                                         |
                     +--------------------+--------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      | Milestone 5: E2E Verification &       |
                      | Adversarial Coverage Hardening (T1-5) |
                      +---------------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Raw Dataset Inventory & Classification | Audit all runs in `raw/` (6 indexed, 114 total) and `raw3/` (9 runs), classify into completed, failed injection, benign, dropout | M1 | R1, Survey |
| 2 | Telemetry & SBOM Missingness Documentation | Document 100% missing pod names, null SBOM IDs, null PURLs, and ambiguous identity statuses in `EXPERIMENTAL_EVALUATION_AUDIT.md` | M1 | R1, Survey |
| 3 | Independent Ground-Truth Protocol | Create `EXPERIMENT_PROTOCOL.md` decoupling $T_{\text{inject}}$, $B_{\text{verified}}$, $Y_{\text{drift}}$, and $\hat{Y}_{\text{phantom}}$ | M1 | R2, Survey |
| 4 | Causal Estimand & Anti-Mediator DAG Formalization | Separate $T_{\text{inject}} \to Y_{\text{drift}}$ from $T_{\text{purl}} \to Y_{\text{drift}}$, restrict covariates to Tier 0 pre-treatment | M1 | R2, Survey |
| 5 | Observation Schema Extensions | Associate records with stable run/window IDs, immutable event references, and provenance | M2 | R3, Survey |
| 6 | Preflight Gate G1 Technical Guard | Enforce $N \ge 10$ as technical software sanity guard preventing singular/rank-deficient regression matrices | M2 | R3, Survey |
| 7 | Causal Abstention Preservation | Preserve clean abstention (`too_few_observations`, `positivity_failure`, `not_identifiable`) on small/imbalanced datasets | M2 | R3, Survey |
| 8 | Anti-Window Slicing Enforcement | Strictly forbid splitting one run into temporal windows to artificially satisfy Gate G1 | M2 | R3, Survey |
| 9 | Failed Injection Exclusion from Denominators | Exclude failed injections (`inject_ok=False`, e.g. solarwinds-001) from detection TPR denominators | M3 | R4, Survey |
| 10 | Undefined Metric Denominators | Return `None`/undefined for FPR, Precision, and F1 when denominators are zero; do not default to 0.0 or 1.0 | M3 | R4, Survey |
| 11 | Standard Ordinary Wilson Score Interval | Compute exact ordinary Wilson score without continuity correction ($[0.6096, 1.0000]$ for $6/6$ at $z=1.96$) | M3 | R4, Survey |
| 12 | Bootstrap MTTD Confidence Intervals | Compute non-parametric bootstrap intervals for MTTD; report median and IQR alongside mean | M3 | R4, Survey |
| 13 | Runtime-to-SBOM Mapping Evaluation | Empirically evaluate runtime mapping, keeping verified, inferred, and ambiguous statuses distinct | M3 | R4, Survey |
| 14 | Baseline Absence Classification | Distinguish missing telemetry from true negatives; report Falco, Trivy, IsoForest as `telemetry_unavailable` / `NR` | M3 | R5, Survey |
| 15 | Resource-Overhead Accounting | Record missing Prometheus CPU, memory, and event lag as `null` / `unmeasured`, never fabricated as 0.0 | M3 | R5, Survey |
| 16 | Comparison Table Formatting & Bolding Fix | Update `comparison_table.py` to output `\text{---}` for undefined cells and prevent bolding unmeasured zeros | M3 | R5, Survey |
| 17 | Deterministic Pipeline Command | Provide deterministic command emitting versioned `reports.json` (v1.0.0) from actual run records | M4 | R6, Survey |
| 18 | LaTeX and CSV Report Generation | Emit deterministic, reproducible LaTeX and CSV summary tables | M4 | R6, Survey |
| 19 | Comprehensive Documentation | Create `EXPERIMENTAL_EVALUATION_README.md` documenting environment, reproduction commands, offline vs live demarcation | M4 | R6, Survey |
| 20 | Existing Test Suite Preservation | Ensure all existing tests pass (`services/causal-engine/tests`, `services/sbom-service/tests`, `research/evaluation/tests`) | M5 | Acceptance Criteria |
| 21 | Comprehensive E2E Verification & Hardening | Pass 100% of E2E test suite (Tiers 1-4) and adversarial coverage hardening (Tier 5) | M5 | Dual Track / Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Audit, Inventory & Protocol Foundations | R1 & R2: Author `EXPERIMENTAL_EVALUATION_AUDIT.md` and `EXPERIMENT_PROTOCOL.md` | none | DONE (Gate PASS) |
| M2 | Observation Schemas & Preflight Validation | R3: Causal validation Gate G1 ($N \ge 10$) software guard, abstention preservation, anti-window slicing, anti-mediator DAG | M1 | DONE (Gate PASS) |
| M3 | Defensible Detection, Mapping & Stats | R4 & R5: Wilson score, bootstrap MTTD, failed injection exclusion, undefined denominators, baseline NR classification, unmeasured overhead | M1, M2 | DONE (Gate PASS) |
| M4 | Deterministic Reporting & Documentation | R6: Versioned `reports.json`, LaTeX/CSV comparison tables, `EXPERIMENTAL_EVALUATION_README.md` | M1, M2, M3 | DONE (Gate PASS) |
| M5 | Final E2E Pass & Adversarial Hardening | Phase 1: 100% pass of E2E Test Suite (Tiers 1-4); Phase 2: Tier 5 Adversarial Coverage Hardening | M4, E2E Track | DONE (100% E2E Pass, Tier 5 Hardened, Final Audit CLEAN) |
| E2E | E2E Testing Track | Requirement-driven opaque-box test suite (Tiers 1-4), `TEST_INFRA.md`, publish `TEST_READY.md` | M1 | DONE (TEST_READY.md published, 242 tests passing) |

## Interface Contracts
### Evaluator ↔ Reports / Comparison Tables
- `Evaluator.evaluate()` returns dictionary with keys:
  - `metrics`: dict containing `tpr`, `tpr_ci_wilson` (`[lower, upper]`), `fpr` (`float | None`), `precision` (`float | None`), `f1` (`float | None`), `mttd_mean`, `mttd_median`, `mttd_iqr`, `mttd_ci_bootstrap` (`[lower, upper]`)
  - `overhead`: dict containing `cpu_overhead_pct` (`float | None`), `memory_overhead_mb` (`float | None`), `event_lag_p95_ms` (`float | None`), `status`: `"unmeasured"` when telemetry missing.
  - `baselines`: dict of baseline results where detectors with missing telemetry have `status: "telemetry_unavailable"` and metrics set to `None`.
  - `exclusions`: list of excluded runs with reason (e.g. `{"scenario_id": "solarwinds-001_rep1", "reason": "failed_injection", "error": "inject() returned False"}`).

### Causal Validation ↔ Estimation Pipeline
- `gate_minimum_observations(observation_count, minimum=10)`:
  - Returns `GateVerdict(outcome=BLOCK, reason="too_few_observations", suggested_status="insufficient_evidence")`.
  - Explanation explicitly states: `"Minimum technical guard: N >= 10 required to prevent rank-deficient regression matrices. Does not imply statistical power or identifiability."`
- `gate_treatment_variation(observations)`:
  - Blocks if $T$ has only one unique value (e.g., all 1s or all 0s), returning `GateVerdict(outcome=BLOCK, reason="no_treatment_variation")`.

## Code Layout
- `EXPERIMENTAL_EVALUATION_AUDIT.md`: Project root
- `EXPERIMENT_PROTOCOL.md`: Project root
- `EXPERIMENTAL_EVALUATION_README.md`: Project root
- `research/evaluation/metrics/evaluator.py`: Detection and baseline evaluation metrics
- `research/evaluation/metrics/comparison_table.py`: LaTeX and CSV table generation
- `research/evaluation/metrics/wilson_score.py`: Pure-math standard Wilson score implementation
- `research/evaluation/scenarios/run_evaluation.py`: Evaluation runner
- `run_pipeline_report.py`: Master deterministic CLI pipeline command
- `services/causal-engine/app/domain/causal_validation.py`: Preflight validation gates
- `services/causal-engine/app/domain/observation_builder.py`: Observation schema builder
- `services/causal-engine/app/domain/causal.py`: Causal DAG construction & anti-mediator rules
- `research/evaluation/tests/`: Evaluation unit and regression tests
- `tests/e2e/`: Opaque-box E2E test suite created by E2E Testing Track
