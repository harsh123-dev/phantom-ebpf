# PHANTOM Causal Attribution — Part 4 Audit

> **Author**: Part 4 automated audit  
> **Date**: 2026-10-23  
> **Status**: AUDIT COMPLETE — implementation follows

---

## 1. Existing Causal-Attribution Flow

```
Redis Stream (drift events)
       │
       ▼
DriftEventRedisConsumer          [interface/worker.py]
       │  (per message)
       ▼
UpdateBdgUseCase.execute()       [application/use_cases.py]
       │
       ├──► BehavioralDependencyGraph.update()   [domain/bdg.py]
       │         (nodes/edges with decayed weights)
       │
       └──► BdgRepository.save_snapshot()        [infrastructure/postgres_repository.py]
                 (triggers on batch boundary)

Attribution is NOT triggered automatically per event.
Attribution is triggered externally by RunAttributionUseCase:

RunAttributionUseCase.execute()  [application/use_cases.py]
       │
       ▼
estimate_causal_attribution()    [application/estimate_attribution.py]
       │
       ├─ Step 1: BDG.project_to_temporal_dag()
       ├─ Step 2: Check treatment_or_outcome_in_cycle → NOT_IDENTIFIABLE
       ├─ Step 3: build_causal_data_table()       [domain/causal.py]
       │       └─ InsufficientVariationError → NOT_IDENTIFIABLE
       ├─ Step 4: check_positivity()
       │       └─ PositivityFailureError → NOT_IDENTIFIABLE
       ├─ Step 5: build_scm_graph() + graph_to_gml()
       │       └─ GraphCycleError → NOT_IDENTIFIABLE
       ├─ Step 6: dowhy.CausalModel.identify_effect()
       │       └─ exception/None → NOT_IDENTIFIABLE
       ├─ Step 7: model.estimate_effect() with backdoor estimator
       │       └─ exception → NOT_IDENTIFIABLE (labelled "estimation_failed")
       ├─ Step 8: counterfactual cohort risk (best-effort; "unavailable" if fails)
       ├─ Step 9: 3× refutations: random_common_cause, placebo_treatment, data_subset
       └─ Step 10: compute_attribution_confidence() → AttributionResult(COMPLETED)
```

---

## 2. Inputs and Outputs at Every Stage

| Stage | Input | Output |
|-------|-------|--------|
| BDG update | `event_id`, `event_type`, `event_time`, identities, `binding_status`, `component_purl` | `GraphMutation` |
| `project_to_temporal_dag` | `BehavioralDependencyGraph`, treatment/outcome variable names, `window_count` | `TemporalDAGProjection` |
| `build_causal_data_table` | `list[CausalObservation]`, column names | `pd.DataFrame` |
| `check_positivity` | df, treatment col, covariate cols | `bool` |
| `build_scm_graph` | `TemporalDAGProjection`, variable names | `nx.DiGraph` |
| `identify_effect` | DoWhy `CausalModel` | DoWhy estimand (or exception) |
| `estimate_effect` | estimand, DoWhy model | DoWhy estimate object |
| refutations (×3) | estimand, estimate | `RefutationResult` objects |
| confidence | ATE, CI, refutations, data-quality params | `float ∈ [0,1]` |
| **Final output** | — | `AttributionResult(status=COMPLETED or NOT_IDENTIFIABLE)` |

---

## 3. How the System Constructs the Causal Graph

1. `project_to_temporal_dag()` iterates BDG edges and collapses them into
   `(variable_name, window_index)` tuples, excluding backward-time edges.
2. `build_scm_graph()` adds a forced `treatment → outcome` edge (always) and
   `covariate → treatment`, `covariate → outcome` edges for all covariates.
3. The graph is serialized to GML and passed to `dowhy.CausalModel`.

**Critical observation**: The forced `treatment → outcome` edge is always added
regardless of whether the BDG actually contains such a relationship. This is a
structural assumption, not an empirically derived edge.

---

## 4. Exposure, Outcome, and Confounder Choice

- **Treatment**: `component_version_treatment` (binary; 1 = candidate/manipulated version)
- **Outcome**: `runtime_sbom_drift` (binary; 1 = contract deviation observed)
- **Covariates**: `list[CovariateSpec]` — caller-supplied; no automatic selection

**Defect**: There is no enforcement that covariates precede treatment in time.
A covariate observed after the outcome could silently be included as a confounder,
violating temporal ordering and introducing outcome leakage.

---

## 5. How the System Determines Identifiability

Five sequential gates:

1. `projection.treatment_or_outcome_in_cycle` → cycles in the BDG's SCCs
2. `df[treatment].nunique() < 2` → no treatment variation
3. `df[outcome].nunique() < 2` → no outcome variation
4. `check_positivity()` → insufficient overlap in covariate strata
5. `model.identify_effect(proceed_when_unidentifiable=False)` → DoWhy check

**Defect**: Steps 2–3 collapse two fundamentally different abstention reasons
(`no_empirical_variation`, `positivity_failure`) into a single
`AttributionStatus.NOT_IDENTIFIABLE` reason string. Machine-readable status
codes do not distinguish them.

**Defect**: Estimation failure (`model.estimate_effect` exception) is also
mapped to `NOT_IDENTIFIABLE`. An estimation failure is structurally different
from a non-identifiable effect — the identification step may have succeeded.

---

## 6. Are Estimates Genuinely Calculated or Are They Placeholders?

**Yes, estimates are genuinely calculated** when DoWhy is installed. The pipeline:
- Calls `dowhy.CausalModel.identify_effect()` (real backdoor-criterion check)
- Calls `model.estimate_effect()` (real regression/matching/GLM)
- Runs 3 genuine DoWhy refutations

**However**, DoWhy is NOT installed in the current dev environment:
```
ModuleNotFoundError: No module named 'dowhy'
```
All tests that require DoWhy are guarded by `importorskip("dowhy")` or
`pytest.mark.skip` in the existing test suite. Any test reaching `construct_causal_model`
with real DoWhy calls is currently skipped or would fail with ImportError.

**Separate defect**: `estimate_attribution.py` maps `estimation_failed` to
`NOT_IDENTIFIABLE` rather than a distinct status, concealing numerical failures.

---

## 7. Available vs. Missing Upstream Interfaces

| Interface | Status |
|-----------|--------|
| `BehavioralDependencyGraph.update()` | ✅ Implemented (Part 2) |
| `BehavioralDependencyGraph.project_to_temporal_dag()` | ✅ Implemented |
| `CausalObservation` builder from BDG nodes | ❌ MISSING — callers must supply `list[CausalObservation]` manually |
| `MappingResult` → `CausalObservation` adapter | ❌ MISSING (Part 3 mapping not connected to causal pipeline) |
| `MappingResult.binding_status` used in `UpdateBdgUseCase` | ❌ Not wired (BDG receives `binding_status` as raw string, not from `RuntimeToSbomMapper`) |
| `AttributionStatus.ESTIMATION_FAILED` | ❌ MISSING — conflated with `NOT_IDENTIFIABLE` |
| `AttributionStatus.INSUFFICIENT_EVIDENCE` | ❌ MISSING — conflated with `NOT_IDENTIFIABLE` |
| Mapping provenance in `AttributionResult` | ❌ MISSING — no evidence IDs, no mapping status |
| Pre-treatment covariate temporal ordering check | ❌ MISSING |
| Experiment run boundary / observation window | ❌ No enforced boundary — `CausalObservation.window_index` is caller-supplied |

---

## 8. Most Important Correctness Defects

| ID | Severity | Defect |
|----|----------|--------|
| C-1 | HIGH | `AttributionStatus` has only two values: `COMPLETED` and `NOT_IDENTIFIABLE`. Estimation failures, insufficient evidence, and ambiguous mapping are all silently collapsed into `NOT_IDENTIFIABLE`. The reason field carries a free-form string, not a machine-readable code. |
| C-2 | HIGH | No check that covariates precede treatment in time. Post-outcome covariates can silently be included, leaking the outcome into the exposure model. |
| C-3 | HIGH | Part 3 `RuntimeToSbomMapper` output is not connected to `UpdateBdgUseCase`. Component PURLs and binding statuses are supplied as raw strings by the Redis consumer, without evidence-quality gating. |
| C-4 | MEDIUM | The forced `treatment → outcome` edge in `build_scm_graph` is a modeling assumption that should be explicitly documented in each `AttributionResult`. |
| C-5 | MEDIUM | No minimum observation count check before calling DoWhy. Small N can produce numerically unstable estimates that appear `COMPLETED`. |
| C-6 | MEDIUM | `component_purl` arrives in the causal observation only if the upstream consumer supplies it. There is no guard preventing an unresolved PURL from reaching the SCM as a treatment variable. |
| C-7 | LOW | Refutation "passed" heuristic (50% effect change threshold) is hardcoded with no configuration or documentation. |
| C-8 | LOW | The confidence score is a composite product formula; it is not calibrated and should not be interpreted as a probability. |

---

## 9. Conclusion on Real-Data Causal Estimation

The current dataset consists of synthetic eBPF events generated by attack
simulations run against the PHANTOM testbed. **Real-data causal attribution is
not yet supported** because:

1. No `list[CausalObservation]` builder exists that converts BDG snapshots into
   the windowed treatment/outcome table that DoWhy requires.
2. The `component_purl` and `binding_status` fields in BDG events are not
   sourced from the evidential `RuntimeToSbomMapper` (Part 3).
3. DoWhy is not installed in the local development environment.
4. No ground-truth outcome labels (drift vs. no-drift per observation window)
   exist in the repository for evaluating causal identification.

The tests in Part 4 validate the software contract for the attribution pipeline,
not the real-world causal accuracy.
