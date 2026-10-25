# PHANTOM Causal Attribution — Part 4 Validation Reference

> **Authors**: Harsh Ranjan (23BDS0078), Sampreti Samanta (23BDS0020),  
> Jai Goel (23BDS0191). Guide: Dr. Thanuja R.

---

## 1. Causal Attribution Pipeline (Before → After Part 4)

### Before Part 4

```
estimate_causal_attribution()
  → COMPLETED  (DoWhy ran successfully)
  → NOT_IDENTIFIABLE  (all other cases: cycles, no variation, positivity,
                       model construction, DoWhy identification failure,
                       estimation failure)
```

All abstention reasons were collapsed into a single `NOT_IDENTIFIABLE` status
with a free-form text reason field — not machine-readable.

### After Part 4

```
estimate_causal_attribution()
  → COMPLETED              DoWhy ran; ATE available
  → NOT_IDENTIFIABLE       DoWhy's identify_effect() failed; no adjustment set
  → INSUFFICIENT_EVIDENCE  No variation in treatment/outcome; positivity failed;
                           or fewer than minimum observations (pre-flight gate)
  → ESTIMATION_FAILED      Identification succeeded but estimator raised;
                           ATE is NOT available (distinct from NOT_IDENTIFIABLE)
  → INVALID_GRAPH          Treatment/outcome in BDG cycle; SCM graph has cycle
  → AMBIGUOUS_COMPONENT    Component identity is UNRESOLVED, INVALID, or AMBIGUOUS;
                           treatment variable not defensibly mapped
```

---

## 2. API / Status Contract

### `AttributionStatus` values

| Value | When set | ATE available? |
|-------|----------|---------------|
| `completed` | DoWhy returned an estimate | ✅ |
| `not_identifiable` | DoWhy could not find an adjustment set | ❌ |
| `insufficient_evidence` | No treatment/outcome variation; positivity failure; too few observations | ❌ |
| `estimation_failed` | Identification succeeded; estimator raised | ❌ |
| `invalid_graph` | Cycle in BDG projection or SCM; graph structurally invalid | ❌ |
| `ambiguous_component` | SBOM component identity is UNRESOLVED, INVALID, or AMBIGUOUS | ❌ |

### `AttributionResult` new fields (Part 4)

| Field | Type | Description |
|-------|------|-------------|
| `explanation` | `str` | Human-readable explanation of the abstention |
| `mapping_provenance` | `list[str]` | MappingStatus values from Part 3 for treatment events |
| `evidence_ids` | `list[uuid.UUID]` | RuntimeEventRecord UUIDs used as evidence |
| `observation_count` | `int` | Number of CausalObservation rows used |
| `causal_assumptions` | `list[str]` | Explicit causal assumptions made (always populated) |

---

## 3. Model Variables and Assumptions

### Variables

| Variable | Role | Default column name |
|----------|------|-------------------|
| Treatment | Binary; 1 = candidate component version | `component_version_treatment` |
| Outcome | Binary; 1 = contract deviation observed | `runtime_sbom_drift` |
| Covariates | Pre-treatment; caller-supplied | Varies |

### Explicit Causal Assumptions (logged in every `AttributionResult`)

1. **Forced treatment→outcome edge**: The SCM graph always contains a directed
   edge from the treatment node to the outcome node, regardless of whether the
   BDG contains a path between them. This is a structural modeling choice, not
   an empirically derived relationship.

2. **Backdoor sufficient**: The backdoor adjustment set is assumed to block all
   back-door paths from treatment to outcome. Unobserved confounders that are
   not captured in the BDG remain uncontrolled.

3. **Causal direction asserted**: Causal direction (treatment causes outcome)
   is asserted by the caller via temporal ordering. The pipeline does not
   independently test for reverse causality.

4. **INFERRED identity** (when applicable): When a component is identified by
   file-inventory path matching (INFERRED status), identity is established by
   path evidence, not by cryptographic hash. A different component at the same
   path would produce the same treatment assignment.

---

## 4. Mapping Provenance Handling

Part 4 integrates Part 3's `MappingResult` provenance in two layers:

### Pre-flight gate G2 (component identity)

Before any SCM construction, the caller can supply a list of
`MappingResult.status.value` strings for the events that contribute to the
treatment column:

```python
from app.domain.causal_validation import run_preflight_checks

report = run_preflight_checks(
    observation_count=20,
    outcome_positive_count=5,
    window_indices=list(range(20)),
    mapping_statuses=["INFERRED", "INFERRED", "VERIFIED"],  # from Part 3
    treatment_first_seen_ns=...,
    outcome_first_seen_ns=...,
)
if not report.passed:
    # Return AttributionResult with suggested_status
    ...
```

| Mapping status | Gate G2 verdict |
|---------------|-----------------|
| `VERIFIED` | PASS |
| `INFERRED` | PASS (by default); BLOCK if `allow_inferred=False` |
| `AMBIGUOUS` | BLOCK — two candidates, cannot designate one as treatment |
| `UNRESOLVED` | BLOCK — no evidence linkage |
| `INVALID` | BLOCK — structural validation failure |

### `AttributionResult.mapping_provenance`

After running the pipeline, the caller should populate
`AttributionResult.mapping_provenance` with the list of status strings used.
This makes the source of the treatment assignment auditable.

---

## 5. Abstention Conditions and Reasons

| Gate | Reason code | Status |
|------|-------------|--------|
| G1: Too few observations | `too_few_observations` | `insufficient_evidence` |
| G2: Unresolved component | `unresolved_component_identity` | `ambiguous_component` |
| G2: Ambiguous component | `ambiguous_component_identity` | `ambiguous_component` |
| G3: Reversed timestamps | `reversed_temporal_order` | `not_identifiable` |
| G4: Post-treatment covariate | `covariate_observed_after_outcome` | `invalid_graph` |
| G5: No positive outcomes | `outcome_absent_from_window` | `insufficient_evidence` |
| G6: Duplicate windows | `duplicate_observations_detected` | `insufficient_evidence` |
| Cyclic BDG projection | `cyclic_treatment_or_outcome` | `invalid_graph` |
| SCM graph cycle | `invalid_graph_cycle` | `invalid_graph` |
| No treatment variation | `no_empirical_variation` | `insufficient_evidence` |
| No outcome variation | `no_empirical_variation` | `insufficient_evidence` |
| Positivity failure | `positivity_failure` | `insufficient_evidence` |
| DoWhy model construction | `model_construction_error` | `not_identifiable` |
| Identification failure | `unidentified_effect` | `not_identifiable` |
| Estimator exception | `estimation_failed` | `estimation_failed` |

---

## 6. Test Cases and Commands

### Run only Part 4 validation tests

```powershell
cd services/causal-engine
python -m pytest tests/test_causal_validation.py -v --tb=short
```

### Run full causal-engine test suite

```powershell
python -m pytest tests/ -v --tb=short
```

### Run only Part 3 mapping tests (for reference)

```powershell
cd services/sbom-service
python -m pytest tests/test_runtime_mapper.py -v --tb=short
```

### Run Part 3 + Part 4 combined

```powershell
cd services/sbom-service
python -m pytest tests/test_runtime_mapper.py tests/test_domain.py tests/test_contracts.py -q

cd ../causal-engine
python -m pytest tests/test_causal_validation.py tests/test_attribution.py tests/test_domain.py tests/test_graph.py tests/test_bdg_builder.py tests/test_pceps.py -q
```

---

## 7. Actual Test Outcomes

### Part 4 new tests (`test_causal_validation.py`)

```
90 passed, 1 skipped, 1 warning in 3.45s
```

The 1 skip is `test_estimation_failed_status_distinct_from_not_identifiable` —
intentionally gated on `pytest.importorskip("dowhy")` because `ESTIMATION_FAILED`
can only be triggered at the estimator level, which requires DoWhy to be installed.
The entity-level contract is verified by the remaining tests.

### Full causal-engine suite

See **Section 8** for the breakdown.

### Part 3 mapping tests (unchanged by Part 4)

```
84 passed in 0.40s   (tests/test_runtime_mapper.py)
155 passed in 0.29s  (test_runtime_mapper + test_domain + test_contracts combined)
```

---

## 8. Existing Failures and Missing Dependencies

The following failures exist in the repository BEFORE Part 4 and are unchanged:

| File | Failure | Root cause |
|------|---------|-----------|
| `test_scm_constructor.py::TestGraphStoreRoundTrip` (7 tests) | `ModuleNotFoundError: No module named 'asyncpg'` | `asyncpg` not installed in local dev env |
| `test_scm_constructor.py::TestDoWhyAdapterNotIdentifiable` (2 tests) | `async def functions are not natively supported` | `pytest-asyncio` not installed |
| `test_use_cases.py` (12 tests, sbom-service) | `async def functions are not natively supported` | `pytest-asyncio` not installed |
| `test_router.py` (sbom-service) | `ModuleNotFoundError: No module named 'pytest_asyncio'` | `pytest_asyncio` not installed |

**Part 4 introduced zero new failures.**

---

## 9. Real-Data Causal Attribution Status

**Real-data causal attribution is NOT yet supported.** The blockers are:

1. **No `CausalObservation` builder**: No code converts BDG snapshots into the
   windowed treatment/outcome table that DoWhy requires. `CausalObservation` rows
   must currently be supplied by the caller manually.

2. **Part 3 not yet wired**: `RuntimeToSbomMapper` output is not yet consumed by
   `UpdateBdgUseCase`. Component PURLs arrive as raw strings from the Redis consumer,
   not from the evidential mapping pipeline.

3. **DoWhy not installed**: `dowhy` is not in the local dev environment, so the
   full pipeline (identification + estimation + refutation) cannot run.

4. **No outcome labels**: No ground-truth `runtime_sbom_drift` labels exist per
   observation window for the synthetic attack runs, preventing empirical evaluation.

The implementation is **software-contract complete**: all gates, status codes,
and provenance fields are implemented and tested. Real-data evaluation requires
the four items above to be resolved.

---

## 10. New Files (Part 4)

| File | Description |
|------|-------------|
| [`causal_validation.py`](file:///d:/project-1/services/causal-engine/app/domain/causal_validation.py) | Six pre-attribution evidence gates (G1–G6), `PreflightReport`, `GateVerdict`, and 15 explicit reason codes |
| [`test_causal_validation.py`](file:///d:/project-1/services/causal-engine/tests/test_causal_validation.py) | 90 Part 4 validation tests |
| [`CAUSAL_VALIDATION_AUDIT.md`](file:///d:/project-1/services/causal-engine/CAUSAL_VALIDATION_AUDIT.md) | Pre-implementation pipeline audit |
| [`CAUSAL_VALIDATION_README.md`](file:///d:/project-1/services/causal-engine/CAUSAL_VALIDATION_README.md) | This document |

## 11. Modified Files (Part 4)

| File | Change |
|------|--------|
| [`entities.py`](file:///d:/project-1/services/causal-engine/app/domain/entities.py) | `AttributionStatus` — 4 new values; `AttributionResult` — 5 new fields |
| [`exceptions.py`](file:///d:/project-1/services/causal-engine/app/domain/exceptions.py) | Added `InsufficientObservationsError`, `TemporalOrderViolationError` |
| [`estimate_attribution.py`](file:///d:/project-1/services/causal-engine/app/application/estimate_attribution.py) | All abstention paths use specific status codes; `explanation` populated; `causal_assumptions` and `observation_count` set on all results |
