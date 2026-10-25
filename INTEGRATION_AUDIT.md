# PHANTOM Part 5 — Integration Audit

> **Author**: Part 5 automated audit
> **Date**: 2026-10-23
> **Python version in use**: 3.14.6 (the local Anaconda environment)

---

## 1. Components Inspected

| Component | Location | Status |
|-----------|----------|--------|
| Drift decider + `DriftResult` | `services/ebpf-agent/domain/drift/decider.py` | ✅ Implemented |
| BDG + `update()` method | `services/causal-engine/app/domain/bdg.py` | ✅ Implemented |
| `UpdateBdgUseCase` | `services/causal-engine/app/application/use_cases.py` | ✅ Implemented |
| Redis consumer | `services/causal-engine/app/infrastructure/redis_consumer.py` | ✅ Implemented |
| Part 3 `RuntimeToSbomMapper` | `services/sbom-service/app/domain/mapping/resolver.py` | ✅ Implemented |
| `MappingResult` evidence types | `services/sbom-service/app/domain/mapping/evidence.py` | ✅ Implemented |
| Part 4 causal validation gates | `services/causal-engine/app/domain/causal_validation.py` | ✅ Implemented (Part 4) |
| `AttributionStatus` (6 values) | `services/causal-engine/app/domain/entities.py` | ✅ Implemented (Part 4) |
| `estimate_causal_attribution` | `services/causal-engine/app/application/estimate_attribution.py` | ✅ Implemented |
| Evaluation runner | `research/evaluation/metrics/evaluator.py` | ✅ Implemented |
| Scenario runner | `research/evaluation/scenarios/scenario_runner.py` | ✅ Implemented |
| Raw experiment records | `research/datasets/raw/*.json` (115 files) | ✅ Present |
| DoWhy 0.11.1 | declared in `pyproject.toml` | ❌ UNAVAILABLE (Python 3.14 > constraint `<3.12`) |
| `asyncpg` | declared in `pyproject.toml` | ❌ not installed in Anaconda env |
| `pytest-asyncio` | declared in `pyproject.toml[dev]` | ❌ not installed in Anaconda env |

---

## 2. Real Call Chain (as implemented)

```
eBPF agent (Go/C)
       │ XADD
       ▼
Redis Stream ("phantom:drift-events")
       │ XREADGROUP
       ▼
DriftEventRedisConsumer             [causal-engine/infrastructure/redis_consumer.py]
       │
       ▼  (per message, for each field in the Redis message)
UpdateBdgUseCase.execute()          [causal-engine/application/use_cases.py]
       │
       ├─ BDG.update(event_id, event_type, event_time, ...)   [domain/bdg.py]
       │       └─ upsert_node(WORKLOAD, CONTAINER, PROCESS)
       │       └─ upsert_node(PURL) ← raw `component_purl` string from Redis
       │       └─ upsert_edge(PROCESS→PURL, LOADS)  ← if component_purl present
       │       └─ upsert_edge(PROCESS→CONTRACT, VIOLATES) ← if violations present
       │       └─ idempotency_index dedup
       │       └─ snapshot cut at batch boundary
       │
       └─ BdgRepository.save_snapshot()
                 (postgres via asyncpg — not runnable locally)
```

**Attribution is NOT triggered automatically per event.**
Attribution is a separate `RunAttributionUseCase.execute()` call that requires
`list[CausalObservation]` from the caller. **No builder for this list exists.**

---

## 3. Confirmed Integration Blockers

### Blocker 1 — No `CausalObservation` builder from BDG evidence

`UpdateBdgUseCase.execute()` stores graph nodes/edges but does NOT emit or
accumulate `CausalObservation` rows. The caller of `estimate_causal_attribution()`
must supply `list[CausalObservation]` directly.

**No code in the repository converts BDG nodes/edges into
`CausalObservation(window_index, treatment_value, outcome_value, covariates)`
rows.**

The connection is broken at this interface.

### Blocker 2 — Part 3 mapper not wired to `UpdateBdgUseCase`

`UpdateBdgUseCase.execute()` accepts `binding_status: str` and
`component_purl: str | None` as raw strings. These come from the Redis message
fields, not from `RuntimeToSbomMapper`.

The Redis consumer parses `binding_status` and `component_purl` directly from
the Redis stream frame. `RuntimeToSbomMapper` is defined in `sbom-service` and
is never imported by `causal-engine`. The mapper's `MappingResult` provenance
(evidence IDs, `MappingStatus`, evidence sources) is never written to the BDG.

**The BDG nodes created for PURL components carry no mapping provenance.**

### Blocker 3 — DoWhy version mismatch

`pyproject.toml` declares `dowhy==0.11.1`.
The local Anaconda Python is 3.14.6.
All dowhy releases with version ≥ 0.9 require Python `<3.12` or `<3.13`.
**No compatible dowhy version can be installed on Python 3.14.**

The latest available release that pip can find is 0.8, which has a
different API than 0.11.x.

**Impact**: DoWhy-dependent pipeline stages cannot run at all locally. The
abstention path (returning `NOT_IDENTIFIABLE`, `ESTIMATION_FAILED`, etc.) is the
only path that will be exercised.

### Blocker 4 — No per-window outcome labels in experiment records

Raw experiment records (`research/datasets/raw/*.json`) contain:
- `ground_truth_label: 1` (all attack runs; benign runs have `0`)
- `injection_timestamp`
- `first_phantom_detection_timestamp: null` (all runs in last batch)
- `is_true_positive: false` (all runs in last batch)
- `phantom_detections: []` (all runs in last batch)
- Phase timestamps

**There are no per-window `runtime_sbom_drift` outcome labels. The
`CausalObservation.outcome_value` field cannot be populated from these records.**

The available information at the run level is: attack injected or not
(run-level binary), not per-observation-window drift outcome.

### Blocker 5 — `asyncpg` not installed

`BdgRepository.save_snapshot()` requires asyncpg. Without it, snapshot
persistence fails. The 7 `TestGraphStoreRoundTrip` tests (pre-existing) fail
with `ModuleNotFoundError: No module named 'asyncpg'`.

---

## 4. What the Raw Records DO Support

| Field | Source | Available? |
|-------|--------|------------|
| Run ID | `run_id` | ✅ |
| Scenario (attack/benign) | `attack_id`, `attack_family` | ✅ |
| Ground truth label (run-level) | `ground_truth_label` | ✅ |
| Injection succeeded | phase `inject`, `notes: inject_ok=True/False` | ✅ |
| Injection timestamp | `injection_timestamp` | ✅ |
| PHANTOM detected | `first_phantom_detection_timestamp` (null) | Null for all last-batch runs |
| MTTD | `mttd_s` (null) | Null for all last-batch runs |
| Target PURL | `scenario_label.target_purl` | ✅ |
| Recovery succeeded | phase `recover`, `notes: recover_ok=True/False` | ✅ |
| Phase timings | `phases` array | ✅ |
| Resource metrics | `metrics_snapshots` | ✅ (all zeros) |

**The `phantom_detections` array is empty for all runs in the most recent
batch (2026-08-23).** This means no PHANTOM alerts were recorded; there is
no MTTD or TP data in the available dataset.

---

## 5. Per-Run Injection and Recovery Status Summary

From the index (last 6 runs):
| Run ID | Scenario | Label | inject_ok | recover_ok |
|--------|----------|-------|-----------|------------|
| 20260823T201630Z_xzutils-001_rep1 | attack | 1 | True | False |
| 20260823T201938Z_dep-confusion-001_rep1 | attack | 1 | True | ? |
| 20260823T202255Z_solarwinds-001_rep1 | attack | 1 | True | ? |
| 20260823T202826Z_benign-update-001_rep1 | benign | 0 | N/A | N/A |
| 20260823T203128Z_benign-load-001_rep1 | benign | 0 | N/A | N/A |
| 20260823T203429Z_benign-restart-001_rep1 | benign | 0 | N/A | N/A |

Note: `recover_ok=False` for xzutils-001_rep1. This is a partially-completed
attack run.

---

## 6. What Part 5 Must Build (Minimum)

Given the blockers, the minimum honest integration is:

1. **`CausalObservationBuilder`**: Converts run-level manifest + BDG edge data
   into `CausalObservation` rows, with outcome value = `UNKNOWN` when per-window
   labels are unavailable. The builder must document why it cannot produce valid
   observations and return an `InsufficientEvidence` result.

2. **Mapping provenance injection**: Add `mapping_status` and `evidence_ids`
   attributes to PURL nodes when the BDG is updated, even though the full
   `RuntimeToSbomMapper` pipeline is in `sbom-service`. This requires a
   lightweight `MappingBdgRecord` value object in `causal-engine` that carries
   the mapping provenance from the Redis message (or the mapper output if called).

3. **End-to-end orchestrator**: A `RunAnalysisUseCase` that takes a run manifest
   record, builds observations (or returns `INSUFFICIENT_EVIDENCE` with documented
   reason), runs preflight checks, and attempts estimation (skipping if DoWhy
   is absent).

4. **Per-run pipeline report**: A CLI/script entry point that reads
   `research/datasets/raw/index.json` and produces a structured per-run report
   without fabricating labels or detections.

5. **Integration tests (15+ cases)**: Covering all specified scenarios using
   synthetic fixtures.

---

## 7. DoWhy Environment Finding

- Declared version `dowhy==0.11.1` is incompatible with Python 3.14.
- Latest compatible version (0.8) has a different API surface.
- **DoWhy cannot be installed in the current environment.**
- All pipeline branches requiring DoWhy will return `NOT_IDENTIFIABLE` via
  `CausalModelConstructionError` (raised when `import dowhy` fails inside
  `construct_causal_model`).
- **No real causal estimate can be produced in the current environment.**
- The correct outcome is documented abstention, not a fabricated score.

---

## 8. Pre-Existing Test Failures (Verified Baseline)

| Test file | Count | Cause | Action |
|-----------|-------|-------|--------|
| `test_scm_constructor.py::TestGraphStoreRoundTrip` | 7 | `asyncpg` not installed | Pre-existing; no change |
| `test_scm_constructor.py::TestDoWhyAdapterNotIdentifiable` | 2 | async tests without `pytest-asyncio` | Pre-existing; no change |

These 9 failures exist in the repository baseline and are not caused by Part 5.

---

## 9. What Is NOT Supported by the Available Data

The following must NOT be reported:
- Causal attribution accuracy (CAA) — no oracle attribution labels per TP
- TP/FP/FN/TN counts — PHANTOM detections are empty for the last batch
- MTTD — detection timestamps are null
- PCEPS Brier score — PCEPS model is not trained
- Real-data ATE / causal effect estimates — DoWhy unavailable

These can only be reported when the conditions listed in `research/evaluation/EVALUATION_README.md` are met.
