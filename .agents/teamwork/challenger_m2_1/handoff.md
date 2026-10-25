# Milestone 2 Empirical Challenger Handoff Report: Preflight Gate G1, Treatment Variation, and Anti-Window Slicing

**Agent**: `challenger_m2_1` (`teamwork_preview_challenger`)  
**Parent**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Date**: 2026-10-24  
**Scope**: Adversarial stress testing of Preflight Gate G1, treatment variation, anti-window slicing, and clean abstention preservation in `services/causal-engine/app/domain/causal_validation.py`.  
**Verdict**: **APPROVE**

---

## 1. Observation

All findings are backed by direct execution of unit and stress-test harnesses against `services/causal-engine/app/domain/causal_validation.py`:

1. **Preflight Gate G1 ($N \ge 10$ Software Sanity Guard)**:
   - In `services/causal-engine/app/domain/causal_validation.py` (lines 116–151), `gate_minimum_observations(observation_count, minimum=10)`:
     - For $N=9$: blocks with `outcome=GateOutcome.BLOCK`, `reason="too_few_observations"`, and `suggested_status="insufficient_evidence"`.
     - Verbatim explanation contains:
       `"Minimum technical guard: N >= 10 required to prevent rank-deficient regression matrices. Does not imply statistical power or identifiability."`
     - For $N=10$: passes with `outcome=GateOutcome.PASS`, `reason=""`, and `suggested_status=None`.
     - Boundary tests evaluated: $N \in \{-1, 0, 1, 9\} \implies \text{BLOCK}$; $N \in \{10, 11, 1000\} \implies \text{PASS}$; custom minimum ($N=4$ vs $N=5$ at `minimum=5`) verified.
2. **Treatment Variation ($T \in \{0, 1\}$)**:
   - In `services/causal-engine/app/domain/causal_validation.py` (lines 154–212), `gate_treatment_variation(treatment_values_or_observations)`:
     - All treated ($T=1$ across all observations): blocks with `outcome=GateOutcome.BLOCK`, `reason="no_treatment_variation"`, and `suggested_status="not_identifiable"`. Verbatim explanation: `"No treatment variation in observations (treated=10, controls=0). Causal identification requires both T=1 and T=0 units; one-sided batches are not identifiable."`
     - All controls ($T=0$ across all observations): blocks with `outcome=GateOutcome.BLOCK`, `reason="no_treatment_variation"`, and `suggested_status="not_identifiable"`. Verbatim explanation: `"(treated=0, controls=10)"`.
     - Empty list (`[]`): blocks with `outcome=GateOutcome.BLOCK`, `reason="no_treatment_variation"`, and `suggested_status="not_identifiable"`.
     - Polymorphic inputs tested: raw integer lists, booleans (`[True, False]`), `CausalObservation` objects with `.treatment_value`, and dictionaries with `"treatment_value"` or `"treatment"` keys all properly parsed and evaluated.
     - Non-binary treatments (`[2, 3]`, `[0, 2]`, `[1, 2]`): strictly blocked when either $0$ or $1$ is absent.
     - Imbalanced variation ($1$ treated with $99$ controls, or $99$ treated with $1$ control): passes with `GateOutcome.PASS`.
3. **Anti-Window Slicing & Independent Experimental Units**:
   - In `services/causal-engine/app/domain/causal_validation.py` (lines 214–283), `gate_unique_run_ids(run_ids_or_observations, minimum_unique_runs=10)` and alias `gate_independent_experimental_units`:
     - Slicing attack ($10$ temporal windows from $1$ unique run): blocks with `outcome=GateOutcome.BLOCK`, `reason="window_slicing_detected"`, and `suggested_status="insufficient_evidence"`. Verbatim explanation: `"Slicing detected: 10 observation(s) originate from only 1 unique run(s). Slicing one run into multiple temporal windows to satisfy Gate G1 is strictly forbidden (one run = one independent unit). Requires at least 10 unique runs."`
     - Extreme slicing attacks ($100$ windows from $1$ run, or $15$ windows from $3$ runs): cleanly blocked with `reason="window_slicing_detected"`.
     - Honest small batches without slicing ($1$ run with $1$ observation, $6$ unique runs with $6$ observations as in `raw3/`, or $9$ runs with $9$ observations): blocked with `reason="too_few_observations"`, distinguishing genuine low sample size from slicing inflation attacks.
     - Sufficient independent units ($10$ unique runs with $10$ observations, or $10$ unique runs with $20$ observations): passes with `GateOutcome.PASS`.
     - Polymorphic inputs tested: string run IDs, `WindowProvenance` instances, `ObservationRecord` instances, and dicts with `"run_id"`.
4. **Clean Abstention Status Preservation**:
   - In `services/causal-engine/app/domain/causal_validation.py` (lines 559–621), `run_preflight_checks`:
     - Evaluates gates in deterministic sequence: Gate G1, `gate_unique_run_ids` (if provided), `gate_treatment_variation` (if provided), `gate_outcome_present`, `gate_no_duplicate_observations`, `gate_component_mapping_quality`, `gate_temporal_order`, `gate_covariates_pre_treatment`.
     - When any gate fails, `passed=False` and `first_blocker` accurately preserves the specific blocking `GateVerdict`, including its `gate_name`, `reason`, and `suggested_status`.
   - In `services/causal-engine/app/application/run_analysis.py` (lines 268–285):
     - When preflight fails, estimation is aborted (`report.estimation_attempted = False`).
     - Abstention statuses are preserved verbatim: `report.estimation_status` receives `first_blocker.suggested_status` (`"insufficient_evidence"` for G1 and window slicing, `"not_identifiable"` for treatment variation, `"ambiguous_component"` for G2, `"invalid_graph"` for temporal violations). No synthetic effects or ATE estimates are fabricated.
5. **Execution Results**:
   - `python scripts/verify_challenger_m2.py`: **79 / 79 tests passed** (0 failed).
   - `pytest services/causal-engine/tests/test_causal_validation.py -v`: **109 / 109 tests passed** (0 failed, 1 warning).
   - `pytest tests/e2e/test_tier1_features.py -k "Feature06 or Feature07 or Feature08" -v`: **15 / 15 tests passed** (0 failed).
   - `pytest tests/e2e/test_tier2_boundaries.py -k "Gate or Preflight or Causal or Abstention" -v`: **16 / 16 tests passed** (0 failed).

---

## 2. Logic Chain

1. **Protocol Compliance**:
   - `EXPERIMENT_PROTOCOL.md` §2.1–§2.2 mandates that one run equals one independent experimental unit ($N=1$), and explicitly prohibits treating temporal windows as independent cross-sectional units to bypass Gate G1.
   - `EXPERIMENT_PROTOCOL.md` §6.1 mandates that Gate G1 ($N \ge 10$) acts strictly as a technical software sanity guard preventing rank-deficient regression matrices, disclaiming claims of statistical power.
   - `EXPERIMENT_PROTOCOL.md` §6.4 mandates treatment variation ($T \in \{0, 1\}$) before estimation can proceed.
2. **Stress Test Verification**:
   - Directly tested $N=9$ vs $N=10$ at Gate G1: $N=9$ blocked with `too_few_observations` and `insufficient_evidence`, while $N=10$ passed. The explanation string contains the mandated software sanity guard and power disclaimer.
   - Directly tested uniform treatments: $T=1$ across all units blocked with `no_treatment_variation` and `not_identifiable`; $T=0$ across all units similarly blocked.
   - Directly tested window slicing attack: passing 10 windows from 1 unique run triggered the slicing condition (`total_obs > num_unique and num_unique < 10`), emitting `window_slicing_detected` and `insufficient_evidence`.
   - Directly tested honest small batches: 6 runs with 6 observations blocked with `too_few_observations` without false-triggering `window_slicing_detected`.
   - Directly tested composite preflight and use-case integration: preflight reports maintain the first blocker, and `run_analysis.py` converts blocked verdicts to honest abstention without calling DoWhy or fabricating effects.
3. **Synthesis**:
   - All empirical behaviors match the requirements of `ORIGINAL_REQUEST.md` (R3), `PROJECT.md` (Features 6, 7, 8), and `EXPERIMENT_PROTOCOL.md` (§2, §6).

---

## 3. Caveats

1. **Input Representation for `gate_unique_run_ids`**:
   - `gate_unique_run_ids` calculates `total_obs = len(extracted_ids)` from the collection passed to it. Callers must pass the full sequence of observations or per-observation run IDs (e.g. `[obs.run_id for obs in observations]` or the observation objects directly), rather than a deduplicated set with a separate `observation_count` keyword argument. The function is designed and tested for sequence extraction, and this is properly satisfied in `run_preflight_checks` and `ObservationRecord`.
2. **Infrastructure PostgreSQL Tests**:
   - Seven async repository storage tests in `test_scm_constructor.py::TestGraphStoreRoundTrip` require `asyncpg` and live PostgreSQL, which are part of database infrastructure rather than domain preflight logic. They were deselected during engine test runs per project standard procedure.

---

## 4. Conclusion

**Verdict: APPROVE**

Preflight Gate G1, treatment variation gating, and anti-window slicing enforcement in `services/causal-engine/app/domain/causal_validation.py` are robust, mathematically defensible, and fully compliant with R3 and `EXPERIMENT_PROTOCOL.md`:
- $N=9$ strictly blocks with `too_few_observations` and suggested status `insufficient_evidence`.
- $N=10$ passes Gate G1 as a minimum technical guard.
- Batches with uniform treatment ($T=1$ only or $T=0$ only) strictly block with `no_treatment_variation` and suggested status `not_identifiable`.
- Window slicing attacks (e.g., 10 temporal windows from 1 run) are actively detected and blocked with `window_slicing_detected` and suggested status `insufficient_evidence`.
- All abstention statuses are cleanly preserved without exception leakage or fabricated causal metrics.

---

## 5. Verification Method

To independently reproduce and verify this assessment:

1. **Run the Challenger Stress Test Harness**:
   ```powershell
   python scripts/verify_challenger_m2.py
   ```
   *Expected Output*: `STRESS TEST SUMMARY: Total=79, Passed=79, Failed=0`.

2. **Run Causal Validation Unit Tests**:
   ```powershell
   pytest services/causal-engine/tests/test_causal_validation.py -v
   ```
   *Expected Output*: `109 passed, 1 warning`.

3. **Run E2E Tier 1 & Tier 2 Preflight Tests**:
   ```powershell
   pytest tests/e2e/test_tier1_features.py -k "Feature06 or Feature07 or Feature08" -v
   pytest tests/e2e/test_tier2_boundaries.py -k "Gate or Preflight or Causal or Abstention" -v
   ```
   *Expected Output*: 31 passed (15 in Tier 1, 16 in Tier 2).
