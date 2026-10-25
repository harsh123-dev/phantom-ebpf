"""
scripts/verify_challenger_m2.py

Empirical stress testing and adversarial challenge harness for Milestone 2:
- Preflight Gate G1 ($N >= 10$ software sanity guard)
- Treatment variation ($T in {0, 1}$, one-sided blocking)
- Anti-window slicing ($N=1$ per run, detection of temporal window inflation)
- Clean abstention status preservation (insufficient_evidence, not_identifiable)
"""

import sys
from pathlib import Path

# Add project root and services/causal-engine to sys.path
root_dir = Path(__file__).resolve().parent.parent
causal_dir = root_dir / "services" / "causal-engine"
if str(causal_dir) not in sys.path:
    sys.path.insert(0, str(causal_dir))

from app.domain.causal_validation import (
    GateOutcome,
    GateVerdict,
    PreflightReport,
    REASON_TOO_FEW_OBSERVATIONS,
    REASON_NO_TREATMENT_VARIATION,
    REASON_WINDOW_SLICING_DETECTED,
    REASON_MISSING_OUTCOME,
    REASON_UNRESOLVED_COMPONENT,
    REASON_AMBIGUOUS_COMPONENT,
    gate_minimum_observations,
    gate_treatment_variation,
    gate_unique_run_ids,
    gate_independent_experimental_units,
    gate_outcome_present,
    gate_no_duplicate_observations,
    gate_component_mapping_quality,
    gate_temporal_order,
    run_preflight_checks,
)
from app.domain.observation_builder import (
    WindowProvenance,
    ObservationRecord,
)
from app.domain.entities import CausalObservation


class TestHarness:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests_run = 0

    def assert_true(self, condition: bool, msg: str):
        self.tests_run += 1
        if condition:
            self.passed += 1
        else:
            self.failed += 1
            print(f"[FAIL] {msg}")

    def assert_equal(self, actual, expected, msg: str):
        self.tests_run += 1
        if actual == expected:
            self.passed += 1
        else:
            self.failed += 1
            print(f"[FAIL] {msg} | Expected {expected!r}, got {actual!r}")


def run_stress_tests() -> bool:
    h = TestHarness()
    print("=" * 70)
    print("RUNNING ADVERSARIAL CHALLENGER STRESS TESTS FOR MILESTONE 2")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # 1. Gate G1 Stress Tests ($N=9$ blocks, $N=10$ passes)
    # -------------------------------------------------------------------------
    print("\n--- 1. Testing Preflight Gate G1 ($N >= 10$ Software Sanity Guard) ---")

    # N = 9 (Boundary below minimum)
    v9 = gate_minimum_observations(9, minimum=10)
    h.assert_equal(v9.outcome, GateOutcome.BLOCK, "N=9 must block Gate G1")
    h.assert_equal(v9.reason, REASON_TOO_FEW_OBSERVATIONS, "N=9 reason must be too_few_observations")
    h.assert_equal(v9.suggested_status, "insufficient_evidence", "N=9 status must be insufficient_evidence")
    h.assert_true(
        "Minimum technical guard: N >= 10 required to prevent rank-deficient" in v9.explanation,
        "N=9 explanation must state technical guard against rank-deficient matrices"
    )
    h.assert_true(
        "Does not imply statistical power or identifiability" in v9.explanation,
        "N=9 explanation must disclaim statistical power / identifiability"
    )

    # N = 10 (Exact minimum)
    v10 = gate_minimum_observations(10, minimum=10)
    h.assert_equal(v10.outcome, GateOutcome.PASS, "N=10 must pass Gate G1")
    h.assert_equal(v10.reason, "", "N=10 reason must be empty string")
    h.assert_equal(v10.suggested_status, None, "N=10 suggested_status must be None")

    # Extreme boundaries: N = -1, N = 0, N = 1, N = 11, N = 1000
    v_neg = gate_minimum_observations(-1)
    h.assert_equal(v_neg.outcome, GateOutcome.BLOCK, "N=-1 must block")
    v_zero = gate_minimum_observations(0)
    h.assert_equal(v_zero.outcome, GateOutcome.BLOCK, "N=0 must block")
    v_one = gate_minimum_observations(1)
    h.assert_equal(v_one.outcome, GateOutcome.BLOCK, "N=1 must block")
    v_11 = gate_minimum_observations(11)
    h.assert_equal(v_11.outcome, GateOutcome.PASS, "N=11 must pass")
    v_1000 = gate_minimum_observations(1000)
    h.assert_equal(v_1000.outcome, GateOutcome.PASS, "N=1000 must pass")

    # Custom minimum threshold
    v_custom_4 = gate_minimum_observations(4, minimum=5)
    h.assert_equal(v_custom_4.outcome, GateOutcome.BLOCK, "N=4 with min=5 must block")
    v_custom_5 = gate_minimum_observations(5, minimum=5)
    h.assert_equal(v_custom_5.outcome, GateOutcome.PASS, "N=5 with min=5 must pass")

    # -------------------------------------------------------------------------
    # 2. Treatment Variation Stress Tests (all T=1 blocks, all T=0 blocks)
    # -------------------------------------------------------------------------
    print("\n--- 2. Testing Treatment Variation ($T in {0, 1}$) ---")

    # All T=1 (N=10)
    all_treated = [1] * 10
    vt1 = gate_treatment_variation(all_treated)
    h.assert_equal(vt1.outcome, GateOutcome.BLOCK, "All T=1 must block")
    h.assert_equal(vt1.reason, REASON_NO_TREATMENT_VARIATION, "All T=1 reason must be no_treatment_variation")
    h.assert_equal(vt1.suggested_status, "not_identifiable", "All T=1 status must be not_identifiable")
    h.assert_true("treated=10, controls=0" in vt1.explanation, "All T=1 explanation must state treated=10, controls=0")

    # All T=0 (N=10)
    all_control = [0] * 10
    vt0 = gate_treatment_variation(all_control)
    h.assert_equal(vt0.outcome, GateOutcome.BLOCK, "All T=0 must block")
    h.assert_equal(vt0.reason, REASON_NO_TREATMENT_VARIATION, "All T=0 reason must be no_treatment_variation")
    h.assert_equal(vt0.suggested_status, "not_identifiable", "All T=0 status must be not_identifiable")
    h.assert_true("treated=0, controls=10" in vt0.explanation, "All T=0 explanation must state treated=0, controls=10")

    # Empty treatment list
    v_empty = gate_treatment_variation([])
    h.assert_equal(v_empty.outcome, GateOutcome.BLOCK, "Empty treatment list must block")
    h.assert_equal(v_empty.reason, REASON_NO_TREATMENT_VARIATION, "Empty treatment reason must be no_treatment_variation")
    h.assert_equal(v_empty.suggested_status, "not_identifiable", "Empty treatment status must be not_identifiable")

    # Input format polymorphism:
    # A) CausalObservation objects
    obs_treated = [CausalObservation(window_index=i, treatment_value=1, outcome_value=1) for i in range(10)]
    h.assert_equal(gate_treatment_variation(obs_treated).outcome, GateOutcome.BLOCK, "Obs with all T=1 must block")
    obs_mixed = [CausalObservation(window_index=i, treatment_value=i % 2, outcome_value=1) for i in range(10)]
    h.assert_equal(gate_treatment_variation(obs_mixed).outcome, GateOutcome.PASS, "Obs with mixed T must pass")

    # B) Dictionaries with treatment_value or treatment
    dicts_val = [{"treatment_value": 1}, {"treatment_value": 0}]
    h.assert_equal(gate_treatment_variation(dicts_val).outcome, GateOutcome.PASS, "Dicts with treatment_value must pass")
    dicts_t = [{"treatment": 1}, {"treatment": 0}]
    h.assert_equal(gate_treatment_variation(dicts_t).outcome, GateOutcome.PASS, "Dicts with treatment key must pass")

    # C) Booleans
    bools = [True, False, True, False]
    h.assert_equal(gate_treatment_variation(bools).outcome, GateOutcome.PASS, "Booleans [True, False] must pass")

    # D) Adversarial non-binary treatments:
    # [2, 3] (neither 0 nor 1 present)
    v_non_binary = gate_treatment_variation([2, 3, 2, 3])
    h.assert_equal(v_non_binary.outcome, GateOutcome.BLOCK, "Treatments without 0 or 1 must block")
    # [0, 2] (1 not present)
    v_no_one = gate_treatment_variation([0, 2, 0, 2])
    h.assert_equal(v_no_one.outcome, GateOutcome.BLOCK, "Treatments without 1 must block")
    # [1, 2] (0 not present)
    v_no_zero = gate_treatment_variation([1, 2, 1, 2])
    h.assert_equal(v_no_zero.outcome, GateOutcome.BLOCK, "Treatments without 0 must block")

    # Extreme imbalance (1 treated, 99 controls) -> valid variation
    imbalanced_1 = [1] + [0] * 99
    h.assert_equal(gate_treatment_variation(imbalanced_1).outcome, GateOutcome.PASS, "1 treated + 99 controls must pass")
    # Extreme imbalance (99 treated, 1 control) -> valid variation
    imbalanced_2 = [1] * 99 + [0]
    h.assert_equal(gate_treatment_variation(imbalanced_2).outcome, GateOutcome.PASS, "99 treated + 1 control must pass")

    # -------------------------------------------------------------------------
    # 3. Anti-Window Slicing & Experimental Unit Integrity Stress Tests
    # -------------------------------------------------------------------------
    print("\n--- 3. Testing Anti-Window Slicing & Unit Integrity ---")

    # Attack 1: Pass 10 windows from 1 unique run_id (total_obs=10, num_unique=1)
    sliced_10 = ["run_attack_01"] * 10
    v_slice_10 = gate_unique_run_ids(sliced_10, minimum_unique_runs=10)
    h.assert_equal(v_slice_10.outcome, GateOutcome.BLOCK, "10 windows from 1 run must block")
    h.assert_equal(v_slice_10.reason, REASON_WINDOW_SLICING_DETECTED, "Must block with window_slicing_detected")
    h.assert_equal(v_slice_10.suggested_status, "insufficient_evidence", "Must suggest insufficient_evidence")
    h.assert_true("Slicing detected" in v_slice_10.explanation, "Explanation must explicitly state 'Slicing detected'")

    # Attack 2: Pass 100 windows from 1 unique run_id
    sliced_100 = ["run_attack_01"] * 100
    v_slice_100 = gate_unique_run_ids(sliced_100, minimum_unique_runs=10)
    h.assert_equal(v_slice_100.outcome, GateOutcome.BLOCK, "100 windows from 1 run must block")
    h.assert_equal(v_slice_100.reason, REASON_WINDOW_SLICING_DETECTED, "100 windows slicing reason must match")

    # Attack 3: Pass 15 windows from 3 unique runs (5 windows each)
    sliced_multi = ["run_A"] * 5 + ["run_B"] * 5 + ["run_C"] * 5
    v_slice_multi = gate_unique_run_ids(sliced_multi, minimum_unique_runs=10)
    h.assert_equal(v_slice_multi.outcome, GateOutcome.BLOCK, "15 windows from 3 runs must block")
    h.assert_equal(v_slice_multi.reason, REASON_WINDOW_SLICING_DETECTED, "15 windows from 3 runs must detect slicing")

    # Honest low-sample batches (no slicing, just too few runs):
    # A) 1 run, 1 observation
    v_honest_1 = gate_unique_run_ids(["run_001"], minimum_unique_runs=10)
    h.assert_equal(v_honest_1.outcome, GateOutcome.BLOCK, "1 single run must block")
    h.assert_equal(v_honest_1.reason, REASON_TOO_FEW_OBSERVATIONS, "1 single run must be too_few_observations")

    # B) 6 runs, 6 observations (like raw3 completed runs)
    raw3_runs = [f"raw3_run_{i}" for i in range(6)]
    v_raw3 = gate_unique_run_ids(raw3_runs, minimum_unique_runs=10)
    h.assert_equal(v_raw3.outcome, GateOutcome.BLOCK, "6 unique runs must block")
    h.assert_equal(v_raw3.reason, REASON_TOO_FEW_OBSERVATIONS, "6 unique runs must be too_few_observations")
    h.assert_equal(v_raw3.suggested_status, "insufficient_evidence", "6 unique runs status must be insufficient_evidence")

    # C) 9 runs, 9 observations
    v_nine = gate_unique_run_ids([f"run_{i}" for i in range(9)], minimum_unique_runs=10)
    h.assert_equal(v_nine.outcome, GateOutcome.BLOCK, "9 unique runs must block")
    h.assert_equal(v_nine.reason, REASON_TOO_FEW_OBSERVATIONS, "9 unique runs must be too_few_observations")

    # Compliant batches:
    # A) 10 unique runs, 10 observations
    v_ten = gate_unique_run_ids([f"run_{i}" for i in range(10)], minimum_unique_runs=10)
    h.assert_equal(v_ten.outcome, GateOutcome.PASS, "10 unique runs must pass")
    h.assert_equal(v_ten.reason, "", "10 unique runs reason must be empty")

    # B) 20 observations from 10 unique runs (2 windows per run, but >= 10 unique units)
    v_ten_runs_20_obs = gate_unique_run_ids([f"run_{i % 10}" for i in range(20)], minimum_unique_runs=10)
    h.assert_equal(v_ten_runs_20_obs.outcome, GateOutcome.PASS, "10 unique runs with 20 obs passes minimum unit requirement")

    # C) Empty run IDs list
    v_empty_runs = gate_unique_run_ids([], minimum_unique_runs=10)
    h.assert_equal(v_empty_runs.outcome, GateOutcome.BLOCK, "Empty run list must block")
    h.assert_equal(v_empty_runs.reason, REASON_TOO_FEW_OBSERVATIONS, "Empty run list must be too_few_observations")

    # Alias check
    h.assert_true(
        gate_independent_experimental_units is gate_unique_run_ids,
        "gate_independent_experimental_units must be identical alias to gate_unique_run_ids"
    )

    # Object polymorphism with WindowProvenance
    prov_sliced = [
        WindowProvenance(
            run_id="run_single",
            scenario_id="xzutils",
            window_index=i,
            window_start_iso="2026-01-01T00:00:00Z",
            window_end_iso="2026-01-01T00:01:00Z",
        )
        for i in range(10)
    ]
    h.assert_equal(
        gate_unique_run_ids(prov_sliced, minimum_unique_runs=10).reason,
        REASON_WINDOW_SLICING_DETECTED,
        "WindowProvenance list with 10 windows from 1 run must detect slicing"
    )

    # Object polymorphism with ObservationRecord
    obs_rec_sliced = [
        ObservationRecord(
            run_id="run_single",
            window_id=f"run_single_w{i}",
            window_index=i,
            t_inject=1,
            t_purl=1,
            treatment_value=1,
            outcome_value=1,
            y_hat_phantom=1,
            pre_treatment_covariates={},
            event_refs=(),
            provenance=None,
        )
        for i in range(10)
    ]
    h.assert_equal(
        gate_unique_run_ids(obs_rec_sliced, minimum_unique_runs=10).reason,
        REASON_WINDOW_SLICING_DETECTED,
        "ObservationRecord list with 10 windows from 1 run must detect slicing"
    )

    # Dictionaries with 'run_id'
    dict_sliced = [{"run_id": "run_single", "window_index": i} for i in range(10)]
    h.assert_equal(
        gate_unique_run_ids(dict_sliced, minimum_unique_runs=10).reason,
        REASON_WINDOW_SLICING_DETECTED,
        "Dictionary list with 'run_id' must detect slicing"
    )

    # -------------------------------------------------------------------------
    # 4. Composite Preflight Checks Integration (run_preflight_checks)
    # -------------------------------------------------------------------------
    print("\n--- 4. Testing Composite Preflight Checks Integration ---")

    # Scenario A: N=9 total observations
    rep_n9 = run_preflight_checks(
        observation_count=9,
        outcome_positive_count=5,
        window_indices=list(range(9)),
        mapping_statuses=["VERIFIED"] * 9,
        minimum_observations=10,
    )
    h.assert_equal(rep_n9.passed, False, "Preflight must fail for N=9")
    h.assert_equal(rep_n9.first_blocker.gate_name, "G1_minimum_observations", "First blocker must be G1")
    h.assert_equal(rep_n9.first_blocker.reason, REASON_TOO_FEW_OBSERVATIONS, "Reason must be too_few_observations")
    h.assert_equal(rep_n9.first_blocker.suggested_status, "insufficient_evidence", "Status must be insufficient_evidence")

    # Scenario B: N=10, but sliced from 1 run_id
    rep_sliced = run_preflight_checks(
        observation_count=10,
        outcome_positive_count=5,
        window_indices=list(range(10)),
        mapping_statuses=["VERIFIED"] * 10,
        run_ids=["run_single"] * 10,
        treatment_values=[1, 0] * 5,
        minimum_observations=10,
    )
    h.assert_equal(rep_sliced.passed, False, "Preflight must fail for sliced run_ids")
    h.assert_equal(rep_sliced.first_blocker.gate_name, "gate_unique_run_ids", "First blocker must be gate_unique_run_ids")
    h.assert_equal(rep_sliced.first_blocker.reason, REASON_WINDOW_SLICING_DETECTED, "Reason must be window_slicing_detected")
    h.assert_equal(rep_sliced.first_blocker.suggested_status, "insufficient_evidence", "Status must be insufficient_evidence")

    # Scenario C: N=10, 10 unique runs, but all T=1 (no treatment variation)
    rep_no_tv = run_preflight_checks(
        observation_count=10,
        outcome_positive_count=5,
        window_indices=list(range(10)),
        mapping_statuses=["VERIFIED"] * 10,
        run_ids=[f"run_{i}" for i in range(10)],
        treatment_values=[1] * 10,
        minimum_observations=10,
    )
    h.assert_equal(rep_no_tv.passed, False, "Preflight must fail when all T=1")
    h.assert_equal(rep_no_tv.first_blocker.gate_name, "gate_treatment_variation", "First blocker must be gate_treatment_variation")
    h.assert_equal(rep_no_tv.first_blocker.reason, REASON_NO_TREATMENT_VARIATION, "Reason must be no_treatment_variation")
    h.assert_equal(rep_no_tv.first_blocker.suggested_status, "not_identifiable", "Status must be not_identifiable")

    # Scenario D: N=10, 10 unique runs, both T=0 and T=1, but 0 positive outcomes
    rep_no_outcomes = run_preflight_checks(
        observation_count=10,
        outcome_positive_count=0,
        window_indices=list(range(10)),
        mapping_statuses=["VERIFIED"] * 10,
        run_ids=[f"run_{i}" for i in range(10)],
        treatment_values=[1, 0] * 5,
        minimum_observations=10,
    )
    h.assert_equal(rep_no_outcomes.passed, False, "Preflight must fail when outcome_positive_count=0")
    h.assert_equal(rep_no_outcomes.first_blocker.reason, REASON_MISSING_OUTCOME, "Reason must be outcome_absent_from_window")
    h.assert_equal(rep_no_outcomes.first_blocker.suggested_status, "insufficient_evidence", "Status must be insufficient_evidence")

    # Scenario E: All valid (N=10, 10 unique runs, balanced T, positive outcomes, verified mapping, ordered time)
    rep_valid = run_preflight_checks(
        observation_count=10,
        outcome_positive_count=5,
        window_indices=list(range(10)),
        mapping_statuses=["VERIFIED"] * 10,
        treatment_first_seen_ns=1000,
        outcome_first_seen_ns=2000,
        covariate_name_to_first_seen_ns={"baseline_rps": 500},
        run_ids=[f"run_{i}" for i in range(10)],
        treatment_values=[1, 0] * 5,
        minimum_observations=10,
    )
    h.assert_equal(rep_valid.passed, True, "All valid inputs must pass preflight")
    h.assert_equal(rep_valid.first_blocker, None, "No blocker on valid inputs")
    h.assert_equal(len(rep_valid.blocking_verdicts), 0, "No blocking verdicts on valid inputs")
    h.assert_equal(len(rep_valid.verdicts), 8, "Expected exactly 8 passed gates")

    # -------------------------------------------------------------------------
    # 5. Summary & Verdict
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(f"STRESS TEST SUMMARY: Total={h.tests_run}, Passed={h.passed}, Failed={h.failed}")
    print("=" * 70)
    return h.failed == 0


if __name__ == "__main__":
    success = run_stress_tests()
    sys.exit(0 if success else 1)
