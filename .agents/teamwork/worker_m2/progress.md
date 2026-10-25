# Progress Log - worker_m2

Last visited: 2026-10-24T06:45:30Z
Status: Complete - All Milestone 2 requirements implemented and verified.

## Completed Work
1. Audited requirements from DISPATCH.md, ORIGINAL_REQUEST.md, PROJECT.md, EXPERIMENT_PROTOCOL.md, and survey_report.md.
2. Hardened `services/causal-engine/app/domain/causal_validation.py`:
   - Enforced Gate G1 ($N \ge 10$) strictly as a technical software sanity guard preventing rank-deficient regression matrices.
   - Updated explanation: "Minimum technical guard: N >= 10 required to prevent rank-deficient regression matrices. Does not imply statistical power or identifiability."
   - Implemented `gate_treatment_variation` blocking when $T$ has 0 controls or 0 treatments with `GateVerdict(outcome=BLOCK, reason="no_treatment_variation", suggested_status="not_identifiable")`.
   - Implemented `gate_unique_run_ids` (and alias `gate_independent_experimental_units`) preventing within-run window slicing from satisfying G1, emitting `window_slicing_detected`.
   - Updated `run_preflight_checks` to accept optional `run_ids` and `treatment_values`.
3. Extended `services/causal-engine/app/domain/observation_builder.py`:
   - Updated `WindowProvenance` with stable `window_id` and immutable `event_refs`.
   - Created `ObservationRecord` dataclass carrying stable `run_id`, `window_id`, `window_index`, `t_inject`, `t_purl`, `treatment_value`, `outcome_value`, `y_hat_phantom`, `pre_treatment_covariates`, `event_refs`, and `provenance`.
   - Strictly decoupled $T_{\text{inject}}$ (external intervention delivery) from $T_{\text{purl}}$ (component substitution).
   - Removed post-treatment execution artifacts (`run_duration_s`, `injection_succeeded`) from confounder covariates.
   - Prohibited using PHANTOM detection alert ($\hat{Y}_{\text{phantom}}$) as ground truth drift ($Y_{\text{drift}}$).
4. Hardened `services/causal-engine/app/domain/causal.py`:
   - Implemented `is_post_treatment_mediator()` detecting execution artifacts/mediators (Tier $\ge 2$ in BDG).
   - Enforced anti-mediator DAG conditioning in `build_scm_graph`: blocked mediator covariates from receiving confounding edges into treatment or outcome, and blocked mediator-to-treatment projection edges.
5. Added 18 new unit tests in `services/causal-engine/tests/test_causal_validation.py`:
   - `TestGateG1SoftwareSanityGuardRequirements`
   - `TestGateTreatmentVariationRequirements`
   - `TestGateUniqueRunIdsRequirements`
   - `TestAntiMediatorDagConditioningRequirements`
   - `TestObservationSchemaDecouplingRequirements`
6. Verification:
   - `pytest services/causal-engine/tests/test_causal_validation.py`: 109 passed (100%).
   - `pytest services/causal-engine/tests/`: 272 passed, 29 deselected.
   - `pytest tests/e2e/test_tier1_features.py -k "Feature06 or Feature07 or Feature08"`: 15 passed.
   - `pytest tests/e2e/test_tier2_boundaries.py`: 16 passed.
