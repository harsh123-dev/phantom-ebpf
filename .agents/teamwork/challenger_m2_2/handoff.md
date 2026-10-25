# Milestone 2 Challenge Report: Causal DAG & Observation Builder Verification

**Agent**: `challenger_m2_2` (teamwork_preview_challenger)  
**Parent**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Date**: 2026-10-24  
**Scope**: Adversarial verification of `services/causal-engine/app/domain/causal.py` and `services/causal-engine/app/domain/observation_builder.py`.  
**Verdict**: **APPROVE**

---

## 1. Observation

Direct examination and empirical test execution against the work completed by `worker_m2` revealed the following concrete implementation details and test results:

1. **Anti-Mediator SCM Graph Enforcement (`causal.py`)**:
   - In `services/causal-engine/app/domain/causal.py` (`build_scm_graph`, lines 268–284):
     ```python
     for cov in covariate_names:
         if is_post_treatment_mediator(cov):
             log.warning(
                 "scm_builder.mediator_covariate_excluded_from_confounders",
                 covariate=cov,
                 reason="anti_mediator_conditioning_rule",
             )
             continue
         if not dag.has_edge(cov, treatment_name):
             dag.add_edge(cov, treatment_name)
         if not dag.has_edge(cov, outcome_name):
             dag.add_edge(cov, outcome_name)
     ```
   - In `is_post_treatment_mediator` (lines 149–207), 14 standard mediator names and substrings are registered (`process_behavior`, `syscall_count`, `run_duration_s`, `run_duration`, `file_behavior`, `network_behavior`, `privilege_behavior`, `contract_deviation`, `runtime_sbom_drift`, `b_behavior`, `b_process`, `spawned_pids`, `network_packets`, `intermediate_process_spawns`), with case-insensitive normalization and Tier $\ge 2$ checks against `CAUSAL_TIERS`.
   - In `build_scm_graph` (lines 254–261), edges from post-treatment execution mediators into treatment in projection edges ($M \to T$) are intercepted and blocked:
     ```python
     if tgt == treatment_name and is_post_treatment_mediator(src):
         log.warning(
             "scm_builder.mediator_to_treatment_edge_blocked",
             source=src,
             target=tgt,
         )
         continue
     ```

2. **Decoupled Ground-Truth & Estimands in Observation Builder (`observation_builder.py`)**:
   - In `_classify_run_outcome` (lines 700–733), detector alerts ($\hat{Y}_{\text{phantom}}$) are strictly isolated from ground-truth drift ($Y_{\text{drift}}$):
     ```python
     # Independent oracle verified contract drift:
     if manifest.verified_contract_drift is not None:
         if manifest.verified_contract_drift == 1:
             return OutcomeLabel.POSITIVE, "verified_contract_drift"
         elif manifest.verified_contract_drift == 0:
             return OutcomeLabel.NEGATIVE, "verified_contract_drift"
     ...
     # Attack run without verified contract drift label:
     # Ground truth is unknown. A PHANTOM detection alert alone does not
     # constitute ground-truth drift (Y_drift != Y_hat_phantom).
     return OutcomeLabel.UNKNOWN, "unverified_drift_telemetry"
     ```
   - When `manifest.verified_contract_drift` is absent on an attack run and `is_true_positive` is False, `_classify_outcome_value` yields `outcome_value = None`, causing `build_from_run_manifest_only` to exclude the run with `BuilderInsufficiency(reason_code="unknown_outcome")`.
   - Treatment variables are strictly separated:
     - `t_inject`: `1 if (manifest.is_attack_run and manifest.injection_succeeded is True) else 0` (line 509).
     - `t_purl`: `1 if manifest.is_attack_run else 0` (line 512).
     - `treatment_target`: `"inject"` selects `t_inject`, `"purl"` selects `t_purl`.
     - When `injection_succeeded is False` (`inject_ok=False`), the run returns `OutcomeLabel.FAILED_INJECTION`, excluding the run with `BuilderInsufficiency(reason_code="failed_injection")`.

3. **`ObservationRecord` Schema Completeness and Immutability (`observation_builder.py`)**:
   - `ObservationRecord` (lines 135–168) is declared with `@dataclass(frozen=True)` and defines:
     `run_id: str`, `window_id: str`, `window_index: int`, `t_inject: int`, `t_purl: int`, `treatment_value: int`, `outcome_value: Optional[int]`, `y_hat_phantom: Optional[int]`, `pre_treatment_covariates: dict[str, float]`, `event_refs: tuple[str, ...]`, `provenance: Optional[WindowProvenance]`.
   - In lines 572–580, `pre_treatment_covariates` strictly accepts pre-treatment variables (e.g. from `manifest.pre_treatment_covariates` or `manifest.repetition`), never post-treatment artifacts like `run_duration_s` or `injection_succeeded`.

4. **Empirical Execution of 56 New Adversarial Tests**:
   - Created `services/causal-engine/tests/test_adversarial_challenger_m2.py` containing 56 test cases.
   - Execution command: `pytest services/causal-engine/tests/test_adversarial_challenger_m2.py -v`.
   - Result: 56 passed, 0 failed in 5.49s.
   - Regression run with existing validation suite: `pytest services/causal-engine/tests/test_causal_validation.py services/causal-engine/tests/test_adversarial_challenger_m2.py`.
   - Result: 165 passed, 0 failed in 3.70s.
   - E2E test verification:
     - `pytest tests/e2e/test_tier1_features.py -k "Feature06 or Feature07 or Feature08"`: 15 passed in 1.71s.
     - `pytest tests/e2e/test_tier2_boundaries.py -k "Gate or Preflight or Causal or Abstention"`: 16 passed in 1.59s.

---

## 2. Logic Chain

1. **Anti-Mediator Conditioning Rule Conformance**:
   - *Premise*: `EXPERIMENT_PROTOCOL.md` §5.3 forbids conditioning on post-treatment execution artifacts ($B_{\text{behavior}}$, $B_{\text{process}}$, syscall counts, network packets, run duration) to prevent blocking the causal mechanism or inducing M-bias / collider stratification.
   - *Observed*: In `test_adversarial_challenger_m2.py`, 20 distinct mediator variables (including exact names, uppercase variations, and substrings) were passed into `build_scm_graph` as `covariate_names`. In 100% of cases, `dag.has_edge(M, treatment)` was `False` and `dag.has_edge(M, outcome)` was `False`.
   - *Observed*: When 7 Tier 0 pre-treatment variables (`cluster_node_count`, `kernel_version`, `baseline_rps`, `container_cpu_limit`, `base_image_os`, `repetition`, `initial_memory_mb`) were passed, `dag.has_edge(Z, treatment)` was `True` and `dag.has_edge(Z, outcome)` was `True`.
   - *Inference*: `build_scm_graph` strictly and accurately enforces the anti-mediator conditioning rule while preserving valid pre-treatment confounder adjustment paths.

2. **Decoupling of Detector Alerts ($\hat{Y}$) from Verified Drift ($Y_{\text{drift}}$)**:
   - *Premise*: `EXPERIMENT_PROTOCOL.md` §3.3 & §3.4 mandates that runtime contract drift must be verified independently against signed contracts and never evaluated from PHANTOM's own alerts.
   - *Observed*: In `test_phantom_alert_alone_is_not_used_as_ydrift`, a manifest with `first_phantom_detection_timestamp` present, `verified_contract_drift=None`, and `is_true_positive=False` was processed. `CausalObservationBuilder` returned `OutcomeLabel.UNKNOWN`, excluded the observation, and populated `batch.insufficiencies` with `reason_code="unknown_outcome"`.
   - *Observed*: In `test_benign_run_with_detector_false_alarm` (false alarm on benign run), `rec.outcome_value` evaluated to 0 while `rec.y_hat_phantom` evaluated to 1.
   - *Observed*: In `test_verified_contract_drift_overrides_detector_absence` (detector false negative), `rec.outcome_value` evaluated to 1 while `rec.y_hat_phantom` evaluated to 0.
   - *Inference*: Detector performance ($\hat{Y}$) is strictly decoupled from ground-truth drift ($Y$). PHANTOM cannot self-evaluate against its own detection alerts.

3. **Separation of $T_{\text{inject}}$ and $T_{\text{purl}}$**:
   - *Premise*: `EXPERIMENT_PROTOCOL.md` §5 requires separating the experiment-level intervention effect ($T_{\text{inject}} \to Y_{\text{drift}}$) from component-level attribution ($T_{\text{purl}} \to Y_{\text{drift}}$).
   - *Observed*: When `inject_ok=False` in an attack run, `rec.t_inject` evaluates to 0, `rec.t_purl` evaluates to 1, and the run is classified as `OutcomeLabel.FAILED_INJECTION`, excluding it from causal estimation with `reason_code="failed_injection"`.
   - *Observed*: Parameter `treatment_target="inject"` selects $T_{\text{inject}}$, while `treatment_target="purl"` selects $T_{\text{purl}}$ as the active estimation treatment value.
   - *Inference*: The two estimands are formally separated in schema and execution.

4. **ObservationRecord Schema Integrity**:
   - *Premise*: `PROJECT.md` Feature 5 and `EXPERIMENT_PROTOCOL.md` §2 require stable IDs, immutable event references, and strict provenance.
   - *Observed*: `rec.run_id`, `rec.window_id` (`f"{run_id}_w0"`), and `rec.event_refs` match input provenance. `ObservationRecord` and `WindowProvenance` are frozen; attempting attribute mutation raises `dataclasses.FrozenInstanceError`. Post-treatment artifacts (`run_duration_s`, `injection_succeeded`) are absent from `pre_treatment_covariates`.
   - *Inference*: The observation schema satisfies all structural and immutability invariants.

---

## 3. Challenge Report

### Challenge Summary
**Overall risk assessment**: **LOW**

The implementation in `services/causal-engine/app/domain/` satisfies the formal mathematical and protocol requirements specified in `EXPERIMENT_PROTOCOL.md` and `PROJECT.md`.

### Challenges Tested

#### 1. [Low] Mediators in SCM Covariates
- **Assumption challenged**: Calling `build_scm_graph` with post-treatment mediators in `covariate_names` might add spurious $M \to T$ or $M \to Y$ edges.
- **Attack scenario**: Injected 20 mediator variations (casing, substrings) into `covariate_names`.
- **Result**: PASSED. Zero illegal edges added.

#### 2. [Low] Malformed Projection Edges
- **Assumption challenged**: Upstream BDG projections containing $M \to T$ edges might bypass DAG validation.
- **Attack scenario**: Injected `(("process_behavior", 1), (treatment, 1))` into `projection.projected_edges`.
- **Result**: PASSED. Intercepted by `is_post_treatment_mediator` and blocked.

#### 3. [Low] Self-Evaluation via Detection Alert
- **Assumption challenged**: Presence of `first_phantom_detection_timestamp` might impute positive drift.
- **Attack scenario**: Manifest with alert but unverified drift label.
- **Result**: PASSED. Cleanly classified as `OutcomeLabel.UNKNOWN` and excluded.

#### 4. [Low] Unit Slicing Bypass
- **Assumption challenged**: Slicing a single run into 10 windows could bypass Gate G1.
- **Attack scenario**: Sliced run IDs tested against `gate_unique_run_ids`.
- **Result**: PASSED. Blocked with `window_slicing_detected`.

### Stress Test Results

- `test_mediator_covariates_receive_no_edges_to_treatment_or_outcome` (20 variations) → No $M \to T$ or $M \to Y$ edges → **PASS**
- `test_pre_treatment_covariates_receive_confounding_edges` (7 variables) → Both $Z \to T$ and $Z \to Y$ edges added → **PASS**
- `test_mixed_mediators_and_pre_treatment_covariates` → Confounders kept, mediators excluded → **PASS**
- `test_adversarial_projected_edge_from_mediator_to_treatment_blocked` → Projected $M \to T$ blocked → **PASS**
- `test_construct_causal_model_with_mediators_preserves_valid_dag` → DoWhy model built with valid GML DAG → **PASS**
- `test_phantom_alert_alone_is_not_used_as_ydrift` → Unverified alert yields `OutcomeLabel.UNKNOWN` → **PASS**
- `test_verified_contract_drift_overrides_detector_absence` → FN retains $Y=1, \hat{Y}=0$ → **PASS**
- `test_benign_run_with_detector_false_alarm` → FP retains $Y=0, \hat{Y}=1$ → **PASS**
- `test_decoupling_of_t_inject_and_t_purl_on_failed_injection` → Failed injection yields $T_{\text{inject}}=0, T_{\text{purl}}=1$, excluded → **PASS**
- `test_treatment_target_selection_inject_vs_purl` → Target selects proper treatment variable → **PASS**
- `test_observation_record_schema_fields_and_immutability` → All fields validated, mutation raises error → **PASS**
- `test_post_treatment_execution_artifacts_excluded_from_covariates` → Post-treatment metrics excluded → **PASS**
- `test_batch_aggregation_and_gate_g1_abstention` → Multi-run aggregation enforces G1 and variation → **PASS**
- `test_window_slicing_adversarial_detection` → Slicing 1 run into 10 windows blocked → **PASS**
- `test_is_post_treatment_mediator_boundary_discrimination` (17 cases) → Exact classification → **PASS**

### Unchallenged Areas
- Downstream statistical metrics (Wilson score intervals, bootstrap MTTD, LaTeX tables) belong to Milestone 3 and were not challenged.

---

## 4. Caveats

1. **Async Repository Storage Tests**:
   - As documented by `worker_m2`, 7 tests in `test_scm_constructor.py::TestGraphStoreRoundTrip` requiring PostgreSQL driver `asyncpg` remain deselected; this is an infrastructure dependency outside domain validation.
2. **Historical Dataset Baseline Absence**:
   - The verified behavior ensures that running the causal engine on existing raw datasets (`raw/`, `raw3/`) cleanly abstains without fabricating causal effects.

---

## 5. Conclusion

**Verdict: APPROVE**

The causal DAG construction and observation builder in Milestone 2 fully satisfy all requirements from `PROJECT.md`, `EXPERIMENT_PROTOCOL.md`, and `ORIGINAL_REQUEST.md`:
1. Post-treatment mediators are strictly excluded from receiving directed edges to treatment or outcome in `build_scm_graph`.
2. Pre-treatment confounders correctly receive directed edges $Z \to T$ and $Z \to Y$.
3. PHANTOM detection alerts ($\hat{Y}$) are strictly decoupled from verified contract drift ($Y_{\text{drift}}$).
4. $T_{\text{inject}}$ and $T_{\text{purl}}$ are cleanly separated.
5. `ObservationRecord` schema fields (`run_id`, `window_id`, `event_refs`) and immutability invariants are enforced.

---

## 6. Verification Method

To independently reproduce the empirical challenge verification:

```powershell
# 1. Run the 56 new adversarial stress tests
pytest services/causal-engine/tests/test_adversarial_challenger_m2.py -v

# 2. Run the full causal validation unit test suite (165 passed)
pytest services/causal-engine/tests/test_causal_validation.py services/causal-engine/tests/test_adversarial_challenger_m2.py -v

# 3. Verify Tier 1 E2E tests for Features 6, 7, 8 (15 passed)
pytest tests/e2e/test_tier1_features.py -k "Feature06 or Feature07 or Feature08" -v

# 4. Verify Tier 2 E2E boundary tests (16 passed)
pytest tests/e2e/test_tier2_boundaries.py -k "Gate or Preflight or Causal or Abstention" -v
```
