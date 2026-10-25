## 2026-10-24T06:27:23Z
You are worker_m2 (teamwork_preview_worker). Your working directory is d:\project-1\.agents\teamwork\worker_m2.
Your parent is orchestrator_1 (conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9).

MANDATORY: Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.
Read PROJECT.md at: d:\project-1\PROJECT.md.
Read EXPERIMENT_PROTOCOL.md at: d:\project-1\EXPERIMENT_PROTOCOL.md.
Read survey report at: d:\project-1\.agents\teamwork\explorer_survey_2\survey_report.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

EXCLUSIVE WRITE OWNERSHIP:
You own exclusively:
- services/causal-engine/app/domain/causal_validation.py
- services/causal-engine/app/domain/observation_builder.py
- services/causal-engine/app/domain/causal.py
- services/causal-engine/tests/ (new unit tests or updates directly relating to preflight gates)
Do NOT modify sbom-service or evaluation/metrics files.

TASK DETAILS (Milestone 2: R3 - Observation Schemas & Preflight Data-Quality Validation):
1. In `services/causal-engine/app/domain/causal_validation.py`:
   - Enforce Preflight Gate G1 ($N \ge 10$) strictly as a technical software sanity guard preventing rank-deficient regression matrices in OLS/GLM.
   - Update explanation to explicitly clarify that passing $N \ge 10$ is NOT proof of statistical power, sample adequacy, or causal identifiability.
   - Require treatment variation ($T \in \{0, 1\}$), comparable controls, and valid labels before estimation. Implement or reinforce `gate_treatment_variation` that blocks when $T$ has 0 controls or 0 treatments with `GateVerdict(outcome=BLOCK, reason="no_treatment_variation", suggested_status="not_identifiable")`.
   - Preserve clean abstention (`too_few_observations`, `positivity_failure`, `not_identifiable`) on small or imbalanced batches.
   - Strictly forbid splitting one run into multiple temporal windows to artificially satisfy Gate G1. Add validation that checks `unique_run_ids` if run-level independent units are evaluated.
2. In `services/causal-engine/app/domain/observation_builder.py`:
   - Extend observation schema to associate every record with stable `run_id`, `window_id`, immutable event references, and provenance.
   - Strictly decouple $T_{\text{inject}}$ (external scenario injection) from $T_{\text{purl}}$ (component attribution).
   - Ensure post-treatment execution artifacts (like `run_duration_s`, intermediate process spawns) are NOT conditioned on as pre-treatment confounders.
   - Prohibit using PHANTOM detection alert ($\hat{Y}_{\text{phantom}}$) as ground-truth drift ($Y_{\text{drift}}$).
3. In `services/causal-engine/app/domain/causal.py`:
   - Enforce strict anti-mediator DAG conditioning rules: restrict confounder adjustments strictly to Tier 0 pre-treatment variables. Do NOT add edges from post-treatment execution mediators into treatment or outcome.
4. Run tests and verify:
   - Run tests: `pytest services/causal-engine/tests/test_causal_validation.py`
   - Ensure all causal-engine unit tests pass.
5. Write a comprehensive 5-component handoff report at `d:\project-1\.agents\teamwork\worker_m2\handoff.md` and send a message to parent.
