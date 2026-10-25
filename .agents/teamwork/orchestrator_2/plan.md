# Master Execution Plan — Generation 2 (orchestrator_2)

## Context & Objectives
Resuming Project Orchestration for PHANTOM Experimental Evaluation Hardening:
- M1 (Audit & Protocol): PASSED GATE.
- E2E Testing Track (Tiers 1-4): 242/242 passed (TEST_READY.md).
- M2 (Observation Schemas & G1 Guard): PASSED GATE.
- M3 (Wilson Score, Evaluator, Tables): PASSED GATE.
- M4 (Deterministic Reporting & Documentation): Implementation delivered by worker_m4.

## Plan Breakdown

### Step 1: Milestone 4 Gate Verification
- **Subagents**:
  - `reviewer_m4_1` (`teamwork_preview_reviewer`): Review `run_pipeline_report.py`, `EXPERIMENTAL_EVALUATION_README.md`, `output/reports.json`, LaTeX/CSV tables. Verify compliance with R6 and acceptance criteria.
  - `reviewer_m4_2` (`teamwork_preview_reviewer`): Independent review of reporting schema v1.0.0, table formatting (`\text{---}`, no bolding unmeasured zeros), and documentation accuracy.
  - `challenger_m4_1` (`teamwork_preview_challenger`): Run CLI with various arguments (`--data-dir`, `--out`, `--tables-dir`), verify exit codes, determinism, exclusion of failed injections.
  - `challenger_m4_2` (`teamwork_preview_challenger`): Verify JSON schema validity, table parsing, reproducibility across multiple runs, and edge case CLI handling.
  - `auditor_m4_1` (`teamwork_preview_auditor`): Forensic integrity verification. Check for hardcoded outputs, fake tables, fabricated overhead, or circumvented evaluation.
- **Exit Criteria**: All Reviewers APPROVE, all Challengers APPROVE, Forensic Auditor CLEAN.

### Step 2: Phase 3 — Full-Battery E2E Verification & Existing Test Suites
- Dispatch worker/reviewer to run:
  - `services/causal-engine/tests`
  - `services/sbom-service/tests`
  - `research/evaluation/tests`
  - `tests/e2e/` (Tiers 1-4: 242 tests)
- **Exit Criteria**: 100% tests passing across all suites.

### Step 3: Phase 4 — Adversarial Coverage Hardening (Tier 5)
- Dispatch 2 Challengers (`challenger_t5_1`, `challenger_t5_2`) to analyze source + existing tests, identify untested code paths / boundary gaps, and write adversarial test cases.
- If gaps found: Dispatch Worker to integrate Tier 5 tests and fix exposed bugs, then Reviewer to verify.
- **Exit Criteria**: Zero remaining adversarial gaps; all new tests pass cleanly.

### Step 4: Phase 5 — Final Audit & Deterministic Reporting Verification
- Dispatch Final Forensic Auditor (`auditor_final`) for comprehensive project-wide integrity verification.
- Dispatch Worker to run final deterministic report generation and verify artifacts in `output/` and `research/evaluation/results3/`.
- **Exit Criteria**: Full audit CLEAN, deterministic artifacts verified.

### Step 5: Final Synthesis & Human Reporting
- Update `PROJECT.md` to mark all milestones and phases DONE.
- Compile comprehensive human report summarizing achievements, metrics, limitations, and reproducible evidence.
- Send completion message to parent.
