## 2026-10-24T05:48:13Z
You are explorer_survey_2 (teamwork_preview_explorer). Your working directory is d:\project-1\.agents\teamwork\explorer_survey_2.
Your parent is orchestrator_1 (conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9).
MANDATORY: Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.
Do NOT implement any code. Your task is to investigate and survey R2 (Causal estimands & DAG rules), R3 (Observation Schemas & Preflight Data-Quality Validation), and R4 (Defensible Detection, Mapping & Causal Attribution Evaluation).
Investigate the authoritative sources:
1. Inspect the codebase for causal engine and evaluation:
   - `services/causal-engine/` (including Part 4-6 interfaces, estimators, DAGs, validation)
   - `services/sbom-service/`
   - `research/evaluation/` (schemas, validation scripts, metrics calculators, existing tests)
2. Investigate Preflight Gate G1 (N >= 10), how it is currently implemented and tested, how abstention (`too_few_observations`, `positivity_failure`, `not_identifiable`) is handled, and how windowing is used.
3. Investigate the current detection metric computation, Wilson score interval implementation (note requirement for ordinary Wilson score without continuity correction yielding [0.6096, 1.0000] for 6/6), bootstrap intervals for MTTD, and SBOM mapping evaluation.
4. Inspect the test suites and test runners: `services/causal-engine/tests` (283 tests), `services/sbom-service/tests` (177 tests), `research/evaluation/tests` (37 tests).
5. Document all findings, existing architecture, interface contracts, gaps, and recommendations in your working directory at `d:\project-1\.agents\teamwork\explorer_survey_2\survey_report.md` and write a handoff report at `d:\project-1\.agents\teamwork\explorer_survey_2\handoff.md`.
6. Send a message to parent when completed.
