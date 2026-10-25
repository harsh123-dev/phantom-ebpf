# BRIEFING — 2026-10-24T06:01:00Z

## Mission
Investigate and survey R2 (Causal estimands & DAG rules), R3 (Observation Schemas & Preflight Data-Quality Validation), and R4 (Defensible Detection, Mapping & Causal Attribution Evaluation) across causal-engine, sbom-service, and research/evaluation.

## 🔒 My Identity
- Archetype: explorer (teamwork_preview_explorer)
- Roles: Read-only investigator, synthesis reporter
- Working directory: d:\project-1\.agents\teamwork\explorer_survey_2
- Original parent: 4299c465-79cb-468c-95c3-8aed4c92f7f9
- Milestone: Survey & Investigation (R2, R3, R4)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement
- Investigate causal-engine, sbom-service, research/evaluation
- Detailed focus on Preflight Gate G1, Wilson score intervals, bootstrap MTTD, SBOM mapping, causal estimands & DAGs, abstention handling
- Document findings in survey_report.md and handoff.md

## Current Parent
- Conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9
- Updated: 2026-10-24T06:01:00Z

## Investigation State
- **Explored paths**:
  - `services/causal-engine/app/domain/{bdg.py, causal.py, causal_validation.py, observation_builder.py, entities.py}`
  - `services/causal-engine/app/application/{run_analysis.py, estimate_attribution.py}`
  - `services/sbom-service/app/domain/mapping/{resolver.py, evidence.py, metrics.py}`
  - `research/evaluation/metrics/{evaluator.py, comparison_table.py}`
  - `research/evaluation/scenarios/{scenario_runner.py}`
  - `research/evaluation/attacks/{base_attack.py}`
  - `research/datasets/{raw/, raw3/}`
  - `research/evaluation/results3/{reports.json, table_1_detection_performance.tex}`
  - Test suites: `services/causal-engine/tests` (283 tests), `services/sbom-service/tests` (177 tests), `research/evaluation/tests` (60 tests)
- **Key findings**:
  - R2: $T_{\text{inject}}$ and $T_{\text{purl}}$ are conflated; PHANTOM alert $\hat{Y}$ is used as $Y_{\text{drift}}$; SCM unconditionally inserts covariate edges violating anti-mediator DAG rules.
  - R3: Preflight Gate G1 ($N \ge 10$) is a software sanity guard; cleanly abstains on existing 6 runs; single-run window slicing is forbidden.
  - R4: Standard ordinary Wilson score interval matches $[0.6096, 1.0000]$ for $6/6$; bootstrap MTTD and Wilson intervals missing in code; undefined denominators defaulted to 0.0 creating false 0.000 FPR claims; failed injections incorrectly counted as FNs; existing unit test asserts FN on failed run.
- **Unexplored areas**: Complete survey finished. Implementation to be delegated to downstream specialists.

## Key Decisions Made
- Fully documented all findings and recommendations in `survey_report.md`
- Generated 5-component self-contained handoff in `handoff.md`

## Artifact Index
- DISPATCH.md — Recorded instructions
- BRIEFING.md — Working memory & state
- progress.md — Liveness heartbeat
- survey_report.md — Comprehensive technical survey report
- handoff.md — 5-component handoff report
