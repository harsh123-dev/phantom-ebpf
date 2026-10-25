# Dispatch for explorer_survey_1

- Identity: explorer_survey_1 (teamwork_preview_spec_miner)
- Working directory: d:\project-1\.agents\teamwork\explorer_survey_1
- Parent: d:\project-1\.agents\teamwork\orchestrator_1

Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.

## 2026-10-24T05:48:13Z
You are explorer_survey_1 (teamwork_preview_spec_miner). Your working directory is d:\project-1\.agents\teamwork\explorer_survey_1.
Your parent is orchestrator_1 (conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9).
MANDATORY: Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.
Do NOT implement any code. Your task is to investigate and survey R1 (Real Experimental Data Audit & Inventory) and R2 (Independent Ground-Truth & Experimental Protocol).
Investigate the authoritative sources:
1. Inspect raw dataset directories and files:
   - `research/datasets/raw/` (all 6 runs)
   - `research/datasets/raw3/` (all 9 runs)
   - `research/evaluation/`
2. For each run, inspect the structure, manifests, attack scenarios, telemetry files, logs, event counts, SBOM mappings, container/image digests, kernel/K8s versions, inject_ok flags, and telemetry drops.
3. Identify what ground truth signals, contracts, or oracle signals exist vs what is missing. Distinguish between completed attacks, failed injections, benign controls, and incomplete runs.
4. Note how R1 requires `EXPERIMENTAL_EVALUATION_AUDIT.md` and R2 requires `EXPERIMENT_PROTOCOL.md` (decoupling inject_ok, independently verified behavior, Y_drift, Y_hat_phantom; causal estimands with anti-mediator DAG rules).
5. Document all findings, inventory tables, file paths, and recommendations in your working directory at `d:\project-1\.agents\teamwork\explorer_survey_1\survey_report.md` and write a handoff report at `d:\project-1\.agents\teamwork\explorer_survey_1\handoff.md`.
6. Send a message to parent when completed.
