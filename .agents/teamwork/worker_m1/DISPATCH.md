## 2026-10-24T06:03:40Z
You are worker_m1 (teamwork_preview_worker). Your working directory is d:\project-1\.agents\teamwork\worker_m1.
Your parent is orchestrator_1 (conversation ID: 4299c465-79cb-468c-95c3-8aed4c92f7f9).

MANDATORY: Read ORIGINAL_REQUEST.md at: d:\project-1\.agents\teamwork\ORIGINAL_REQUEST.md before starting work.
Read PROJECT.md at: d:\project-1\PROJECT.md.
Read explorer findings at:
- d:\project-1\.agents\teamwork\explorer_survey_1\survey_report.md
- d:\project-1\.agents\teamwork\explorer_survey_1\handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

EXCLUSIVE WRITE OWNERSHIP:
You own exclusively:
- d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md
- d:\project-1\EXPERIMENT_PROTOCOL.md
Do NOT modify any other project files.

TASK DETAILS (Milestone 1: R1 & R2):
1. Author `d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md` (R1):
   - Complete inventory and classification of all raw records in `research/datasets/raw/` (all 6 indexed runs + 108 legacy runs) and `research/datasets/raw3/` (all 9 runs).
   - Classify every run into completed attack, failed injection (`inject_ok=False`), benign control, or telemetry collection dropout.
   - Accurately document available vs. missing telemetry, event counts (e.g. 3,701 drift detections in raw3), SBOM mappings, container/image digests, kernel/K8s versions.
   - Document upstream identity resolution failure (100% missing pod names, null SBOM IDs, null PURLs, ambiguous identity statuses).
   - Document collection dropouts in `raw/` (100% empty detections) and prohibit treating them as True Negatives.
   - Document Prometheus fallback zeros (unmeasured overhead) and empty Falco logs.
2. Author `d:\project-1\EXPERIMENT_PROTOCOL.md` (R2):
   - Define hypotheses, independent experimental units (one run = one unit), verified ground-truth collection, and observation windows.
   - Strictly decouple the 4 dimensions:
     1. Injection delivery success (`inject_ok`)
     2. Independently verified behavior (sink receipts, process verification)
     3. Verified contract violation/drift ($Y_{\text{drift}}$): sink connection is runtime network activity, not automatically drift; drift occurs only when runtime behavior violates the signed container contract. When independent verification or coverage is insufficient, labels must remain `unknown` and never be imputed.
     4. PHANTOM detection alert ($\hat{Y}_{\text{phantom}}$).
   - Formalize causal estimands: separate experiment-level injection ($T_{\text{inject}} \to Y_{\text{drift}}$) from component attribution ($T_{\text{purl}} \to Y_{\text{drift}}$), enforcing strict anti-mediator DAG conditioning rules (Tier 0 pre-treatment covariates only).
   - Explicitly document Preflight Gate G1 ($N \ge 10$) as software sanity guard and strictly forbid splitting runs into windows to artificially satisfy G1.

When complete, write a thorough 5-component handoff report at `d:\project-1\.agents\teamwork\worker_m1\handoff.md` and send a message to parent.
