# PHANTOM Research Audit

## Executive finding

PHANTOM's repository contains substantial implementation for SBOM ingestion, eBPF event handling, variable-order Markov contracts, KL drift scoring, typed BDG updates, a DoWhy estimation path, PCEPS scoring, API/report services, and test suites. The existing IEEE manuscript overstates what the checked-in evaluation establishes. The raw dataset has six completed attack runs with event-positive drift events, three failed SolarWinds-style injections, and no benign controls. More importantly, all saved detections have ambiguous/missing runtime identity and no PURL/SBOM binding. The defensible current result is therefore **six of six valid injected runs contained at least one drift event in the detection window**, not component-attributed detection, 100% causal accuracy, calibrated prediction, a zero false-positive rate, or low runtime overhead.

The original paper and source files were left unchanged. The revised manuscript is a separate copy in this directory. The copied manuscript preserves the established title and research question, but reports implementation separately from evidence and narrows unsupported claims.

## Materials inspected

- Existing paper source and PDF: `phantom_paper_final.tex`, `phantom_paper_final.pdf`.
- Saved project handoffs: `docs/phantom_task_1_architecture_handoff.md` through `docs/phantom_task_4_evaluation_methodology_handoff.md`.
- Source paths: SBOM service; eBPF Markov, KL, contract generation and Kubernetes attributor; causal-engine BDG, SCM/DoWhy, PCEPS feature/training/scoring modules; evaluation runner, metrics, baselines and attack definitions.
- Experiment evidence: nine JSON files in `research/datasets/raw3/`, `research/evaluation/results3/reports.json`, CSV/TeX tables, `research/datasets/scenario_run_log.txt`, and `research/datasets/baseline_run_log.txt`.
- No PowerPoint deck or standalone diagram source was found in the inventoried project files. The LaTeX manuscript contains an algorithm and tables but no external figure assets.

Handoff material is treated as design intent where it exceeds code or experiment evidence. ChatGPT conversations outside this workspace were not accessible for review; no claim is made that they were inspected. The available in-session history contained prior wording edits and confirms the expected replacement paragraphs, but those are editorial choices, not scientific evidence.

## Findings and severity

| Severity | Finding | Evidence | Disposition |
|---|---|---|---|
| Critical | Manuscript metrics (8/9 TPR, 0.05 FPR, F1 0.872, 54.3 s MTTD, overhead, baseline comparisons) conflict with checked-in source records. | Current manuscript Section Evaluation vs raw3/results3. | Corrected in the revised copy; unsupported metrics are removed. |
| Critical | Three SolarWinds-style runs are failed injections, not false negatives or completed attack trials. | Each SolarWinds raw3 record has `error="inject() returned False"`, no attack phase; scenario log records the failure. | Excluded from effectiveness denominator and reported as failed/incomplete. Rerun required. |
| Critical | Event-positive run label is too weak to validate component-level detection or attribution. | Runner marks TP when any event is observed within window. Saved events are `namespace_change`/`privilege_transition`, identity is ambiguous/missing, PURL and SBOM ID null, workload fields unknown. | Manuscript uses “event-positive run” and explicitly states attribution is unverified. |
| High | No benign controls exist in raw3; results table sets FPR to zero despite `n_benign=0`. | `results3/reports.json`; evaluator zero-denominator handling. | FPR, precision, full binary F1 and FP/hour are marked undefined/unverified. |
| High | Reported 100% causal attribution has no per-run ground-truth attribution evidence. | `results3/reports.json` aggregate only; raw3 has no correct-PURL comparison and unresolved binding. | Removed as a validated result. Causal method is documented as implemented but unevaluated. |
| High | PCEPS AUC/Brier/calibration claims lack model and prediction artifacts. | Search of research outputs and source: no deployed/trained PCEPS artifacts, scored windows, labels or metrics. | Removed from empirical claims; scoring method retained in algorithm specification. |
| High | Zero CPU/memory/event-lag values are not proof of zero cost. | All raw3 metric snapshots are 0.0; no provenance/raw samples. | Marked unverified. Re-measurement required. |
| High | Baseline results came from a dry-run or missing alert logs. | `baseline_run_log.txt`: Falco/Trivy setup skipped, Falco alert files missing; output all zero. | Baselines are not presented as comparative evidence. Trivy is identified as a static scanner with a different task. |
| High | Split-conformal threshold and non-scorable contract decision appear in design handoff but not KL scorer. | `KlDriftScorer` returns continuous score; no calibration threshold API. | Revised claims describe continuous score only and state missing thresholded detector step. |
| Medium | Current paper’s PCEPS table used feature family labels that do not match implemented 16 features. | `PCEPS_FEATURE_NAMES`, `feature_extractor.py`. | Replaced in revised copy with actual ordered feature names and formula. |
| Medium | Current paper describes graph projection as preserving causal inference, but tiering is a design rule and not causal proof. | `bdg.py` tier map/projection and SCM builder; projection only orders graph edges. | Revised paper labels it as assumed temporal projection and keeps association distinct from cause. |
| Medium | Project plans and source disagree on some reproducibility details; saved trial manifest omits actual cluster/kernel/image digests and version outputs. | run script states desired EKS/K8s pins; raw3 lacks manifest. | Exact missing details listed in experiment validation and future work. |
| Low | References contain a possibly inaccurate EuroSys LLM-RCA citation and no verified Bomfather source in the checked-in bibliography. | Manuscript reference [14] is incomplete; Bomfather absent. | The revised paper removes unsupported specific novelty comparison and avoids relying on those entries. Further bibliography verification remains necessary before submission. |

## Contribution-by-contribution novelty and evidence

| Contribution | Existing system distinction | PHANTOM mechanism | Status/evidence |
|---|---|---|---|
| SBOM-anchored behavioral contracts | SBOM and runtime monitors commonly serve separate purposes; this integration alone is not algorithmic novelty. | Signed SBOM/image identity plus a variable-order Markov model keyed by image/PURL. | Contract training/signing code exists. Runtime evaluation records show no resolved component binding, so end-to-end anchoring is not empirically demonstrated. |
| Drift detection | eBPF monitors already detect policy or behavior changes; novelty is not simply using eBPF. | Conditional sequence KL against learned contract. | Score code and unit tests exist. A calibrated threshold/decision rule is absent in scorer; no verified false-alarm evaluation. |
| BDG construction | Provenance/dependency graphs are established methods. | Typed, directed multigraph with time-decayed edges, evidence references and snapshotting. | Implemented. Graph association does not itself establish causality. |
| Structural causal attribution | DoWhy is a general causal inference library; applying it to a security graph is integration, not by itself novelty. | BDG temporal projection, specified treatment/outcome/covariates, DoWhy identification/estimation, abstention and refutations. | Code path exists; assumptions and projection are partly heuristic. No raw experiment validates attribution correctness. Narrowed claim to implementation pathway, not validated causal novelty. |
| PCEPS | XGBoost and Platt scaling are established tools. | A 16-feature score combines runtime, provenance, attribution and context features for ranking. | Feature and scoring code exist; model outputs and predictive experiment absent. No prospectivity claim retained. |

The revised manuscript does not claim this combination is novel because it combines known components. The central research contribution remains a testable integration hypothesis: verified component identity plus contract-conditioned event evidence may support a useful attribution workflow. The current artifacts do not establish that hypothesis experimentally.

## Preserved completed work

- Fixed PHANTOM title, research domain, intended pipeline, and core terminology.
- Existing Markov variable-order model with BIC selection, local context pruning, Laplace smoothing, and signed serialization.
- Existing typed directed multigraph, edge decay update, event idempotency, evidence references, and temporal projection.
- Existing DoWhy adapter and explicit `not_identifiable` outcomes for specified checks.
- Existing PCEPS feature names, feature extraction, mask, XGBoost training utility, Platt mapping, score range and severity thresholds.
- Earlier requested editorial replacements on Falco/Tetragon, README setup text, DoWhy adapter prose, and API/report-generator sentence remain retained where present in the copied paper or surrounding material.

## Completion checklist

- **Already resolved — preserved without unnecessary changes:** Project title and scope, service/algorithm architecture, variable-order Markov contract method, BDG update formula, DoWhy adapter path and PCEPS model/scorer implementation.
- **Verified and corrected:** Results arithmetic and latency timestamp arithmetic; failed SolarWinds injections excluded; zero-denominator FPR misrepresentation removed; incorrect paper narrative values and feature table replaced in the revised copy; original files retained.
- **Partially resolved:** IEEE paper structure and prose are revised, but bibliography validation for every reference and citation remains incomplete. The manuscript’s causal and component-binding description is explicitly constrained by implementation/evidence.
- **Unresolved:** Successful SolarWinds attack injection, benign controls, component-ground-truth attribution, trained/evaluated PCEPS, baseline reruns, thresholded drift decision, nonzero runtime overhead measurement, and full reproducibility manifest.
- **Unable to verify:** Cause of 70.33 s first XZ detection; historical ChatGPT conversation decisions outside available chat/workspace; the existence/details of the named Bomfather publication from repository materials; actual versions/digests/kernel used in the saved runs.

## Material changes made to the copied paper

1. Replaced Result Set A metrics with the narrow, recomputed raw3 evidence and reported the six completed runs and three failed injections distinctly.
2. Added a per-run/family results table; no placeholder values are used for missing data.
3. Removed unsupported FPR, precision/F1, false-positive-rate, causal-accuracy, PCEPS AUC/Brier, overhead and comparative baseline claims.
4. Rewrote detection criterion and MTTD description; kept timestamp-verified latency but state that event identity is unresolved.
5. Replaced the PCEPS feature table with the 16 implemented feature names and actual scoring formula interpretation.
6. Revised algorithm/projection description to distinguish graph relationship and tier assumptions from causal evidence.
7. Added methods, threats to validity, missing artifact details, and conclusion consistent with available evidence.
8. Kept the official title and double-blind metadata; preserved and refined the prior Falco/Tetragon descriptions.
9. After reviewing the user's online-compiled PDF, changed the run-outcome table to a compact single-column table and placed float barriers before the conclusion and bibliography. This prevents a deferred wide float from appearing among the references.
10. Replaced anonymous/double-blind author metadata in the revised copy with Harsh Ranjan, Jai Goel, and guide Dr. Thanuja R, their provided VIT affiliations, and email addresses.
11. Compiled the revised LaTeX source successfully with the desktop editor compiler.

## Review limitation

Reference claims and current web product capabilities should be checked against primary sources before conference submission. The previous thread context was not accessible beyond the active workspace/chat. These limitations are not silently converted into evidence.
