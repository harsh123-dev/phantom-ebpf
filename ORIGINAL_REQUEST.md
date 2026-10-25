# Original User Request

## Initial Request — 2026-10-24T05:44:39Z

# Teamwork Project Prompt — Draft

> Status: Launched
> Goal: Craft prompt → get user approval → delegate to teamwork_preview
> Requested team: [none — teamwork routes from the description to full team]

Develop and execute a reproducible, scientifically defensible experimental evaluation for PHANTOM (Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes), auditing existing raw records, establishing independent ground-truth verification, implementing defensible detection/mapping/causal evaluation, and generating an honest empirical report.

Working directory: d:\project-1
Integrity mode: benchmark

## Requirements

### R1. Real Experimental Data Audit & Inventory
Inspect all raw dataset records (`research/datasets/raw/`, `research/datasets/raw3/`, and `research/evaluation/`), classify each run (completed attack, failed injection, benign control, incomplete run), and create `EXPERIMENTAL_EVALUATION_AUDIT.md`. Accurately document available vs. missing telemetry, event counts, SBOM mappings, container/image digests, and kernel/K8s versions without treating collection dropouts as true negatives.

### R2. Independent Ground-Truth & Experimental Protocol
Establish `EXPERIMENT_PROTOCOL.md` defining hypotheses, independent experimental units (one run = one unit), verified ground-truth collection, and observation windows.
Strictly decouple four dimensions:
1. Injection delivery success (`inject_ok`)
2. Independently verified behavior (sink receipts, process verification)
3. Verified contract violation/drift ($Y_{\text{drift}}$): sink connection is runtime network activity, not automatically contract drift; drift occurs only when that behavior violates the signed container contract. When independent verification or coverage is insufficient, labels must remain `unknown` and never be imputed.
4. PHANTOM detection alert ($\hat{Y}_{\text{phantom}}$).
Explicitly formalize the causal estimands: separate the experiment-level injection intervention effect ($T_{\text{inject}} \to Y_{\text{drift}}$) from component attribution ($T_{\text{purl}} \to Y_{\text{drift}}$), enforcing strict anti-mediator DAG conditioning rules.

### R3. Observation Schemas & Preflight Data-Quality Validation
Extend the observation schema to associate every record with stable run and window IDs, immutable event references, and provenance. Implement preflight checks for timestamp ordering, injection success, telemetry coverage, and split leakage.
Enforce Preflight Gate G1 ($N \ge 10$) strictly as a minimum technical software sanity guard to avoid singular/rank-deficient regression matrices, not proof of statistical power, sample adequacy, or causal identifiability. Require treatment variation ($T \in \{0, 1\}$), comparable controls, valid labels, and justified structural DAG exchangeability before any estimation is attempted. Preserve abstention (`too_few_observations`, `positivity_failure`, `not_identifiable`) on small or imbalanced batches, strictly forbidding splitting one run into multiple windows to artificially satisfy G1.

### R4. Defensible Detection, Mapping & Causal Attribution Evaluation
Compute detection metrics (TPR, FPR, Precision, Recall, F1, MTTD, FP/hr) strictly with appropriate independent denominators. Compute proportion uncertainty intervals using the **standard (ordinary) Wilson score interval** without continuity correction, matching the exact mathematical formula ($[0.6096, 1.0000]$ for $6/6$), and non-parametric bootstrap intervals for MTTD.
Empirically evaluate runtime-to-SBOM mapping against independent package manifests, keeping verified, inferred, and ambiguous statuses distinct. Evaluate causal attribution using actual Part 4–6 interfaces, preserving distinct statuses (`INVALID_GRAPH`, `NOT_IDENTIFIABLE`, `INSUFFICIENT_EVIDENCE`, `ESTIMATION_FAILED`), treating confidence scores as heuristic diagnostic stability indices, and abstaining whenever causal identification is unsupported.

### R5. Baseline Comparisons & Resource-Overhead Accounting
Audit and execute eligible baselines (Falco 0.44.1, Trivy 0.70.0, IsolationForest) against equivalent inputs and real logs. Distinguish static scanning (Trivy) from runtime drift detection, and leave comparative metrics unavailable if baseline telemetry is missing. Measure container and agent CPU/memory overhead and event lag via Prometheus when live telemetry is available; if missing, report overhead as unmeasured rather than fabricating zero overhead.

### R6. Deterministic Reporting & Comprehensive Documentation
Implement a deterministic pipeline command that emits a versioned JSON report (`reports.json`) and LaTeX/CSV comparison tables from actual run records. Create `EXPERIMENTAL_EVALUATION_README.md` documenting environment requirements, scenario lifecycles, reproduction commands, and explicit limitations. Clearly demarcate offline-verified infrastructure from live-cluster execution requirements, and never claim unsupported metrics in the paper or final summaries.

## Acceptance Criteria

### Data Provenance & Integrity
- [ ] `EXPERIMENTAL_EVALUATION_AUDIT.md` inventories all 6 runs in `raw/` and 9 runs in `raw3/`, distinguishing completed runs, failed injections (`inject_ok=False`), and telemetry collection failures.
- [ ] No absent detection is classified as a True Negative (TN) unless active monitoring coverage is independently verified.
- [ ] Ground-truth drift labels are derived from independent oracle signals evaluated against signed contracts, never from PHANTOM's own detection outputs.
- [ ] Incomplete or unverified ground truth remains strictly `unknown`.

### Causal Inference & Preflight Guards
- [ ] Preflight Gate G1 is treated strictly as a minimum technical software rule; passing $N \ge 10$ is not claimed as statistical adequacy or causal identifiability.
- [ ] Preflight Gate G1 cleanly abstains with `insufficient_evidence: too_few_observations` on existing datasets without bypasses.
- [ ] Estimation strictly requires treatment variation, controls, valid labels, and justified causal assumptions before execution.
- [ ] Within-run temporal windows are used strictly for latency/timeline diagnostics and are never treated as independent cross-sectional units for causal inference.
- [ ] Post-treatment execution artifacts are not conditioned on as pre-treatment confounders in causal models.

### Metric Calculation & Statistical Uncertainty
- [ ] Standard Wilson score confidence intervals (without continuity correction) are computed for all binary rates; MTTD reports median and IQR alongside mean.
- [ ] Undefined metric denominators return unavailable/undefined (or 0.0 where specified by formula) without raising unhandled exceptions or inventing false positives/negatives.
- [ ] Trivy static scans, Falco rule evaluations, and IsolationForest anomaly outputs are verified from actual inputs, or recorded as unavailable.
- [ ] Resource overhead is recorded as unmeasured/null when Prometheus metrics are missing, not converted to 0.0.

### Test Coverage & Reporting
- [ ] All existing test suites continue to pass (`services/causal-engine/tests` 283 passed, `services/sbom-service/tests` 177 passed, `research/evaluation/tests` 37 passed).
- [ ] New unit tests cover failed injection exclusions, G1 abstention preservation, standard Wilson score calculations, and report determinism.
- [ ] Final pipeline report generates deterministic JSON containing data quality summaries, run exclusions, and honest limitation disclosures.
- [ ] `EXPERIMENTAL_EVALUATION_README.md` and `EXPERIMENT_PROTOCOL.md` are complete and reviewable.
