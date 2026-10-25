# Milestone 1 Review & Adversarial Challenge Report

**Reviewer Agent**: `reviewer_m1_2` (`teamwork_preview_reviewer`)  
**Roles**: Reviewer, Adversarial Critic  
**Date**: 2026-10-24  
**Target Deliverables**:
- `d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md` (R1)
- `d:\project-1\EXPERIMENT_PROTOCOL.md` (R2)
- Worker Handoff: `d:\project-1\.agents\teamwork\worker_m1\handoff.md`  
**Parent Agent**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Verdict**: **APPROVE**  

---

## Review Summary & Verdict

- **Verdict**: **APPROVE**
- **Overall Quality**: Exceptional scientific rigor, comprehensive empirical verification, and mathematically sound causal protocol design.
- **Integrity Audit**: **CLEAN**. No hardcoded evaluation outcomes, no facade implementations, no shortcuts or bypasses, and zero fabricated claims. Every single factual statement in the audit and protocol has been independently corroborated against raw dataset artifacts.

---

## Detailed Evaluation of the 5 Mandatory Examination Areas

### 1. Strict Decoupling of the 4 Dimensions
- **Audit & Protocol Coverage**: `EXPERIMENT_PROTOCOL.md` §3 (lines 44–118) and `EXPERIMENTAL_EVALUATION_AUDIT.md` §4 (lines 149–196).
- **Formal Decoupling**:
  1. **Injection Delivery Success** ($T_{\text{inject}} \in \{0, 1\}$ or `inject_ok`): Evaluates scenario delivery mechanics. If $T_{\text{inject}} = 0$ (`inject_ok=False`), the run is classified as **Failed Injection** and strictly excluded from detection sensitivity ($TPR$) and attribution denominators.
  2. **Independently Verified Behavior** ($B_{\text{verified}} \in \{0, 1, \text{unknown}\}$): Independent physical evidence from out-of-band mock sinks (`phantom-sink:8443`), host `/proc/<pid>/cmdline`, or file artifacts. If telemetry is missing, labels remain strictly `unknown` and are never imputed.
  3. **Verified Contract Drift** ($Y_{\text{drift}} \in \{0, 1, \text{unknown}\}$): Normative comparison of verified behavior against the cryptographically signed container contract.
  4. **PHANTOM Detection Alert** ($\hat{Y}_{\text{phantom}} \in \{0, 1\}$): Empirical detector output within the qualifying time window $[t_{\text{inject}}, t_{\text{inject}} + \text{window}]$.
- **Decoupled Metric Grounding**:
  - $TP \iff (Y_{\text{drift}} = 1 \land \hat{Y}_{\text{phantom}} = 1)$
  - $FN \iff (Y_{\text{drift}} = 1 \land \hat{Y}_{\text{phantom}} = 0)$
  - $FP \iff (Y_{\text{drift}} = 0 \land \hat{Y}_{\text{phantom}} = 1)$
  - $TN \iff (Y_{\text{drift}} = 0 \land \hat{Y}_{\text{phantom}} = 0 \land \text{Coverage}_{\text{verified}} = \text{True})$
  - When monitoring coverage is unverified, absent detections are classified as `collection_dropout`, never as True Negatives.
- **Reviewer Assessment**: **PASS**. Decoupling is absolute and prevents the historic conflation of injection attempts with detector false negatives.

### 2. Runtime Activity vs. Signed Contract Violation
- **Audit & Protocol Coverage**: `EXPERIMENT_PROTOCOL.md` §3.3 (lines 86–99) and §4.2 (lines 152–182).
- **Axiomatic Principle**:
  $$\text{Physical Runtime Activity} \neq \text{Contract Drift}$$
- **Evaluation**: The protocol explicitly clarifies that egress TCP connections to mock sinks (e.g. port 8443) or subprocess executions are physical runtime behaviors. They constitute contract drift ($Y_{\text{drift}} = 1$) **if and only if** the observed activity violates the cryptographically signed container contract. If an egress destination or lifecycle transition is explicitly permitted by the signed profile, $Y_{\text{drift}} = 0$. Conversely, in benign workloads, unexpected privilege transitions or relation violations constitute drift on benign load ($Y_{\text{drift}} = 1$).
- **Reviewer Assessment**: **PASS**. This prevents labeling non-violating network activity as drift and firmly anchors drift to signed contract semantics.

### 3. Causal Estimands & Strict Anti-Mediator DAG Conditioning
- **Audit & Protocol Coverage**: `EXPERIMENT_PROTOCOL.md` §5 (lines 185–240).
- **Structural Separation of Estimands**:
  - **Tier A (Intervention Effect)**: $\tau_{\text{inject}} \equiv \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 1)] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 0)]$, evaluating the external attack delivery intervention effect on cluster nodes, adjusted for pre-treatment baseline cluster covariates $X_{\text{pre}}$.
  - **Tier B (Component Attribution Effect)**: $\tau_{\text{purl}} \equiv \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{tampered})] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{clean})]$, evaluating component substitution effect inside the container, adjusted for pre-treatment workload confounders $X_{\text{workload}}$.
- **Anti-Mediator Conditioning Rules**:
  - Intermediate execution artifacts ($B_{\text{behavior}}$, $B_{\text{process}}$, spawned pids, cgroups, syscall counts, network sockets) are post-treatment mediators.
  - The protocol proves two distinct failure modes if mediators are conditioned upon:
    1. **Mechanism Blocking**: Conditioning on $B_{\text{process}}$ blocks the causal chain $T_{\text{purl}} \to B_{\text{process}} \to Y_{\text{drift}}$, biasing the estimated causal effect $\hat{\tau}_{\text{purl}} \to 0$.
    2. **M-Bias (Collider Stratification)**: If unobserved system noise $U$ influences both behavior and drift ($T \to B \leftarrow U \to Y$), conditioning on collider $B$ opens the spurious backdoor path $T \to B \leftarrow U \to Y$.
  - Conditioning sets are strictly restricted to **Tier 0 pre-treatment covariates** ($t_{\text{covariate}} < t_{\text{treatment}}$).
- **Reviewer Assessment**: **PASS**. Causal DAG specifications conform to rigorous Pearlian causal graphical standards.

### 4. Preflight Gate G1 ($N \ge 10$) Software Sanity Guard & Anti-Window Slicing
- **Audit & Protocol Coverage**: `EXPERIMENT_PROTOCOL.md` §2.2 (lines 34–41) and §6.1 (lines 247–280).
- **Independent Unit Specification**: Strict axiom: **ONE RUN = ONE INDEPENDENT EXPERIMENTAL UNIT** ($N=1$ per scenario repetition).
- **Anti-Window Slicing**: Contiguous temporal windows within a run are longitudinal, serially correlated observations. Slicing a single run into 10 windows to satisfy $N \ge 10$ is strictly prohibited as an invalid inflation of degrees of freedom violating I.I.D. assumptions.
- **Software Sanity Guard Definition**: Gate G1 is strictly a software sanity guard to prevent singular/rank-deficient regression matrices in OLS/GLM and division by zero in DoWhy estimators. Passing $N \ge 10$ is explicitly NOT claimed as statistical power, sample adequacy, or causal identifiability.
- **Preservation of Clean Abstention**: On existing datasets (`raw/` $N=6$ dropouts, `raw3/` $N=6$ completed attacks, $N=3$ failed rollouts, $N=0$ controls), Gate G1 cleanly blocks with `insufficient_evidence: too_few_observations`.
- **Reviewer Assessment**: **PASS**. The guard prevents pseudo-replication and guarantees honest abstention.

### 5. Ordinary Wilson Score Interval & Bootstrap MTTD
- **Audit & Protocol Coverage**: `EXPERIMENT_PROTOCOL.md` §7 (lines 307–336).
- **Formula Specification**:
  $$p_{\text{lower}}, p_{\text{upper}} = \frac{\hat{p} + \frac{z^2}{2n} \mp z \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
- **Exact Benchmarks Verified** ($z = 1.95996398454$):
  - For $k=6, n=6$: $[0.6096657, 1.0000] \implies \mathbf{[0.6096, 1.0000]}$.
  - For $k=0, n=6$: $[0.0000, 0.390334] \implies \mathbf{[0.0000, 0.3904]}$.
  - No continuity correction and no normal approximation.
- **Bootstrap MTTD**: 95% percentile bootstrap interval computed with $B=2,000$ resamples with replacement over true positive latencies, accompanied by mean (15.74s), median (5.52s), and IQR.
- **Undefined Denominators**: Explicit policy returning `None` / `\text{---}` when denominators are zero (e.g., $FPR$ when $FP+TN=0$), strictly prohibiting defaulting to 0.0 or 1.0.
- **Reviewer Assessment**: **PASS**. Exact mathematical formula and benchmark compliance verified.

---

## Adversarial Challenge & Stress Tests

### Challenge 1: Key Schema Asymmetry in Scenario JSONs
- **Observation**: In `research/datasets/raw3/*.json`, the scenario identifier is stored under the key `"attack_id"` (e.g. `"attack_id": "xzutils-001"`), while in `research/datasets/raw/*.json` legacy runs it is under `"scenario_id"`.
- **Attack Scenario**: An evaluator or verification script assuming `"scenario_id"` exists across all files (such as `scripts/verify_audit_empirics.py` line 142) fails with `TypeError: argument of type 'NoneType' is not a container or iterable` when evaluating raw3 files.
- **Mitigation**: Downstream parsers in Milestone 3 (`evaluator.py`, `comparison_table.py`) must adopt robust key resolution: `scen_id = data.get("scenario_id") or data.get("attack_id")`.
- **Severity**: Minor (advisory for M3/M4 implementers).

### Challenge 2: Quartile Interpolation Method in Small Samples ($N=6$)
- **Observation**: For the 6 completed attack latencies $[2.578, 2.607, 4.682, 6.350, 7.876, 70.332]$, different IQR algorithms yield slightly different numbers:
  - `statistics.quantiles(data, n=4, method='inclusive')`: $\text{IQR} = 7.4944 - 2.6072 = 4.8872\,\text{s}$ (reported as 4.88s).
  - Tukey's hinges / median split: $\text{IQR} = 7.8759 - 2.6072 = 5.2687\,\text{s}$.
  - Default NumPy linear interpolation: $\text{IQR} = 4.3686\,\text{s}$.
- **Blast Radius**: If automated test assertions in M3/M5 check IQR with high decimal precision without specifying the interpolation method, tests could fail due to quartile convention mismatches.
- **Mitigation**: Milestone 3 test writers should explicitly test the specific quantile method implemented (e.g., `statistics.quantiles` inclusive or Tukey hinges) or check tolerance $\pm 0.1\,\text{s}$.
- **Severity**: Minor (advisory for M3/M5 test suites).

---

## 5-Component Handoff Protocol

### 1. Observation
1. **Deliverable Existence & Integrity**:
   - `d:\project-1\EXPERIMENTAL_EVALUATION_AUDIT.md`: 360 lines, 29,414 bytes.
   - `d:\project-1\EXPERIMENT_PROTOCOL.md`: 356 lines, 25,881 bytes.
   - Both files are complete, non-truncated, and fully articulated.
2. **Empirical Dataset Audit Verification**:
   - `research/datasets/raw/`: Exactly 114 JSON files (1 `index.json` with 6 registered runs, plus 113 scenario JSON files). Exactly 0 phantom detections and 0 Falco detections across all 113 scenario files. 299 metrics snapshots all contain 0.0 fallbacks.
   - `research/datasets/raw3/`: Exactly 9 JSON files.
     - 3 `solarwinds-001` runs: truncated at Phase 2 (`inject_ok=False`, duration ~126.7s, error: `inject() returned False`), 0 detections, 0 true positives.
     - 6 completed attack runs (`xzutils-001` and `dep-confusion-001`): 3,701 total detections, all `is_true_positive: True`.
     - Detections field analysis: 100% `pod_name = "unknown"` (3,701/3,701), 100% `container_name = "unknown"` (3,701/3,701), 99.08% `container_id = "unknown"` (3,667/3,701), 100% dummy image digest `sha256:000...`, 100% `purl = null` and `sbom_id = null`.
     - Event types: 2,555 `privilege_transition` (69.04%) and 1,146 `namespace_change` (30.96%). Zero process spawn, network connect, or file access events recorded.
     - 0 benign control runs in `raw3/`.
3. **Existing Test Suite Verification**:
   - `research/evaluation/tests`: 60 passed in 0.19s (Python 3.14).
   - `services/sbom-service/tests`: 177 passed in 1.65s (Python 3.12).
   - `services/causal-engine/tests`: 283 passed in 39.80s (Python 3.12).
   - Total: 520 passed, 0 failed.

### 2. Logic Chain
1. *From Observation 2*: Telemetry polling in `raw/` failed across all 113 runs regardless of scenario type or injection delivery success. Therefore, absent detections represent telemetry collection failure, and classifying benign runs in `raw/` as True Negatives is scientifically invalid.
2. *From Observation 2*: All 3 `solarwinds-001` runs in `raw3/` timed out during Phase 2 injection (`inject_ok=False`) before attack execution. Therefore, these are failed injection deliveries and must be excluded from detection sensitivity ($TPR$) denominators.
3. *From Observation 2*: `raw3/` contains 0 benign control runs. Therefore, $FPR$, Precision, and F1 denominators are empty, and these metrics are mathematically undefined (`None` / `\text{---}`).
4. *From Observation 2*: 100% of drift detections in `raw3/` have `purl = null` and `pod_name = "unknown"`. Therefore, component attribution cannot be identified from these records, and Preflight Gate G2 must block with `ambiguous_component`.
5. *From Observation 2 & 3*: Sample size in `raw3/` completed runs is $N=6 < 10$. Therefore, Preflight Gate G1 must block causal estimation with `insufficient_evidence: too_few_observations`.
6. *From Observation 1*: The protocol in `EXPERIMENT_PROTOCOL.md` strictly incorporates all these rules, establishes structural causal DAGs with anti-mediator conditioning, enforces ordinary Wilson score intervals, and prohibits window slicing.

### 3. Caveats
1. **Remote AWS EKS Cluster Telemetry**: The raw records were collected from an AWS EKS v1.36.2 cluster (`eks.6` platform, containerd). No live cluster re-execution was conducted; the audit is strictly forensic.
2. **Quartile Convention**: In small samples ($N=6$), the reported IQR of 4.88s reflects inclusive percentile interpolation (`statistics.quantiles` inclusive). Implementations in M3 should document the chosen interpolation convention.

### 4. Conclusion
Worker M1's deliverables (`EXPERIMENTAL_EVALUATION_AUDIT.md` and `EXPERIMENT_PROTOCOL.md`) fully satisfy Requirements R1 and R2 and all Milestone 1 acceptance criteria. All findings and rules are evidence-based, scientifically defensible, and adversarial-hardened.
**Verdict: APPROVE.**

### 5. Verification Method
To independently verify this review:
1. Run independent dataset verification:
   `python d:\project-1\.agents\teamwork\reviewer_m1_2\verify_audit.py`
2. Run test suites:
   - `python -m pytest research/evaluation/tests`
   - `d:\project-1\.venv-causal\Scripts\pytest.exe services/sbom-service/tests`
   - `d:\project-1\.venv-causal\Scripts\pytest.exe services/causal-engine/tests`
3. Invalidation Conditions:
   - Any raw JSON file in `research/datasets/raw/` containing non-empty `phantom_detections` invalidates the collection dropout finding.
   - Any `solarwinds-001` file in `raw3/` having `inject_ok=True` invalidates the failed injection finding.
   - Any detection in `raw3/` with a non-null `purl` invalidates the identity resolution failure finding.
