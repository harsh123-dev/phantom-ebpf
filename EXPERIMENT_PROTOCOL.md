# EXPERIMENT PROTOCOL: SCIENTIFIC EVALUATION PROTOCOL FOR PHANTOM

**Document Version**: 1.0.0  
**Status**: Authoritative Protocol Specification  
**Scope**: Experimental methodology, independent units, 4-dimensional ground-truth decoupling, structural causal DAGs, anti-mediator conditioning rules, and preflight sanity guards for PHANTOM evaluation.  

---

## 1. Scientific Motivation & Core Hypotheses

PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*) monitors container execution via eBPF kernel probes, constructs Behavioral Dependency Graphs (BDGs), detects deviations from cryptographically signed behavioral contracts, and attributes observed drift to specific software supply chain components via structural causal models.

To ensure empirical validity, reproducibility, and defensive causal claims, this protocol formalizes three testable scientific hypotheses:

### Hypothesis 1 ($H_1$): Timely Runtime Contract Drift Detection
> **Statement**: In Kubernetes microservice workloads subjected to software supply chain attacks (library backdoor injection, dependency confusion, or build-pipeline tampering), eBPF behavioral contract enforcement detects contract-violating activity prior to malicious payload completion ($\text{MTTD} < \text{attack\_duration}$) with statistically bounded True Positive Rates ($TPR$).

### Hypothesis 2 ($H_2$): Non-Spurious Causal Component Attribution
> **Statement**: Given verified runtime contract drift ($Y_{\text{drift}} = 1$) and defensible package mapping evidence, structural backdoor adjustment over pre-treatment workload covariates identifies the tampered package URL ($T_{\text{purl}}$) as the causal parent of the drift event, while cleanly abstaining when identification assumptions or data requirements fail.

### Hypothesis 3 ($H_3$): Minimal Intrusiveness & Negligible Overhead
> **Statement**: Real-time eBPF behavioral monitoring introduces bounded agent CPU overhead ($\le 5.0\%$), minimal memory footprint ($\le 64\,\text{MB}$ RSS), and negligible event ingestion lag ($P_{95} \le 100\,\text{ms}$) under representative production traffic loads.

---

## 2. Independent Experimental Units & Observation Windows

### 2.1 The Experimental Unit
- **Strict Axiom**: **ONE RUN = ONE INDEPENDENT EXPERIMENTAL UNIT** ($N=1$ per scenario repetition).
- An experimental unit is an independently instantiated, freshly deployed Kubernetes scenario run encompassing the full lifecycle:
  $$\text{Unit}_i = \langle \text{ScenarioID}, \text{Repetition}_j, \text{Namespace}, t_{\text{start}}, t_{\text{end}} \rangle$$
- Each run begins with clean cluster deployment, executes an explicit baseline phase, applies an intervention (or benign perturbation), collects detector and system telemetry, initiates rollback/recovery, and performs namespace cleanup.

### 2.2 Temporal Observation Windows vs. Experimental Units
- Within any given run $i$, time is discretized into contiguous observation windows $W_1, W_2, \dots, W_k$ (e.g., 5-second or 10-second intervals).
- **Prohibition on Unit Slicing**:
  - Temporal windows $W_k$ are **longitudinal, serially correlated observations of a single experimental unit**.
  - Temporal windows are valid **strictly for timeline diagnostics and latency calculations** (e.g., measuring Mean Time To Detect, $\text{MTTD} = t_{\text{alert}} - t_{\text{inject}}$).
  - Temporal windows **MUST NEVER be treated as independent cross-sectional units** to inflate sample size $N$ for statistical testing or to bypass sample-size sanity gates.
  - Slicing a single run into 10 windows and treating them as $N=10$ independent observations violates the Independent and Identically Distributed (I.I.D.) assumption, artificially deflates standard errors, and produces invalid causal inference.

---

## 3. Decoupling the Four Dimensions

Previous evaluations conflated attack execution, physical traffic, contract violations, and detector alerts. To achieve scientific defensibility, this protocol strictly decouples four distinct dimensions:

```
[ Dimension 1: Intervention Delivery ]
       T_inject in {0, 1} (inject_ok == True)
                    │
                    ▼
[ Dimension 2: Physical Runtime Execution ]
       B_verified in {0, 1, unknown} (Sink receipts, /proc inspection)
                    │
                    ▼
[ Dimension 3: Normative Contract Evaluation ]
       Y_drift in {0, 1, unknown} (Behavior violates Signed Contract)
                    │
                    ▼
[ Dimension 4: Detector Performance ]
       Y_hat_phantom in {0, 1} (PHANTOM alert fired within detection window)
```

### 3.1 Dimension 1: Injection Delivery Success ($T_{\text{inject}} \in \{0, 1\}$ or `inject_ok`)
- **Definition**: The physical success of the scenario delivery harness in deploying the intended workload configuration into the target container.
- **Evaluation Criteria**:
  - `inject_ok = True` $\iff$ kubectl commands (`cp`, `patch`, `rollout`) return exit code 0, container readiness probes succeed, and the scenario harness logs successful injection.
  - `inject_ok = False` $\iff$ rollout timeouts (e.g., `solarwinds-001` in `raw3/`), package installation errors, or container crashes during injection.
- **Handling Rule**:
  - When $T_{\text{inject}} = 0$ (`inject_ok = False`), the run is classified as **Failed Injection**.
  - **Exclusion Requirement**: Failed injection runs **MUST BE EXCLUDED** from detection sensitivity ($TPR$) denominators. They cannot evaluate detector performance because the intervention was never delivered. They must also be excluded from causal estimation.

### 3.2 Dimension 2: Physical Runtime Execution ($B_{\text{verified}} \in \{0, 1, \text{unknown}\}$)
- **Definition**: Independent physical evidence that the deployed payload actually executed code within the workload container.
- **Verification Sources**:
  1. Out-of-band network receipts at dedicated mock sinks (`phantom-sink:8443`, `phantom-sink:4445`, `phantom-sink:4446`).
  2. Direct `/proc/<pid>/cmdline` and process tree examination via host/node execution.
  3. Cryptographic hash verification of modified filesystem artifacts.
- **Handling Rule**:
  - If independent verification telemetry is captured and confirms payload execution $\implies B_{\text{verified}} = 1$.
  - If independent verification telemetry confirms clean execution without payload $\implies B_{\text{verified}} = 0$.
  - If sink receipt logs or host process inspection logs are missing or uncollected $\implies B_{\text{verified}} = \mathbf{unknown}$.
  - Under no circumstances may $B_{\text{verified}}$ be imputed based on scenario intentions.

### 3.3 Dimension 3: Verified Contract Violation / Drift ($Y_{\text{drift}} \in \{0, 1, \text{unknown}\}$)
- **The Core Scientific Principle**:
  $$\text{Physical Runtime Activity} \neq \text{Contract Drift}$$
  - A runtime network connection to a sink, a process spawn, or a file read is merely runtime behavior. It is **NOT automatically contract drift**!
  - Runtime behavior constitutes drift ($Y_{\text{drift}} = 1$) **if and only if** that observed behavior violates the cryptographically signed container contract.
  - If an egress network connection to port 8443 is explicitly permitted by the signed container profile, then $Y_{\text{drift}} = 0$, even if that connection was initiated by a malicious payload.
  - Conversely, in a benign scenario, if an unexpected process relation or privilege escalation violates the signed contract, $Y_{\text{drift}} = 1$ (representing contract drift on benign load).
- **Labeling Matrix**:
  - $Y_{\text{drift}} = 1$: Independent oracle verifies that observed runtime behavior violates the signed container profile.
  - $Y_{\text{drift}} = 0$: Independent oracle verifies that all observed runtime behavior is strictly permitted by the signed container profile.
  - $Y_{\text{drift}} = \mathbf{unknown}$: When independent verification or signed contract coverage is missing, ambiguous, or incomplete.
- **Strict Imputation Prohibition**:
  - **NEVER impute $Y_{\text{drift}}$**. If telemetry dropouts prevent verifying the contract violation, the label must remain `unknown`. It must not be defaulted to 0 or 1.

### 3.4 Dimension 4: PHANTOM Detection Alert ($\hat{Y}_{\text{phantom}} \in \{0, 1\}$)
- **Definition**: The empirical output of the PHANTOM detector during the evaluation window.
- **Qualification Rule**:
  - $\hat{Y}_{\text{phantom}} = 1 \iff$ At least one drift detection event is emitted by PHANTOM with:
    $$t_{\text{injection}} \le t_{\text{alert}} \le t_{\text{injection}} + \text{detection\_window\_s}$$
  - Subsequent alerts after the first within the same window do not increment True Positives; they are recorded for event rate analysis.
  - $\hat{Y}_{\text{phantom}} = 0 \iff$ Zero qualifying drift detection events are emitted within the window.
- **Decoupled Metric Grounding**:
  - **True Positive ($TP$)**: Requires BOTH independently verified drift AND a qualifying detector alert:
    $$TP \iff (Y_{\text{drift}} = 1 \land \hat{Y}_{\text{phantom}} = 1)$$
  - **False Negative ($FN$)**: Independently verified drift occurred, but detector failed to alert:
    $$FN \iff (Y_{\text{drift}} = 1 \land \hat{Y}_{\text{phantom}} = 0)$$
  - **False Positive ($FP$)**: No verified contract drift, but detector alerted:
    $$FP \iff (Y_{\text{drift}} = 0 \land \hat{Y}_{\text{phantom}} = 1)$$
  - **True Negative ($TN$)**: No verified contract drift, active monitoring coverage verified, and detector did not alert:
    $$TN \iff (Y_{\text{drift}} = 0 \land \hat{Y}_{\text{phantom}} = 0 \land \text{Coverage}_{\text{verified}} = \text{True})$$
  - **Telemetry Dropout**: If active monitoring coverage is NOT verified, absent detections ($\hat{Y} = 0$) are categorized as **Collection Dropout**, NEVER as True Negatives.

---

## 4. Ground-Truth Collection & Verification Protocols

### 4.1 Multi-Phase Scenario Lifecycle
Every scenario run adheres to a five-phase execution protocol managed by `ScenarioRunner`:

```
Phase 1: BASELINE (T_0 to T_1)
  - Workload running clean under synthetic background load (K6 / Locust).
  - Detector warm-up; verify zero baseline alerts.
  - Baseline Prometheus snapshot recorded (CPU, memory RSS).

Phase 2: INJECT (T_1 to T_2)
  - Scenario harness applies attack payload or benign update.
  - Injection delivery validated (exit codes, readiness checks).
  - If delivery fails, log inject_ok=False and abort to cleanup.

Phase 3: ATTACK / OBSERVATION (T_2 to T_3)
  - Workload executes with intervention active (duration: 120s to 300s).
  - Sink listener captures exfiltration beacons.
  - PHANTOM eBPF agent captures kernel events and emits drift alerts.
  - Attack phase Prometheus snapshot recorded.

Phase 4: RECOVER (T_3 to T_4)
  - Harness restores clean container image or executes rollback steps.
  - Pod readiness verified (`kubectl rollout status`).

Phase 5: POST-RECOVERY (T_4 to T_5)
  - Workload observed for post-recovery stabilization (duration: 60s to 120s).
  - Post-recovery Prometheus snapshot recorded.
  - Verification that drift alerts cease.
```

### 4.2 Independent Oracle Specifications
Oracle configurations are declaratively specified in `research/evaluation/oracles/*.yaml`:

1. **`xzutils-001.yaml` (Supply Chain Backdoor)**:
   - Target Service: `recommendationservice` (Python)
   - Component Substitution: Clean `pkg:pypi/lzmaffi@1.0.0` $\to$ Backdoored `pkg:pypi/lzmaffi@1.0.1-phantom-backdoor`
   - Sink Control Endpoint: `phantom-sink.phantom-eval.svc.cluster.local:8443`
   - Contract Violation: Outbound TCP connect to port 8443 and execution of `/tmp/.phantom_beacon.py` violate signed contract.
2. **`dep-confusion-001.yaml` (Dependency Confusion)**:
   - Target Service: `emailservice` (Python)
   - Component Substitution: Undeclared `pkg:pypi/acme-email-templates@9.9.9` injected via rogue internal index.
   - Sink Control Endpoint: `phantom-sink.phantom-eval.svc.cluster.local:4445`
   - Contract Violation: Egress to port 4445 and unauthorized subprocess spawn violate signed contract.
3. **`solarwinds-001.yaml` (Build Pipeline Tampering)**:
   - Target Service: `cartservice` (C# / .NET)
   - Component Substitution: Undeclared background worker `pkg:generic/phantom-background-worker@0.1.0` embedded in binary.
   - Sink Control Endpoint: `phantom-sink.phantom-eval.svc.cluster.local:4446`
   - Contract Violation: Undeclared background thread and network connect violate signed contract.
4. **`benign-update-001.yaml` (Harmless Deployment Metadata Update)**:
   - Target Service: `recommendationservice`
   - Perturbation: Apply a unique pod-template annotation, verify rollout and unchanged image references, then remove the annotation during recovery. No package update is claimed.
   - Contract state remains unknown until a separate trusted source confirms conformance.
5. **`benign-load-001.yaml` (High Load Burst)**:
   - Target Service: `emailservice`
   - Perturbation: Bounded 200-request HTTP burst to internal `emailservice`; service access-log receipts are required.
   - Contract state remains unknown until a separate trusted source confirms conformance.
6. **`benign-restart-001.yaml` (Pod Restart / Reschedule)**:
   - Target Service: `cartservice`
   - Perturbation: Pod deletion triggering ReplicaSet recreation.
   - Contract state remains unknown until a separate trusted source confirms conformance.

---

## 5. Formal Causal Estimands & Structural Causal Models (SCM)

In PHANTOM, causal inference is applied at two distinct structural tiers. These tiers must never be conflated:

```
[ Tier A: Experiment-Level Intervention Effect ]
         X_pre ────────► T_inject ────────► B_behavior ────────► Y_drift ────────► Y_hat
                             │                                     ▲
                             └─────────────────────────────────────┘

[ Tier B: Component Attribution Effect ]
         X_workload ───► T_purl ──────────► B_process ─────────► Y_drift
                             │                                     ▲
                             └─────────────────────────────────────┘
```

### 5.1 Estimand 1: Experiment-Level Injection Intervention Effect ($\tau_{\text{inject}}$)
- **Scientific Query**: What is the average causal effect of the external attack injection intervention ($T_{\text{inject}}$) on container contract drift ($Y_{\text{drift}}$)?
- **Formal Estimand**:
  $$\tau_{\text{inject}} \equiv \mathbb{E}\left[ Y_{\text{drift}}(T_{\text{inject}} = 1) - Y_{\text{drift}}(T_{\text{inject}} = 0) \right] = \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 1)] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = 0)]$$
- **Identification & Backdoor Adjustment**:
  - Under randomized or conditional unconfoundedness given pre-treatment cluster covariates $X_{\text{pre}}$:
    $$\mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{inject}} = t)] = \sum_{x} \mathbb{E}[Y_{\text{drift}} \mid T_{\text{inject}} = t, X_{\text{pre}} = x] P(X_{\text{pre}} = x)$$
- **Adjustment Set**: $X_{\text{pre}}$ contains strictly pre-treatment baseline variables:
  - Node instance type, kernel version, baseline request rate (RPS), baseline memory pressure.

### 5.2 Estimand 2: Component Attribution Effect ($\tau_{\text{purl}}$)
- **Scientific Query**: Did the substitution of a specific software component ($T_{\text{purl}} = \text{tampered}$) cause the observed runtime contract drift ($Y_{\text{drift}} = 1$), rather than ambient workload noise?
- **Formal Estimand**:
  $$\tau_{\text{purl}} \equiv \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{tampered})] - \mathbb{E}[Y_{\text{drift}} \mid \text{do}(T_{\text{purl}} = \text{clean})]$$
- **Identification & Backdoor Adjustment**:
  - Adjustment for workload confounders $X_{\text{workload}}$ (e.g., service call volume, framework entrypoint).

### 5.3 Strict Anti-Mediator Conditioning Rules
A central vulnerability in causal inference is conditioning on post-treatment execution artifacts:

$$\begin{aligned}
&\textbf{Mediators}: && B_{\text{behavior}}, B_{\text{process}}, \text{spawned pids}, \text{cgroups}, \text{syscall counts}, \text{network packets} \\
&\textbf{Rule}: && \text{No post-treatment variable may be included in the conditioning set } Z!
\end{aligned}$$

#### Mathematical Rationale:
1. **Blocking the Causal Mechanism**:
   - The causal path from package tampering to contract drift runs *through* process execution and syscalls:
     $$T_{\text{purl}} \longrightarrow B_{\text{process}} \longrightarrow Y_{\text{drift}}$$
   - Conditioning on $B_{\text{process}}$ blocks the directed causal path, biasing $\hat{\tau}_{\text{purl}} \to 0$ even when the package is 100% responsible for the attack.
2. **Induction of M-Bias (Collider Stratification Bias)**:
   - If there is unobserved system noise $U$ influencing both process behavior and contract drift:
     $$T \longrightarrow B \longleftarrow U \longrightarrow Y$$
   - Intermediate process state $B$ is a collider. Conditioning on $B$ opens the spurious backdoor path $T \to B \leftarrow U \to Y$, creating artificial correlation between clean packages and drift.
3. **Pre-Treatment Covariates Taxonomy (Tier 0 Covariates Only)**:
   - Acceptable covariates are strictly restricted to **Tier 0 pre-treatment variables** where:
     $$t_{\text{covariate}} < t_{\text{treatment}}$$
   - Allowed: Baseline requests per second, pre-injection memory utilization, container CPU limit, base image OS version, replica count.
   - Prohibited: Any event, log, metric, or socket opened after $t_{\text{injection}}$.

---

## 6. Preflight Gates & Defensive Causal Gating

To prevent numerical errors, spurious regressions, and unjustified causal claims, the evaluation pipeline enforces strict preflight validation gates before any causal estimation is attempted.

### 6.1 Preflight Gate G1 ($N \ge 10$) Software Sanity Guard

#### A. Formal Specification:
```python
def gate_minimum_observations(observation_count: int, minimum: int = 10) -> GateVerdict:
    if observation_count >= minimum:
        return GateVerdict(gate_name="G1_minimum_observations", outcome=GateOutcome.PASS)
    return GateVerdict(
        gate_name="G1_minimum_observations",
        outcome=GateOutcome.BLOCK,
        reason="too_few_observations",
        explanation=(
            f"Only {observation_count} causal observation(s) available; "
            f"minimum required is {minimum}. "
            "Minimum technical guard: N >= 10 required to prevent rank-deficient "
            "regression matrices. Does not imply statistical power or identifiability."
        ),
        suggested_status="insufficient_evidence",
    )
```

#### B. Software Sanity Guard Mandate:
- **What Gate G1 Is**:
  - Gate G1 is strictly a **minimum technical software sanity guard** designed to prevent singular/rank-deficient covariance matrices in Ordinary Least Squares (OLS) and Generalized Linear Models (GLM), and to avoid division by zero in propensity score matching algorithms (e.g. DoWhy estimators).
- **What Gate G1 Is NOT**:
  - Passing $N \ge 10$ is **NOT** proof of statistical power.
  - Passing $N \ge 10$ is **NOT** evidence of sample adequacy.
  - Passing $N \ge 10$ does **NOT** establish causal identifiability or satisfy the unconfoundedness assumption.
- **Empirical Status on Raw Datasets**:
  - `research/datasets/raw/`: $N=6$ (all dropouts). **Gate G1 BLOCKS**.
  - `research/datasets/raw3/`: $N=6$ completed attack runs, $N=3$ failed rollouts, $N=0$ controls. **Gate G1 BLOCKS**.
  - **Mandatory Action**: The causal engine must cleanly abstain with:
    $$\text{status} = \text{"insufficient\_evidence"}, \quad \text{reason} = \text{"too\_few\_observations"}$$

### 6.2 Preflight Gate G2: Component Mapping Quality
- **Rule**: Treatment components with `UNRESOLVED` or `INVALID` mapping statuses are blocked with `reason: "unresolved_component_identity"`.
- Treatment components with `AMBIGUOUS` mapping statuses are blocked with `reason: "ambiguous_component_identity"`.
- **Status on `raw3/`**: Because 100% of drift detections have `purl = null` and `identity_status = "ambiguous"` (99.08%) or `"missing"` (0.92%), Gate G2 must cleanly block with `ambiguous_component`.

### 6.3 Preflight Gate G3 & G4: Temporal Precedence
- **Gate G3 (Treatment precedes Outcome)**:
  $$t_{\text{treatment\_first\_seen}} \le t_{\text{outcome\_first\_seen}}$$
  A cause must precede its effect. If violated, blocks with `status: "not_identifiable"`, `reason: "reversed_temporal_order"`.
- **Gate G4 (Covariates precede Treatment)**:
  $$\forall X_k \in \mathbf{X}, \quad t_{X_k} \le t_{\text{treatment\_first\_seen}}$$
  If any covariate is observed after treatment, blocks with `status: "invalid_graph"`, `reason: "covariate_observed_after_outcome"`.

### 6.4 Empirical Variation & Positivity Requirements
Before any causal estimator runs, empirical variation must be verified:
- **Treatment Variation**: $T$ must contain at least two unique values:
  $$\text{Var}(T) > 0 \iff \{0, 1\} \subseteq \text{unique}(T)$$
  If all units are treated ($T=1$, as in `raw3/`), the pipeline must block with `reason: "no_treatment_variation"`.
- **Outcome Variation**: $Y$ must contain at least two unique values:
  $$\text{Var}(Y) > 0 \iff \{0, 1\} \subseteq \text{unique}(Y)$$
- **Positivity (Overlap)**: For every covariate stratum $X = x$:
  $$0 < P(T = 1 \mid X = x) < 1$$
  If positivity fails, the pipeline must abstain with `reason: "positivity_failure"`.

---

## 7. Statistical Uncertainty & Performance Metric Formulas

### 7.1 Detection Rate Uncertainty: Standard Ordinary Wilson Score Interval
Binary proportions (True Positive Rate $TPR$, False Positive Rate $FPR$, Precision, Recall) must be reported with confidence intervals computed via the **standard ordinary Wilson score interval without continuity correction**.

#### Formula:
Given $k$ successes in $n$ independent trials, sample proportion $\hat{p} = \frac{k}{n}$, and standard normal quantile $z = \Phi^{-1}\left(1 - \frac{\alpha}{2}\right)$ (where $z = 1.95996398454 \approx 1.96$ for a 95% confidence interval):

$$p_{\text{lower}}, p_{\text{upper}} = \frac{\hat{p} + \frac{z^2}{2n} \mp z \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

#### Benchmark Values ($z = 1.95996398454$):
- For $k = 6, n = 6$ ($\hat{p} = 1.0$):
  $$p_{\text{lower}} = \frac{1 + \frac{3.841459}{12} - 1.959964 \sqrt{0 + \frac{3.841459}{144}}}{1 + \frac{3.841459}{6}} = \frac{1.320122 - 1.959964 \cdot 0.163299}{1.640243} = \frac{1.000062}{1.640243} \approx \mathbf{0.6096}$$
  $$p_{\text{upper}} = \mathbf{1.0000} \quad (\text{bounded at 1.0})$$
  $$\text{Interval: } [0.6096, 1.0000]$$
- For $k = 0, n = 6$ ($\hat{p} = 0.0$):
  $$\text{Interval: } [0.0000, 0.3904]$$

### 7.2 Latency Uncertainty: Non-Parametric Bootstrap Intervals for MTTD
Because detection latency distributions are right-skewed and non-normal, Mean Time To Detect ($MTTD$) must report:
1. **Parametric & Non-Parametric Descriptors**: Mean, Median ($P_{50}$), and Interquartile Range ($\text{IQR} = P_{75} - P_{25}$).
2. **Bootstrap Confidence Interval**: 95% percentile bootstrap interval computed with $B = 2,000$ resamples with replacement over the true positive latencies.

### 7.3 Undefined Denominator Policy
If any denominator in a performance metric is zero:
- $\text{FPR} = \frac{FP}{FP + TN}$: If $FP + TN = 0 \implies \text{FPR} = \mathbf{None} \ (\text{or } \text{\text{---}} \text{ in LaTeX})$.
- $\text{Precision} = \frac{TP}{TP + FP}$: If $TP + FP = 0 \implies \text{Precision} = \mathbf{None}$.
- $F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$: If Precision is undefined $\implies F_1 = \mathbf{None}$.
- **Zero Default Prohibition**: Never default undefined denominators to $0.0$ or $1.0$.

---

## 8. Summary of Protocol Compliance Rules

| # | Requirement | Mandated Behavior | Prohibited Behavior |
|---|---|---|---|
| **1** | Independent Unit | 1 Scenario Run = 1 Unit ($N=1$). | Slicing 1 run into multiple windows to claim $N \ge 10$. |
| **2** | Ground Truth Drift | $Y_{\text{drift}} = 1 \iff$ Verified violation of signed container contract. | Assuming sink network traffic is automatically contract drift. |
| **3** | Unverified Labels | Label remains strictly `unknown`. | Imputing $Y_{\text{drift}} = 0$ or $1$ when telemetry is absent. |
| **4** | Failed Injections | Exclude `inject_ok=False` from detection TPR and causal attribution. | Counting rollout failures as detector False Negatives. |
| **5** | Collection Dropouts | Classify absent detections as `collection_dropout`. | Counting collection dropouts in `raw/` as True Negatives. |
| **6** | Preflight Gate G1 | Enforce $N \ge 10$ as technical software sanity guard; cleanly abstain. | Claiming $N \ge 10$ proves statistical adequacy or power. |
| **7** | Causal Mediators | Condition strictly on Tier 0 pre-treatment covariates ($X_{\text{pre}} \prec T$). | Conditioning on post-treatment execution events or syscalls. |
| **8** | Confidence Intervals | Ordinary Wilson Score Interval without continuity correction ($[0.6096, 1.0]$). | Normal approximation ($\pm 1.96 \sqrt{p(1-p)/n}$) or continuity correction. |
| **9** | Baseline Absence | Report uncollected baselines as `telemetry_unavailable` / `NR`. | Reporting baseline $TPR = 0.0$ when logs are absent. |
| **10** | System Overhead | Report missing Prometheus data as `unmeasured` / `null`. | Defaulting Prometheus connection failures to 0.0% CPU / 0 MB. |

---
*Certified and Authorized by Worker M1 (Data Audit & Experimental Protocol Track).*
