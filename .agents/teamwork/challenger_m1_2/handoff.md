# Handoff Report: Milestone 1 Protocol Verification & Challenge
**Agent ID**: `challenger_m1_2` (`teamwork_preview_challenger`)  
**Type**: Hard Handoff (Challenge and Verification Complete)  
**Date**: 2026-10-24  
**Recipient**: `orchestrator_1` (`4299c465-79cb-468c-95c3-8aed4c92f7f9`)  
**Working Directory**: `d:\project-1\.agents\teamwork\challenger_m1_2`  
**Target Under Review**: `d:\project-1\EXPERIMENT_PROTOCOL.md`  
**Verdict**: **APPROVE**

---

## 1. Observation

Direct empirical observations made from files, mathematical execution, and independent verification harnesses:

### 1.1 Wilson Score Interval ($x=6, n=6, z=1.95996398454$)
- Formula inspected in `EXPERIMENT_PROTOCOL.md` (lines 313–324):
  $$p_{\text{lower}}, p_{\text{upper}} = \frac{\hat{p} + \frac{z^2}{2n} \mp z \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
- Numerical execution via `scripts/verify_challenger_m1.py`:
  - Quantile $z = \Phi^{-1}(0.975) = 1.959963984540054$
  - Denominator $1 + \frac{z^2}{n} = 1 + \frac{3.841458820694}{6} = 1.640243136782$
  - Center $\hat{p} + \frac{z^2}{2n} = 1.0 + \frac{3.841458820694}{12} = 1.320121568391$
  - Spread $z \sqrt{0 + \frac{z^2}{4n^2}} = \frac{z^2}{2n} = 0.320121568391$
  - $p_{\text{lower}} = \frac{1.0}{1.640243136782} = 0.6096657...$
  - $p_{\text{upper}} = \frac{1.320122 + 0.320122}{1.640243} = 1.000000$
  - Truncated to 4 decimals: $[0.6096, 1.0000]$ (matching `EXPERIMENT_PROTOCOL.md` line 321 verbatim).
  - Rounded to 4 decimals: $[0.6097, 1.0000]$.
  - Agreement with `statsmodels.stats.proportion.proportion_confint(6, 6, alpha=0.05, method='wilson')`: difference $< 10^{-14}$.
- Boundary conditions tested:
  - $(x=0, n=1) \implies [0.000000, 0.793451]$ (Statsmodels match: max diff $< 1.11 \times 10^{-16}$)
  - $(x=1, n=1) \implies [0.206549, 1.000000]$ (Statsmodels match: max diff $< 2.78 \times 10^{-17}$)
  - $(x=0, n=6) \implies [0.000000, 0.390334]$ (Statsmodels match: max diff $< 1.11 \times 10^{-16}$)
  - $(x=6, n=6) \implies [0.609666, 1.000000]$ (Statsmodels match: max diff $= 0.0$)
  - $(x=0, n=10) \implies [0.000000, 0.277533]$ (Statsmodels match: max diff $< 5.55 \times 10^{-17}$)
  - $(x=1, n=10) \implies [0.017876, 0.404150]$ (Statsmodels match: max diff $< 5.55 \times 10^{-17}$)
  - $(x=5, n=10) \implies [0.236593, 0.763407]$ (Statsmodels match: max diff $< 1.11 \times 10^{-16}$)
  - $(x=9, n=10) \implies [0.595850, 0.982124]$ (Statsmodels match: max diff $< 2.22 \times 10^{-16}$)
  - $(x=10, n=10) \implies [0.722467, 1.000000]$ (Statsmodels match: max diff $< 1.11 \times 10^{-16}$)
  - Exact symmetry verified across all pairs: $p_{\text{lower}}(k, n) = 1.0 - p_{\text{upper}}(n - k, n)$.

### 1.2 Latency Uncertainty & MTTD Non-Parametric Bootstrap
- Empirical latency data from `research/datasets/raw3/` ($N=6$ completed true positive runs):
  - Values: $[70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247]$ seconds.
  - Sample Mean: $15.7374\,\text{s}$
  - Sample Median: $5.5157\,\text{s}$
  - Interquartile Range ($IQR$): $4.3686\,\text{s}$ ($Q_{25} = 3.1258\,\text{s}, Q_{75} = 7.4944\,\text{s}$).
- Normal distribution assumption failure:
  - Standard error $SE = 10.9517\,\text{s}$.
  - Wald normal 95% CI: $\bar{x} \pm 1.96 \cdot SE = [-5.7278, 37.2027]\,\text{s}$.
  - Student-t 95% CI ($df=5$): $[-12.4239, 43.8988]\,\text{s}$.
  - Both standard parametric models yield negative latency lower bounds ($< 0$), which violates the physical domain lower bound for detection latency.
- Non-parametric bootstrap percentile interval ($B = 2,000$ resamples with replacement):
  - 95% Bootstrap CI for Mean: $[3.5719, 37.7893]\,\text{s}$.
  - 95% Bootstrap CI for Median: $[2.5927, 39.1039]\,\text{s}$.
  - Both bootstrap percentile intervals remain strictly positive ($\ge 0.0$).

### 1.3 Structural DAG & Anti-Mediator / M-Bias Conditioning
- Codebase tier definitions in `services/causal-engine/app/domain/bdg.py` (lines 47–58):
  - Tier 0: `environment`, `rbac`, `image` (pre-treatment context: Workload, Container, RBAC).
  - Tier 1: `component_version` (treatment: $T_{\text{purl}}$ or $T_{\text{inject}}$).
  - Tier 2: `process_behavior` (intermediate process execution, spawned PIDs).
  - Tier 3: `file_behavior`, `network_behavior`, `privilege_behavior` (intermediate syscalls).
  - Tier 4: `contract_deviation` (proximate contract violation trigger).
  - Tier 5: `runtime_sbom_drift` (outcome: $Y_{\text{drift}}$).
- Empirical SCM simulation in `scripts/verify_challenger_m1.py`:
  - **Mediator Overcontrolling**: In the causal mechanism $X_0 \to T \to M \to Y$ (where true total effect $\tau = 3.0000$):
    - Adjusting strictly for Tier 0 ($X_0$): Estimated effect $\hat{\beta}_T = 3.0554$ ($p < 10^{-100}$). Unbiased recovery of total causal effect.
    - Conditioning on Tier 2–4 Mediator ($M$): Estimated direct effect $\hat{\beta}_T = -0.0485$ ($p = 0.286$). True causal effect is extinguished/blocked.
  - **Collider Stratification / M-Bias**: In the structure $U_1 \to T, U_1 \to M, U_2 \to M, U_2 \to Y$ (where true effect of $T \to Y$ is $0.0000$):
    - Unconditioned on $M$: Estimated effect $\hat{\beta}_T = 0.0239$ (practically zero).
    - Conditioning on Collider $M$: Estimated effect $\hat{\beta}_T = -0.9078$ ($p < 10^{-100}$). Massive spurious correlation induced between treatment and outcome.

### 1.4 Preflight Gate G1 Technical Sanity Guard ($N \ge 10$)
- Linear regression design matrix rank analysis on small sample sizes:
  - For $N=6$ (raw3 sample size) with treatment $T$ and 4 Tier 0 covariates (5 predictors + 1 intercept = 6 parameters):
  - When $T$ has no empirical variation (e.g., $T=1$ across all 6 runs in `raw3/`), design matrix $X$ has $\text{rank}(X) = 1$ for the treatment/intercept submatrix, rendering $X^T X$ singular.
  - Even with treatment variation ($T \in \{0, 1\}$), $N=6$ with 5 predictors yields residual degrees of freedom $df = N - p - 1 = 6 - 5 - 1 = 0$, resulting in zero residual degrees of freedom and unidentifiable parameter covariance.
  - Gate G1 evaluation via `services/causal-engine/app/domain/causal_validation.py`:
    - $N=6 \implies \text{outcome} = \text{BLOCK}, \text{reason} = \text{"too\_few\_observations"}, \text{suggested\_status} = \text{"insufficient\_evidence"}$.
    - $N=10 \implies \text{outcome} = \text{PASS}$.

### 1.5 Full Test Suite Baseline Integrity
- `research/evaluation/tests`: 60 passed in 0.18s.
- `services/sbom-service/tests`: 177 passed in 1.42s.
- `services/causal-engine/tests`: 283 passed in 35.17s.
- Total: 520 passed, 0 failed.

---

## 2. Logic Chain

1. **Wilson Score Mathematical Rigor (from Observation 1.1)**:
   - The ordinary Wilson score interval without continuity correction directly solves the score test inversion equation $(p - \hat{p})^2 = \frac{z^2 p(1-p)}{n}$.
   - For $k=6, n=6$, the quadratic roots yield $p_{\text{lower}} = \frac{1}{1 + z^2/n} = \frac{1}{1 + 3.841459/6} = 0.6096657...$ and $p_{\text{upper}} = 1.000000$.
   - Truncation yields $[0.6096, 1.0000]$ and rounding yields $[0.6097, 1.0000]$. The formula in `EXPERIMENT_PROTOCOL.md` Section 7.1 accurately matches both the algebraic derivation and the `statsmodels` reference implementation to machine precision ($< 10^{-14}$).
   - The Wald normal approximation ($1.0 \pm 0.0$) yields a degenerate confidence interval of width 0, falsely claiming 100% certainty. The Wilson score accurately reflects the wide uncertainty ($[0.61, 1.00]$) inherent in small-sample binomial trials.

2. **Latency Uncertainty Handling (from Observation 1.2)**:
   - Empirical latency data is heavily right-skewed ($70.33\,\text{s}$ vs sub-$8\,\text{s}$ cluster), violating the symmetry and normality assumptions of Student-t and Gaussian intervals.
   - Normal and Student-t intervals produce negative lower bounds ($-5.73\,\text{s}$ and $-12.42\,\text{s}$), which are physically impossible.
   - Non-parametric percentile bootstrap resamples from the empirical distribution, preserving domain constraints ($MTTD \ge 0$) and reporting robust non-parametric descriptors (Median and IQR). The protocol's latency specification is mathematically essential.

3. **Anti-Mediator DAG Enforcement & Tier 0 Adjustment (from Observation 1.3)**:
   - In Pearl's structural causal framework, a variable that lies on the causal path between treatment and outcome is a mediator. Adjusting for mediators absorbs indirect causal effects, reducing estimated ATE to direct effects only ($\hat{\beta} \to 0$).
   - When intermediate variables are subject to latent environmental disturbances (e.g., node CPU/memory pressure), they act as colliders. Conditioning on colliders unblocks non-causal paths, generating spurious M-bias ($\hat{\beta} = -0.91$ when true effect is $0$).
   - Tier 0 covariates (workload identity, container configuration, baseline resource load) precede treatment temporally ($t < t_{\text{treatment}}$). They cannot be descendants of treatment, cannot be mediators, and do not open collider pathways. Adjusting exclusively for Tier 0 satisfies the Backdoor Criterion.

4. **Technical Function of Preflight Gate G1 (from Observation 1.4)**:
   - For OLS and GLM estimators, invertibility of the Gram matrix $X^T X$ requires $\text{rank}(X) = p + 1 \le N$.
   - When $N < 10$, realistic covariate sets (e.g., treatment + 4 workload controls) induce near-singular or singular matrices, zero degrees of freedom, and undefined standard errors.
   - Gate G1 ($N \ge 10$) acts as an indispensable technical software guard against singular matrix exceptions in numerical libraries (NumPy/DoWhy).
   - Crucially, `EXPERIMENT_PROTOCOL.md` explicitly avoids claiming that $N \ge 10$ provides statistical power or guarantees identifiability, mandating clean abstention (`insufficient_evidence: too_few_observations`) on small batches.

---

## 3. Caveats

1. **Continuous vs Discrete Latency Resampling**: Bootstrap percentile intervals with $N=6$ discrete data points have a finite set of possible sample medians ($6^6 = 46,656$ possible bootstrap samples). With $B=2,000$ iterations, the bootstrap interval is a Monte Carlo approximation of the discrete permutation distribution. For production runs, $B \ge 2,000$ must be maintained with fixed seeds for reproducibility.
2. **Cluster Telemetry Overhead**: Overhead and baseline metrics for live clusters were not executed live during this challenge turn, as this review is an offline audit and protocol verification.

---

## 4. Conclusion

The specifications formalized in `d:\project-1\EXPERIMENT_PROTOCOL.md` are mathematically rigorous, structurally sound, and empirically verified:
1. The standard Wilson score interval without continuity correction matches the exact benchmark $[0.6096, 1.0000]$ for $6/6$ and passes all boundary conditions.
2. The bootstrap percentile latency interval and non-parametric statistics (Median, IQR) prevent physically invalid negative latency bounds.
3. The anti-mediator conditioning rules and restriction to Tier 0 covariates are mathematically necessary to prevent causal blockage and collider M-bias.
4. Preflight Gate G1 ($N \ge 10$) is properly specified as a technical software sanity guard against singular regression matrices, with explicit abstention protocols.

**Verdict**: **APPROVE**

---

## 5. Verification Method

To independently reproduce all empirical verification results:

1. **Execute Challenger Verification Harness**:
   ```powershell
   d:\project-1\.venv-causal\Scripts\python.exe scripts/verify_challenger_m1.py
   ```
   *Expected result*: Exits with code 0; logs "ALL VERIFICATION SUITES COMPLETED AND EMPIRICALLY CONFIRMED."

2. **Verify All Project Test Suites**:
   ```powershell
   python -m pytest research/evaluation/tests
   d:\project-1\.venv-causal\Scripts\pytest.exe services/sbom-service/tests
   d:\project-1\.venv-causal\Scripts\pytest.exe services/causal-engine/tests
   ```
   *Expected result*: 60 passed in evaluation, 177 passed in sbom-service, 283 passed in causal-engine.

3. **Invalidation Conditions**:
   - If the Wilson score calculation for $x=6, n=6$ deviates from $[0.609666, 1.000000]$ by more than $10^{-10}$, the verification is invalidated.
   - If conditioning on Tier 2–4 mediators does not suppress the estimated total causal effect in the SCM simulation, the anti-mediator challenge is invalidated.
   - If $N=6$ with 5 predictors and no treatment variation can produce a non-singular $X^T X$ matrix, the Gate G1 sanity guard argument is invalidated.
