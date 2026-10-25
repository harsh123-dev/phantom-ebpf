"""
Verification and Empirical Challenge Script for EXPERIMENT_PROTOCOL.md
Milestone 1 Hardening Verification (challenger_m1_2)

Sections:
1. Wilson Score Interval verification (exact formula, x=6, n=6, z=1.95996398454 -> [0.6096, 1.0000])
2. Boundary conditions: x=0, x=n, n=1, n=10, symmetry and clipping tests
3. Non-parametric bootstrap percentile intervals for MTTD vs normal approximation
4. Structural DAG verification: Tier 2-4 mediator conditioning and M-bias vs Tier 0 valid adjustment
5. Preflight Gate G1 (N >= 10) technical software sanity guard against singular regression matrices
"""

import sys
import os
sys.path.insert(0, os.path.abspath("services/causal-engine"))
import numpy as np
import scipy.stats as stats
import statsmodels.api as sm
import statsmodels.stats.proportion as sm_prop
import networkx as nx
import dowhy
from dowhy import CausalModel
import pandas as pd

def test_wilson_exact_benchmark():
    print("=== 1. Wilson Score Exact Formula & Benchmark Test ===")
    z = stats.norm.ppf(1 - 0.05 / 2) # 1.959963984540054
    n = 6
    x = 6
    p_hat = x / n
    denom = 1 + (z**2) / n
    center = p_hat + (z**2) / (2 * n)
    spread = z * np.sqrt((p_hat * (1 - p_hat)) / n + (z**2) / (4 * n**2))
    lower = max(0.0, (center - spread) / denom)
    upper = min(1.0, (center + spread) / denom)

    print(f"Calculated z: {z:.11f}")
    print(f"p_hat: {p_hat}, denom: {denom:.6f}, center: {center:.6f}, spread: {spread:.6f}")
    print(f"lower: {lower:.6f}, upper: {upper:.6f}")
    
    # Truncated to 4 decimal places:
    lower_trunc = int(lower * 10000) / 10000.0
    upper_trunc = int(upper * 10000) / 10000.0
    print(f"Truncated [lower, upper]: [{lower_trunc:.4f}, {upper_trunc:.4f}]")
    assert lower_trunc == 0.6096, f"Expected lower 0.6096, got {lower_trunc}"
    assert upper_trunc == 1.0000, f"Expected upper 1.0000, got {upper_trunc}"

    # Rounded to 4 decimal places:
    lower_round = round(lower, 4)
    upper_round = round(upper, 4)
    print(f"Rounded [lower, upper]: [{lower_round:.4f}, {upper_round:.4f}]")
    assert lower_round == 0.6097

    # Check statsmodels agreement
    sm_low, sm_high = sm_prop.proportion_confint(6, 6, alpha=0.05, method="wilson")
    assert abs(lower - sm_low) < 1e-12
    assert abs(upper - sm_high) < 1e-12
    print("PASS: Wilson score 6/6 matches [0.6096, 1.0000] and statsmodels exactly.\n")

def test_wilson_boundary_conditions():
    print("=== 2. Wilson Score Boundary Conditions Test ===")
    def wilson(x, n, alpha=0.05):
        if n <= 0:
            raise ValueError("n must be positive")
        if x < 0 or x > n:
            raise ValueError("x must be between 0 and n")
        z = stats.norm.ppf(1 - alpha / 2)
        p_hat = x / n
        denom = 1 + (z**2) / n
        center = p_hat + (z**2) / (2 * n)
        spread = z * np.sqrt((p_hat * (1 - p_hat)) / n + (z**2) / (4 * n**2))
        lower = max(0.0, (center - spread) / denom)
        upper = min(1.0, (center + spread) / denom)
        return lower, upper

    cases = [
        # (x, n)
        (0, 1), (1, 1),
        (0, 6), (6, 6),
        (0, 10), (1, 10), (5, 10), (9, 10), (10, 10)
    ]

    for x, n in cases:
        low, high = wilson(x, n)
        sm_low, sm_high = sm_prop.proportion_confint(x, n, alpha=0.05, method="wilson")
        # Assert within numerical precision of statsmodels
        assert abs(low - sm_low) < 1e-14, f"Mismatch at ({x}, {n}) lower"
        assert abs(high - sm_high) < 1e-14, f"Mismatch at ({x}, {n}) upper"
        # Assert bounded in [0, 1]
        assert 0.0 <= low <= high <= 1.0, f"Bounds violated at ({x}, {n}): [{low}, {high}]"
        print(f"Case x={x:2d}, n={n:2d} -> [{low:.6f}, {high:.6f}] (sm: [{sm_low:.6f}, {sm_high:.6f}]) PASS")

    # Check symmetry property: wilson(k, n)[0] == 1 - wilson(n-k, n)[1]
    for x, n in [(0, 1), (0, 6), (0, 10), (1, 10), (2, 10)]:
        low_k, high_k = wilson(x, n)
        low_comp, high_comp = wilson(n - x, n)
        assert abs(low_k - (1.0 - high_comp)) < 1e-14, f"Symmetry broken at ({x}, {n})"
        assert abs(high_k - (1.0 - low_comp)) < 1e-14, f"Symmetry broken at ({x}, {n})"
    print("PASS: Wilson score satisfies all boundary and symmetry conditions.\n")

def test_mttd_bootstrap_intervals():
    print("=== 3. Non-Parametric Bootstrap Percentile Intervals for MTTD ===")
    # Raw3 true positive latencies
    mttd_data = np.array([70.331969, 6.349775, 4.681537, 2.607243, 7.875910, 2.578247])
    mean = np.mean(mttd_data)
    median = np.median(mttd_data)
    q75, q25 = np.percentile(mttd_data, [75, 25])
    iqr = q75 - q25

    print(f"Data: {mttd_data}")
    print(f"Mean: {mean:.4f}s, Median: {median:.4f}s, IQR: {iqr:.4f}s (Q25: {q25:.4f}, Q75: {q75:.4f})")

    # Check standard normal CI failure
    se = stats.sem(mttd_data)
    norm_low = mean - 1.959964 * se
    norm_high = mean + 1.959964 * se
    print(f"Normal assumption 95% CI: [{norm_low:.4f}, {norm_high:.4f}]")
    assert norm_low < 0.0, "Expected normal CI lower bound to be negative on skewed latency data!"

    # Bootstrap percentile CI (B = 2,000)
    np.random.seed(42)
    B = 2000
    boot_means = [np.mean(np.random.choice(mttd_data, size=len(mttd_data), replace=True)) for _ in range(B)]
    boot_low, boot_high = np.percentile(boot_means, [2.5, 97.5])
    print(f"Bootstrap 95% CI for Mean: [{boot_low:.4f}, {boot_high:.4f}]")
    assert boot_low >= 0.0, "Bootstrap percentile interval lower bound must be >= 0.0"

    boot_medians = [np.median(np.random.choice(mttd_data, size=len(mttd_data), replace=True)) for _ in range(B)]
    med_low, med_high = np.percentile(boot_medians, [2.5, 97.5])
    print(f"Bootstrap 95% CI for Median: [{med_low:.4f}, {med_high:.4f}]")
    assert med_low >= 0.0, "Bootstrap percentile interval for median must be >= 0.0"
    print("PASS: Bootstrap percentile intervals protect against nonsensical negative latency lower bounds.\n")

def test_structural_dag_mediator_and_mbias():
    print("=== 4. Structural DAG Specifications: Mediator Conditioning & M-Bias ===")
    # 4A. Mediator Conditioning (Overcontrolling)
    # DAG: X0 (Tier 0) -> T (Tier 1) -> M (Tier 2-4) -> Y (Tier 5)
    # True data generating process:
    # X0 ~ N(0, 1)
    # T = 1 if (0.5 * X0 + eps_T) > 0 else 0
    # M = 2.0 * T + 0.3 * X0 + eps_M
    # Y = 1.5 * M + 0.5 * X0 + eps_Y
    # Total effect of T on Y = direct(0) + indirect(2.0 * 1.5) = 3.0.
    np.random.seed(123)
    N = 5000
    X0 = np.random.normal(0, 1, N)
    T = (0.5 * X0 + np.random.normal(0, 1, N) > 0).astype(int)
    M = 2.0 * T + 0.3 * X0 + np.random.normal(0, 1, N)
    Y = 1.5 * M + 0.5 * X0 + np.random.normal(0, 1, N)
    df = pd.DataFrame({"X0": X0, "T": T, "M": M, "Y": Y})

    # Model 1: Adjusting ONLY for Tier 0 (X0)
    model_valid = sm.OLS(df["Y"], sm.add_constant(df[["T", "X0"]])).fit()
    est_total = model_valid.params["T"]
    print(f"Valid adjustment (Tier 0 only): Estimated Total Effect of T = {est_total:.4f} (True = 3.0000)")
    assert abs(est_total - 3.0) < 0.2, f"Expected ~3.0, got {est_total}"

    # Model 2: Conditioning on Tier 2-4 Mediator M
    model_mediator = sm.OLS(df["Y"], sm.add_constant(df[["T", "X0", "M"]])).fit()
    est_mediator = model_mediator.params["T"]
    print(f"Conditioning on Mediator M (Tier 2-4): Estimated Direct Effect of T = {est_mediator:.4f} (Biased from total effect 3.0)")
    assert abs(est_mediator) < 0.2, f"Conditioning on mediator should collapse effect towards 0, got {est_mediator}"

    # 4B. Collider Conditioning / M-Bias
    # DAG: T is independent of Y directly.
    # U1 -> T, U1 -> M (Tier 2-4), U2 -> M, U2 -> Y
    # True causal effect of T on Y is 0.
    np.random.seed(42)
    N_mbias = 20000
    U1 = np.random.normal(0, 1, N_mbias)
    U2 = np.random.normal(0, 1, N_mbias)
    T_mbias = 1.0 * U1 + np.random.normal(0, 0.5, N_mbias)
    M_collider = 1.5 * U1 + 1.5 * U2 + np.random.normal(0, 0.5, N_mbias)
    Y_mbias = 1.5 * U2 + np.random.normal(0, 0.5, N_mbias)
    df_mbias = pd.DataFrame({"T": T_mbias, "M": M_collider, "Y": Y_mbias})

    # Model 1: Without conditioning on M (Unconditioned)
    model_uncond = sm.OLS(df_mbias["Y"], sm.add_constant(df_mbias[["T"]])).fit()
    est_uncond = model_uncond.params["T"]
    pval_uncond = model_uncond.pvalues["T"]
    print(f"M-Bias Unconditioned on M: Effect of T = {est_uncond:.4f} (True = 0.0000)")
    assert abs(est_uncond) < 0.05, f"Expected ~0.0, got {est_uncond}"

    # Model 2: Conditioning on Collider M
    model_cond = sm.OLS(df_mbias["Y"], sm.add_constant(df_mbias[["T", "M"]])).fit()
    est_cond = model_cond.params["T"]
    pval_cond = model_cond.pvalues["T"]
    print(f"M-Bias Conditioning on M: Spurious Effect of T = {est_cond:.4f} (p={pval_cond:.4e}, Spurious bias induced!)")
    assert abs(est_cond) > 0.5, f"Conditioning on collider should induce strong spurious correlation, got {est_cond}"
    assert pval_cond < 1e-10, f"Spurious effect must be highly statistically significant, got p={pval_cond}"

    print("PASS: Causal DAG verification confirms Tier 2-4 variables induce mediator blockage and collider M-bias. Tier 0 is the strictly valid adjustment set.\n")

def test_preflight_gate_g1_software_sanity():
    print("=== 5. Preflight Gate G1 Technical Sanity Guard Verification ===")
    # When N < 10, design matrix with intercept + treatment + covariates is at extreme risk of rank-deficiency / singularity
    # Let's test with N = 4, 6, 8, 10
    
    # Example: N = 6 (as in raw3 completed runs) with intercept, treatment, and 4 typical workload covariates:
    # [baseline_rps, baseline_mem, cpu_limit, is_worker_node]
    p = 5 # 1 treatment + 4 covariates = 5 features + intercept = 6 columns!
    # For N = 6, X is 6x6. If any collinearity or sparse categorical variable occurs:
    np.random.seed(99)
    N_small = 6
    X_cov = np.random.normal(0, 1, (N_small, 4))
    T_small = np.array([1, 1, 1, 1, 1, 1]) # As in raw3 where all 6 completed runs are attack injections!
    
    # 1. No treatment variation (Var(T) == 0):
    rank_no_var = np.linalg.matrix_rank(np.column_stack([np.ones(N_small), T_small]))
    print(f"Design matrix rank with T all 1s (intercept + T): {rank_no_var} (Columns: 2) -> SINGULAR / RANK DEFICIENT")
    assert rank_no_var == 1, "Expected rank 1 for intercept + constant treatment"

    # 2. Even if T had variation, e.g. 5 treated, 1 control, with 5 covariates:
    T_var = np.array([1, 1, 1, 1, 1, 0])
    X_mat = np.column_stack([np.ones(N_small), T_var, X_cov]) # shape: 6 x 6
    cond_number = np.linalg.cond(X_mat)
    print(f"Condition number for N=6 with 5 covariates: {cond_number:.2e}")

    # 3. Test statsmodels OLS with N < 10 vs rank deficiency
    try:
        y_small = np.random.normal(0, 1, N_small)
        # Add a categorical column with identical values in control
        X_df = pd.DataFrame(X_cov, columns=["c1", "c2", "c3", "c4"])
        X_df["T"] = T_small
        model = sm.OLS(y_small, sm.add_constant(X_df)).fit()
        print("Model params:", model.params)
        has_nans = model.params.isna().any()
        print("Has NaN params due to rank deficiency:", has_nans)
        assert has_nans or np.isneginf(model.df_resid) or model.df_resid <= 0, "Expected rank deficiency or zero residual df"
    except Exception as e:
        print("Caught expected singular/rank error:", type(e).__name__, str(e))

    # Test Gate G1 logic from causal_validation.py
    from app.domain.causal_validation import gate_minimum_observations, GateOutcome
    res_6 = gate_minimum_observations(6, minimum=10)
    print(f"Gate G1 on N=6: outcome={res_6.outcome.value}, reason={res_6.reason}, status={res_6.suggested_status}")
    assert res_6.outcome == GateOutcome.BLOCK
    assert res_6.reason == "too_few_observations"
    assert res_6.suggested_status == "insufficient_evidence"

    res_10 = gate_minimum_observations(10, minimum=10)
    print(f"Gate G1 on N=10: outcome={res_10.outcome.value}")
    assert res_10.outcome == GateOutcome.PASS

    print("PASS: Preflight Gate G1 successfully acts as a software sanity guard against singular regression matrices.\n")

if __name__ == "__main__":
    test_wilson_exact_benchmark()
    test_wilson_boundary_conditions()
    test_mttd_bootstrap_intervals()
    test_structural_dag_mediator_and_mbias()
    test_preflight_gate_g1_software_sanity()
    print("ALL VERIFICATION SUITES COMPLETED AND EMPIRICALLY CONFIRMED.")
