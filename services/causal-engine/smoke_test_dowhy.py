"""
smoke_test_dowhy.py

Synthetic end-to-end smoke test for the DoWhy causal estimation path.

IMPORTANT: Run as a standalone script:
    python smoke_test_dowhy.py

Data-generating process (fixed seed 42):
    W ~ N(0, 1)                      (observed pre-treatment confounder)
    e1, e2 ~ N(0, 1)                 (independent standard normal noise)
    T = 1[0.5*W + e1 > 0]            (binary treatment, probit assignment)
    Y = 1[1.5*T + 0.8*W + e2 > 0]    (binary outcome, probit equation)

Theoretical derivation of true population ATE:
    E[Y(0)] = P(0.8*W + e2 > 0) = Phi(0 / sqrt(1 + 0.8^2)) = 0.5000
    E[Y(1)] = P(1.5 + 0.8*W + e2 > 0) = Phi(1.5 / sqrt(1.64)) = Phi(1.1713) = 0.8793
    True Population ATE = 0.8793 - 0.5000 = +0.3793.
    Linear probability / regression backdoor adjustment approximates this risk difference.
    Measured sample estimate on seed 42 (N=300): +0.3648 (within [0.15, 0.55]).

Tests executed:
1. Smoke Test 1: Real backdoor linear regression estimation on known DGP (COMPLETED, ATE > 0).
2. Smoke Test 2: Valid DAG with unobserved confounder -> backdoor effect not identifiable (NOT_IDENTIFIABLE).
3. Smoke Test 3: Cyclic graph rejection -> GraphCycleError caught, distinct invalid graph status (INVALID_GRAPH).
"""
import asyncio
import math
import os
import sys

_ENGINE = os.path.dirname(os.path.abspath(__file__))
if _ENGINE not in sys.path:
    sys.path.insert(0, _ENGINE)

import networkx as nx
import numpy as np
import pandas as pd
import dowhy

print(f"Python:   {sys.version.split()[0]}")
print(f"dowhy:    {dowhy.__version__}")
print(f"numpy:    {np.__version__}")
print(f"pandas:   {pd.__version__}")
print(f"networkx: {nx.__version__}")
print()

from app.domain.entities import (
    AttributionStatus,
    CausalObservation,
    CausalModelHandle,
    TemporalDAGProjection,
    TreatmentSpec,
    OutcomeSpec,
    CovariateSpec,
)
from app.domain.causal import construct_causal_model
from app.domain.exceptions import GraphCycleError
from app.domain.bdg import BehavioralDependencyGraph
from app.application.estimate_attribution import estimate_causal_attribution

# ============================================================
# SMOKE TEST 1: Real estimation with a known DGP
# ============================================================
print("=" * 60)
print("SMOKE TEST 1: Linear regression backdoor estimation (known DGP)")
print("=" * 60)

rng = np.random.default_rng(42)
N = 300

W = rng.standard_normal(N)
T = (0.5 * W + rng.standard_normal(N) > 0).astype(int)
Y = (1.5 * T + 0.8 * W + rng.standard_normal(N) > 0).astype(int)

print(f"N={N}, T=1 count={int(T.sum())}, Y=1 count={int(Y.sum())}")

treatment_name = TreatmentSpec().variable_name      # "component_version_treatment"
outcome_name   = OutcomeSpec().variable_name         # "runtime_sbom_drift"
cov_name       = "pre_treatment_load_W"

observations = [
    CausalObservation(
        window_index=i,
        treatment_value=int(T[i]),
        outcome_value=int(Y[i]),
        covariates={cov_name: float(W[i])},
    )
    for i in range(N)
]

# Minimal TemporalDAGProjection matching the DGP structure.
projection = TemporalDAGProjection(
    projected_nodes=[
        (cov_name, 0),
        (treatment_name, 0),
        (outcome_name, 1),
    ],
    projected_edges=[
        ((cov_name, 0), (treatment_name, 0)),
        ((cov_name, 0), (outcome_name, 1)),
        ((treatment_name, 0), (outcome_name, 1)),
    ],
    treatment_or_outcome_in_cycle=False,
)

# Construct model through the production adapter.
handle: CausalModelHandle = construct_causal_model(
    projection=projection,
    observations=observations,
    treatment_name=treatment_name,
    outcome_name=outcome_name,
    covariate_names=[cov_name],
)

model = handle.model

estimand = model.identify_effect(proceed_when_unidentifiable=False)
print(f"Estimand type: {estimand.estimand_type}")

estimate = model.estimate_effect(
    estimand,
    method_name="backdoor.linear_regression",
    control_value=0,
    treatment_value=1,
    target_units="ate",
)

ate = float(estimate.value)
print(f"ATE (backdoor.linear_regression): {ate:.4f}")

assert math.isfinite(ate),     f"ATE is not finite: {ate}"
assert ate > 0.0,              f"Expected positive ATE from DGP; got {ate:.4f}"
assert 0.15 < ate < 0.55,      f"ATE {ate:.4f} outside expected tolerance [0.15, 0.55] for population effect +0.3793"

print()
print("  ASSERTIONS PASSED (SMOKE TEST 1)")
print(f"  [PASS] ATE = {ate:.4f} > 0 (positive, as derived from DGP)")
print("  [PASS] ATE is finite")
print("  [PASS] ATE is within justified tolerance [0.15, 0.55] of true population ATE +0.3793")

# ============================================================
# SMOKE TEST 2: Valid DAG with non-identifiable effect
# ============================================================
print()
print("=" * 60)
print("SMOKE TEST 2: Valid DAG with non-identifiable effect (latent confounder)")
print("=" * 60)

# In this scenario, U_latent is an unobserved common cause: U -> T and U -> Y.
# No observed covariate is available to block the backdoor path.
# The graph is a valid, acyclic DAG, but the backdoor effect is NOT identifiable.
unobs_cov = "U_latent"
non_identifiable_proj = TemporalDAGProjection(
    projected_nodes=[
        (unobs_cov, 0),
        (treatment_name, 0),
        (outcome_name, 1),
    ],
    projected_edges=[
        ((unobs_cov, 0), (treatment_name, 0)),
        ((unobs_cov, 0), (outcome_name, 1)),
        ((treatment_name, 0), (outcome_name, 1)),
    ],
    treatment_or_outcome_in_cycle=False,
)

# Verify graph is strictly a DAG (no cycles)
g_check = nx.DiGraph()
g_check.add_edges_from([
    ("U_latent", treatment_name),
    ("U_latent", outcome_name),
    (treatment_name, outcome_name),
])
assert nx.is_directed_acyclic_graph(g_check), "Graph must be a valid DAG"

# Build model without U_latent in observations (so it is treated as unobserved)
obs_unobserved = [
    CausalObservation(
        window_index=i,
        treatment_value=int(T[i]),
        outcome_value=int(Y[i]),
        covariates={},  # U_latent is not observed!
    )
    for i in range(N)
]

handle_unidentifiable = construct_causal_model(
    projection=non_identifiable_proj,
    observations=obs_unobserved,
    treatment_name=treatment_name,
    outcome_name=outcome_name,
    covariate_names=[],
)

estimand_unidentifiable = handle_unidentifiable.model.identify_effect(
    proceed_when_unidentifiable=False
)
backdoor_estimand = estimand_unidentifiable.estimands.get("backdoor")
print(f"Backdoor estimand: {backdoor_estimand}")
assert backdoor_estimand is None, f"Expected backdoor estimand to be None, got {backdoor_estimand}"

# Verify end-to-end via estimate_causal_attribution
bdg = BehavioralDependencyGraph()
res_unidentifiable = asyncio.run(
    estimate_causal_attribution(
        bdg=bdg,
        observations=obs_unobserved,
        treatment_spec=TreatmentSpec(),
        outcome_spec=OutcomeSpec(),
        covariates=[],
        projection=non_identifiable_proj,
    )
)

print(f"Attribution Status: {res_unidentifiable.status.value}")
print(f"Attribution Reason: {res_unidentifiable.reason}")
assert res_unidentifiable.status == AttributionStatus.NOT_IDENTIFIABLE, (
    f"Expected NOT_IDENTIFIABLE, got {res_unidentifiable.status}"
)
assert res_unidentifiable.ate is None, "ATE must be None when not identifiable"

print()
print("  ASSERTIONS PASSED (SMOKE TEST 2)")
print("  [PASS] Graph is a verified acyclic DAG (nx.is_directed_acyclic_graph == True)")
print("  [PASS] DoWhy returns estimand.estimands['backdoor'] is None")
print("  [PASS] estimate_causal_attribution returns AttributionStatus.NOT_IDENTIFIABLE")
print("  [PASS] ATE is None (system abstains correctly)")

# ============================================================
# SMOKE TEST 3: Invalid Graph — Cycle Rejection
# ============================================================
print()
print("=" * 60)
print("SMOKE TEST 3: Invalid graph — cycle rejection (INVALID_GRAPH)")
print("=" * 60)

cyclic_projection = TemporalDAGProjection(
    projected_nodes=[(treatment_name, 0), (outcome_name, 0)],
    projected_edges=[
        ((treatment_name, 0), (outcome_name, 0)),
        ((outcome_name, 0), (treatment_name, 0)),
    ],
    treatment_or_outcome_in_cycle=True,
)

# 1. Direct adapter check: raises GraphCycleError
try:
    construct_causal_model(
        projection=cyclic_projection,
        observations=observations,
        treatment_name=treatment_name,
        outcome_name=outcome_name,
        covariate_names=[],
    )
    print("  FAIL: Expected GraphCycleError but none was raised")
    sys.exit(1)
except GraphCycleError as exc:
    print(f"  GraphCycleError raised correctly: {exc}")

# 2. Pipeline check: returns AttributionStatus.INVALID_GRAPH (not NOT_IDENTIFIABLE)
res_cyclic = asyncio.run(
    estimate_causal_attribution(
        bdg=bdg,
        observations=observations,
        treatment_spec=TreatmentSpec(),
        outcome_spec=OutcomeSpec(),
        covariates=[],
        projection=cyclic_projection,
    )
)

print(f"Attribution Status: {res_cyclic.status.value}")
print(f"Attribution Reason: {res_cyclic.reason}")
assert res_cyclic.status == AttributionStatus.INVALID_GRAPH, (
    f"Expected INVALID_GRAPH, got {res_cyclic.status}"
)
assert res_cyclic.status != AttributionStatus.NOT_IDENTIFIABLE, (
    "Cycle must not be mislabeled as NOT_IDENTIFIABLE"
)
assert res_cyclic.ate is None, "ATE must be None for invalid graph"

print()
print("  ASSERTIONS PASSED (SMOKE TEST 3)")
print("  [PASS] Cyclic graph raises GraphCycleError in construct_causal_model")
print("  [PASS] estimate_causal_attribution returns AttributionStatus.INVALID_GRAPH")
print("  [PASS] Cyclic graph is distinctly separated from NOT_IDENTIFIABLE")

# ============================================================
# Summary
# ============================================================
print()
print("=" * 60)
print("ALL 3 SMOKE TESTS PASSED")
print(f"  Synthetic ATE:              {ate:.4f}")
print(f"  Estimator:                  backdoor.linear_regression")
print(f"  Identification:             {estimand.estimand_type}")
print(f"  Expected population ATE:    +0.3793 (probit DGP derived)")
print(f"  Tolerance asserted:         [0.15, 0.55]")
print(f"  Non-identifiable status:    {res_unidentifiable.status.value}")
print(f"  Invalid graph status:       {res_cyclic.status.value}")
print("=" * 60)
sys.exit(0)
