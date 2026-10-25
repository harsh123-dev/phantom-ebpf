# PHANTOM E2E Test Infrastructure & Methodology Specification

## 1. Overview & Objectives

This document specifies the architecture, testing infrastructure, tiering hierarchy, and verification methodology of the PHANTOM end-to-end (E2E) opaque-box test suite (`tests/e2e/`).

The suite provides exhaustive, requirement-driven verification across all 21 features identified in `PROJECT.md § Feature Inventory` and `ORIGINAL_REQUEST.md`. It validates both core functional paths and adversarial boundaries, cross-feature interactions, and real-world deployment/evaluation scenarios.

---

## 2. Test Architecture & Directory Layout

The E2E test suite resides at `tests/e2e/` at the root of the workspace:

```text
tests/
├── __init__.py
└── e2e/
    ├── __init__.py
    ├── contracts.py                # Pure-math reference oracles, dataclasses, and interface contracts
    ├── conftest.py                 # Pytest session fixtures, path resolvers, isolated service importers
    ├── test_tier1_features.py      # Tier 1: Core feature coverage (105 tests, >=5 per feature)
    ├── test_tier2_boundaries.py    # Tier 2: Boundary & corner cases (105 tests, >=5 per feature)
    ├── test_tier3_interactions.py  # Tier 3: Cross-feature combinations (11 tests)
    └── test_tier4_scenarios.py     # Tier 4: Real-world application scenarios (21 tests)
```

### Namespace Isolation Design
The repository hosts multiple decoupled microservices with overlapping top-level package namespaces (`app` in `services/causal-engine` and `app` in `services/sbom-service`).
To prevent `sys.modules['app']` shadowing and cross-service pollution:
1. `tests/e2e/conftest.py` configures `services/causal-engine` as the default application import in `sys.path`.
2. A dedicated context manager `isolated_service_import(service_name: str)` temporarily unloads `app.*` modules, re-points `sys.path` to the target service directory, executes the import block, and restores previous module cache cleanly.
3. Fixtures like `sbom_mapping_classes` and `causal_validation_classes` expose typed domain classes safely without risking pollution.

---

## 3. The 4-Tier Test Strategy

The test suite is structured into four progressive tiers:

| Tier | File | Description | Test Count |
| :--- | :--- | :--- | :--- |
| **Tier 1** | `test_tier1_features.py` | Primary behavior (happy path) for all 21 features in `PROJECT.md` | **105** (5/feature) |
| **Tier 2** | `test_tier2_boundaries.py` | Boundary conditions, edge cases, malformed payloads, zero-denominators | **105** (5/feature) |
| **Tier 3** | `test_tier3_interactions.py` | Cross-feature combinations (pipeline + gates, resolver + BDG, tables + Wilson) | **11** |
| **Tier 4** | `test_tier4_scenarios.py` | Real-world datasets (`raw`, `raw3`), reproduction scripts, oracle alignment | **21** |
| **Total** | | | **242 tests** |

---

## 4. Feature-to-Test Traceability Matrix (All 21 Features)

| Feature # | Feature Name in `PROJECT.md` | Tier 1 Tests | Tier 2 Tests | Tier 3/4 Coverage |
| :---: | :--- | :---: | :---: | :--- |
| **1** | Raw Dataset Dropout Audit | 5 tests | 5 tests | Scenario 1, Scenario 3 |
| **2** | Raw3 Dataset Evaluation & Ingestion | 5 tests | 5 tests | Scenario 2, Interaction 8 |
| **3** | Ground Truth Decoupled 4-Dim Protocol | 5 tests | 5 tests | Scenario 4, Interaction 9 |
| **4** | Preflight Gate G1 Technical Guard | 5 tests | 5 tests | Scenario 1, Interaction 4 |
| **5** | Preflight Gate G2 Component Mapping | 5 tests | 5 tests | Interaction 8 |
| **6** | Preflight Gate G3 Temporal Precedence | 5 tests | 5 tests | Interaction 9 |
| **7** | Preflight Gate G4 Anti-Mediator Rule | 5 tests | 5 tests | Interaction 9 |
| **8** | Preflight Gate G5 Treatment Variation & Positivity | 5 tests | 5 tests | Interaction 5 |
| **9** | Defensible TPR Metric Computation | 5 tests | 5 tests | Scenario 2, Interaction 1 |
| **10** | Defensible FPR & Denominator Handling | 5 tests | 5 tests | Scenario 2, Interaction 2 |
| **11** | Pure-Math Ordinary Wilson Score Interval | 5 tests | 5 tests | Scenario 2, Interaction 6 |
| **12** | Non-Parametric Bootstrap MTTD & IQR | 5 tests | 5 tests | Scenario 2, Interaction 10 |
| **13** | Honest Baseline Detector Accounting | 5 tests | 5 tests | Interaction 3 |
| **14** | Baseline Phase Overhead Accounting | 5 tests | 5 tests | Interaction 3 |
| **15** | Runtime-to-SBOM Mapping Resolution | 5 tests | 5 tests | Interaction 8 |
| **16** | Comparison Table Formatting & Bolding Fix | 5 tests | 5 tests | Scenario 5, Interaction 7 |
| **17** | Deterministic Pipeline CLI (`run_pipeline_report.py`)| 5 tests | 5 tests | Scenario 3, Interaction 11 |
| **18** | LaTeX and CSV Artifact Generation | 5 tests | 5 tests | Scenario 5, Interaction 7 |
| **19** | Comprehensive Documentation & Protocols | 5 tests | 5 tests | Interaction 11 |
| **20** | Existing Test Suite Preservation | 5 tests | 5 tests | Baseline suite verification |
| **21** | Comprehensive E2E Verification Hardening | 5 tests | 5 tests | All integration paths |

---

## 5. Authoritative Pure-Math Oracles & Interface Contracts

The module `tests/e2e/contracts.py` implements pure-math reference oracles derived from `ORIGINAL_REQUEST.md`, `PROJECT.md`, and standard statistical literature:

### 1. Ordinary Wilson Score Interval (No Continuity Correction)
Standard normal score interval for binomial proportions:
$$\hat{p} = \frac{x}{n}, \quad z = 1.95996398454 \text{ (for 95\% CI)}$$
$$\text{Center} = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}$$
$$\text{Margin} = \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}}$$
$$\text{CI} = [\max(0.0, \text{Center} - \text{Margin}), \min(1.0, \text{Center} + \text{Margin})]$$
*Reference test oracle value:* $x=6, n=6 \implies [0.6096, 1.0000]$.

### 2. Non-Parametric Bootstrap Percentile CI for MTTD
- Computes mean, median, interquartile range (IQR = $Q_3 - Q_1$), and $P_{95}$ with deterministic seed.
- 1,000 bootstrap resamples with replacement to derive 95% empirical percentile confidence intervals $[P_{2.5}, P_{97.5}]$.

### 3. Decoupled 4-Dimensional Protocol
Evaluates 4 orthogonal experimental dimensions:
1. $T_{\text{inject}} \in \{\text{True}, \text{False}\}$: Delivery success (verified via exit codes and deployment status).
2. $B_{\text{verified}} \in \{\text{True}, \text{False}, \text{Unknown}\}$: Behavioral baseline stability.
3. $Y_{\text{drift}} \in \{\text{True}, \text{False}, \text{Unknown}\}$: Independently verified runtime contract violation.
4. $\hat{Y}_{\text{phantom}} \in \{\text{True}, \text{False}\}$: Detector alert emitted within the scenario detection window.

*Rule:* True Positive requires BOTH $Y_{\text{drift}} = \text{True}$ AND $\hat{Y}_{\text{phantom}} = \text{True}$. Failed injection ($T_{\text{inject}} = \text{False}$) is excluded from TPR denominator.

### 4. LaTeX and CSV Formatting Standards
- LaTeX table cells format undefined metrics as `\text{---}`.
- CSV table cells format undefined metrics as `---` or empty strings.
- Bolding is strictly reserved for the best legitimate numeric value. Unmeasured metrics (such as unobserved 0% overhead) are never bolded.

---

## 6. Execution Commands & Environment

### Environment
- **Operating System:** Windows 11
- **Python Version:** Python 3.12.0
- **Virtual Environment:** `.venv-causal` at project root (`d:\project-1\.venv-causal`)
- **Pytest Version:** 9.1.1

### Running the E2E Test Suite
To execute the complete E2E test suite:
```powershell
$env:PYTHONPATH="."
.venv-causal\Scripts\pytest.exe tests/e2e -v
```

Or via `cmd.exe`:
```cmd
set PYTHONPATH=. && .venv-causal\Scripts\pytest.exe tests/e2e -v
```

### Running Individual Tiers
```powershell
# Tier 1
.venv-causal\Scripts\pytest.exe tests/e2e/test_tier1_features.py -v

# Tier 2
.venv-causal\Scripts\pytest.exe tests/e2e/test_tier2_boundaries.py -v

# Tier 3
.venv-causal\Scripts\pytest.exe tests/e2e/test_tier3_interactions.py -v

# Tier 4
.venv-causal\Scripts\pytest.exe tests/e2e/test_tier4_scenarios.py -v
```

### Running Baseline Suites
```cmd
# Evaluation baseline
set PYTHONPATH=. && .venv-causal\Scripts\pytest.exe research/evaluation/tests

# SBOM Service baseline
set PYTHONPATH=services/sbom-service && .venv-causal\Scripts\pytest.exe services/sbom-service/tests

# Causal Engine baseline
set PYTHONPATH=services/causal-engine && .venv-causal\Scripts\pytest.exe services/causal-engine/tests
```
