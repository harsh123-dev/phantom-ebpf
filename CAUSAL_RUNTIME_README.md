# PHANTOM Part 6 — Compatible Causal Runtime & Functional Estimation Validation

> **Document**: `CAUSAL_RUNTIME_README.md`  
> **Date**: 2026-10-23  
> **Status**: COMPLETED & VERIFIED (Including Verification Patch: Causal Status Semantics and Confidence)

---

## 1. Original Runtime and Dependency Problem

In Parts 1–5, the host environment defaulted to Python 3.14 (`C:\Python314\python.exe` / Anaconda `D:\anaconda3\python.exe`). Under this configuration:
- `dowhy==0.11.1` refused to install because its PyPI distribution declares `requires-python = ">=3.8,<3.12"`.
- When pip was run without version constraints, it fell back to `dowhy==0.8.0`.
- `dowhy 0.8.0` on Python 3.14 caused a native Windows entry point failure (`NTSTATUS 0xc0000139`) in the `gmpy2` binary C extension upon `import dowhy`.
- To prevent test runner crashes, prior work substituted `importlib.util.find_spec("dowhy")` and wrapped estimation logic in blanket `BaseException` handlers.
- In addition, modern unpinned installations of `networkx` (v3.7) removed `nx.algorithms.d_separated`, causing `AttributeError` inside DoWhy's backdoor identifier, and modern `pandas` (v3.1) broke positional parameter indexing (`self.model.params[0]` -> `KeyError: 0`).

---

## 2. Selected Python and Dependency Versions

- **Python**: **Python 3.12.0** (`C:\Users\harsh\AppData\Local\Programs\Python\Python312\python.exe`).
  - *Rationale*: Python 3.13 was not installed on the host system. Python 3.12 is natively supported by `dowhy==0.12.0` (`requires-python: ">=3.8,<3.13"`).
- **Causal Inference**: `dowhy==0.12.0`
- **Graph Processing**: `networkx==3.3` (retains `d_separated`)
- **Data Tables**: `pandas==2.2.2` (preserves positional indexing fallback)
- **Numerical / Scientific**: `numpy==2.5.4`, `scipy==1.18.1`, `scikit-learn==1.9.1`, `statsmodels==0.15.0`, `sympy==1.14.0`
- **Application Framework**: `pydantic==2.14.1`, `pydantic-settings==2.16.1`, `structlog==26.1.0`, `asyncpg==0.32.0`
- **Pinned Manifest**: Recorded in [`services/causal-engine/requirements-causal-runtime.txt`](file:///d:/project-1/services/causal-engine/requirements-causal-runtime.txt).

---

## 3. Environment Setup Commands (Windows PowerShell)

To create, activate, configure, and verify the isolated causal runtime:

```powershell
# 1. Create isolated virtual environment using Python 3.12
& "C:\Users\harsh\AppData\Local\Programs\Python\Python312\python.exe" -m venv d:\project-1\.venv-causal

# 2. Activate environment
d:\project-1\.venv-causal\Scripts\Activate.ps1

# 3. Install pinned compatible causal runtime dependencies
& "d:\project-1\.venv-causal\Scripts\pip.exe" install -r "d:\project-1\services\causal-engine\requirements-causal-runtime.txt"

# 4. Install local repository libraries in editable mode without dependencies
& "d:\project-1\.venv-causal\Scripts\pip.exe" install --no-deps -e "d:\project-1\libs\phantom-core" -e "d:\project-1\services\causal-engine" -e "d:\project-1\services\sbom-service"

# 5. Verify installed packages
& "d:\project-1\.venv-causal\Scripts\pip.exe" list

# 6. Verify DoWhy fresh-process import in an isolated subprocess
& "d:\project-1\.venv-causal\Scripts\python.exe" -c "import dowhy; print('DoWhy imported successfully, version:', dowhy.__version__)"

# 7. Run focused functional causal smoke test
& "d:\project-1\.venv-causal\Scripts\python.exe" "d:\project-1\services\causal-engine\smoke_test_dowhy.py"

# 8. Run regression test suite
& "d:\project-1\.venv-causal\Scripts\pytest.exe" "d:\project-1\services\causal-engine\tests"
```

---

## 4. Actual DoWhy Import Result

In `.venv-causal`:
```
> & "d:\project-1\.venv-causal\Scripts\python.exe" -c "import dowhy; print(dowhy.__version__)"
0.12
```
Subprocess execution exit code: `0`.  
Standard error: empty (`b''`).  
Execution duration: ~7.6s on cold-start import.  
No native DLL dialogs, no entry-point faults, and no interpreter termination.

---

## 5. Synthetic Causal Model & Mathematical DGP Derivation

### Data-Generating Process (Fixed Seed `42`, $N=300$)
- **Exogenous Noise**:
  - $W \sim \mathcal{N}(0, 1)$ (observed pre-treatment workload confounder)
  - $\epsilon_1 \sim \mathcal{N}(0, 1)$ (independent standard normal treatment noise)
  - $\epsilon_2 \sim \mathcal{N}(0, 1)$ (independent standard normal outcome noise)
- **Structural Causal Equations**:
  - Treatment assignment (probit): $T = \mathbf{1}[0.5 \cdot W + \epsilon_1 > 0]$
  - Outcome equation (probit): $Y = \mathbf{1}[1.5 \cdot T + 0.8 \cdot W + \epsilon_2 > 0]$

### Mathematical Derivation of True Population ATE
Under the intervention $do(T = t)$, the potential outcomes are:
$$Y(0) = \mathbf{1}[0.8 \cdot W + \epsilon_2 > 0]$$
$$Y(1) = \mathbf{1}[1.5 + 0.8 \cdot W + \epsilon_2 > 0]$$

Let $Z_0 = 0.8 \cdot W + \epsilon_2$. Since $W, \epsilon_2 \sim \mathcal{N}(0, 1)$ independently:
$$Z_0 \sim \mathcal{N}\left(0, 0.8^2 + 1\right) = \mathcal{N}(0, 1.64)$$
$$\sigma_0 = \sqrt{1.64} \approx 1.28062$$

The population potential outcome expectations are:
$$\mathbb{E}[Y(0)] = \mathbb{P}(Z_0 > 0) = \Phi\left(\frac{0}{\sigma_0}\right) = 0.5000$$
$$\mathbb{E}[Y(1)] = \mathbb{P}(Z_0 > -1.5) = \Phi\left(\frac{1.5}{1.28062}\right) = \Phi(1.1713) \approx 0.8793$$

Thus, the exact true population Average Treatment Effect is:
$$\text{ATE}^* = \mathbb{E}[Y(1)] - \mathbb{E}[Y(0)] = 0.8793 - 0.5000 = +0.3793$$

On the binary outcome scale, linear probability backdoor regression approximates this risk difference.  
On sample seed 42 ($N=300$), the sample estimate is:
$$\widehat{\text{ATE}} = +0.3648$$
Asserted tolerance range: $[0.15, 0.55]$. The sample estimate agrees within $0.0145$ of the true population effect.

---

## 6. Attribution Confidence Audit & Diagnostic Stability Semantics

### Interpretation of the Confidence Score
- The value produced by `compute_attribution_confidence(...)` is a **heuristic diagnostic stability and data-quality index** in $[0, 1]$, **NOT** a calibrated Bayesian or frequentist probability that the causal claim is empirically true.
- Passing refutation tests (random common cause, data subset, placebo treatment) establishes robustness to tested model perturbations under the maintained structural assumptions; it does **not** prove that no unobserved confounding or unfaithfulness exists.
- To prevent misleading scientific claims, an explicit alias `diagnostic_stability_score` is provided on `AttributionResult`. Both fields are synchronized for backward compatibility.
- The raw estimate, identification status, causal assumptions, and individual refutation results remain unaggregated and fully accessible.

### Refutation Safeguards
- If `ate` is `None` or non-finite (`NaN` or `Inf`), confidence is strictly **0.0**.
- If refutations are skipped, missing, or failed, confidence is penalized proportionally (`passed_count / max(len(refutations), required_refuter_count)`).
- When all 3 refuters pass with narrow confidence intervals and 0% event loss, the stability score reaches `1.0`.

---

## 7. Causal Status Semantics: Invalid Graph vs. Non-Identifiability

To correct semantic ambiguity, the system strictly separates structural graph defects from identification and estimation outcomes:

| Outcome Condition | Returned Status (`AttributionStatus`) | DoWhy / Pipeline Mechanism | ATE Value |
| :--- | :--- | :--- | :--- |
| **Cyclic Graph** | `INVALID_GRAPH` | Projection has cycles or `GraphCycleError` raised by `construct_causal_model` | `None` |
| **Valid DAG, Unidentifiable Effect** | `NOT_IDENTIFIABLE` | Valid DAG with unobserved confounder ($U \to T, U \to Y$); `estimand.estimands['backdoor'] is None` | `None` |
| **Data Shortfall / Small N** | `INSUFFICIENT_EVIDENCE` | Preflight gate G1 failure or `InsufficientVariationError` | `None` |
| **Numerical / Model Crash** | `ESTIMATION_FAILED` | Estimator runtime exception in `estimate_effect()` (never converted to non-identifiability) | `None` |
| **Missing Dependency** | `dependency_unavailable` | DoWhy import fails in subprocess smoke test | `None` |
| **Successful Estimation** | `COMPLETED` | Identifiable DAG, valid data table, estimator returns finite numerical ATE | Finite `float` |

---

## 8. Exact Test Commands and Counts

Executed with `.venv-causal\Scripts\pytest.exe`:

1. **Focused Functional Estimation Suite** (`services/causal-engine/tests/test_functional_estimation.py`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\pytest.exe" services/causal-engine/tests/test_functional_estimation.py -v
   ```
   - **20 passed**, 0 failed in 34.66s.
   - Includes valid-DAG non-identifiability, cyclic-graph rejection, refutation penalties, and confidence diagnostics.

2. **Causal Validation Suite** (`services/causal-engine/tests/test_causal_validation.py`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\pytest.exe" services/causal-engine/tests/test_causal_validation.py -v
   ```
   - **91 passed**, 0 failed in 1.62s.

3. **End-to-End Integration Suite** (`services/causal-engine/tests/test_end_to_end_integration.py`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\pytest.exe" services/causal-engine/tests/test_end_to_end_integration.py -v
   ```
   - **52 passed**, 0 failed in 9.27s.

4. **Full Causal Engine Test Suite** (`services/causal-engine/tests`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\pytest.exe" services/causal-engine/tests
   ```
   - **283 passed**, 0 skipped, 0 failed in 35.70s.
   - Exit code: 0.

5. **Standalone Functional Smoke Test** (`smoke_test_dowhy.py`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\python.exe" services/causal-engine/smoke_test_dowhy.py
   ```
   - Smoke Test 1 (Known DGP Backdoor Linear Regression): $\widehat{\text{ATE}} = +0.3648$ (PASS)
   - Smoke Test 2 (Valid DAG with Latent Confounder): `NOT_IDENTIFIABLE` (PASS)
   - Smoke Test 3 (Cyclic Graph Rejection): `INVALID_GRAPH` (PASS)
   - Exit code: 0.

6. **Production Pipeline Report on Real Dataset** (`run_pipeline_report.py`):
   ```powershell
   & "d:\project-1\.venv-causal\Scripts\python.exe" run_pipeline_report.py
   ```
   - Total runs: 6
   - Preflight passed: 0 (all 6 rejected by Gate G1 `too_few_observations`)
   - Real causal estimates produced: **0**
   - Exit code: 0.

---

## 9. Separation: Synthetic Validation vs. Real-Data Validation

> **CRITICAL SCIENTIFIC DISTINCTION**:
>
> 1. **Software Functional Validation (Achieved)**:
>    The causal engine software, DoWhy adapter, graph constructor, identification algorithm, refutation routines, and estimation pipeline are verified to run end to end on synthetic data with known ground truth ($N=300$, true population ATE $= +0.3793$, sample estimate $\widehat{\text{ATE}} = +0.3648$).
>
> 2. **Real-World Empirical Validation (NOT Claimed & NOT Feasible on Current Dataset)**:
>    No real-data causal attribution estimate was generated for the 6 real Kubernetes experiment runs in `research/datasets/raw/`.
>    - All 6 real runs were rejected by preflight gate G1 (`too_few_observations`).
>    - Each real run contains only 1 run-level observation (minimum required is 10).
>    - Per-window drift labels and detection timestamps are absent in the raw dataset.
>    - The next concrete blocker to real-data causal evaluation is the collection of multi-window telemetry with valid per-window drift labels from a live Kubernetes cluster or expanded replay dataset.
