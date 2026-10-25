# PHANTOM Part 6 — Causal Runtime & Dependency Audit

> **Document**: `CAUSAL_RUNTIME_AUDIT.md`  
> **Date**: 2026-10-23  
> **Component**: `services/causal-engine` & Root Pipeline  
> **Status**: COMPLETED & VERIFIED

---

## 1. Executive Summary

During Parts 1–5 of the PHANTOM research prototype, the local environment ran on Python 3.14 (system default at `C:\Python314\python.exe` and Anaconda at `D:\anaconda3\python.exe`). Under Python 3.14, the causal engine was non-functional:
1. `dowhy==0.11.1` declared `requires-python = ">=3.8,<3.12"` on PyPI, completely blocking installation on Python 3.12, 3.13, and 3.14.
2. Unconstrained pip fallback resolved to ancient `dowhy==0.8.0`, pulling in outdated C extensions including `gmpy2`. On Windows under Python 3.14, importing `gmpy2` triggered an uncatchable native OS crash (`NTSTATUS 0xc0000139`, "Entry Point Not Found"), terminating or hanging any process that attempted an import.
3. Code in Part 5 had to substitute `importlib.util.find_spec("dowhy")` and wrap estimation calls in `BaseException` handlers to survive the test suite without crashing.

In Part 6, an isolated compatible Python 3.12 environment (`.venv-causal`) was established using Python 3.12 (`C:\Users\harsh\AppData\Local\Programs\Python\Python312\python.exe`). A verified, pinned dependency set was established (`dowhy==0.12.0`, `networkx==3.3`, `pandas==2.2.2`), resolving native crashes, auto-identifier attribute errors, and pandas Series indexing breakages.

Subsequent deep verification audited runtime interactions, uncovering and resolving:
- An overly tight subprocess import timeout in `run_pipeline_report.py` (5s -> 20s) that was masking healthy DoWhy availability.
- An async event-loop clash in `RunAnalysisUseCase._attempt_estimation` when invoked from active async loops.
- An inverted pass condition for `placebo_treatment_refuter` in `estimate_causal_attribution`.
- An imbalanced fixture covariate stratification in `conftest.py` that caused `test_construct_causal_model_valid` to skip, which now passes completely.

---

## 2. Runtime Environment Audit

### 2.1 Python Executables on Host

| Environment | Executable Path | Python Version | Status / Compatibility |
|---|---|---|---|
| Host Default | `C:\Python314\python.exe` | Python 3.14.6 | Incompatible with DoWhy C extensions (gmpy2 crash 0xc0000139) |
| Anaconda | `D:\anaconda3\python.exe` | Python 3.14.6 | Incompatible (gmpy2 DLL modal hang / timeout) |
| Local Python 3.12 | `C:\Users\harsh\AppData\Local\Programs\Python\Python312\python.exe` | Python 3.12.0 | **Supported & Verified** |
| Virtualenv `.venv` | `D:\project-1\.venv\pyvenv.cfg` | Python 3.12.11 (MSYS2) | Incomplete (missing pip/native Windows layout) |
| Virtualenv `.venv-causal` | `D:\project-1\.venv-causal\Scripts\python.exe` | Python 3.12.0 | **Active Isolated Causal Runtime** |

*Note on Python 3.13*: Python 3.13 is NOT installed on the host OS. Python 3.12.0 is installed and fully supported by `dowhy==0.12.0` (which specifies `requires-python = ">=3.8,<3.13"`).

### 2.2 Python Executable Used by Pipeline Scripts & Tests

- **Tests (`services/causal-engine/tests`)**: Executed using `d:\project-1\.venv-causal\Scripts\pytest.exe` (Python 3.12.0).
- **Report Script (`run_pipeline_report.py`)**: Executed using `d:\project-1\.venv-causal\Scripts\python.exe` (Python 3.12.0).
- **Standalone Smoke Test (`smoke_test_dowhy.py`)**: Executed using `d:\project-1\.venv-causal\Scripts\python.exe` (Python 3.12.0).

---

## 3. Installed Package Versions Audit

| Package | Version in Host / Anaconda (3.14) | Version in `.venv-causal` (3.12) | Role / Compatibility Assessment |
|---|---|---|---|
| `dowhy` | 0.8.0 (broken) | **0.12.0** | Pinned. Supports Python <3.13. |
| `networkx` | 3.7 (incompatible) | **3.3** | Pinned. NetworkX >=3.4 removed `nx.algorithms.d_separated` which DoWhy 0.12 calls in `graph.py:99`. Version 3.3 retains `d_separated`. |
| `pandas` | 3.1.0 (incompatible) | **2.2.2** | Pinned. Pandas >=3.0 removed integer positional fallback on string index (`ser[0]` -> `KeyError: 0`). DoWhy regression estimator requires 2.x behavior. |
| `numpy` | 2.5.4 | **2.5.4** | Compatible. Satisfies `numpy>2.0` for dowhy 0.12. |
| `scipy` | 1.18.1 | **1.18.1** | Compatible. Prebuilt wheel, no native build issues. |
| `scikit-learn`| 1.9.1 | **1.9.1** | Compatible. |
| `sympy` | 1.14.0 | **1.14.0** | Compatible. Pure python + mpmath. |
| `gmpy2` | Installed (crashes 0xc0000139) | **Not Installed** | Not required by DoWhy 0.12 or sympy. |
| `pydantic` | 2.14.1 | **2.14.1** | Compatible with `libs/phantom-core`. |
| `structlog` | 26.1.0 | **26.1.0** | Compatible. |
| `asyncpg` | Not installed | **0.32.0** | Installed for BDG graph store tests. |

---

## 4. Runtime Defect & Exception-Handling Analysis

### 4.1 Native DLL Crash Mechanism (Host Python 3.14)
- **Stage of failure**: Package import (`import dowhy`).
- **Trigger**: On Python 3.14, `dowhy 0.8` imported `sympy`, which attempted to import `gmpy2`. The prebuilt binary wheel for `gmpy2` lacked entry points compatible with the Python 3.14 C-API DLL export table on Windows.
- **Manifestation**: Windows NTSTATUS code `0xc0000139` (`STATUS_ENTRYPOINT_NOT_FOUND`).
- **Interpreter Behavior**: The OS terminated the process immediately without raising a Python exception.
- **Resolution**: Under Python 3.12 with modern `dowhy==0.12.0` and `sympy 1.14.0`, `gmpy2` is omitted. Subprocess verification (`python -c "import dowhy"`) exits with returncode 0.

### 4.2 Subprocess Smoke Check Timeout in `run_pipeline_report.py`
- **Issue**: `_check_dowhy` used an isolated subprocess with `timeout=5`. On Windows with full cold dependency loading (SciPy, scikit-learn, SymPy, NetworkX), initial process import takes ~7.6 seconds.
- **Symptom**: `_check_dowhy` timed out, caught `Exception`, and returned `False`, falsely reporting `dowhy_available = False` in pipeline reports even though the environment was fully functional.
- **Fix**: Increased subprocess timeout to 20 seconds. The report now accurately outputs `"dowhy_available": true`.

### 4.3 Async Event-Loop Conflict in `_attempt_estimation`
- **Issue**: `RunAnalysisUseCase._attempt_estimation` called `asyncio.run(estimate_causal_attribution(...))` unconditionally.
- **Symptom**: When `execute()` was invoked within an existing active event loop (e.g. FastAPI request thread or async test), `asyncio.run()` threw `RuntimeError: asyncio.run() cannot be called from a running event loop`, failing estimation and leaking unawaited coroutine warnings.
- **Fix**: Detected active running loops via `asyncio.get_running_loop()`; when a loop is active, execution is delegated to a separate thread via `concurrent.futures.ThreadPoolExecutor(max_workers=1)`.

### 4.4 Inverted Placebo Refutation Pass Evaluation
- **Issue**: `estimate_causal_attribution` evaluated all refuters with `abs(new_effect - ate_value) / abs(ate_value) < 0.5`.
- **Symptom**: For `placebo_treatment_refuter`, the treatment is replaced with random noise so the effect should drop to zero. A new effect of ~0.002 (successful refutation) produced `abs(0.002 - 0.365) / 0.365 = 0.99 > 0.5`, incorrectly failing the refutation and docking confidence.
- **Fix**: Refactored pass criteria: `placebo_treatment_refuter` checks that effect magnitude vanishes (`abs(new_effect) < 0.2 * abs(ate_value)` or `p_value > 0.05`), while stability refuters retain the 50% change bound.

### 4.5 Imbalanced Covariate Stratification in Fixtures
- **Issue**: `sample_observations` in `conftest.py` had `namespace_risk: 0.5 if i < 20 else 0.8` while `treatment = 1 if i >= 15 else 0`. For all `i >= 20`, `treatment` was 1 with zero controls, violating positivity and causing `test_construct_causal_model_valid` to call `pytest.skip`.
- **Fix**: Stratified `namespace_risk: 0.5 if (i % 4 < 2) else 0.8` ensuring both treatment levels appear across all covariate strata. Removed the skip; the test now executes and passes.

---

## 5. Dependency Declaration Discrepancies Across the Repository

| File | Declared Dependency | Actual Requirement / Discrepancy |
|---|---|---|
| `services/causal-engine/Dockerfile` | `FROM python:3.11-slim` | Uses Python 3.11 for Linux container. |
| `services/causal-engine/pyproject.toml` (original) | `dowhy==0.11.1` | Pinned exact 0.11.1. On PyPI, 0.11.1 has `requires-python: ">=3.8,<3.12"`. This prevented installation on Python 3.12+. Updated to `dowhy>=0.11.1,<0.15`. |
| `services/causal-engine/pyproject.toml` (original) | `networkx==3.3` | Pinned to 3.3. Correct, because networkx >=3.4 breaks DoWhy 0.12. Updated to `networkx>=3.3,<3.4`. |
| `services/causal-engine/pyproject.toml` (original) | `pandas==2.2.2` | Pinned to 2.2.2. Correct, because pandas >=3.0 breaks DoWhy 0.12. Updated to `pandas>=2.2.0,<3.0.0`. |
| `research/evaluation/pyproject.toml` | `pandas>=2.2.0`, `scikit-learn>=1.5.0` | Compatible with causal-engine runtime. |
| `libs/phantom-core/pyproject.toml` | `pydantic==2.7.4`, `structlog==24.2.0` | Flexible under modern v2/structlog in local venv. |

---

## 6. Audit Conclusions

1. **Root Cause**: Python 3.14 + `dowhy 0.8` + Windows DLL ABI mismatch produced native OS crashes. In addition, NetworkX 3.7 and pandas 3.1 broke DoWhy's internal assumptions (`nx.algorithms.d_separated` and `ser[0]`).
2. **Solution**: Python 3.12 virtual environment (`.venv-causal`) with pinned `dowhy==0.12.0`, `networkx==3.3`, and `pandas==2.2.2`.
3. **Verification**:
   - `dowhy` imports cleanly in a fresh process (exit code 0).
   - Model construction, effect identification, backdoor linear regression estimation, and refutations all execute functionally.
   - All 278 tests in `services/causal-engine`, 47 tests in `libs/phantom-core`, and 177 tests in `services/sbom-service` pass (502 passed total, 0 skipped, 0 failed).
