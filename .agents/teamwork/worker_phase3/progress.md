# Progress — worker_phase3

Last visited: 2026-10-24T11:15:00Z

## Status
- Verified Phase 3 full test execution across all 4 suites:
  1. Opaque-box E2E test suite (`tests/e2e/`): 242 / 242 passed (100% green).
     - Tier 1: 105 passed in 36.14s
     - Tier 2: 105 passed in 23.60s
     - Tier 3: 11 passed in 13.80s
     - Tier 4: 21 passed in 12.93s
  2. Research evaluation test suite (`research/evaluation/tests/`): 114 / 114 passed in 69.85s (100% green).
  3. Causal engine tests (`services/causal-engine/tests/`):
     - In `.venv-causal` (with `pytest-asyncio` + `asyncpg`): 357 / 357 passed in 32.64s (100% green).
     - In Python 3.14 (without `asyncpg`/`pytest-asyncio`): 339 passed, 18 failed due to documented asyncpg/pytest-asyncio dependencies.
  4. SBOM service tests (`services/sbom-service/tests/`):
     - In `.venv-causal` (with `pytest-asyncio`): 177 / 177 passed in 1.62s (100% green).
     - In Python 3.14 (without `pytest-asyncio`): 121 passed (`test_domain.py` and `test_runtime_mapper.py`), while `test_router.py` and `test_use_cases.py` require `pytest-asyncio`.
- Verified all 21 features in PROJECT.md Feature Inventory continue to have passing tests.
- Verified deterministic pipeline report generation:
  `python run_pipeline_report.py --data-dir research/datasets/raw3 --out output/reports.json`
  Generated `reports.json` (schema v1.0.0), `table_1_detection_performance.tex`, and `table_1_detection_performance.csv`.
- Preparing final handoff.md and orchestrator notification.
