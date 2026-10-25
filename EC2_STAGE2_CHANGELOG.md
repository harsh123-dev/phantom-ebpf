# PHANTOM Stage 2 Changelog

## 2026-10-25 — Preserve missing-overhead state

- **File:** `research/evaluation/scenarios/scenario_runner.py`
- **Problem:** Prometheus query failures, absent series, and dry-run measurements were encoded as `0.0`, incorrectly making missing telemetry indistinguishable from measured zero overhead.
- **Change:** `MetricsSnapshot` overhead fields accept `None`; dry-run and unavailable query results now return `None`.
- **Reasoning:** Preserve unknown/unmeasured state and prevent false zero-overhead claims.
- **Verification:** Python AST parsing passed. The full pytest suite is unavailable because `pytest`, `httpx`, and project dependencies are not installed. The pilot dry-run import failed on missing `httpx` before executing the plan; no data files were written.
- **Risk/limit:** Runtime serialization and downstream analysis tests remain unverified on this host. Prometheus scrape/metric-name mismatches remain unresolved and block overhead measurement.
