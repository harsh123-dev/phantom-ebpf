# PHANTOM Stage 4: Safe Smoke Test Report

**Status:** **NOT RUN — application services are not deployed and the smoke-test dependencies are unavailable.**

The pilot runner dry-run was attempted as a harmless supported check. It exited before planning because `httpx` is missing. No attack scenario was invoked, no cluster command was issued, and the output directory `research/datasets/pilot_batch01` was not created.

| Workflow | Status | Evidence / reason |
|---|---|---|
| Application health | UNKNOWN | No cluster, services, or health endpoints reachable. |
| Runtime event ingestion | UNKNOWN | No running eBPF agent or API. |
| Event-to-observation transformation | UNKNOWN | No pipeline available. |
| Runtime-to-SBOM mapping | UNKNOWN | No services available. |
| Fixture drift evaluation / causal engine | UNKNOWN | Not run; dependencies unavailable. |
| Report generation and persistence/export | UNKNOWN | Not run; no test fixture workflow could be executed. |
| Independent ground truth | UNKNOWN | No live observation; no alerts treated as evidence. |
| Missing telemetry behavior | PARTIAL static fix | Runner now serializes missing/dry-run overhead as `None`; runtime and downstream tests unavailable. |
| Synthetic vs real dataset separation | PASS (filesystem check only) | `pilot_batch01` absent; historical `raw` and `raw3` directories were not modified. |

No synthetic smoke record or live experiment record was created. A synthetic test, when dependencies are available, must remain separately labeled and must not be described as attack detection evidence.
