# PHANTOM Pilot Batch 01 — Manual Runbook (Draft; Gate Not Cleared)

**Do not execute live until deployment, smoke testing, sink isolation, independent evidence, and the manual pilot gate are reviewed and cleared.** Safe dry-run planning completes locally without contacting a cluster.

## Planned matrix from the runner

`research/evaluation/experiment_config.yaml` is loaded by the runner and defines six pilot scenarios and three repetitions (18 planned runs):

| Type | Scenario | Target |
|---|---|---|
| Attack | `xzutils-001` | `recommendationservice` |
| Attack | `dep-confusion-001` | `emailservice` |
| Attack | `solarwinds-001` | `cartservice` |
| Control | `benign-update-001` | `recommendationservice` |
| Control | `benign-load-001` | `emailservice` |
| Control | `benign-restart-001` | `cartservice` |

These are planned counts, not successful experiments. Control actions are implemented as a metadata rollout, a bounded internal HTTP request burst, and a pod replacement. Their behavior requires independent receipts. Contract outcome remains unknown until a separate contract-state oracle is available.

**Current execution result:** 0 of 18 planned runs attempted. The timestamped status-only record is `research/datasets/pilot_batch01/20261025T123839Z/`. The current host failed the dedicated-lab identity gate. See `PILOT_BATCH01_ANALYSIS.md`.

## Gate and preflight

Before proceeding, the operator must confirm the actual designated disposable lab and review the deployment and smoke-test reports. Then, from the correct checkout:

1. Confirm `kubectl config current-context` and `kubectl cluster-info`; verify the API endpoint is the approved lab endpoint and the intended context is disposable.
2. Verify `kubectl get nodes -o wide`, `kubectl get ns`, all workload/service readiness, eBPF event ingestion, current Prometheus samples, sink reachability, and enforced egress policy.
3. Verify independent injection and behavior evidence capture. PHANTOM alerts are detector outputs only. Falco evidence is unknown unless its collector is deployed and verified.
4. Ensure `research/datasets/pilot_batch01` does not already contain results. Never write to historical `raw` or `raw3` directories. Export/copy raw output and logs after each operator-run batch without overwriting existing artifacts.
5. The dry-run plan was verified here for 18 and 27 runs. Run it again after changes and inspect IDs/targets. The focused pytest command cannot currently start because pytest is unavailable; use a project-supported Python 3.11 environment before live execution. Do not infer readiness from dry-run alone.
6. Confirm enough disk space and that the local API/Prometheus access paths and Falco log path are valid for the operator's host.

## Dry-run command

Run from the repository root (planning needs PyYAML but not HTTP runtime dependencies):

```bash
python3 research/evaluation/scenarios/run_all_scenarios.py \
  --campaign pilot \
  --namespace phantom-eval \
  --kubectl-context "$LAB_CONTEXT" \
  --repetitions 3 \
  --dry-run
```

Expected behavior is a printed 18-run plan under a unique timestamped output path and no output files. Verify the printed resolved path is new; dry-run performs no directory creation.

## Manual live command for operator review only

This is the runner command to execute only after the gate is explicitly cleared, the context value is verified, access paths are established, and the operator intentionally starts the pilot. Do not add automatic retries. Do not run it from this assistant session.

```bash
python3 research/evaluation/scenarios/run_all_scenarios.py \
  --campaign pilot \
  --namespace phantom-eval \
  --kubectl-context "$LAB_CONTEXT" \
  --phantom-api http://localhost:8080 \
  --prometheus http://localhost:9090/api/v1/query \
  --repetitions 3 \
  --execute
```

The runner uses phase durations from the YAML config unless overridden. The default Falco path is `/var/log/falco/events.jsonl`. Any missing telemetry or contract-state evidence remains unknown. The runner writes per-run JSON, `index.json`, and immutable batch oracles beneath the unique timestamped directory printed by the dry-run; preserve these raw files.

## Interruption and teardown

If the endpoint, namespace, sink, or egress perimeter differs from the approved lab, stop before starting or interrupt the runner with Ctrl-C and preserve logs and partial artifacts. Do not restart failed injections automatically. After the operator records and exports evidence, follow the reviewed lab teardown procedure manually. Do not use Terraform from this runbook.
