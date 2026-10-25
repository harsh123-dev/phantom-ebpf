# PHANTOM Stage 5D: Pilot Configuration Audit

**Result:** **BLOCKER for pilot readiness.** This is a source audit only; no scenarios ran.

## Issue classifications

| Issue | Classification | Basis |
|---|---|---|
| Requested config path | **WARNING** | `research/evaluation/scenarios/experiment_config.yaml` is absent; actual file is `research/evaluation/experiment_config.yaml`. |
| YAML controls the runner | **BLOCKER** | YAML is not loaded; advertised `--config` option is unsupported. |
| Profile discrepancies | **WARNING** | YAML omits `solarwinds-001`, gives stale `benign-load-001` target, and names historical output `raw/`. |
| Runner's planned 18-run matrix | **PASS (static only)** | Six IDs and three repetitions are present in source; planned count is not completed run evidence. |
| Benign controls actually execute | **BLOCKER** | All three active benign scenario IDs use `_BenignNoOp`. |
| Output/oracle overwrite protection | **BLOCKER** | Live path uses write mode and has no non-empty-directory or existing-oracle guard. |
| Dry-run output in current environment | **UNKNOWN** | Source indicates no live operations/files, but the actual run previously failed importing missing `httpx`. |
| Cluster identity and pilot safety preflight | **BLOCKER** | No context or endpoint is available here; no pilot preflight was executed. |

## Configuration mismatch

The path mentioned in the request, `research/evaluation/scenarios/experiment_config.yaml`, does not exist. The actual file is `research/evaluation/experiment_config.yaml`.

That YAML header documents `run_all_scenarios.py --config ...`, but the runner has no `--config` argument and does not load YAML. It hard-codes `PILOT_SCENARIO_IDS` and `EXTENDED_SCENARIO_IDS` in `run_all_scenarios.py:71-93`, defines the scenario objects in that file/attack modules, and reads CLI arguments. Therefore the YAML's `dry_run: false`, scenario lists, timing values, and `raw_output_dir` do not control the runner. Passing the documented `--config` argument is expected to fail argument parsing. In particular, the YAML output path `research/datasets/raw` is historical; it must not be used for a new pilot.

The YAML omits `solarwinds-001`, lists only two attack entries, and labels `benign-load-001` as targeting `recommendationservice`. The active runner/manifest defines `solarwinds-001` and targets `benign-load-001` to `emailservice`.

## Active runner profile (planned, not executed)

The runner's default `--campaign pilot` selects six IDs with default `--repetitions 3`: 18 planned runs, in namespace `phantom-eval` unless overridden. Successful-run output defaults to `research/datasets/pilot_batch01/<run_id>.json` plus `index.json`; the runner's live path also writes oracle YAML under `research/evaluation/oracles/`. `research/datasets/pilot_batch01` and `research/evaluation/oracles` were absent at the prior filesystem check, while historical `research/datasets/raw` and `raw3` exist and must remain untouched.

| Planned class | Scenario ID | Manifest target | Repetitions |
|---|---|---|---:|
| Attack | `xzutils-001` | `recommendationservice` | 3 |
| Attack | `dep-confusion-001` | `emailservice` | 3 |
| Attack | `solarwinds-001` | `cartservice` | 3 |
| Control | `benign-update-001` | `recommendationservice` | 3 |
| Control | `benign-load-001` | `emailservice` | 3 |
| Control | `benign-restart-001` | `cartservice` | 3 |

Scenario manifests are Python `AttackManifest` constants/classes, not YAML oracle files in this checkout. The referenced `research/evaluation/oracles/` directory is absent. Attack metadata assigns expected labels, but actual injection and behavior status must remain separately verified.

## Pilot blockers in the active runner

1. **Controls are no-ops.** `run_all_scenarios.py:140-173` implements `_BenignNoOp.inject()` and `.recover()` as log-only functions. `_make_benign_scenarios()` returns that class for benign update, high-load, and pod restart. Thus the planned control IDs do not currently perform the documented dependency update, k6 load, or pod restart. A planned run count of nine controls is not evidence that controls occurred. Pilot execution is blocked until control behavior and independent completion checks are implemented and reviewed.
2. **Potential overwrite of evidence.** Live execution calls `output_dir.mkdir(..., exist_ok=True)` and writes JSON/index files with mode `w`; the deterministic `FAILED_<scenario>_rep<n>.json` IDs can collide on a later batch. `AttackManifest.save_oracle()` also opens existing `<id>.yaml` files with mode `w`. There is no preflight refusing a non-empty output directory or existing oracle file. Use a unique empty batch directory and add fail-closed overwrite protection before any future execution.
3. **Dry-run not verified in this environment.** Source inspection shows `SafetyPreflight.validate()` is configuration-only in dry-run, then `_print_dry_run_plan()` prints the matrix and exits before output-directory creation or live operations. However, the command previously stopped at import with `ModuleNotFoundError: httpx`, so no plan was generated here. Do not treat the source inspection as a successful dry-run.
4. **The current Python environment cannot run the runner or tests.** Python 3.10.12 is present; project metadata requires Python 3.11+. `httpx` and pytest are unavailable.

## Recommended single source of truth and compatibility

For the least disruptive correction, keep the existing active Python runner and its attack manifests as the sole executable source of pilot membership, workload targets, repetitions default, namespace default, and output default. Preserve the YAML's current values as an archival/non-operative configuration snapshot and correct its header so it no longer advertises an unsupported `--config` interface. Derive target workload labels from each manifest rather than duplicating them as separate tuple strings. This avoids silently changing scenario behavior and preserves historical configuration content/keys. Existing CLI options (`--campaign`, `--scenarios`, `--namespace`, `--repetitions`, `--output-dir`) remain backward-compatible.

Before a later pilot, separately review implementations and tests for all three benign controls, fail-closed output/oracle overwrite checks, and the exact dry-run output. This audit proposes no attack/control implementation changes and initiates no execution.
