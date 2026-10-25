"""
research/evaluation/scenarios/run_all_scenarios.py

Top-level orchestration script for the PHANTOM empirical evaluation.

Campaign Profiles:
  1. Pilot Campaign (default: 18 runs total):
     Attack scenarios (3 repetitions each):
       - xzutils-001:       XZ-Utils style library backdoor      (recommendationservice)
       - dep-confusion-001: Dependency confusion beacon package  (emailservice)
       - solarwinds-001:    SolarWinds-style build tampering     (cartservice)
     Benign control scenarios (3 repetitions each):
       - benign-update-001:  Benign dependency patch update      (recommendationservice)
       - benign-load-001:    Benign high-load burst              (recommendationservice)
       - benign-restart-001: Benign pod restart / reschedule     (cartservice)
     Total: 6 scenarios x 3 repetitions = 18 planned runs.

  2. Extended Campaign (27 runs total):
     Includes the 6 pilot scenarios above PLUS 3 additional variants:
       - proc-spawn-001:  Unauthorized child process spawn      (recommendationservice)
       - net-egress-001:  Unauthorized internal network connect  (cartservice)
       - file-tamper-001: Unexpected temporary file access       (recommendationservice)
     Total: 9 scenarios x 3 repetitions = 27 planned runs.

Safety contract:
  - Default execution mode is dry-run (--dry-run is True by default).
  - In dry-run mode, the script prints the precise scenario matrix, repetition count,
    planned run IDs, and destination directory. No kubectl calls are made, no sinks
    are contacted, and zero experiment records are written to disk.
  - To execute live against a disposable lab cluster, the user MUST pass --execute
    along with an approved disposable kubectl context.
  - New genuine experimental records are saved to research/datasets/pilot_batch01/<run_id>.json.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

# ---------------------------------------------------------------------------
# Path setup: allow running from repo root without pip install.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.file_tamper_style import FileTamperAttack
from research.evaluation.attacks.net_egress_style import NetEgressAttack
from research.evaluation.attacks.proc_spawn_style import ProcSpawnAttack
from research.evaluation.attacks.safety import SafetyCheckError, SafetyPreflight
from research.evaluation.attacks.solarwinds_style import SolarWindsStyleAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack
from research.evaluation.scenarios.scenario_runner import ScenarioResult, ScenarioRunner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Campaign scenario sets
# ---------------------------------------------------------------------------

PILOT_SCENARIO_IDS: Final[tuple[str, ...]] = (
    "xzutils-001",
    "dep-confusion-001",
    "solarwinds-001",
    "benign-update-001",
    "benign-load-001",
    "benign-restart-001",
)

EXTENDED_SCENARIO_IDS: Final[tuple[str, ...]] = (
    "xzutils-001",
    "dep-confusion-001",
    "solarwinds-001",
    "proc-spawn-001",
    "net-egress-001",
    "file-tamper-001",
    "benign-update-001",
    "benign-load-001",
    "benign-restart-001",
)

# Default destination for new experimental runs (preserves historical raw/ and raw3/)
DEFAULT_PILOT_DIR: Path = _REPO_ROOT / "research" / "datasets" / "pilot_batch01"

# ---------------------------------------------------------------------------
# Pod name discovery helpers
# ---------------------------------------------------------------------------


def _get_pod_name(namespace: str, app_label: str, kubectl_context: str | None) -> str:
    """Discover the first Running pod for a given app label.

    Args:
        namespace: Kubernetes namespace.
        app_label: Value of the 'app' label (e.g. 'recommendationservice').
        kubectl_context: kubectl context or None for current context.

    Returns:
        Pod name string.

    Raises:
        RuntimeError: If no Running pod is found.
    """
    cmd = ["kubectl"]
    if kubectl_context:
        cmd += ["--context", kubectl_context]
    cmd += [
        "get", "pods",
        "-n", namespace,
        "-l", f"app={app_label}",
        "--field-selector", "status.phase=Running",
        "-o", "jsonpath={.items[0].metadata.name}",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=15, check=False
    )
    pod = result.stdout.strip()
    if not pod:
        raise RuntimeError(
            f"No running pod found for app={app_label} in namespace={namespace}"
        )
    return pod


# ---------------------------------------------------------------------------
# Benign scenario stubs
# ---------------------------------------------------------------------------


class _BenignNoOp(BaseAttack):
    """Stub attack that does nothing (for benign control scenarios).

    Args:
        manifest: The AttackManifest for this benign scenario.
        kubectl_context: kubectl context name.
        dry_run: If True, skip subprocess calls.
        allow_live_execution: Confirmation flag.
    """

    def __init__(
        self,
        manifest: AttackManifest,
        kubectl_context: str | None = None,
        dry_run: bool = True,
        allow_live_execution: bool = False,
    ) -> None:
        super().__init__(
            kubectl_context=kubectl_context,
            dry_run=dry_run,
            allow_live_execution=allow_live_execution,
        )
        self.manifest = manifest

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        log.info("benign.inject.noop", extra={"scenario": self.manifest.attack_id})
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        return True

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        log.info("benign.recover.noop", extra={"scenario": self.manifest.attack_id})
        return True


def _make_benign_scenarios(
    kubectl_context: str | None,
    dry_run: bool = True,
    allow_live_execution: bool = False,
) -> list[_BenignNoOp]:
    """Build the three benign control scenario stubs.

    Args:
        kubectl_context: kubectl context.
        dry_run: If True, skip subprocess calls.
        allow_live_execution: Live execution opt-in flag.

    Returns:
        List of three _BenignNoOp instances.
    """
    benign_update = AttackManifest(
        attack_id="benign-update-001",
        attack_family="benign_update",
        target_service="recommendationservice",
        target_image="gcr.io/google-samples/microservices-demo/recommendationservice:latest",
        target_component_purl="pkg:pypi/lzmaffi@1.0.1",
        clean_component_purl="pkg:pypi/lzmaffi@1.0.0",
        injection_time_offset_s=0.0,
        expected_behavioral_changes=[],
        ground_truth_label=0,
        control_endpoint="",
        recovery_steps=["No recovery needed (benign update)."],
        detection_window_s=120.0,
        repetitions=3,
        notes="Handoff §2 benign control: hash-pinned patch update.",
    )

    high_load = AttackManifest(
        attack_id="benign-load-001",
        attack_family="high_load",
        target_service="emailservice",
        target_image="gcr.io/google-samples/microservices-demo/emailservice:latest",
        target_component_purl="",
        clean_component_purl="",
        injection_time_offset_s=0.0,
        expected_behavioral_changes=[],
        ground_truth_label=0,
        control_endpoint="",
        recovery_steps=["Stop k6 load generator."],
        detection_window_s=120.0,
        repetitions=3,
        notes=(
            "Handoff §2 benign control: k6 high-load burst against emailservice. "
            "No image/package/network changes; stable transition probabilities expected."
        ),
    )

    pod_restart = AttackManifest(
        attack_id="benign-restart-001",
        attack_family="pod_restart",
        target_service="cartservice",
        target_image="",
        target_component_purl="",
        clean_component_purl="",
        injection_time_offset_s=0.0,
        expected_behavioral_changes=[],
        ground_truth_label=0,
        control_endpoint="",
        recovery_steps=["Deployments self-heal; verify Pod ready."],
        detection_window_s=120.0,
        repetitions=3,
        notes=(
            "Handoff §2 benign control: pod delete + reschedule for "
            "cartservice and emailservice. Same images; contracts unchanged."
        ),
    )

    return [
        _BenignNoOp(benign_update, kubectl_context=kubectl_context, dry_run=dry_run, allow_live_execution=allow_live_execution),
        _BenignNoOp(high_load, kubectl_context=kubectl_context, dry_run=dry_run, allow_live_execution=allow_live_execution),
        _BenignNoOp(pod_restart, kubectl_context=kubectl_context, dry_run=dry_run, allow_live_execution=allow_live_execution),
    ]


# ---------------------------------------------------------------------------
# Dry-run execution plan printer
# ---------------------------------------------------------------------------


def _print_dry_run_plan(
    campaign: str,
    namespace: str,
    context: str | None,
    output_dir: Path,
    repetitions: int,
    selected_scenarios: list[tuple[BaseAttack, str]],
) -> None:
    """Print the complete dry-run scenario execution matrix without mutating state."""
    total_runs = len(selected_scenarios) * repetitions
    sep = "=" * 115
    sub_sep = "-" * 115

    print("\n" + sep)
    print("PHANTOM Controlled Evaluation — Dry-Run Execution Plan")
    print(sep)
    print(f"Mode:                  DRY-RUN (Safe Planning Mode — No Cluster Execution)")
    print(f"Campaign Profile:      {campaign.upper()} ({len(selected_scenarios)} scenarios x {repetitions} reps = {total_runs} planned runs)")
    print(f"Target Namespace:      {namespace}")
    print(f"Kubectl Context:       {context or '(default/current)'}")
    print(f"Destination Dataset:   {output_dir}")
    print(f"Safety Verification:   No kubectl target calls made; No network sinks contacted; Zero records written to disk.")
    print(sub_sep)
    print(f"{'Seq':<4} {'Scenario ID':<22} {'Rep':>3} {'Label':>5} {'Target Workload':<24} {'Control / Sink Endpoint':<38} {'Win(s)':>6}")
    print(sub_sep)

    seq = 1
    planned_run_ids: list[str] = []
    now_tag = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    for attack, _ in selected_scenarios:
        for rep in range(1, repetitions + 1):
            run_id = f"PLAN_{now_tag}_{attack.manifest.attack_id}_rep{rep}"
            planned_run_ids.append(run_id)
            endpoint_str = attack.manifest.control_endpoint or "(None - Benign control)"
            print(
                f"{seq:<4} {attack.manifest.attack_id:<22} {rep:>3} {attack.manifest.ground_truth_label:>5} "
                f"{attack.manifest.target_service:<24} {endpoint_str:<38} {attack.manifest.detection_window_s:>5.0f}s"
            )
            seq += 1

    print(sub_sep)
    print(f"\nTotal Planned Run IDs ({len(planned_run_ids)} total):")
    for r_id in planned_run_ids:
        print(f"  - {r_id}")

    print("\nDecoupled Ground-Truth Tracking:")
    print("  - Dimensions: [inject_ok, behavior_verified, contract_drift_verified, phantom_alerted]")
    print("  - Invariant:  PHANTOM alerts are strictly evaluated as detector outputs, NEVER as ground truth.")
    print("  - Denominator: Runs where inject_ok=False are excluded from TPR sensitivity metrics.")

    print("\nExecution Instructions:")
    print("  To launch these runs in live mode against a verified disposable lab cluster, supply:")
    print(f"    python research/evaluation/scenarios/run_all_scenarios.py \\\n"
          f"        --campaign {campaign} \\\n"
          f"        --namespace {namespace} \\\n"
          f"        --kubectl-context <approved-disposable-context> \\\n"
          f"        --output-dir {output_dir} \\\n"
          f"        --repetitions {repetitions} \\\n"
          f"        --execute")
    print(sep + "\n")


# ---------------------------------------------------------------------------
# Summary table printer
# ---------------------------------------------------------------------------


def _print_summary(results: list[ScenarioResult]) -> None:
    """Print a formatted summary table of all scenario results to stdout.

    Args:
        results: List of ScenarioResult objects.
    """
    header = (
        f"{'Run ID':<50} {'Attack ID':<22} {'Rep':>3} "
        f"{'Label':>5} {'TP':>4} {'MTTD(s)':>10} {'#Detect':>8} "
        f"{'#Falco':>7} {'Error':<40}"
    )
    sep = "-" * len(header)
    print("\n" + sep)
    print("PHANTOM Evaluation — Scenario Summary")
    print(sep)
    print(header)
    print(sep)

    for r in results:
        mttd = f"{r.mttd_s:.1f}" if r.mttd_s is not None else "—"
        if r.is_true_positive:
            tp = "TP"
        elif r.ground_truth_label == 0 and r.phantom_detections:
            tp = "FP"
        elif r.ground_truth_label == 0:
            tp = "TN"
        else:
            tp = "FN"
        error_short = r.error[:38] if r.error else ""
        print(
            f"{r.run_id:<50} {r.attack_id:<22} {r.repetition:>3} "
            f"{r.ground_truth_label:>5} {tp:>4} {mttd:>10} "
            f"{len(r.phantom_detections):>8} {len(r.falco_detections):>7} "
            f"{error_short:<40}"
        )

    print(sep)

    from collections import defaultdict
    by_family: dict[str, list[ScenarioResult]] = defaultdict(list)
    for r in results:
        by_family[r.attack_family].append(r)

    print("\nAggregate by attack family:")
    for family, fam_results in sorted(by_family.items()):
        n_attack = sum(1 for r in fam_results if r.ground_truth_label == 1)
        n_benign = sum(1 for r in fam_results if r.ground_truth_label == 0)
        n_tp = sum(1 for r in fam_results if r.is_true_positive)
        n_fp = sum(
            1 for r in fam_results
            if r.ground_truth_label == 0 and r.phantom_detections
        )
        mttd_vals = [r.mttd_s for r in fam_results if r.mttd_s is not None]
        mean_mttd = sum(mttd_vals) / len(mttd_vals) if mttd_vals else None
        print(
            f"  {family:<28} attacks={n_attack} benign={n_benign} "
            f"TP={n_tp} FP={n_fp} "
            f"mean_MTTD={'%.1f' % mean_mttd if mean_mttd is not None else '—'}s"
        )
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for evaluation scenario runs."""
    parser = argparse.ArgumentParser(
        description="Run PHANTOM evaluation scenarios (safe dry-run by default)."
    )
    parser.add_argument(
        "--campaign", choices=["pilot", "extended", "all"], default="pilot",
        help="Campaign profile: 'pilot' (18 runs: 3 original attacks + 3 benign controls x 3 reps) "
             "or 'extended'/'all' (27 runs: 6 attacks + 3 benign controls x 3 reps). Default: 'pilot'.",
    )
    parser.add_argument(
        "--scenarios", default=None,
        help="Optional comma-separated list of scenario IDs to run (e.g. 'xzutils-001,benign-update-001'). "
             "Overrides --campaign if specified.",
    )
    parser.add_argument(
        "--namespace", default="phantom-eval",
        help="Kubernetes namespace for all attack targets.",
    )
    parser.add_argument(
        "--kubectl-context", default=None,
        help="kubectl context name (must be a positively verified disposable lab cluster in live mode).",
    )
    parser.add_argument(
        "--baseline-duration", type=int, default=300,
        help="Baseline phase duration in seconds.",
    )
    parser.add_argument(
        "--attack-duration", type=int, default=300,
        help="Attack observation phase duration in seconds.",
    )
    parser.add_argument(
        "--recovery-duration", type=int, default=120,
        help="Post-recovery phase duration in seconds.",
    )
    parser.add_argument(
        "--phantom-api", default="http://localhost:8080",
        help="PHANTOM API Gateway base URL.",
    )
    parser.add_argument(
        "--prometheus",
        default="http://localhost:9090/api/v1/query",
        help="Prometheus query API URL.",
    )
    parser.add_argument(
        "--falco-log",
        default="/var/log/falco/events.jsonl",
        help="Path to Falco JSON-lines alert log.",
    )
    parser.add_argument(
        "--token", default="",
        help="PHANTOM API bearer token.",
    )
    parser.add_argument(
        "--dry-run", action="store_true", default=None,
        help="Explicitly force dry-run mode (default behavior).",
    )
    parser.add_argument(
        "--execute", action="store_true", default=False,
        help="Explicit confirmation required to allow live execution against the cluster.",
    )
    parser.add_argument(
        "--repetitions", type=int, default=3,
        help="Number of repetitions per scenario.",
    )
    parser.add_argument(
        "--output-dir", default=str(DEFAULT_PILOT_DIR),
        help=f"Directory to save raw ScenarioResult JSON files (default: {DEFAULT_PILOT_DIR}).",
    )

    args = parser.parse_args()

    # Determine execution mode safely:
    # If --execute is supplied and --dry-run is not explicitly requested, allow live execution.
    if args.execute and args.dry_run is not True:
        dry_run = False
        allow_live_execution = True
    else:
        dry_run = True
        allow_live_execution = False

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    output_dir = Path(args.output_dir)

    # ------------------------------------------------------------------ #
    # Build complete scenario catalog                                    #
    # ------------------------------------------------------------------ #
    attack_scenarios: list[tuple[BaseAttack, str]] = [
        (
            XZUtilsStyleAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
            ),
            "recommendationservice",
        ),
        (
            DependencyConfusionAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
                eval_namespace=args.namespace,
            ),
            "emailservice",
        ),
        (
            SolarWindsStyleAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
                build_attack_image=False,
                target_namespace=args.namespace,
            ),
            "cartservice",
        ),
        (
            ProcSpawnAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
            ),
            "recommendationservice",
        ),
        (
            NetEgressAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
            ),
            "cartservice",
        ),
        (
            FileTamperAttack(
                kubectl_context=args.kubectl_context,
                dry_run=dry_run,
                allow_live_execution=allow_live_execution,
            ),
            "recommendationservice",
        ),
    ]

    benign_scenarios: list[tuple[_BenignNoOp, str]] = [
        (s, s.manifest.target_service or "recommendationservice")
        for s in _make_benign_scenarios(
            args.kubectl_context,
            dry_run=dry_run,
            allow_live_execution=allow_live_execution,
        )
    ]

    all_scenarios: list[tuple[BaseAttack, str]] = attack_scenarios + benign_scenarios

    # ------------------------------------------------------------------ #
    # Filter scenarios based on campaign or explicit selection           #
    # ------------------------------------------------------------------ #
    if args.scenarios:
        selected_ids = set(s.strip() for s in args.scenarios.split(",") if s.strip())
        campaign_label = f"custom ({len(selected_ids)} scenarios)"
    elif args.campaign == "pilot":
        selected_ids = set(PILOT_SCENARIO_IDS)
        campaign_label = "pilot"
    else:
        selected_ids = set(EXTENDED_SCENARIO_IDS)
        campaign_label = "extended"

    selected_scenarios = [
        (attack, app_label)
        for attack, app_label in all_scenarios
        if attack.manifest.attack_id in selected_ids
    ]

    # Validate that all requested scenarios were located
    found_ids = {a.manifest.attack_id for a, _ in selected_scenarios}
    missing_ids = selected_ids - found_ids
    if missing_ids:
        log.error("run.missing_scenarios", extra={"missing": sorted(missing_ids)})
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Preflight safety check across all selected scenarios              #
    # ------------------------------------------------------------------ #
    for attack, _ in selected_scenarios:
        SafetyPreflight.validate(
            namespace=args.namespace,
            service=getattr(attack.manifest, "target_service", None),
            endpoint=getattr(attack.manifest, "control_endpoint", None),
            context=args.kubectl_context,
            dry_run=dry_run,
            allow_live_execution=allow_live_execution,
            scenario_id=getattr(attack.manifest, "attack_id", None),
        )

    # ------------------------------------------------------------------ #
    # Dry-run handling: Print execution plan and exit safely             #
    # ------------------------------------------------------------------ #
    if dry_run:
        _print_dry_run_plan(
            campaign=campaign_label,
            namespace=args.namespace,
            context=args.kubectl_context,
            output_dir=output_dir,
            repetitions=args.repetitions,
            selected_scenarios=selected_scenarios,
        )
        log.info("SAFETY: Dry-run planning complete. Zero live operations executed. Zero dataset files written.")
        sys.exit(0)

    # ------------------------------------------------------------------ #
    # Live execution mode (--execute provided)                           #
    # ------------------------------------------------------------------ #
    log.warning("SAFETY: Live execution confirmed via --execute. Proceeding with cluster operations.")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save oracle manifests before running
    for attack, _ in selected_scenarios:
        oracle_path = attack.manifest.save_oracle()
        log.info("oracle.saved", extra={"path": str(oracle_path)})

    runner = ScenarioRunner(
        phantom_api_base_url=args.phantom_api,
        prometheus_url=args.prometheus,
        falco_log_path=args.falco_log,
        api_token=args.token,
        dry_run=False,
        allow_live_execution=True,
    )

    all_results: list[ScenarioResult] = []

    for attack, app_label in selected_scenarios:
        log.info(
            "run.scenario_start",
            extra={"attack_id": attack.manifest.attack_id, "repetitions": args.repetitions},
        )
        for rep in range(1, args.repetitions + 1):
            try:
                pod_name = _get_pod_name(
                    namespace=args.namespace,
                    app_label=app_label,
                    kubectl_context=args.kubectl_context,
                )
            except RuntimeError as exc:
                log.error(
                    "run.pod_discovery_failed",
                    extra={"app": app_label, "error": str(exc)},
                )
                result = ScenarioResult(
                    run_id=f"FAILED_{attack.manifest.attack_id}_rep{rep}",
                    attack_id=attack.manifest.attack_id,
                    attack_family=attack.manifest.attack_family,
                    repetition=rep,
                    namespace=args.namespace,
                    pod_name="",
                    ground_truth_label=attack.manifest.ground_truth_label,
                    error=str(exc),
                    scenario_label=attack.label(),
                )
                all_results.append(result)
                continue

            log.info(
                "run.rep_start",
                extra={
                    "attack_id": attack.manifest.attack_id,
                    "rep": rep,
                    "pod": pod_name,
                },
            )

            try:
                result = runner.run_scenario(
                    attack=attack,
                    namespace=args.namespace,
                    pod_name=pod_name,
                    repetition=rep,
                    baseline_duration_s=args.baseline_duration,
                    attack_duration_s=args.attack_duration,
                    recovery_duration_s=args.recovery_duration,
                )
            except Exception as exc:
                log.error(
                    "scenario.failed",
                    extra={
                        "attack_id": attack.manifest.attack_id,
                        "rep": rep,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                )
                result = ScenarioResult(
                    run_id=f"FAILED_{attack.manifest.attack_id}_rep{rep}",
                    attack_id=attack.manifest.attack_id,
                    attack_family=attack.manifest.attack_family,
                    repetition=rep,
                    namespace=args.namespace,
                    pod_name=pod_name,
                    ground_truth_label=attack.manifest.ground_truth_label,
                    error=str(exc),
                    scenario_label=attack.label(),
                )

            all_results.append(result)

            out_path = output_dir / f"{result.run_id}.json"
            with out_path.open("w") as fh:
                json.dump(result.to_dict(), fh, indent=2, default=str)
            log.info("result.saved", extra={"path": str(out_path)})

            if rep < args.repetitions:
                log.info("run.inter_rep_pause")
                time.sleep(30)

    # ------------------------------------------------------------------ #
    # Summary table and run index                                        #
    # ------------------------------------------------------------------ #
    _print_summary(all_results)

    index = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "campaign": campaign_label,
        "repetitions": args.repetitions,
        "namespace": args.namespace,
        "context": args.kubectl_context,
        "results": [r.run_id for r in all_results],
    }
    index_path = output_dir / "index.json"
    with index_path.open("w") as fh:
        json.dump(index, fh, indent=2)
    log.info("index.saved", extra={"path": str(index_path)})

    successful = [r for r in all_results if not r.error]
    errors = [r for r in all_results if r.error and r.ground_truth_label == 1]
    log.info(
        "run.completed",
        extra={"total": len(all_results), "successful": len(successful), "errors": len(errors)},
    )
    if successful:
        log.info("run.complete")
        sys.exit(0)
    else:
        log.error("run.all_scenarios_failed", extra={"n_errors": len(errors)})
        sys.exit(1)


if __name__ == "__main__":
    main()
