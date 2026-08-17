"""
research/evaluation/scenarios/run_all_scenarios.py

Top-level orchestration script for the PHANTOM evaluation.

Runs:
  Attack scenarios (3 repetitions each):
    1. XZ-Utils style library backdoor      (recommendationservice)
    2. Dependency confusion beacon package  (emailservice)
    3. SolarWinds-style build tampering     (cartservice)

  Benign control scenarios (3 repetitions each):
    4. Benign dependency patch update       (should NOT trigger PHANTOM)
    5. Benign high-load burst               (should NOT trigger PHANTOM)
    6. Benign pod restart / reschedule      (should NOT trigger PHANTOM)

Each ScenarioResult is saved as JSON to:
    research/datasets/raw/<run_id>.json

A summary table is printed to stdout at the end.

Usage:
    python research/evaluation/scenarios/run_all_scenarios.py \\
        [--namespace phantom-eval] \\
        [--baseline-duration 300] \\
        [--attack-duration 300] \\
        [--recovery-duration 120] \\
        [--phantom-api http://localhost:8080] \\
        [--prometheus http://localhost:9090/api/v1/query] \\
        [--falco-log /var/log/falco/events.jsonl] \\
        [--token <bearer_token>] \\
        [--dry-run]

The --dry-run flag skips all kubectl/subprocess calls but exercises the
full orchestration logic. Useful for CI and local development.
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
from typing import Any

# ---------------------------------------------------------------------------
# Path setup: allow running from repo root without pip install.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.solarwinds_style import SolarWindsStyleAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack
from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.scenarios.scenario_runner import ScenarioRunner, ScenarioResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataset output directory
# ---------------------------------------------------------------------------

RAW_DIR: Path = _REPO_ROOT / "research" / "datasets" / "raw"

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
#
# Benign scenarios do NOT inject an attack; they exercise the same
# ScenarioRunner pipeline with an "attack" that does nothing. This verifies
# PHANTOM does not produce false positives during ordinary maintenance events.


class _BenignNoOp(BaseAttack):
    """Stub attack that does nothing (for benign control scenarios).

    Args:
        manifest: The AttackManifest for this benign scenario.
        kubectl_context: kubectl context name.
        dry_run: If True, skip subprocess calls.
    """

    def __init__(
        self,
        manifest: AttackManifest,
        kubectl_context: str | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialise the no-op benign stub.

        Args:
            manifest: AttackManifest for this benign scenario.
            kubectl_context: kubectl context name.
            dry_run: If True, skip subprocess calls.
        """
        super().__init__(kubectl_context=kubectl_context, dry_run=dry_run)
        self.manifest = manifest

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """No-op inject for benign scenarios.

        Args:
            target_namespace: Namespace (unused).
            pod_name: Pod name (unused).

        Returns:
            Always True.
        """
        log.info("benign.inject.noop", extra={"scenario": self.manifest.attack_id})
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """No-op verify for benign scenarios.

        Args:
            target_namespace: Namespace (unused).
            pod_name: Pod name (unused).

        Returns:
            Always True.
        """
        return True

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """No-op recover for benign scenarios.

        Args:
            target_namespace: Namespace (unused).
            pod_name: Pod name (unused).

        Returns:
            Always True.
        """
        log.info("benign.recover.noop", extra={"scenario": self.manifest.attack_id})
        return True


def _make_benign_scenarios(kubectl_context: str | None, dry_run: bool) -> list[_BenignNoOp]:
    """Build the three benign control scenario stubs.

    Benign scenarios from handoff §2:
        - benign_update:  Dependency patch update for recommendationservice.
        - high_load:      k6 high-load burst (no image/package changes).
        - pod_restart:    Pod deletion and reschedule for cart/email services.

    Args:
        kubectl_context: kubectl context.
        dry_run: If True, skip subprocess calls.

    Returns:
        List of three _BenignNoOp instances.
    """
    benign_update = AttackManifest(
        attack_id="benign-update-001",
        attack_family="benign_update",
        target_service="recommendationservice",
        target_image="gcr.io/google-samples/microservices-demo/recommendationservice:latest",
        target_component_purl="pkg:pypi/lzmaffi@1.0.1",     # legitimate patch
        clean_component_purl="pkg:pypi/lzmaffi@1.0.0",
        injection_time_offset_s=0.0,
        expected_behavioral_changes=[],          # none expected
        ground_truth_label=0,                    # benign
        control_endpoint="",
        recovery_steps=["No recovery needed (benign update)."],
        detection_window_s=120.0,
        repetitions=3,
        notes="Handoff §2 benign control: hash-pinned patch update.",
    )

    high_load = AttackManifest(
        attack_id="benign-load-001",
        attack_family="high_load",
        target_service="recommendationservice",
        target_image="",
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
            "Handoff §2 benign control: k6 high-load burst. "
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
        _BenignNoOp(benign_update, kubectl_context=kubectl_context, dry_run=dry_run),
        _BenignNoOp(high_load, kubectl_context=kubectl_context, dry_run=dry_run),
        _BenignNoOp(pod_restart, kubectl_context=kubectl_context, dry_run=dry_run),
    ]


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
            tp = "FP"   # benign scenario, but PHANTOM fired (false alarm)
        elif r.ground_truth_label == 0:
            tp = "TN"   # benign scenario, no detection (correct)
        else:
            tp = "FN"   # attack scenario, no detection within window
        error_short = r.error[:38] if r.error else ""
        print(
            f"{r.run_id:<50} {r.attack_id:<22} {r.repetition:>3} "
            f"{r.ground_truth_label:>5} {tp:>4} {mttd:>10} "
            f"{len(r.phantom_detections):>8} {len(r.falco_detections):>7} "
            f"{error_short:<40}"
        )

    print(sep)

    # Aggregate per attack family.
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
    """Entry point for the full evaluation run.

    Parses arguments, creates attack and benign scenario instances,
    runs all scenarios with the specified repetitions, saves results to
    research/datasets/raw/, and prints the summary table.
    """
    parser = argparse.ArgumentParser(
        description="Run all PHANTOM evaluation scenarios."
    )
    parser.add_argument(
        "--namespace", default="phantom-eval",
        help="Kubernetes namespace for all attack targets.",
    )
    parser.add_argument(
        "--kubectl-context", default=None,
        help="kubectl context name (default: current context).",
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
        "--phantom-api", default=PHANTOM_API_BASE_URL if 'PHANTOM_API_BASE_URL' in dir() else "http://localhost:8080",
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
        "--dry-run", action="store_true",
        help="Skip kubectl/subprocess calls; exercise orchestration only.",
    )
    parser.add_argument(
        "--repetitions", type=int, default=3,
        help="Number of repetitions per scenario.",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    # Build the runner.
    runner = ScenarioRunner(
        phantom_api_base_url=args.phantom_api,
        prometheus_url=args.prometheus,
        falco_log_path=args.falco_log,
        api_token=args.token,
        dry_run=args.dry_run,
    )

    # ------------------------------------------------------------------ #
    # Build attack instances.                                              #
    # ------------------------------------------------------------------ #
    attack_scenarios: list[tuple[BaseAttack, str]] = [
        # (attack_instance, app_label_for_pod_discovery)
        (
            XZUtilsStyleAttack(
                kubectl_context=args.kubectl_context,
                dry_run=args.dry_run,
            ),
            "recommendationservice",
        ),
        (
            DependencyConfusionAttack(
                kubectl_context=args.kubectl_context,
                dry_run=args.dry_run,
                eval_namespace=args.namespace,
            ),
            "emailservice",
        ),
        (
            SolarWindsStyleAttack(
                kubectl_context=args.kubectl_context,
                dry_run=args.dry_run,
                target_namespace=args.namespace,
            ),
            "cartservice",
        ),
    ]

    benign_scenarios: list[tuple[_BenignNoOp, str]] = [
        (s, s.manifest.target_service or "recommendationservice")
        for s in _make_benign_scenarios(args.kubectl_context, args.dry_run)
    ]

    all_scenarios: list[tuple[BaseAttack, str]] = attack_scenarios + benign_scenarios

    # ------------------------------------------------------------------ #
    # Save oracle manifests before running.                               #
    # ------------------------------------------------------------------ #
    for attack, _ in all_scenarios:
        oracle_path = attack.manifest.save_oracle()
        log.info("oracle.saved", extra={"path": str(oracle_path)})

    # ------------------------------------------------------------------ #
    # Run all scenarios.                                                   #
    # ------------------------------------------------------------------ #
    all_results: list[ScenarioResult] = []

    for attack, app_label in all_scenarios:
        log.info(
            "run.scenario_start",
            extra={"attack_id": attack.manifest.attack_id, "repetitions": args.repetitions},
        )
        for rep in range(1, args.repetitions + 1):
            # Discover the current pod name for this scenario.
            pod_name = "dry-run-pod"
            if not args.dry_run:
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
                    # Record a failed result and continue.
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

            result = runner.run_scenario(
                attack=attack,
                namespace=args.namespace,
                pod_name=pod_name,
                repetition=rep,
                baseline_duration_s=args.baseline_duration,
                attack_duration_s=args.attack_duration,
                recovery_duration_s=args.recovery_duration,
            )
            all_results.append(result)

            # Save result to disk immediately after each repetition.
            out_path = RAW_DIR / f"{result.run_id}.json"
            with out_path.open("w") as fh:
                json.dump(result.to_dict(), fh, indent=2, default=str)
            log.info("result.saved", extra={"path": str(out_path)})

            # Brief pause between repetitions to allow pod state to stabilize.
            if rep < args.repetitions:
                log.info("run.inter_rep_pause")
                time.sleep(30)

    # ------------------------------------------------------------------ #
    # Summary table.                                                       #
    # ------------------------------------------------------------------ #
    _print_summary(all_results)

    # Save an index of all result files.
    index = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "repetitions": args.repetitions,
        "namespace": args.namespace,
        "dry_run": args.dry_run,
        "results": [r.run_id for r in all_results],
    }
    index_path = RAW_DIR / "index.json"
    with index_path.open("w") as fh:
        json.dump(index, fh, indent=2)
    log.info("index.saved", extra={"path": str(index_path)})

    # Exit with non-zero if any attack scenario had an error.
    errors = [r for r in all_results if r.error and r.ground_truth_label == 1]
    if errors:
        log.error("run.completed_with_errors", extra={"n_errors": len(errors)})
        sys.exit(1)
    log.info("run.complete")


if __name__ == "__main__":
    main()
