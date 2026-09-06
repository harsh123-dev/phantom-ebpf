import argparse
import logging
import sys
from pathlib import Path

# Add repo root to path
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack
from research.evaluation.scenarios.run_all_scenarios import _get_pod_name

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
log = logging.getLogger("demo_runner")

def main():
    parser = argparse.ArgumentParser(description="Quickly inject an attack for a live demo.")
    parser.add_argument(
        "--attack", 
        choices=["dep-confusion", "xzutils"], 
        required=True,
        help="Which attack to inject."
    )
    parser.add_argument(
        "--namespace", 
        default="phantom-eval",
        help="Kubernetes namespace where demo app runs."
    )
    args = parser.parse_args()

    try:
        if args.attack == "dep-confusion":
            log.info("Starting Dependency Confusion Attack Demo...")
            attack = DependencyConfusionAttack(eval_namespace=args.namespace)
            app_label = "emailservice"
            
        elif args.attack == "xzutils":
            log.info("Starting XZ-Utils Backdoor Attack Demo...")
            attack = XZUtilsStyleAttack()
            app_label = "recommendationservice"

        # 1. Discover Pod
        pod_name = _get_pod_name(args.namespace, app_label, None)
        log.info(f"Discovered target pod: {pod_name}")

        # 2. Inject Attack
        log.info(f"Injecting {args.attack} into {pod_name}...")
        attack.inject(pod_name)
        log.info("Injection complete! The attack should now be running.")
        log.info("Check your PHANTOM Dashboard for live detection.")

    except Exception as e:
        log.error(f"Failed to inject demo attack: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
