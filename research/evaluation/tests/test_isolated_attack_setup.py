"""Safety tests for registry isolation and clean scenario recovery."""

import subprocess
import unittest

from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack


class IsolatedAttackSetupTests(unittest.TestCase):
    def test_dependency_confusion_uses_only_the_internal_index(self):
        command = DependencyConfusionAttack._local_index_install_command(
            "pypiserver-mirror.phantom-eval.svc.cluster.local:8080"
        )
        self.assertIn("--index-url", command)
        self.assertIn(
            "http://pypiserver-mirror.phantom-eval.svc.cluster.local:8080/simple/",
            command,
        )
        self.assertNotIn("--extra-index-url", command)
        self.assertFalse(any("pypi.org" in part for part in command))
        self.assertIn("--no-deps", command)

    def test_xz_recovery_replaces_the_pod_without_package_downloads(self):
        attack = XZUtilsStyleAttack(dry_run=False, allow_live_execution=True)
        attack.validate_safety = lambda _namespace: None
        commands = []

        def fake_kubectl(args, timeout=30):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, "pod ready", "")

        attack._kubectl = fake_kubectl
        self.assertTrue(attack.recover("phantom-eval", "recommendationservice-old"))
        self.assertEqual(commands[0][:3], ["delete", "pod", "recommendationservice-old"])
        self.assertEqual(commands[1][0], "wait")
        self.assertFalse(any("pip" in arg for command in commands for arg in command))


if __name__ == "__main__":
    unittest.main()
