"""
research/evaluation/attacks/proc_spawn_style.py

Unauthorized Child Process Spawn Scenario (proc-spawn-001).

Specification:
    Target workload:   recommendationservice (Python)
    Clean component:   pkg:generic/recommendationservice@latest
    Attack component:  pkg:generic/recommendationservice@latest+unauthorized-exec
    Beacon sink:       phantom-sink.phantom-eval.svc.cluster.local:8080
    Detection window:  120 seconds
    Expected eBPF evidence:
        - PHANTOM_EVT_EXEC: unexpected process spawn (/tmp/.phantom_proc_worker.sh / sleep)

Objective:
    Test PHANTOM's ability to detect runtime behavioral drift caused by an
    unauthorized child process execution in a container where the process contract
    strictly defines allowable binaries (e.g. only python recommendation_server.py).
    No SBOM or package substitutions are performed.

Safety constraints:
    - Default mode is dry_run=True.
    - SafetyPreflight gates validate namespace and service before execution.
    - Child process is inert (sleeps only; no network access or privilege escalation).
    - Recovery reliably kills the spawned child and removes the worker script.
"""

from __future__ import annotations

import logging
import subprocess
import textwrap
from pathlib import Path

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.safety import SafetyPreflight

log = logging.getLogger(__name__)

_WORKER_SCRIPT_PATH = "/tmp/.phantom_proc_worker.sh"
_WORKER_SCRIPT = textwrap.dedent("""\
    #!/bin/sh
    # phantom_proc_worker.sh — safe inert child process for PHANTOM evaluation
    exec sleep 300
""")

PROC_SPAWN_MANIFEST = AttackManifest(
    attack_id="proc-spawn-001",
    attack_family="unauthorized_process",
    target_service="recommendationservice",
    target_image="gcr.io/google-samples/microservices-demo/recommendationservice:latest",
    target_component_purl="pkg:generic/recommendationservice@latest+unauthorized-exec",
    clean_component_purl="pkg:generic/recommendationservice@latest",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_process_spawn",
    ],
    ground_truth_label=1,
    control_endpoint="phantom-sink.phantom-eval.svc.cluster.local:8080",
    recovery_steps=[
        f"pkill -f {_WORKER_SCRIPT_PATH} (inside pod)",
        f"rm -f {_WORKER_SCRIPT_PATH} (inside pod)",
        "Verify process tree restored to clean server state",
    ],
    detection_window_s=120.0,
    repetitions=3,
    notes=(
        "Child process spawn anomaly scenario. "
        "Tests contract rule violation for unauthorized binary execution without package changes."
    ),
)


class ProcSpawnAttack(BaseAttack):
    """Unauthorized child process spawn attack for PHANTOM evaluation.

    Spawns an unauthorized inert child process inside recommendationservice.

    Args:
        kubectl_context: kubectl context name.
        dry_run: If True, log commands without executing (default: True).
        allow_live_execution: Explicit confirmation flag required to exit dry-run mode.
    """

    manifest: AttackManifest = PROC_SPAWN_MANIFEST

    def __init__(
        self,
        kubectl_context: str | None = None,
        dry_run: bool = True,
        allow_live_execution: bool = False,
    ) -> None:
        super().__init__(
            kubectl_context=kubectl_context,
            dry_run=dry_run,
            allow_live_execution=allow_live_execution,
        )

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """Write inert worker script and fork it in the target pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if injection succeeded.
        """
        self.validate_safety(target_namespace)

        log.info(
            "proc_spawn.inject.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("proc_spawn.inject.dry_run_complete")
            return True

        # 1. Write worker script
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"cat << 'EOF' > {_WORKER_SCRIPT_PATH}\n{_WORKER_SCRIPT}\nEOF"],
            timeout=15,
        )
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["chmod", "+x", _WORKER_SCRIPT_PATH],
            timeout=10,
        )

        # 2. Fork the worker script into background
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"nohup {_WORKER_SCRIPT_PATH} >/dev/null 2>&1 &"],
            timeout=15,
        )
        log.info("proc_spawn.inject.worker_spawned")
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify the worker process is running in the pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if worker process is running (or True in dry_run).
        """
        self.validate_safety(target_namespace)

        if self.dry_run:
            log.info("proc_spawn.verify.dry_run_ok")
            return True

        try:
            out = self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pgrep", "-f", _WORKER_SCRIPT_PATH],
                timeout=10,
            )
            return bool(out.strip())
        except subprocess.CalledProcessError:
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Kill the worker process and delete the worker script.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if recovery completed.
        """
        self.validate_safety(target_namespace)

        log.info(
            "proc_spawn.recover.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("proc_spawn.recover.dry_run_complete")
            return True

        ok = True
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pkill", "-f", _WORKER_SCRIPT_PATH],
                timeout=10,
            )
        except subprocess.CalledProcessError:
            pass

        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["rm", "-f", _WORKER_SCRIPT_PATH],
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("proc_spawn.recover.rm_failed", extra={"error": str(exc)})
            ok = False

        log.info("proc_spawn.recover.complete", extra={"ok": ok})
        return ok
