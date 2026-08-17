"""
research/evaluation/attacks/base_attack.py

Abstract base class and ground-truth manifest for all PHANTOM evaluation
attack scenarios.

Design contract:
- Every attack is entirely self-contained: it knows how to inject,
  verify, and recover without external orchestration state.
- AttackManifest is the oracle ground-truth record used by the metric
  computation pipeline. It is written to oracles/ as YAML before the
  scenario run and is NEVER derived from PHANTOM output.
- All kubectl and subprocess calls use explicit argument lists (no
  shell=True) to prevent injection and to make argument changes auditable.
- Injection is idempotent: calling inject() twice must leave the pod
  in the same attacked state.
- Recovery is idempotent: calling recover() on a clean pod must be safe.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml  # PyYAML

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Oracle manifest path root (relative to repo root)
# ---------------------------------------------------------------------------

ORACLE_DIR: Path = Path(__file__).resolve().parents[3] / "research" / "evaluation" / "oracles"


# ---------------------------------------------------------------------------
# AttackManifest — oracle ground-truth record
# ---------------------------------------------------------------------------


@dataclass
class AttackManifest:
    """Oracle ground-truth descriptor for one attack scenario.

    This dataclass is serialized to YAML before each run and constitutes
    the independent ground-truth record against which all detector outputs
    are compared. It must never be populated from PHANTOM output.

    Attributes:
        attack_id: Unique stable identifier (e.g. 'xzutils-001').
        attack_family: Taxonomy label for the attack class.
            One of: 'supply_chain_backdoor', 'dependency_confusion',
                    'build_pipeline_tampering', 'benign_update',
                    'high_load', 'pod_restart'.
        target_service: Kubernetes Deployment/Service name (e.g.
            'recommendationservice').
        target_image: Docker image repository:tag of the attack image.
        target_component_purl: PURL of the component being substituted
            or added (e.g. 'pkg:pypi/lzmaffi@1.0.1-phantom-backdoor').
        clean_component_purl: PURL of the clean component being replaced.
        injection_time_offset_s: Seconds after scenario phase-2 start at
            which the attack becomes active. Used to compute oracle
            injection timestamps.
        expected_behavioral_changes: List of eBPF event type labels that
            PHANTOM is expected to observe. Must match eBPF event
            categories from process_events.bpf.c / network_events.bpf.c
            / file_events.bpf.c. Valid values:
            'unexpected_process_spawn', 'unexpected_network_connect',
            'unexpected_file_access', 'privilege_transition',
            'namespace_change', 'module_load'.
        ground_truth_label: 1 = attack, 0 = benign. Set at manifest
            construction; never updated after the scenario runs.
        control_endpoint: Beacon/sink endpoint (host:port or FQDN:port).
            Always localhost or cluster-internal for safety.
        recovery_steps: Ordered list of human-readable recovery actions,
            used for operator documentation and post-run verification.
        detection_window_s: Seconds after injection during which a first
            PHANTOM detection is counted as a true positive.
        repetitions: Number of trial repetitions planned.
        oracle_manifest_path: Path to the YAML oracle file (set by
            save_oracle()).
        notes: Free-form notes for the README and paper appendix.
    """

    attack_id: str
    attack_family: str
    target_service: str
    target_image: str
    target_component_purl: str
    clean_component_purl: str
    injection_time_offset_s: float
    expected_behavioral_changes: list[str]
    ground_truth_label: int          # 1 = attack, 0 = benign
    control_endpoint: str
    recovery_steps: list[str]
    detection_window_s: float = 120.0
    repetitions: int = 3
    oracle_manifest_path: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for YAML/JSON output.

        Returns:
            Dict with all manifest fields.
        """
        return {
            "attack_id": self.attack_id,
            "attack_family": self.attack_family,
            "target_service": self.target_service,
            "target_image": self.target_image,
            "target_component_purl": self.target_component_purl,
            "clean_component_purl": self.clean_component_purl,
            "injection_time_offset_s": self.injection_time_offset_s,
            "expected_behavioral_changes": self.expected_behavioral_changes,
            "ground_truth_label": self.ground_truth_label,
            "control_endpoint": self.control_endpoint,
            "recovery_steps": self.recovery_steps,
            "detection_window_s": self.detection_window_s,
            "repetitions": self.repetitions,
            "oracle_manifest_path": self.oracle_manifest_path,
            "notes": self.notes,
        }

    def save_oracle(self, out_dir: Path = ORACLE_DIR) -> Path:
        """Write the manifest to a YAML oracle file.

        The file is named ``<attack_id>.yaml`` and written to ``out_dir``.
        Sets self.oracle_manifest_path to the written path string.

        Args:
            out_dir: Directory to write the oracle YAML. Created if absent.

        Returns:
            Path to the written YAML file.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{self.attack_id}.yaml"
        self.oracle_manifest_path = str(path)
        with path.open("w") as fh:
            yaml.dump(self.to_dict(), fh, default_flow_style=False, sort_keys=True)
        log.info("oracle_manifest.saved", extra={"path": str(path)})
        return path


# ---------------------------------------------------------------------------
# BaseAttack — abstract attack implementation
# ---------------------------------------------------------------------------


class BaseAttack(ABC):
    """Abstract base class for all PHANTOM evaluation attack scenarios.

    Subclasses must set ``manifest`` as a class attribute or in ``__init__``
    and implement the three abstract methods.

    Attributes:
        manifest: AttackManifest describing this attack's oracle ground truth.
        kubectl_context: Optional kubectl context name. If None, the current
            context is used.
        dry_run: If True, log all commands without executing them.
    """

    manifest: AttackManifest

    def __init__(
        self,
        kubectl_context: str | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialise the attack runner.

        Args:
            kubectl_context: kubectl context to use. None = current context.
            dry_run: If True, print commands without executing.
        """
        self.kubectl_context = kubectl_context
        self.dry_run = dry_run

    # ------------------------------------------------------------------ #
    # Abstract interface                                                   #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """Apply the attack to the running pod.

        Implementation must be idempotent: calling inject twice leaves the
        pod in the same attacked state.

        Args:
            target_namespace: Kubernetes namespace of the target pod.
            pod_name: Name of the target pod.

        Returns:
            True if injection succeeded; False otherwise.
        """

    @abstractmethod
    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Confirm the attack is active before measurement begins.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Name of the target pod.

        Returns:
            True if the attack is confirmed active.
        """

    @abstractmethod
    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Restore the pod to its clean state.

        Implementation must be idempotent: calling recover on a clean pod
        must be safe and return True.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Name of the target pod.

        Returns:
            True if recovery succeeded.
        """

    # ------------------------------------------------------------------ #
    # Ground-truth labeling                                                #
    # ------------------------------------------------------------------ #

    def label(self) -> dict[str, Any]:
        """Return ground-truth metadata for dataset packaging.

        This is the dict written to ``labels.parquet`` for this scenario.
        It is derived entirely from the manifest; it never reflects
        PHANTOM output.

        Returns:
            Dict matching the labels.parquet schema fields for this attack.
        """
        return {
            "attack_id": self.manifest.attack_id,
            "attack_family": self.manifest.attack_family,
            "target_service": self.manifest.target_service,
            "target_purl": self.manifest.target_component_purl,
            "clean_purl": self.manifest.clean_component_purl,
            "label": self.manifest.ground_truth_label,
            "injection_time_offset_s": self.manifest.injection_time_offset_s,
            "expected_changes": self.manifest.expected_behavioral_changes,
            "detection_window_s": self.manifest.detection_window_s,
            "control_endpoint": self.manifest.control_endpoint,
        }

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _kubectl(
        self,
        args: list[str],
        timeout: int = 60,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a kubectl command with an explicit argument list.

        No shell=True; no string interpolation of untrusted values.

        Args:
            args: kubectl subcommand + arguments (e.g. ['exec', pod, '--', 'ls']).
            timeout: Command timeout in seconds.
            capture: If True, capture stdout/stderr.

        Returns:
            CompletedProcess with stdout/stderr attributes.

        Raises:
            subprocess.CalledProcessError: On non-zero exit code.
        """
        cmd = ["kubectl"]
        if self.kubectl_context:
            cmd += ["--context", self.kubectl_context]
        cmd.extend(args)

        log.debug("kubectl.run", extra={"cmd": " ".join(cmd)})

        if self.dry_run:
            log.info("kubectl.dry_run", extra={"cmd": " ".join(cmd)})
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        return subprocess.run(
            cmd,
            timeout=timeout,
            check=True,
            capture_output=capture,
            text=True,
        )

    def _kubectl_exec(
        self,
        namespace: str,
        pod_name: str,
        command: list[str],
        container: str | None = None,
        timeout: int = 60,
    ) -> str:
        """Run a command inside a pod via kubectl exec.

        Args:
            namespace: Kubernetes namespace.
            pod_name: Pod name.
            command: Command + args to run inside the pod.
            container: Container name (if pod has multiple containers).
            timeout: Execution timeout.

        Returns:
            stdout from the command.
        """
        args = ["exec", pod_name, "-n", namespace]
        if container:
            args += ["-c", container]
        args += ["--"] + command
        result = self._kubectl(args, timeout=timeout)
        return result.stdout.strip()

    def _kubectl_cp(
        self,
        namespace: str,
        pod_name: str,
        local_path: str,
        remote_path: str,
        timeout: int = 120,
    ) -> None:
        """Copy a file into a pod via kubectl cp.

        Args:
            namespace: Kubernetes namespace.
            pod_name: Pod name.
            local_path: Local source path.
            remote_path: Destination path inside the pod.
            timeout: Copy timeout.
        """
        self._kubectl(
            ["cp", local_path, f"{namespace}/{pod_name}:{remote_path}"],
            timeout=timeout,
            capture=True,
        )

    def _wait_for_pod_ready(
        self,
        namespace: str,
        label_selector: str,
        timeout_s: int = 120,
    ) -> None:
        """Wait for at least one pod with the label selector to be Running/Ready.

        Args:
            namespace: Kubernetes namespace.
            label_selector: e.g. 'app=recommendationservice'.
            timeout_s: Maximum seconds to wait.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                result = self._kubectl(
                    [
                        "get", "pods",
                        "-n", namespace,
                        "-l", label_selector,
                        "--field-selector", "status.phase=Running",
                        "-o", "jsonpath={.items[*].metadata.name}",
                    ],
                    timeout=15,
                )
                if result.stdout.strip():
                    log.info(
                        "pod.ready",
                        extra={"selector": label_selector, "pods": result.stdout.strip()},
                    )
                    return
            except subprocess.CalledProcessError:
                pass
            time.sleep(5)
        raise TimeoutError(
            f"Pod with selector '{label_selector}' not ready after {timeout_s}s"
        )

    def _timestamp_utc(self) -> str:
        """Return the current UTC timestamp in ISO 8601 format.

        Returns:
            ISO 8601 UTC timestamp string.
        """
        return datetime.now(tz=timezone.utc).isoformat()
