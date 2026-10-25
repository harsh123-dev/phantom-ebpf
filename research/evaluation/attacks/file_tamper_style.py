"""
research/evaluation/attacks/file_tamper_style.py

Unauthorized File Access Scenario (file-tamper-001).

Specification:
    Target workload:   recommendationservice
    Clean component:   pkg:generic/recommendationservice@latest
    Attack component:  pkg:generic/recommendationservice@latest+file-tamper
    Beacon sink:       phantom-sink.phantom-eval.svc.cluster.local:8080
    Detection window:  120 seconds
    Expected eBPF evidence:
        - PHANTOM_EVT_FILE_OPEN: access to /tmp/.phantom_unauthorized_marker

Objective:
    Test PHANTOM's ability to detect unauthorized file access where an uncontracted
    file or path is read, created, or modified by a running workload.

Safety constraints:
    - Default mode is dry_run=True.
    - SafetyPreflight gates validate namespace and service before execution.
    - Only touches an inert marker file in /tmp/ (/tmp/.phantom_unauthorized_marker).
    - No modification of application configuration or runtime binaries.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.safety import SafetyPreflight

log = logging.getLogger(__name__)

_MARKER_PATH = "/tmp/.phantom_unauthorized_marker"

FILE_TAMPER_MANIFEST = AttackManifest(
    attack_id="file-tamper-001",
    attack_family="file_integrity_violation",
    target_service="recommendationservice",
    target_image="gcr.io/google-samples/microservices-demo/recommendationservice:latest",
    target_component_purl="pkg:generic/recommendationservice@latest+file-tamper",
    clean_component_purl="pkg:generic/recommendationservice@latest",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_file_access",
    ],
    ground_truth_label=1,
    control_endpoint="phantom-sink.phantom-eval.svc.cluster.local:8080",
    recovery_steps=[
        f"rm -f {_MARKER_PATH} (inside pod)",
    ],
    detection_window_s=120.0,
    repetitions=3,
    notes=(
        "Unauthorized file access anomaly scenario. "
        "Tests contract rule violation for file read/write operations outside authorized paths."
    ),
)


class FileTamperAttack(BaseAttack):
    """Unauthorized file access scenario for PHANTOM evaluation.

    Creates an unauthorized marker file in /tmp/ and triggers repeated access.

    Args:
        kubectl_context: kubectl context name.
        dry_run: If True, log commands without executing (default: True).
        allow_live_execution: Explicit confirmation flag required to exit dry-run mode.
    """

    manifest: AttackManifest = FILE_TAMPER_MANIFEST

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
        """Create and touch the unauthorized file in the target pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if injection succeeded.
        """
        self.validate_safety(target_namespace)

        log.info(
            "file_tamper.inject.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("file_tamper.inject.dry_run_complete")
            return True

        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"echo 'unauthorized_payload_marker' > {_MARKER_PATH}"],
            timeout=10,
        )
        # Trigger an open/read
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["cat", _MARKER_PATH],
            timeout=10,
        )
        log.info("file_tamper.inject.marker_created")
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify the marker file exists in the pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if marker exists (or True in dry_run).
        """
        self.validate_safety(target_namespace)

        if self.dry_run:
            log.info("file_tamper.verify.dry_run_ok")
            return True

        try:
            out = self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["test", "-f", _MARKER_PATH],
                timeout=10,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Delete the unauthorized marker file from the pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if recovery succeeded.
        """
        self.validate_safety(target_namespace)

        log.info(
            "file_tamper.recover.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("file_tamper.recover.dry_run_complete")
            return True

        ok = True
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["rm", "-f", _MARKER_PATH],
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("file_tamper.recover.rm_failed", extra={"error": str(exc)})
            ok = False

        log.info("file_tamper.recover.complete", extra={"ok": ok})
        return ok
