"""
research/evaluation/attacks/net_egress_style.py

Unauthorized Network Connect Scenario (net-egress-001).

Specification:
    Target workload:   cartservice
    Clean component:   pkg:generic/cartservice@latest
    Attack component:  pkg:generic/cartservice@latest+unauthorized-connect
    Beacon sink:       phantom-sink.phantom-eval.svc.cluster.local:8080
    Detection window:  120 seconds
    Expected eBPF evidence:
        - PHANTOM_EVT_NET_CONNECT: connection to phantom-sink:8080

Objective:
    Test PHANTOM's ability to detect unauthorized network connections where a workload
    attempts to establish a TCP session to an internal service/port that is absent
    from its signed behavioral contract.

Safety constraints:
    - Default mode is dry_run=True.
    - SafetyPreflight gates validate namespace, service, and endpoint before execution.
    - Destination is strictly cluster-internal (phantom-sink ClusterIP).
    - No real data exfiltration.
"""

from __future__ import annotations

import logging
import subprocess
import textwrap
from pathlib import Path

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack
from research.evaluation.attacks.safety import SafetyPreflight

log = logging.getLogger(__name__)

_SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
_SINK_PORT = 8080
_PROBE_SCRIPT_PATH = "/tmp/.phantom_net_probe.sh"

_PROBE_SCRIPT = textwrap.dedent(f"""\
    #!/bin/sh
    # phantom_net_probe.sh — safe inert probe for PHANTOM evaluation
    while true; do
        curl -s -m 2 http://{_SINK_HOST}:{_SINK_PORT}/ >/dev/null 2>&1 || nc -z -w 2 {_SINK_HOST} {_SINK_PORT} 2>/dev/null || true
        sleep 15
    done
""")

NET_EGRESS_MANIFEST = AttackManifest(
    attack_id="net-egress-001",
    attack_family="unauthorized_network_egress",
    target_service="cartservice",
    target_image="gcr.io/google-samples/microservices-demo/cartservice:latest",
    target_component_purl="pkg:generic/cartservice@latest+unauthorized-connect",
    clean_component_purl="pkg:generic/cartservice@latest",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_network_connect",
    ],
    ground_truth_label=1,
    control_endpoint=f"{_SINK_HOST}:{_SINK_PORT}",
    recovery_steps=[
        f"pkill -f {_PROBE_SCRIPT_PATH} (inside pod)",
        f"rm -f {_PROBE_SCRIPT_PATH} (inside pod)",
    ],
    detection_window_s=120.0,
    repetitions=3,
    notes=(
        "Unauthorized network egress scenario. "
        "Tests contract rule violation for outbound connection to undeclared cluster endpoint."
    ),
)


class NetEgressAttack(BaseAttack):
    """Unauthorized network connect scenario for PHANTOM evaluation.

    Triggers periodic connection attempts to an uncontracted cluster-internal port.

    Args:
        kubectl_context: kubectl context name.
        dry_run: If True, log commands without executing (default: True).
        allow_live_execution: Explicit confirmation flag required to exit dry-run mode.
    """

    manifest: AttackManifest = NET_EGRESS_MANIFEST

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
        """Write and run the inert probe script inside the pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if injection succeeded.
        """
        self.validate_safety(target_namespace)

        log.info(
            "net_egress.inject.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("net_egress.inject.dry_run_complete")
            return True

        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"cat << 'EOF' > {_PROBE_SCRIPT_PATH}\n{_PROBE_SCRIPT}\nEOF"],
            timeout=15,
        )
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["chmod", "+x", _PROBE_SCRIPT_PATH],
            timeout=10,
        )
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"nohup {_PROBE_SCRIPT_PATH} >/dev/null 2>&1 &"],
            timeout=15,
        )
        log.info("net_egress.inject.probe_started")
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify the probe process is running in the pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if probe process is active (or True in dry_run).
        """
        self.validate_safety(target_namespace)

        if self.dry_run:
            log.info("net_egress.verify.dry_run_ok")
            return True

        try:
            out = self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pgrep", "-f", _PROBE_SCRIPT_PATH],
                timeout=10,
            )
            return bool(out.strip())
        except subprocess.CalledProcessError:
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Kill the probe process and delete the probe script.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if recovery succeeded.
        """
        self.validate_safety(target_namespace)

        log.info(
            "net_egress.recover.start",
            extra={"namespace": target_namespace, "pod": pod_name, "dry_run": self.dry_run},
        )

        if self.dry_run:
            log.info("net_egress.recover.dry_run_complete")
            return True

        ok = True
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pkill", "-f", _PROBE_SCRIPT_PATH],
                timeout=10,
            )
        except subprocess.CalledProcessError:
            pass

        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["rm", "-f", _PROBE_SCRIPT_PATH],
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("net_egress.recover.rm_failed", extra={"error": str(exc)})
            ok = False

        log.info("net_egress.recover.complete", extra={"ok": ok})
        return ok
