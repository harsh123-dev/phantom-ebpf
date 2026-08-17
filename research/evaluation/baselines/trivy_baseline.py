"""
research/evaluation/baselines/trivy_baseline.py

Trivy static SBOM/image scan baseline for PHANTOM evaluation.

Baseline rationale (from handoff §3):
    Trivy 0.70.0 is the static SBOM scanner baseline. It is chosen because:
      1. Static SBOM scanning is the most common defense against supply-chain
         attacks in production Kubernetes environments. Comparing PHANTOM
         against it demonstrates the gap between static declarations and
         runtime truth.
      2. Trivy is widely used and well understood by reviewers.
      3. Including it cleanly answers: "Can Trivy detect these attacks?"
         For XZ-Utils and dependency confusion: partially (if the substituted
         package has known CVEs in the frozen DB). For SolarWinds: no (the
         SBOM is clean; the extra binary is not declared).

CRITICAL LIMITATION (by design — this is the paper's point):
    Trivy cannot detect runtime SBOM drift because it is a static scanner.
    Its 'detections' are CVEs declared in image layers at build time, not
    behavioral anomalies observed at runtime. Specifically:
      - XZ-Utils: Trivy may flag the clean lzmaffi@1.0.0 if it has CVEs,
        but it cannot observe that a backdoored wheel was injected post-build.
      - Dependency confusion: Trivy scans the image as built; it cannot
        detect that pip.conf was modified in the running pod.
      - SolarWinds: The clean SBOM is still attached; Trivy confirms it.
        The extra phantom-worker binary is invisible to Trivy unless it
        scans the tampered image (which is the attack image, not the declared
        image). This is what this baseline records.

    This limitation is precisely what motivates PHANTOM.

Scan mode:
    ``trivy image --format json --scanners vuln --output <file> <image>``
    against each distinct image seen in the evaluation namespace.
    The vulnerability database is frozen once at the start of the experiment
    batch (``trivy image --download-db-only``) and not refreshed during runs,
    per handoff §3 reproducibility requirement.

Detection definition for metric computation:
    A Trivy 'detection' for a given scenario is defined as:
    - The scenario's target image has one or more HIGH or CRITICAL CVEs
      in the frozen Trivy DB.
    - The reported component PURL matches or overlaps the attack target PURL.
    - Timestamp = scan completion time (not a runtime event timestamp).

    Since Trivy is point-in-time, MTTD is undefined for Trivy.
    For TPR/FPR computation, a Trivy detection is a TP only if the
    exact attack image was scanned AND it reported the target component.
    For the SolarWinds scenario, Trivy will always be FN (clean SBOM).

Trivy version: 0.70.0 (pinned for reproducibility per handoff §3).
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from research.evaluation.baselines.base_baseline import BaseBaseline, Detection

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRIVY_VERSION: str = "0.70.0"
"""Pinned Trivy version for reproducibility (handoff §3)."""

TRIVY_SCAN_COMMAND: str = "trivy"
"""Trivy binary name (assumed on PATH)."""

# Severity levels included as 'detections' for metric computation.
_INCLUDED_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Severity → confidence mapping (analogous to Falco priority mapping).
_SEVERITY_CONFIDENCE: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH":     0.8,
    "MEDIUM":   0.5,
    "LOW":      0.2,
    "UNKNOWN":  0.1,
}

# Default output directory for Trivy JSON scan results.
_DEFAULT_SCAN_OUTPUT_DIR: Path = (
    Path(__file__).resolve().parents[3]
    / "research" / "datasets" / "raw" / "trivy"
)


class TrivyBaseline(BaseBaseline):
    """Trivy 0.70.0 static image-scan baseline for PHANTOM evaluation.

    IMPORTANT LIMITATION (by design — this is the paper's point):
    ---------------------------------------------------------------
    Trivy cannot detect runtime SBOM drift because it is a static
    scanner. Its 'detections' are CVEs in image layers declared at
    build time, not behavioral anomalies observed at runtime.

    This baseline is included to demonstrate the gap that PHANTOM addresses:
      - XZ-Utils:         Trivy may flag the clean lzmaffi CVEs, but cannot
                          observe a backdoored wheel injected post-build.
      - Dependency conf.: Trivy scans the original image; it cannot see
                          that pip.conf was modified in the running pod.
      - SolarWinds:       The SBOM is clean; Trivy confirms it and produces
                          no detection, making this a false negative by design.

    Scan mode: ``trivy image --format json --scanners vuln`` on each image.
    The vulnerability database is frozen once at setup() and not refreshed
    during the experiment batch.

    Args:
        scan_output_dir: Directory to store Trivy JSON scan outputs.
        kubectl_context: kubectl context name.
        dry_run: If True, skip trivy/kubectl calls.
        include_medium: If True, include MEDIUM severity in detections
            (changes recall but inflates FP on benign scenarios).
    """

    name: str = "trivy-sbom-static"

    def __init__(
        self,
        scan_output_dir: Path | None = None,
        kubectl_context: str | None = None,
        dry_run: bool = False,
        include_medium: bool = False,
    ) -> None:
        """Initialise the Trivy baseline.

        Args:
            scan_output_dir: Output directory for Trivy scan JSON files.
            kubectl_context: kubectl context name.
            dry_run: If True, skip trivy/kubectl calls.
            include_medium: If True, include MEDIUM CVEs in detections.
        """
        self._scan_dir = scan_output_dir or _DEFAULT_SCAN_OUTPUT_DIR
        self._context = kubectl_context
        self._dry_run = dry_run
        self._db_frozen = False
        self._scan_cache: dict[str, dict[str, Any]] = {}  # image → trivy output
        if include_medium:
            self._included_severities = frozenset({"HIGH", "CRITICAL", "MEDIUM"})
        else:
            self._included_severities = _INCLUDED_SEVERITIES

    # ------------------------------------------------------------------ #
    # BaseBaseline interface                                               #
    # ------------------------------------------------------------------ #

    def setup(self, namespace: str) -> bool:
        """Freeze the Trivy vulnerability database.

        Downloads the Trivy DB once so all scans during the experiment
        batch use identical vulnerability data. This is required for
        reproducibility (handoff §3: "Database cache is refreshed once
        before the experiment batch and then frozen for reproducibility").

        No persistent Kubernetes resources are created.

        Args:
            namespace: Kubernetes namespace (unused by Trivy; stored for context).

        Returns:
            True if the DB was downloaded successfully.
        """
        self._namespace = namespace
        self._scan_dir.mkdir(parents=True, exist_ok=True)

        if self._dry_run:
            log.info("trivy.setup.dry_run_skipped")
            self._db_frozen = True
            return True

        # Verify trivy is available and at the expected version.
        try:
            result = subprocess.run(
                [TRIVY_SCAN_COMMAND, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            version_line = result.stdout.split("\n")[0]
            if TRIVY_VERSION not in version_line:
                log.warning(
                    "trivy.version_mismatch",
                    extra={"expected": TRIVY_VERSION, "found": version_line},
                )
        except FileNotFoundError:
            log.error("trivy.not_found_on_path", extra={"cmd": TRIVY_SCAN_COMMAND})
            return False

        # Download / update vulnerability database.
        try:
            subprocess.run(
                [TRIVY_SCAN_COMMAND, "image", "--download-db-only"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
            self._db_frozen = True
            log.info("trivy.setup.db_frozen")
            return True
        except subprocess.CalledProcessError as exc:
            log.error("trivy.setup.db_download_failed", extra={"error": exc.stderr[:300]})
            return False

    def scan_image(
        self,
        image: str,
        scan_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Run a Trivy scan on a container image and return the JSON output.

        Results are cached by image reference to avoid duplicate scans.
        The scan output JSON is also written to self._scan_dir for audit.

        Args:
            image: Docker image reference (e.g. 'repo/name:tag').
            scan_time: Timestamp to associate with this scan. If None,
                uses the current UTC time.

        Returns:
            Trivy JSON output dict. Empty dict on failure.
        """
        if image in self._scan_cache:
            return self._scan_cache[image]

        if self._dry_run:
            log.info("trivy.scan.dry_run", extra={"image": image})
            empty: dict[str, Any] = {"Results": [], "_scan_time": datetime.now(tz=timezone.utc).isoformat()}
            self._scan_cache[image] = empty
            return empty

        ts = scan_time or datetime.now(tz=timezone.utc)
        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        out_path = self._scan_dir / f"{safe_name}.json"

        try:
            result = subprocess.run(
                [
                    TRIVY_SCAN_COMMAND,
                    "image",
                    "--format", "json",
                    "--scanners", "vuln",
                    "--output", str(out_path),
                    "--no-progress",
                    image,
                ],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,  # trivy exits 1 when vulns found — not a failure
            )

            if out_path.exists():
                with out_path.open() as fh:
                    data: dict[str, Any] = json.load(fh)
                data["_scan_time"] = ts.isoformat()
                data["_image"] = image
                self._scan_cache[image] = data
                log.info(
                    "trivy.scan.done",
                    extra={"image": image, "output": str(out_path)},
                )
                return data
            else:
                log.error(
                    "trivy.scan.no_output",
                    extra={"image": image, "stderr": result.stderr[:200]},
                )
        except subprocess.TimeoutExpired:
            log.error("trivy.scan.timeout", extra={"image": image})
        except Exception as exc:  # noqa: BLE001
            log.error("trivy.scan.error", extra={"image": image, "error": str(exc)})

        return {}

    def get_detections(
        self,
        since: datetime,
        until: datetime,
        namespace: str = "",
    ) -> list[Detection]:
        """Return all Trivy HIGH/CRITICAL detections from scans in [since, until].

        Trivy is a batch point-in-time scanner. A detection is returned
        for each HIGH or CRITICAL CVE found in any scan whose _scan_time
        falls within the [since, until] window.

        MTTD is undefined for Trivy detections because all detections
        share the scan_time timestamp, not the vulnerability discovery time.
        The ScenarioEvaluator handles this by marking Trivy MTTD as None.

        Args:
            since: Window start (inclusive).
            until: Window end (inclusive).

        Returns:
            List of Detection objects for CVEs in window-scanned images.
        """
        detections: list[Detection] = []

        for image, scan_data in self._scan_cache.items():
            scan_time_raw = scan_data.get("_scan_time", "")
            if not scan_time_raw:
                continue
            try:
                scan_ts = datetime.fromisoformat(
                    scan_time_raw.rstrip("Z")
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            if not self._in_window(scan_ts, since, until):
                continue

            # Parse Trivy Results array.
            for result in scan_data.get("Results", []):
                target = result.get("Target", image)
                for vuln in result.get("Vulnerabilities") or []:
                    severity = (vuln.get("Severity") or "UNKNOWN").upper()
                    if severity not in self._included_severities:
                        continue

                    cve_id = vuln.get("VulnerabilityID", "")
                    pkg_name = vuln.get("PkgName", "")
                    installed_ver = vuln.get("InstalledVersion", "")
                    purl = f"pkg:pypi/{pkg_name}@{installed_ver}" if pkg_name else ""
                    confidence = _SEVERITY_CONFIDENCE.get(severity, 0.1)

                    detections.append(Detection(
                        detected_at=scan_ts,
                        scenario_id="",       # filled by ScenarioEvaluator
                        detector_name=self.name,
                        confidence=confidence,
                        raw_alert={
                            "cve_id": cve_id,
                            "pkg_name": pkg_name,
                            "installed_version": installed_ver,
                            "severity": severity,
                            "target": target,
                            "image": image,
                        },
                        rule_name=cve_id,
                        namespace="",
                        pod_name="",
                        service_name=image,
                    ))

        log.debug(
            "trivy.get_detections.done",
            extra={"n": len(detections), "cached_images": len(self._scan_cache)},
        )
        return detections

    def teardown(self) -> bool:
        """No persistent resources to remove for Trivy.

        The cached scan JSON files remain in scan_output_dir for audit.
        The frozen DB is not removed (it is reusable).

        Returns:
            Always True.
        """
        log.info("trivy.teardown.noop")
        return True

    def scan_namespace_images(
        self,
        namespace: str,
        scan_time: datetime | None = None,
    ) -> list[str]:
        """Discover and scan all distinct images running in a namespace.

        Uses kubectl get pods to enumerate unique images, then scans each.

        Args:
            namespace: Kubernetes namespace to scan.
            scan_time: Timestamp to attach to scan results.

        Returns:
            List of image references that were scanned.
        """
        if self._dry_run:
            log.info("trivy.scan_namespace.dry_run", extra={"namespace": namespace})
            return []

        try:
            ctx_args = ["--context", self._context] if self._context else []
            result = subprocess.run(
                [
                    "kubectl",
                    *ctx_args,
                    "get", "pods",
                    "-n", namespace,
                    "-o",
                    "jsonpath={range .items[*]}"
                    "{range .spec.containers[*]}"
                    "{.image}{'\\n'}"
                    "{end}{end}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            images = sorted(set(
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip()
            ))
        except subprocess.CalledProcessError as exc:
            log.error(
                "trivy.scan_namespace.kubectl_failed",
                extra={"error": exc.stderr[:200]},
            )
            return []

        scanned: list[str] = []
        for image in images:
            data = self.scan_image(image, scan_time=scan_time)
            if data:
                scanned.append(image)

        log.info(
            "trivy.scan_namespace.done",
            extra={"namespace": namespace, "scanned": len(scanned)},
        )
        return scanned
