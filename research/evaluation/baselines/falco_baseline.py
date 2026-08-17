"""
research/evaluation/baselines/falco_baseline.py

Falco detection baseline for PHANTOM evaluation.

Baseline rationale (from handoff §3):
    Falco 0.44.1 with its upstream default ruleset is the primary
    rule-based runtime security baseline. It is chosen because:
      1. It uses the same eBPF data plane as PHANTOM (tracepoints /
         kprobes via the Falco eBPF driver), making CPU/memory overhead
         comparison methodologically sound.
      2. It is the de-facto standard Kubernetes runtime security tool,
         widely used in production.
      3. Comparing PHANTOM against Falco demonstrates that behavioral
         contracts + SBOM context detect supply-chain attacks that
         generic rules miss — specifically: attacks that do NOT trigger
         known syscall patterns (e.g. a beacon that only opens a TCP
         connection without issuing ptrace or setuid).
      4. Falco's precision-recall tradeoff is well understood;
         including it gives reviewers a calibrated reference point.

    Limitation: Falco default rules do not know which package PURL
    caused the anomaly. It cannot attribute drift to a substituted
    component and cannot express ``not_identifiable`` causal states.

Deployment:
    Falco 0.44.1 is installed via Helm (falcosecurity/falco chart) in
    the phantom-eval namespace as a DaemonSet with:
        --set driver.kind=ebpf
        --set falco.json_output=true
        --set falco.log_level=info
    Alert JSON output is directed to /var/log/falco/events.jsonl via
    a hostPath volume and file_output configuration.

Alert parsing:
    Each JSON line from Falco has the fields:
        time        : RFC3339 alert timestamp
        rule        : Rule name that fired
        priority    : EMERGENCY|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG
        output      : Human-readable alert message
        output_fields: Structured k-v field dict

Priority → confidence mapping (for uniform comparison with PHANTOM scores):
    EMERGENCY / CRITICAL → 1.0
    ERROR                → 0.9
    WARNING              → 0.7
    NOTICE               → 0.5
    INFO                 → 0.3
    DEBUG                → 0.1

Helm chart version: falcosecurity/falco 4.3.1 (Falco 0.44.1 appVersion).
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from research.evaluation.baselines.base_baseline import BaseBaseline, Detection

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FALCO_VERSION: str = "0.44.1"
FALCO_CHART_VERSION: str = "4.3.1"      # Helm chart version for this appVersion
FALCO_HELM_REPO: str = "https://falcosecurity.github.io/charts"
FALCO_RELEASE_NAME: str = "phantom-eval-falco"

# Default alert log path (hostPath mount configured in Helm values).
DEFAULT_ALERT_LOG: str = "/var/log/falco/events.jsonl"

# Priority → confidence mapping (handoff §3: Falco alert-level comparison).
_PRIORITY_CONFIDENCE: dict[str, float] = {
    "EMERGENCY": 1.0,
    "CRITICAL":  1.0,
    "ERROR":     0.9,
    "WARNING":   0.7,
    "NOTICE":    0.5,
    "INFO":      0.3,
    "DEBUG":     0.1,
}

# Default: only report alerts at WARNING or above (reduces noise for comparison).
DEFAULT_MIN_PRIORITY: str = "WARNING"
_MIN_PRIORITY_ORDER: list[str] = [
    "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "EMERGENCY"
]


class FalcoBaseline(BaseBaseline):
    """Falco 0.44.1 rule-based runtime detection baseline.

    Installs Falco as a Kubernetes DaemonSet via Helm with the default
    upstream ruleset. Alert JSON output is read from a log file on the
    evaluation host. No custom Falco rules are added, per the fair
    comparison design in handoff §3.

    Falco is the primary rule-based baseline because it uses the same
    eBPF data plane as PHANTOM, making overhead comparison valid.

    Args:
        namespace: Kubernetes namespace for Falco deployment.
        alert_log_path: Path to the Falco JSON-lines alert log.
        kubectl_context: kubectl context name (None = current context).
        min_priority: Minimum Falco priority to include in detections.
            One of DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|EMERGENCY.
        dry_run: If True, skip Helm/kubectl calls.
    """

    name: str = "falco-default-rules"

    def __init__(
        self,
        namespace: str = "phantom-eval",
        alert_log_path: str = DEFAULT_ALERT_LOG,
        kubectl_context: str | None = None,
        min_priority: str = DEFAULT_MIN_PRIORITY,
        dry_run: bool = False,
    ) -> None:
        """Initialise the Falco baseline.

        Args:
            namespace: Kubernetes namespace.
            alert_log_path: Path to Falco JSON alert log.
            kubectl_context: kubectl context name.
            min_priority: Minimum Falco priority level to include.
            dry_run: If True, log commands without executing.
        """
        self._namespace = namespace
        self._alert_log = Path(alert_log_path)
        self._context = kubectl_context
        self._min_priority_idx = _MIN_PRIORITY_ORDER.index(
            min_priority.upper()
        ) if min_priority.upper() in _MIN_PRIORITY_ORDER else 3
        self._dry_run = dry_run
        self._installed = False

    # ------------------------------------------------------------------ #
    # BaseBaseline interface                                               #
    # ------------------------------------------------------------------ #

    def setup(self, namespace: str) -> bool:
        """Install Falco 0.44.1 via Helm in the evaluation namespace.

        Adds the falcosecurity Helm repo, then installs the falco chart
        with eBPF driver, JSON output enabled, and log file configured.

        The DaemonSet is waited on (``kubectl rollout status``) before
        returning. This ensures Falco is collecting events before the
        first scenario starts.

        Args:
            namespace: Kubernetes namespace to install Falco into.

        Returns:
            True if installation succeeded.
        """
        self._namespace = namespace

        if self._dry_run:
            log.info("falco.setup.dry_run_skipped")
            self._installed = True
            return True

        # Add Helm repo (idempotent).
        try:
            self._run(
                ["helm", "repo", "add", "falcosecurity", FALCO_HELM_REPO],
                timeout=30,
            )
            self._run(["helm", "repo", "update"], timeout=60)
        except subprocess.CalledProcessError as exc:
            log.warning("falco.helm_repo.failed", extra={"error": str(exc)})

        # Install Falco DaemonSet.
        values = [
            "--set", "driver.kind=ebpf",
            "--set", "falco.json_output=true",
            "--set", "falco.log_level=info",
            "--set", f"falco.priority={DEFAULT_MIN_PRIORITY.lower()}",
            # Configure file output to the evaluation log path.
            "--set", "falco.file_output.enabled=true",
            "--set", f"falco.file_output.filename={DEFAULT_ALERT_LOG}",
            "--set", "falco.file_output.keep_alive=true",
            "--version", FALCO_CHART_VERSION,
        ]

        try:
            self._run(
                [
                    "helm", "install",
                    FALCO_RELEASE_NAME,
                    "falcosecurity/falco",
                    "--namespace", self._namespace,
                    "--create-namespace",
                    "--wait",
                    "--timeout", "5m",
                ] + values,
                timeout=360,
            )
            self._installed = True
            log.info(
                "falco.setup.installed",
                extra={
                    "version": FALCO_VERSION,
                    "namespace": self._namespace,
                },
            )
            return True
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            if "already exists" in stderr.lower() or "cannot re-use" in stderr.lower():
                log.info("falco.setup.already_installed")
                self._installed = True
                return True
            log.error("falco.setup.install_failed", extra={"error": stderr[:400]})
            return False

    def get_detections(
        self,
        since: datetime,
        until: datetime,
        namespace: str = "",
    ) -> list[Detection]:
        """Parse Falco alert JSON-lines log for alerts in [since, until].

        Reads the alert log file and returns Detection objects for all
        alerts with priority >= min_priority and timestamp in [since, until].

        The JSON alert format per Falco 0.44.1:
            {
              "time": "2026-07-26T10:00:00.000000000Z",
              "rule": "Unexpected outbound connection",
              "priority": "WARNING",
              "output": "...",
              "output_fields": {
                "container.name": "...",
                "k8s.ns.name": "...",
                "k8s.pod.name": "...",
                ...
              }
            }

        Args:
            since: Window start (inclusive).
            until: Window end (inclusive).

        Returns:
            List of Detection objects within the time window and above
            the minimum priority threshold.
        """
        if not self._alert_log.exists():
            log.warning(
                "falco.alert_log_missing",
                extra={"path": str(self._alert_log)},
            )
            return []

        detections: list[Detection] = []

        try:
            with self._alert_log.open() as fh:
                for line_no, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        alert = json.loads(line)
                    except json.JSONDecodeError:
                        log.debug(
                            "falco.parse_error",
                            extra={"line_no": line_no},
                        )
                        continue

                    # Parse timestamp.
                    ts_raw = alert.get("time", "")
                    if not ts_raw:
                        continue
                    try:
                        ts = datetime.fromisoformat(
                            ts_raw.rstrip("Z")
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue

                    if not self._in_window(ts, since, until):
                        continue

                    # Check priority threshold.
                    priority = (alert.get("priority") or "INFO").upper()
                    priority_idx = _MIN_PRIORITY_ORDER.index(priority) if priority in _MIN_PRIORITY_ORDER else 0
                    if priority_idx < self._min_priority_idx:
                        continue

                    confidence = _PRIORITY_CONFIDENCE.get(priority, 0.3)
                    fields = alert.get("output_fields", {})

                    detections.append(Detection(
                        detected_at=ts,
                        scenario_id="",       # filled by ScenarioEvaluator
                        detector_name=self.name,
                        confidence=confidence,
                        raw_alert=alert,
                        rule_name=alert.get("rule", ""),
                        namespace=fields.get("k8s.ns.name", ""),
                        pod_name=fields.get("k8s.pod.name", ""),
                        service_name=fields.get("container.name", ""),
                    ))

        except OSError as exc:
            log.error("falco.read_error", extra={"error": str(exc)})

        log.debug(
            "falco.get_detections.done",
            extra={"n": len(detections), "since": since.isoformat()},
        )
        return detections

    def teardown(self) -> bool:
        """Uninstall Falco from the namespace via Helm.

        Returns:
            True if uninstall succeeded or Falco was not installed.
        """
        if self._dry_run:
            log.info("falco.teardown.dry_run_skipped")
            return True

        if not self._installed:
            return True

        try:
            self._run(
                [
                    "helm", "uninstall",
                    FALCO_RELEASE_NAME,
                    "--namespace", self._namespace,
                ],
                timeout=60,
            )
            self._installed = False
            log.info("falco.teardown.uninstalled")
            return True
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            if "not found" in stderr.lower():
                log.info("falco.teardown.not_found")
                return True
            log.error("falco.teardown.failed", extra={"error": stderr[:200]})
            return False

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _run(
        self,
        cmd: list[str],
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        """Run a subprocess command with an explicit arg list.

        No shell=True. All command arguments are literals under our control.

        Args:
            cmd: Command + argument list.
            timeout: Execution timeout in seconds.

        Returns:
            CompletedProcess.

        Raises:
            subprocess.CalledProcessError: On non-zero exit.
        """
        ctx_prefix: list[str] = []
        # Propagate kubectl context for helm commands that need it.
        # (helm uses --kube-context, not --context)
        if self._context and cmd[0] == "helm":
            ctx_prefix = ["--kube-context", self._context]

        full_cmd = [cmd[0]] + ctx_prefix + cmd[1:]
        log.debug("falco.run", extra={"cmd": " ".join(full_cmd)})
        return subprocess.run(
            full_cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
