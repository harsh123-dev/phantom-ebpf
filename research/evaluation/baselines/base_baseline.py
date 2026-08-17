"""
research/evaluation/baselines/base_baseline.py

Abstract interface for all PHANTOM evaluation baseline detectors.

Every baseline must produce a list of Detection objects for any
time window [since, until]. The ScenarioEvaluator then classifies
each detection as TP / FP / FN / TN against the oracle ground-truth
injection timestamps in ScenarioResult.

Baseline implementations in this package:
    FalcoBaseline           — Falco 0.44.1 with default rules (rule-based, eBPF)
    TrivyBaseline           — Trivy 0.70.0 static image scan (SBOM + CVE)
    IsolationForestBaseline — scikit-learn IsolationForest on eBPF syscall
                              frequency vectors (unsupervised, no SBOM context)

Design notes:
    - All baselines share the same data source (eBPF events from the cluster)
      except Trivy, which is a static image scanner.
    - Baselines are instantiated once per evaluation run and reused across
      scenarios. ``setup()`` is called once before any scenarios run;
      ``teardown()`` is called once after all scenarios complete.
    - ``get_detections()`` must be deterministic for a given [since, until]
      window — repeated calls return the same results.
    - ``get_detections()`` must never access PHANTOM API or PHANTOM results;
      it uses only its own telemetry (Falco logs, Trivy output, Prometheus).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection — shared output type for all baselines
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    """A single detection event from a baseline detector.

    This is the canonical output type for all baselines and is also used
    for PHANTOM detections when fed into the ScenarioEvaluator so that
    metrics are computed on a uniform representation.

    Attributes:
        detected_at: UTC datetime of the detection event. For rule-based
            detectors (Falco), this is the alert timestamp. For batch
            scanners (Trivy), this is the scan completion timestamp. For
            windowed anomaly detectors (IsolationForest), this is the
            end of the first anomalous window.
        scenario_id: The scenario / run_id string this detection is
            associated with. Set by the evaluator when classifying
            detections against scenario windows.
        detector_name: Identifies the detector (e.g. 'falco-default-rules',
            'trivy-sbom-static', 'isolation-forest-syscall-frequency',
            'phantom').
        confidence: Normalized confidence in [0, 1]. For Falco: mapped
            from Falco priority (CRITICAL=1.0, EMERGENCY=1.0, ERROR=0.9,
            WARNING=0.7, NOTICE=0.5, INFO=0.3, DEBUG=0.1). For Trivy:
            mapped from CVSS severity (CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5,
            LOW=0.2). For IsolationForest: anomaly score normalized to [0,1].
        raw_alert: The raw detector output dict (Falco JSON, Trivy JSON,
            or IsolationForest feature dict). Preserved for audit.
        rule_name: For rule-based detectors: the rule or CVE identifier
            that fired. Empty string for anomaly detectors.
        namespace: Kubernetes namespace of the detected event (if known).
        pod_name: Pod name of the detected event (if known).
        service_name: Kubernetes service / workload name (if known).
    """

    detected_at: datetime
    scenario_id: str
    detector_name: str
    confidence: float
    raw_alert: dict[str, Any] = field(default_factory=dict)
    rule_name: str = ""
    rule_or_signal: str = ""   # alias for rule_name; spec compatibility
    severity: str = ""         # low | medium | high | critical
    namespace: str = ""
    pod_name: str = ""
    service_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict.

        Returns:
            Dict representation of this Detection.
        """
        return {
            "detected_at": self.detected_at.isoformat(),
            "scenario_id": self.scenario_id,
            "detector_name": self.detector_name,
            "confidence": self.confidence,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "rule_or_signal": self.rule_or_signal,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "service_name": self.service_name,
            # raw_alert excluded to keep serialized size manageable;
            # callers can include it explicitly if needed.
        }


# ---------------------------------------------------------------------------
# BaselineResult — aggregate result for one baseline run
# ---------------------------------------------------------------------------


@dataclass
class BaselineResult:
    """Evaluation result for one baseline across all scenarios.

    Attributes:
        detector_name: Identifier for the baseline detector.
        detector_version: Version string (e.g. 'falco-0.38.x-default-rules').
        detections: All Detection objects produced during the run.
        setup_errors: Error messages from setup(), if any.
        teardown_errors: Error messages from teardown(), if any.
    """

    detector_name: str
    detector_version: str = ""
    detections: list[Detection] = field(default_factory=list)
    setup_errors: list[str] = field(default_factory=list)
    teardown_errors: list[str] = field(default_factory=list)

    def detections_in_window(
        self,
        since: datetime,
        until: datetime,
    ) -> list[Detection]:
        """Return detections within a time window.

        Args:
            since: Window start (inclusive).
            until: Window end (inclusive).

        Returns:
            Detections with detected_at in [since, until].
        """
        return [
            d for d in self.detections
            if since <= d.detected_at <= until
        ]


# ---------------------------------------------------------------------------
# BaseBaseline — abstract interface
# ---------------------------------------------------------------------------


class BaseBaseline(ABC):
    """Abstract base class for all evaluation baselines.

    Subclasses must provide:
        name:           Class-level string constant identifying the detector.
        setup():        Install or configure the baseline in the test cluster.
        get_detections(): Return all detections in a time window.
        teardown():     Remove the baseline from the cluster.

    Attributes:
        name: Detector identifier used in metrics tables and output files.
    """

    name: str = "base_baseline"

    # ------------------------------------------------------------------ #
    # Abstract interface                                                   #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def setup(self, namespace: str) -> bool:
        """Install or configure the baseline in the test namespace.

        Called once before any scenarios run. Must be idempotent.

        Args:
            namespace: Kubernetes namespace of the evaluation cluster.

        Returns:
            True if setup succeeded.
        """

    @abstractmethod
    def get_detections(
        self,
        since: datetime,
        until: datetime,
        namespace: str = "",
    ) -> list[Detection]:
        """Collect all alerts from this baseline in the [since, until] window.

        Must be deterministic for a given window — repeated calls with the
        same arguments return the same results.

        Must NOT access PHANTOM API or PHANTOM outputs. All data must come
        from the baseline's own telemetry sources.

        Args:
            since: UTC datetime start of the collection window (inclusive).
            until: UTC datetime end of the collection window (inclusive).

        Returns:
            List of Detection objects for alerts in the window.
        """

    @abstractmethod
    def teardown(self) -> bool:
        """Remove the baseline from the test namespace.

        Called once after all scenarios complete. Must be idempotent.

        Returns:
            True if teardown succeeded.
        """

    # ------------------------------------------------------------------ #
    # Helpers shared by all baselines                                      #
    # ------------------------------------------------------------------ #

    def _in_window(self, ts: datetime, since: datetime, until: datetime) -> bool:
        """Check whether a timestamp falls within [since, until].

        Args:
            ts: Timestamp to test.
            since: Window start (inclusive).
            until: Window end (inclusive).

        Returns:
            True if since <= ts <= until.
        """
        return since <= ts <= until

    def __repr__(self) -> str:
        """Return a readable representation.

        Returns:
            String representation.
        """
        return f"{self.__class__.__name__}(name={self.name!r})"
