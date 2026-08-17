"""
research/evaluation/scenarios/scenario_runner.py

Orchestrates one complete PHANTOM evaluation scenario.

A scenario has five sequential phases:
    Phase 1 — Baseline (baseline_duration_s):
        Record benign behavior before any attack. No pod changes.
    Phase 2 — Inject:
        Call attack.inject(). Record exact injection timestamp (oracle).
    Phase 3 — Attack (attack_duration_s):
        Record eBPF-driven PHANTOM detections and overhead while the
        attack is active.
    Phase 4 — Recover:
        Call attack.recover(). Wait for pod to return to clean state.
    Phase 5 — Post-recovery (recovery_duration_s):
        Record that detections cease. Validates no persistent false signal.

Ground-truth contract:
    - phase_start / phase_end timestamps come from the local clock.
    - injection_timestamp is set immediately before attack.inject() returns.
    - These timestamps are the independent ground truth used for MTTD
      computation. They are never derived from PHANTOM outputs.

PHANTOM detections:
    - Polled from GET /api/v1/drift-events?since=<iso_ts> every
      DETECTION_POLL_INTERVAL_S seconds.
    - First detection timestamp after injection defines t_detection.

Overhead metrics:
    - Queried from Prometheus at each phase boundary.
    - cpu_usage: rate(container_cpu_usage_seconds_total) for PHANTOM pods.
    - memory_rss: container_memory_rss for PHANTOM pods.
    - event_lag_p95: phantom_event_collection_latency_seconds{quantile="0.95"}.

Baseline detections (Falco):
    - Collected from Falco JSON alert log file on the node.
    - Parsed by FalcoCollector (implemented below).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from research.evaluation.attacks.base_attack import BaseAttack

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DETECTION_POLL_INTERVAL_S: float = 5.0
"""How often to poll PHANTOM API for drift detections during attack phase."""

PROMETHEUS_QUERY_URL: str = "http://localhost:9090/api/v1/query"
"""Default Prometheus HTTP API endpoint."""

PHANTOM_API_BASE_URL: str = "http://localhost:8080"
"""Default PHANTOM API Gateway base URL."""

FALCO_ALERT_LOG: str = "/var/log/falco/events.jsonl"
"""Default path to Falco alert JSON-lines log on the evaluation host."""

# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PhaseRecord:
    """Timestamps and summary for one scenario phase.

    Attributes:
        name: Phase name (baseline, inject, attack, recover, post_recovery).
        start_time: UTC datetime when the phase began.
        end_time: UTC datetime when the phase ended (None if still running).
        duration_s: Wall-clock duration in seconds.
        notes: Optional free-text notes.
    """

    name: str
    start_time: datetime
    end_time: datetime | None = None
    duration_s: float = 0.0
    notes: str = ""

    def close(self, notes: str = "") -> None:
        """Mark the phase as complete and compute duration.

        Args:
            notes: Optional notes to attach.
        """
        self.end_time = datetime.now(tz=timezone.utc)
        self.duration_s = (self.end_time - self.start_time).total_seconds()
        if notes:
            self.notes = notes


@dataclass
class MetricsSnapshot:
    """CPU, memory, and event-lag metrics at a point in time.

    Attributes:
        timestamp: UTC datetime of the snapshot.
        cpu_usage_cores: PHANTOM agent CPU usage in cores.
        memory_rss_mb: PHANTOM agent memory RSS in MiB.
        event_lag_p95_ms: 95th-percentile event collection latency in ms.
        phase: The scenario phase during which this was collected.
        raw: Raw Prometheus query results.
    """

    timestamp: datetime
    cpu_usage_cores: float
    memory_rss_mb: float
    event_lag_p95_ms: float
    phase: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScenarioResult:
    """Complete result record for one scenario run.

    This is the data structure serialized to research/datasets/raw/<run_id>.json
    and used by the metric computation notebooks.

    Attributes:
        run_id: Unique run identifier (ISO timestamp + attack_id).
        attack_id: Attack manifest attack_id.
        attack_family: Attack taxonomy label.
        repetition: Repetition index (1-based).
        namespace: Kubernetes namespace.
        pod_name: Target pod name.
        ground_truth_label: 1 = attack, 0 = benign.
        injection_timestamp: UTC datetime immediately before inject() returned.
            None for benign scenarios.
        first_phantom_detection_timestamp: UTC datetime of the first PHANTOM
            detection event after injection. None if no detection in window.
        mttd_s: Mean time to detection in seconds. None if no TP detection.
        is_true_positive: True if PHANTOM detected within detection_window_s.
        phases: List of PhaseRecord (one per phase).
        phantom_detections: All drift-event records collected from PHANTOM API.
        falco_detections: All Falco alert records during the scenario.
        metrics_snapshots: Prometheus overhead snapshots.
        scenario_label: Ground truth label dict from attack.label().
        error: Error message if scenario did not complete.
    """

    run_id: str
    attack_id: str
    attack_family: str
    repetition: int
    namespace: str
    pod_name: str
    ground_truth_label: int
    injection_timestamp: datetime | None = None
    first_phantom_detection_timestamp: datetime | None = None
    mttd_s: float | None = None
    is_true_positive: bool = False
    phases: list[PhaseRecord] = field(default_factory=list)
    phantom_detections: list[dict[str, Any]] = field(default_factory=list)
    falco_detections: list[dict[str, Any]] = field(default_factory=list)
    metrics_snapshots: list[MetricsSnapshot] = field(default_factory=list)
    scenario_label: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict for dataset storage.

        Returns:
            Dict with all result fields.
        """
        def _dt(dt: datetime | None) -> str | None:
            return dt.isoformat() if dt is not None else None

        def _phase(p: PhaseRecord) -> dict[str, Any]:
            return {
                "name": p.name,
                "start_time": _dt(p.start_time),
                "end_time": _dt(p.end_time),
                "duration_s": p.duration_s,
                "notes": p.notes,
            }

        def _metric(m: MetricsSnapshot) -> dict[str, Any]:
            return {
                "timestamp": _dt(m.timestamp),
                "cpu_usage_cores": m.cpu_usage_cores,
                "memory_rss_mb": m.memory_rss_mb,
                "event_lag_p95_ms": m.event_lag_p95_ms,
                "phase": m.phase,
            }

        return {
            "run_id": self.run_id,
            "attack_id": self.attack_id,
            "attack_family": self.attack_family,
            "repetition": self.repetition,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "ground_truth_label": self.ground_truth_label,
            "injection_timestamp": _dt(self.injection_timestamp),
            "first_phantom_detection_timestamp": _dt(self.first_phantom_detection_timestamp),
            "mttd_s": self.mttd_s,
            "is_true_positive": self.is_true_positive,
            "phases": [_phase(p) for p in self.phases],
            "phantom_detections": self.phantom_detections,
            "falco_detections": self.falco_detections,
            "metrics_snapshots": [_metric(m) for m in self.metrics_snapshots],
            "scenario_label": self.scenario_label,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Falco alert collector
# ---------------------------------------------------------------------------


class FalcoCollector:
    """Parses Falco JSON-lines alert output from the alert log file.

    Args:
        log_path: Path to the Falco alert JSON-lines log file.
    """

    def __init__(self, log_path: str = FALCO_ALERT_LOG) -> None:
        """Initialise with path to Falco log.

        Args:
            log_path: Absolute path to falco events.jsonl.
        """
        self._log_path = log_path
        self._last_position: int = 0  # byte offset for incremental reads

    def collect_since(self, since: datetime) -> list[dict[str, Any]]:
        """Return all Falco alerts with time >= since.

        Args:
            since: UTC datetime lower bound.

        Returns:
            List of Falco alert dicts.
        """
        import json
        from pathlib import Path

        path = Path(self._log_path)
        if not path.exists():
            log.warning("falco.log_missing", extra={"path": self._log_path})
            return []

        alerts: list[dict[str, Any]] = []
        try:
            with path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        # Falco timestamps: "time" field in RFC3339 format.
                        ts_raw = alert.get("time") or alert.get("output_fields", {}).get("evt.time")
                        if ts_raw:
                            ts = datetime.fromisoformat(ts_raw.rstrip("Z")).replace(tzinfo=timezone.utc)
                            if ts >= since:
                                alerts.append(alert)
                    except (json.JSONDecodeError, ValueError):
                        continue
        except OSError as exc:
            log.warning("falco.read_error", extra={"error": str(exc)})

        return alerts


# ---------------------------------------------------------------------------
# ScenarioRunner
# ---------------------------------------------------------------------------


class ScenarioRunner:
    """Orchestrates one complete evaluation scenario.

    Runs baseline → inject → attack → recover → post-recovery, collecting
    PHANTOM detections, Falco alerts, and Prometheus overhead metrics.

    Args:
        phantom_api_base_url: Base URL of the PHANTOM API Gateway.
        prometheus_url: Prometheus HTTP API URL.
        falco_log_path: Path to Falco JSON-lines alert log.
        api_token: Bearer token for PHANTOM API authentication.
        http_timeout_s: HTTP request timeout in seconds.
        dry_run: If True, skip actual attack injection but still record
            timing and query metrics.
    """

    def __init__(
        self,
        phantom_api_base_url: str = PHANTOM_API_BASE_URL,
        prometheus_url: str = PROMETHEUS_QUERY_URL,
        falco_log_path: str = FALCO_ALERT_LOG,
        api_token: str = "",
        http_timeout_s: float = 10.0,
        dry_run: bool = False,
    ) -> None:
        """Initialise the runner.

        Args:
            phantom_api_base_url: PHANTOM API base URL.
            prometheus_url: Prometheus query API URL.
            falco_log_path: Falco alert log path.
            api_token: PHANTOM API bearer token.
            http_timeout_s: HTTP request timeout.
            dry_run: If True, skip injection but still time phases.
        """
        self._api_base = phantom_api_base_url.rstrip("/")
        self._prometheus = prometheus_url
        self._falco = FalcoCollector(falco_log_path)
        self._token = api_token
        self._timeout = http_timeout_s
        self._dry_run = dry_run

    def run_scenario(
        self,
        attack: BaseAttack,
        namespace: str,
        pod_name: str,
        repetition: int = 1,
        baseline_duration_s: int = 300,
        attack_duration_s: int = 300,
        recovery_duration_s: int = 120,
    ) -> ScenarioResult:
        """Run one complete evaluation scenario.

        Phases:
            Phase 1 (baseline_duration_s): Record benign behavior.
            Phase 2: Inject attack.
            Phase 3 (attack_duration_s): Poll PHANTOM for detections;
                collect overhead; check detection window.
            Phase 4: Recover.
            Phase 5 (recovery_duration_s): Verify detections cease.

        Ground-truth timestamps are recorded from the local clock and
        are never derived from PHANTOM output.

        Args:
            attack: The attack implementation to run.
            namespace: Kubernetes namespace of the target pod.
            pod_name: Target pod name.
            repetition: Trial repetition index (1-based).
            baseline_duration_s: Duration of the baseline phase.
            attack_duration_s: Duration of the attack observation phase.
            recovery_duration_s: Duration of the post-recovery phase.

        Returns:
            ScenarioResult with all collected data.
        """
        run_id = (
            datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"_{attack.manifest.attack_id}_rep{repetition}"
        )
        log.info(
            "scenario.start",
            extra={"run_id": run_id, "attack_id": attack.manifest.attack_id},
        )

        result = ScenarioResult(
            run_id=run_id,
            attack_id=attack.manifest.attack_id,
            attack_family=attack.manifest.attack_family,
            repetition=repetition,
            namespace=namespace,
            pod_name=pod_name,
            ground_truth_label=attack.manifest.ground_truth_label,
            scenario_label=attack.label(),
        )

        # ------------------------------------------------------------------ #
        # Phase 1: Baseline                                                   #
        # ------------------------------------------------------------------ #
        phase_baseline = PhaseRecord(name="baseline", start_time=datetime.now(tz=timezone.utc))
        result.phases.append(phase_baseline)
        log.info("scenario.phase_baseline.start", extra={"duration_s": baseline_duration_s})

        baseline_metrics = self.collect_metrics_snapshot("baseline")
        result.metrics_snapshots.append(baseline_metrics)

        time.sleep(baseline_duration_s)

        phase_baseline.close()
        log.info("scenario.phase_baseline.complete")

        # ------------------------------------------------------------------ #
        # Phase 2: Inject                                                     #
        # ------------------------------------------------------------------ #
        phase_inject = PhaseRecord(name="inject", start_time=datetime.now(tz=timezone.utc))
        result.phases.append(phase_inject)
        log.info("scenario.phase_inject.start")

        inject_ok = False
        if not self._dry_run:
            try:
                inject_ok = attack.inject(namespace, pod_name)
            except Exception as exc:  # noqa: BLE001
                log.error("scenario.inject.error", extra={"error": str(exc)})
                result.error = str(exc)
        else:
            inject_ok = True
            log.info("scenario.dry_run.inject_skipped")

        # Record oracle injection timestamp AFTER inject() returns.
        result.injection_timestamp = datetime.now(tz=timezone.utc)
        phase_inject.close(notes=f"inject_ok={inject_ok}")
        log.info(
            "scenario.phase_inject.complete",
            extra={"inject_ok": inject_ok, "ts": result.injection_timestamp.isoformat()},
        )

        if not inject_ok:
            result.error = result.error or "inject() returned False"
            return result

        # Verify injection before measurement.
        if not self._dry_run:
            verified = attack.verify_injection(namespace, pod_name)
            if not verified:
                log.warning("scenario.inject.verify_failed")
                result.error = "verify_injection() returned False"

        # ------------------------------------------------------------------ #
        # Phase 3: Attack observation                                         #
        # ------------------------------------------------------------------ #
        phase_attack = PhaseRecord(name="attack", start_time=datetime.now(tz=timezone.utc))
        result.phases.append(phase_attack)
        log.info("scenario.phase_attack.start", extra={"duration_s": attack_duration_s})

        detection_deadline = time.monotonic() + attack_duration_s
        detection_window_deadline = (
            result.injection_timestamp.timestamp()
            + attack.manifest.detection_window_s
        )

        while time.monotonic() < detection_deadline:
            time.sleep(DETECTION_POLL_INTERVAL_S)

            new_detections = self.collect_phantom_detections(
                since=result.injection_timestamp
            )
            result.phantom_detections.extend(new_detections)

            # Record first detection within the oracle detection window.
            if (
                result.first_phantom_detection_timestamp is None
                and new_detections
            ):
                for det in new_detections:
                    det_ts_raw = det.get("observed_at") or det.get("created_at", "")
                    if det_ts_raw:
                        try:
                            det_ts = datetime.fromisoformat(
                                det_ts_raw.rstrip("Z")
                            ).replace(tzinfo=timezone.utc)
                            if det_ts.timestamp() <= detection_window_deadline:
                                result.first_phantom_detection_timestamp = det_ts
                                result.is_true_positive = True
                                result.mttd_s = (
                                    det_ts - result.injection_timestamp
                                ).total_seconds()
                                log.info(
                                    "scenario.tp_detected",
                                    extra={"mttd_s": result.mttd_s},
                                )
                        except ValueError:
                            pass

        # Collect attack-phase Falco alerts.
        result.falco_detections.extend(
            self._falco.collect_since(result.injection_timestamp)
        )

        # Overhead snapshot during attack.
        result.metrics_snapshots.append(self.collect_metrics_snapshot("attack"))

        phase_attack.close()
        log.info(
            "scenario.phase_attack.complete",
            extra={
                "phantom_detections": len(result.phantom_detections),
                "is_tp": result.is_true_positive,
            },
        )

        # ------------------------------------------------------------------ #
        # Phase 4: Recovery                                                   #
        # ------------------------------------------------------------------ #
        phase_recover = PhaseRecord(name="recover", start_time=datetime.now(tz=timezone.utc))
        result.phases.append(phase_recover)
        log.info("scenario.phase_recover.start")

        recover_ok = False
        if not self._dry_run:
            try:
                recover_ok = attack.recover(namespace, pod_name)
            except Exception as exc:  # noqa: BLE001
                log.error("scenario.recover.error", extra={"error": str(exc)})
        else:
            recover_ok = True

        phase_recover.close(notes=f"recover_ok={recover_ok}")
        log.info("scenario.phase_recover.complete", extra={"recover_ok": recover_ok})

        # ------------------------------------------------------------------ #
        # Phase 5: Post-recovery                                              #
        # ------------------------------------------------------------------ #
        phase_post = PhaseRecord(name="post_recovery", start_time=datetime.now(tz=timezone.utc))
        result.phases.append(phase_post)
        log.info("scenario.phase_post_recovery.start", extra={"duration_s": recovery_duration_s})

        time.sleep(recovery_duration_s)

        # Collect post-recovery detections (should be empty for a clean rollback).
        recovery_start = datetime.now(tz=timezone.utc)
        post_detections = self.collect_phantom_detections(since=recovery_start)
        result.phantom_detections.extend(post_detections)

        result.metrics_snapshots.append(self.collect_metrics_snapshot("post_recovery"))

        phase_post.close()
        log.info("scenario.phase_post_recovery.complete")

        log.info(
            "scenario.complete",
            extra={
                "run_id": run_id,
                "is_tp": result.is_true_positive,
                "mttd_s": result.mttd_s,
                "phantom_detections": len(result.phantom_detections),
            },
        )
        return result

    # ------------------------------------------------------------------ #
    # PHANTOM API integration                                              #
    # ------------------------------------------------------------------ #

    def collect_phantom_detections(self, since: datetime) -> list[dict[str, Any]]:
        """Poll GET /api/v1/drift-events for detections since a timestamp.

        Filters by observed_at >= since. Returns only new records each call.

        Args:
            since: UTC datetime lower bound for observed_at filtering.

        Returns:
            List of drift-event dicts from PHANTOM API.
        """
        since_iso = since.isoformat().replace("+00:00", "Z")
        url = f"{self._api_base}/api/v1/drift-events"
        params = {"since": since_iso, "limit": 200}
        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(url, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                events: list[dict[str, Any]] = data.get("items", data) if isinstance(data, dict) else data
                return events
        except httpx.HTTPError as exc:
            log.warning("phantom_api.request_failed", extra={"error": str(exc)})
            return []

    # ------------------------------------------------------------------ #
    # Prometheus overhead integration                                      #
    # ------------------------------------------------------------------ #

    def collect_metrics_snapshot(self, phase: str) -> MetricsSnapshot:
        """Query Prometheus for current PHANTOM overhead metrics.

        Queries:
            cpu_usage_cores:   rate(container_cpu_usage_seconds_total
                               {container="phantom-agent"}[1m])
            memory_rss_mb:     container_memory_rss{container="phantom-agent"} / 1024^2
            event_lag_p95_ms:  phantom_event_collection_latency_seconds{quantile="0.95"} * 1000

        Falls back to 0.0 for each metric on query failure.

        Args:
            phase: Phase label for the snapshot record.

        Returns:
            MetricsSnapshot with current metric values.
        """
        now = datetime.now(tz=timezone.utc)

        def _query(promql: str) -> float:
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    resp = client.get(
                        self._prometheus,
                        params={"query": promql},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    results = data.get("data", {}).get("result", [])
                    if results:
                        return float(results[0]["value"][1])
            except Exception as exc:  # noqa: BLE001
                log.debug("prometheus.query_failed", extra={"promql": promql, "error": str(exc)})
            return 0.0

        cpu = _query(
            'rate(container_cpu_usage_seconds_total{container="phantom-agent"}[1m])'
        )
        mem = _query(
            'container_memory_rss{container="phantom-agent"} / 1048576'
        )
        lag = _query(
            'phantom_event_collection_latency_seconds{quantile="0.95"} * 1000'
        )

        return MetricsSnapshot(
            timestamp=now,
            cpu_usage_cores=cpu,
            memory_rss_mb=mem,
            event_lag_p95_ms=lag,
            phase=phase,
        )
