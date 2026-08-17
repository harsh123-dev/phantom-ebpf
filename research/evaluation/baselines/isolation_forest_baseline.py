"""
research/evaluation/baselines/isolation_forest_baseline.py

Unsupervised syscall-frequency anomaly detection baseline.

Baseline rationale (from handoff §3):
    The IsolationForest baseline answers a critical fairness question:
    "What if we simply apply ML anomaly detection to the same eBPF
    data that PHANTOM collects, but without SBOM context, behavioral
    contracts, or causal reasoning?"

    If this baseline performs similarly to PHANTOM, it would suggest
    that PHANTOM's contribution comes from the data source alone,
    not from its SBOM-aware contract model or causal attribution.
    If PHANTOM substantially outperforms it — especially on false
    positives during benign controls (high load, pod restarts) where
    syscall frequency shifts without any actual drift — the paper's
    claim is supported.

    Configuration (from handoff §3):
        Algorithm:     scikit-learn IsolationForest
        n_estimators:  200 (handoff §3 spec)
        contamination: matched to PHANTOM's validation-set alert budget
                       (set at threshold selection time)
        random_state:  42 (reproducibility)
        Window size:   10 seconds per handoff §3
        Feature vector (17 features, from handoff §3):
            execve, clone, fork, openat, connect, accept,
            sendmsg, recvmsg, tcp_sendmsg, tcp_cleanup_rbuf,
            dns_query, unlink, chmod, ptrace, setuid, capset
            + total_event_count (log-scaled)
        Normalization: L1 on the 16 syscall features; log1p on total.

    Threshold selection:
        The anomaly score threshold is set on the validation-set
        benign windows to match PHANTOM's target false-positive budget.
        The threshold is then frozen before any test-set scenario runs.

    Training data:
        Same benign baseline-phase windows used by PHANTOM, from the
        ``phantom_ebpf_events_captured_total`` Prometheus counter series.

    Why this baseline strengthens the paper:
        It demonstrates that PHANTOM's precision (fewer false positives
        during load bursts and pod restarts) and component attribution
        come from SBOM awareness and causal reasoning — not just from
        eBPF-based anomaly detection per se.
"""

from __future__ import annotations

import json
import logging
import pickle
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import numpy as np
from sklearn.ensemble import IsolationForest  # type: ignore[import]

from research.evaluation.baselines.base_baseline import BaseBaseline, Detection

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — from handoff §3
# ---------------------------------------------------------------------------

_N_ESTIMATORS: int = 200
_RANDOM_STATE: int = 42
_WINDOW_SECONDS: int = 10
_DEFAULT_CONTAMINATION: float = 0.05   # updated at threshold calibration

# eBPF syscall feature names (16 + 1 total-count feature).
# These match the feature vector spec in handoff §3 exactly.
FEATURE_NAMES: list[str] = [
    "execve",
    "clone",
    "fork",
    "openat",
    "connect",
    "accept",
    "sendmsg",
    "recvmsg",
    "tcp_sendmsg",
    "tcp_cleanup_rbuf",
    "dns_query",
    "unlink",
    "chmod",
    "ptrace",
    "setuid",
    "capset",
    "total_event_count",  # log-scaled; last feature
]

# Prometheus metric name for raw syscall event counts.
# The phantom eBPF agent emits this counter with label `event_type`.
_PROM_METRIC: str = "phantom_ebpf_events_captured_total"

_DEFAULT_MODEL_PATH: Path = (
    Path(__file__).resolve().parents[3]
    / "research" / "datasets" / "raw" / "isoforest_model.pkl"
)

_DEFAULT_PROMETHEUS_URL: str = "http://localhost:9090/api/v1/query_range"


class IsolationForestBaseline(BaseBaseline):
    """Unsupervised syscall-frequency anomaly detection baseline.

    Uses scikit-learn IsolationForest (n_estimators=200, random_state=42)
    trained on benign eBPF event frequency vectors from the same Prometheus
    counters as PHANTOM, but without SBOM context or behavioral contracts.

    This baseline is the "fairness control" that distinguishes PHANTOM's
    causal-contract contribution from the eBPF data source alone.

    Args:
        prometheus_url: Prometheus query_range API URL.
        model_path: Path to save/load the fitted model.
        contamination: IsolationForest contamination parameter. Updated
            at calibration time to match PHANTOM's validation-set budget.
        window_seconds: Feature window size in seconds.
        http_timeout_s: HTTP request timeout.
        dry_run: If True, skip Prometheus queries; use synthetic data.
    """

    name: str = "isolation-forest-syscall-frequency"

    def __init__(
        self,
        prometheus_url: str = _DEFAULT_PROMETHEUS_URL,
        model_path: Path | None = None,
        contamination: float = _DEFAULT_CONTAMINATION,
        window_seconds: int = _WINDOW_SECONDS,
        http_timeout_s: float = 10.0,
        dry_run: bool = False,
    ) -> None:
        """Initialise the IsolationForest baseline.

        Args:
            prometheus_url: Prometheus query_range API URL.
            model_path: Path to save/load the fitted pkl model.
            contamination: IsolationForest contamination parameter.
            window_seconds: Feature extraction window duration.
            http_timeout_s: HTTP request timeout.
            dry_run: If True, skip Prometheus queries.
        """
        self._prometheus = prometheus_url
        self._model_path = model_path or _DEFAULT_MODEL_PATH
        self._contamination = contamination
        self._window_s = window_seconds
        self._timeout = http_timeout_s
        self._dry_run = dry_run
        self._model: IsolationForest | None = None
        self._threshold: float = -0.5   # anomaly score threshold (calibrated)
        self._namespace = ""

    # ------------------------------------------------------------------ #
    # BaseBaseline interface                                               #
    # ------------------------------------------------------------------ #

    def setup(self, namespace: str) -> bool:
        """Collect benign baseline windows and fit the IsolationForest model.

        Queries Prometheus for the benign training windows (any windows
        from the baseline phase of all benign control scenarios), builds
        frequency feature vectors, and fits the IsolationForest.

        The fitted model is saved to model_path for reproducibility.

        Threshold is NOT set here — it is set by calibrate_threshold()
        after the validation phase, to match PHANTOM's FP budget.

        Args:
            namespace: Kubernetes namespace (used for Prometheus label filter).

        Returns:
            True if the model was fitted successfully.
        """
        self._namespace = namespace

        if self._model_path.exists():
            log.info(
                "isoforest.setup.loading_cached_model",
                extra={"path": str(self._model_path)},
            )
            try:
                with self._model_path.open("rb") as fh:
                    saved = pickle.load(fh)  # noqa: S301 — eval artifacts only
                self._model = saved.get("model")
                self._threshold = saved.get("threshold", -0.5)
                return True
            except Exception as exc:  # noqa: BLE001
                log.warning("isoforest.setup.load_failed", extra={"error": str(exc)})

        # Collect benign training windows from the last 2 hours (enough for
        # baseline-phase data; adjust start_time to scenario baseline start
        # when running the full evaluation via collect_training_windows()).
        training_vectors = self._collect_windows_from_prometheus(
            start=datetime.now(tz=timezone.utc) - timedelta(hours=2),
            end=datetime.now(tz=timezone.utc),
        )

        if len(training_vectors) < 10:
            log.warning(
                "isoforest.setup.insufficient_training_data",
                extra={"n": len(training_vectors)},
            )
            if self._dry_run:
                # Use synthetic data for dry-run.
                training_vectors = [
                    np.zeros(len(FEATURE_NAMES)) for _ in range(50)
                ]
            else:
                return False

        return self._fit(np.array(training_vectors))

    def collect_training_windows(
        self,
        start: datetime,
        end: datetime,
    ) -> bool:
        """Collect training data from a specific time window and re-fit.

        Called after the baseline phase with the exact baseline phase
        timestamps from ScenarioResult.phases[0] to ensure the model
        is trained on the same benign data used by PHANTOM.

        Args:
            start: Start of the benign baseline window.
            end: End of the benign baseline window.

        Returns:
            True if re-fit succeeded.
        """
        vectors = self._collect_windows_from_prometheus(start, end)
        if len(vectors) < 5:
            log.warning(
                "isoforest.train.insufficient",
                extra={"n": len(vectors)},
            )
            return False
        return self._fit(np.array(vectors))

    def calibrate_threshold(
        self,
        validation_vectors: list[list[float]],
        target_fp_rate: float = 0.05,
    ) -> float:
        """Set the anomaly score threshold on validation-set benign windows.

        Chooses the threshold such that at most target_fp_rate fraction of
        benign validation windows are scored as anomalous. This matches
        PHANTOM's FP budget for fair comparison (handoff §3).

        Args:
            validation_vectors: List of benign feature vectors from the
                validation phase.
            target_fp_rate: Maximum allowed false-positive rate on
                validation benign windows.

        Returns:
            The calibrated threshold score.
        """
        if self._model is None:
            log.error("isoforest.calibrate.model_not_fitted")
            return self._threshold

        X = np.array(validation_vectors)
        scores = self._model.score_samples(X)
        # Set threshold at the target_fp_rate percentile of benign scores.
        # Scores below this → anomalous. We want <= target_fp_rate fraction
        # of benign windows to fall below the threshold.
        self._threshold = float(np.percentile(scores, target_fp_rate * 100))
        log.info(
            "isoforest.calibrate.done",
            extra={
                "threshold": self._threshold,
                "target_fp_rate": target_fp_rate,
                "n_val": len(validation_vectors),
            },
        )
        self._save_model()
        return self._threshold

    def get_detections(
        self,
        since: datetime,
        until: datetime,
        namespace: str = "",
    ) -> list[Detection]:
        """Score all 10-second windows in [since, until] with the fitted model.

        For each window, builds the syscall frequency feature vector from
        Prometheus and scores it with the IsolationForest. Windows with
        anomaly_score < threshold are flagged as detections.

        Args:
            since: Window start (inclusive).
            until: Window end (inclusive).

        Returns:
            List of Detection objects for anomalous windows.
        """
        if self._model is None:
            log.warning("isoforest.get_detections.model_not_fitted")
            return []

        vectors_with_ts = self._collect_windows_from_prometheus_with_timestamps(
            since, until
        )
        if not vectors_with_ts:
            return []

        timestamps, vectors = zip(*vectors_with_ts)
        X = np.array(vectors)
        scores = self._model.score_samples(X)

        detections: list[Detection] = []
        for ts, score in zip(timestamps, scores):
            if score < self._threshold:
                # Normalize anomaly score to [0,1] confidence.
                # IsoForest scores typically in [-0.5, 0.5]; remap.
                confidence = float(
                    min(1.0, max(0.0, (self._threshold - score) / max(abs(self._threshold), 1e-6)))
                )
                detections.append(Detection(
                    detected_at=ts,
                    scenario_id="",
                    detector_name=self.name,
                    confidence=confidence,
                    raw_alert={
                        "anomaly_score": float(score),
                        "threshold": self._threshold,
                        "window_start": ts.isoformat(),
                        "window_seconds": self._window_s,
                    },
                    rule_name="syscall_frequency_anomaly",
                    namespace=self._namespace,
                ))

        log.debug(
            "isoforest.get_detections.done",
            extra={
                "n_windows": len(vectors),
                "n_anomalies": len(detections),
                "threshold": self._threshold,
            },
        )
        return detections

    def teardown(self) -> bool:
        """No cluster resources to remove.

        The saved model file remains at model_path for reproducibility.

        Returns:
            Always True.
        """
        log.info("isoforest.teardown.noop")
        return True

    # ------------------------------------------------------------------ #
    # Prometheus data collection                                           #
    # ------------------------------------------------------------------ #

    def _collect_windows_from_prometheus(
        self,
        start: datetime,
        end: datetime,
    ) -> list[list[float]]:
        """Fetch syscall frequency vectors from Prometheus for [start, end].

        Args:
            start: Window start.
            end: Window end.

        Returns:
            List of feature vectors (each a list of floats).
        """
        _, vectors = zip(
            *self._collect_windows_from_prometheus_with_timestamps(start, end)
        ) if self._collect_windows_from_prometheus_with_timestamps(start, end) else ([], [])
        return list(vectors) if vectors else []

    def _collect_windows_from_prometheus_with_timestamps(
        self,
        start: datetime,
        end: datetime,
    ) -> list[tuple[datetime, list[float]]]:
        """Fetch (timestamp, feature_vector) pairs from Prometheus.

        Queries ``increase(phantom_ebpf_events_captured_total[10s])``
        for each event_type label over the [start, end] range. Returns
        one feature vector per window_seconds step.

        Args:
            start: Window start.
            end: Window end.

        Returns:
            List of (window_end_ts, feature_vector) pairs.
        """
        if self._dry_run:
            # Synthetic benign-looking data for dry-run / unit tests.
            n_windows = max(1, int((end - start).total_seconds() / self._window_s))
            result_pairs: list[tuple[datetime, list[float]]] = []
            rng = np.random.default_rng(42)
            for i in range(n_windows):
                ts = start + timedelta(seconds=i * self._window_s)
                vec = rng.poisson(lam=5.0, size=len(FEATURE_NAMES)).astype(float)
                vec[-1] = float(np.log1p(vec[:-1].sum()))
                result_pairs.append((ts, vec.tolist()))
            return result_pairs

        # Build per-event-type Prometheus queries.
        # Feature order matches FEATURE_NAMES (excluding total_event_count).
        syscall_features = FEATURE_NAMES[:-1]
        raw_counters: dict[str, list[tuple[float, float]]] = {}

        for evt_type in syscall_features:
            promql = (
                f'increase({_PROM_METRIC}'
                f'{{event_type="{evt_type}"}}[{self._window_s}s])'
            )
            series = self._query_range(promql, start, end, step=self._window_s)
            if series:
                raw_counters[evt_type] = series

        if not raw_counters:
            log.warning("isoforest.prometheus.no_data")
            return []

        # Align all series to the same timestamps.
        # Use the timestamps from the first available series.
        ref_series = next(iter(raw_counters.values()))
        timestamps = [
            datetime.fromtimestamp(t, tz=timezone.utc)
            for t, _ in ref_series
        ]

        result: list[tuple[datetime, list[float]]] = []
        for idx, ts in enumerate(timestamps):
            vec: list[float] = []
            total = 0.0
            for evt_type in syscall_features:
                series = raw_counters.get(evt_type, [])
                val = float(series[idx][1]) if idx < len(series) else 0.0
                total += val
                vec.append(val)
            # L1 normalize the 16 syscall features.
            total_raw = sum(vec)
            if total_raw > 0:
                vec = [v / total_raw for v in vec]
            # Append log-scaled total count as the 17th feature.
            vec.append(float(np.log1p(total)))
            result.append((ts, vec))

        return result

    def _query_range(
        self,
        promql: str,
        start: datetime,
        end: datetime,
        step: int = 10,
    ) -> list[tuple[float, float]]:
        """Execute a Prometheus query_range and return (timestamp, value) pairs.

        Args:
            promql: PromQL expression.
            start: Query start.
            end: Query end.
            step: Step interval in seconds.

        Returns:
            List of (unix_timestamp, value) pairs.
        """
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(
                    self._prometheus,
                    params={
                        "query": promql,
                        "start": start.timestamp(),
                        "end": end.timestamp(),
                        "step": str(step),
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                results = data.get("data", {}).get("result", [])
                if results:
                    # Use the first matching series.
                    values: list[tuple[float, float]] = [
                        (float(v[0]), float(v[1]))
                        for v in results[0].get("values", [])
                    ]
                    return values
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "isoforest.prometheus.query_failed",
                extra={"promql": promql[:80], "error": str(exc)},
            )
        return []

    # ------------------------------------------------------------------ #
    # Model persistence                                                    #
    # ------------------------------------------------------------------ #

    def _fit(self, X: "np.ndarray[Any, Any]") -> bool:
        """Fit the IsolationForest on the training matrix X.

        Args:
            X: (n_samples, n_features) training matrix.

        Returns:
            True if fitting succeeded.
        """
        try:
            self._model = IsolationForest(
                n_estimators=_N_ESTIMATORS,
                contamination=self._contamination,
                random_state=_RANDOM_STATE,
                n_jobs=-1,
            )
            self._model.fit(X)
            log.info(
                "isoforest.fit.done",
                extra={"n_samples": len(X), "n_features": X.shape[1]},
            )
            self._save_model()
            return True
        except Exception as exc:  # noqa: BLE001
            log.error("isoforest.fit.failed", extra={"error": str(exc)})
            return False

    def _save_model(self) -> None:
        """Persist the model and threshold to disk.

        Saves a dict with 'model' and 'threshold' keys. The threshold is
        re-loaded by setup() when the model file already exists.
        """
        self._model_path.parent.mkdir(parents=True, exist_ok=True)
        with self._model_path.open("wb") as fh:
            pickle.dump(
                {"model": self._model, "threshold": self._threshold},
                fh,
                protocol=4,
            )
        log.info("isoforest.model_saved", extra={"path": str(self._model_path)})
