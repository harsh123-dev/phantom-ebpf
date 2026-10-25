"""
research/evaluation/metrics/evaluator.py

Computes all paper metrics for PHANTOM and baseline detectors.

Metric definitions — exact match to handoff §4:

    TP: detector fires within detection_window_s after oracle injection_timestamp.
    FP: detector fires during a known benign scenario (ground_truth_label == 0).
    FN: attack scenario where no detection occurs within detection_window_s.
    TN: benign scenario where no detection occurs.

    TPR = TP / (TP + FN)           — detection coverage
    FPR = FP / (FP + TN)           — benign false alarm rate
    Precision = TP / (TP + FP)
    Recall = TPR
    F1 = 2 * Precision * Recall / (Precision + Recall)
    FP/hour = FP / (total_benign_duration_s / 3600)

    MTTD (mean time to detection):
        For each TP scenario: delta_i = t_detection - t_injection
        MTTD = mean(delta_i for TPs only)
        FN cases are excluded from MTTD (handoff §4: "FN cases excluded;
        sensitivity table assigns FN the full scenario timeout").

    Causal Attribution Accuracy (PHANTOM only, handoff §4):
        For each attack scenario with a TP:
          exact credit (1.0): top attributed PURL == oracle ground_truth_purl
          partial credit (0.5): oracle PURL in top-3 AND in same dep chain
          zero (0.0): otherwise
        CAA = mean(credit_i)

    PCEPS Calibration — Brier score (PHANTOM only):
        BS = (1/N) * sum((p_i - y_i)^2)
        where p_i = PCEPS predicted probability, y_i = oracle label.

    CPU overhead:
        cpu_overhead_pct = 100 * (mean_cpu_attack - mean_cpu_baseline)
                           / mean_cpu_baseline

    FP/hour:
        Total FP detections across all benign scenarios
        divided by total benign scenario duration in hours.
"""

from __future__ import annotations

import logging
import math
import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from research.evaluation.baselines.base_baseline import Detection
from research.evaluation.metrics.wilson_score import compute_ordinary_wilson_score
from research.evaluation.scenarios.scenario_runner import MetricsSnapshot, ScenarioResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EvaluationReport dataclass
# ---------------------------------------------------------------------------


@dataclass
class EvaluationReport:
    """Per-detector metric report for the paper's results tables.

    Attributes:
        detector_name: Detector identifier (e.g. 'phantom', 'falco-default-rules').
        n_attack_scenarios: Total eligible attack scenario runs evaluated.
        n_benign_scenarios: Total benign scenario runs evaluated.
        tp: True positive count (or None if baseline telemetry missing).
        fp: False positive count (or None if no benign runs).
        fn: False negative count (or None if baseline telemetry missing).
        tn: True negative count (or None if no benign runs).
        tpr: True positive rate (recall), or None if denominator is zero.
        tpr_ci_wilson: 95% Wilson score interval [lower, upper] for TPR.
        fpr: False positive rate, or None if denominator is zero.
        precision: Precision (TP / (TP + FP)), or None if denominator is zero.
        recall: Same as TPR.
        f1: F1 score, or None if precision/recall undefined.
        false_positives_per_hour: FP count per hour of benign monitoring.
        mttd_mean_s: Mean time to detection in seconds (TP cases only).
        mttd_p50_s: Median MTTD in seconds.
        mttd_median_s: Median MTTD in seconds (alias for mttd_p50_s).
        mttd_iqr_s: Interquartile range of MTTD in seconds.
        mttd_p95_s: 95th percentile MTTD in seconds.
        mttd_ci_bootstrap: 95% non-parametric bootstrap percentile interval for MTTD.
        mttd_values_s: All individual MTTD values (for distribution reporting).
        overhead_status: 'measured' or 'unmeasured'.
        cpu_overhead_pct: Mean CPU overhead % (attack vs baseline phase), or None if unmeasured.
        memory_overhead_mb: Mean memory overhead MB, or None if unmeasured.
        event_lag_p95_ms: 95th-percentile collection latency in ms, or None if unmeasured.
        status: Evaluation status ('evaluated', 'telemetry_unavailable', etc.).
        excluded_failed_injections: Count of failed injection runs excluded from TPR.
        attribution_accuracy: Causal attribution accuracy (PHANTOM only; else None).
        attribution_exact: Exact-match attribution accuracy (PHANTOM only).
        attribution_partial: Partial-credit attribution accuracy (PHANTOM only).
        brier_score: PCEPS calibration Brier score (PHANTOM only; else None).
        notes: Free-text notes for the paper appendix.
    """

    detector_name: str
    n_attack_scenarios: int = 0
    n_benign_scenarios: int = 0
    tp: int | None = 0
    fp: int | None = 0
    fn: int | None = 0
    tn: int | None = 0
    tpr: float | None = None
    tpr_ci_wilson: tuple[float, float] | None = None
    fpr: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    false_positives_per_hour: float | None = None
    mttd_mean_s: float | None = None
    mttd_p50_s: float | None = None
    mttd_median_s: float | None = None
    mttd_iqr_s: float | None = None
    mttd_p95_s: float | None = None
    mttd_ci_bootstrap: tuple[float, float] | None = None
    mttd_values_s: list[float] = field(default_factory=list)
    overhead_status: str = "measured"
    cpu_overhead_pct: float | None = None
    memory_overhead_mb: float | None = None
    event_lag_p95_ms: float | None = None
    status: str = "evaluated"
    excluded_failed_injections: int = 0
    attribution_accuracy: float | None = None     # PHANTOM only
    attribution_exact: float | None = None        # PHANTOM only
    attribution_partial: float | None = None      # PHANTOM only
    brier_score: float | None = None              # PHANTOM only
    notes: str = ""

    @property
    def tpr_wilson_ci(self) -> tuple[float, float] | None:
        """Alias for tpr_ci_wilson."""
        return self.tpr_ci_wilson

    @tpr_wilson_ci.setter
    def tpr_wilson_ci(self, value: tuple[float, float] | None) -> None:
        self.tpr_ci_wilson = value

    @property
    def mttd_median(self) -> float | None:
        """Alias for mttd_median_s."""
        return self.mttd_median_s

    @property
    def mttd_iqr(self) -> float | None:
        """Alias for mttd_iqr_s."""
        return self.mttd_iqr_s

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict.

        Returns:
            Dict with all metric fields.
        """
        return {
            "detector_name": self.detector_name,
            "status": self.status,
            "n_attack_scenarios": self.n_attack_scenarios,
            "n_benign_scenarios": self.n_benign_scenarios,
            "excluded_failed_injections": self.excluded_failed_injections,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "tpr": self.tpr,
            "tpr_ci_wilson": list(self.tpr_ci_wilson) if self.tpr_ci_wilson is not None else None,
            "tpr_wilson_ci": list(self.tpr_wilson_ci) if self.tpr_wilson_ci is not None else None,
            "fpr": self.fpr,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positives_per_hour": self.false_positives_per_hour,
            "mttd_mean_s": self.mttd_mean_s,
            "mttd_p50_s": self.mttd_p50_s,
            "mttd_median_s": self.mttd_median_s,
            "mttd_iqr_s": self.mttd_iqr_s,
            "mttd_p95_s": self.mttd_p95_s,
            "mttd_ci_bootstrap": list(self.mttd_ci_bootstrap) if self.mttd_ci_bootstrap is not None else None,
            "mttd_values_s": self.mttd_values_s,
            "overhead_status": self.overhead_status,
            "cpu_overhead_pct": self.cpu_overhead_pct,
            "memory_overhead_mb": self.memory_overhead_mb,
            "event_lag_p95_ms": self.event_lag_p95_ms,
            "attribution_accuracy": self.attribution_accuracy,
            "attribution_exact": self.attribution_exact,
            "attribution_partial": self.attribution_partial,
            "brier_score": self.brier_score,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Injection Failure Helper
# ---------------------------------------------------------------------------


def is_failed_injection(r: ScenarioResult) -> bool:
    """Return True if this run represents a failed injection (inject_ok=False).

    Per EXPERIMENT_PROTOCOL.md §3.1:
    Failed injection runs must be excluded from detection sensitivity (TPR)
    denominators as the intervention was never delivered.
    """
    if getattr(r, "inject_ok", None) is False:
        return True
    error_str = getattr(r, "error", "") or ""
    if "inject() returned False" in error_str or "inject() raised" in error_str or "inject_ok=False" in error_str:
        return True
    for p in getattr(r, "phases", []):
        if getattr(p, "name", "") == "inject" and "inject_ok=False" in getattr(p, "notes", ""):
            return True
    label = getattr(r, "scenario_label", {}) or {}
    if label.get("inject_ok") is False:
        return True
    return False


# ---------------------------------------------------------------------------
# ScenarioEvaluator
# ---------------------------------------------------------------------------


class ScenarioEvaluator:
    """Computes all paper metrics for PHANTOM and baseline detectors.

    Takes ScenarioResult objects (which contain oracle ground truth) and
    Detection lists (from each detector) and computes TPR, FPR, F1, MTTD,
    and overhead metrics per the handoff §4 definitions.

    Args:
        detection_window_s: Default detection window in seconds. Overridden
            per-scenario by ScenarioResult.scenario_label['detection_window_s']
            if present.
        phantom_detector_name: Name string used to identify PHANTOM detections
            in the detections dict.
    """

    def __init__(
        self,
        detection_window_s: float = 300.0,
        phantom_detector_name: str = "phantom",
    ) -> None:
        """Initialise the evaluator.

        Args:
            detection_window_s: Default detection window in seconds.
            phantom_detector_name: Key used for PHANTOM in the detections dict.
        """
        self._default_window_s = detection_window_s
        self._phantom_name = phantom_detector_name

    def evaluate(
        self,
        scenario_results: list[ScenarioResult],
        detections: dict[str, list[Detection]],
    ) -> list[EvaluationReport]:
        """Compute all paper metrics for each detector.

        For each detector in ``detections`` (keyed by detector_name), and
        also for PHANTOM (from ScenarioResult.is_true_positive et al.),
        computes TPR, FPR, Precision, Recall, F1, FP/hr, MTTD statistics,
        and overhead metrics.

        PHANTOM-specific metrics (attribution accuracy, Brier score) are
        computed if detector_name == self._phantom_name.

        Args:
            scenario_results: List of ScenarioResult from run_all_scenarios.
            detections: Dict mapping detector_name → list of Detection.
                Must include all baseline detectors. PHANTOM detections are
                read directly from ScenarioResult fields.

        Returns:
            List of EvaluationReport, one per detector (PHANTOM first).
        """
        reports: list[EvaluationReport] = []

        # ----- PHANTOM report (from ScenarioResult fields) -----
        phantom_report = self._evaluate_phantom(scenario_results)
        reports.append(phantom_report)

        # ----- Baseline reports -----
        for detector_name, det_list in detections.items():
            if detector_name == self._phantom_name:
                continue
            report = self._evaluate_baseline(
                detector_name=detector_name,
                detections=det_list,
                scenario_results=scenario_results,
            )
            reports.append(report)

        return reports

    # ------------------------------------------------------------------ #
    # PHANTOM evaluation (from ScenarioResult)                            #
    # ------------------------------------------------------------------ #

    def _evaluate_phantom(
        self,
        scenario_results: list[ScenarioResult],
    ) -> EvaluationReport:
        """Compute PHANTOM metrics from ScenarioResult.is_true_positive etc.

        Args:
            scenario_results: All scenario results.

        Returns:
            EvaluationReport for PHANTOM.
        """
        unresolved_ground_truth = [
            r for r in scenario_results
            if (r.scenario_label or {}).get("ground_truth_status") == "unknown_contract_state"
        ]
        eligible_results = [
            r for r in scenario_results
            if (r.scenario_label or {}).get("ground_truth_status") != "unknown_contract_state"
        ]
        attack_results = [r for r in eligible_results if r.ground_truth_label == 1]
        benign_results = [r for r in eligible_results if r.ground_truth_label == 0]

        valid_attack_results = [r for r in attack_results if not is_failed_injection(r)]
        failed_attack_results = [r for r in attack_results if is_failed_injection(r)]

        if valid_attack_results:
            tp: int | None = sum(1 for r in valid_attack_results if r.is_true_positive)
            fn: int | None = sum(1 for r in valid_attack_results if not r.is_true_positive)
        elif unresolved_ground_truth and not eligible_results:
            tp = None
            fn = None
        else:
            tp = 0
            fn = 0
        if benign_results:
            fp: int | None = sum(
                1 for r in benign_results
                if r.phantom_detections  # any detection in a benign scenario = FP
            )
            tn: int | None = len(benign_results) - fp
        else:
            fp = None
            tn = None

        mttd_values = [r.mttd_s for r in valid_attack_results if r.mttd_s is not None]

        # Overhead metrics.
        baseline_snaps = [
            s for r in scenario_results
            for s in r.metrics_snapshots
            if s.phase == "baseline"
        ]
        attack_snaps = [
            s for r in scenario_results
            for s in r.metrics_snapshots
            if s.phase == "attack"
        ]

        # Zero is not a credible live sample for a running agent's RSS or for
        # its kernel-to-callback histogram. Older collectors serialized empty
        # Prometheus query results as 0.0, so exclude those sentinel values.
        baseline_cpu = [s.cpu_usage_cores for s in baseline_snaps if s.cpu_usage_cores is not None and s.cpu_usage_cores > 0]
        attack_cpu = [s.cpu_usage_cores for s in attack_snaps if s.cpu_usage_cores is not None and s.cpu_usage_cores > 0]
        baseline_memory = [s.memory_rss_mb for s in baseline_snaps if s.memory_rss_mb is not None and s.memory_rss_mb > 0]
        attack_memory = [s.memory_rss_mb for s in attack_snaps if s.memory_rss_mb is not None and s.memory_rss_mb > 0]
        attack_lag = [s.event_lag_p95_ms for s in attack_snaps if s.event_lag_p95_ms is not None and s.event_lag_p95_ms > 0]

        cpu_overhead_pct = None
        if baseline_cpu and attack_cpu:
            cpu_base = _safe_mean(baseline_cpu)
            if cpu_base > 0:
                cpu_overhead_pct = 100.0 * (_safe_mean(attack_cpu) - cpu_base) / cpu_base

        memory_overhead_mb = None
        if baseline_memory and attack_memory:
            memory_overhead_mb = _safe_mean(attack_memory) - _safe_mean(baseline_memory)

        event_lag_p95 = _safe_percentile(attack_lag, 95) if attack_lag else None
        overhead_status = (
            "measured"
            if (baseline_cpu and attack_cpu) or (baseline_memory and attack_memory) or attack_lag
            else "unmeasured"
        )

        # Attribution accuracy (from scenario_label.top_attributed_purl if present).
        attribution_accuracy, attribution_exact, attribution_partial = (
            self._compute_attribution_accuracy(valid_attack_results)
        )

        # PCEPS Brier score (from scenario_label.pceps_probability if present).
        brier = self._compute_brier_score(scenario_results)

        # FP/hr.
        total_benign_s = sum(
            p.duration_s
            for r in benign_results
            for p in r.phases
            if p.name in ("baseline", "attack", "post_recovery")
        )

        report = _build_report(
            detector_name=self._phantom_name,
            tp=tp,
            fp=fp,
            fn=fn,
            tn=tn,
            n_attack=len(valid_attack_results),
            n_benign=len(benign_results),
            mttd_values=mttd_values,
            total_benign_s=total_benign_s,
            cpu_overhead_pct=cpu_overhead_pct,
            memory_overhead_mb=memory_overhead_mb,
            event_lag_p95_ms=event_lag_p95,
            overhead_status=overhead_status,
            status=("ground_truth_unavailable" if not eligible_results and unresolved_ground_truth else "evaluated"),
            notes=(f"Excluded {len(unresolved_ground_truth)} run(s) with unverified contract state." if unresolved_ground_truth else ""),
            excluded_failed_injections=len(failed_attack_results),
        )
        report.attribution_accuracy = attribution_accuracy
        report.attribution_exact = attribution_exact
        report.attribution_partial = attribution_partial
        report.brier_score = brier
        return report

    # ------------------------------------------------------------------ #
    # Baseline evaluation                                                  #
    # ------------------------------------------------------------------ #

    def _evaluate_baseline(
        self,
        detector_name: str,
        detections: list[Detection],
        scenario_results: list[ScenarioResult],
    ) -> EvaluationReport:
        """Compute metrics for one baseline detector.

        Classifies each Detection as TP/FP by matching it to the
        scenario whose time window contains the detection timestamp,
        then checking whether the oracle injection_timestamp is before
        detected_at and within the detection window.

        If baseline telemetry is absent (detections is empty), classifies as
        'telemetry_unavailable' rather than fabricating False Negatives (FN=N, TPR=0.0).

        Args:
            detector_name: Detector name string.
            detections: All detections from this baseline.
            scenario_results: Oracle scenario results for window lookup.

        Returns:
            EvaluationReport for this baseline.
        """
        eligible_results = [
            r for r in scenario_results
            if (r.scenario_label or {}).get("ground_truth_status") != "unknown_contract_state"
        ]
        attack_results = [r for r in eligible_results if r.ground_truth_label == 1]
        benign_results = [r for r in eligible_results if r.ground_truth_label == 0]

        valid_attack_results = [r for r in attack_results if not is_failed_injection(r)]
        failed_attack_results = [r for r in attack_results if is_failed_injection(r)]

        is_trivy = "trivy" in detector_name.lower()
        if not detections:
            status = "task_mismatch_and_telemetry_unavailable" if is_trivy else "telemetry_unavailable"
            return EvaluationReport(
                detector_name=detector_name,
                n_attack_scenarios=len(valid_attack_results),
                n_benign_scenarios=len(benign_results),
                excluded_failed_injections=len(failed_attack_results),
                tp=None,
                fp=None,
                fn=None,
                tn=None,
                tpr=None,
                tpr_ci_wilson=None,
                fpr=None,
                precision=None,
                recall=None,
                f1=None,
                false_positives_per_hour=None,
                mttd_mean_s=None,
                mttd_p50_s=None,
                mttd_median_s=None,
                mttd_iqr_s=None,
                mttd_p95_s=None,
                mttd_ci_bootstrap=None,
                mttd_values_s=[],
                overhead_status="unmeasured",
                cpu_overhead_pct=None,
                memory_overhead_mb=None,
                event_lag_p95_ms=None,
                status=status,
                notes=status,
            )

        # Build a lookup from scenario attack phase windows for valid attacks.
        attack_windows: list[tuple[ScenarioResult, datetime, datetime, float]] = []
        for r in valid_attack_results:
            attack_phase = next(
                (p for p in r.phases if p.name == "attack"), None
            )
            if attack_phase and attack_phase.start_time and attack_phase.end_time:
                window_s = float(
                    r.scenario_label.get("detection_window_s", self._default_window_s)
                )
                attack_windows.append(
                    (r, attack_phase.start_time, attack_phase.end_time, window_s)
                )

        benign_windows: list[tuple[ScenarioResult, datetime, datetime]] = []
        for r in benign_results:
            for phase in r.phases:
                if phase.name in ("baseline", "attack", "post_recovery"):
                    if phase.start_time and phase.end_time:
                        benign_windows.append((r, phase.start_time, phase.end_time))

        # Classify detections.
        tp_runs: set[str] = set()   # run_id of attack scenarios with TP
        fp_count = 0

        for det in detections:
            classified = False
            # Check against attack windows.
            for r, phase_start, phase_end, window_s in attack_windows:
                if not (phase_start <= det.detected_at <= phase_end):
                    continue
                # Is this within the detection window after injection?
                if r.injection_timestamp is None:
                    continue
                delta = (det.detected_at - r.injection_timestamp).total_seconds()
                if 0 <= delta <= window_s:
                    tp_runs.add(r.run_id)
                    classified = True
                    break

            if not classified:
                # Check against benign windows.
                for _r, phase_start, phase_end in benign_windows:
                    if phase_start <= det.detected_at <= phase_end:
                        fp_count += 1
                        classified = True
                        break

        # Collect MTTD for TP runs.
        mttd_values_final: list[float] = []
        for r, phase_start, phase_end, window_s in attack_windows:
            if r.run_id not in tp_runs:
                continue
            # Find earliest detection in this attack window.
            dets_in_window = [
                d for d in detections
                if (
                    phase_start <= d.detected_at <= phase_end
                    and r.injection_timestamp is not None
                    and 0 <= (d.detected_at - r.injection_timestamp).total_seconds() <= window_s
                )
            ]
            if dets_in_window:
                earliest = min(dets_in_window, key=lambda d: d.detected_at)
                delta = (earliest.detected_at - r.injection_timestamp).total_seconds()
                mttd_values_final.append(delta)

        tp = len(tp_runs)
        fn = len(valid_attack_results) - tp
        fp = fp_count if benign_results else None
        tn = max(0, len(benign_results) - fp_count) if benign_results else None

        total_benign_s = sum(
            (p.end_time - p.start_time).total_seconds()
            for r in benign_results
            for p in r.phases
            if p.name in ("baseline", "attack", "post_recovery")
            and p.start_time and p.end_time
        )

        return _build_report(
            detector_name=detector_name,
            tp=tp,
            fp=fp,
            fn=fn,
            tn=tn,
            n_attack=len(valid_attack_results),
            n_benign=len(benign_results),
            mttd_values=mttd_values_final,
            total_benign_s=total_benign_s,
            cpu_overhead_pct=None,
            memory_overhead_mb=None,
            event_lag_p95_ms=None,
            overhead_status="unmeasured",
            status="evaluated",
            excluded_failed_injections=len(failed_attack_results),
        )

    # ------------------------------------------------------------------ #
    # PHANTOM-specific metric helpers                                      #
    # ------------------------------------------------------------------ #

    def _compute_attribution_accuracy(
        self,
        attack_results: list[ScenarioResult],
    ) -> tuple[float | None, float | None, float | None]:
        """Compute causal attribution accuracy from scenario labels.

        Uses scenario_label fields:
            top_attributed_purl: str   — PHANTOM's top causal attribution
            top3_attributed_purls: list[str]  — PHANTOM's top-3 attributions
            ground_truth_purl: str     — from oracle manifest

        Credit assignment (handoff §4):
            exact: top_attributed_purl == ground_truth_purl → 1.0
            partial: oracle in top-3 AND in same dep chain → 0.5
            else → 0.0

        Args:
            attack_results: Attack scenario ScenarioResult list.

        Returns:
            (overall_accuracy, exact_rate, partial_rate) or (None, None, None)
            if attribution data is not available.
        """
        credits: list[float] = []
        exact_hits: list[float] = []
        partial_hits: list[float] = []

        for r in attack_results:
            if not r.is_true_positive:
                continue
            label = r.scenario_label
            truth_purl = label.get("ground_truth_purl") or label.get("target_purl", "")
            top_purl = label.get("top_attributed_purl", "")
            top3 = label.get("top3_attributed_purls", [])

            if not truth_purl:
                continue

            if top_purl and top_purl == truth_purl:
                credits.append(1.0)
                exact_hits.append(1.0)
                partial_hits.append(0.0)
            elif truth_purl in (top3 or []):
                credits.append(0.5)
                exact_hits.append(0.0)
                partial_hits.append(0.5)
            else:
                credits.append(0.0)
                exact_hits.append(0.0)
                partial_hits.append(0.0)

        if not credits:
            return None, None, None

        return (
            statistics.mean(credits),
            statistics.mean(exact_hits),
            statistics.mean(partial_hits),
        )

    def _compute_brier_score(
        self,
        scenario_results: list[ScenarioResult],
    ) -> float | None:
        """Compute PCEPS Brier score from scenario labels.

        Looks for scenario_label fields:
            pceps_probability: float   — predicted exploit probability
            is_pre_compromise: bool    — oracle label (1 = positive)

        Returns:
            Brier score or None if data not available.
        """
        pairs: list[tuple[float, float]] = []
        for r in scenario_results:
            label = r.scenario_label
            prob = label.get("pceps_probability")
            is_pre = label.get("is_pre_compromise")
            if prob is not None and is_pre is not None:
                pairs.append((float(prob), float(int(is_pre))))

        if not pairs:
            return None

        n = len(pairs)
        brier = sum((p - y) ** 2 for p, y in pairs) / n
        return brier


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _safe_mean(values: list[float]) -> float:
    """Return mean of a non-empty list, or 0.0.

    Args:
        values: List of floats.

    Returns:
        Mean value or 0.0.
    """
    if not values:
        return 0.0
    return statistics.mean(values)


def _safe_percentile(values: list[float], percentile: float) -> float:
    """Return the p-th percentile of values, or 0.0.

    Uses linear interpolation.

    Args:
        values: List of floats.
        percentile: Percentile in [0, 100].

    Returns:
        Percentile value or 0.0.
    """
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    rank = (percentile / 100.0) * (n - 1)
    lower = int(rank)
    upper = min(lower + 1, n - 1)
    frac = rank - lower
    return sorted_vals[lower] + frac * (sorted_vals[upper] - sorted_vals[lower])


def _compute_mttd_stats(
    mttd_values: list[float],
    n_bootstrap: int = 2000,
    seed: int = 42,
) -> tuple[float | None, float | None, float | None, float | None, tuple[float, float] | None]:
    """Compute mean, median (p50), IQR, p95, and non-parametric bootstrap 95% CI for MTTD.

    Returns:
        (mean, median, iqr, p95, bootstrap_ci_95)
    """
    if not mttd_values:
        return None, None, None, None, None

    vals = sorted(mttd_values)
    n = len(vals)
    mean_val = statistics.mean(vals)
    median_val = statistics.median(vals)
    p95_val = _safe_percentile(vals, 95.0)

    q1 = _safe_percentile(vals, 25.0)
    q3 = _safe_percentile(vals, 75.0)
    iqr_val = q3 - q1

    if n < 2:
        bootstrap_ci = None
    else:
        rng = random.Random(seed)
        boot_means: list[float] = []
        for _ in range(n_bootstrap):
            sample = [vals[rng.randrange(n)] for _ in range(n)]
            boot_means.append(statistics.mean(sample))
        boot_means.sort()
        idx_low = int(0.025 * n_bootstrap)
        idx_high = int(0.975 * n_bootstrap)
        bootstrap_ci = (round(boot_means[idx_low], 2), round(boot_means[idx_high], 2))

    return (
        round(mean_val, 2),
        round(median_val, 2),
        round(iqr_val, 2),
        round(p95_val, 2),
        bootstrap_ci,
    )


def _build_report(
    detector_name: str,
    tp: int | None,
    fp: int | None,
    fn: int | None,
    tn: int | None,
    n_attack: int,
    n_benign: int,
    mttd_values: list[float],
    total_benign_s: float,
    cpu_overhead_pct: float | None = None,
    memory_overhead_mb: float | None = None,
    event_lag_p95_ms: float | None = None,
    overhead_status: str = "measured",
    status: str = "evaluated",
    notes: str = "",
    excluded_failed_injections: int = 0,
) -> EvaluationReport:
    """Build an EvaluationReport from raw counts.

    Computes derived metrics (TPR with Wilson CI, FPR, F1, MTTD stats with bootstrap CI, FP/hr).
    Preserves None for undefined denominators (no fabrication of 0.0 or 1.0).

    Args:
        detector_name: Detector name.
        tp, fp, fn, tn: Confusion matrix counts (or None).
        n_attack: Total eligible attack scenario runs.
        n_benign: Total benign scenario runs.
        mttd_values: Per-TP MTTD values in seconds.
        total_benign_s: Total benign monitoring duration in seconds.
        cpu_overhead_pct: CPU overhead % (or None if unmeasured).
        memory_overhead_mb: Memory overhead MB (or None if unmeasured).
        event_lag_p95_ms: P95 event lag ms (or None if unmeasured).
        overhead_status: 'measured' or 'unmeasured'.
        status: Evaluation status string.
        notes: Free-text notes.
        excluded_failed_injections: Number of failed injections excluded.

    Returns:
        EvaluationReport with all derived metrics filled.
    """
    denom_tpr = (tp + fn) if (tp is not None and fn is not None) else 0
    if denom_tpr > 0 and tp is not None:
        tpr = round(tp / denom_tpr, 4)
        recall = tpr
        ci = compute_ordinary_wilson_score(tp, denom_tpr, confidence=0.95)
        tpr_ci_wilson = (round(ci[0], 4), round(ci[1], 4)) if ci[0] is not None else None
    else:
        tpr = None
        recall = None
        tpr_ci_wilson = None

    denom_fpr = (fp + tn) if (fp is not None and tn is not None) else 0
    fpr = round(fp / denom_fpr, 4) if (denom_fpr > 0 and fp is not None) else None

    denom_prec = (tp + fp) if (tp is not None and fp is not None) else 0
    precision = round(tp / denom_prec, 4) if (denom_prec > 0 and tp is not None) else None

    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = round(2.0 * precision * recall / (precision + recall), 4)
    else:
        f1 = None

    if fp is not None and total_benign_s > 0:
        fp_per_hour = round(fp / (total_benign_s / 3600.0), 4)
    else:
        fp_per_hour = None

    mttd_mean, mttd_median, mttd_iqr, mttd_p95, mttd_boot_ci = _compute_mttd_stats(mttd_values)

    return EvaluationReport(
        detector_name=detector_name,
        n_attack_scenarios=n_attack,
        n_benign_scenarios=n_benign,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        tpr=tpr,
        tpr_ci_wilson=tpr_ci_wilson,
        fpr=fpr,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positives_per_hour=fp_per_hour,
        mttd_mean_s=mttd_mean,
        mttd_p50_s=mttd_median,
        mttd_median_s=mttd_median,
        mttd_iqr_s=mttd_iqr,
        mttd_p95_s=mttd_p95,
        mttd_ci_bootstrap=mttd_boot_ci,
        mttd_values_s=mttd_values,
        overhead_status=overhead_status,
        cpu_overhead_pct=round(cpu_overhead_pct, 2) if cpu_overhead_pct is not None else None,
        memory_overhead_mb=round(memory_overhead_mb, 2) if memory_overhead_mb is not None else None,
        event_lag_p95_ms=round(event_lag_p95_ms, 2) if event_lag_p95_ms is not None else None,
        status=status,
        excluded_failed_injections=excluded_failed_injections,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Public alias — DetectorMetrics
# ---------------------------------------------------------------------------
# EvaluationReport is the canonical name in this codebase; DetectorMetrics is
# the name used in the evaluation spec (SUB-TASK 8B) and comparison_table.py.
# Both refer to the same dataclass so downstream code can use either name.

DetectorMetrics = EvaluationReport
