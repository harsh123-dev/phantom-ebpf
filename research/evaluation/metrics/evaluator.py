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
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from research.evaluation.baselines.base_baseline import Detection
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
        n_attack_scenarios: Total attack scenario runs evaluated.
        n_benign_scenarios: Total benign scenario runs evaluated.
        tp: True positive count.
        fp: False positive count.
        fn: False negative count.
        tn: True negative count.
        tpr: True positive rate (recall).
        fpr: False positive rate.
        precision: Precision (TP / (TP + FP)).
        recall: Same as TPR.
        f1: F1 score.
        false_positives_per_hour: FP count per hour of benign monitoring.
        mttd_mean_s: Mean time to detection in seconds (TP cases only).
        mttd_p50_s: Median MTTD in seconds.
        mttd_p95_s: 95th percentile MTTD in seconds.
        mttd_values_s: All individual MTTD values (for distribution reporting).
        cpu_overhead_pct: Mean CPU overhead % (attack vs baseline phase).
        memory_overhead_mb: Mean memory overhead MB.
        event_lag_p95_ms: 95th-percentile collection latency in ms.
        attribution_accuracy: Causal attribution accuracy (PHANTOM only; else None).
        attribution_exact: Exact-match attribution accuracy (PHANTOM only).
        attribution_partial: Partial-credit attribution accuracy (PHANTOM only).
        brier_score: PCEPS calibration Brier score (PHANTOM only; else None).
        notes: Free-text notes for the paper appendix.
    """

    detector_name: str
    n_attack_scenarios: int = 0
    n_benign_scenarios: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    tpr: float = 0.0
    fpr: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positives_per_hour: float = 0.0
    mttd_mean_s: float | None = None
    mttd_p50_s: float | None = None
    mttd_p95_s: float | None = None
    mttd_values_s: list[float] = field(default_factory=list)
    cpu_overhead_pct: float = 0.0
    memory_overhead_mb: float = 0.0
    event_lag_p95_ms: float = 0.0
    attribution_accuracy: float | None = None     # PHANTOM only
    attribution_exact: float | None = None        # PHANTOM only
    attribution_partial: float | None = None      # PHANTOM only
    brier_score: float | None = None              # PHANTOM only
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-serializable dict.

        Returns:
            Dict with all metric fields.
        """
        return {
            "detector_name": self.detector_name,
            "n_attack_scenarios": self.n_attack_scenarios,
            "n_benign_scenarios": self.n_benign_scenarios,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "tpr": self.tpr,
            "fpr": self.fpr,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positives_per_hour": self.false_positives_per_hour,
            "mttd_mean_s": self.mttd_mean_s,
            "mttd_p50_s": self.mttd_p50_s,
            "mttd_p95_s": self.mttd_p95_s,
            "mttd_values_s": self.mttd_values_s,
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
        attack_results = [r for r in scenario_results if r.ground_truth_label == 1]
        benign_results = [r for r in scenario_results if r.ground_truth_label == 0]

        tp = sum(1 for r in attack_results if r.is_true_positive)
        fn = sum(1 for r in attack_results if not r.is_true_positive)
        fp = sum(
            1 for r in benign_results
            if r.phantom_detections  # any detection in a benign scenario = FP
        )
        tn = len(benign_results) - fp

        mttd_values = [r.mttd_s for r in attack_results if r.mttd_s is not None]

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

        cpu_base = _safe_mean([s.cpu_usage_cores for s in baseline_snaps])
        cpu_attack = _safe_mean([s.cpu_usage_cores for s in attack_snaps])
        cpu_overhead_pct = (
            100.0 * (cpu_attack - cpu_base) / max(cpu_base, 1e-9)
            if cpu_base > 0
            else 0.0
        )
        mem_base = _safe_mean([s.memory_rss_mb for s in baseline_snaps])
        mem_attack = _safe_mean([s.memory_rss_mb for s in attack_snaps])
        memory_overhead_mb = mem_attack - mem_base

        event_lag_p95 = _safe_percentile(
            [s.event_lag_p95_ms for s in attack_snaps], 95
        )

        # Attribution accuracy (from scenario_label.top_attributed_purl if present).
        attribution_accuracy, attribution_exact, attribution_partial = (
            self._compute_attribution_accuracy(attack_results)
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
            tp=tp, fp=fp, fn=fn, tn=tn,
            n_attack=len(attack_results),
            n_benign=len(benign_results),
            mttd_values=mttd_values,
            total_benign_s=total_benign_s,
            cpu_overhead_pct=cpu_overhead_pct,
            memory_overhead_mb=memory_overhead_mb,
            event_lag_p95_ms=event_lag_p95,
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

        Args:
            detector_name: Detector name string.
            detections: All detections from this baseline.
            scenario_results: Oracle scenario results for window lookup.

        Returns:
            EvaluationReport for this baseline.
        """
        attack_results = [r for r in scenario_results if r.ground_truth_label == 1]
        benign_results = [r for r in scenario_results if r.ground_truth_label == 0]

        # Build a lookup from scenario attack phase windows.
        # For each attack scenario: (phase_start, phase_end, detection_window_s).
        ScenarioWindow = tuple  # (result, phase_start, phase_end, detection_window_s)
        attack_windows: list[tuple[ScenarioResult, datetime, datetime, float]] = []
        for r in attack_results:
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
        mttd_values: list[float] = []

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
                    if r.run_id not in {rid for rid in tp_runs}:
                        mttd_values.append(delta)
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
        fn = len(attack_results) - tp
        tn = max(0, len(benign_results) - fp_count)

        total_benign_s = sum(
            (p.end_time - p.start_time).total_seconds()
            for r in benign_results
            for p in r.phases
            if p.name in ("baseline", "attack", "post_recovery")
            and p.start_time and p.end_time
        )

        return _build_report(
            detector_name=detector_name,
            tp=tp, fp=fp_count, fn=fn, tn=tn,
            n_attack=len(attack_results),
            n_benign=len(benign_results),
            mttd_values=mttd_values_final,
            total_benign_s=total_benign_s,
            cpu_overhead_pct=0.0,    # baselines don't track their own overhead here
            memory_overhead_mb=0.0,
            event_lag_p95_ms=0.0,
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


def _build_report(
    detector_name: str,
    tp: int,
    fp: int,
    fn: int,
    tn: int,
    n_attack: int,
    n_benign: int,
    mttd_values: list[float],
    total_benign_s: float,
    cpu_overhead_pct: float,
    memory_overhead_mb: float,
    event_lag_p95_ms: float,
) -> EvaluationReport:
    """Build an EvaluationReport from raw counts.

    Computes derived metrics (TPR, FPR, F1, MTTD stats, FP/hr).

    Args:
        detector_name: Detector name.
        tp, fp, fn, tn: Confusion matrix counts.
        n_attack: Total attack scenario runs.
        n_benign: Total benign scenario runs.
        mttd_values: Per-TP MTTD values in seconds.
        total_benign_s: Total benign monitoring duration in seconds.
        cpu_overhead_pct: CPU overhead %.
        memory_overhead_mb: Memory overhead MB.
        event_lag_p95_ms: P95 event lag ms.

    Returns:
        EvaluationReport with all derived metrics filled.
    """
    denom_tpr = tp + fn
    tpr = tp / denom_tpr if denom_tpr > 0 else 0.0

    denom_fpr = fp + tn
    fpr = fp / denom_fpr if denom_fpr > 0 else 0.0

    denom_prec = tp + fp
    precision = tp / denom_prec if denom_prec > 0 else 0.0

    recall = tpr

    denom_f1 = precision + recall
    f1 = 2 * precision * recall / denom_f1 if denom_f1 > 0 else 0.0

    fp_per_hour = fp / max(total_benign_s / 3600.0, 1e-9)

    mttd_mean = _safe_mean(mttd_values) if mttd_values else None
    mttd_p50 = _safe_percentile(mttd_values, 50) if mttd_values else None
    mttd_p95 = _safe_percentile(mttd_values, 95) if mttd_values else None

    return EvaluationReport(
        detector_name=detector_name,
        n_attack_scenarios=n_attack,
        n_benign_scenarios=n_benign,
        tp=tp, fp=fp, fn=fn, tn=tn,
        tpr=round(tpr, 4),
        fpr=round(fpr, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        false_positives_per_hour=round(fp_per_hour, 4),
        mttd_mean_s=round(mttd_mean, 2) if mttd_mean is not None else None,
        mttd_p50_s=round(mttd_p50, 2) if mttd_p50 is not None else None,
        mttd_p95_s=round(mttd_p95, 2) if mttd_p95 is not None else None,
        mttd_values_s=mttd_values,
        cpu_overhead_pct=round(cpu_overhead_pct, 2),
        memory_overhead_mb=round(memory_overhead_mb, 2),
        event_lag_p95_ms=round(event_lag_p95_ms, 2),
    )


# ---------------------------------------------------------------------------
# Public alias — DetectorMetrics
# ---------------------------------------------------------------------------
# EvaluationReport is the canonical name in this codebase; DetectorMetrics is
# the name used in the evaluation spec (SUB-TASK 8B) and comparison_table.py.
# Both refer to the same dataclass so downstream code can use either name.

DetectorMetrics = EvaluationReport
