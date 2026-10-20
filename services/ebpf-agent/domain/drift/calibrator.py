"""
services/ebpf-agent/domain/drift/calibrator.py

Empirical threshold calibration for the PHANTOM drift detector.

Calibration procedure:
    1. Score a set of *independent* benign-baseline observation windows
       using the same MarkovModel (contract) that will be used at inference.
    2. Sort the resulting KL scores in ascending order.
    3. Choose the empirical upper quantile at the configured level.
    4. That quantile value becomes the drift threshold stored in the config.

Assumptions (must be met for the threshold to be scientifically valid):
    - All calibration windows come from benign, ground-truth-labelled
      baseline periods (never from attack windows or unlabelled data).
    - Calibration windows are exchangeable with future benign windows:
      same workload, same image digest, same contract version, same
      deployment environment.
    - Attack windows must be completely excluded from calibration input.
      Mixing attack data with calibration data would bias the threshold
      upward, increasing false-negative rate.
    - The calibration split must be held out from training (the Markov
      model must not have been trained on the calibration windows).
    - The calibration split must be held out from evaluation (the same
      windows must never appear in the test set).

This is NOT conformal calibration.  The procedure is a simple empirical
upper-quantile threshold.  Conformal coverage guarantees require
exchangeability across both calibration and test sets; that assumption
is documented here but its validity for a live eBPF workload remains
unverified.

Current status:
    No real benign calibration windows from the PHANTOM evaluation are
    available in the repository.  When calibrate() is called with fewer
    than config.min_calibration_windows scored windows, it returns a
    CalibrationResult with is_valid=False and documents the reason.
    The default threshold remains float('inf') until valid calibration
    is performed.

Usage::

    from domain.drift.calibrator import ThresholdCalibrator
    from domain.drift.config import DriftDetectorConfig

    cfg = DriftDetectorConfig()
    calibrator = ThresholdCalibrator(model, cfg)

    # Score each benign baseline window:
    scores = calibrator.score_windows(benign_windows, loss_flags)

    # Compute threshold (may return is_valid=False if too few windows):
    result = calibrator.calibrate(scores)
    if result.is_valid:
        cfg.threshold = result.threshold
        cfg.threshold_version = result.threshold_version
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from domain.drift.config import DriftDetectorConfig
from domain.drift.kl_scorer import KlDriftScorer
from domain.markov.chain import MarkovModel, Token


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class CalibrationResult:
    """Result of a calibration run.

    Attributes:
        is_valid: True iff the calibration succeeded and the threshold
            can be used.  False when insufficient windows were provided.
        threshold: The computed threshold value.  float('inf') when
            is_valid=False.
        threshold_version: A sha256-derived version string that changes
            whenever the calibration inputs change.  "uncalibrated" when
            is_valid=False.
        n_windows: Number of scored windows provided as calibration input.
        quantile: The quantile used (from config.calibration_quantile).
        score_min: Minimum scored value (NaN when is_valid=False).
        score_max: Maximum scored value (NaN when is_valid=False).
        score_mean: Arithmetic mean of scores (NaN when is_valid=False).
        calibrated_at: UTC timestamp of calibration (None when is_valid=False).
        reason_invalid: Non-empty when is_valid=False.
        notes: Human-readable summary of calibration assumptions.
    """

    is_valid: bool
    threshold: float
    threshold_version: str
    n_windows: int
    quantile: float
    score_min: float
    score_max: float
    score_mean: float
    calibrated_at: Optional[datetime]
    reason_invalid: str = ""
    notes: str = (
        "Empirical upper-quantile threshold.  "
        "Assumes calibration windows are exchangeable with future benign "
        "traffic on the same contract.  Attack windows MUST be excluded.  "
        "This is not conformal calibration; coverage guarantees are not provided."
    )


# ---------------------------------------------------------------------------
# Calibrator
# ---------------------------------------------------------------------------


class ThresholdCalibrator:
    """Computes an empirical upper-quantile threshold from benign baseline scores.

    Args:
        model: The trained MarkovModel used for scoring.
        config: DriftDetectorConfig controlling quantile and minimums.
    """

    def __init__(
        self,
        model: MarkovModel,
        config: DriftDetectorConfig,
    ) -> None:
        """Initialise the calibrator.

        Args:
            model: The behavioral contract model to score windows with.
            config: Configuration controlling quantile and min windows.
        """
        self._model = model
        self._cfg = config
        self._scorer = KlDriftScorer(
            model, loss_penalty_factor=config.loss_penalty_factor
        )

    def score_windows(
        self,
        windows: list[list[Token]],
        loss_flags: Optional[list[bool]] = None,
    ) -> list[float]:
        """Score a list of observation windows with the contract model.

        Intended for calibration use only.  Do not include attack windows
        in the input; doing so will bias the threshold upward.

        Args:
            windows: List of tokenised observation windows.  Each window
                is a list of Tokens from a benign baseline period.
            loss_flags: Optional per-window loss indicators.  Defaults to
                all-False.

        Returns:
            A list of final_score floats, one per window.
            Windows with fewer than config.min_observation_tokens tokens
            are scored as NaN and should be excluded from calibration.
        """
        if loss_flags is None:
            loss_flags = [False] * len(windows)
        if len(loss_flags) != len(windows):
            raise ValueError(
                f"loss_flags length {len(loss_flags)} != windows length {len(windows)}"
            )

        scores: list[float] = []
        for window, loss in zip(windows, loss_flags):
            if len(window) < self._cfg.min_observation_tokens:
                scores.append(float("nan"))
            else:
                result = self._scorer.score(window, loss_observed=loss)
                # Apply novelty term if configured.
                adjusted = result.final_score + (
                    self._cfg.novelty_weight * result.novel_token_fraction
                )
                scores.append(adjusted)
        return scores

    def calibrate(self, scores: list[float]) -> CalibrationResult:
        """Compute the empirical upper-quantile threshold from scored windows.

        Args:
            scores: List of scores from score_windows().  NaN values are
                silently excluded (they represent too-short windows).

        Returns:
            A CalibrationResult.  If is_valid=False, the threshold is
            float('inf') and threshold_version is "uncalibrated".
        """
        # Filter out NaN values (too-short windows).
        valid_scores = sorted(s for s in scores if not math.isnan(s))
        n = len(valid_scores)

        if n < self._cfg.min_calibration_windows:
            return CalibrationResult(
                is_valid=False,
                threshold=float("inf"),
                threshold_version="uncalibrated",
                n_windows=n,
                quantile=self._cfg.calibration_quantile,
                score_min=float("nan"),
                score_max=float("nan"),
                score_mean=float("nan"),
                calibrated_at=None,
                reason_invalid=(
                    f"Only {n} valid calibration windows provided; "
                    f"minimum required is {self._cfg.min_calibration_windows}.  "
                    "Threshold cannot be set.  No real benign calibration dataset "
                    "is currently available in this repository.  "
                    "Run benign baseline scenarios and collect scored windows "
                    "before attempting calibration."
                ),
            )

        # Empirical upper quantile.
        threshold = _quantile(valid_scores, self._cfg.calibration_quantile)
        score_mean = sum(valid_scores) / n

        # Version the threshold by hashing the sorted input values.
        digest = hashlib.sha256(
            json.dumps(valid_scores, sort_keys=True).encode()
        ).hexdigest()[:16]
        version = f"empirical-q{self._cfg.calibration_quantile:.3f}-{digest}"

        return CalibrationResult(
            is_valid=True,
            threshold=threshold,
            threshold_version=version,
            n_windows=n,
            quantile=self._cfg.calibration_quantile,
            score_min=valid_scores[0],
            score_max=valid_scores[-1],
            score_mean=score_mean,
            calibrated_at=datetime.now(tz=timezone.utc),
            reason_invalid="",
        )


# ---------------------------------------------------------------------------
# Linear-interpolation quantile (no scipy dependency)
# ---------------------------------------------------------------------------


def _quantile(sorted_values: list[float], q: float) -> float:
    """Compute the q-th quantile using linear interpolation.

    Equivalent to numpy.percentile(sorted_values, q * 100,
    interpolation='linear').

    Args:
        sorted_values: Sorted list of floats (ascending).  Must be non-empty.
        q: Quantile in [0, 1].

    Returns:
        The interpolated quantile value.

    Raises:
        ValueError: If sorted_values is empty or q is outside [0, 1].
    """
    if not sorted_values:
        raise ValueError("sorted_values must not be empty")
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"q must be in [0, 1], got {q}")

    n = len(sorted_values)
    if n == 1:
        return sorted_values[0]

    # Linear interpolation index.
    idx = q * (n - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_values[lo]
    frac = idx - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac
