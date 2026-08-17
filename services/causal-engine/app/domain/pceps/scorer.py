"""
causal-engine domain PCEPS scorer.

XGBoost inference with Platt scaling calibration for PCEPS priority scoring.

Implements the scoring side of Algorithm 5 §7.4:
1. Accept a PcepsFeatureVector (16 features + mask).
2. Concatenate (features, mask) for model input.
3. Run XGBoost predict_proba → p_raw.
4. Apply Platt scaling: p_cal = sigmoid(a * logit(clamp(p_raw)) + b).
5. PCEPS = 100 * p_cal.
6. Map to pre-registered severity band.

XGBoost is used for priority ranking ONLY; it is not causal evidence.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np
import structlog

from app.domain.entities import (
    PcepsCalibration,
    PcepsFeatureVector,
    PcepsScore,
    PcepsSeverity,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Platt scaling helpers
# ---------------------------------------------------------------------------

_CLAMP_EPS: float = 1e-7
"""Clamp epsilon to avoid logit(0) or logit(1)."""


def _clamp(p: float) -> float:
    """Clamp a probability to (ε, 1-ε).

    Args:
        p: Raw probability.

    Returns:
        Clamped probability.
    """
    return max(_CLAMP_EPS, min(1.0 - _CLAMP_EPS, p))


def _logit(p: float) -> float:
    """Compute the logit (log-odds) of a probability.

    Args:
        p: Probability in (0, 1).

    Returns:
        logit(p) = log(p / (1-p)).
    """
    return math.log(p / (1.0 - p))


def _sigmoid(x: float) -> float:
    """Compute the sigmoid function.

    Args:
        x: Input value.

    Returns:
        sigmoid(x) = 1 / (1 + exp(-x)).
    """
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    else:
        exp_x = math.exp(x)
        return exp_x / (1.0 + exp_x)


def platt_calibrate(p_raw: float, a: float, b: float) -> float:
    """Apply Platt scaling to a raw probability.

    p_cal = sigmoid(a * logit(clamp(p_raw)) + b)

    Per handoff §7.2: two-parameter calibration using sigmoid.

    Args:
        p_raw: Raw XGBoost probability.
        a: Platt slope parameter.
        b: Platt intercept parameter.

    Returns:
        Calibrated probability.
    """
    clamped = _clamp(p_raw)
    return _sigmoid(a * _logit(clamped) + b)


# ---------------------------------------------------------------------------
# Severity mapping (§7.4 line 15)
# ---------------------------------------------------------------------------

# Pre-registered operating points on the validation set.
_SEVERITY_THRESHOLDS: list[tuple[float, PcepsSeverity]] = [
    (80.0, PcepsSeverity.CRITICAL),
    (60.0, PcepsSeverity.HIGH),
    (40.0, PcepsSeverity.MEDIUM),
    (20.0, PcepsSeverity.LOW),
    (0.0, PcepsSeverity.INFO),
]


def map_score_to_severity(score: float) -> PcepsSeverity:
    """Map a PCEPS score to a pre-registered severity band.

    Args:
        score: PCEPS score in [0, 100].

    Returns:
        A PcepsSeverity enum value.
    """
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return PcepsSeverity.INFO


# ---------------------------------------------------------------------------
# PCEPS Scorer
# ---------------------------------------------------------------------------


class PcepsScorer:
    """Calibrated XGBoost PCEPS scorer.

    Wraps a trained XGBoost model with Platt calibration parameters.

    Args:
        xgb_model: A trained XGBoost Booster or XGBClassifier model.
        calibration: Platt scaling parameters (a, b).
        model_version: Version identifier string.
    """

    def __init__(
        self,
        xgb_model: Any,  # noqa: ANN401
        calibration: PcepsCalibration,
        model_version: str = "v0.1.0",
    ) -> None:
        """Initialise the scorer.

        Args:
            xgb_model: Trained XGBoost model with predict_proba().
            calibration: Platt scaling parameters.
            model_version: Model version identifier.
        """
        self._model = xgb_model
        self._calibration = calibration
        self._model_version = model_version

    def score(self, features: PcepsFeatureVector) -> PcepsScore:
        """Score a PCEPS feature vector.

        Implements §7.4 lines 12–16:
        1. Concatenate (features, mask) → 32-dim input.
        2. XGBoost predict_proba → p_raw.
        3. Platt calibrate → p_cal.
        4. PCEPS = 100 * p_cal.
        5. Map to severity band.

        Args:
            features: The 16-feature vector with mask.

        Returns:
            A PcepsScore with score, severity, raw/calibrated probability,
            completeness, imputed features, and provenance.
        """
        # Build model input: 16 features + 16 mask booleans = 32 dims.
        input_values = features.values + [1.0 if m else 0.0 for m in features.mask]
        input_array = np.array([input_values], dtype=np.float32)

        # XGBoost inference.
        try:
            if hasattr(self._model, "predict_proba"):
                # XGBClassifier interface.
                proba = self._model.predict_proba(input_array)
                p_raw = float(proba[0, 1])  # Probability of positive class.
            elif hasattr(self._model, "predict"):
                # Raw Booster interface.
                import xgboost as xgb

                dmatrix = xgb.DMatrix(input_array)
                p_raw = float(self._model.predict(dmatrix)[0])
            else:
                raise ValueError("Model has no predict_proba or predict method")
        except Exception as exc:
            log.error("pceps_scorer.inference_failed", error=str(exc))
            raise

        # Platt calibration (§7.2).
        p_cal = platt_calibrate(p_raw, self._calibration.a, self._calibration.b)

        # PCEPS score (§7.4 line 14).
        pceps_score = 100.0 * p_cal
        severity = map_score_to_severity(pceps_score)

        return PcepsScore(
            score=pceps_score,
            severity=severity,
            raw_probability=p_raw,
            calibrated_probability=p_cal,
            feature_completeness=features.feature_completeness,
            imputed_features=features.imputed_feature_names,
            model_version=self._model_version,
            calibration=self._calibration,
        )
