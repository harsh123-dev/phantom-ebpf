"""
causal-engine XGBoost PCEPS scoring adapter.

Implements the ScoringModelPort domain interface using a trained
XGBoost classifier that maps attribution evidence features to a
deterministic PCEPS priority score (0..100).
XGBoost is used for priority ranking only; it is not causal evidence.

The adapter loads a trained model and calibration parameters from disk
and wraps the PcepsScorer domain object.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from app.domain.entities import (
    PcepsCalibration,
    PcepsFeatureBaseline,
    PcepsFeatureVector,
    PcepsScore,
)
from app.domain.pceps.scorer import PcepsScorer
from app.domain.ports import ScoringModelPort

log: structlog.BoundLogger = structlog.get_logger(__name__)


class XGBoostScoringAdapter(ScoringModelPort):
    """XGBoost-backed PCEPS scoring adapter.

    Loads a trained model (JSON format) and Platt calibration parameters
    from a model directory and wraps PcepsScorer.

    Args:
        model_dir: Path to the directory containing pceps_model.json,
                   calibration.json, and feature_baseline.json.
    """

    def __init__(self, model_dir: Path) -> None:
        """Initialise and load the model artifacts.

        Args:
            model_dir: Path to model artifact directory.

        Raises:
            FileNotFoundError: If required model files are missing.
            RuntimeError: If XGBoost import fails.
        """
        self._model_dir = model_dir
        self._scorer: PcepsScorer | None = None
        self._baseline: PcepsFeatureBaseline | None = None

    async def _ensure_loaded(self) -> None:
        """Lazily load the model on first use.

        Raises:
            FileNotFoundError: If model files are not found.
            RuntimeError: If XGBoost is not installed.
        """
        if self._scorer is not None:
            return

        try:
            import xgboost as xgb
        except ImportError as exc:
            raise RuntimeError(
                "XGBoost is required for PCEPS scoring but not installed."
            ) from exc

        model_path = self._model_dir / "pceps_model.json"
        cal_path = self._model_dir / "calibration.json"
        baseline_path = self._model_dir / "feature_baseline.json"

        if not model_path.exists():
            raise FileNotFoundError(f"PCEPS model not found: {model_path}")
        if not cal_path.exists():
            raise FileNotFoundError(f"Calibration file not found: {cal_path}")
        if not baseline_path.exists():
            raise FileNotFoundError(f"Feature baseline not found: {baseline_path}")

        # Load model.
        clf = xgb.XGBClassifier()
        clf.load_model(str(model_path))

        # Load calibration.
        cal_data = json.loads(cal_path.read_text())
        calibration = PcepsCalibration(
            a=cal_data["a"],
            b=cal_data["b"],
            calibration_sample_count=cal_data.get("calibration_sample_count", 0),
            brier_score=cal_data.get("brier_score", 0.0),
            expected_calibration_error=cal_data.get("expected_calibration_error", 0.0),
        )

        # Load baseline.
        baseline_data = json.loads(baseline_path.read_text())
        self._baseline = PcepsFeatureBaseline(
            medians=baseline_data["medians"],
            mads=baseline_data["mads"],
            model_version=baseline_data.get("model_version", ""),
        )

        # Build scorer.
        self._scorer = PcepsScorer(
            xgb_model=clf,
            calibration=calibration,
            model_version=baseline_data.get("model_version", ""),
        )

        log.info(
            "xgboost_adapter.loaded",
            model_dir=str(self._model_dir),
            model_version=self._baseline.model_version,
        )

    async def score(self, features: PcepsFeatureVector) -> PcepsScore:
        """Score a feature vector via XGBoost + Platt calibration.

        Args:
            features: The 16-feature PCEPS vector with mask.

        Returns:
            A PcepsScore with score, severity, and provenance.
        """
        await self._ensure_loaded()
        assert self._scorer is not None
        return self._scorer.score(features)

    async def get_baseline(self) -> PcepsFeatureBaseline:
        """Load the training-partition feature baseline.

        Returns:
            The PcepsFeatureBaseline.
        """
        await self._ensure_loaded()
        assert self._baseline is not None
        return self._baseline


class MockPcepsScorer(ScoringModelPort):
    """Deterministic mock scorer for testing and development.

    Returns a fixed score based on f1 (causal effect) and f4 (KL divergence).
    Never loads any model files.

    Args:
        fixed_score: A fixed PCEPS score to return (default 50.0).
    """

    def __init__(self, fixed_score: float = 50.0) -> None:
        """Initialise with a fixed score.

        Args:
            fixed_score: Score to return from score().
        """
        from app.domain.pceps.scorer import map_score_to_severity

        self._score = fixed_score
        self._severity = map_score_to_severity(fixed_score)
        self._baseline = PcepsFeatureBaseline()

    async def score(self, features: PcepsFeatureVector) -> PcepsScore:
        """Return the fixed score.

        Args:
            features: Ignored in mock mode.

        Returns:
            A PcepsScore with the fixed score.
        """
        return PcepsScore(
            score=self._score,
            severity=self._severity,
            raw_probability=self._score / 100.0,
            calibrated_probability=self._score / 100.0,
            feature_completeness=features.feature_completeness,
            imputed_features=features.imputed_feature_names,
            model_version="mock",
        )

    async def get_baseline(self) -> PcepsFeatureBaseline:
        """Return an empty baseline.

        Returns:
            A default PcepsFeatureBaseline.
        """
        return self._baseline
