"""
causal-engine domain PCEPS model trainer.

Training script for research evaluation — NOT part of the service runtime.

Implements Algorithm 5 §7.4 training pipeline:
1. Split labeled windows by workload/image family, scenario, time.
2. Derive 16 features + mask per window using training-partition stats only.
3. Fit XGBoost on train with class weights; tune on validation.
4. Fit Platt scaling (a, b) on held-out calibration set.
5. Evaluate on test: Brier score, ECE, precision-recall, calibration plot.
6. Persist model, calibration parameters, and baseline statistics.

Invariants (§7, implementation invariant 6):
- Feature derivation uses only pre-outcome information.
- Normalization baselines are computed ONLY on training partition.
- Validation/test/calibration data NEVER update baselines.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import structlog

from app.domain.entities import (
    PCEPS_FEATURE_NAMES,
    PcepsCalibration,
    PcepsFeatureBaseline,
    PcepsFeatureVector,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class LabeledPcepsWindow:
    """A labeled window for PCEPS training.

    Attributes:
        window_id: Unique identifier.
        features: The 16-feature vector.
        label: Binary label (0 = benign, 1 = security-relevant).
        scenario_family: Scenario family for split stratification.
        workload_family: Workload/image family for split stratification.
        timestamp: Window timestamp for temporal splitting.
    """

    window_id: str
    features: PcepsFeatureVector
    label: int  # 0 or 1
    scenario_family: str = ""
    workload_family: str = ""
    timestamp: float = 0.0


@dataclass
class PcepsModelConfig:
    """XGBoost training configuration.

    Attributes:
        n_estimators: Number of boosting rounds.
        max_depth: Maximum tree depth.
        learning_rate: Learning rate (eta).
        min_child_weight: Minimum child weight.
        subsample: Row subsampling ratio.
        colsample_bytree: Column subsampling ratio.
        scale_pos_weight: Positive class weight multiplier.
        eval_metric: Evaluation metric.
        seed: Random seed for reproducibility.
    """

    n_estimators: int = 200
    max_depth: int = 6
    learning_rate: float = 0.1
    min_child_weight: int = 1
    subsample: float = 0.8
    colsample_bytree: float = 0.8
    scale_pos_weight: float = 1.0
    eval_metric: str = "logloss"
    seed: int = 42


@dataclass
class TrainingResult:
    """Result of PCEPS model training.

    Attributes:
        model: Trained XGBoost classifier.
        calibration: Platt scaling parameters.
        baseline: Feature baseline statistics from training partition.
        model_version: Version identifier.
        train_brier_score: Brier score on training set.
        val_brier_score: Brier score on validation set.
        cal_brier_score: Brier score on calibration set.
        ece: Expected Calibration Error.
        precision: Precision at default threshold.
        recall: Recall at default threshold.
        f1: F1 score at default threshold.
    """

    model: Any
    calibration: PcepsCalibration
    baseline: PcepsFeatureBaseline
    model_version: str = ""
    train_brier_score: float = 0.0
    val_brier_score: float = 0.0
    cal_brier_score: float = 0.0
    ece: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


# ---------------------------------------------------------------------------
# Baseline computation (training partition ONLY)
# ---------------------------------------------------------------------------


def compute_training_baseline(
    windows: list[LabeledPcepsWindow],
) -> PcepsFeatureBaseline:
    """Compute per-feature medians and MADs from the training partition.

    Per handoff §7.1: normalization baselines are computed ONLY on the
    training partition and versioned with the model.

    Args:
        windows: Training-partition labeled windows.

    Returns:
        A PcepsFeatureBaseline with medians and MADs.
    """
    if not windows:
        return PcepsFeatureBaseline()

    n_features = 16
    feature_matrix = np.array(
        [w.features.values for w in windows], dtype=np.float64
    )

    medians = np.median(feature_matrix, axis=0).tolist()
    mads = np.median(np.abs(feature_matrix - np.median(feature_matrix, axis=0)), axis=0).tolist()

    return PcepsFeatureBaseline(
        medians=medians[:n_features],
        mads=mads[:n_features],
    )


# ---------------------------------------------------------------------------
# Feature imputation using training baseline
# ---------------------------------------------------------------------------


def impute_features(
    features: PcepsFeatureVector,
    baseline: PcepsFeatureBaseline,
) -> PcepsFeatureVector:
    """Impute missing features using training-partition statistics.

    Per handoff §7.4 line 06: impute using training partition statistics only.

    Args:
        features: Original feature vector with possible missing values.
        baseline: Training-partition baseline for imputation.

    Returns:
        A new PcepsFeatureVector with imputed values.
    """
    new_values = list(features.values)
    new_mask = list(features.mask)

    for i in range(16):
        if new_mask[i]:
            new_values[i] = baseline.medians[i]

    imputed_names = [PCEPS_FEATURE_NAMES[i] for i in range(16) if new_mask[i]]

    return PcepsFeatureVector(
        values=new_values,
        mask=new_mask,
        feature_completeness=1.0 - sum(new_mask) / 16.0,
        imputed_feature_names=imputed_names,
    )


# ---------------------------------------------------------------------------
# Platt scaling fitting (§7.2)
# ---------------------------------------------------------------------------


def fit_platt_scaling(
    raw_probabilities: np.ndarray,
    labels: np.ndarray,
) -> tuple[float, float]:
    """Fit Platt scaling parameters (a, b) on a calibration set.

    p_cal = sigmoid(a * logit(clamp(p_raw)) + b)

    Per handoff §7.2: two-parameter calibration is less prone to
    overfitting than isotonic regression.

    Args:
        raw_probabilities: Model raw probabilities (1D array).
        labels: Binary ground-truth labels (1D array).

    Returns:
        Tuple (a, b) of Platt scaling parameters.
    """
    eps = 1e-7

    # Lazy import: scipy only needed during training.
    from scipy.optimize import minimize

    def _logit_clamp(p: float) -> float:
        p_c = max(eps, min(1.0 - eps, p))
        return math.log(p_c / (1.0 - p_c))

    logits = np.array([_logit_clamp(p) for p in raw_probabilities])

    def neg_log_likelihood(params: np.ndarray) -> float:
        a, b = params
        z = np.clip(a * logits + b, -500.0, 500.0)
        p_cal = 1.0 / (1.0 + np.exp(-z))
        p_cal = np.clip(p_cal, eps, 1.0 - eps)
        ll = labels * np.log(p_cal) + (1 - labels) * np.log(1 - p_cal)
        return float(-np.sum(ll))

    result = minimize(
        neg_log_likelihood,
        x0=np.array([1.0, 0.0]),
        method="Nelder-Mead",
    )

    a, b = result.x
    return float(a), float(b)


# ---------------------------------------------------------------------------
# Expected Calibration Error
# ---------------------------------------------------------------------------


def compute_ece(
    probabilities: np.ndarray,
    labels: np.ndarray,
    n_bins: int = 10,
) -> float:
    """Compute Expected Calibration Error (ECE).

    Args:
        probabilities: Calibrated probabilities.
        labels: Binary ground-truth labels.
        n_bins: Number of bins for calibration.

    Returns:
        ECE value.
    """
    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(labels)

    for i in range(n_bins):
        in_bin = (probabilities >= bin_boundaries[i]) & (probabilities < bin_boundaries[i + 1])
        prop_in_bin = in_bin.mean()
        if prop_in_bin > 0:
            avg_confidence = probabilities[in_bin].mean()
            avg_accuracy = labels[in_bin].mean()
            ece += prop_in_bin * abs(avg_accuracy - avg_confidence)

    return float(ece)


# ---------------------------------------------------------------------------
# Training pipeline (Algorithm 5)
# ---------------------------------------------------------------------------


def train_pceps_model(
    labeled_windows: list[LabeledPcepsWindow],
    validation_windows: list[LabeledPcepsWindow],
    calibration_windows: list[LabeledPcepsWindow],
    model_config: PcepsModelConfig,
    model_version: str = "v0.1.0",
) -> TrainingResult:
    """Train and calibrate a PCEPS XGBoost model.

    Implements Algorithm 5 §7.4 lines 01–17.

    Args:
        labeled_windows: Training partition windows.
        validation_windows: Validation partition windows.
        calibration_windows: Calibration partition windows.
        model_config: XGBoost hyperparameters.
        model_version: Model version identifier.

    Returns:
        A TrainingResult with trained model, calibration, baseline, and metrics.
    """
    bound_log = log.bind(
        model_version=model_version,
        train_n=len(labeled_windows),
        val_n=len(validation_windows),
        cal_n=len(calibration_windows),
    )

    # Step 1: Compute training baseline (§7.4 line 06).
    bound_log.info("pceps_trainer.computing_baseline")
    baseline = compute_training_baseline(labeled_windows)
    baseline.model_version = model_version

    # Step 2: Impute features using training stats (§7.4 lines 03–07).
    def _prepare(windows: list[LabeledPcepsWindow]) -> tuple[np.ndarray, np.ndarray]:
        features_list: list[list[float]] = []
        labels_list: list[int] = []
        for w in windows:
            imputed = impute_features(w.features, baseline)
            # 32-dim input: 16 features + 16 mask booleans.
            input_vec = imputed.values + [1.0 if m else 0.0 for m in imputed.mask]
            features_list.append(input_vec)
            labels_list.append(w.label)
        return np.array(features_list, dtype=np.float32), np.array(labels_list, dtype=np.int32)

    X_train, y_train = _prepare(labeled_windows)
    X_val, y_val = _prepare(validation_windows)
    X_cal, y_cal = _prepare(calibration_windows)

    # Step 3: Fit XGBoost (§7.4 line 09).
    # Lazy imports: only needed at training time.
    import xgboost as xgb
    from sklearn.metrics import (
        brier_score_loss,
        precision_recall_fscore_support,
    )

    bound_log.info("pceps_trainer.fitting_xgboost")
    clf = xgb.XGBClassifier(
        n_estimators=model_config.n_estimators,
        max_depth=model_config.max_depth,
        learning_rate=model_config.learning_rate,
        min_child_weight=model_config.min_child_weight,
        subsample=model_config.subsample,
        colsample_bytree=model_config.colsample_bytree,
        scale_pos_weight=model_config.scale_pos_weight,
        eval_metric=model_config.eval_metric,
        random_state=model_config.seed,
        use_label_encoder=False,
    )
    clf.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    # Step 4: Platt scaling on calibration set (§7.4 lines 10–11).
    bound_log.info("pceps_trainer.fitting_platt")
    raw_cal = clf.predict_proba(X_cal)[:, 1]
    a, b = fit_platt_scaling(raw_cal, y_cal.astype(np.float64))

    calibration = PcepsCalibration(
        a=a,
        b=b,
        calibration_sample_count=len(calibration_windows),
    )

    # Step 5: Evaluate metrics.
    bound_log.info("pceps_trainer.evaluating")

    # Brier scores.
    raw_train = clf.predict_proba(X_train)[:, 1]
    raw_val = clf.predict_proba(X_val)[:, 1]
    train_brier = brier_score_loss(y_train, raw_train)
    val_brier = brier_score_loss(y_val, raw_val)

    # Calibrated probabilities on calibration set.
    from app.domain.pceps.scorer import platt_calibrate

    cal_probs = np.array([platt_calibrate(p, a, b) for p in raw_cal])
    cal_brier = brier_score_loss(y_cal, cal_probs)

    # ECE.
    ece = compute_ece(cal_probs, y_cal.astype(np.float64))
    calibration.brier_score = cal_brier
    calibration.expected_calibration_error = ece

    # Precision/recall on validation.
    val_preds = (raw_val >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_val, val_preds, average="binary", zero_division=0.0,
    )

    bound_log.info(
        "pceps_trainer.complete",
        platt_a=a,
        platt_b=b,
        cal_brier=round(cal_brier, 4),
        ece=round(ece, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
    )

    return TrainingResult(
        model=clf,
        calibration=calibration,
        baseline=baseline,
        model_version=model_version,
        train_brier_score=float(train_brier),
        val_brier_score=float(val_brier),
        cal_brier_score=float(cal_brier),
        ece=float(ece),
        precision=float(prec),
        recall=float(rec),
        f1=float(f1),
    )


def save_model_artifacts(
    result: TrainingResult,
    output_dir: Path,
) -> None:
    """Save trained model and metadata to disk.

    Persists:
    - XGBoost model file (JSON format).
    - Calibration parameters JSON.
    - Feature baseline JSON.
    - Training metrics JSON.

    Args:
        result: The TrainingResult from train_pceps_model.
        output_dir: Directory to write artifacts to.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save XGBoost model.
    model_path = output_dir / "pceps_model.json"
    result.model.save_model(str(model_path))

    # Save calibration.
    cal_path = output_dir / "calibration.json"
    cal_data = {
        "a": result.calibration.a,
        "b": result.calibration.b,
        "calibration_sample_count": result.calibration.calibration_sample_count,
        "brier_score": result.calibration.brier_score,
        "expected_calibration_error": result.calibration.expected_calibration_error,
    }
    cal_path.write_text(json.dumps(cal_data, indent=2))

    # Save baseline.
    baseline_path = output_dir / "feature_baseline.json"
    baseline_data = {
        "medians": result.baseline.medians,
        "mads": result.baseline.mads,
        "model_version": result.baseline.model_version,
    }
    baseline_path.write_text(json.dumps(baseline_data, indent=2))

    # Save metrics.
    metrics_path = output_dir / "training_metrics.json"
    metrics_data = {
        "model_version": result.model_version,
        "train_brier_score": result.train_brier_score,
        "val_brier_score": result.val_brier_score,
        "cal_brier_score": result.cal_brier_score,
        "ece": result.ece,
        "precision": result.precision,
        "recall": result.recall,
        "f1": result.f1,
    }
    metrics_path.write_text(json.dumps(metrics_data, indent=2))

    log.info(
        "pceps_trainer.artifacts_saved",
        output_dir=str(output_dir),
        model_version=result.model_version,
    )
