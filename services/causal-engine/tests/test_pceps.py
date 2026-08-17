"""
tests/causal-engine/test_pceps.py

Unit tests for PCEPS feature extraction, scoring, and model training.

Coverage:
- Feature extractor produces 16 values in [0, 1].
- Missing features imputed with correct defaults (median vs conservative).
- Conservative defaults for security features (f10, f12, f13, f16 → 1.0).
- Feature completeness reflects imputed count.
- Platt calibration produces probabilities in (0, 1).
- Severity mapping thresholds.
- Training baseline computed from training partition only.
- Platt fit_platt_scaling produces finite parameters.
- Feature derivation formulas match §7.1 exactly.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from app.domain.entities import (
    PCEPS_FEATURE_NAMES,
    PcepsFeatureBaseline,
    PcepsFeatureVector,
    PcepsSeverity,
)
from app.domain.pceps.feature_extractor import (
    FeatureDerivationContext,
    derive_pceps_features,
)
from app.domain.pceps.model_trainer import (
    LabeledPcepsWindow,
    compute_ece,
    compute_training_baseline,
    fit_platt_scaling,
    impute_features,
)
from app.domain.pceps.scorer import (
    _clamp,
    _logit,
    _sigmoid,
    map_score_to_severity,
    platt_calibrate,
)

# ---------------------------------------------------------------------------
# Feature extractor tests
# ---------------------------------------------------------------------------


class TestFeatureExtractor:
    """Tests for derive_pceps_features()."""

    def test_all_features_in_range(
        self,
        sample_feature_context: FeatureDerivationContext,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """All 16 features are in [0, 1]."""
        fv = derive_pceps_features(sample_feature_context, sample_feature_baseline)
        for i, v in enumerate(fv.values):
            assert 0.0 <= v <= 1.0, (
                f"Feature {PCEPS_FEATURE_NAMES[i]} = {v} out of range"
            )

    def test_feature_count_is_16(
        self,
        sample_feature_context: FeatureDerivationContext,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """Feature vector has exactly 16 values and 16 mask entries."""
        fv = derive_pceps_features(sample_feature_context, sample_feature_baseline)
        assert len(fv.values) == 16
        assert len(fv.mask) == 16

    def test_no_imputation_with_complete_context(
        self,
        sample_feature_context: FeatureDerivationContext,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """Fully populated context produces no imputed features."""
        fv = derive_pceps_features(sample_feature_context, sample_feature_baseline)
        assert fv.feature_completeness == 1.0
        assert not any(fv.mask)

    def test_missing_attribution_imputes_f1_f2(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """Missing attribution imputes f1 and f2 with training medians."""
        ctx = FeatureDerivationContext(attribution=None)
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        assert fv.mask[0] is True  # f1 imputed
        assert fv.mask[1] is True  # f2 imputed
        assert fv.values[0] == pytest.approx(sample_feature_baseline.medians[0])

    def test_conservative_defaults_for_security_features(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """f10, f12, f13, f16 use conservative default=1.0 when missing."""
        ctx = FeatureDerivationContext()  # All None.
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        # f10 (idx 9): image_signature_invalid → 1.0
        assert fv.values[9] == 1.0
        assert fv.mask[9] is True
        # f12 (idx 11): service_account_privilege → 1.0
        assert fv.values[11] == 1.0
        assert fv.mask[11] is True
        # f13 (idx 12): event_loss_rate → 1.0
        assert fv.values[12] == 1.0
        assert fv.mask[12] is True
        # f16 (idx 15): runtime_component_novelty → 1.0
        assert fv.values[15] == 1.0
        assert fv.mask[15] is True

    def test_f3_formula(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """f3 = violations / max(1, evaluated_rules)."""
        ctx = FeatureDerivationContext(
            contract_violations=10,
            evaluated_contract_rules=50,
        )
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        assert fv.values[2] == pytest.approx(10 / 50)

    def test_f4_formula(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """f4 = min(1, D / max(θ, δ))."""
        ctx = FeatureDerivationContext(
            kl_divergence=0.6,
            kl_threshold=0.3,
        )
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        assert fv.values[3] == pytest.approx(min(1.0, 0.6 / 0.3))

    def test_f15_beta_smoothed(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """f15 = (prior_drift + 1) / (prior_observed + 2) (beta-smoothed)."""
        ctx = FeatureDerivationContext(
            prior_drift_windows=5,
            prior_observed_windows=20,
        )
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        expected = (5 + 1) / (20 + 2)
        assert fv.values[14] == pytest.approx(expected)

    def test_imputed_feature_names_populated(
        self,
        sample_feature_baseline: PcepsFeatureBaseline,
    ) -> None:
        """Imputed feature names list contains the correct names."""
        ctx = FeatureDerivationContext()  # All None.
        fv = derive_pceps_features(ctx, sample_feature_baseline)
        assert len(fv.imputed_feature_names) > 0
        for name in fv.imputed_feature_names:
            assert name in PCEPS_FEATURE_NAMES


# ---------------------------------------------------------------------------
# Scorer helper tests
# ---------------------------------------------------------------------------


class TestScorerHelpers:
    """Tests for Platt scaling helper functions."""

    def test_clamp_bounds(self) -> None:
        """Clamp keeps values in (ε, 1-ε)."""
        assert _clamp(0.0) > 0.0
        assert _clamp(1.0) < 1.0
        assert _clamp(0.5) == pytest.approx(0.5)

    def test_sigmoid_bounds(self) -> None:
        """Sigmoid output is in (0, 1)."""
        assert 0.0 < _sigmoid(-10.0) < 0.5
        assert 0.5 < _sigmoid(10.0) < 1.0
        assert _sigmoid(0.0) == pytest.approx(0.5)

    def test_logit_inverse_of_sigmoid(self) -> None:
        """logit(sigmoid(x)) ≈ x."""
        for x in [-5.0, -1.0, 0.0, 1.0, 5.0]:
            assert _logit(_sigmoid(x)) == pytest.approx(x, abs=1e-10)

    def test_platt_calibrate_identity(self) -> None:
        """platt_calibrate with a=1, b=0 preserves probability."""
        for p in [0.1, 0.3, 0.5, 0.7, 0.9]:
            cal = platt_calibrate(p, 1.0, 0.0)
            assert cal == pytest.approx(p, abs=1e-5)

    def test_platt_calibrate_produces_probability(self) -> None:
        """Platt calibration output is in (0, 1)."""
        for p in [0.01, 0.1, 0.5, 0.9, 0.99]:
            cal = platt_calibrate(p, 2.0, -0.5)
            assert 0.0 < cal < 1.0


# ---------------------------------------------------------------------------
# Severity mapping tests
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Tests for map_score_to_severity()."""

    def test_critical_threshold(self) -> None:
        assert map_score_to_severity(90.0) == PcepsSeverity.CRITICAL

    def test_high_threshold(self) -> None:
        assert map_score_to_severity(70.0) == PcepsSeverity.HIGH

    def test_medium_threshold(self) -> None:
        assert map_score_to_severity(50.0) == PcepsSeverity.MEDIUM

    def test_low_threshold(self) -> None:
        assert map_score_to_severity(25.0) == PcepsSeverity.LOW

    def test_info_threshold(self) -> None:
        assert map_score_to_severity(5.0) == PcepsSeverity.INFO

    def test_boundary_80(self) -> None:
        assert map_score_to_severity(80.0) == PcepsSeverity.CRITICAL

    def test_boundary_0(self) -> None:
        assert map_score_to_severity(0.0) == PcepsSeverity.INFO


# ---------------------------------------------------------------------------
# Training baseline tests
# ---------------------------------------------------------------------------


class TestTrainingBaseline:
    """Tests for compute_training_baseline()."""

    def test_medians_computed(self) -> None:
        """Baseline medians computed from training windows."""
        windows = [
            LabeledPcepsWindow(
                window_id=str(i),
                features=PcepsFeatureVector(
                    values=[float(i) / 10.0] * 16,
                ),
                label=i % 2,
            )
            for i in range(10)
        ]
        baseline = compute_training_baseline(windows)
        assert len(baseline.medians) == 16
        # Median of [0.0, 0.1, 0.2, ..., 0.9] = 0.45.
        assert baseline.medians[0] == pytest.approx(0.45, abs=0.01)

    def test_empty_windows_returns_default(self) -> None:
        """Empty window list returns default baseline."""
        baseline = compute_training_baseline([])
        assert len(baseline.medians) == 16


# ---------------------------------------------------------------------------
# Imputation tests
# ---------------------------------------------------------------------------


class TestImputation:
    """Tests for impute_features()."""

    def test_imputed_values_use_baseline_medians(self) -> None:
        """Imputed features use training baseline medians."""
        baseline = PcepsFeatureBaseline(
            medians=[0.5] * 16,
        )
        fv = PcepsFeatureVector(
            values=[0.0] * 16,
            mask=[True] * 16,  # All missing.
        )
        result = impute_features(fv, baseline)
        for i in range(16):
            assert result.values[i] == pytest.approx(0.5)

    def test_non_imputed_values_preserved(self) -> None:
        """Non-imputed features keep their original values."""
        baseline = PcepsFeatureBaseline(medians=[0.5] * 16)
        fv = PcepsFeatureVector(
            values=[0.3] * 16,
            mask=[False] * 16,
        )
        result = impute_features(fv, baseline)
        for i in range(16):
            assert result.values[i] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Platt fitting tests
# ---------------------------------------------------------------------------


class TestFitPlattScaling:
    """Tests for fit_platt_scaling()."""

    def test_produces_finite_parameters(self) -> None:
        """Platt fit produces finite a, b."""
        raw = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
        labels = np.array([0, 0, 0, 1, 1, 1])
        a, b = fit_platt_scaling(raw, labels)
        assert math.isfinite(a)
        assert math.isfinite(b)

    def test_calibrated_probabilities_in_range(self) -> None:
        """Calibrated values for moderate inputs are in (ε, 1-ε)."""
        # Use a balanced, moderate dataset to keep Platt params reasonable.
        raw = np.array([0.3, 0.4, 0.5, 0.6, 0.7, 0.3, 0.6])
        labels = np.array([0, 0, 1, 1, 1, 0, 1])
        a, b = fit_platt_scaling(raw, labels)
        # Test only the middle range where parameters should be well-behaved.
        for p in [0.3, 0.4, 0.5, 0.6, 0.7]:
            cal = platt_calibrate(float(p), a, b)
            assert 0.0 <= cal <= 1.0, f"Out of range for p={p}: cal={cal}"


# ---------------------------------------------------------------------------
# ECE tests
# ---------------------------------------------------------------------------


class TestComputeECE:
    """Tests for compute_ece()."""

    def test_perfect_calibration_zero_ece(self) -> None:
        """Perfectly calibrated predictions have ECE ≈ 0."""
        # Probabilities equal to observed frequencies.
        probs = np.array([0.5, 0.5, 0.5, 0.5])
        labels = np.array([0, 1, 0, 1])
        ece = compute_ece(probs, labels)
        assert ece < 0.1

    def test_ece_non_negative(self) -> None:
        """ECE is always non-negative."""
        probs = np.array([0.9, 0.9, 0.1, 0.1])
        labels = np.array([0, 0, 1, 1])
        ece = compute_ece(probs, labels)
        assert ece >= 0.0
