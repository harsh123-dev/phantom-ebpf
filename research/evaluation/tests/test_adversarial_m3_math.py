"""
research/evaluation/tests/test_adversarial_m3_math.py

Adversarial mathematical stress tests for:
1. Ordinary Wilson score interval without continuity correction (Feature 11).
2. Non-parametric bootstrap percentile confidence intervals for MTTD (Feature 12).
"""

import math
import random
import statistics
import pytest

from research.evaluation.metrics.wilson_score import (
    compute_ordinary_wilson_score,
    wilson_score_interval,
)
from research.evaluation.metrics.evaluator import _compute_mttd_stats


# ============================================================================
# Challenge 1: Ordinary Wilson Score Mathematical Exactness & Invariants
# ============================================================================

class TestWilsonScoreMathematicalExactness:
    """Adversarially challenge mathematical exactness of ordinary Wilson score."""

    def test_wilson_score_six_of_six_exact_formula(self):
        """Verify x=6, n=6, z=1.95996... matches exact analytical lower bound 0.6096657... -> [0.6096, 1.0000]."""
        z = 1.959963984540054
        n = 6.0
        # For p = 1.0, theoretical lower bound simplifies to: 1 / (1 + z^2 / n)
        exact_lower = 1.0 / (1.0 + (z * z) / n)
        assert math.isclose(exact_lower, 0.6096657120978346, rel_tol=1e-9)

        lower, upper = compute_ordinary_wilson_score(6, 6, confidence=0.95)
        assert math.isclose(lower, exact_lower, rel_tol=1e-7)
        assert math.isclose(upper, 1.0, rel_tol=1e-7)
        assert round(lower, 4) in (0.6096, 0.6097)
        assert round(upper, 4) == 1.0000

    def test_wilson_score_zero_of_six_exact_formula(self):
        """Verify x=0, n=6 yields lower=0.0 and upper=1 - 1/(1+z^2/n) = 0.390334... -> [0.0000, 0.3904]."""
        z = 1.959963984540054
        n = 6.0
        exact_upper = 1.0 - (1.0 / (1.0 + (z * z) / n))
        assert math.isclose(exact_upper, 0.39033428790216534, rel_tol=1e-9)

        lower, upper = compute_ordinary_wilson_score(0, 6, confidence=0.95)
        assert lower == 0.0
        assert math.isclose(upper, exact_upper, rel_tol=1e-7)
        assert round(lower, 4) == 0.0000
        assert round(upper, 4) in (0.3903, 0.3904)

    def test_wilson_score_one_of_ten(self):
        """Verify x=1, n=10 yields lower ~0.0179, upper ~0.4042."""
        lower, upper = compute_ordinary_wilson_score(1, 10, confidence=0.95)
        assert round(lower, 4) == 0.0179
        assert round(upper, 4) == 0.4042
        assert 0.0 <= lower < 0.1 < upper <= 1.0

    def test_wilson_score_ten_of_ten(self):
        """Verify x=10, n=10 yields lower ~0.7225, upper = 1.0000."""
        lower, upper = compute_ordinary_wilson_score(10, 10, confidence=0.95)
        assert round(lower, 4) == 0.7225
        assert round(upper, 4) == 1.0000

    def test_wilson_score_symmetry_invariance(self):
        """Verify mathematical symmetry: Wilson(x, n) is complementary to Wilson(n-x, n)."""
        n = 12
        for x in range(n + 1):
            l1, u1 = compute_ordinary_wilson_score(x, n, confidence=0.95)
            l2, u2 = compute_ordinary_wilson_score(n - x, n, confidence=0.95)
            assert math.isclose(l1 + u2, 1.0, abs_tol=1e-6)
            assert math.isclose(u1 + l2, 1.0, abs_tol=1e-6)

    def test_wilson_score_monotonicity(self):
        """Verify strict monotonicity: as x increases for fixed n, lower and upper strictly increase."""
        n = 20
        prev_l, prev_u = -1.0, -1.0
        for x in range(n + 1):
            l, u = compute_ordinary_wilson_score(x, n, confidence=0.95)
            assert l > prev_l
            assert u > prev_u
            prev_l, prev_u = l, u

    def test_wilson_score_confidence_level_expansion(self):
        """Higher confidence level must strictly expand the interval width."""
        x, n = 7, 10
        l_90, u_90 = compute_ordinary_wilson_score(x, n, confidence=0.90)
        l_95, u_95 = compute_ordinary_wilson_score(x, n, confidence=0.95)
        l_99, u_99 = compute_ordinary_wilson_score(x, n, confidence=0.99)

        width_90 = u_90 - l_90
        width_95 = u_95 - l_95
        width_99 = u_99 - l_99

        assert width_90 < width_95 < width_99
        assert l_99 < l_95 < l_90 < 0.7 < u_90 < u_95 < u_99


# ============================================================================
# Challenge 2: Wilson Score Edge Cases and Input Validation
# ============================================================================

class TestWilsonScoreEdgeCasesAndValidation:
    """Stress-test edge cases and input sanitization."""

    def test_wilson_score_zero_trials_graceful_abstention(self):
        """When trials n=0 and successes x=0, returns (None, None)."""
        res = compute_ordinary_wilson_score(0, 0)
        assert res == (None, None)

    def test_wilson_score_invalid_successes_exceed_trials_positive_n(self):
        """When successes > trials for n > 0, raises ValueError."""
        with pytest.raises(ValueError, match="successes must be between 0 and 6, got 7"):
            compute_ordinary_wilson_score(7, 6)
        with pytest.raises(ValueError, match="successes must be between 0 and 10, got 11"):
            compute_ordinary_wilson_score(11, 10)

    def test_wilson_score_negative_trials(self):
        """Negative trials must raise ValueError."""
        with pytest.raises(ValueError, match="trials must be non-negative"):
            compute_ordinary_wilson_score(6, -1)
        with pytest.raises(ValueError, match="trials must be non-negative"):
            compute_ordinary_wilson_score(-1, -1)

    def test_wilson_score_negative_successes_positive_n(self):
        """Negative successes for positive trials must raise ValueError."""
        with pytest.raises(ValueError, match="successes must be between 0 and 10"):
            compute_ordinary_wilson_score(-1, 10)

    def test_wilson_score_alias_equivalence(self):
        """Verify alias wilson_score_interval matches compute_ordinary_wilson_score."""
        assert wilson_score_interval(6, 6) == compute_ordinary_wilson_score(6, 6)
        assert wilson_score_interval(0, 0) == compute_ordinary_wilson_score(0, 0)


# ============================================================================
# Challenge 3: Non-Parametric Bootstrap Percentile MTTD Stress Testing
# ============================================================================

class TestBootstrapMTTDAdversarialStress:
    """Stress-test MTTD bootstrap with right-skewed and degenerate distributions."""

    def test_bootstrap_raw3_empirical_latencies(self):
        """Verify bootstrap CI on raw3 latencies [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]."""
        latencies = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
        mean_v, med_v, iqr_v, p95_v, ci = _compute_mttd_stats(latencies, n_bootstrap=2000, seed=42)

        assert mean_v == pytest.approx(15.74, abs=0.01)
        assert med_v == pytest.approx(5.51, abs=0.01)
        assert iqr_v == pytest.approx(4.37, abs=0.01)
        assert p95_v > 50.0  # Captures extreme 70.33 tail

        assert ci is not None
        low, high = ci
        # Bounded within physical non-negative range and covers sample mean
        assert 0.0 <= low <= mean_v <= high
        assert low == pytest.approx(3.57, abs=0.1)
        assert high == pytest.approx(38.04, abs=0.5)

    def test_bootstrap_seed_determinism(self):
        """Same seed must produce bit-for-bit identical bootstrap intervals."""
        latencies = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
        r1 = _compute_mttd_stats(latencies, n_bootstrap=1000, seed=12345)
        r2 = _compute_mttd_stats(latencies, n_bootstrap=1000, seed=12345)
        assert r1 == r2

    def test_bootstrap_different_seeds_produce_variation(self):
        """Different seeds should generate slightly different bootstrap draws with small N."""
        latencies = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
        r1 = _compute_mttd_stats(latencies, n_bootstrap=200, seed=1)
        r2 = _compute_mttd_stats(latencies, n_bootstrap=200, seed=99999)
        # Point estimates are identical
        assert r1[0] == r2[0]  # mean
        assert r1[1] == r2[1]  # median
        # Bootstrap CIs should both bracket the mean
        assert r1[4][0] <= r1[0] <= r1[4][1]
        assert r2[4][0] <= r2[0] <= r2[4][1]

    def test_bootstrap_non_negative_physical_bounds(self):
        """Any sample of non-negative latencies must yield non-negative CI lower bound."""
        rng = random.Random(999)
        # Generate 50 synthetic right-skewed lognormal datasets
        for _ in range(50):
            sample = [math.exp(rng.gauss(1.0, 1.5)) for _ in range(8)]
            mean_v, med_v, iqr_v, p95_v, ci = _compute_mttd_stats(sample, n_bootstrap=500, seed=42)
            assert ci is not None
            low, high = ci
            assert low >= 0.0, f"Bootstrap lower bound {low} violated non-negativity!"
            assert low <= mean_v <= high

    def test_bootstrap_permutation_invariance(self):
        """Ordering of input latency list must not affect summary statistics or CI."""
        latencies = [70.33, 6.35, 4.68, 2.61, 7.88, 2.58]
        shuffled = list(latencies)
        random.Random(77).shuffle(shuffled)
        assert shuffled != latencies

        r_orig = _compute_mttd_stats(latencies, n_bootstrap=500, seed=42)
        r_shuf = _compute_mttd_stats(shuffled, n_bootstrap=500, seed=42)
        assert r_orig == r_shuf

    def test_bootstrap_scale_equivariance(self):
        """Multiplying latencies by constant c > 0 scales all metrics by c."""
        latencies = [10.0, 20.0, 30.0, 40.0]
        c = 3.0
        scaled = [x * c for x in latencies]

        r_base = _compute_mttd_stats(latencies, n_bootstrap=500, seed=42)
        r_scaled = _compute_mttd_stats(scaled, n_bootstrap=500, seed=42)

        # mean
        assert math.isclose(r_scaled[0], r_base[0] * c, abs_tol=0.05)
        # median
        assert math.isclose(r_scaled[1], r_base[1] * c, abs_tol=0.05)
        # iqr
        assert math.isclose(r_scaled[2], r_base[2] * c, abs_tol=0.05)
        # CI
        assert math.isclose(r_scaled[4][0], r_base[4][0] * c, abs_tol=0.1)
        assert math.isclose(r_scaled[4][1], r_base[4][1] * c, abs_tol=0.1)

    def test_bootstrap_empty_and_single_sample_degeneration(self):
        """Empty yields all None; single sample yields valid mean/median but None CI."""
        assert _compute_mttd_stats([]) == (None, None, None, None, None)

        mean_v, med_v, iqr_v, p95_v, ci = _compute_mttd_stats([42.0])
        assert mean_v == 42.0
        assert med_v == 42.0
        assert iqr_v == 0.0
        assert p95_v == 42.0
        assert ci is None

    def test_bootstrap_zero_variance_identical_values(self):
        """Identical values yield degenerate zero-width CI matching the constant value."""
        mean_v, med_v, iqr_v, p95_v, ci = _compute_mttd_stats([15.0, 15.0, 15.0, 15.0], n_bootstrap=200)
        assert mean_v == 15.0
        assert med_v == 15.0
        assert iqr_v == 0.0
        assert ci == (15.0, 15.0)

    def test_bootstrap_extreme_outlier_survives_without_overflow(self):
        """Extreme outlier (10^7) does not trigger overflow or NaN."""
        latencies = [1.0, 1.2, 0.9, 1.1, 10_000_000.0]
        mean_v, med_v, iqr_v, p95_v, ci = _compute_mttd_stats(latencies, n_bootstrap=500, seed=42)
        assert med_v == 1.1
        assert mean_v > 1_000_000.0
        assert ci is not None
        assert ci[0] <= mean_v <= ci[1]
