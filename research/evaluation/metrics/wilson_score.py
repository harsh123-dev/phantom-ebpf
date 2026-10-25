"""
research/evaluation/metrics/wilson_score.py

Pure-math implementation of the standard (ordinary) Wilson score confidence interval
for binomial proportions without continuity correction.

Mathematical definition matching EXPERIMENT_PROTOCOL.md §7:
Given k successes in n trials, proportion p = k / n, and two-sided normal quantile z:
    Center = (p + z^2 / (2n)) / (1 + z^2 / n)
    Margin = (z / (1 + z^2 / n)) * sqrt(p * (1 - p) / n + z^2 / (4n^2))
    Lower = max(0.0, Center - Margin)
    Upper = min(1.0, Center + Margin)

Properties:
    - At 95% confidence (z ≈ 1.95996398454):
      For k = 6, n = 6: interval is [0.6096, 1.0000]
      For k = 0, n = 6: interval is [0.0000, 0.3904]
    - When n = 0, returns (None, None) gracefully.
"""

from __future__ import annotations

import math
from typing import Tuple, Union

try:
    from scipy.stats import norm
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False


def _get_z(confidence: float) -> float:
    """Return the two-tailed standard normal critical value z for a given confidence level."""
    if math.isclose(confidence, 0.95):
        # Exact two-tailed standard normal critical value for 95% CI
        return 1.959963984540054
    if _HAS_SCIPY:
        return float(norm.ppf(1.0 - (1.0 - confidence) / 2.0))
    # Standard lookup for common confidence levels
    lookup = {
        0.90: 1.6448536269514722,
        0.95: 1.959963984540054,
        0.98: 2.3263478740408408,
        0.99: 2.5758293035489004,
    }
    for level, val in lookup.items():
        if math.isclose(confidence, level, rel_tol=1e-3):
            return val
    # Fallback to 1.96 for 95%
    return 1.959963984540054


def compute_ordinary_wilson_score(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float] | tuple[None, None]:
    """Compute the standard ordinary Wilson score interval without continuity correction.

    Args:
        successes: Number of successful outcomes (k).
        trials: Total number of independent trials (n).
        confidence: Two-sided confidence level (default 0.95).

    Returns:
        Tuple of (lower, upper) bounded in [0.0, 1.0], or (None, None) if trials == 0.

    Raises:
        ValueError: If trials < 0, or successes < 0, or successes > trials.
    """
    if trials == 0:
        return (None, None)
    if trials < 0:
        raise ValueError(f"trials must be non-negative, got {trials}")
    if successes < 0 or successes > trials:
        raise ValueError(f"successes must be between 0 and {trials}, got {successes}")

    n = float(trials)
    p = float(successes) / n
    z = _get_z(confidence)
    z2 = z * z

    denom = 1.0 + (z2 / n)
    center = (p + (z2 / (2.0 * n))) / denom

    variance_term = (p * (1.0 - p) / n) + (z2 / (4.0 * n * n))
    margin = (z / denom) * math.sqrt(max(0.0, variance_term))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (lower, upper)


# Aliases for interface compatibility
wilson_score_interval = compute_ordinary_wilson_score
wilson_score = compute_ordinary_wilson_score
